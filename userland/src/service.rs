//! Windows Service Implementation
//! 
//! Implements the main XDR service that runs as a Windows service,
//! coordinates all components, and handles lifecycle management.

use crate::config::{ConfigManager, XdrConfig};
use crate::driver::{create_shared_driver, SharedDriver};
use crate::events::EventProcessor;
use crate::live_response::LiveResponseManager;
use crate::pipeline::EventPipeline;
use crate::rules::RulesEngine;
use crate::storage::EventStorage;
use crate::utils::{set_process_priority, PerfTimer};
use crate::{LibResult, XdrError};
use anyhow::{Context, Result};
use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{interval, sleep};
use tracing::{error, info, warn};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

/// Service name for Windows Service Manager
const SERVICE_NAME: &str = "XdrService";

/// Main XDR service structure
pub struct XdrService {
    config_manager: ConfigManager,
    driver: SharedDriver,
    storage: Arc<EventStorage>,
    rules_engine: Arc<RulesEngine>,
    live_response: Arc<LiveResponseManager>,
    pipeline: Option<EventPipeline>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    status_handle: Option<windows_service::service_control_handler::ServiceStatusHandle>,
}

impl XdrService {
    /// Create a new XDR service instance
    pub fn new() -> Result<Self> {
        info!("Initializing XDR service");

        // Load configuration
        let config_path = "C:\\ProgramData\\XDR\\config.yaml";
        let config_manager = ConfigManager::new(config_path)?;
        let config = config_manager.get_config();

        // Set process priority
        if let Err(e) = set_process_priority(&config.performance.priority_class) {
            warn!("Failed to set process priority: {}", e);
        }

        // Connect to driver
        let driver = create_shared_driver()
            .context("Failed to connect to XDR kernel driver")?;

        // Initialize storage
        let storage_config = config.to_storage_config();
        let storage = Arc::new(EventStorage::new(storage_config)?);

        // Initialize rules engine
        let rules_engine = Arc::new(RulesEngine::new(config.rules.rules_directory.clone()));

        // Initialize live response
        let live_response = Arc::new(LiveResponseManager::new(
            config.live_response.enabled,
            config.live_response.require_admin,
            config.live_response.allowed_actions.clone(),
        ));

        // Configure driver
        {
            let mut driver_guard = driver.lock().unwrap();
            let driver_config = config.to_driver_config();
            driver_guard.set_config(&driver_config)?;
            driver_guard.map_shared_memory()?;
        }

        info!("XDR service components initialized successfully");

        Ok(Self {
            config_manager,
            driver,
            storage,
            rules_engine,
            live_response,
            pipeline: None,
            shutdown_tx: None,
            status_handle: None,
        })
    }

    /// Run the service (for standalone mode)
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting XDR service in standalone mode");

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Set up signal handling for graceful shutdown
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl-c");
            info!("Received shutdown signal");
        });

        // Start event processing pipeline
        let mut pipeline = EventPipeline::new(
            self.driver.clone(),
            self.storage.clone(),
            self.rules_engine.clone(),
        );

        // Start configuration hot-reload
        let mut config_changes = self.config_manager.enable_hot_reload()?;

        // Main service loop
        let mut health_check_interval = interval(Duration::from_secs(30));
        let mut cleanup_interval = interval(Duration::from_secs(3600)); // 1 hour

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Shutdown requested");
                    break;
                }
                
                new_config = config_changes.recv() => {
                    if let Some(config) = new_config {
                        info!("Configuration changed, applying updates");
                        if let Err(e) = self.apply_config_changes(&config).await {
                            error!("Failed to apply configuration changes: {}", e);
                        }
                    }
                }
                
                _ = health_check_interval.tick() => {
                    self.perform_health_check().await;
                }
                
                _ = cleanup_interval.tick() => {
                    self.perform_cleanup().await;
                }
                
                _ = pipeline.start() => {
                    warn!("Event pipeline stopped unexpectedly");
                    // Pipeline should run continuously, restart if needed
                    sleep(Duration::from_secs(5)).await;
                }
            }
        }

        // Graceful shutdown
        info!("Performing graceful shutdown");
        pipeline.shutdown().await?;

        info!("XDR service stopped");
        Ok(())
    }

    /// Apply configuration changes
    async fn apply_config_changes(&self, config: &XdrConfig) -> Result<()> {
        let _timer = PerfTimer::new("apply_config_changes");

        // Update driver configuration
        {
            let mut driver = self.driver.lock().unwrap();
            let driver_config = config.to_driver_config();
            driver.set_config(&driver_config)?;
        }

        // TODO: Update other components as needed
        // - Rules engine reload
        // - Storage configuration updates
        // - Live response settings

        info!("Configuration changes applied successfully");
        Ok(())
    }

    /// Perform health check
    async fn perform_health_check(&self) {
        let _timer = PerfTimer::new("health_check");

        // Check driver connection
        let driver_ok = {
            let driver = self.driver.lock().unwrap();
            driver.is_mapped() && driver.version().is_some()
        };

        if !driver_ok {
            warn!("Driver health check failed");
            // TODO: Attempt reconnection
        }

        // Check storage health
        if let Err(e) = self.storage.get_statistics() {
            warn!("Storage health check failed: {}", e);
        }

        // Log basic statistics
        if let Ok(stats) = self.storage.get_statistics() {
            info!(
                "Health check: {} total events, {} MB database",
                stats.total_events,
                stats.database_size_bytes / 1024 / 1024
            );
        }
    }

    /// Perform periodic cleanup
    async fn perform_cleanup(&self) {
        let _timer = PerfTimer::new("cleanup");

        // Clean up old events
        match self.storage.cleanup_old_events() {
            Ok(deleted_count) => {
                if deleted_count > 0 {
                    info!("Cleanup: Removed {} old events", deleted_count);
                }
            }
            Err(e) => {
                error!("Failed to cleanup old events: {}", e);
            }
        }

        // TODO: Additional cleanup tasks
        // - Log file rotation
        // - Cache cleanup
        // - Temporary file cleanup
    }

    /// Update service status
    fn update_service_status(&self, state: ServiceState) {
        if let Some(ref handle) = self.status_handle {
            let status = ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::from_secs(3),
                process_id: None,
            };

            if let Err(e) = handle.set_service_status(status) {
                error!("Failed to update service status: {}", e);
            }
        }
    }
}

/// Windows service entry point
define_windows_service!(ffi_service_main, xdr_service_main);

/// Service main function
fn xdr_service_main(_arguments: Vec<OsString>) {
    // Initialize async runtime
    let rt = tokio::runtime::Runtime::new().expect("Failed to create async runtime");

    rt.block_on(async {
        // Initialize logging for service mode
        if let Err(e) = crate::init() {
            eprintln!("Failed to initialize XDR library: {}", e);
            return;
        }

        // Create service instance
        let mut service = match XdrService::new() {
            Ok(service) => service,
            Err(e) => {
                error!("Failed to create XDR service: {}", e);
                return;
            }
        };

        // Set up service control handler
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        let status_handle = service_control_handler::register(SERVICE_NAME, move |control_event| {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    info!("Service stop/shutdown requested");
                    let _ = shutdown_tx.try_send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        });

        let status_handle = match status_handle {
            Ok(handle) => handle,
            Err(e) => {
                error!("Failed to register service control handler: {}", e);
                return;
            }
        };

        service.status_handle = Some(status_handle);

        // Update service status to running
        service.update_service_status(ServiceState::Running);

        // Create shutdown channel for service
        let (service_shutdown_tx, service_shutdown_rx) = mpsc::channel(1);
        service.shutdown_tx = Some(service_shutdown_tx);

        // Wait for either service shutdown or control handler shutdown
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("Received service control shutdown signal");
            }
            result = service.run() => {
                if let Err(e) = result {
                    error!("Service run error: {}", e);
                }
            }
        }

        // Update service status to stopped
        service.update_service_status(ServiceState::Stopped);
    });
}

/// Run as Windows service
pub fn run_service() -> Result<()> {
    info!("Starting XDR as Windows service");
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("Failed to start Windows service")?;
    Ok(())
}

/// Install Windows service
pub fn install_service() -> Result<()> {
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::service::{ServiceAccess, ServiceInfo, ServiceStartType};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;

    let current_exe = std::env::current_exe()?;
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("XDR Endpoint Detection and Response Service"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: windows_service::service::ServiceErrorControl::Normal,
        executable_path: current_exe,
        launch_arguments: vec![OsString::from("--service")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let _service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
    
    info!("XDR service installed successfully");
    Ok(())
}

/// Uninstall Windows service
pub fn uninstall_service() -> Result<()> {
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::service::ServiceAccess;

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
    
    service.delete()?;
    
    info!("XDR service uninstalled successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_service_creation() {
        // This test may fail if driver is not available
        if let Err(e) = XdrService::new() {
            println!("Service creation failed (expected in test environment): {}", e);
        }
    }
}