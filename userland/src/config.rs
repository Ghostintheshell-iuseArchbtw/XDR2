//! Configuration Module
//! 
//! Manages XDR service configuration with hot-reload capabilities,
//! validation, and integration with the kernel driver configuration.

use crate::driver::DriverConfig;
use crate::storage::StorageConfig;
use crate::{LibResult, XdrError};
use anyhow::{Context, Result};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Configuration-specific error types
#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("Configuration file not found: {0}")]
    NotFound(PathBuf),
    
    #[error("Invalid configuration format: {0}")]
    InvalidFormat(String),
    
    #[error("Configuration validation failed: {0}")]
    Validation(String),
    
    #[error("File watcher error: {0}")]
    Watcher(#[from] notify::Error),
    
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("YAML parsing error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    
    #[error("Permission denied: {0}")]
    Permission(String),
}

/// Main XDR configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdrConfig {
    /// Service configuration
    pub service: ServiceConfig,
    
    /// Driver configuration
    pub driver: DriverConfigYaml,
    
    /// Storage configuration
    pub storage: StorageConfigYaml,
    
    /// Rules configuration
    pub rules: RulesConfig,
    
    /// Live response configuration
    pub live_response: LiveResponseConfig,
    
    /// ETW configuration
    pub etw: EtwConfig,
    
    /// Logging configuration
    pub logging: LoggingConfig,
    
    /// Performance tuning
    pub performance: PerformanceConfig,
}

/// Service-level configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Service display name
    pub name: String,
    
    /// Service description
    pub description: String,
    
    /// Number of worker threads
    pub worker_threads: u32,
    
    /// Event processing queue size
    pub queue_size: u32,
    
    /// Health check interval (seconds)
    pub health_check_interval: u32,
    
    /// Enable Windows service mode
    pub service_mode: bool,
    
    /// Restart on failure
    pub auto_restart: bool,
    
    /// Maximum restart attempts
    pub max_restart_attempts: u32,
}

/// Driver configuration (YAML representation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverConfigYaml {
    /// Minimum severity level to log
    pub min_severity: String,
    
    /// Enabled event sources
    pub sources: SourcesConfig,
    
    /// Maximum queue depth before dropping events
    pub max_queue_depth: u32,
    
    /// Heartbeat interval in milliseconds
    pub heartbeat_interval_ms: u32,
    
    /// WFP mode: "monitor" or "block"
    pub wfp_mode: String,
    
    /// Driver connection timeout (ms)
    pub connection_timeout_ms: u32,
    
    /// Shared memory size (bytes)
    pub shared_memory_size: u64,
}

/// Event sources configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourcesConfig {
    pub process: bool,
    pub thread: bool,
    pub image: bool,
    pub registry: bool,
    pub file: bool,
    pub network: bool,
}

/// Storage configuration (YAML representation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfigYaml {
    /// Database file path
    pub database_path: PathBuf,
    
    /// NDJSON export directory
    pub export_directory: PathBuf,
    
    /// Maximum database size (GB)
    pub max_database_size_gb: f64,
    
    /// Event retention period (days)
    pub retention_days: u32,
    
    /// Enable WAL mode
    pub enable_wal: bool,
    
    /// Enable NDJSON export
    pub enable_ndjson_export: bool,
    
    /// Enable compression
    pub enable_compression: bool,
    
    /// Cleanup interval (hours)
    pub cleanup_interval_hours: u32,
    
    /// Batch size for bulk operations
    pub batch_size: usize,
}

/// Rules engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
    /// Rules directory
    pub rules_directory: PathBuf,
    
    /// Enable rules engine
    pub enabled: bool,
    
    /// Rules file patterns
    pub file_patterns: Vec<String>,
    
    /// Auto-reload rules on change
    pub auto_reload: bool,
    
    /// Maximum rules to load
    pub max_rules: u32,
    
    /// Rule evaluation timeout (ms)
    pub evaluation_timeout_ms: u32,
    
    /// Enable correlation engine
    pub enable_correlation: bool,
    
    /// Correlation window size (events)
    pub correlation_window_size: u32,
    
    /// Correlation timeout (seconds)
    pub correlation_timeout_seconds: u32,
}

/// Live response configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveResponseConfig {
    /// Enable live response capabilities
    pub enabled: bool,
    
    /// Require administrator privileges
    pub require_admin: bool,
    
    /// Allowed actions
    pub allowed_actions: Vec<String>,
    
    /// Action timeout (seconds)
    pub action_timeout_seconds: u32,
    
    /// Enable audit logging
    pub enable_audit_log: bool,
    
    /// Audit log path
    pub audit_log_path: PathBuf,
    
    /// Rate limiting (actions per minute)
    pub rate_limit: u32,
}

/// ETW configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwConfig {
    /// Enable ETW provider
    pub enabled: bool,
    
    /// ETW session name
    pub session_name: String,
    
    /// Providers to subscribe to
    pub providers: Vec<EtwProviderConfig>,
    
    /// Buffer size (KB)
    pub buffer_size_kb: u32,
    
    /// Number of buffers
    pub buffer_count: u32,
    
    /// Enable real-time processing
    pub real_time: bool,
}

/// ETW provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwProviderConfig {
    /// Provider GUID
    pub guid: String,
    
    /// Provider name
    pub name: String,
    
    /// Enable flags
    pub enable_flags: u64,
    
    /// Enable level
    pub enable_level: u32,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
    
    /// Log file path
    pub file_path: PathBuf,
    
    /// Enable console logging
    pub console: bool,
    
    /// Enable JSON formatting
    pub json_format: bool,
    
    /// Maximum log file size (MB)
    pub max_file_size_mb: u32,
    
    /// Number of log files to keep
    pub max_files: u32,
    
    /// Log rotation interval (hours)
    pub rotation_hours: u32,
    
    /// Enable tracing
    pub enable_tracing: bool,
}

/// Performance tuning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// CPU affinity mask
    pub cpu_affinity: Option<u64>,
    
    /// Process priority class
    pub priority_class: String,
    
    /// Working set size (MB)
    pub working_set_mb: Option<u32>,
    
    /// Enable large pages
    pub enable_large_pages: bool,
    
    /// Memory allocation strategy
    pub memory_strategy: String,
    
    /// Event processing batch size
    pub event_batch_size: u32,
    
    /// Processing delay (microseconds)
    pub processing_delay_us: u32,
}

impl Default for XdrConfig {
    fn default() -> Self {
        Self {
            service: ServiceConfig {
                name: "XDR Service".to_string(),
                description: "XDR Endpoint Detection and Response Service".to_string(),
                worker_threads: num_cpus::get() as u32,
                queue_size: 10000,
                health_check_interval: 30,
                service_mode: true,
                auto_restart: true,
                max_restart_attempts: 3,
            },
            driver: DriverConfigYaml {
                min_severity: "low".to_string(),
                sources: SourcesConfig {
                    process: true,
                    thread: true,
                    image: true,
                    registry: true,
                    file: true,
                    network: true,
                },
                max_queue_depth: 10000,
                heartbeat_interval_ms: 5000,
                wfp_mode: "monitor".to_string(),
                connection_timeout_ms: 5000,
                shared_memory_size: 16 * 1024 * 1024, // 16MB
            },
            storage: StorageConfigYaml {
                database_path: PathBuf::from("C:\\ProgramData\\XDR\\events.db"),
                export_directory: PathBuf::from("C:\\ProgramData\\XDR\\exports"),
                max_database_size_gb: 10.0,
                retention_days: 90,
                enable_wal: true,
                enable_ndjson_export: true,
                enable_compression: true,
                cleanup_interval_hours: 24,
                batch_size: 1000,
            },
            rules: RulesConfig {
                rules_directory: PathBuf::from("C:\\ProgramData\\XDR\\rules"),
                enabled: true,
                file_patterns: vec!["*.yaml".to_string(), "*.yml".to_string()],
                auto_reload: true,
                max_rules: 1000,
                evaluation_timeout_ms: 1000,
                enable_correlation: true,
                correlation_window_size: 1000,
                correlation_timeout_seconds: 300,
            },
            live_response: LiveResponseConfig {
                enabled: true,
                require_admin: true,
                allowed_actions: vec![
                    "terminate_process".to_string(),
                    "suspend_process".to_string(),
                    "kill_connection".to_string(),
                ],
                action_timeout_seconds: 30,
                enable_audit_log: true,
                audit_log_path: PathBuf::from("C:\\ProgramData\\XDR\\audit.log"),
                rate_limit: 10,
            },
            etw: EtwConfig {
                enabled: false,
                session_name: "XDR-ETW-Session".to_string(),
                providers: vec![],
                buffer_size_kb: 64,
                buffer_count: 20,
                real_time: true,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file_path: PathBuf::from("C:\\ProgramData\\XDR\\logs\\xdr.log"),
                console: true,
                json_format: false,
                max_file_size_mb: 100,
                max_files: 10,
                rotation_hours: 24,
                enable_tracing: true,
            },
            performance: PerformanceConfig {
                cpu_affinity: None,
                priority_class: "normal".to_string(),
                working_set_mb: None,
                enable_large_pages: false,
                memory_strategy: "default".to_string(),
                event_batch_size: 100,
                processing_delay_us: 0,
            },
        }
    }
}

impl XdrConfig {
    /// Load configuration from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        
        if !path.exists() {
            return Err(ConfigError::NotFound(path.to_path_buf()).into());
        }
        
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;
        
        let config: XdrConfig = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {:?}", path))?;
        
        config.validate()?;
        
        info!("Configuration loaded from: {:?}", path);
        Ok(config)
    }
    
    /// Save configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        
        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        let content = serde_yaml::to_string(self)?;
        std::fs::write(path, content)?;
        
        info!("Configuration saved to: {:?}", path);
        Ok(())
    }
    
    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate severity level
        match self.driver.min_severity.as_str() {
            "low" | "medium" | "high" | "critical" => {}
            _ => return Err(ConfigError::Validation(
                "Invalid severity level. Must be: low, medium, high, critical".to_string()
            ).into()),
        }
        
        // Validate WFP mode
        match self.driver.wfp_mode.as_str() {
            "monitor" | "block" => {}
            _ => return Err(ConfigError::Validation(
                "Invalid WFP mode. Must be: monitor, block".to_string()
            ).into()),
        }
        
        // Validate log level
        match self.logging.level.as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            _ => return Err(ConfigError::Validation(
                "Invalid log level. Must be: trace, debug, info, warn, error".to_string()
            ).into()),
        }
        
        // Validate priority class
        match self.performance.priority_class.as_str() {
            "idle" | "below_normal" | "normal" | "above_normal" | "high" | "realtime" => {}
            _ => return Err(ConfigError::Validation(
                "Invalid priority class".to_string()
            ).into()),
        }
        
        // Validate paths exist or can be created
        for path in &[
            &self.storage.database_path.parent().unwrap_or(Path::new("C:\\")),
            &self.storage.export_directory,
            &self.rules.rules_directory,
            &self.logging.file_path.parent().unwrap_or(Path::new("C:\\")),
        ] {
            if !path.exists() {
                std::fs::create_dir_all(path)
                    .with_context(|| format!("Cannot create directory: {:?}", path))?;
            }
        }
        
        // Validate numeric ranges
        if self.driver.max_queue_depth == 0 || self.driver.max_queue_depth > 100000 {
            return Err(ConfigError::Validation(
                "max_queue_depth must be between 1 and 100000".to_string()
            ).into());
        }
        
        if self.storage.retention_days == 0 || self.storage.retention_days > 3650 {
            return Err(ConfigError::Validation(
                "retention_days must be between 1 and 3650".to_string()
            ).into());
        }
        
        if self.rules.max_rules > 10000 {
            return Err(ConfigError::Validation(
                "max_rules cannot exceed 10000".to_string()
            ).into());
        }
        
        info!("Configuration validation passed");
        Ok(())
    }
    
    /// Convert to driver configuration
    pub fn to_driver_config(&self) -> DriverConfig {
        let min_severity = match self.driver.min_severity.as_str() {
            "low" => crate::ffi::XDR_SEVERITY_LOW,
            "medium" => crate::ffi::XDR_SEVERITY_MEDIUM,
            "high" => crate::ffi::XDR_SEVERITY_HIGH,
            "critical" => crate::ffi::XDR_SEVERITY_CRITICAL,
            _ => crate::ffi::XDR_SEVERITY_LOW,
        };
        
        let mut source_mask = 0u32;
        if self.driver.sources.process { source_mask |= 1 << crate::ffi::XDR_SOURCE_PROCESS; }
        if self.driver.sources.thread { source_mask |= 1 << crate::ffi::XDR_SOURCE_THREAD; }
        if self.driver.sources.image { source_mask |= 1 << crate::ffi::XDR_SOURCE_IMAGE; }
        if self.driver.sources.registry { source_mask |= 1 << crate::ffi::XDR_SOURCE_REGISTRY; }
        if self.driver.sources.file { source_mask |= 1 << crate::ffi::XDR_SOURCE_FILE; }
        if self.driver.sources.network { source_mask |= 1 << crate::ffi::XDR_SOURCE_NETWORK; }
        
        let wfp_mode = match self.driver.wfp_mode.as_str() {
            "block" => 1,
            _ => 0, // monitor
        };
        
        DriverConfig {
            min_severity,
            source_mask,
            max_queue_depth: self.driver.max_queue_depth,
            heartbeat_interval_ms: self.driver.heartbeat_interval_ms,
            allowlist_hash: 0, // TODO: Compute from allowlists
            wfp_mode,
        }
    }
    
    /// Convert to storage configuration
    pub fn to_storage_config(&self) -> StorageConfig {
        StorageConfig {
            database_path: self.storage.database_path.clone(),
            export_directory: self.storage.export_directory.clone(),
            max_database_size: (self.storage.max_database_size_gb * 1024.0 * 1024.0 * 1024.0) as u64,
            retention_days: self.storage.retention_days,
            enable_wal: self.storage.enable_wal,
            pool_size: 10, // Fixed for now
            batch_size: self.storage.batch_size,
            auto_vacuum: true,
            enable_ndjson_export: self.storage.enable_ndjson_export,
            enable_compression: self.storage.enable_compression,
        }
    }
}

/// Configuration manager with hot-reload capabilities
pub struct ConfigManager {
    config: Arc<Mutex<XdrConfig>>,
    config_path: PathBuf,
    change_tx: Option<mpsc::UnboundedSender<XdrConfig>>,
    _watcher: Option<RecommendedWatcher>,
}

impl ConfigManager {
    /// Create a new configuration manager
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self> {
        let config_path = config_path.as_ref().to_path_buf();
        
        // Load initial configuration
        let config = if config_path.exists() {
            XdrConfig::load_from_file(&config_path)?
        } else {
            warn!("Config file not found, using defaults: {:?}", config_path);
            let default_config = XdrConfig::default();
            
            // Create default config file
            if let Some(parent) = config_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            default_config.save_to_file(&config_path)?;
            
            default_config
        };
        
        Ok(Self {
            config: Arc::new(Mutex::new(config)),
            config_path,
            change_tx: None,
            _watcher: None,
        })
    }
    
    /// Get current configuration
    pub fn get_config(&self) -> XdrConfig {
        self.config.lock().unwrap().clone()
    }
    
    /// Update configuration
    pub fn update_config(&self, new_config: XdrConfig) -> Result<()> {
        new_config.validate()?;
        
        // Save to file
        new_config.save_to_file(&self.config_path)?;
        
        // Update in-memory config
        {
            let mut config = self.config.lock().unwrap();
            *config = new_config.clone();
        }
        
        // Notify subscribers
        if let Some(ref tx) = self.change_tx {
            let _ = tx.send(new_config);
        }
        
        info!("Configuration updated");
        Ok(())
    }
    
    /// Enable hot-reload with file watching
    pub fn enable_hot_reload(&mut self) -> Result<mpsc::UnboundedReceiver<XdrConfig>> {
        let (tx, rx) = mpsc::unbounded_channel();
        
        let config_path = self.config_path.clone();
        let config_arc = self.config.clone();
        let tx_clone = tx.clone();
        
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, _>| {
            match res {
                Ok(event) => {
                    if matches!(event.kind, EventKind::Modify(_)) {
                        debug!("Config file changed, reloading...");
                        
                        // Add a small delay to avoid partial writes
                        std::thread::sleep(Duration::from_millis(100));
                        
                        match XdrConfig::load_from_file(&config_path) {
                            Ok(new_config) => {
                                {
                                    let mut config = config_arc.lock().unwrap();
                                    *config = new_config.clone();
                                }
                                
                                let _ = tx_clone.send(new_config);
                                info!("Configuration hot-reloaded");
                            }
                            Err(e) => {
                                error!("Failed to reload config: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("File watcher error: {}", e);
                }
            }
        })?;
        
        watcher.watch(&self.config_path, RecursiveMode::NonRecursive)?;
        
        self.change_tx = Some(tx);
        self._watcher = Some(watcher);
        
        info!("Configuration hot-reload enabled for: {:?}", self.config_path);
        Ok(rx)
    }
    
    /// Validate current configuration
    pub fn validate(&self) -> Result<()> {
        let config = self.config.lock().unwrap();
        config.validate()
    }
    
    /// Reset to default configuration
    pub fn reset_to_defaults(&self) -> Result<()> {
        let default_config = XdrConfig::default();
        self.update_config(default_config)
    }
    
    /// Export configuration as YAML string
    pub fn export_yaml(&self) -> Result<String> {
        let config = self.config.lock().unwrap();
        Ok(serde_yaml::to_string(&*config)?)
    }
    
    /// Import configuration from YAML string
    pub fn import_yaml(&self, yaml: &str) -> Result<()> {
        let config: XdrConfig = serde_yaml::from_str(yaml)?;
        self.update_config(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = XdrConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_serialization() {
        let config = XdrConfig::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let deserialized: XdrConfig = serde_yaml::from_str(&yaml).unwrap();
        assert!(deserialized.validate().is_ok());
    }

    #[test]
    fn test_config_manager() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.yaml");
        
        let manager = ConfigManager::new(&config_path).unwrap();
        let config = manager.get_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_driver_config_conversion() {
        let config = XdrConfig::default();
        let driver_config = config.to_driver_config();
        assert_eq!(driver_config.min_severity, crate::ffi::XDR_SEVERITY_LOW);
        assert_ne!(driver_config.source_mask, 0);
    }

    #[test]
    fn test_storage_config_conversion() {
        let config = XdrConfig::default();
        let storage_config = config.to_storage_config();
        assert!(storage_config.enable_wal);
        assert!(storage_config.enable_ndjson_export);
    }
}