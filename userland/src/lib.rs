//! XDR Userland Library
//! 
//! This library provides safe Rust wrappers around the XDR kernel driver interface,
//! shared memory communication, event processing, and all userland functionality.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::too_many_arguments)]

use anyhow::{Context, Result};
use std::sync::Once;
use tracing::{info, warn};

// Re-export commonly used types
pub use chrono::{DateTime, Utc};
pub use serde::{Deserialize, Serialize};
pub use uuid::Uuid;

// Generated FFI bindings
pub mod ffi {
    include!(concat!(env!("OUT_DIR"), "/xdr_bindings.rs"));
    
    // Link to our C helper functions
    extern "C" {
        pub fn xdr_abi_version() -> u32;
        pub fn xdr_shm_default_size() -> u32;
        pub fn xdr_shm_magic() -> u32;
        pub fn xdr_max_path() -> u32;
        pub fn xdr_max_string() -> u32;
        pub fn xdr_event_record_size() -> u32;
        pub fn xdr_shm_header_size() -> u32;
        
        pub fn xdr_ioctl_get_version() -> u32;
        pub fn xdr_ioctl_map_shm() -> u32;
        pub fn xdr_ioctl_set_config() -> u32;
        pub fn xdr_ioctl_peek_fallback() -> u32;
        pub fn xdr_ioctl_dequeue_fallback() -> u32;
        pub fn xdr_ioctl_user_event() -> u32;
        
        pub fn xdr_validate_event_record(record: *const XDR_EVENT_RECORD) -> i32;
        pub fn xdr_fnv1a_hash(data: *const std::ffi::c_void, length: usize) -> u64;
        pub fn xdr_current_timestamp() -> u64;
        pub fn xdr_filetime_to_unix(filetime: u64) -> u64;
        
        pub fn xdr_get_process_info(
            pid: u32,
            image_path: *mut u16,
            image_path_size: usize,
            session_id: *mut u32,
        ) -> i32;
        
        pub fn xdr_is_admin() -> i32;
        pub fn xdr_enable_debug_privilege() -> i32;
    }
}

// Public modules
pub mod driver;
pub mod events;
pub mod config;
pub mod storage;
pub mod rules;
pub mod pipeline;
pub mod live_response;
pub mod crypto;
pub mod etw;
pub mod utils;

// Build information
pub const BUILD_TIMESTAMP: &str = env!("XDR_BUILD_TIMESTAMP");
pub const GIT_HASH: &str = env!("XDR_GIT_HASH");
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the XDR library
/// This should be called once at application startup
pub fn init() -> Result<()> {
    static INIT: Once = Once::new();
    static mut INIT_RESULT: Option<Result<(), anyhow::Error>> = None;

    unsafe {
        INIT.call_once(|| {
            INIT_RESULT = Some(init_internal());
        });
        
        match &INIT_RESULT {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(anyhow::anyhow!("Initialization failed: {}", e)),
            None => unreachable!(),
        }
    }
}

fn init_internal() -> Result<()> {
    // Initialize logging
    init_logging()?;
    
    info!("XDR userland library initializing");
    info!("Version: {}", VERSION);
    info!("Build timestamp: {}", BUILD_TIMESTAMP);
    info!("Git hash: {}", GIT_HASH);
    
    // Check ABI version compatibility
    let abi_version = unsafe { ffi::xdr_abi_version() };
    if abi_version != ffi::XDR_ABI_VERSION {
        return Err(anyhow::anyhow!(
            "ABI version mismatch: expected {}, got {}",
            ffi::XDR_ABI_VERSION,
            abi_version
        ));
    }
    
    info!("ABI version {} confirmed", abi_version);
    
    // Check if running as administrator
    let is_admin = unsafe { ffi::xdr_is_admin() } != 0;
    if !is_admin {
        warn!("Not running as administrator - some functionality may be limited");
    } else {
        info!("Running with administrator privileges");
        
        // Enable debug privilege for process inspection
        if unsafe { ffi::xdr_enable_debug_privilege() } != 0 {
            info!("Debug privilege enabled successfully");
        } else {
            warn!("Failed to enable debug privilege");
        }
    }
    
    // Initialize subsystems
    crypto::init()?;
    
    info!("XDR userland library initialized successfully");
    Ok(())
}

fn init_logging() -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
    
    // Create a file appender for persistent logging
    let file_appender = tracing_appender::rolling::hourly("C:\\ProgramData\\XDR\\logs", "xdr.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    
    // Set up logging with both console and file output
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    
    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_target(true)
                .with_thread_ids(true)
                .compact()
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_target(true)
                .with_thread_ids(true)
                .json()
        )
        .init();
    
    Ok(())
}

/// Convert Windows FILETIME to Unix timestamp
pub fn filetime_to_unix(filetime: u64) -> u64 {
    unsafe { ffi::xdr_filetime_to_unix(filetime) }
}

/// Convert Windows FILETIME to DateTime<Utc>
pub fn filetime_to_datetime(filetime: u64) -> DateTime<Utc> {
    let unix_timestamp = filetime_to_unix(filetime);
    DateTime::from_timestamp(unix_timestamp as i64, 0)
        .unwrap_or_else(|| Utc::now())
}

/// Get current timestamp in Windows FILETIME format
pub fn current_timestamp() -> u64 {
    unsafe { ffi::xdr_current_timestamp() }
}

/// Compute FNV-1a hash of data
pub fn fnv1a_hash(data: &[u8]) -> u64 {
    unsafe { ffi::xdr_fnv1a_hash(data.as_ptr() as *const std::ffi::c_void, data.len()) }
}

/// Get process information by PID
pub fn get_process_info(pid: u32) -> Result<(String, u32)> {
    let mut image_path = vec![0u16; 512];
    let mut session_id = 0u32;
    
    let result = unsafe {
        ffi::xdr_get_process_info(
            pid,
            image_path.as_mut_ptr(),
            image_path.len(),
            &mut session_id,
        )
    };
    
    if result == 0 {
        return Err(anyhow::anyhow!("Failed to get process info for PID {}", pid));
    }
    
    // Convert UTF-16 to String
    let end_pos = image_path.iter().position(|&c| c == 0).unwrap_or(image_path.len());
    let path = String::from_utf16(&image_path[..end_pos])
        .context("Failed to convert image path from UTF-16")?;
    
    Ok((path, session_id))
}

/// Check if current process is running as administrator
pub fn is_admin() -> bool {
    unsafe { ffi::xdr_is_admin() != 0 }
}

/// Validate an event record structure
pub fn validate_event_record(record: &ffi::XDR_EVENT_RECORD) -> bool {
    unsafe { ffi::xdr_validate_event_record(record as *const _) != 0 }
}

/// Error types for the XDR library
#[derive(thiserror::Error, Debug)]
pub enum XdrError {
    #[error("Driver communication error: {0}")]
    Driver(#[from] driver::DriverError),
    
    #[error("Event processing error: {0}")]
    Event(String),
    
    #[error("Storage error: {0}")]
    Storage(#[from] storage::StorageError),
    
    #[error("Rules engine error: {0}")]
    Rules(#[from] rules::RulesError),
    
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),
    
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Windows API error: {0}")]
    Windows(#[from] windows::core::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Time parsing error: {0}")]
    Time(#[from] chrono::ParseError),
    
    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    
    #[error("UTF-16 conversion error: {0}")]
    Utf16(#[from] std::string::FromUtf16Error),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Resource not found: {0}")]
    NotFound(String),
    
    #[error("Invalid state: {0}")]
    InvalidState(String),
    
    #[error("Timeout: {0}")]
    Timeout(String),
}

pub type XdrResult<T> = Result<T, XdrError>;

/// Common result type for the XDR library
pub type LibResult<T> = Result<T>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        init().expect("Library initialization should succeed");
    }

    #[test]
    fn test_abi_version() {
        let version = unsafe { ffi::xdr_abi_version() };
        assert_eq!(version, ffi::XDR_ABI_VERSION);
    }

    #[test]
    fn test_fnv1a_hash() {
        let data = b"hello world";
        let hash1 = fnv1a_hash(data);
        let hash2 = fnv1a_hash(data);
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, 0);
    }

    #[test]
    fn test_timestamps() {
        let filetime = current_timestamp();
        assert_ne!(filetime, 0);
        
        let unix_ts = filetime_to_unix(filetime);
        assert_ne!(unix_ts, 0);
        
        let dt = filetime_to_datetime(filetime);
        assert!(dt.timestamp() > 0);
    }
}