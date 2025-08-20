//! Driver Communication Module
//! 
//! Provides safe Rust interface to the XDR kernel driver,
//! including shared memory management and IOCTL operations.

use crate::ffi;
use anyhow::{Context, Result};
use std::ffi::c_void;
use std::mem;
use std::ptr;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};
use windows::core::Error as WindowsError;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::{DeviceIoControl, OVERLAPPED};
use windows::Win32::System::Memory::{
    MapViewOfFile, UnmapViewOfFile, FILE_MAP_READ, FILE_MAP_WRITE, VirtualQuery,
    MEMORY_BASIC_INFORMATION, MEM_COMMIT,
};
use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE};

/// Driver-specific error types
#[derive(thiserror::Error, Debug)]
pub enum DriverError {
    #[error("Failed to open driver device: {0}")]
    DeviceOpen(WindowsError),
    
    #[error("IOCTL operation failed: {0}")]
    Ioctl(WindowsError),
    
    #[error("Shared memory mapping failed: {0}")]
    SharedMemory(WindowsError),
    
    #[error("Invalid driver response")]
    InvalidResponse,
    
    #[error("Driver version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u32, actual: u32 },
    
    #[error("Driver not ready or not loaded")]
    NotReady,
    
    #[error("Buffer size insufficient: need {needed}, have {available}")]
    BufferSize { needed: usize, available: usize },
    
    #[error("Shared memory not mapped")]
    NotMapped,
    
    #[error("Ring buffer full")]
    RingBufferFull,
}

/// Driver version information
#[derive(Debug, Clone)]
pub struct DriverVersion {
    pub abi_version: u32,
    pub driver_version: u32,
    pub build_timestamp: u64,
}

/// Driver configuration
#[derive(Debug, Clone)]
pub struct DriverConfig {
    pub min_severity: u32,
    pub source_mask: u32,
    pub max_queue_depth: u32,
    pub heartbeat_interval_ms: u32,
    pub allowlist_hash: u64,
    pub wfp_mode: u32,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            min_severity: ffi::XDR_SEVERITY_LOW,
            source_mask: 0xFF, // All sources enabled
            max_queue_depth: 10000,
            heartbeat_interval_ms: 5000,
            allowlist_hash: 0,
            wfp_mode: 0, // Monitor mode
        }
    }
}

/// Shared memory ring buffer manager
pub struct SharedMemoryRing {
    section_handle: HANDLE,
    event_handle: HANDLE,
    base_address: *mut u8,
    size: usize,
    header: *mut ffi::XDR_SHM_HEADER,
    last_read_index: u64,
}

impl SharedMemoryRing {
    /// Create a new shared memory ring from driver handles
    fn new(section_handle: HANDLE, event_handle: HANDLE, size: u64) -> Result<Self> {
        let base_address = unsafe {
            MapViewOfFile(
                section_handle,
                FILE_MAP_READ | FILE_MAP_WRITE,
                0,
                0,
                size as usize,
            )
        };

        if base_address.is_null() {
            return Err(DriverError::SharedMemory(WindowsError::from_win32()).into());
        }

        let header = base_address as *mut ffi::XDR_SHM_HEADER;

        // Validate shared memory header
        unsafe {
            if (*header).magic != unsafe { ffi::xdr_shm_magic() } {
                UnmapViewOfFile(base_address);
                return Err(DriverError::InvalidResponse.into());
            }

            if (*header).version != ffi::XDR_ABI_VERSION {
                UnmapViewOfFile(base_address);
                return Err(DriverError::VersionMismatch {
                    expected: ffi::XDR_ABI_VERSION,
                    actual: (*header).version as u32,
                }.into());
            }
        }

        Ok(Self {
            section_handle,
            event_handle,
            base_address: base_address as *mut u8,
            size: size as usize,
            header,
            last_read_index: 0,
        })
    }

    /// Get the current write index from the ring buffer
    pub fn write_index(&self) -> u64 {
        unsafe { (*self.header).write_index }
    }

    /// Get the current read index from the ring buffer  
    pub fn read_index(&self) -> u64 {
        unsafe { (*self.header).read_index }
    }

    /// Check if there are new events available
    pub fn has_events(&self) -> bool {
        self.write_index() != self.last_read_index
    }

    /// Wait for new events with timeout
    pub fn wait_for_events(&self, timeout_ms: u32) -> Result<bool> {
        if self.has_events() {
            return Ok(true);
        }

        let result = unsafe { WaitForSingleObject(self.event_handle, timeout_ms) };
        match result.0 {
            0 => Ok(true), // WAIT_OBJECT_0
            258 => Ok(false), // WAIT_TIMEOUT
            _ => Err(DriverError::SharedMemory(WindowsError::from_win32()).into()),
        }
    }

    /// Read the next event from the ring buffer
    pub fn read_event(&mut self) -> Result<Option<ffi::XDR_EVENT_RECORD>> {
        let write_index = self.write_index();
        if self.last_read_index >= write_index {
            return Ok(None);
        }

        let data_start = unsafe { self.base_address.add(mem::size_of::<ffi::XDR_SHM_HEADER>()) };
        let ring_size = unsafe { (*self.header).ring_size as usize };

        // Calculate read position
        let read_pos = (self.last_read_index % ring_size as u64) as usize;
        
        // Read length prefix
        if read_pos + 4 > ring_size {
            // Handle wraparound for length
            warn!("Ring buffer wraparound detected during length read");
            self.last_read_index = write_index; // Skip to current write position
            return Ok(None);
        }

        let length_ptr = unsafe { data_start.add(read_pos) as *const u32 };
        let record_length = unsafe { *length_ptr } as usize;

        // Validate length
        if record_length < mem::size_of::<ffi::XDR_EVENT_HEADER>() 
            || record_length > mem::size_of::<ffi::XDR_EVENT_RECORD>() {
            error!("Invalid record length: {}", record_length);
            self.last_read_index = write_index; // Skip corrupted data
            return Ok(None);
        }

        // Check if we have enough space for the full record
        let total_size = 4 + record_length; // length prefix + record
        if read_pos + total_size > ring_size {
            // Handle wraparound for record data
            warn!("Ring buffer wraparound detected during record read");
            self.last_read_index = write_index;
            return Ok(None);
        }

        // Read the event record
        let record_ptr = unsafe { data_start.add(read_pos + 4) as *const ffi::XDR_EVENT_RECORD };
        let mut event_record = unsafe { ptr::read(record_ptr) };

        // Validate the event record
        if !crate::validate_event_record(&event_record) {
            error!("Invalid event record read from ring buffer");
            self.last_read_index += 8; // Skip ahead aligned
            return Ok(None);
        }

        // Update read index with alignment
        let aligned_size = (total_size + 7) & !7; // 8-byte alignment
        self.last_read_index += aligned_size as u64;

        // Update the shared read index
        unsafe {
            (*self.header).read_index = self.last_read_index;
        }

        debug!("Read event: source={}, severity={}, size={}", 
               event_record.header.source, event_record.header.severity, record_length);

        Ok(Some(event_record))
    }

    /// Get ring buffer statistics
    pub fn get_stats(&self) -> RingBufferStats {
        unsafe {
            RingBufferStats {
                write_index: (*self.header).write_index,
                read_index: (*self.header).read_index,
                total_events: (*self.header).total_events,
                dropped_events: (*self.header).dropped_events,
                ring_size: (*self.header).ring_size,
                max_record_size: (*self.header).max_record_size,
            }
        }
    }
}

impl Drop for SharedMemoryRing {
    fn drop(&mut self) {
        if !self.base_address.is_null() {
            unsafe {
                UnmapViewOfFile(self.base_address as *const c_void);
            }
        }
        
        if self.section_handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.section_handle);
            }
        }
        
        if self.event_handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.event_handle);
            }
        }
    }
}

/// Ring buffer statistics
#[derive(Debug, Clone)]
pub struct RingBufferStats {
    pub write_index: u64,
    pub read_index: u64,
    pub total_events: u64,
    pub dropped_events: [u64; ffi::XDR_SOURCE_MAX as usize],
    pub ring_size: u32,
    pub max_record_size: u32,
}

/// Main driver interface
pub struct XdrDriver {
    device_handle: HANDLE,
    shared_memory: Option<SharedMemoryRing>,
    version: Option<DriverVersion>,
}

impl XdrDriver {
    /// Connect to the XDR driver
    pub fn connect() -> Result<Self> {
        let device_name = "\\\\?\\XdrCore";
        let device_name_wide: Vec<u16> = device_name.encode_utf16().chain(std::iter::once(0)).collect();

        let device_handle = unsafe {
            CreateFileW(
                windows::core::PCWSTR(device_name_wide.as_ptr()),
                windows::Win32::System::IO::FILE_GENERIC_READ | windows::Win32::System::IO::FILE_GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }.map_err(DriverError::DeviceOpen)?;

        if device_handle == INVALID_HANDLE_VALUE {
            return Err(DriverError::DeviceOpen(WindowsError::from_win32()).into());
        }

        let mut driver = Self {
            device_handle,
            shared_memory: None,
            version: None,
        };

        // Get driver version
        driver.version = Some(driver.get_version()?);
        info!("Connected to XDR driver version {}", driver.version.as_ref().unwrap().driver_version);

        Ok(driver)
    }

    /// Get driver version information
    pub fn get_version(&self) -> Result<DriverVersion> {
        let mut output = ffi::XDR_VERSION_OUTPUT {
            abi_version: 0,
            driver_version: 0,
            build_timestamp: 0,
        };

        self.device_io_control(
            unsafe { ffi::xdr_ioctl_get_version() },
            None,
            Some(&mut output),
        )?;

        // Validate ABI version
        if output.abi_version != ffi::XDR_ABI_VERSION {
            return Err(DriverError::VersionMismatch {
                expected: ffi::XDR_ABI_VERSION,
                actual: output.abi_version,
            }.into());
        }

        Ok(DriverVersion {
            abi_version: output.abi_version,
            driver_version: output.driver_version,
            build_timestamp: output.build_timestamp,
        })
    }

    /// Map shared memory for event communication
    pub fn map_shared_memory(&mut self) -> Result<()> {
        if self.shared_memory.is_some() {
            return Ok(()); // Already mapped
        }

        let mut output = ffi::XDR_MAP_SHM_OUTPUT {
            section_handle: INVALID_HANDLE_VALUE,
            section_size: 0,
            event_handle: INVALID_HANDLE_VALUE,
        };

        self.device_io_control(
            unsafe { ffi::xdr_ioctl_map_shm() },
            None::<&()>,
            Some(&mut output),
        )?;

        if output.section_handle == INVALID_HANDLE_VALUE || output.event_handle == INVALID_HANDLE_VALUE {
            return Err(DriverError::InvalidResponse.into());
        }

        let ring = SharedMemoryRing::new(
            output.section_handle,
            output.event_handle,
            output.section_size,
        )?;

        info!("Shared memory mapped: {} bytes", output.section_size);
        self.shared_memory = Some(ring);

        Ok(())
    }

    /// Set driver configuration
    pub fn set_config(&self, config: &DriverConfig) -> Result<()> {
        let driver_config = ffi::XDR_CONFIG {
            min_severity: config.min_severity,
            source_mask: config.source_mask,
            max_queue_depth: config.max_queue_depth,
            heartbeat_interval_ms: config.heartbeat_interval_ms,
            allowlist_hash: config.allowlist_hash,
            wfp_mode: config.wfp_mode,
            reserved: [0; 15],
        };

        self.device_io_control(
            unsafe { ffi::xdr_ioctl_set_config() },
            Some(&driver_config),
            None::<&mut ()>,
        )?;

        debug!("Driver configuration updated: {:?}", config);
        Ok(())
    }

    /// Send a user event to the driver
    pub fn send_user_event(&self, event_type: u32, data: &[u8]) -> Result<()> {
        if data.len() > 512 {
            return Err(DriverError::BufferSize {
                needed: data.len(),
                available: 512,
            }.into());
        }

        let mut user_event = ffi::XDR_USER_EVENT {
            event_type,
            data_size: data.len() as u32,
            data: [0; 512],
        };

        user_event.data[..data.len()].copy_from_slice(data);

        self.device_io_control(
            unsafe { ffi::xdr_ioctl_user_event() },
            Some(&user_event),
            None::<&mut ()>,
        )?;

        debug!("User event sent: type={}, size={}", event_type, data.len());
        Ok(())
    }

    /// Get shared memory reference for event reading
    pub fn shared_memory(&mut self) -> Result<&mut SharedMemoryRing> {
        self.shared_memory.as_mut().ok_or(DriverError::NotMapped.into())
    }

    /// Check if shared memory is mapped
    pub fn is_mapped(&self) -> bool {
        self.shared_memory.is_some()
    }

    /// Get driver version if available
    pub fn version(&self) -> Option<&DriverVersion> {
        self.version.as_ref()
    }

    /// Perform a device I/O control operation
    fn device_io_control<I, O>(&self, ioctl_code: u32, input: Option<&I>, output: Option<&mut O>) -> Result<()> {
        let input_ptr = input.map_or(ptr::null(), |i| i as *const I as *const c_void);
        let input_size = input.map_or(0, |_| mem::size_of::<I>() as u32);
        
        let output_ptr = output.map_or(ptr::null_mut(), |o| o as *mut O as *mut c_void);
        let output_size = output.map_or(0, |_| mem::size_of::<O>() as u32);

        let mut bytes_returned = 0u32;

        let success = unsafe {
            DeviceIoControl(
                self.device_handle,
                ioctl_code,
                Some(input_ptr),
                input_size,
                Some(output_ptr),
                output_size,
                Some(&mut bytes_returned),
                None,
            )
        };

        if !success.as_bool() {
            return Err(DriverError::Ioctl(WindowsError::from_win32()).into());
        }

        debug!("IOCTL 0x{:08X} completed, {} bytes returned", ioctl_code, bytes_returned);
        Ok(())
    }
}

impl Drop for XdrDriver {
    fn drop(&mut self) {
        if self.device_handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.device_handle);
            }
        }
    }
}

/// Thread-safe driver interface
pub type SharedDriver = Arc<Mutex<XdrDriver>>;

/// Create a shared driver instance
pub fn create_shared_driver() -> Result<SharedDriver> {
    let driver = XdrDriver::connect()?;
    Ok(Arc::new(Mutex::new(driver)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_driver_connection() {
        // This test will only work if the driver is loaded
        match XdrDriver::connect() {
            Ok(driver) => {
                assert!(driver.version().is_some());
                println!("Connected to driver version: {:?}", driver.version());
            }
            Err(e) => {
                println!("Driver not available: {}", e);
                // This is expected in test environments
            }
        }
    }

    #[test]
    fn test_config_defaults() {
        let config = DriverConfig::default();
        assert_eq!(config.min_severity, ffi::XDR_SEVERITY_LOW);
        assert_eq!(config.source_mask, 0xFF);
        assert_eq!(config.wfp_mode, 0);
    }
}