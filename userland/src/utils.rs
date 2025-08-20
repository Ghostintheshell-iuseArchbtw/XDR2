//! Utility Functions
//! 
//! Common utilities used throughout the XDR userland service.

use crate::LibResult;
use anyhow::Result;
use std::time::{Duration, Instant};
use tracing::{debug, info};
use windows::Win32::Foundation::{GetLastError, WIN32_ERROR};
use windows::Win32::System::Threading::{GetCurrentProcess, SetPriorityClass, PROCESS_CREATION_FLAGS};

/// Performance timer for measuring execution time
pub struct PerfTimer {
    start: Instant,
    name: String,
}

impl PerfTimer {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            start: Instant::now(),
            name: name.into(),
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.elapsed().as_millis() as u64
    }

    pub fn log_elapsed(&self) {
        debug!("Timer '{}': {}ms", self.name, self.elapsed_ms());
    }
}

impl Drop for PerfTimer {
    fn drop(&mut self) {
        self.log_elapsed();
    }
}

/// Set process priority class
pub fn set_process_priority(priority: &str) -> Result<()> {
    let priority_class = match priority {
        "idle" => PROCESS_CREATION_FLAGS(0x40),
        "below_normal" => PROCESS_CREATION_FLAGS(0x4000),
        "normal" => PROCESS_CREATION_FLAGS(0x20),
        "above_normal" => PROCESS_CREATION_FLAGS(0x8000),
        "high" => PROCESS_CREATION_FLAGS(0x80),
        "realtime" => PROCESS_CREATION_FLAGS(0x100),
        _ => return Err(anyhow::anyhow!("Invalid priority class: {}", priority)),
    };

    unsafe {
        if !SetPriorityClass(GetCurrentProcess(), priority_class).as_bool() {
            let error = GetLastError();
            return Err(anyhow::anyhow!("Failed to set priority class: {:?}", error));
        }
    }

    info!("Process priority set to: {}", priority);
    Ok(())
}

/// Convert Windows error to string
pub fn win32_error_to_string(error: WIN32_ERROR) -> String {
    format!("Win32 Error {}: {}", error.0, error)
}

/// Get system uptime in seconds
pub fn get_system_uptime() -> u64 {
    unsafe {
        windows::Win32::System::SystemInformation::GetTickCount64() / 1000
    }
}

/// Format bytes as human-readable string
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: u64 = 1024;

    if bytes < THRESHOLD {
        return format!("{} B", bytes);
    }

    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= THRESHOLD as f64 && unit_index < UNITS.len() - 1 {
        size /= THRESHOLD as f64;
        unit_index += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_index])
}

/// Format duration as human-readable string
pub fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else if seconds < 86400 {
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        format!("{}h {}m", hours, minutes)
    } else {
        let days = seconds / 86400;
        let hours = (seconds % 86400) / 3600;
        format!("{}d {}h", days, hours)
    }
}

/// Generate a random string of specified length
pub fn generate_random_string(length: usize) -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARS.len());
            CHARS[idx] as char
        })
        .collect()
}

/// Check if a string is a valid GUID
pub fn is_valid_guid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok()
}

/// Safe integer division with rounding
pub fn safe_divide_round(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        (numerator + denominator / 2) / denominator
    }
}

/// Calculate percentage with bounds checking
pub fn calculate_percentage(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (part as f64 / total as f64) * 100.0
    }
}

/// Clamp value between min and max
pub fn clamp<T: PartialOrd>(value: T, min: T, max: T) -> T {
    if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}

/// Retry a function with exponential backoff
pub async fn retry_with_backoff<F, T, E>(
    mut f: F,
    max_attempts: u32,
    initial_delay: Duration,
) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
    E: std::fmt::Display,
{
    let mut delay = initial_delay;
    
    for attempt in 1..=max_attempts {
        match f() {
            Ok(result) => return Ok(result),
            Err(e) => {
                if attempt == max_attempts {
                    return Err(e);
                }
                
                debug!("Attempt {} failed: {}, retrying in {:?}", attempt, e, delay);
                tokio::time::sleep(delay).await;
                delay *= 2; // Exponential backoff
            }
        }
    }
    
    unreachable!()
}

/// Ring buffer utilities
pub mod ring_buffer {
    /// Check if index has wrapped around
    pub fn has_wrapped(current: u64, previous: u64, size: u64) -> bool {
        current < previous && (previous - current) > (size / 2)
    }
    
    /// Calculate available space in ring buffer
    pub fn available_space(write_index: u64, read_index: u64, size: u64) -> u64 {
        if write_index >= read_index {
            size - (write_index - read_index)
        } else {
            read_index - write_index
        }
    }
    
    /// Calculate used space in ring buffer
    pub fn used_space(write_index: u64, read_index: u64, size: u64) -> u64 {
        size - available_space(write_index, read_index, size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m");
        assert_eq!(format_duration(Duration::from_secs(90061)), "1d 1h");
    }

    #[test]
    fn test_calculate_percentage() {
        assert_eq!(calculate_percentage(50, 100), 50.0);
        assert_eq!(calculate_percentage(0, 100), 0.0);
        assert_eq!(calculate_percentage(100, 0), 0.0);
    }

    #[test]
    fn test_clamp() {
        assert_eq!(clamp(5, 0, 10), 5);
        assert_eq!(clamp(-1, 0, 10), 0);
        assert_eq!(clamp(15, 0, 10), 10);
    }

    #[test]
    fn test_ring_buffer_utils() {
        assert_eq!(ring_buffer::available_space(0, 0, 100), 100);
        assert_eq!(ring_buffer::available_space(50, 0, 100), 50);
        assert_eq!(ring_buffer::available_space(0, 50, 100), 50);
        assert_eq!(ring_buffer::used_space(50, 0, 100), 50);
    }

    #[test]
    fn test_is_valid_guid() {
        assert!(is_valid_guid("12345678-1234-5678-9012-123456789012"));
        assert!(!is_valid_guid("not-a-guid"));
        assert!(!is_valid_guid(""));
    }
}