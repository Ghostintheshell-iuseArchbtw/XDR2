//! Event Processing Module
//! 
//! Provides high-level event handling, normalization, and correlation
//! for events received from the kernel driver.

use crate::ffi;
use crate::{filetime_to_datetime, LibResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;

/// High-level event source enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventSource {
    Process,
    Thread, 
    Image,
    Registry,
    File,
    Network,
    Heartbeat,
    User,
}

impl From<u16> for EventSource {
    fn from(value: u16) -> Self {
        match value {
            ffi::XDR_SOURCE_PROCESS => EventSource::Process,
            ffi::XDR_SOURCE_THREAD => EventSource::Thread,
            ffi::XDR_SOURCE_IMAGE => EventSource::Image,
            ffi::XDR_SOURCE_REGISTRY => EventSource::Registry,
            ffi::XDR_SOURCE_FILE => EventSource::File,
            ffi::XDR_SOURCE_NETWORK => EventSource::Network,
            ffi::XDR_SOURCE_HEARTBEAT => EventSource::Heartbeat,
            ffi::XDR_SOURCE_USER => EventSource::User,
            _ => EventSource::User, // Default fallback
        }
    }
}

impl fmt::Display for EventSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventSource::Process => write!(f, "process"),
            EventSource::Thread => write!(f, "thread"),
            EventSource::Image => write!(f, "image"),
            EventSource::Registry => write!(f, "registry"),
            EventSource::File => write!(f, "file"),
            EventSource::Network => write!(f, "network"),
            EventSource::Heartbeat => write!(f, "heartbeat"),
            EventSource::User => write!(f, "user"),
        }
    }
}

/// Event severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl From<u16> for Severity {
    fn from(value: u16) -> Self {
        match value {
            ffi::XDR_SEVERITY_LOW => Severity::Low,
            ffi::XDR_SEVERITY_MEDIUM => Severity::Medium,
            ffi::XDR_SEVERITY_HIGH => Severity::High,
            ffi::XDR_SEVERITY_CRITICAL => Severity::Critical,
            _ => Severity::Low, // Default fallback
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// Normalized event envelope that wraps all event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Unique event ID
    pub id: Uuid,
    
    /// Event source
    pub source: EventSource,
    
    /// Event severity
    pub severity: Severity,
    
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Process ID
    pub process_id: u32,
    
    /// Thread ID  
    pub thread_id: u32,
    
    /// Session ID
    pub session_id: u32,
    
    /// Sequence number from driver
    pub sequence_number: u64,
    
    /// Previous sequence number for same key (for correlation)
    pub prev_sequence_number: u64,
    
    /// Stable key hash for correlation
    pub key_hash: u64,
    
    /// Event flags
    pub flags: Vec<String>,
    
    /// Event-specific data
    pub data: EventData,
    
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Event-specific data union
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum EventData {
    Process(ProcessEvent),
    Thread(ThreadEvent),
    Image(ImageEvent),
    Registry(RegistryEvent),
    File(FileEvent),
    Network(NetworkEvent),
    Heartbeat(HeartbeatEvent),
    User(UserEvent),
}

/// Process creation/exit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub operation: ProcessOperation,
    pub parent_process_id: Option<u32>,
    pub image_path: String,
    pub command_line_hash: Option<u64>,
    pub integrity_level: Option<u32>,
    pub token_flags: Option<u32>,
    pub sid_hash: Option<u64>,
    pub exit_code: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessOperation {
    Start,
    Exit,
}

/// Thread creation/exit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadEvent {
    pub operation: ThreadOperation,
    pub start_address: Option<u64>,
    pub owner_image_hash: Option<u64>,
    pub exit_code: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreadOperation {
    Create,
    Exit,
}

/// Image load event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageEvent {
    pub image_path: String,
    pub base_address: u64,
    pub image_size: u64,
    pub image_hash: u64,
    pub is_signed: bool,
    pub signer_category: SignerCategory,
    pub publisher: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignerCategory {
    Windows,
    Microsoft,
    ThirdParty,
    Unsigned,
}

/// Registry operation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEvent {
    pub operation: RegistryOperation,
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_type: Option<u32>,
    pub data_hash: Option<u64>,
    pub data_size: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistryOperation {
    CreateKey,
    DeleteKey,
    SetValue,
    DeleteValue,
    RenameKey,
    SecurityChange,
}

/// File operation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub operation: FileOperation,
    pub file_path: String,
    pub file_extension: Option<String>,
    pub create_disposition: Option<u32>,
    pub file_attributes: Option<u32>,
    pub file_size: Option<u64>,
    pub process_image_hash: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileOperation {
    Create,
    Write,
    Delete,
    Rename,
    SetInfo,
}

/// Network flow event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub operation: NetworkOperation,
    pub verdict: NetworkVerdict,
    pub protocol: u32,
    pub direction: NetworkDirection,
    pub local_address: NetworkAddress,
    pub remote_address: NetworkAddress,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
    pub process_image_hash: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkOperation {
    Connect,
    Accept,
    Established,
    Close,
    Stats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkVerdict {
    Allow,
    Block,
    Monitor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkDirection {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAddress {
    pub ip: std::net::IpAddr,
    pub port: u16,
}

/// Heartbeat/statistics event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatEvent {
    pub drops_by_source: HashMap<EventSource, u64>,
    pub queue_depth: u32,
    pub overruns: u32,
    pub config_hash: u64,
    pub events_processed: u64,
}

/// User-defined event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEvent {
    pub event_type: u32,
    pub data: Vec<u8>,
}

/// Event processor for converting raw driver events to normalized events
pub struct EventProcessor {
    correlation_enabled: bool,
}

impl EventProcessor {
    /// Create a new event processor
    pub fn new() -> Self {
        Self {
            correlation_enabled: true,
        }
    }

    /// Process a raw event from the driver into a normalized event envelope
    pub fn process_event(&self, raw_event: &ffi::XDR_EVENT_RECORD) -> LibResult<EventEnvelope> {
        let source = EventSource::from(raw_event.header.source);
        let severity = Severity::from(raw_event.header.severity);
        let timestamp = filetime_to_datetime(raw_event.header.timestamp_100ns);

        // Parse flags
        let mut flags = Vec::new();
        if raw_event.header.flags & ffi::XDR_FLAG_SYNTHETIC != 0 {
            flags.push("synthetic".to_string());
        }
        if raw_event.header.flags & ffi::XDR_FLAG_TRUNCATED != 0 {
            flags.push("truncated".to_string());
        }
        if raw_event.header.flags & ffi::XDR_FLAG_CORRELATED != 0 {
            flags.push("correlated".to_string());
        }

        // Process event data based on source
        let data = self.process_event_data(source, &raw_event.payload)?;

        // Create metadata
        let mut metadata = HashMap::new();
        metadata.insert("raw_size".to_string(), serde_json::Value::Number(raw_event.total_size.into()));

        Ok(EventEnvelope {
            id: Uuid::new_v4(),
            source,
            severity,
            timestamp,
            process_id: raw_event.header.process_id,
            thread_id: raw_event.header.thread_id,
            session_id: raw_event.header.session_id,
            sequence_number: raw_event.header.sequence_number,
            prev_sequence_number: raw_event.header.prev_seq_same_key,
            key_hash: raw_event.header.key_hash,
            flags,
            data,
            metadata,
        })
    }

    /// Process event data based on source type
    fn process_event_data(&self, source: EventSource, payload: &ffi::XDR_EVENT_PAYLOAD) -> LibResult<EventData> {
        match source {
            EventSource::Process => {
                let proc_event = unsafe { &payload.process };
                Ok(EventData::Process(ProcessEvent {
                    operation: match proc_event.operation {
                        ffi::XDR_PROCESS_START => ProcessOperation::Start,
                        ffi::XDR_PROCESS_EXIT => ProcessOperation::Exit,
                        _ => ProcessOperation::Start,
                    },
                    parent_process_id: if proc_event.parent_process_id != 0 {
                        Some(proc_event.parent_process_id)
                    } else {
                        None
                    },
                    image_path: self.convert_wide_string(&proc_event.image_path),
                    command_line_hash: if proc_event.cmdline_hash != 0 {
                        Some(proc_event.cmdline_hash)
                    } else {
                        None
                    },
                    integrity_level: if proc_event.integrity_level != 0 {
                        Some(proc_event.integrity_level)
                    } else {
                        None
                    },
                    token_flags: if proc_event.token_flags != 0 {
                        Some(proc_event.token_flags)
                    } else {
                        None
                    },
                    sid_hash: if proc_event.sid_hash != 0 {
                        Some(proc_event.sid_hash)
                    } else {
                        None
                    },
                    exit_code: if proc_event.exit_code != 0 {
                        Some(proc_event.exit_code)
                    } else {
                        None
                    },
                }))
            }

            EventSource::Thread => {
                let thread_event = unsafe { &payload.thread };
                Ok(EventData::Thread(ThreadEvent {
                    operation: match thread_event.operation {
                        ffi::XDR_THREAD_CREATE => ThreadOperation::Create,
                        ffi::XDR_THREAD_EXIT => ThreadOperation::Exit,
                        _ => ThreadOperation::Create,
                    },
                    start_address: if thread_event.start_address != 0 {
                        Some(thread_event.start_address)
                    } else {
                        None
                    },
                    owner_image_hash: if thread_event.owner_image_hash != 0 {
                        Some(thread_event.owner_image_hash)
                    } else {
                        None
                    },
                    exit_code: if thread_event.exit_code != 0 {
                        Some(thread_event.exit_code)
                    } else {
                        None
                    },
                }))
            }

            EventSource::Image => {
                let image_event = unsafe { &payload.image };
                Ok(EventData::Image(ImageEvent {
                    image_path: self.convert_wide_string(&image_event.image_path),
                    base_address: image_event.base_address,
                    image_size: image_event.image_size,
                    image_hash: image_event.image_hash,
                    is_signed: image_event.is_signed != 0,
                    signer_category: match image_event.signer_category {
                        ffi::XDR_SIGNER_WINDOWS => SignerCategory::Windows,
                        ffi::XDR_SIGNER_MICROSOFT => SignerCategory::Microsoft,
                        ffi::XDR_SIGNER_THIRD_PARTY => SignerCategory::ThirdParty,
                        _ => SignerCategory::Unsigned,
                    },
                    publisher: {
                        let pub_str = self.convert_wide_string(&image_event.publisher);
                        if pub_str.is_empty() { None } else { Some(pub_str) }
                    },
                    timestamp: if image_event.timestamp != 0 {
                        Some(filetime_to_datetime(image_event.timestamp))
                    } else {
                        None
                    },
                }))
            }

            EventSource::Registry => {
                let reg_event = unsafe { &payload.registry };
                Ok(EventData::Registry(RegistryEvent {
                    operation: match reg_event.operation {
                        ffi::XDR_REG_CREATE_KEY => RegistryOperation::CreateKey,
                        ffi::XDR_REG_DELETE_KEY => RegistryOperation::DeleteKey,
                        ffi::XDR_REG_SET_VALUE => RegistryOperation::SetValue,
                        ffi::XDR_REG_DELETE_VALUE => RegistryOperation::DeleteValue,
                        ffi::XDR_REG_RENAME_KEY => RegistryOperation::RenameKey,
                        ffi::XDR_REG_SECURITY_CHANGE => RegistryOperation::SecurityChange,
                        _ => RegistryOperation::SetValue,
                    },
                    key_path: self.convert_wide_string(&reg_event.key_path),
                    value_name: {
                        let val_str = self.convert_wide_string(&reg_event.value_name);
                        if val_str.is_empty() { None } else { Some(val_str) }
                    },
                    value_type: if reg_event.value_type != 0 {
                        Some(reg_event.value_type)
                    } else {
                        None
                    },
                    data_hash: if reg_event.data_hash != 0 {
                        Some(reg_event.data_hash)
                    } else {
                        None
                    },
                    data_size: if reg_event.data_size != 0 {
                        Some(reg_event.data_size)
                    } else {
                        None
                    },
                }))
            }

            EventSource::File => {
                let file_event = unsafe { &payload.file };
                Ok(EventData::File(FileEvent {
                    operation: match file_event.operation {
                        ffi::XDR_FILE_CREATE => FileOperation::Create,
                        ffi::XDR_FILE_WRITE => FileOperation::Write,
                        ffi::XDR_FILE_DELETE => FileOperation::Delete,
                        ffi::XDR_FILE_RENAME => FileOperation::Rename,
                        ffi::XDR_FILE_SETINFO => FileOperation::SetInfo,
                        _ => FileOperation::Create,
                    },
                    file_path: self.convert_wide_string(&file_event.file_path),
                    file_extension: {
                        let ext_str = self.convert_wide_string(&file_event.file_extension);
                        if ext_str.is_empty() { None } else { Some(ext_str) }
                    },
                    create_disposition: if file_event.create_disposition != 0 {
                        Some(file_event.create_disposition)
                    } else {
                        None
                    },
                    file_attributes: if file_event.file_attributes != 0 {
                        Some(file_event.file_attributes)
                    } else {
                        None
                    },
                    file_size: if file_event.file_size != 0 {
                        Some(file_event.file_size)
                    } else {
                        None
                    },
                    process_image_hash: if file_event.process_image_hash != 0 {
                        Some(file_event.process_image_hash)
                    } else {
                        None
                    },
                }))
            }

            EventSource::Network => {
                let net_event = unsafe { &payload.network };
                
                // Determine IP addresses
                let local_ip = if net_event.local_addr != 0 {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(net_event.local_addr)))
                } else {
                    // Try IPv6
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(net_event.local_addr_v6))
                };

                let remote_ip = if net_event.remote_addr != 0 {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(net_event.remote_addr)))
                } else {
                    // Try IPv6  
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(net_event.remote_addr_v6))
                };

                Ok(EventData::Network(NetworkEvent {
                    operation: match net_event.operation {
                        ffi::XDR_NET_CONNECT => NetworkOperation::Connect,
                        ffi::XDR_NET_ACCEPT => NetworkOperation::Accept,
                        ffi::XDR_NET_ESTABLISHED => NetworkOperation::Established,
                        ffi::XDR_NET_CLOSE => NetworkOperation::Close,
                        ffi::XDR_NET_STATS => NetworkOperation::Stats,
                        _ => NetworkOperation::Connect,
                    },
                    verdict: match net_event.verdict {
                        ffi::XDR_NET_ALLOW => NetworkVerdict::Allow,
                        ffi::XDR_NET_BLOCK => NetworkVerdict::Block,
                        ffi::XDR_NET_MONITOR => NetworkVerdict::Monitor,
                        _ => NetworkVerdict::Allow,
                    },
                    protocol: net_event.protocol,
                    direction: if net_event.direction == 0 {
                        NetworkDirection::Outbound
                    } else {
                        NetworkDirection::Inbound
                    },
                    local_address: NetworkAddress {
                        ip: local_ip,
                        port: u16::from_be(net_event.local_port),
                    },
                    remote_address: NetworkAddress {
                        ip: remote_ip,
                        port: u16::from_be(net_event.remote_port),
                    },
                    bytes_sent: if net_event.bytes_sent != 0 {
                        Some(net_event.bytes_sent)
                    } else {
                        None
                    },
                    bytes_received: if net_event.bytes_received != 0 {
                        Some(net_event.bytes_received)
                    } else {
                        None
                    },
                    process_image_hash: if net_event.process_image_hash != 0 {
                        Some(net_event.process_image_hash)
                    } else {
                        None
                    },
                }))
            }

            EventSource::Heartbeat => {
                let hb_event = unsafe { &payload.heartbeat };
                
                let mut drops_map = HashMap::new();
                for (i, &count) in hb_event.drops_by_source.iter().enumerate() {
                    if i < ffi::XDR_SOURCE_MAX as usize {
                        let source = EventSource::from(i as u16);
                        drops_map.insert(source, count);
                    }
                }

                Ok(EventData::Heartbeat(HeartbeatEvent {
                    drops_by_source: drops_map,
                    queue_depth: hb_event.queue_depth,
                    overruns: hb_event.overruns,
                    config_hash: hb_event.config_hash,
                    events_processed: hb_event.events_processed,
                }))
            }

            EventSource::User => {
                let user_event = unsafe { &payload.user };
                let data_len = std::cmp::min(user_event.data_size as usize, 512);
                Ok(EventData::User(UserEvent {
                    event_type: user_event.event_type,
                    data: user_event.data[..data_len].to_vec(),
                }))
            }
        }
    }

    /// Convert a wide string (UTF-16) to String
    fn convert_wide_string(&self, wide_chars: &[u16]) -> String {
        // Find null terminator
        let end_pos = wide_chars.iter().position(|&c| c == 0).unwrap_or(wide_chars.len());
        
        // Convert to String
        String::from_utf16(&wide_chars[..end_pos]).unwrap_or_else(|_| {
            // Fallback for invalid UTF-16
            format!("[[INVALID_UTF16_{}]]", end_pos)
        })
    }
}

impl Default for EventProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_source_conversion() {
        assert_eq!(EventSource::from(ffi::XDR_SOURCE_PROCESS), EventSource::Process);
        assert_eq!(EventSource::from(ffi::XDR_SOURCE_FILE), EventSource::File);
        assert_eq!(EventSource::from(999), EventSource::User); // Fallback
    }

    #[test]
    fn test_severity_conversion() {
        assert_eq!(Severity::from(ffi::XDR_SEVERITY_LOW), Severity::Low);
        assert_eq!(Severity::from(ffi::XDR_SEVERITY_CRITICAL), Severity::Critical);
        assert_eq!(Severity::from(999), Severity::Low); // Fallback
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_event_processor_creation() {
        let processor = EventProcessor::new();
        assert!(processor.correlation_enabled);
    }
}