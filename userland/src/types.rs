use serde::{Deserialize, Serialize};

/// High-level event source enumeration independent of FFI.
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

/// Event severity levels independent of FFI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}
