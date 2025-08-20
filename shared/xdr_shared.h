#pragma once

/*
 * XDR Shared ABI Header
 * Single source of truth for kernel-usermode interface
 * All structs use fixed-width types and are packed
 */

#include <stdint.h>

#ifdef _KERNEL_MODE
#include <ntddk.h>
#include <wdf.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

#pragma pack(push, 1)

// ABI Version
#define XDR_ABI_VERSION 1

// Device interface and DOS device name
#define XDR_DEVICE_NAME L"\\Device\\XdrCore"
#define XDR_DOS_DEVICE_NAME L"\\DosDevices\\XdrCore"
#define XDR_USER_DEVICE_NAME L"\\\\.\\XdrCore"

// SDDL for device security - SYSTEM and Administrators only
#define XDR_DEVICE_SDDL L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

// Device type for IOCTLs
#define XDR_DEVICE_TYPE 0x8000

// IOCTLs
#define IOCTL_XDR_GET_VERSION \
    CTL_CODE(XDR_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_XDR_MAP_SHM \
    CTL_CODE(XDR_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_XDR_SET_CONFIG \
    CTL_CODE(XDR_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_XDR_PEEK_FALLBACK \
    CTL_CODE(XDR_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_XDR_DEQUEUE_FALLBACK \
    CTL_CODE(XDR_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_XDR_PUBLISH_EVENT \
    CTL_CODE(XDR_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_XDR_USER_EVENT \
    CTL_CODE(XDR_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Shared memory configuration
#define XDR_SHM_DEFAULT_SIZE (16 * 1024 * 1024)  // 16 MiB
#define XDR_SHM_MIN_SIZE (4 * 1024 * 1024)       // 4 MiB
#define XDR_SHM_MAX_SIZE (64 * 1024 * 1024)      // 64 MiB
#define XDR_SHM_MAGIC 0x52445858                 // "XXDR"

// Event sources
typedef enum _XDR_EVENT_SOURCE {
    XDR_SOURCE_PROCESS = 0,
    XDR_SOURCE_THREAD = 1,
    XDR_SOURCE_IMAGE = 2,
    XDR_SOURCE_REGISTRY = 3,
    XDR_SOURCE_FILE = 4,
    XDR_SOURCE_NETWORK = 5,
    XDR_SOURCE_HEARTBEAT = 6,
    XDR_SOURCE_USER = 7,
    XDR_SOURCE_MAX = 8
} XDR_EVENT_SOURCE;

// Event severity levels
typedef enum _XDR_SEVERITY {
    XDR_SEVERITY_LOW = 0,
    XDR_SEVERITY_MEDIUM = 1,
    XDR_SEVERITY_HIGH = 2,
    XDR_SEVERITY_CRITICAL = 3
} XDR_SEVERITY;

// Event flags
#define XDR_FLAG_SYNTHETIC   0x0001  // Generated event (e.g., drops)
#define XDR_FLAG_TRUNCATED   0x0002  // Data was truncated
#define XDR_FLAG_CORRELATED  0x0004  // Part of a correlation chain

// Maximum path and string lengths
#define XDR_MAX_PATH 512
#define XDR_MAX_STRING 256
#define XDR_MAX_CMDLINE 2048
#define XDR_MAX_REGKEY 512
#define XDR_MAX_REGVALUE 256

// Process operations
typedef enum _XDR_PROCESS_OP {
    XDR_PROCESS_START = 0,
    XDR_PROCESS_EXIT = 1
} XDR_PROCESS_OP;

// Thread operations
typedef enum _XDR_THREAD_OP {
    XDR_THREAD_CREATE = 0,
    XDR_THREAD_EXIT = 1
} XDR_THREAD_OP;

// Registry operations
typedef enum _XDR_REGISTRY_OP {
    XDR_REG_CREATE_KEY = 0,
    XDR_REG_DELETE_KEY = 1,
    XDR_REG_SET_VALUE = 2,
    XDR_REG_DELETE_VALUE = 3,
    XDR_REG_RENAME_KEY = 4,
    XDR_REG_SECURITY_CHANGE = 5
} XDR_REGISTRY_OP;

// File operations
typedef enum _XDR_FILE_OP {
    XDR_FILE_CREATE = 0,
    XDR_FILE_WRITE = 1,
    XDR_FILE_DELETE = 2,
    XDR_FILE_RENAME = 3,
    XDR_FILE_SETINFO = 4
} XDR_FILE_OP;

// Network operations
typedef enum _XDR_NETWORK_OP {
    XDR_NET_CONNECT = 0,
    XDR_NET_ACCEPT = 1,
    XDR_NET_ESTABLISHED = 2,
    XDR_NET_CLOSE = 3,
    XDR_NET_STATS = 4
} XDR_NETWORK_OP;

// Network verdict
typedef enum _XDR_NETWORK_VERDICT {
    XDR_NET_ALLOW = 0,
    XDR_NET_BLOCK = 1,
    XDR_NET_MONITOR = 2
} XDR_NETWORK_VERDICT;

// Common event header (32 bytes)
typedef struct _XDR_EVENT_HEADER {
    uint16_t version;           // XDR_ABI_VERSION
    uint16_t source;            // XDR_EVENT_SOURCE
    uint16_t severity;          // XDR_SEVERITY
    uint16_t flags;             // XDR_FLAG_*
    uint64_t timestamp_100ns;   // Windows FILETIME format
    uint32_t process_id;        // PID
    uint32_t thread_id;         // TID
    uint32_t session_id;        // Session ID
    uint32_t reserved;          // Padding/future use
    uint64_t sequence_number;   // Global sequence
    uint64_t prev_seq_same_key; // Previous sequence for same key
    uint64_t key_hash;          // Stable key hash (FNV1a)
} XDR_EVENT_HEADER;

// Process event payload
typedef struct _XDR_PROCESS_EVENT {
    uint32_t operation;         // XDR_PROCESS_OP
    uint32_t parent_process_id;
    uint32_t integrity_level;   // TOKEN_MANDATORY_LEVEL
    uint32_t token_flags;       // TOKEN_* flags
    uint64_t sid_hash;          // Hash of user SID
    uint64_t cmdline_hash;      // Hash of command line
    uint32_t exit_code;         // For exit events
    uint32_t padding;
    wchar_t image_path[XDR_MAX_PATH];
} XDR_PROCESS_EVENT;

// Thread event payload
typedef struct _XDR_THREAD_EVENT {
    uint32_t operation;         // XDR_THREAD_OP
    uint32_t padding;
    uint64_t start_address;     // Thread start address
    uint64_t owner_image_hash;  // Hash of owning image
    uint32_t exit_code;         // For exit events
    uint32_t padding2;
} XDR_THREAD_EVENT;

// Image load event payload
typedef struct _XDR_IMAGE_EVENT {
    uint64_t base_address;      // Load base
    uint64_t image_size;        // Size in memory
    uint64_t image_hash;        // SHA-256 truncated to 64-bit
    uint32_t is_signed;         // 1 if Authenticode signed
    uint32_t signer_category;   // 0=Windows, 1=Microsoft, 2=3rd party, 3=unsigned
    uint64_t timestamp;         // PE timestamp
    wchar_t image_path[XDR_MAX_PATH];
    wchar_t publisher[XDR_MAX_STRING];
} XDR_IMAGE_EVENT;

// Registry event payload
typedef struct _XDR_REGISTRY_EVENT {
    uint32_t operation;         // XDR_REGISTRY_OP
    uint32_t value_type;        // REG_* type
    uint64_t data_hash;         // Hash of registry data
    uint32_t data_size;         // Size of data
    uint32_t padding;
    wchar_t key_path[XDR_MAX_REGKEY];
    wchar_t value_name[XDR_MAX_REGVALUE];
} XDR_REGISTRY_EVENT;

// File event payload
typedef struct _XDR_FILE_EVENT {
    uint32_t operation;         // XDR_FILE_OP
    uint32_t create_disposition; // FILE_CREATE, FILE_OVERWRITE, etc.
    uint64_t file_size;         // File size
    uint64_t process_image_hash; // Hash of accessing process image
    uint32_t file_attributes;   // FILE_ATTRIBUTE_*
    uint32_t padding;
    wchar_t file_path[XDR_MAX_PATH];
    wchar_t file_extension[16]; // Extracted extension
} XDR_FILE_EVENT;

// Network event payload
typedef struct _XDR_NETWORK_EVENT {
    uint32_t operation;         // XDR_NETWORK_OP
    uint32_t verdict;           // XDR_NETWORK_VERDICT
    uint32_t local_addr;        // IPv4 address (network byte order)
    uint32_t remote_addr;       // IPv4 address (network byte order)
    uint16_t local_port;        // Port (network byte order)
    uint16_t remote_port;       // Port (network byte order)
    uint32_t protocol;          // IPPROTO_TCP, IPPROTO_UDP
    uint32_t direction;         // 0=outbound, 1=inbound
    uint64_t bytes_sent;        // Bytes sent (for stats)
    uint64_t bytes_received;    // Bytes received (for stats)
    uint64_t process_image_hash; // Hash of process image
    uint8_t local_addr_v6[16];  // IPv6 local address
    uint8_t remote_addr_v6[16]; // IPv6 remote address
} XDR_NETWORK_EVENT;

// Heartbeat event payload
typedef struct _XDR_HEARTBEAT_EVENT {
    uint64_t drops_by_source[XDR_SOURCE_MAX]; // Drop counts per source
    uint32_t queue_depth;       // Current ring buffer usage
    uint32_t overruns;          // Ring buffer overrun count
    uint64_t config_hash;       // Hash of current config
    uint64_t events_processed;  // Total events processed
} XDR_HEARTBEAT_EVENT;

// User event payload (for custom events)
typedef struct _XDR_USER_EVENT {
    uint32_t event_type;        // User-defined type
    uint32_t data_size;         // Size of custom data
    uint8_t data[512];          // Custom data payload
} XDR_USER_EVENT;

// Event payload union
typedef union _XDR_EVENT_PAYLOAD {
    XDR_PROCESS_EVENT process;
    XDR_THREAD_EVENT thread;
    XDR_IMAGE_EVENT image;
    XDR_REGISTRY_EVENT registry;
    XDR_FILE_EVENT file;
    XDR_NETWORK_EVENT network;
    XDR_HEARTBEAT_EVENT heartbeat;
    XDR_USER_EVENT user;
} XDR_EVENT_PAYLOAD;

// Complete event record
typedef struct _XDR_EVENT_RECORD {
    uint32_t total_size;        // Size of this record including header
    XDR_EVENT_HEADER header;
    XDR_EVENT_PAYLOAD payload;
} XDR_EVENT_RECORD;

// Shared memory header
typedef struct _XDR_SHM_HEADER {
    uint32_t magic;             // XDR_SHM_MAGIC
    uint16_t version;           // XDR_ABI_VERSION
    uint16_t flags;             // Reserved
    uint64_t write_index;       // Producer index (kernel)
    uint64_t read_index;        // Consumer index (usermode)
    uint64_t dropped_events[XDR_SOURCE_MAX]; // Drop counters per source
    uint32_t ring_size;         // Size of ring buffer in bytes
    uint32_t max_record_size;   // Maximum record size
    uint64_t total_events;      // Total events written
    uint64_t sequence_counter;  // Global sequence counter
} XDR_SHM_HEADER;

// Configuration structure
typedef struct _XDR_CONFIG {
    uint32_t min_severity;      // Minimum severity to log
    uint32_t source_mask;       // Bitmask of enabled sources
    uint32_t max_queue_depth;   // Maximum queue depth before drops
    uint32_t heartbeat_interval_ms; // Heartbeat interval
    uint64_t allowlist_hash;    // Hash of allowlist config
    uint32_t wfp_mode;          // 0=monitor, 1=block
    uint32_t reserved[15];      // Future expansion
} XDR_CONFIG;

// IOCTL input/output structures
typedef struct _XDR_VERSION_OUTPUT {
    uint32_t abi_version;
    uint32_t driver_version;
    uint64_t build_timestamp;
} XDR_VERSION_OUTPUT;

typedef struct _XDR_MAP_SHM_OUTPUT {
    HANDLE section_handle;      // Handle to section object
    uint64_t section_size;      // Size of section
    HANDLE event_handle;        // Event for notifications
} XDR_MAP_SHM_OUTPUT;

typedef struct _XDR_PEEK_OUTPUT {
    uint32_t available_records;
    uint32_t total_size;
    XDR_EVENT_RECORD records[1]; // Variable length
} XDR_PEEK_OUTPUT;

// Function exports for kernel components
#ifdef _KERNEL_MODE
#ifdef __cplusplus
extern "C" {
#endif

// Core driver exports for other kernel components
NTSTATUS XdrPublishEvent(
    _In_ const XDR_EVENT_RECORD* Record
);

NTSTATUS XdrGetAbiVersion(
    _Out_ uint32_t* Version
);

#ifdef __cplusplus
}
#endif
#endif // _KERNEL_MODE

#pragma pack(pop)