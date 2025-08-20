#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include "../../shared/xdr_shared.h"
#include "trace.h"

// Driver tags for pool allocation
#define XDR_POOL_TAG 'RRDX'
#define XDR_EVENT_TAG 'EVDX'
#define XDR_CONFIG_TAG 'CFDX'

// Maximum number of pending events in queue
#define XDR_MAX_PENDING_EVENTS 10000

// Ring buffer implementation
typedef struct _XDR_RING_BUFFER {
    PVOID BaseAddress;              // Mapped view of section
    SIZE_T Size;                    // Total size of ring buffer
    volatile LONG64 WriteIndex;     // Producer index (atomic)
    volatile LONG64 ReadIndex;      // Consumer index (atomic)
    PMDL SectionMdl;               // MDL for the section
    PVOID SectionObject;           // Section object
    HANDLE SectionHandle;          // Section handle
    KEVENT* NotificationEvent;     // Event to signal usermode
    HANDLE NotificationEventHandle; // Handle to notification event
    XDR_SHM_HEADER* Header;        // Shared memory header
} XDR_RING_BUFFER, *PXDR_RING_BUFFER;

// Device context
typedef struct _XDR_DEVICE_CONTEXT {
    WDFDEVICE Device;
    WDFQUEUE DefaultQueue;
    XDR_RING_BUFFER RingBuffer;
    XDR_CONFIG Config;
    KSPIN_LOCK ConfigLock;
    LONG64 SequenceCounter;
    LONG64 TotalEvents;
    PKPROCESS UserProcess;          // Process that mapped SHM
    BOOLEAN ShmMapped;
    
    // Callback registration status
    BOOLEAN ProcessCallbackRegistered;
    BOOLEAN ThreadCallbackRegistered;
    BOOLEAN ImageCallbackRegistered;
    BOOLEAN RegistryCallbackRegistered;
    LARGE_INTEGER CmCookie;         // Registry callback cookie
    
    // Statistics
    LONG64 DroppedEvents[XDR_SOURCE_MAX];
    KSPIN_LOCK StatsLock;
    
    // Lookaside lists for event allocation
    NPAGED_LOOKASIDE_LIST EventLookaside;
    
} XDR_DEVICE_CONTEXT, *PXDR_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(XDR_DEVICE_CONTEXT, XdrGetDeviceContext)

// Function prototypes
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD XdrEvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP XdrEvtDriverContextCleanup;
EVT_WDF_DEVICE_CONTEXT_CLEANUP XdrEvtDeviceContextCleanup;

// Device I/O event handlers
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL XdrEvtIoDeviceControl;

// IOCTL handlers
NTSTATUS XdrHandleGetVersion(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength
);

NTSTATUS XdrHandleMapShm(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength
);

NTSTATUS XdrHandleSetConfig(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength
);

NTSTATUS XdrHandlePeekFallback(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength
);

NTSTATUS XdrHandleDequeueFallback(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength
);

NTSTATUS XdrHandlePublishEvent(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength
);

NTSTATUS XdrHandleUserEvent(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength
);

// Ring buffer operations
NTSTATUS XdrInitializeRingBuffer(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ SIZE_T Size
);

VOID XdrCleanupRingBuffer(
    _In_ PXDR_RING_BUFFER RingBuffer
);

NTSTATUS XdrEnqueueEvent(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ const XDR_EVENT_RECORD* Record
);

BOOLEAN XdrIsRingBufferFull(
    _In_ PXDR_RING_BUFFER RingBuffer,
    _In_ ULONG RecordSize
);

// Event generation and normalization
NTSTATUS XdrNormalizeAndEnqueue(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ XDR_EVENT_SOURCE Source,
    _In_ XDR_SEVERITY Severity,
    _In_ ULONG ProcessId,
    _In_ ULONG ThreadId,
    _In_ const XDR_EVENT_PAYLOAD* Payload,
    _In_ ULONG64 KeyHash
);

ULONG64 XdrComputeKeyHash(
    _In_ const VOID* Data,
    _In_ SIZE_T Length
);

VOID XdrGetCurrentTimeStamp(
    _Out_ PLARGE_INTEGER TimeStamp
);

// Callback routines
VOID XdrProcessCreateNotifyRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

VOID XdrThreadCreateNotifyRoutine(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
);

VOID XdrImageLoadNotifyRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
);

NTSTATUS XdrRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
);

// Utility functions
NTSTATUS XdrRegisterCallbacks(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext
);

VOID XdrUnregisterCallbacks(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext
);

BOOLEAN XdrShouldLogEvent(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ XDR_EVENT_SOURCE Source,
    _In_ XDR_SEVERITY Severity
);

NTSTATUS XdrCreateSecurityDescriptor(
    _Out_ PSECURITY_DESCRIPTOR* SecurityDescriptor
);

VOID XdrIncrementDropCounter(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ XDR_EVENT_SOURCE Source
);

// Hash function (FNV-1a)
ULONG64 XdrFnv1aHash(
    _In_ const VOID* Data,
    _In_ SIZE_T Length
);

// Process/image utilities
NTSTATUS XdrGetProcessImagePath(
    _In_ PEPROCESS Process,
    _Out_ PUNICODE_STRING ImagePath
);

NTSTATUS XdrGetProcessCommandLine(
    _In_ PEPROCESS Process,
    _Out_ PULONG64 CommandLineHash
);

ULONG XdrGetProcessIntegrityLevel(
    _In_ PEPROCESS Process
);

NTSTATUS XdrGetImageSignatureInfo(
    _In_ PUNICODE_STRING ImagePath,
    _Out_ PULONG IsSigned,
    _Out_ PULONG SignerCategory
);

// Registry utilities
NTSTATUS XdrGetRegistryKeyPath(
    _In_ PVOID Object,
    _Out_ PUNICODE_STRING KeyPath
);

// Network utilities (for future WFP integration)
NTSTATUS XdrClassifyNetworkFlow(
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues,
    _Out_ XDR_NETWORK_EVENT* NetworkEvent
);

// Constants for image signature categorization
#define XDR_SIGNER_WINDOWS 0
#define XDR_SIGNER_MICROSOFT 1
#define XDR_SIGNER_THIRD_PARTY 2
#define XDR_SIGNER_UNSIGNED 3

// Registry hive mappings
#define XDR_HIVE_HKLM L"HKEY_LOCAL_MACHINE"
#define XDR_HIVE_HKCU L"HKEY_CURRENT_USER"
#define XDR_HIVE_HKU L"HKEY_USERS"
#define XDR_HIVE_HKCR L"HKEY_CLASSES_ROOT"

// Noise reduction thresholds
#define XDR_PROCESS_BURST_THRESHOLD_MS 100
#define XDR_MAX_EVENTS_PER_BURST 10