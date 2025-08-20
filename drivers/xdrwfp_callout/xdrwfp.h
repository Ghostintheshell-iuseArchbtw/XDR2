#pragma once

#include <ntddk.h>
#include <wsk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ntstrsafe.h>
#include "../../shared/xdr_shared.h"

// Pool tags
#define XDRWFP_POOL_TAG 'PFDX'
#define XDRWFP_FLOW_TAG 'FLDX'
#define XDRWFP_CTX_TAG 'CTDX'

// Sublayer and callout GUIDs
// {12345678-1234-5678-9012-123456789012}
DEFINE_GUID(XDRWFP_SUBLAYER_GUID,
    0x12345678, 0x1234, 0x5678, 0x90, 0x12, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12);

// {87654321-4321-8765-2109-876543210987}
DEFINE_GUID(XDRWFP_CALLOUT_CONNECT_V4_GUID,
    0x87654321, 0x4321, 0x8765, 0x21, 0x09, 0x87, 0x65, 0x43, 0x21, 0x09, 0x87);

// {87654321-4321-8765-2109-876543210988}
DEFINE_GUID(XDRWFP_CALLOUT_CONNECT_V6_GUID,
    0x87654321, 0x4321, 0x8765, 0x21, 0x09, 0x87, 0x65, 0x43, 0x21, 0x09, 0x88);

// {87654321-4321-8765-2109-876543210989}
DEFINE_GUID(XDRWFP_CALLOUT_ACCEPT_V4_GUID,
    0x87654321, 0x4321, 0x8765, 0x21, 0x09, 0x87, 0x65, 0x43, 0x21, 0x09, 0x89);

// {87654321-4321-8765-2109-876543210990}
DEFINE_GUID(XDRWFP_CALLOUT_ACCEPT_V6_GUID,
    0x87654321, 0x4321, 0x8765, 0x21, 0x09, 0x87, 0x65, 0x43, 0x21, 0x09, 0x90);

// {87654321-4321-8765-2109-876543210991}
DEFINE_GUID(XDRWFP_CALLOUT_FLOW_V4_GUID,
    0x87654321, 0x4321, 0x8765, 0x21, 0x09, 0x87, 0x65, 0x43, 0x21, 0x09, 0x91);

// {87654321-4321-8765-2109-876543210992}
DEFINE_GUID(XDRWFP_CALLOUT_FLOW_V6_GUID,
    0x87654321, 0x4321, 0x8765, 0x21, 0x09, 0x87, 0x65, 0x43, 0x21, 0x09, 0x92);

// Maximum number of flows to track
#define XDRWFP_MAX_FLOWS 10000

// Flow tracking interval (milliseconds)
#define XDRWFP_FLOW_STATS_INTERVAL 5000

// Flow context structure
typedef struct _XDRWFP_FLOW_CONTEXT {
    LIST_ENTRY ListEntry;
    UINT64 FlowId;
    UINT16 LayerId;
    UINT32 ProcessId;
    UINT64 ProcessImageHash;
    
    // Network 5-tuple
    UINT32 Protocol;
    UINT32 LocalAddrV4;
    UINT32 RemoteAddrV4;
    UINT8 LocalAddrV6[16];
    UINT8 RemoteAddrV6[16];
    UINT16 LocalPort;
    UINT16 RemotePort;
    
    // Flow statistics
    UINT64 BytesSent;
    UINT64 BytesReceived;
    UINT64 PacketsSent;
    UINT64 PacketsReceived;
    
    // Timestamps
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER LastActivity;
    
    // Flags
    BOOLEAN IsIPv6;
    BOOLEAN IsInbound;
    BOOLEAN IsBlocked;
    BOOLEAN StatsReported;
    
} XDRWFP_FLOW_CONTEXT, *PXDRWFP_FLOW_CONTEXT;

// Global driver data
typedef struct _XDRWFP_DATA {
    HANDLE EngineHandle;
    UINT32 CalloutIdConnectV4;
    UINT32 CalloutIdConnectV6;
    UINT32 CalloutIdAcceptV4;
    UINT32 CalloutIdAcceptV6;
    UINT32 CalloutIdFlowV4;
    UINT32 CalloutIdFlowV6;
    
    // Core driver communication
    PDEVICE_OBJECT CoreDeviceObject;
    PFILE_OBJECT CoreFileObject;
    BOOLEAN Connected;
    KSPIN_LOCK ConnectionLock;
    
    // Flow tracking
    LIST_ENTRY FlowList;
    KSPIN_LOCK FlowListLock;
    ULONG FlowCount;
    
    // Configuration
    BOOLEAN MonitorMode;        // TRUE = monitor only, FALSE = can block
    BOOLEAN LogLoopback;        // Log loopback connections
    BOOLEAN LogSystemProcesses; // Log system process connections
    
    // Statistics
    UINT64 TotalConnections;
    UINT64 TotalAccepts;
    UINT64 TotalFlows;
    UINT64 DroppedEvents;
    UINT64 BlockedConnections;
    
    // Timer for periodic stats reporting
    KTIMER StatsTimer;
    KDPC StatsDpc;
    BOOLEAN TimerActive;
    
} XDRWFP_DATA, *PXDRWFP_DATA;

// Global data
extern XDRWFP_DATA g_WfpData;

// Function prototypes

// Driver entry and unload
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

VOID XdrwfpUnload(
    _In_ PDRIVER_OBJECT DriverObject
);

// WFP engine management
NTSTATUS XdrwfpOpenEngine(VOID);

VOID XdrwfpCloseEngine(VOID);

NTSTATUS XdrwfpRegisterCallouts(VOID);

NTSTATUS XdrwfpUnregisterCallouts(VOID);

NTSTATUS XdrwfpAddFilters(VOID);

NTSTATUS XdrwfpRemoveFilters(VOID);

// Callout functions
VOID NTAPI XdrwfpClassifyConnect(
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT* ClassifyOut
);

VOID NTAPI XdrwfpClassifyAccept(
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT* ClassifyOut
);

VOID NTAPI XdrwfpClassifyFlow(
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT* ClassifyOut
);

NTSTATUS NTAPI XdrwfpNotifyConnect(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _Inout_ FWPS_FILTER* Filter
);

NTSTATUS NTAPI XdrwfpNotifyAccept(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _Inout_ FWPS_FILTER* Filter
);

NTSTATUS NTAPI XdrwfpNotifyFlow(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _Inout_ FWPS_FILTER* Filter
);

VOID NTAPI XdrwfpFlowDelete(
    _In_ UINT16 LayerId,
    _In_ UINT32 CalloutId,
    _In_ UINT64 FlowContext
);

// Flow management
NTSTATUS XdrwfpCreateFlowContext(
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues,
    _In_ UINT64 FlowId,
    _In_ UINT16 LayerId,
    _Out_ PXDRWFP_FLOW_CONTEXT* FlowContext
);

VOID XdrwfpDeleteFlowContext(
    _In_ PXDRWFP_FLOW_CONTEXT FlowContext
);

PXDRWFP_FLOW_CONTEXT XdrwfpFindFlowContext(
    _In_ UINT64 FlowId
);

VOID XdrwfpUpdateFlowStats(
    _In_ PXDRWFP_FLOW_CONTEXT FlowContext,
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues
);

// Event generation
NTSTATUS XdrwfpGenerateNetworkEvent(
    _In_ XDR_NETWORK_OP Operation,
    _In_ XDR_NETWORK_VERDICT Verdict,
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues,
    _In_opt_ PXDRWFP_FLOW_CONTEXT FlowContext
);

// Core driver communication
NTSTATUS XdrwfpConnectToCore(VOID);

VOID XdrwfpDisconnectFromCore(VOID);

NTSTATUS XdrwfpPublishEventToCore(
    _In_ const XDR_EVENT_RECORD* EventRecord
);

// Utility functions
BOOLEAN XdrwfpShouldIgnoreFlow(
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues
);

BOOLEAN XdrwfpIsLoopback(
    _In_ const FWPS_INCOMING_VALUES* InFixedValues
);

BOOLEAN XdrwfpIsSystemProcess(
    _In_ UINT64 ProcessId
);

NTSTATUS XdrwfpGetProcessImageHash(
    _In_ UINT64 ProcessId,
    _Out_ PUINT64 ImageHash
);

VOID XdrwfpExtractNetworkInfo(
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues,
    _Out_ XDR_NETWORK_EVENT* NetworkEvent
);

// Statistics and reporting
VOID XdrwfpStatsTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);

VOID XdrwfpStartStatsTimer(VOID);

VOID XdrwfpStopStatsTimer(VOID);

NTSTATUS XdrwfpReportFlowStats(VOID);

// Configuration
BOOLEAN XdrwfpShouldBlockFlow(
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues
);

// Debugging macros
#define XdrwfpDbgPrint(Level, Format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, Level, "[XDRWFP] " Format "\n", ##__VA_ARGS__)

#ifdef DBG
#define XdrwfpDebugPrint(Format, ...) \
    XdrwfpDbgPrint(DPFLTR_INFO_LEVEL, Format, ##__VA_ARGS__)
#else
#define XdrwfpDebugPrint(Format, ...)
#endif

#define XdrwfpErrorPrint(Format, ...) \
    XdrwfpDbgPrint(DPFLTR_ERROR_LEVEL, "ERROR: " Format, ##__VA_ARGS__)

#define XdrwfpWarningPrint(Format, ...) \
    XdrwfpDbgPrint(DPFLTR_WARNING_LEVEL, "WARNING: " Format, ##__VA_ARGS__)

#define XdrwfpInfoPrint(Format, ...) \
    XdrwfpDbgPrint(DPFLTR_INFO_LEVEL, Format, ##__VA_ARGS__)

// Helper macros for IP address handling
#define XDRWFP_IS_IPV4_LAYER(layerId) \
    ((layerId) == FWPS_LAYER_ALE_AUTH_CONNECT_V4 || \
     (layerId) == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 || \
     (layerId) == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4)

#define XDRWFP_IS_IPV6_LAYER(layerId) \
    ((layerId) == FWPS_LAYER_ALE_AUTH_CONNECT_V6 || \
     (layerId) == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6 || \
     (layerId) == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6)

// Constants
#define XDRWFP_CALLOUT_DISPLAY_NAME L"XDR Network Monitor"
#define XDRWFP_CALLOUT_DESCRIPTION L"XDR Network Activity Monitor Callout"
#define XDRWFP_SUBLAYER_NAME L"XDR Network Monitor Sublayer"
#define XDRWFP_SUBLAYER_DESCRIPTION L"XDR Network Activity Monitor Sublayer"

// Filter weights (higher weight = higher priority)
#define XDRWFP_FILTER_WEIGHT_CONNECT 0x8
#define XDRWFP_FILTER_WEIGHT_ACCEPT 0x8
#define XDRWFP_FILTER_WEIGHT_FLOW 0x8