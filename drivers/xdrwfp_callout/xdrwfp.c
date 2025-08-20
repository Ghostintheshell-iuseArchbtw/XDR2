//
// XDR WFP Callout Driver
// Monitors network flows and publishes events to core driver
//

#include "xdrwfp.h"
#include "xdrwfp_wire.h"

// Global driver data
XDRWFP_DATA g_WfpData = {0};

//
// Driver entry point
//
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    XdrwfpInfoPrint("XDR WFP Callout Driver loading...");

    // Initialize global data
    RtlZeroMemory(&g_WfpData, sizeof(g_WfpData));
    InitializeListHead(&g_WfpData.FlowList);
    KeInitializeSpinLock(&g_WfpData.FlowListLock);
    KeInitializeSpinLock(&g_WfpData.ConnectionLock);
    
    // Default configuration
    g_WfpData.MonitorMode = TRUE;        // Start in monitor-only mode
    g_WfpData.LogLoopback = FALSE;       // Don't log loopback by default
    g_WfpData.LogSystemProcesses = FALSE; // Don't log system processes by default

    // Set unload routine
    DriverObject->DriverUnload = XdrwfpUnload;

    // Open WFP engine
    status = XdrwfpOpenEngine();
    if (!NT_SUCCESS(status)) {
        XdrwfpErrorPrint("Failed to open WFP engine: 0x%08X", status);
        return status;
    }

    // Register callouts
    status = XdrwfpRegisterCallouts();
    if (!NT_SUCCESS(status)) {
        XdrwfpErrorPrint("Failed to register callouts: 0x%08X", status);
        XdrwfpCloseEngine();
        return status;
    }

    // Add filters
    status = XdrwfpAddFilters();
    if (!NT_SUCCESS(status)) {
        XdrwfpErrorPrint("Failed to add filters: 0x%08X", status);
        XdrwfpUnregisterCallouts();
        XdrwfpCloseEngine();
        return status;
    }

    // Connect to core driver
    status = XdrwfpConnectToCore();
    if (!NT_SUCCESS(status)) {
        XdrwfpWarningPrint("Failed to connect to core driver: 0x%08X", status);
        // Continue without core connection - we'll retry later
    }

    // Start statistics timer
    XdrwfpStartStatsTimer();

    XdrwfpInfoPrint("XDR WFP Callout Driver loaded successfully");
    return STATUS_SUCCESS;
}

//
// Driver unload routine
//
VOID
XdrwfpUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    PLIST_ENTRY entry;
    PXDRWFP_FLOW_CONTEXT flowContext;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(DriverObject);

    XdrwfpInfoPrint("XDR WFP Callout Driver unloading...");

    // Stop statistics timer
    XdrwfpStopStatsTimer();

    // Disconnect from core driver
    XdrwfpDisconnectFromCore();

    // Remove filters and unregister callouts
    XdrwfpRemoveFilters();
    XdrwfpUnregisterCallouts();

    // Close WFP engine
    XdrwfpCloseEngine();

    // Clean up flow contexts
    KeAcquireSpinLock(&g_WfpData.FlowListLock, &oldIrql);
    while (!IsListEmpty(&g_WfpData.FlowList)) {
        entry = RemoveHeadList(&g_WfpData.FlowList);
        flowContext = CONTAINING_RECORD(entry, XDRWFP_FLOW_CONTEXT, ListEntry);
        g_WfpData.FlowCount--;
        KeReleaseSpinLock(&g_WfpData.FlowListLock, oldIrql);
        
        ExFreePoolWithTag(flowContext, XDRWFP_FLOW_TAG);
        
        KeAcquireSpinLock(&g_WfpData.FlowListLock, &oldIrql);
    }
    KeReleaseSpinLock(&g_WfpData.FlowListLock, oldIrql);

    XdrwfpInfoPrint("XDR WFP Callout Driver unloaded");
}

//
// Open WFP engine
//
NTSTATUS
XdrwfpOpenEngine(VOID)
{
    NTSTATUS status;

    status = FwpmEngineOpen(NULL,
                          RPC_C_AUTHN_DEFAULT,
                          NULL,
                          NULL,
                          &g_WfpData.EngineHandle);

    if (!NT_SUCCESS(status)) {
        XdrwfpErrorPrint("FwpmEngineOpen failed: 0x%08X", status);
        return status;
    }

    XdrwfpDebugPrint("WFP engine opened successfully");
    return STATUS_SUCCESS;
}

//
// Close WFP engine
//
VOID
XdrwfpCloseEngine(VOID)
{
    if (g_WfpData.EngineHandle) {
        FwpmEngineClose(g_WfpData.EngineHandle);
        g_WfpData.EngineHandle = NULL;
        XdrwfpDebugPrint("WFP engine closed");
    }
}

//
// Register callouts with WFP
//
NTSTATUS
XdrwfpRegisterCallouts(VOID)
{
    NTSTATUS status;
    FWPS_CALLOUT callout = {0};

    // Register connect callout for IPv4
    callout.calloutKey = XDRWFP_CALLOUT_CONNECT_V4_GUID;
    callout.displayData.name = XDRWFP_CALLOUT_DISPLAY_NAME;
    callout.displayData.description = XDRWFP_CALLOUT_DESCRIPTION;
    callout.applicableLayer = FWPS_LAYER_ALE_AUTH_CONNECT_V4;
    callout.classifyFn = XdrwfpClassifyConnect;
    callout.notifyFn = XdrwfpNotifyConnect;
    callout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister(NULL, &callout, &g_WfpData.CalloutIdConnectV4);
    if (!NT_SUCCESS(status)) {
        XdrwfpErrorPrint("Failed to register connect v4 callout: 0x%08X", status);
        return status;
    }

    // Register connect callout for IPv6
    callout.calloutKey = XDRWFP_CALLOUT_CONNECT_V6_GUID;
    callout.applicableLayer = FWPS_LAYER_ALE_AUTH_CONNECT_V6;

    status = FwpsCalloutRegister(NULL, &callout, &g_WfpData.CalloutIdConnectV6);
    if (!NT_SUCCESS(status)) {
        XdrwfpErrorPrint("Failed to register connect v6 callout: 0x%08X", status);
        return status;
    }

    // Register accept callout for IPv4
    callout.calloutKey = XDRWFP_CALLOUT_ACCEPT_V4_GUID;
    callout.applicableLayer = FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
    callout.classifyFn = XdrwfpClassifyAccept;
    callout.notifyFn = XdrwfpNotifyAccept;

    status = FwpsCalloutRegister(NULL, &callout, &g_WfpData.CalloutIdAcceptV4);
    if (!NT_SUCCESS(status)) {
        XdrwfpErrorPrint("Failed to register accept v4 callout: 0x%08X", status);
        return status;
    }

    // Register accept callout for IPv6
    callout.calloutKey = XDRWFP_CALLOUT_ACCEPT_V6_GUID;
    callout.applicableLayer = FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6;

    status = FwpsCalloutRegister(NULL, &callout, &g_WfpData.CalloutIdAcceptV6);
    if (!NT_SUCCESS(status)) {
        XdrwfpErrorPrint("Failed to register accept v6 callout: 0x%08X", status);
        return status;
    }

    // Register flow established callout for IPv4
    callout.calloutKey = XDRWFP_CALLOUT_FLOW_V4_GUID;
    callout.applicableLayer = FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4;
    callout.classifyFn = XdrwfpClassifyFlow;
    callout.notifyFn = XdrwfpNotifyFlow;
    callout.flowDeleteFn = XdrwfpFlowDelete;

    status = FwpsCalloutRegister(NULL, &callout, &g_WfpData.CalloutIdFlowV4);
    if (!NT_SUCCESS(status)) {
        XdrwfpErrorPrint("Failed to register flow v4 callout: 0x%08X", status);
        return status;
    }

    // Register flow established callout for IPv6
    callout.calloutKey = XDRWFP_CALLOUT_FLOW_V6_GUID;
    callout.applicableLayer = FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6;

    status = FwpsCalloutRegister(NULL, &callout, &g_WfpData.CalloutIdFlowV6);
    if (!NT_SUCCESS(status)) {
        XdrwfpErrorPrint("Failed to register flow v6 callout: 0x%08X", status);
        return status;
    }

    XdrwfpDebugPrint("All callouts registered successfully");
    return STATUS_SUCCESS;
}

//
// Unregister callouts
//
NTSTATUS
XdrwfpUnregisterCallouts(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (g_WfpData.CalloutIdFlowV6) {
        FwpsCalloutUnregisterById(g_WfpData.CalloutIdFlowV6);
        g_WfpData.CalloutIdFlowV6 = 0;
    }

    if (g_WfpData.CalloutIdFlowV4) {
        FwpsCalloutUnregisterById(g_WfpData.CalloutIdFlowV4);
        g_WfpData.CalloutIdFlowV4 = 0;
    }

    if (g_WfpData.CalloutIdAcceptV6) {
        FwpsCalloutUnregisterById(g_WfpData.CalloutIdAcceptV6);
        g_WfpData.CalloutIdAcceptV6 = 0;
    }

    if (g_WfpData.CalloutIdAcceptV4) {
        FwpsCalloutUnregisterById(g_WfpData.CalloutIdAcceptV4);
        g_WfpData.CalloutIdAcceptV4 = 0;
    }

    if (g_WfpData.CalloutIdConnectV6) {
        FwpsCalloutUnregisterById(g_WfpData.CalloutIdConnectV6);
        g_WfpData.CalloutIdConnectV6 = 0;
    }

    if (g_WfpData.CalloutIdConnectV4) {
        FwpsCalloutUnregisterById(g_WfpData.CalloutIdConnectV4);
        g_WfpData.CalloutIdConnectV4 = 0;
    }

    XdrwfpDebugPrint("All callouts unregistered");
    return status;
}

//
// Add filters to WFP engine
//
NTSTATUS
XdrwfpAddFilters(VOID)
{
    NTSTATUS status;
    FWPM_SUBLAYER sublayer = {0};
    FWPM_CALLOUT callout = {0};
    FWPM_FILTER filter = {0};

    // Add sublayer
    sublayer.subLayerKey = XDRWFP_SUBLAYER_GUID;
    sublayer.displayData.name = XDRWFP_SUBLAYER_NAME;
    sublayer.displayData.description = XDRWFP_SUBLAYER_DESCRIPTION;
    sublayer.weight = 0x100;

    status = FwpmSubLayerAdd(g_WfpData.EngineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status)) {
        XdrwfpErrorPrint("Failed to add sublayer: 0x%08X", status);
        return status;
    }

    // Add callout to engine for connect v4
    callout.calloutKey = XDRWFP_CALLOUT_CONNECT_V4_GUID;
    callout.displayData.name = XDRWFP_CALLOUT_DISPLAY_NAME;
    callout.displayData.description = XDRWFP_CALLOUT_DESCRIPTION;
    callout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    status = FwpmCalloutAdd(g_WfpData.EngineHandle, &callout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        XdrwfpErrorPrint("Failed to add connect v4 callout to engine: 0x%08X", status);
        return status;
    }

    // Add filter for connect v4
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.displayData.name = L"XDR Connect Monitor v4";
    filter.displayData.description = L"XDR Network Connect Monitor v4";
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = XDRWFP_CALLOUT_CONNECT_V4_GUID;
    filter.subLayerKey = XDRWFP_SUBLAYER_GUID;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = XDRWFP_FILTER_WEIGHT_CONNECT;

    status = FwpmFilterAdd(g_WfpData.EngineHandle, &filter, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        XdrwfpErrorPrint("Failed to add connect v4 filter: 0x%08X", status);
        return status;
    }

    // Add similar filters for other layers (v6, accept, flow)
    // For brevity, showing pattern for connect v4 only
    // Real implementation would add all 6 filters

    XdrwfpDebugPrint("Filters added successfully");
    return STATUS_SUCCESS;
}

//
// Remove filters from WFP engine
//
NTSTATUS
XdrwfpRemoveFilters(VOID)
{
    NTSTATUS status;

    // Remove sublayer (this removes all associated filters and callouts)
    status = FwpmSubLayerDeleteByKey(g_WfpData.EngineHandle, &XDRWFP_SUBLAYER_GUID);
    if (!NT_SUCCESS(status) && status != FWP_E_SUBLAYER_NOT_FOUND) {
        XdrwfpWarningPrint("Failed to remove sublayer: 0x%08X", status);
    }

    XdrwfpDebugPrint("Filters removed");
    return STATUS_SUCCESS;
}

//
// Connect classify function
//
VOID NTAPI
XdrwfpClassifyConnect(
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT* ClassifyOut
)
{
    XDR_NETWORK_VERDICT verdict = XDR_NET_ALLOW;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    // Check if we should ignore this flow
    if (XdrwfpShouldIgnoreFlow(InFixedValues, InMetaValues)) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Check if we should block this flow
    if (!g_WfpData.MonitorMode && XdrwfpShouldBlockFlow(InFixedValues, InMetaValues)) {
        verdict = XDR_NET_BLOCK;
        ClassifyOut->actionType = FWP_ACTION_BLOCK;
        InterlockedIncrement64(&g_WfpData.BlockedConnections);
    } else {
        verdict = XDR_NET_ALLOW;
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
    }

    // Generate network event
    XdrwfpGenerateNetworkEvent(
    XdrwfpWire_PublishConnectV4(InFixedValues, InMetaValues, verdict);
XDR_NET_CONNECT, verdict, InFixedValues, InMetaValues, NULL);

    InterlockedIncrement64(&g_WfpData.TotalConnections);

    ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

//
// Accept classify function
//
VOID NTAPI
XdrwfpClassifyAccept(
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT* ClassifyOut
)
{
    XDR_NETWORK_VERDICT verdict = XDR_NET_ALLOW;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    // Check if we should ignore this flow
    if (XdrwfpShouldIgnoreFlow(InFixedValues, InMetaValues)) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Check if we should block this flow
    if (!g_WfpData.MonitorMode && XdrwfpShouldBlockFlow(InFixedValues, InMetaValues)) {
        verdict = XDR_NET_BLOCK;
        ClassifyOut->actionType = FWP_ACTION_BLOCK;
        InterlockedIncrement64(&g_WfpData.BlockedConnections);
    } else {
        verdict = XDR_NET_ALLOW;
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
    }

    // Generate network event
    XdrwfpGenerateNetworkEvent(XDR_NET_ACCEPT, verdict, InFixedValues, InMetaValues, NULL);

    InterlockedIncrement64(&g_WfpData.TotalAccepts);

    ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

//
// Flow established classify function
//
VOID NTAPI
XdrwfpClassifyFlow(
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT* ClassifyOut
)
{
    NTSTATUS status;
    PXDRWFP_FLOW_CONTEXT flowCtx = NULL;
    UINT64 flowId;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);

    // Check if we should ignore this flow
    if (XdrwfpShouldIgnoreFlow(InFixedValues, InMetaValues)) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Get flow ID from metadata
    flowId = InMetaValues->flowHandle;

    // Find or create flow context
    flowCtx = XdrwfpFindFlowContext(flowId);
    if (!flowCtx) {
        status = XdrwfpCreateFlowContext(InFixedValues, 
                                       InMetaValues, 
                                       flowId, 
                                       InFixedValues->layerId,
                                       &flowCtx);
        
        if (NT_SUCCESS(status) && flowCtx) {
            // Generate flow established event
            XdrwfpGenerateNetworkEvent(XDR_NET_ESTABLISHED, 
                                     XDR_NET_ALLOW, 
                                     InFixedValues, 
                                     InMetaValues, 
                                     flowCtx);
            
            InterlockedIncrement64(&g_WfpData.TotalFlows);
        }
    } else {
        // Update flow statistics
        XdrwfpUpdateFlowStats(flowCtx, InFixedValues, InMetaValues);
    }

    ClassifyOut->actionType = FWP_ACTION_PERMIT;
    ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

//
// Notify functions (simplified implementations)
//
NTSTATUS NTAPI
XdrwfpNotifyConnect(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _Inout_ FWPS_FILTER* Filter
)
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI
XdrwfpNotifyAccept(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _Inout_ FWPS_FILTER* Filter
)
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI
XdrwfpNotifyFlow(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _Inout_ FWPS_FILTER* Filter
)
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);

    return STATUS_SUCCESS;
}

//
// Flow delete callback
//
VOID NTAPI
XdrwfpFlowDelete(
    _In_ UINT16 LayerId,
    _In_ UINT32 CalloutId,
    _In_ UINT64 FlowContext
)
{
    PXDRWFP_FLOW_CONTEXT flowCtx;

    UNREFERENCED_PARAMETER(LayerId);
    UNREFERENCED_PARAMETER(CalloutId);

    // Find and remove flow context
    flowCtx = XdrwfpFindFlowContext(FlowContext);
    if (flowCtx) {
        // Generate close event if not already reported
        if (!flowCtx->StatsReported) {
            XdrwfpGenerateNetworkEvent(XDR_NET_CLOSE, 
                                     XDR_NET_ALLOW, 
                                     NULL, 
                                     NULL, 
                                     flowCtx);
        }
        
        XdrwfpDeleteFlowContext(flowCtx);
    }
}
