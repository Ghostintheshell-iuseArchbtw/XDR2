//
// XDR WFP Callout Utility Functions
// Helper functions for flow management, event generation, and core communication
//

#include "xdrwfp.h"

//
// Create flow context
//
NTSTATUS
XdrwfpCreateFlowContext(
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues,
    _In_ UINT64 FlowId,
    _In_ UINT16 LayerId,
    _Out_ PXDRWFP_FLOW_CONTEXT* FlowContext
)
{
    PXDRWFP_FLOW_CONTEXT flowCtx;
    KIRQL oldIrql;

    *FlowContext = NULL;

    // Check if we've reached the maximum number of flows
    if (g_WfpData.FlowCount >= XDRWFP_MAX_FLOWS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Allocate flow context
    flowCtx = ExAllocatePoolWithTag(NonPagedPool, sizeof(XDRWFP_FLOW_CONTEXT), XDRWFP_FLOW_TAG);
    if (!flowCtx) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Initialize flow context
    RtlZeroMemory(flowCtx, sizeof(XDRWFP_FLOW_CONTEXT));
    flowCtx->FlowId = FlowId;
    flowCtx->LayerId = LayerId;
    
    // Extract network information
    if (XDRWFP_IS_IPV6_LAYER(LayerId)) {
        flowCtx->IsIPv6 = TRUE;
        
        // IPv6 addresses
        if (InFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS].value.byteArray16) {
            RtlCopyMemory(flowCtx->LocalAddrV6,
                         InFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS].value.byteArray16,
                         16);
        }
        
        if (InFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS].value.byteArray16) {
            RtlCopyMemory(flowCtx->RemoteAddrV6,
                         InFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS].value.byteArray16,
                         16);
        }
        
        flowCtx->LocalPort = InFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT].value.uint16;
        flowCtx->RemotePort = InFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT].value.uint16;
        flowCtx->Protocol = InFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL].value.uint8;
    } else {
        flowCtx->IsIPv6 = FALSE;
        
        // IPv4 addresses
        flowCtx->LocalAddrV4 = InFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS].value.uint32;
        flowCtx->RemoteAddrV4 = InFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS].value.uint32;
        flowCtx->LocalPort = InFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT].value.uint16;
        flowCtx->RemotePort = InFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT].value.uint16;
        flowCtx->Protocol = InFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL].value.uint8;
    }

    // Get process information
    if (FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        flowCtx->ProcessId = (UINT32)InMetaValues->processId;
        XdrwfpGetProcessImageHash(InMetaValues->processId, &flowCtx->ProcessImageHash);
    }

    // Determine direction
    flowCtx->IsInbound = (LayerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 ||
                         LayerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6);

    // Set timestamps
    KeQuerySystemTime(&flowCtx->CreateTime);
    flowCtx->LastActivity = flowCtx->CreateTime;

    // Add to flow list
    KeAcquireSpinLock(&g_WfpData.FlowListLock, &oldIrql);
    InsertTailList(&g_WfpData.FlowList, &flowCtx->ListEntry);
    g_WfpData.FlowCount++;
    KeReleaseSpinLock(&g_WfpData.FlowListLock, oldIrql);

    *FlowContext = flowCtx;
    return STATUS_SUCCESS;
}

//
// Delete flow context
//
VOID
XdrwfpDeleteFlowContext(
    _In_ PXDRWFP_FLOW_CONTEXT FlowContext
)
{
    KIRQL oldIrql;

    if (!FlowContext) {
        return;
    }

    // Remove from flow list
    KeAcquireSpinLock(&g_WfpData.FlowListLock, &oldIrql);
    RemoveEntryList(&FlowContext->ListEntry);
    g_WfpData.FlowCount--;
    KeReleaseSpinLock(&g_WfpData.FlowListLock, oldIrql);

    // Free the context
    ExFreePoolWithTag(FlowContext, XDRWFP_FLOW_TAG);
}

//
// Find flow context by flow ID
//
PXDRWFP_FLOW_CONTEXT
XdrwfpFindFlowContext(
    _In_ UINT64 FlowId
)
{
    PLIST_ENTRY entry;
    PXDRWFP_FLOW_CONTEXT flowCtx;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_WfpData.FlowListLock, &oldIrql);
    
    for (entry = g_WfpData.FlowList.Flink; 
         entry != &g_WfpData.FlowList; 
         entry = entry->Flink) {
        
        flowCtx = CONTAINING_RECORD(entry, XDRWFP_FLOW_CONTEXT, ListEntry);
        if (flowCtx->FlowId == FlowId) {
            KeReleaseSpinLock(&g_WfpData.FlowListLock, oldIrql);
            return flowCtx;
        }
    }
    
    KeReleaseSpinLock(&g_WfpData.FlowListLock, oldIrql);
    return NULL;
}

//
// Update flow statistics
//
VOID
XdrwfpUpdateFlowStats(
    _In_ PXDRWFP_FLOW_CONTEXT FlowContext,
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues
)
{
    UNREFERENCED_PARAMETER(InFixedValues);

    if (!FlowContext) {
        return;
    }

    // Update last activity time
    KeQuerySystemTime(&FlowContext->LastActivity);

    // Update byte counters from metadata (if available)
    if (FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_FLOW_CONTEXT)) {
        // In a real implementation, we would extract byte counts from flow context
        // For now, just increment packet counts
        if (FlowContext->IsInbound) {
            FlowContext->PacketsReceived++;
        } else {
            FlowContext->PacketsSent++;
        }
    }
}

//
// Generate network event
//
NTSTATUS
XdrwfpGenerateNetworkEvent(
    _In_ XDR_NETWORK_OP Operation,
    _In_ XDR_NETWORK_VERDICT Verdict,
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues,
    _In_opt_ PXDRWFP_FLOW_CONTEXT FlowContext
)
{
    XDR_EVENT_RECORD eventRecord;
    XDR_NETWORK_EVENT* networkEvent;
    LARGE_INTEGER timestamp;

    // Initialize event record
    RtlZeroMemory(&eventRecord, sizeof(eventRecord));
    eventRecord.total_size = sizeof(XDR_EVENT_RECORD);

    // Fill header
    eventRecord.header.version = XDR_ABI_VERSION;
    eventRecord.header.source = XDR_SOURCE_NETWORK;
    eventRecord.header.severity = (Verdict == XDR_NET_BLOCK) ? XDR_SEVERITY_HIGH : XDR_SEVERITY_LOW;

    KeQuerySystemTimePrecise(&timestamp);
    eventRecord.header.timestamp_100ns = timestamp.QuadPart;

    // Get process information
    if (InMetaValues && FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        eventRecord.header.process_id = (UINT32)InMetaValues->processId;
    } else if (FlowContext) {
        eventRecord.header.process_id = FlowContext->ProcessId;
    }

    // Sequence number
    eventRecord.header.sequence_number = InterlockedIncrement64(&g_WfpData.TotalFlows);

    // Fill network event payload
    networkEvent = &eventRecord.payload.network;
    networkEvent->operation = Operation;
    networkEvent->verdict = Verdict;

    if (FlowContext) {
        // Use flow context information
        networkEvent->protocol = FlowContext->Protocol;
        networkEvent->direction = FlowContext->IsInbound ? 1 : 0;
        networkEvent->bytes_sent = FlowContext->BytesSent;
        networkEvent->bytes_received = FlowContext->BytesReceived;
        networkEvent->process_image_hash = FlowContext->ProcessImageHash;

        if (FlowContext->IsIPv6) {
            RtlCopyMemory(networkEvent->local_addr_v6, FlowContext->LocalAddrV6, 16);
            RtlCopyMemory(networkEvent->remote_addr_v6, FlowContext->RemoteAddrV6, 16);
            networkEvent->local_port = FlowContext->LocalPort;
            networkEvent->remote_port = FlowContext->RemotePort;
        } else {
            networkEvent->local_addr = FlowContext->LocalAddrV4;
            networkEvent->remote_addr = FlowContext->RemoteAddrV4;
            networkEvent->local_port = FlowContext->LocalPort;
            networkEvent->remote_port = FlowContext->RemotePort;
        }

        // Compute key hash based on 5-tuple
        if (FlowContext->IsIPv6) {
            eventRecord.header.key_hash = 0; // Simplified
        } else {
            UINT64 tupleData[3];
            tupleData[0] = ((UINT64)FlowContext->LocalAddrV4 << 32) | FlowContext->RemoteAddrV4;
            tupleData[1] = ((UINT64)FlowContext->LocalPort << 16) | FlowContext->RemotePort;
            tupleData[2] = FlowContext->Protocol;
            
            // Simple hash
            eventRecord.header.key_hash = tupleData[0] ^ tupleData[1] ^ tupleData[2];
        }
    } else if (InFixedValues && InMetaValues) {
        // Extract information directly from WFP values
        XdrwfpExtractNetworkInfo(InFixedValues, InMetaValues, networkEvent);
        
        // Compute simple key hash
        eventRecord.header.key_hash = ((UINT64)networkEvent->local_addr << 32) | 
                                     networkEvent->remote_addr;
    }

    // Send to core driver
    return XdrwfpPublishEventToCore(&eventRecord);
}

//
// Extract network information from WFP values
//
VOID
XdrwfpExtractNetworkInfo(
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues,
    _Out_ XDR_NETWORK_EVENT* NetworkEvent
)
{
    UINT16 layerId = InFixedValues->layerId;

    if (XDRWFP_IS_IPV6_LAYER(layerId)) {
        // IPv6 layer
        if (layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6) {
            RtlCopyMemory(NetworkEvent->local_addr_v6,
                         InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS].value.byteArray16,
                         16);
            RtlCopyMemory(NetworkEvent->remote_addr_v6,
                         InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16,
                         16);
            NetworkEvent->local_port = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT].value.uint16;
            NetworkEvent->remote_port = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;
            NetworkEvent->protocol = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint8;
            NetworkEvent->direction = 0; // Outbound
        }
        // Add other IPv6 layers as needed
    } else {
        // IPv4 layer
        if (layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
            NetworkEvent->local_addr = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
            NetworkEvent->remote_addr = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
            NetworkEvent->local_port = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
            NetworkEvent->remote_port = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
            NetworkEvent->protocol = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
            NetworkEvent->direction = 0; // Outbound
        } else if (layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4) {
            NetworkEvent->local_addr = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS].value.uint32;
            NetworkEvent->remote_addr = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value.uint32;
            NetworkEvent->local_port = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16;
            NetworkEvent->remote_port = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT].value.uint16;
            NetworkEvent->protocol = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value.uint8;
            NetworkEvent->direction = 1; // Inbound
        }
        // Add other IPv4 layers as needed
    }

    // Get process image hash
    if (FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        XdrwfpGetProcessImageHash(InMetaValues->processId, &NetworkEvent->process_image_hash);
    }
}

//
// Check if we should ignore a flow
//
BOOLEAN
XdrwfpShouldIgnoreFlow(
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues
)
{
    // Check if loopback and not configured to log
    if (!g_WfpData.LogLoopback && XdrwfpIsLoopback(InFixedValues)) {
        return TRUE;
    }

    // Check if system process and not configured to log
    if (!g_WfpData.LogSystemProcesses && 
        FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_ID) &&
        XdrwfpIsSystemProcess(InMetaValues->processId)) {
        return TRUE;
    }

    return FALSE;
}

//
// Check if connection is loopback
//
BOOLEAN
XdrwfpIsLoopback(
    _In_ const FWPS_INCOMING_VALUES* InFixedValues
)
{
    UINT16 layerId = InFixedValues->layerId;

    if (XDRWFP_IS_IPV4_LAYER(layerId)) {
        UINT32 localAddr, remoteAddr;
        
        if (layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
            localAddr = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
            remoteAddr = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
        } else if (layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4) {
            localAddr = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS].value.uint32;
            remoteAddr = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value.uint32;
        } else {
            return FALSE;
        }

        // Check for 127.0.0.1 (loopback) - note: addresses are in network byte order
        return (localAddr == 0x0100007F || remoteAddr == 0x0100007F);
    }

    // IPv6 loopback check would go here
    return FALSE;
}

//
// Check if process is system process
//
BOOLEAN
XdrwfpIsSystemProcess(
    _In_ UINT64 ProcessId
)
{
    // System processes typically have PID <= 4
    return ((UINT32)ProcessId <= 4);
}

//
// Get process image hash (simplified)
//
NTSTATUS
XdrwfpGetProcessImageHash(
    _In_ UINT64 ProcessId,
    _Out_ PUINT64 ImageHash
)
{
    if (!ImageHash) {
        return STATUS_INVALID_PARAMETER;
    }

    // For now, use process ID as a simple hash
    // Real implementation would hash the image path
    *ImageHash = ProcessId * 0x9e3779b97f4a7c15ULL;

    return STATUS_SUCCESS;
}

//
// Check if flow should be blocked
//
BOOLEAN
XdrwfpShouldBlockFlow(
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues
)
{
    UNREFERENCED_PARAMETER(InFixedValues);
    UNREFERENCED_PARAMETER(InMetaValues);

    // In monitor mode, never block
    if (g_WfpData.MonitorMode) {
        return FALSE;
    }

    // TODO: Implement blocking logic based on:
    // - Blocklist CIDRs
    // - Process reputation
    // - Connection patterns
    // - Rules engine results

    return FALSE;
}

//
// Connect to core driver
//
NTSTATUS
XdrwfpConnectToCore(VOID)
{
    NTSTATUS status;
    UNICODE_STRING coreDeviceName;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_WfpData.ConnectionLock, &oldIrql);

    if (g_WfpData.Connected) {
        KeReleaseSpinLock(&g_WfpData.ConnectionLock, oldIrql);
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&coreDeviceName, XDR_DEVICE_NAME);

    InitializeObjectAttributes(&objectAttributes,
                             &coreDeviceName,
                             OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                             NULL,
                             NULL);

    status = ZwCreateFile(&g_WfpData.CoreDeviceObject,
                        GENERIC_WRITE,
                        &objectAttributes,
                        &ioStatus,
                        NULL,
                        FILE_ATTRIBUTE_NORMAL,
                        0,
                        FILE_OPEN,
                        FILE_NON_DIRECTORY_FILE,
                        NULL,
                        0);

    if (NT_SUCCESS(status)) {
        status = ObReferenceObjectByHandle(g_WfpData.CoreDeviceObject,
                                         0,
                                         *IoFileObjectType,
                                         KernelMode,
                                         (PVOID*)&g_WfpData.CoreFileObject,
                                         NULL);

        if (NT_SUCCESS(status)) {
            g_WfpData.Connected = TRUE;
            XdrwfpInfoPrint("Connected to core driver successfully");
        } else {
            ZwClose(g_WfpData.CoreDeviceObject);
            g_WfpData.CoreDeviceObject = NULL;
        }
    }

    KeReleaseSpinLock(&g_WfpData.ConnectionLock, oldIrql);
    return status;
}

//
// Disconnect from core driver
//
VOID
XdrwfpDisconnectFromCore(VOID)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_WfpData.ConnectionLock, &oldIrql);

    if (g_WfpData.Connected) {
        if (g_WfpData.CoreFileObject) {
            ObDereferenceObject(g_WfpData.CoreFileObject);
            g_WfpData.CoreFileObject = NULL;
        }

        if (g_WfpData.CoreDeviceObject) {
            ZwClose(g_WfpData.CoreDeviceObject);
            g_WfpData.CoreDeviceObject = NULL;
        }

        g_WfpData.Connected = FALSE;
        XdrwfpInfoPrint("Disconnected from core driver");
    }

    KeReleaseSpinLock(&g_WfpData.ConnectionLock, oldIrql);
}

//
// Publish event to core driver
//
NTSTATUS
XdrwfpPublishEventToCore(
    _In_ const XDR_EVENT_RECORD* EventRecord
)
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatus;
    PIRP irp;
    KEVENT event;
    PIO_STACK_LOCATION irpSp;
    KIRQL oldIrql;

    if (!EventRecord) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_WfpData.ConnectionLock, &oldIrql);

    if (!g_WfpData.Connected) {
        KeReleaseSpinLock(&g_WfpData.ConnectionLock, oldIrql);
        // Try to reconnect
        status = XdrwfpConnectToCore();
        if (!NT_SUCCESS(status)) {
            InterlockedIncrement64(&g_WfpData.DroppedEvents);
            return status;
        }
        KeAcquireSpinLock(&g_WfpData.ConnectionLock, &oldIrql);
    }

    // Create IRP for IOCTL
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    
    irp = IoBuildDeviceIoControlRequest(IOCTL_XDR_PUBLISH_EVENT,
                                      g_WfpData.CoreFileObject->DeviceObject,
                                      (PVOID)EventRecord,
                                      sizeof(XDR_EVENT_RECORD),
                                      NULL,
                                      0,
                                      TRUE, // Internal device control
                                      &event,
                                      &ioStatus);

    if (!irp) {
        KeReleaseSpinLock(&g_WfpData.ConnectionLock, oldIrql);
        InterlockedIncrement64(&g_WfpData.DroppedEvents);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Set up the stack location
    irpSp = IoGetNextIrpStackLocation(irp);
    irpSp->FileObject = g_WfpData.CoreFileObject;

    // Send the IRP
    status = IoCallDriver(g_WfpData.CoreFileObject->DeviceObject, irp);

    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatus.Status;
    }

    KeReleaseSpinLock(&g_WfpData.ConnectionLock, oldIrql);

    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_WfpData.DroppedEvents);
        XdrwfpDebugPrint("Failed to publish event to core: 0x%08X", status);
    }

    return status;
}

//
// Statistics timer DPC
//
VOID
XdrwfpStatsTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
)
{
    LARGE_INTEGER dueTime;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    // Report flow statistics
    XdrwfpReportFlowStats();

    // Set timer for next interval
    if (g_WfpData.TimerActive) {
        dueTime.QuadPart = -((LONGLONG)XDRWFP_FLOW_STATS_INTERVAL * 10000); // Convert ms to 100ns units
        KeSetTimer(&g_WfpData.StatsTimer, dueTime, &g_WfpData.StatsDpc);
    }
}

//
// Start statistics timer
//
VOID
XdrwfpStartStatsTimer(VOID)
{
    LARGE_INTEGER dueTime;

    KeInitializeTimer(&g_WfpData.StatsTimer);
    KeInitializeDpc(&g_WfpData.StatsDpc, XdrwfpStatsTimerDpc, NULL);

    g_WfpData.TimerActive = TRUE;
    
    dueTime.QuadPart = -((LONGLONG)XDRWFP_FLOW_STATS_INTERVAL * 10000);
    KeSetTimer(&g_WfpData.StatsTimer, dueTime, &g_WfpData.StatsDpc);

    XdrwfpDebugPrint("Statistics timer started");
}

//
// Stop statistics timer
//
VOID
XdrwfpStopStatsTimer(VOID)
{
    g_WfpData.TimerActive = FALSE;
    KeCancelTimer(&g_WfpData.StatsTimer);
    XdrwfpDebugPrint("Statistics timer stopped");
}

//
// Report flow statistics
//
NTSTATUS
XdrwfpReportFlowStats(VOID)
{
    PLIST_ENTRY entry;
    PXDRWFP_FLOW_CONTEXT flowCtx;
    KIRQL oldIrql;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG reportedFlows = 0;

    KeAcquireSpinLock(&g_WfpData.FlowListLock, &oldIrql);

    for (entry = g_WfpData.FlowList.Flink; 
         entry != &g_WfpData.FlowList; 
         entry = entry->Flink) {
        
        flowCtx = CONTAINING_RECORD(entry, XDRWFP_FLOW_CONTEXT, ListEntry);
        
        // Only report flows with activity and not already reported
        if (!flowCtx->StatsReported && 
            (flowCtx->BytesSent > 0 || flowCtx->BytesReceived > 0)) {
            
            KeReleaseSpinLock(&g_WfpData.FlowListLock, oldIrql);
            
            // Generate stats event
            XdrwfpGenerateNetworkEvent(XDR_NET_STATS, 
                                     XDR_NET_ALLOW, 
                                     NULL, 
                                     NULL, 
                                     flowCtx);
            
            flowCtx->StatsReported = TRUE;
            reportedFlows++;
            
            KeAcquireSpinLock(&g_WfpData.FlowListLock, &oldIrql);
        }
    }

    KeReleaseSpinLock(&g_WfpData.FlowListLock, oldIrql);

    if (reportedFlows > 0) {
        XdrwfpDebugPrint("Reported statistics for %u flows", reportedFlows);
    }

    return status;
}