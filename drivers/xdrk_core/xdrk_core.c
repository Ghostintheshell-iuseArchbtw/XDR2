//
// XDR Core Driver - KMDF Control Device and Event Aggregator
// Implements the main control device, shared memory ring buffer,
// and system callback registration for telemetry collection
//

#include "xdrk_core.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, XdrEvtDeviceAdd)
#pragma alloc_text (PAGE, XdrEvtDriverContextCleanup)
#pragma alloc_text (PAGE, XdrEvtDeviceContextCleanup)
#endif

//
// Global variables
//
PXDR_DEVICE_CONTEXT g_DeviceContext = NULL;

//
// Driver entry point
//
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES attributes;

    // Initialize WPP tracing
#ifdef WPP_TRACING
    WPP_INIT_TRACING(DriverObject, RegistryPath);
#endif

    TraceDriver(TRACE_LEVEL_INFORMATION, "XDR Core Driver loading...");

    // Initialize the driver configuration
    WDF_DRIVER_CONFIG_INIT(&config, XdrEvtDeviceAdd);
    config.EvtDriverUnload = NULL; // We use cleanup callbacks instead
    
    // Set driver attributes
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = XdrEvtDriverContextCleanup;

    // Create the driver framework object
    status = WdfDriverCreate(DriverObject,
                           RegistryPath,
                           &attributes,
                           &config,
                           WDF_NO_HANDLE);

    if (!NT_SUCCESS(status)) {
        LogError(status, "WdfDriverCreate failed");
#ifdef WPP_TRACING
        WPP_CLEANUP(DriverObject);
#endif
        return status;
    }

    TraceDriver(TRACE_LEVEL_INFORMATION, "XDR Core Driver loaded successfully");
    return status;
}

//
// Device add event handler
//
NTSTATUS
XdrEvtDeviceAdd(
    _In_ WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
)
{
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDFDEVICE device;
    PXDR_DEVICE_CONTEXT deviceContext;
    WDF_IO_QUEUE_CONFIG queueConfig;
    DECLARE_CONST_UNICODE_STRING(deviceName, XDR_DEVICE_NAME);
    DECLARE_CONST_UNICODE_STRING(dosDeviceName, XDR_DOS_DEVICE_NAME);
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;

    PAGED_CODE();
    FuncEntry();

    UNREFERENCED_PARAMETER(Driver);

    // Create security descriptor for the device
    status = XdrCreateSecurityDescriptor(&securityDescriptor);
    if (!NT_SUCCESS(status)) {
        LogError(status, "Failed to create security descriptor");
        goto Exit;
    }

    // Set the device name and security
    status = WdfDeviceInitAssignName(DeviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        LogError(status, "WdfDeviceInitAssignName failed");
        goto Exit;
    }

    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetCharacteristics(DeviceInit, FILE_DEVICE_SECURE_OPEN, FALSE);
    WdfDeviceInitSetExclusive(DeviceInit, FALSE);

    // Set security descriptor
    status = WdfDeviceInitAssignSDDLString(DeviceInit, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (!NT_SUCCESS(status)) {
        LogError(status, "WdfDeviceInitAssignSDDLString failed");
        goto Exit;
    }

    // Initialize device attributes and context
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, XDR_DEVICE_CONTEXT);
    deviceAttributes.EvtCleanupCallback = XdrEvtDeviceContextCleanup;

    // Create the device object
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        LogError(status, "WdfDeviceCreate failed");
        goto Exit;
    }

    // Get device context and initialize it
    deviceContext = XdrGetDeviceContext(device);
    RtlZeroMemory(deviceContext, sizeof(XDR_DEVICE_CONTEXT));
    
    deviceContext->Device = device;
    KeInitializeSpinLock(&deviceContext->ConfigLock);
    KeInitializeSpinLock(&deviceContext->StatsLock);
    
    // Initialize default configuration
    deviceContext->Config.min_severity = XDR_SEVERITY_LOW;
    deviceContext->Config.source_mask = 0xFF; // All sources enabled
    deviceContext->Config.max_queue_depth = XDR_MAX_PENDING_EVENTS;
    deviceContext->Config.heartbeat_interval_ms = 5000;
    deviceContext->Config.wfp_mode = 0; // Monitor mode by default

    // Initialize lookaside list for event allocation
    ExInitializeNPagedLookasideList(&deviceContext->EventLookaside,
                                  NULL,
                                  NULL,
                                  0,
                                  sizeof(XDR_EVENT_RECORD),
                                  XDR_EVENT_TAG,
                                  0);

    // Set global device context pointer
    g_DeviceContext = deviceContext;

    // Create the default I/O queue
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = XdrEvtIoDeviceControl;

    status = WdfIoQueueCreate(device,
                            &queueConfig,
                            WDF_NO_OBJECT_ATTRIBUTES,
                            &deviceContext->DefaultQueue);

    if (!NT_SUCCESS(status)) {
        LogError(status, "WdfIoQueueCreate failed");
        goto Exit;
    }

    // Create DOS device symbolic link
    status = WdfDeviceCreateSymbolicLink(device, &dosDeviceName);
    if (!NT_SUCCESS(status)) {
        LogError(status, "WdfDeviceCreateSymbolicLink failed");
        goto Exit;
    }

    // Initialize ring buffer (default size)
    status = XdrInitializeRingBuffer(deviceContext, XDR_SHM_DEFAULT_SIZE);
    if (!NT_SUCCESS(status)) {
        LogError(status, "Failed to initialize ring buffer");
        goto Exit;
    }

    // Register system callbacks
    status = XdrRegisterCallbacks(deviceContext);
    if (!NT_SUCCESS(status)) {
        LogError(status, "Failed to register system callbacks");
        goto Exit;
    }

    TraceDevice(TRACE_LEVEL_INFORMATION, "XDR device created successfully");

Exit:
    if (securityDescriptor) {
        ExFreePool(securityDescriptor);
    }

    FuncExitWithStatus(status);
    return status;
}

//
// Driver cleanup event handler
//
VOID
XdrEvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
)
{
    PAGED_CODE();
    FuncEntry();

    UNREFERENCED_PARAMETER(DriverObject);

    TraceDriver(TRACE_LEVEL_INFORMATION, "XDR driver unloading");

    // Clear global device context
    g_DeviceContext = NULL;

#ifdef WPP_TRACING
    WPP_CLEANUP(WdfDriverWdmGetDriverObject((WDFDRIVER)DriverObject));
#endif

    FuncExit();
}

//
// Device cleanup event handler
//
VOID
XdrEvtDeviceContextCleanup(
    _In_ WDFOBJECT Device
)
{
    PXDR_DEVICE_CONTEXT deviceContext;

    PAGED_CODE();
    FuncEntry();

    deviceContext = XdrGetDeviceContext((WDFDEVICE)Device);

    // Unregister callbacks
    XdrUnregisterCallbacks(deviceContext);

    // Cleanup ring buffer
    XdrCleanupRingBuffer(&deviceContext->RingBuffer);

    // Cleanup lookaside list
    ExDeleteNPagedLookasideList(&deviceContext->EventLookaside);

    TraceDevice(TRACE_LEVEL_INFORMATION, "XDR device context cleaned up");

    FuncExit();
}

//
// I/O device control event handler
//
VOID
XdrEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PXDR_DEVICE_CONTEXT deviceContext;
    
    deviceContext = XdrGetDeviceContext(WdfIoQueueGetDevice(Queue));

    TraceDevice(TRACE_LEVEL_VERBOSE, "IOCTL received: 0x%08X", IoControlCode);

    switch (IoControlCode) {
        case IOCTL_XDR_GET_VERSION:
            status = XdrHandleGetVersion(Request, OutputBufferLength);
            break;

        case IOCTL_XDR_MAP_SHM:
            status = XdrHandleMapShm(deviceContext, Request, OutputBufferLength);
            break;

        case IOCTL_XDR_SET_CONFIG:
            status = XdrHandleSetConfig(deviceContext, Request, InputBufferLength);
            break;

        case IOCTL_XDR_PEEK_FALLBACK:
            status = XdrHandlePeekFallback(deviceContext, Request, OutputBufferLength);
            break;

        case IOCTL_XDR_DEQUEUE_FALLBACK:
            status = XdrHandleDequeueFallback(deviceContext, Request, OutputBufferLength);
            break;

        case IOCTL_XDR_PUBLISH_EVENT:
            status = XdrHandlePublishEvent(deviceContext, Request, InputBufferLength);
            break;

        case IOCTL_XDR_USER_EVENT:
            status = XdrHandleUserEvent(deviceContext, Request, InputBufferLength);
            break;

        default:
            TraceError("Unknown IOCTL code: 0x%08X", IoControlCode);
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    if (status != STATUS_PENDING) {
        WdfRequestComplete(Request, status);
    }
}

//
// Handle get version IOCTL
//
NTSTATUS
XdrHandleGetVersion(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength
)
{
    NTSTATUS status;
    XDR_VERSION_OUTPUT* output;
    LARGE_INTEGER systemTime;

    FuncEntry();

    if (OutputBufferLength < sizeof(XDR_VERSION_OUTPUT)) {
        LogError(STATUS_BUFFER_TOO_SMALL, "Output buffer too small for version info");
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveOutputBuffer(Request,
                                          sizeof(XDR_VERSION_OUTPUT),
                                          (PVOID*)&output,
                                          NULL);

    if (!NT_SUCCESS(status)) {
        LogError(status, "Failed to retrieve output buffer");
        return status;
    }

    // Fill version information
    output->abi_version = XDR_ABI_VERSION;
    output->driver_version = 0x00010000; // Version 1.0.0.0
    
    KeQuerySystemTime(&systemTime);
    output->build_timestamp = systemTime.QuadPart;

    WdfRequestSetInformation(Request, sizeof(XDR_VERSION_OUTPUT));

    TraceDevice(TRACE_LEVEL_INFORMATION, "Version info returned: ABI=%u, Driver=%u",
               output->abi_version, output->driver_version);

    FuncExitWithStatus(STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

//
// Handle map shared memory IOCTL
//
NTSTATUS
XdrHandleMapShm(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength
)
{
    NTSTATUS status;
    XDR_MAP_SHM_OUTPUT* output;
    HANDLE processHandle = NULL;
    HANDLE sectionHandle = NULL;
    HANDLE eventHandle = NULL;

    FuncEntry();

    if (OutputBufferLength < sizeof(XDR_MAP_SHM_OUTPUT)) {
        LogError(STATUS_BUFFER_TOO_SMALL, "Output buffer too small for SHM mapping");
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Check if SHM is already mapped
    if (DeviceContext->ShmMapped) {
        LogError(STATUS_DEVICE_BUSY, "Shared memory already mapped");
        return STATUS_DEVICE_BUSY;
    }

    status = WdfRequestRetrieveOutputBuffer(Request,
                                          sizeof(XDR_MAP_SHM_OUTPUT),
                                          (PVOID*)&output,
                                          NULL);

    if (!NT_SUCCESS(status)) {
        LogError(status, "Failed to retrieve output buffer");
        return status;
    }

    // Get current process handle
    status = ObOpenObjectByPointer(PsGetCurrentProcess(),
                                 0,
                                 NULL,
                                 PROCESS_ALL_ACCESS,
                                 *PsProcessType,
                                 KernelMode,
                                 &processHandle);

    if (!NT_SUCCESS(status)) {
        LogError(status, "Failed to get process handle");
        goto Exit;
    }

    // Duplicate section handle for usermode
    status = ZwDuplicateObject(NtCurrentProcess(),
                             DeviceContext->RingBuffer.SectionHandle,
                             processHandle,
                             &sectionHandle,
                             SECTION_MAP_READ | SECTION_MAP_WRITE,
                             0,
                             0);

    if (!NT_SUCCESS(status)) {
        LogError(status, "Failed to duplicate section handle");
        goto Exit;
    }

    // Duplicate event handle for usermode
    status = ZwDuplicateObject(NtCurrentProcess(),
                             DeviceContext->RingBuffer.NotificationEventHandle,
                             processHandle,
                             &eventHandle,
                             EVENT_ALL_ACCESS,
                             0,
                             0);

    if (!NT_SUCCESS(status)) {
        LogError(status, "Failed to duplicate event handle");
        goto Exit;
    }

    // Fill output structure
    output->section_handle = sectionHandle;
    output->section_size = DeviceContext->RingBuffer.Size;
    output->event_handle = eventHandle;

    // Mark as mapped and store process reference
    DeviceContext->ShmMapped = TRUE;
    DeviceContext->UserProcess = PsGetCurrentProcess();
    ObReferenceObject(DeviceContext->UserProcess);

    WdfRequestSetInformation(Request, sizeof(XDR_MAP_SHM_OUTPUT));

    TraceDevice(TRACE_LEVEL_INFORMATION, "Shared memory mapped: Size=%zu bytes",
               DeviceContext->RingBuffer.Size);

    status = STATUS_SUCCESS;

Exit:
    if (processHandle) {
        ZwClose(processHandle);
    }

    if (!NT_SUCCESS(status)) {
        if (sectionHandle) {
            ZwClose(sectionHandle);
        }
        if (eventHandle) {
            ZwClose(eventHandle);
        }
    }

    FuncExitWithStatus(status);
    return status;
}

//
// Handle set configuration IOCTL
//
NTSTATUS
XdrHandleSetConfig(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength
)
{
    NTSTATUS status;
    XDR_CONFIG* config;
    KIRQL oldIrql;
    XDR_CONFIG oldConfig;

    FuncEntry();

    if (InputBufferLength < sizeof(XDR_CONFIG)) {
        LogError(STATUS_BUFFER_TOO_SMALL, "Input buffer too small for config");
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(Request,
                                         sizeof(XDR_CONFIG),
                                         (PVOID*)&config,
                                         NULL);

    if (!NT_SUCCESS(status)) {
        LogError(status, "Failed to retrieve input buffer");
        return status;
    }

    // Validate configuration
    if (config->min_severity > XDR_SEVERITY_CRITICAL ||
        config->max_queue_depth == 0 ||
        config->max_queue_depth > XDR_MAX_PENDING_EVENTS * 2) {
        LogError(STATUS_INVALID_PARAMETER, "Invalid configuration parameters");
        return STATUS_INVALID_PARAMETER;
    }

    // Atomically update configuration
    KeAcquireSpinLock(&DeviceContext->ConfigLock, &oldIrql);
    oldConfig = DeviceContext->Config;
    DeviceContext->Config = *config;
    KeReleaseSpinLock(&DeviceContext->ConfigLock, oldIrql);

    // Log configuration changes
    if (oldConfig.min_severity != config->min_severity) {
        TraceConfigChange(min_severity, oldConfig.min_severity, config->min_severity);
    }
    if (oldConfig.source_mask != config->source_mask) {
        TraceConfigChange(source_mask, oldConfig.source_mask, config->source_mask);
    }

    TraceConfig(TRACE_LEVEL_INFORMATION, "Configuration updated successfully");

    FuncExitWithStatus(STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

//
// Handle publish event IOCTL (kernel-to-kernel only)
//
NTSTATUS
XdrHandlePublishEvent(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength
)
{
    NTSTATUS status;
    XDR_EVENT_RECORD* record;

    FuncEntry();

    // Security check: reject calls from user mode
    if (WdfRequestGetRequestorMode(Request) != KernelMode) {
        LogError(STATUS_ACCESS_DENIED, "Publish event IOCTL called from user mode");
        return STATUS_ACCESS_DENIED;
    }

    if (InputBufferLength < sizeof(XDR_EVENT_RECORD)) {
        LogError(STATUS_BUFFER_TOO_SMALL, "Input buffer too small for event record");
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(Request,
                                         sizeof(XDR_EVENT_RECORD),
                                         (PVOID*)&record,
                                         NULL);

    if (!NT_SUCCESS(status)) {
        LogError(status, "Failed to retrieve input buffer");
        return status;
    }

    // Validate event record
    if (record->header.version != XDR_ABI_VERSION ||
        record->header.source >= XDR_SOURCE_MAX ||
        record->total_size > InputBufferLength) {
        LogError(STATUS_INVALID_PARAMETER, "Invalid event record");
        return STATUS_INVALID_PARAMETER;
    }

    // Enqueue the event
    status = XdrEnqueueEvent(DeviceContext, record);
    if (!NT_SUCCESS(status)) {
        LogError(status, "Failed to enqueue event");
        return status;
    }

    TraceEventGeneration(TRACE_LEVEL_VERBOSE, "Event published from kernel component");

    FuncExitWithStatus(STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

//
// Handle user event IOCTL
//
NTSTATUS
XdrHandleUserEvent(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength
)
{
    NTSTATUS status;
    XDR_USER_EVENT* userEvent;
    XDR_EVENT_RECORD record;
    LARGE_INTEGER timestamp;

    FuncEntry();

    if (InputBufferLength < sizeof(XDR_USER_EVENT)) {
        LogError(STATUS_BUFFER_TOO_SMALL, "Input buffer too small for user event");
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(Request,
                                         sizeof(XDR_USER_EVENT),
                                         (PVOID*)&userEvent,
                                         NULL);

    if (!NT_SUCCESS(status)) {
        LogError(status, "Failed to retrieve input buffer");
        return status;
    }

    // Create event record from user event
    RtlZeroMemory(&record, sizeof(record));
    record.total_size = sizeof(XDR_EVENT_RECORD);
    record.header.version = XDR_ABI_VERSION;
    record.header.source = XDR_SOURCE_USER;
    record.header.severity = XDR_SEVERITY_LOW;
    record.header.process_id = HandleToUlong(PsGetCurrentProcessId());
    record.header.thread_id = HandleToUlong(PsGetCurrentThreadId());
    
    XdrGetCurrentTimeStamp(&timestamp);
    record.header.timestamp_100ns = timestamp.QuadPart;
    
    record.header.sequence_number = InterlockedIncrement64(&DeviceContext->SequenceCounter);
    record.payload.user = *userEvent;

    // Enqueue the event
    status = XdrEnqueueEvent(DeviceContext, &record);
    if (!NT_SUCCESS(status)) {
        LogError(status, "Failed to enqueue user event");
        return status;
    }

    TraceEventGeneration(TRACE_LEVEL_INFORMATION, "User event enqueued");

    FuncExitWithStatus(STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

//
// Placeholder implementations for fallback IOCTLs
//
NTSTATUS
XdrHandlePeekFallback(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength
)
{
    UNREFERENCED_PARAMETER(DeviceContext);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    
    // TODO: Implement fallback peek for debugging
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
XdrHandleDequeueFallback(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength
)
{
    UNREFERENCED_PARAMETER(DeviceContext);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    
    // TODO: Implement fallback dequeue for debugging
    return STATUS_NOT_IMPLEMENTED;
}

//
// Export functions for kernel components
//
NTSTATUS
XdrPublishEvent(
    _In_ const XDR_EVENT_RECORD* Record
)
{
    if (!g_DeviceContext) {
        return STATUS_DEVICE_NOT_READY;
    }

    return XdrEnqueueEvent(g_DeviceContext, Record);
}

NTSTATUS
XdrGetAbiVersion(
    _Out_ uint32_t* Version
)
{
    if (!Version) {
        return STATUS_INVALID_PARAMETER;
    }

    *Version = XDR_ABI_VERSION;
    return STATUS_SUCCESS;
}