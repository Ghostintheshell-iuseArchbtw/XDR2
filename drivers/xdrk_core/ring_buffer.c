//
// Ring Buffer Implementation for XDR Core Driver
// Manages shared memory ring buffer for kernel-usermode communication
//

#include "xdrk_core.h"

//
// Initialize the ring buffer and shared memory
//
NTSTATUS
XdrInitializeRingBuffer(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ SIZE_T Size
)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    LARGE_INTEGER sectionSize;
    PXDR_RING_BUFFER ringBuffer;

    FuncEntry();

    ringBuffer = &DeviceContext->RingBuffer;
    RtlZeroMemory(ringBuffer, sizeof(XDR_RING_BUFFER));

    // Align size to page boundary
    Size = ROUND_TO_PAGES(Size);
    if (Size < XDR_SHM_MIN_SIZE || Size > XDR_SHM_MAX_SIZE) {
        LogError(STATUS_INVALID_PARAMETER, "Invalid ring buffer size: %zu", Size);
        return STATUS_INVALID_PARAMETER;
    }

    sectionSize.QuadPart = Size;

    // Create section object for shared memory
    InitializeObjectAttributes(&objectAttributes,
                             NULL,
                             OBJ_KERNEL_HANDLE,
                             NULL,
                             NULL);

    status = ZwCreateSection(&ringBuffer->SectionHandle,
                           SECTION_ALL_ACCESS,
                           &objectAttributes,
                           &sectionSize,
                           PAGE_READWRITE,
                           SEC_COMMIT,
                           NULL);

    if (!NT_SUCCESS(status)) {
        LogError(status, "ZwCreateSection failed");
        goto Exit;
    }

    // Reference the section object
    status = ObReferenceObjectByHandle(ringBuffer->SectionHandle,
                                     SECTION_ALL_ACCESS,
                                     *MmSectionObjectType,
                                     KernelMode,
                                     &ringBuffer->SectionObject,
                                     NULL);

    if (!NT_SUCCESS(status)) {
        LogError(status, "ObReferenceObjectByHandle failed");
        goto Exit;
    }

    // Map the section into kernel address space
    status = ZwMapViewOfSection(ringBuffer->SectionHandle,
                              NtCurrentProcess(),
                              &ringBuffer->BaseAddress,
                              0,
                              0,
                              NULL,
                              &Size,
                              ViewUnmap,
                              0,
                              PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
        LogError(status, "ZwMapViewOfSection failed");
        goto Exit;
    }

    ringBuffer->Size = Size;

    // Create notification event
    InitializeObjectAttributes(&objectAttributes,
                             NULL,
                             OBJ_KERNEL_HANDLE,
                             NULL,
                             NULL);

    status = ZwCreateEvent(&ringBuffer->NotificationEventHandle,
                         EVENT_ALL_ACCESS,
                         &objectAttributes,
                         NotificationEvent,
                         FALSE);

    if (!NT_SUCCESS(status)) {
        LogError(status, "ZwCreateEvent failed");
        goto Exit;
    }

    // Reference the event object
    status = ObReferenceObjectByHandle(ringBuffer->NotificationEventHandle,
                                     EVENT_ALL_ACCESS,
                                     *ExEventObjectType,
                                     KernelMode,
                                     (PVOID*)&ringBuffer->NotificationEvent,
                                     NULL);

    if (!NT_SUCCESS(status)) {
        LogError(status, "Failed to reference event object");
        goto Exit;
    }

    // Initialize shared memory header
    ringBuffer->Header = (XDR_SHM_HEADER*)ringBuffer->BaseAddress;
    RtlZeroMemory(ringBuffer->Header, sizeof(XDR_SHM_HEADER));
    
    ringBuffer->Header->magic = XDR_SHM_MAGIC;
    ringBuffer->Header->version = XDR_ABI_VERSION;
    ringBuffer->Header->ring_size = (ULONG)(Size - sizeof(XDR_SHM_HEADER));
    ringBuffer->Header->max_record_size = sizeof(XDR_EVENT_RECORD);
    
    // Initialize atomic indices
    ringBuffer->WriteIndex = 0;
    ringBuffer->ReadIndex = 0;

    TraceRing(TRACE_LEVEL_INFORMATION, 
             "Ring buffer initialized: Size=%zu, DataSize=%u", 
             Size, ringBuffer->Header->ring_size);

    status = STATUS_SUCCESS;

Exit:
    if (!NT_SUCCESS(status)) {
        XdrCleanupRingBuffer(ringBuffer);
    }

    FuncExitWithStatus(status);
    return status;
}

//
// Cleanup ring buffer resources
//
VOID
XdrCleanupRingBuffer(
    _In_ PXDR_RING_BUFFER RingBuffer
)
{
    FuncEntry();

    if (RingBuffer->BaseAddress) {
        ZwUnmapViewOfSection(NtCurrentProcess(), RingBuffer->BaseAddress);
        RingBuffer->BaseAddress = NULL;
    }

    if (RingBuffer->NotificationEvent) {
        ObDereferenceObject(RingBuffer->NotificationEvent);
        RingBuffer->NotificationEvent = NULL;
    }

    if (RingBuffer->NotificationEventHandle) {
        ZwClose(RingBuffer->NotificationEventHandle);
        RingBuffer->NotificationEventHandle = NULL;
    }

    if (RingBuffer->SectionObject) {
        ObDereferenceObject(RingBuffer->SectionObject);
        RingBuffer->SectionObject = NULL;
    }

    if (RingBuffer->SectionHandle) {
        ZwClose(RingBuffer->SectionHandle);
        RingBuffer->SectionHandle = NULL;
    }

    TraceRing(TRACE_LEVEL_INFORMATION, "Ring buffer cleaned up");

    FuncExit();
}

//
// Check if ring buffer has space for a record
//
BOOLEAN
XdrIsRingBufferFull(
    _In_ PXDR_RING_BUFFER RingBuffer,
    _In_ ULONG RecordSize
)
{
    LONG64 writeIndex, readIndex;
    ULONG available;

    // Read indices atomically
    writeIndex = InterlockedCompareExchange64(&RingBuffer->WriteIndex, 0, 0);
    readIndex = InterlockedCompareExchange64(&RingBuffer->ReadIndex, 0, 0);

    // Calculate available space
    if (writeIndex >= readIndex) {
        available = RingBuffer->Header->ring_size - (ULONG)(writeIndex - readIndex);
    } else {
        available = (ULONG)(readIndex - writeIndex);
    }

    return (available < RecordSize + sizeof(ULONG)); // +4 for length prefix
}

//
// Enqueue an event record into the ring buffer
//
NTSTATUS
XdrEnqueueEvent(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ const XDR_EVENT_RECORD* Record
)
{
    PXDR_RING_BUFFER ringBuffer;
    PUCHAR dataBuffer;
    LONG64 writeIndex, newWriteIndex;
    ULONG recordSize, alignedSize;
    KIRQL oldIrql;
    BOOLEAN wasEmpty;

    if (!DeviceContext || !Record) {
        return STATUS_INVALID_PARAMETER;
    }

    ringBuffer = &DeviceContext->RingBuffer;
    if (!ringBuffer->BaseAddress) {
        return STATUS_DEVICE_NOT_READY;
    }

    recordSize = Record->total_size;
    if (recordSize > sizeof(XDR_EVENT_RECORD) || recordSize < sizeof(XDR_EVENT_HEADER)) {
        TraceError("Invalid record size: %u", recordSize);
        return STATUS_INVALID_PARAMETER;
    }

    // Align to 8-byte boundary
    alignedSize = ALIGN_UP(recordSize + sizeof(ULONG), 8);

    // Check if we should log this event based on configuration
    if (!XdrShouldLogEvent(DeviceContext, Record->header.source, Record->header.severity)) {
        return STATUS_SUCCESS; // Silently ignore
    }

    // Check for available space
    if (XdrIsRingBufferFull(ringBuffer, alignedSize)) {
        XdrIncrementDropCounter(DeviceContext, Record->header.source);
        TraceRing(TRACE_LEVEL_WARNING, "Ring buffer full, dropping event from source %u", 
                 Record->header.source);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Calculate write position
    writeIndex = InterlockedCompareExchange64(&ringBuffer->WriteIndex, 0, 0);
    wasEmpty = (writeIndex == InterlockedCompareExchange64(&ringBuffer->ReadIndex, 0, 0));

    dataBuffer = (PUCHAR)ringBuffer->BaseAddress + sizeof(XDR_SHM_HEADER);
    
    // Handle wraparound
    if (writeIndex + alignedSize > ringBuffer->Header->ring_size) {
        // Reset to beginning if we would exceed buffer
        writeIndex = 0;
        InterlockedExchange64(&ringBuffer->WriteIndex, 0);
    }

    // Copy record to ring buffer with length prefix
    KeAcquireSpinLock(&DeviceContext->StatsLock, &oldIrql);
    
    // Write length first
    *(PULONG)(dataBuffer + writeIndex) = recordSize;
    
    // Write record data
    RtlCopyMemory(dataBuffer + writeIndex + sizeof(ULONG), Record, recordSize);
    
    // Update write index atomically (release semantics)
    newWriteIndex = writeIndex + alignedSize;
    InterlockedExchange64(&ringBuffer->WriteIndex, newWriteIndex);
    
    // Update statistics
    InterlockedIncrement64(&DeviceContext->TotalEvents);
    InterlockedIncrement64(&ringBuffer->Header->total_events);
    ringBuffer->Header->write_index = newWriteIndex;
    
    KeReleaseSpinLock(&DeviceContext->StatsLock, oldIrql);

    // Signal usermode if buffer was empty
    if (wasEmpty && ringBuffer->NotificationEvent) {
        KeSetEvent(ringBuffer->NotificationEvent, IO_NO_INCREMENT, FALSE);
    }

    TracePerfStart(Enqueue);
    TraceEventGeneration(TRACE_LEVEL_VERBOSE, 
                        "Event enqueued: Source=%u, Size=%u, WriteIndex=%lld",
                        Record->header.source, recordSize, newWriteIndex);
    TracePerfEnd(Enqueue, "Event enqueue");

    return STATUS_SUCCESS;
}

//
// Compute FNV-1a hash for key generation
//
ULONG64
XdrFnv1aHash(
    _In_ const VOID* Data,
    _In_ SIZE_T Length
)
{
    const UCHAR* bytes = (const UCHAR*)Data;
    ULONG64 hash = 0xCBF29CE484222325ULL; // FNV offset basis
    SIZE_T i;

    for (i = 0; i < Length; i++) {
        hash ^= bytes[i];
        hash *= 0x100000001B3ULL; // FNV prime
    }

    return hash;
}

//
// Compute stable key hash for an event
//
ULONG64
XdrComputeKeyHash(
    _In_ const VOID* Data,
    _In_ SIZE_T Length
)
{
    return XdrFnv1aHash(Data, Length);
}

//
// Get current timestamp in Windows FILETIME format
//
VOID
XdrGetCurrentTimeStamp(
    _Out_ PLARGE_INTEGER TimeStamp
)
{
    KeQuerySystemTimePrecise(TimeStamp);
}

//
// Check if an event should be logged based on configuration
//
BOOLEAN
XdrShouldLogEvent(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ XDR_EVENT_SOURCE Source,
    _In_ XDR_SEVERITY Severity
)
{
    KIRQL oldIrql;
    BOOLEAN shouldLog;
    XDR_CONFIG config;

    if (Source >= XDR_SOURCE_MAX) {
        return FALSE;
    }

    // Read configuration atomically
    KeAcquireSpinLock(&DeviceContext->ConfigLock, &oldIrql);
    config = DeviceContext->Config;
    KeReleaseSpinLock(&DeviceContext->ConfigLock, oldIrql);

    // Check severity threshold
    if (Severity < config.min_severity) {
        return FALSE;
    }

    // Check if source is enabled
    shouldLog = (config.source_mask & (1 << Source)) != 0;

    return shouldLog;
}

//
// Increment drop counter for a source
//
VOID
XdrIncrementDropCounter(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ XDR_EVENT_SOURCE Source
)
{
    KIRQL oldIrql;

    if (Source >= XDR_SOURCE_MAX) {
        return;
    }

    KeAcquireSpinLock(&DeviceContext->StatsLock, &oldIrql);
    
    DeviceContext->DroppedEvents[Source]++;
    if (DeviceContext->RingBuffer.Header) {
        DeviceContext->RingBuffer.Header->dropped_events[Source]++;
    }
    
    KeReleaseSpinLock(&DeviceContext->StatsLock, oldIrql);

    TraceRing(TRACE_LEVEL_WARNING, "Dropped event from source %u, total drops: %lld",
             Source, DeviceContext->DroppedEvents[Source]);
}