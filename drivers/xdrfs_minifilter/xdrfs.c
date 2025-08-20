#include "xdrfs_wire.h"
//
// XDR Filesystem Minifilter Driver
// Monitors filesystem operations and publishes events to core driver
//

#include "xdrfs.h"

// Global filter data
XDRFS_DATA g_FilterData = {0};

// Operations we register for
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    {
        IRP_MJ_CREATE,
        0,
        XdrfsPreCreate,
        XdrfsPostCreate
    },
    {
        IRP_MJ_WRITE,
        0,
        XdrfsPreWrite,
        XdrfsPostWrite
    },
    {
        IRP_MJ_SET_INFORMATION,
        0,
        XdrfsPreSetInformation,
        XdrfsPostSetInformation
    },
    { IRP_MJ_OPERATION_END }
};

// Context registration
CONST FLT_CONTEXT_REGISTRATION Contexts[] = {
    {
        FLT_VOLUME_CONTEXT,
        0,
        XdrfsVolumeContextCleanup,
        XDRFS_VOLUME_CONTEXT_SIZE,
        XDRFS_CTX_TAG
    },
    {
        FLT_STREAM_CONTEXT,
        0,
        XdrfsStreamContextCleanup,
        XDRFS_STREAM_CONTEXT_SIZE,
        XDRFS_CTX_TAG
    },
    { FLT_CONTEXT_END }
};

// Filter registration
CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),           // Size
    FLT_REGISTRATION_VERSION,           // Version
    0,                                  // Flags
    Contexts,                          // Contexts
    Callbacks,                         // Operation callbacks
    XdrfsUnload,                       // FilterUnload
    XdrfsInstanceSetup,                // InstanceSetup
    XdrfsInstanceQueryTeardown,        // InstanceQueryTeardown
    XdrfsInstanceTeardownStart,        // InstanceTeardownStart
    XdrfsInstanceTeardownComplete,     // InstanceTeardownComplete
    NULL,                              // GenerateFileName
    NULL,                              // NormalizeNameComponent
    NULL                               // NormalizeContextCleanup
};

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

    XdrfsInfoPrint("XDR Filesystem Minifilter loading...");

    // Initialize global data
    RtlZeroMemory(&g_FilterData, sizeof(g_FilterData));
    ExInitializeFastMutex(&g_FilterData.ConnectionLock);

    // Register the filter
    status = FltRegisterFilter(DriverObject,
                             &FilterRegistration,
                             &g_FilterData.Filter);

    if (!NT_SUCCESS(status)) {
        XdrfsErrorPrint("FltRegisterFilter failed: 0x%08X", status);
        return status;
    }

    // Connect to core driver
    status = XdrfsConnectToCore();
    if (!NT_SUCCESS(status)) {
        XdrfsWarningPrint("Failed to connect to core driver: 0x%08X", status);
        // Continue without core connection - we'll retry later
    }

    // Start filtering
    status = FltStartFiltering(g_FilterData.Filter);
    if (!NT_SUCCESS(status)) {
        XdrfsErrorPrint("FltStartFiltering failed: 0x%08X", status);
        FltUnregisterFilter(g_FilterData.Filter);
        XdrfsDisconnectFromCore();
        return status;
    }

    XdrfsInfoPrint("XDR Filesystem Minifilter loaded successfully");
    return STATUS_SUCCESS;
}

//
// Filter unload callback
//
NTSTATUS
XdrfsUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    XdrfsInfoPrint("XDR Filesystem Minifilter unloading...");

    // Disconnect from core driver
    XdrfsDisconnectFromCore();

    // Unregister the filter
    FltUnregisterFilter(g_FilterData.Filter);

    XdrfsInfoPrint("XDR Filesystem Minifilter unloaded");
    return STATUS_SUCCESS;
}

//
// Instance setup callback
//
NTSTATUS
XdrfsInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    NTSTATUS status;
    PXDRFS_VOLUME_CONTEXT volumeContext = NULL;

    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);

    XdrfsDebugPrint("Instance setup for volume, filesystem type: %d", VolumeFilesystemType);

    // We only care about NTFS and ReFS volumes
    if (VolumeFilesystemType != FLT_FSTYPE_NTFS &&
        VolumeFilesystemType != FLT_FSTYPE_REFS) {
        XdrfsDebugPrint("Skipping non-NTFS/ReFS volume");
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    // Allocate volume context
    status = FltAllocateContext(g_FilterData.Filter,
                              FLT_VOLUME_CONTEXT,
                              XDRFS_VOLUME_CONTEXT_SIZE,
                              PagedPool,
                              &volumeContext);

    if (!NT_SUCCESS(status)) {
        XdrfsErrorPrint("Failed to allocate volume context: 0x%08X", status);
        return status;
    }

    // Initialize volume context
    RtlZeroMemory(volumeContext, XDRFS_VOLUME_CONTEXT_SIZE);
    volumeContext->Volume = FltObjects->Volume;
    volumeContext->MonitoringEnabled = TRUE;

    // Get volume name
    status = FltGetVolumeName(FltObjects->Volume,
                            &volumeContext->VolumeName,
                            NULL);

    if (!NT_SUCCESS(status)) {
        XdrfsWarningPrint("Failed to get volume name: 0x%08X", status);
        // Continue without volume name
    }

    // Set the context
    status = FltSetVolumeContext(FltObjects->Volume,
                               FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                               volumeContext,
                               NULL);

    if (!NT_SUCCESS(status)) {
        XdrfsErrorPrint("Failed to set volume context: 0x%08X", status);
        FltReleaseContext(volumeContext);
        return status;
    }

    FltReleaseContext(volumeContext);

    XdrfsDebugPrint("Successfully attached to volume");
    return STATUS_SUCCESS;
}

//
// Instance query teardown callback
//
NTSTATUS
XdrfsInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    XdrfsDebugPrint("Instance query teardown");
    return STATUS_SUCCESS;
}

//
// Instance teardown start callback
//
VOID
XdrfsInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    XdrfsDebugPrint("Instance teardown start");
}

//
// Instance teardown complete callback
//
VOID
XdrfsInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    XdrfsDebugPrint("Instance teardown complete");
}

//
// Volume context cleanup callback
//
VOID
XdrfsVolumeContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
)
{
    PXDRFS_VOLUME_CONTEXT volumeContext = (PXDRFS_VOLUME_CONTEXT)Context;

    UNREFERENCED_PARAMETER(ContextType);

    if (volumeContext->VolumeName.Buffer) {
        ExFreePool(volumeContext->VolumeName.Buffer);
    }
}

//
// Stream context cleanup callback
//
VOID
XdrfsStreamContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
)
{
    PXDRFS_STREAM_CONTEXT streamContext = (PXDRFS_STREAM_CONTEXT)Context;

    UNREFERENCED_PARAMETER(ContextType);

    if (streamContext->FileName.Buffer) {
        ExFreePool(streamContext->FileName.Buffer);
    }
}

//
// Pre-create callback
//
FLT_PREOP_CALLBACK_STATUS
XdrfsPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // We'll do most of our work in post-create
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

//
// Post-create callback
//
FLT_POSTOP_CALLBACK_STATUS
XdrfsPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PXDRFS_STREAM_CONTEXT streamContext = NULL;
    ULONG createDisposition;
    BOOLEAN isDirectory;
    
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    // Skip if the operation failed
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Skip directories initially
    if (FltObjects->FileObject->Flags & FO_DIRECTORY_FILE) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Get file name information
    status = XdrfsGetFileNameInformation(Data, FltObjects, &nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo) {
        goto Cleanup;
    }

    // Check if we should ignore this file
    if (XdrfsShouldIgnoreFile(&nameInfo->Name)) {
        goto Cleanup;
    }

    // Get create disposition from parameters
    createDisposition = Data->Iopb->Parameters.Create.Options & 0xFF;

    // Only track certain create dispositions
    if (createDisposition != FILE_CREATE &&
        createDisposition != FILE_OVERWRITE &&
        createDisposition != FILE_OVERWRITE_IF &&
        createDisposition != FILE_SUPERSEDE) {
        goto Cleanup;
    }

    // Create stream context
    status = FltAllocateContext(g_FilterData.Filter,
                              FLT_STREAM_CONTEXT,
                              XDRFS_STREAM_CONTEXT_SIZE,
                              PagedPool,
                              &streamContext);

    if (NT_SUCCESS(status)) {
        RtlZeroMemory(streamContext, XDRFS_STREAM_CONTEXT_SIZE);
        
        // Copy file name
        streamContext->FileName.Length = nameInfo->Name.Length;
        streamContext->FileName.MaximumLength = nameInfo->Name.MaximumLength;
        streamContext->FileName.Buffer = ExAllocatePoolWithTag(PagedPool,
                                                             nameInfo->Name.MaximumLength,
                                                             XDRFS_NAME_TAG);
        
        if (streamContext->FileName.Buffer) {
            RtlCopyMemory(streamContext->FileName.Buffer,
                         nameInfo->Name.Buffer,
                         nameInfo->Name.Length);
            
            // Extract file extension
            XdrfsExtractFileExtension(&nameInfo->Name,
                                    streamContext->FileExtension,
                                    RTL_NUMBER_OF(streamContext->FileExtension));
            
            streamContext->IsExecutable = XdrfsIsExecutableExtension(streamContext->FileExtension);
            streamContext->IsScriptFile = XdrfsIsScriptExtension(streamContext->FileExtension);
            
            // Get process image hash
            XdrfsGetProcessImageHash(PsGetCurrentProcess(),
                                   &streamContext->ProcessImageHash);
            
            KeQuerySystemTime(&streamContext->CreationTime);
            
            // Set the context
            FltSetStreamContext(FltObjects->Instance,
                              FltObjects->FileObject,
                              FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                              streamContext,
                              NULL);
        }
    }

    // Generate file event
    XdrfsGenerateFileEvent(
    XdrfsWire_OnPostCreate(nameInfo, createDisposition, Data->Iopb->Parameters.Create.FileAttributes, HandleToUlong(PsGetCurrentProcessId()), HandleToUlong(PsGetCurrentThreadId()));
XDR_FILE_CREATE,
                          nameInfo,
                          createDisposition,
                          Data->Iopb->Parameters.Create.FileAttributes,
                          0, // Size not available at create time
                          HandleToUlong(PsGetCurrentProcessId()),
                          HandleToUlong(PsGetCurrentThreadId()));

    XdrfsUpdateStatistics(XDR_FILE_CREATE);

Cleanup:
    if (nameInfo) {
        FltReleaseFileNameInformation(nameInfo);
    }
    if (streamContext) {
        FltReleaseContext(streamContext);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

//
// Pre-write callback
//
FLT_PREOP_CALLBACK_STATUS
XdrfsPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // We'll do our work in post-write
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

//
// Post-write callback
//
FLT_POSTOP_CALLBACK_STATUS
XdrfsPostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PXDRFS_STREAM_CONTEXT streamContext = NULL;
    ULONG64 fileSize;
    
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    // Skip if the operation failed
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Get stream context
    status = FltGetStreamContext(FltObjects->Instance,
                               FltObjects->FileObject,
                               &streamContext);

    if (!NT_SUCCESS(status)) {
        // No context, skip
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Only track writes to executables and scripts for noise reduction
    if (!streamContext->IsExecutable && !streamContext->IsScriptFile) {
        goto Cleanup;
    }

    // Get file name information
    status = XdrfsGetFileNameInformation(Data, FltObjects, &nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo) {
        goto Cleanup;
    }

    // Get file size
    fileSize = Data->Iopb->Parameters.Write.ByteOffset.QuadPart + 
               Data->Iopb->Parameters.Write.Length;

    // Generate file event
    XdrfsGenerateFileEvent(
    XdrfsWire_OnPostWrite(nameInfo, fileSize, HandleToUlong(PsGetCurrentProcessId()), HandleToUlong(PsGetCurrentThreadId()));
XDR_FILE_WRITE,
                          nameInfo,
                          0, // No create disposition for write
                          0, // No file attributes for write
                          fileSize,
                          HandleToUlong(PsGetCurrentProcessId()),
                          HandleToUlong(PsGetCurrentThreadId()));

    XdrfsUpdateStatistics(XDR_FILE_WRITE);

Cleanup:
    if (nameInfo) {
        FltReleaseFileNameInformation(nameInfo);
    }
    if (streamContext) {
        FltReleaseContext(streamContext);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

//
// Pre-set information callback
//
FLT_PREOP_CALLBACK_STATUS
XdrfsPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Check if this is a delete or rename operation
    if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation ||
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation) {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//
// Post-set information callback
//
FLT_POSTOP_CALLBACK_STATUS
XdrfsPostSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    XDR_FILE_OP operation;
    
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    // Skip if the operation failed
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Determine operation type
    if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation) {
        operation = XDR_FILE_DELETE;
    } else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation) {
        operation = XDR_FILE_RENAME;
    } else {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Get file name information
    status = XdrfsGetFileNameInformation(Data, FltObjects, &nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo) {
        goto Cleanup;
    }

    // Check if we should ignore this file
    if (XdrfsShouldIgnoreFile(&nameInfo->Name)) {
        goto Cleanup;
    }

    // Generate file event
    XdrfsGenerateFileEvent(
    XdrfsWire_OnPostSetInformation(nameInfo, Data->Iopb->Parameters.SetFileInformation.FileInformationClass, HandleToUlong(PsGetCurrentProcessId()), HandleToUlong(PsGetCurrentThreadId()));
operation,
                          nameInfo,
                          0, // No create disposition
                          0, // No file attributes
                          0, // No file size
                          HandleToUlong(PsGetCurrentProcessId()),
                          HandleToUlong(PsGetCurrentThreadId()));

    XdrfsUpdateStatistics(operation);

Cleanup:
    if (nameInfo) {
        FltReleaseFileNameInformation(nameInfo);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}
