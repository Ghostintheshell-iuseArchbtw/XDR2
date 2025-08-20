//
// XDR Filesystem Minifilter Utility Functions
// Helper functions for file operations, filtering, and core communication
//

#include "xdrfs.h"

typedef struct _XDRFS_EVENT_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    PXDR_EVENT_RECORD EventRecord;
} XDRFS_EVENT_WORK_ITEM, *PXDRFS_EVENT_WORK_ITEM;

static VOID XdrfsPublishEventWorker(_In_ PVOID Context)
{
    PXDRFS_EVENT_WORK_ITEM work = (PXDRFS_EVENT_WORK_ITEM)Context;
    if (work && work->EventRecord) {
        (void)XdrfsPublishEventToCore(work->EventRecord);
        ExFreePoolWithTag(work->EventRecord, XDRFS_POOL_TAG);
    }
    ExFreePoolWithTag(work, XDRFS_POOL_TAG);
}

static NTSTATUS XdrfsQueueFileEvent(_In_ PXDR_EVENT_RECORD Event)
{
    PXDRFS_EVENT_WORK_ITEM work;

    if (g_FilterData.Stopping) {
        ExFreePoolWithTag(Event, XDRFS_POOL_TAG);
        return STATUS_DEVICE_NOT_READY;
    }

    work = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*work), XDRFS_POOL_TAG);
    if (!work) {
        ExFreePoolWithTag(Event, XDRFS_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    work->EventRecord = Event;
    ExInitializeWorkItem(&work->WorkItem, XdrfsPublishEventWorker, work);
    ExQueueWorkItem(&work->WorkItem, DelayedWorkQueue);
    return STATUS_SUCCESS;
}

//
// Get file name information
//
NTSTATUS
XdrfsGetFileNameInformation(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PFLT_FILE_NAME_INFORMATION *NameInfo
)
{
    NTSTATUS status;

    if (!Data || !FltObjects || !NameInfo) {
        return STATUS_INVALID_PARAMETER;
    }

    *NameInfo = NULL;

    // Get opened name information
    status = FltGetFileNameInformation(Data,
                                     FLT_FILE_NAME_OPENED |
                                     FLT_FILE_NAME_QUERY_DEFAULT,
                                     NameInfo);

    if (NT_SUCCESS(status)) {
        // Parse the name information
        status = FltParseFileNameInformation(*NameInfo);
        if (!NT_SUCCESS(status)) {
            FltReleaseFileNameInformation(*NameInfo);
            *NameInfo = NULL;
        }
    }

    return status;
}

//
// Check if we should ignore a file based on path
//
BOOLEAN
XdrfsShouldIgnoreFile(
    _In_ PUNICODE_STRING FileName
)
{
    int i;
    PWCHAR fileNameUpper = NULL;
    BOOLEAN shouldIgnore = FALSE;
    ULONG len;

    if (!FileName || !FileName->Buffer || FileName->Length == 0) {
        return TRUE;
    }

    // Convert to uppercase for comparison
    len = FileName->Length / sizeof(WCHAR);
    fileNameUpper = ExAllocatePoolWithTag(NonPagedPoolNx, FileName->Length + sizeof(WCHAR), XDRFS_NAME_TAG);
    if (!fileNameUpper) {
        return FALSE; // If we can't allocate, don't ignore
    }

    RtlCopyMemory(fileNameUpper, FileName->Buffer, FileName->Length);
    fileNameUpper[len] = L'\0';
    _wcsupr(fileNameUpper);

    // Check against ignored directories
    for (i = 0; IgnoredDirectories[i] != NULL; i++) {
        WCHAR upperPattern[256];
        RtlStringCchCopyW(upperPattern, RTL_NUMBER_OF(upperPattern), IgnoredDirectories[i]);
        _wcsupr(upperPattern);
        
        if (wcsstr(fileNameUpper, upperPattern)) {
            shouldIgnore = TRUE;
            break;
        }
    }

    // Skip temp files and common noise
    if (!shouldIgnore) {
        PWCHAR fileName = wcsrchr(fileNameUpper, L'\\');
        if (fileName) {
            fileName++; // Skip backslash
            
            // Skip temporary files
            if (wcsstr(fileName, L"~") ||
                wcsstr(fileName, L".TMP") ||
                wcsstr(fileName, L".TEMP") ||
                _wcsnicmp(fileName, L"ETL", 3) == 0) {
                shouldIgnore = TRUE;
            }
        }
    }

    ExFreePoolWithTag(fileNameUpper, XDRFS_NAME_TAG);
    return shouldIgnore;
}

//
// Check if extension is executable
//
BOOLEAN
XdrfsIsExecutableExtension(
    _In_ PCWSTR Extension
)
{
    static const WCHAR* executableExtensions[] = {
        L"exe", L"dll", L"sys", L"scr", L"com", L"msi", NULL
    };
    
    int i;

    if (!Extension || wcslen(Extension) == 0) {
        return FALSE;
    }

    for (i = 0; executableExtensions[i] != NULL; i++) {
        if (_wcsicmp(Extension, executableExtensions[i]) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

//
// Check if extension is script file
//
BOOLEAN
XdrfsIsScriptExtension(
    _In_ PCWSTR Extension
)
{
    static const WCHAR* scriptExtensions[] = {
        L"ps1", L"vbs", L"js", L"bat", L"cmd", L"hta", L"wsf", L"vbe", L"jse", NULL
    };
    
    int i;

    if (!Extension || wcslen(Extension) == 0) {
        return FALSE;
    }

    for (i = 0; scriptExtensions[i] != NULL; i++) {
        if (_wcsicmp(Extension, scriptExtensions[i]) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

//
// Extract file extension from path
//
NTSTATUS
XdrfsExtractFileExtension(
    _In_ PUNICODE_STRING FileName,
    _Out_ PWCHAR Extension,
    _In_ ULONG ExtensionSize
)
{
    PWCHAR fileName, ext;
    ULONG len;

    if (!FileName || !Extension || ExtensionSize < 8) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Extension, ExtensionSize * sizeof(WCHAR));

    if (!FileName->Buffer || FileName->Length == 0) {
        return STATUS_SUCCESS;
    }

    // Find the last backslash (filename part)
    fileName = wcsrchr(FileName->Buffer, L'\\');
    if (fileName) {
        fileName++; // Skip the backslash
    } else {
        fileName = FileName->Buffer;
    }

    // Find the last dot (extension)
    ext = wcsrchr(fileName, L'.');
    if (ext && (ext + 1) != L'\0') {
        ext++; // Skip the dot
        len = min(wcslen(ext), ExtensionSize - 1);
        RtlStringCchCopyNW(Extension, ExtensionSize, ext, len);
        _wcslwr(Extension); // Convert to lowercase
    }

    return STATUS_SUCCESS;
}

//
// Get process image hash (simplified)
//
NTSTATUS
XdrfsGetProcessImageHash(
    _In_ PEPROCESS Process,
    _Out_ PULONG64 ImageHash
)
{
    HANDLE processId;

    if (!Process || !ImageHash) {
        return STATUS_INVALID_PARAMETER;
    }

    // For now, use process ID as a simple hash
    // Real implementation would hash the image path
    processId = PsGetProcessId(Process);
    *ImageHash = (ULONG64)HandleToUlong(processId) * 0x9e3779b97f4a7c15ULL;

    return STATUS_SUCCESS;
}

//
// Generate file event and send to core
//
NTSTATUS
XdrfsGenerateFileEvent(
    _In_ XDR_FILE_OP Operation,
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_ ULONG CreateDisposition,
    _In_ ULONG FileAttributes,
    _In_ ULONG64 FileSize,
    _In_ ULONG ProcessId,
    _In_ ULONG ThreadId
)
{
    PXDR_EVENT_RECORD eventRecord;
    XDR_FILE_EVENT* fileEvent;
    LARGE_INTEGER timestamp;
    NTSTATUS status;
    WCHAR extension[16];

    if (!NameInfo) {
        return STATUS_INVALID_PARAMETER;
    }

    eventRecord = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(XDR_EVENT_RECORD), XDRFS_POOL_TAG);
    if (!eventRecord) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(eventRecord, sizeof(XDR_EVENT_RECORD));
    eventRecord->total_size = sizeof(XDR_EVENT_RECORD);

    eventRecord->header.version = XDR_ABI_VERSION;
    eventRecord->header.source = XDR_SOURCE_FILE;
    eventRecord->header.severity = XDR_SEVERITY_LOW;
    eventRecord->header.process_id = ProcessId;
    eventRecord->header.thread_id = ThreadId;

    KeQuerySystemTimePrecise(&timestamp);
    eventRecord->header.timestamp_100ns = timestamp.QuadPart;

    eventRecord->header.sequence_number = InterlockedIncrement64(&g_FilterData.TotalEvents);

    eventRecord->header.key_hash = 0;
    if (NameInfo->Name.Buffer && NameInfo->Name.Length > 0) {
        ULONG i;
        ULONG64 hash = 0xcbf29ce484222325ULL;
        for (i = 0; i < NameInfo->Name.Length / sizeof(WCHAR); i++) {
            hash ^= (ULONG64)NameInfo->Name.Buffer[i];
            hash *= 0x100000001b3ULL;
        }
        eventRecord->header.key_hash = hash;
    }

    fileEvent = &eventRecord->payload.file;
    fileEvent->operation = Operation;
    fileEvent->create_disposition = CreateDisposition;
    fileEvent->file_size = FileSize;
    fileEvent->file_attributes = FileAttributes;

    XdrfsGetProcessImageHash(PsGetCurrentProcess(), &fileEvent->process_image_hash);

    if (NameInfo->Name.Buffer && NameInfo->Name.Length > 0) {
        ULONG copyLength = min(NameInfo->Name.Length,
                              (XDR_MAX_PATH - 1) * sizeof(WCHAR));
        RtlCopyMemory(fileEvent->file_path,
                     NameInfo->Name.Buffer,
                     copyLength);
        fileEvent->file_path[copyLength / sizeof(WCHAR)] = L'\0';
    }

    XdrfsExtractFileExtension(&NameInfo->Name, extension, RTL_NUMBER_OF(extension));
    RtlStringCchCopyW(fileEvent->file_extension,
                     RTL_NUMBER_OF(fileEvent->file_extension),
                     extension);

    if (XdrfsIsHighRiskOperation(Operation, &NameInfo->Name, CreateDisposition)) {
        eventRecord->header.severity = XDR_SEVERITY_MEDIUM;
    }

    status = XdrfsQueueFileEvent(eventRecord);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_FilterData.DroppedEvents);
        XdrfsDebugPrint("Failed to queue file event: 0x%08X", status);
    }

    return status;
}

//
// Check if operation is high risk
//
BOOLEAN
XdrfsIsHighRiskOperation(
    _In_ XDR_FILE_OP Operation,
    _In_ PUNICODE_STRING FilePath,
    _In_ ULONG CreateDisposition
)
{
    WCHAR extension[16];
    BOOLEAN isSystemPath;

    if (!FilePath) {
        return FALSE;
    }

    XdrfsExtractFileExtension(FilePath, extension, RTL_NUMBER_OF(extension));
    isSystemPath = XdrfsIsSystemDirectory(FilePath);

    switch (Operation) {
        case XDR_FILE_CREATE:
        case XDR_FILE_WRITE:
            // Executable files written outside system directories
            if (XdrfsIsExecutableExtension(extension) && !isSystemPath) {
                return TRUE;
            }
            
            // Script files created/written anywhere
            if (XdrfsIsScriptExtension(extension)) {
                return TRUE;
            }
            
            // Files created with overwrite disposition
            if (CreateDisposition == FILE_OVERWRITE ||
                CreateDisposition == FILE_SUPERSEDE) {
                return TRUE;
            }
            break;

        case XDR_FILE_DELETE:
            // Deletion of executables or scripts
            if (XdrfsIsExecutableExtension(extension) ||
                XdrfsIsScriptExtension(extension)) {
                return TRUE;
            }
            break;

        case XDR_FILE_RENAME:
            // Renaming to executable extension
            if (XdrfsIsExecutableExtension(extension)) {
                return TRUE;
            }
            break;

        default:
            break;
    }

    return FALSE;
}

//
// Check if path is in system directory
//
BOOLEAN
XdrfsIsSystemDirectory(
    _In_ PUNICODE_STRING FilePath
)
{
    static const WCHAR* systemDirs[] = {
        L"\\Windows\\System32\\",
        L"\\Windows\\SysWOW64\\",
        L"\\Program Files\\",
        L"\\Program Files (x86)\\",
        NULL
    };
    
    int i;
    PWCHAR pathUpper = NULL;
    BOOLEAN isSystem = FALSE;
    ULONG len;

    if (!FilePath || !FilePath->Buffer) {
        return FALSE;
    }

    // Convert to uppercase for comparison
    len = FilePath->Length / sizeof(WCHAR);
    pathUpper = ExAllocatePoolWithTag(NonPagedPoolNx, FilePath->Length + sizeof(WCHAR), XDRFS_NAME_TAG);
    if (!pathUpper) {
        return FALSE;
    }

    RtlCopyMemory(pathUpper, FilePath->Buffer, FilePath->Length);
    pathUpper[len] = L'\0';
    _wcsupr(pathUpper);

    for (i = 0; systemDirs[i] != NULL; i++) {
        WCHAR upperPattern[128];
        RtlStringCchCopyW(upperPattern, RTL_NUMBER_OF(upperPattern), systemDirs[i]);
        _wcsupr(upperPattern);
        
        if (wcsstr(pathUpper, upperPattern)) {
            isSystem = TRUE;
            break;
        }
    }

    ExFreePoolWithTag(pathUpper, XDRFS_NAME_TAG);
    return isSystem;
}

//
// Check if file is temporary
//
BOOLEAN
XdrfsIsTemporaryFile(
    _In_ PUNICODE_STRING FilePath
)
{
    static const WCHAR* tempPaths[] = {
        L"\\TEMP\\",
        L"\\TMP\\",
        L"\\AppData\\Local\\Temp\\",
        L"\\Windows\\Temp\\",
        NULL
    };
    
    int i;
    PWCHAR pathUpper = NULL;
    BOOLEAN isTemp = FALSE;
    ULONG len;

    if (!FilePath || !FilePath->Buffer) {
        return FALSE;
    }

    // Convert to uppercase for comparison
    len = FilePath->Length / sizeof(WCHAR);
    pathUpper = ExAllocatePoolWithTag(NonPagedPoolNx, FilePath->Length + sizeof(WCHAR), XDRFS_NAME_TAG);
    if (!pathUpper) {
        return FALSE;
    }

    RtlCopyMemory(pathUpper, FilePath->Buffer, FilePath->Length);
    pathUpper[len] = L'\0';
    _wcsupr(pathUpper);

    for (i = 0; tempPaths[i] != NULL; i++) {
        WCHAR upperPattern[64];
        RtlStringCchCopyW(upperPattern, RTL_NUMBER_OF(upperPattern), tempPaths[i]);
        _wcsupr(upperPattern);
        
        if (wcsstr(pathUpper, upperPattern)) {
            isTemp = TRUE;
            break;
        }
    }

    ExFreePoolWithTag(pathUpper, XDRFS_NAME_TAG);
    return isTemp;
}

//
// Connect to core driver
//
NTSTATUS
XdrfsConnectToCore(VOID)
{
    NTSTATUS status;
    UNICODE_STRING coreDeviceName;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_FilterData.ConnectionLock, &oldIrql);

    if (g_FilterData.Connected) {
        KeReleaseSpinLock(&g_FilterData.ConnectionLock, oldIrql);
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&coreDeviceName, XDR_DEVICE_NAME);

    InitializeObjectAttributes(&objectAttributes,
                             &coreDeviceName,
                             OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                             NULL,
                             NULL);

    status = ZwCreateFile(&g_FilterData.CoreDeviceObject,
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
        status = ObReferenceObjectByHandle(g_FilterData.CoreDeviceObject,
                                         0,
                                         *IoFileObjectType,
                                         KernelMode,
                                         (PVOID*)&g_FilterData.CoreFileObject,
                                         NULL);

        if (NT_SUCCESS(status)) {
            g_FilterData.Connected = TRUE;
            XdrfsInfoPrint("Connected to core driver successfully");
        } else {
            ZwClose(g_FilterData.CoreDeviceObject);
            g_FilterData.CoreDeviceObject = NULL;
        }
    }

    KeReleaseSpinLock(&g_FilterData.ConnectionLock, oldIrql);
    return status;
}

//
// Disconnect from core driver
//
VOID
XdrfsDisconnectFromCore(VOID)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_FilterData.ConnectionLock, &oldIrql);

    if (g_FilterData.Connected) {
        if (g_FilterData.CoreFileObject) {
            ObDereferenceObject(g_FilterData.CoreFileObject);
            g_FilterData.CoreFileObject = NULL;
        }

        if (g_FilterData.CoreDeviceObject) {
            ZwClose(g_FilterData.CoreDeviceObject);
            g_FilterData.CoreDeviceObject = NULL;
        }

        g_FilterData.Connected = FALSE;
        XdrfsInfoPrint("Disconnected from core driver");
    }

    KeReleaseSpinLock(&g_FilterData.ConnectionLock, oldIrql);
}

//
// Publish event to core driver
//
NTSTATUS
XdrfsPublishEventToCore(
    _In_ const XDR_EVENT_RECORD* EventRecord
)
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatus;
    PIRP irp;
    KEVENT event;
    PIO_STACK_LOCATION irpSp;

    if (!EventRecord) {
        return STATUS_INVALID_PARAMETER;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_FilterData.ConnectionLock, &oldIrql);

    if (!g_FilterData.Connected) {
        KeReleaseSpinLock(&g_FilterData.ConnectionLock, oldIrql);
        status = XdrfsConnectToCore();
        if (!NT_SUCCESS(status)) {
            return status;
        }
        KeAcquireSpinLock(&g_FilterData.ConnectionLock, &oldIrql);
    }

    // Create IRP for IOCTL
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    
    irp = IoBuildDeviceIoControlRequest(IOCTL_XDR_PUBLISH_EVENT,
                                      g_FilterData.CoreFileObject->DeviceObject,
                                      (PVOID)EventRecord,
                                      sizeof(XDR_EVENT_RECORD),
                                      NULL,
                                      0,
                                      TRUE, // Internal device control
                                      &event,
                                      &ioStatus);

    if (!irp) {
        KeReleaseSpinLock(&g_FilterData.ConnectionLock, oldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Set up the stack location
    irpSp = IoGetNextIrpStackLocation(irp);
    irpSp->FileObject = g_FilterData.CoreFileObject;

    // Send the IRP
    status = IoCallDriver(g_FilterData.CoreFileObject->DeviceObject, irp);

    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatus.Status;
    }

    KeReleaseSpinLock(&g_FilterData.ConnectionLock, oldIrql);

    if (!NT_SUCCESS(status)) {
        XdrfsDebugPrint("Failed to publish event to core: 0x%08X", status);
    }

    return status;
}

//
// Update statistics
//
VOID
XdrfsUpdateStatistics(
    _In_ XDR_FILE_OP Operation
)
{
    InterlockedIncrement64(&g_FilterData.TotalEvents);

    switch (Operation) {
        case XDR_FILE_CREATE:
            InterlockedIncrement64(&g_FilterData.CreateEvents);
            break;
        case XDR_FILE_WRITE:
            InterlockedIncrement64(&g_FilterData.WriteEvents);
            break;
        case XDR_FILE_DELETE:
        case XDR_FILE_RENAME:
            InterlockedIncrement64(&g_FilterData.DeleteEvents);
            break;
        default:
            break;
    }
}

//
// Log operation details for debugging
//
VOID
XdrfsLogOperationDetails(
    _In_ XDR_FILE_OP Operation,
    _In_ PUNICODE_STRING FilePath,
    _In_ NTSTATUS Status
)
{
    static const WCHAR* operationNames[] = {
        L"CREATE", L"WRITE", L"DELETE", L"RENAME", L"SETINFO"
    };
    
    const WCHAR* opName = L"UNKNOWN";
    
    if (Operation < RTL_NUMBER_OF(operationNames)) {
        opName = operationNames[Operation];
    }

    XdrfsDebugPrint("File %S: %wZ (Status: 0x%08X)",
                   opName,
                   FilePath,
                   Status);
}