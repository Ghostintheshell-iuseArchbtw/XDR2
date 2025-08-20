#pragma once

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>
#include "../../shared/xdr_shared.h"

// Pool tags
#define XDRFS_POOL_TAG 'SFDX'
#define XDRFS_NAME_TAG 'NFDX'
#define XDRFS_CTX_TAG 'CFDX'

// Filter altitude (configurable, starting with 385200)
#define XDRFS_ALTITUDE L"385200"

// Maximum path length we'll track
#define XDRFS_MAX_TRACKED_PATH 512

// File extensions we always track
static const WCHAR* TrackedExtensions[] = {
    L".exe", L".dll", L".sys", L".ps1", L".vbs", 
    L".js", L".bat", L".cmd", L".scr", L".com",
    L".msi", L".jar", L".hta", L".lnk", L".chm",
    NULL
};

// Directories we ignore (noise reduction)
static const WCHAR* IgnoredDirectories[] = {
    L"\\Windows\\Temp\\",
    L"\\Windows\\Logs\\",
    L"\\Windows\\Prefetch\\",
    L"\\Windows\\SoftwareDistribution\\",
    L"\\ProgramData\\Microsoft\\Windows Defender\\",
    L"\\Users\\All Users\\Microsoft\\Windows Defender\\",
    NULL
};

// Volume context structure
typedef struct _XDRFS_VOLUME_CONTEXT {
    PFLT_VOLUME Volume;
    UNICODE_STRING VolumeName;
    BOOLEAN MonitoringEnabled;
} XDRFS_VOLUME_CONTEXT, *PXDRFS_VOLUME_CONTEXT;

#define XDRFS_VOLUME_CONTEXT_SIZE sizeof(XDRFS_VOLUME_CONTEXT)

// Stream context structure
typedef struct _XDRFS_STREAM_CONTEXT {
    UNICODE_STRING FileName;
    WCHAR FileExtension[16];
    BOOLEAN IsExecutable;
    BOOLEAN IsScriptFile;
    LARGE_INTEGER CreationTime;
    ULONG64 ProcessImageHash;
    ULONG AccessCount;
} XDRFS_STREAM_CONTEXT, *PXDRFS_STREAM_CONTEXT;

#define XDRFS_STREAM_CONTEXT_SIZE sizeof(XDRFS_STREAM_CONTEXT)

// Filter data structure
typedef struct _XDRFS_DATA {
    PFLT_FILTER Filter;
    PFLT_PORT ServerPort;
    PEPROCESS UserProcess;
    PDEVICE_OBJECT CoreDeviceObject;
    PFILE_OBJECT CoreFileObject;
    BOOLEAN Connected;
    FAST_MUTEX ConnectionLock;
    
    // Statistics
    LONG64 TotalEvents;
    LONG64 DroppedEvents;
    LONG64 CreateEvents;
    LONG64 WriteEvents;
    LONG64 DeleteEvents;
    
} XDRFS_DATA, *PXDRFS_DATA;

// Global filter data
extern XDRFS_DATA g_FilterData;

// Function prototypes

// Driver entry and cleanup
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS XdrfsUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

// Instance setup and teardown
NTSTATUS XdrfsInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID XdrfsInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID XdrfsInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

// Query teardown
NTSTATUS XdrfsInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

// Operation callbacks
FLT_PREOP_CALLBACK_STATUS XdrfsPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS XdrfsPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS XdrfsPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS XdrfsPostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS XdrfsPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS XdrfsPostSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

// Context management
VOID XdrfsVolumeContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
);

VOID XdrfsStreamContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
);

// Utility functions
NTSTATUS XdrfsGetFileNameInformation(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PFLT_FILE_NAME_INFORMATION *NameInfo
);

BOOLEAN XdrfsShouldIgnoreFile(
    _In_ PUNICODE_STRING FileName
);

BOOLEAN XdrfsIsExecutableExtension(
    _In_ PCWSTR Extension
);

BOOLEAN XdrfsIsScriptExtension(
    _In_ PCWSTR Extension
);

NTSTATUS XdrfsExtractFileExtension(
    _In_ PUNICODE_STRING FileName,
    _Out_ PWCHAR Extension,
    _In_ ULONG ExtensionSize
);

NTSTATUS XdrfsGetProcessImageHash(
    _In_ PEPROCESS Process,
    _Out_ PULONG64 ImageHash
);

// Event generation
NTSTATUS XdrfsGenerateFileEvent(
    _In_ XDR_FILE_OP Operation,
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_ ULONG CreateDisposition,
    _In_ ULONG FileAttributes,
    _In_ ULONG64 FileSize,
    _In_ ULONG ProcessId,
    _In_ ULONG ThreadId
);

NTSTATUS XdrfsPublishEventToCore(
    _In_ const XDR_EVENT_RECORD* EventRecord
);

// Core driver communication
NTSTATUS XdrfsConnectToCore(VOID);

VOID XdrfsDisconnectFromCore(VOID);

// File path utilities
NTSTATUS XdrfsNormalizeFilePath(
    _In_ PUNICODE_STRING OriginalPath,
    _Out_ PUNICODE_STRING NormalizedPath
);

BOOLEAN XdrfsIsSystemDirectory(
    _In_ PUNICODE_STRING FilePath
);

BOOLEAN XdrfsIsTemporaryFile(
    _In_ PUNICODE_STRING FilePath
);

// Configuration and filtering
BOOLEAN XdrfsShouldMonitorOperation(
    _In_ XDR_FILE_OP Operation,
    _In_ PUNICODE_STRING FilePath,
    _In_ PEPROCESS Process
);

BOOLEAN XdrfsIsHighRiskOperation(
    _In_ XDR_FILE_OP Operation,
    _In_ PUNICODE_STRING FilePath,
    _In_ ULONG CreateDisposition
);

// Statistics and debugging
VOID XdrfsUpdateStatistics(
    _In_ XDR_FILE_OP Operation
);

VOID XdrfsLogOperationDetails(
    _In_ XDR_FILE_OP Operation,
    _In_ PUNICODE_STRING FilePath,
    _In_ NTSTATUS Status
);

// Constants for create disposition mapping
#define XDRFS_MAP_CREATE_DISPOSITION(disp) \
    ((disp) == FILE_CREATE ? XDR_FILE_CREATE : \
     (disp) == FILE_OVERWRITE || (disp) == FILE_OVERWRITE_IF ? XDR_FILE_WRITE : \
     XDR_FILE_CREATE)

// Macros for logging
#define XdrfsDbgPrint(Level, Format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, Level, "[XDRFS] " Format "\n", ##__VA_ARGS__)

#ifdef DBG
#define XdrfsDebugPrint(Format, ...) \
    XdrfsDbgPrint(DPFLTR_INFO_LEVEL, Format, ##__VA_ARGS__)
#else
#define XdrfsDebugPrint(Format, ...)
#endif

#define XdrfsErrorPrint(Format, ...) \
    XdrfsDbgPrint(DPFLTR_ERROR_LEVEL, "ERROR: " Format, ##__VA_ARGS__)

#define XdrfsWarningPrint(Format, ...) \
    XdrfsDbgPrint(DPFLTR_WARNING_LEVEL, "WARNING: " Format, ##__VA_ARGS__)

#define XdrfsInfoPrint(Format, ...) \
    XdrfsDbgPrint(DPFLTR_INFO_LEVEL, Format, ##__VA_ARGS__)