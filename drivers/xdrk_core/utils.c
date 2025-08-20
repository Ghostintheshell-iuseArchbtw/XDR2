//
// Utility Functions for XDR Core Driver
// Helper functions for process info, security, and system utilities
//

#include "xdrk_core.h"

//
// Create security descriptor for device
//
NTSTATUS
XdrCreateSecurityDescriptor(
    _Out_ PSECURITY_DESCRIPTOR* SecurityDescriptor
)
{
    NTSTATUS status;
    ULONG size;
    PSECURITY_DESCRIPTOR sd = NULL;

    FuncEntry();

    // Calculate size needed for security descriptor
    size = sizeof(SECURITY_DESCRIPTOR) + 256; // Extra space for ACL

    sd = ExAllocatePoolWithTag(PagedPool, size, XDR_POOL_TAG);
    if (!sd) {
        LogError(STATUS_INSUFFICIENT_RESOURCES, "Failed to allocate security descriptor");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Initialize security descriptor
    status = RtlCreateSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) {
        LogError(status, "RtlCreateSecurityDescriptor failed");
        ExFreePoolWithTag(sd, XDR_POOL_TAG);
        return status;
    }

    // For simplicity, we'll use the SDDL string in device creation
    // This is a minimal implementation - real world would build proper ACLs
    *SecurityDescriptor = sd;

    FuncExitWithStatus(STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

//
// Get process image path
//
NTSTATUS
XdrGetProcessImagePath(
    _In_ PEPROCESS Process,
    _Out_ PUNICODE_STRING ImagePath
)
{
    NTSTATUS status;
    ULONG returnedLength;
    PUNICODE_STRING processImageFileName;

    if (!Process || !ImagePath) {
        return STATUS_INVALID_PARAMETER;
    }

    // Use ZwQueryInformationProcess to get image path
    status = ZwQueryInformationProcess(NtCurrentProcess(),
                                     ProcessImageFileName,
                                     NULL,
                                     0,
                                     &returnedLength);

    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        return status;
    }

    processImageFileName = ExAllocatePoolWithTag(PagedPool, returnedLength, XDR_POOL_TAG);
    if (!processImageFileName) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryInformationProcess(NtCurrentProcess(),
                                     ProcessImageFileName,
                                     processImageFileName,
                                     returnedLength,
                                     &returnedLength);

    if (NT_SUCCESS(status)) {
        ImagePath->Length = processImageFileName->Length;
        ImagePath->MaximumLength = processImageFileName->MaximumLength;
        ImagePath->Buffer = ExAllocatePoolWithTag(PagedPool, 
                                                processImageFileName->MaximumLength, 
                                                XDR_POOL_TAG);
        
        if (ImagePath->Buffer) {
            RtlCopyMemory(ImagePath->Buffer, 
                         processImageFileName->Buffer, 
                         processImageFileName->Length);
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    ExFreePoolWithTag(processImageFileName, XDR_POOL_TAG);
    return status;
}

//
// Get process command line hash
//
NTSTATUS
XdrGetProcessCommandLine(
    _In_ PEPROCESS Process,
    _Out_ PULONG64 CommandLineHash
)
{
    NTSTATUS status;
    ULONG returnedLength;
    PUNICODE_STRING commandLine = NULL;

    UNREFERENCED_PARAMETER(Process);

    if (!CommandLineHash) {
        return STATUS_INVALID_PARAMETER;
    }

    *CommandLineHash = 0;

    // Try to get command line from current process
    status = ZwQueryInformationProcess(NtCurrentProcess(),
                                     ProcessCommandLineInformation,
                                     NULL,
                                     0,
                                     &returnedLength);

    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        // If we can't get command line, use process ID as hash
        HANDLE processId = PsGetProcessId(Process);
        *CommandLineHash = XdrComputeKeyHash(&processId, sizeof(processId));
        return STATUS_SUCCESS;
    }

    commandLine = ExAllocatePoolWithTag(PagedPool, returnedLength, XDR_POOL_TAG);
    if (!commandLine) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryInformationProcess(NtCurrentProcess(),
                                     ProcessCommandLineInformation,
                                     commandLine,
                                     returnedLength,
                                     &returnedLength);

    if (NT_SUCCESS(status) && commandLine->Buffer && commandLine->Length > 0) {
        *CommandLineHash = XdrComputeKeyHash(commandLine->Buffer, commandLine->Length);
    } else {
        // Fallback to process ID hash
        HANDLE processId = PsGetProcessId(Process);
        *CommandLineHash = XdrComputeKeyHash(&processId, sizeof(processId));
    }

    if (commandLine) {
        ExFreePoolWithTag(commandLine, XDR_POOL_TAG);
    }

    return STATUS_SUCCESS;
}

//
// Get process integrity level
//
ULONG
XdrGetProcessIntegrityLevel(
    _In_ PEPROCESS Process
)
{
    PACCESS_TOKEN token;
    ULONG integrityLevel = SECURITY_MANDATORY_MEDIUM_RID;

    UNREFERENCED_PARAMETER(Process);

    // Get primary token
    token = PsReferencePrimaryToken(Process);
    if (token) {
        // For simplicity, assume medium integrity
        // Real implementation would query token mandatory label
        integrityLevel = SECURITY_MANDATORY_MEDIUM_RID;
        PsDereferencePrimaryToken(token);
    }

    return integrityLevel;
}

//
// Get image signature information
//
NTSTATUS
XdrGetImageSignatureInfo(
    _In_ PUNICODE_STRING ImagePath,
    _Out_ PULONG IsSigned,
    _Out_ PULONG SignerCategory
)
{
    PWCHAR fileName;
    PWCHAR extension;

    if (!ImagePath || !IsSigned || !SignerCategory) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsSigned = 0;
    *SignerCategory = XDR_SIGNER_UNSIGNED;

    if (!ImagePath->Buffer) {
        return STATUS_SUCCESS;
    }

    // Extract filename
    fileName = wcsrchr(ImagePath->Buffer, L'\\');
    if (fileName) {
        fileName++; // Skip backslash
    } else {
        fileName = ImagePath->Buffer;
    }

    // Simple heuristic based on path and filename
    // Real implementation would verify Authenticode signatures
    if (wcsstr(ImagePath->Buffer, L"\\Windows\\System32\\") ||
        wcsstr(ImagePath->Buffer, L"\\Windows\\SysWOW64\\")) {
        *IsSigned = 1;
        *SignerCategory = XDR_SIGNER_WINDOWS;
    } else if (wcsstr(ImagePath->Buffer, L"\\Program Files\\") ||
               wcsstr(ImagePath->Buffer, L"\\Program Files (x86)\\")) {
        // Assume third-party signed for program files
        *IsSigned = 1;
        *SignerCategory = XDR_SIGNER_THIRD_PARTY;
    } else if (wcsstr(ImagePath->Buffer, L"Microsoft") ||
               _wcsnicmp(fileName, L"ms", 2) == 0) {
        *IsSigned = 1;
        *SignerCategory = XDR_SIGNER_MICROSOFT;
    }

    // Check extension for executables
    extension = wcsrchr(fileName, L'.');
    if (extension) {
        if (_wcsicmp(extension, L".exe") == 0 ||
            _wcsicmp(extension, L".dll") == 0 ||
            _wcsicmp(extension, L".sys") == 0) {
            // These should be signed in legitimate scenarios
            if (*IsSigned == 0) {
                // Unsigned executable in suspicious location
                *SignerCategory = XDR_SIGNER_UNSIGNED;
            }
        }
    }

    return STATUS_SUCCESS;
}

//
// Get registry key path from object
//
NTSTATUS
XdrGetRegistryKeyPath(
    _In_ PVOID Object,
    _Out_ PUNICODE_STRING KeyPath
)
{
    NTSTATUS status;
    ULONG returnedLength;
    POBJECT_NAME_INFORMATION nameInfo = NULL;

    if (!Object || !KeyPath) {
        return STATUS_INVALID_PARAMETER;
    }

    // Query object name
    status = ObQueryNameString(Object,
                             NULL,
                             0,
                             &returnedLength);

    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        return status;
    }

    nameInfo = ExAllocatePoolWithTag(PagedPool, returnedLength, XDR_POOL_TAG);
    if (!nameInfo) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ObQueryNameString(Object,
                             nameInfo,
                             returnedLength,
                             &returnedLength);

    if (NT_SUCCESS(status)) {
        KeyPath->Length = nameInfo->Name.Length;
        KeyPath->MaximumLength = nameInfo->Name.MaximumLength;
        KeyPath->Buffer = ExAllocatePoolWithTag(PagedPool, 
                                              nameInfo->Name.MaximumLength, 
                                              XDR_POOL_TAG);
        
        if (KeyPath->Buffer) {
            RtlCopyMemory(KeyPath->Buffer, 
                         nameInfo->Name.Buffer, 
                         nameInfo->Name.Length);
            
            // Null-terminate
            if (KeyPath->Length < KeyPath->MaximumLength - sizeof(WCHAR)) {
                KeyPath->Buffer[KeyPath->Length / sizeof(WCHAR)] = L'\0';
            }
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (nameInfo) {
        ExFreePoolWithTag(nameInfo, XDR_POOL_TAG);
    }

    return status;
}

//
// Classify network flow (placeholder for WFP integration)
//
NTSTATUS
XdrClassifyNetworkFlow(
    _In_ const FWPS_INCOMING_VALUES* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* InMetaValues,
    _Out_ XDR_NETWORK_EVENT* NetworkEvent
)
{
    UNREFERENCED_PARAMETER(InFixedValues);
    UNREFERENCED_PARAMETER(InMetaValues);
    
    if (!NetworkEvent) {
        return STATUS_INVALID_PARAMETER;
    }

    // TODO: Implement WFP classification
    RtlZeroMemory(NetworkEvent, sizeof(XDR_NETWORK_EVENT));
    NetworkEvent->operation = XDR_NET_CONNECT;
    NetworkEvent->verdict = XDR_NET_ALLOW;

    return STATUS_SUCCESS;
}

//
// Helper function to check if a path is in system directories
//
BOOLEAN
XdrIsSystemPath(
    _In_ PUNICODE_STRING Path
)
{
    static const WCHAR* systemPaths[] = {
        L"\\Windows\\System32\\",
        L"\\Windows\\SysWOW64\\",
        L"\\Windows\\WinSxS\\",
        L"\\Program Files\\Windows Defender\\",
        NULL
    };
    
    int i;

    if (!Path || !Path->Buffer) {
        return FALSE;
    }

    for (i = 0; systemPaths[i] != NULL; i++) {
        if (wcsstr(Path->Buffer, systemPaths[i])) {
            return TRUE;
        }
    }

    return FALSE;
}

//
// Helper function to extract file extension
//
NTSTATUS
XdrExtractFileExtension(
    _In_ PUNICODE_STRING FilePath,
    _Out_ PWCHAR Extension,
    _In_ ULONG ExtensionLength
)
{
    PWCHAR fileName;
    PWCHAR ext;

    if (!FilePath || !Extension || ExtensionLength < 8) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Extension, ExtensionLength * sizeof(WCHAR));

    if (!FilePath->Buffer) {
        return STATUS_SUCCESS;
    }

    // Find filename
    fileName = wcsrchr(FilePath->Buffer, L'\\');
    if (fileName) {
        fileName++; // Skip backslash
    } else {
        fileName = FilePath->Buffer;
    }

    // Find extension
    ext = wcsrchr(fileName, L'.');
    if (ext) {
        ext++; // Skip dot
        RtlStringCchCopyW(Extension, ExtensionLength, ext);
        _wcslwr(Extension); // Convert to lowercase
    }

    return STATUS_SUCCESS;
}

//
// Helper to check if we should ignore common noise
//
BOOLEAN
XdrShouldIgnoreEvent(
    _In_ XDR_EVENT_SOURCE Source,
    _In_ const XDR_EVENT_PAYLOAD* Payload
)
{
    if (!Payload) {
        return TRUE;
    }

    switch (Source) {
        case XDR_SOURCE_IMAGE:
        {
            const XDR_IMAGE_EVENT* imageEvent = &Payload->image;
            PWCHAR fileName = wcsrchr(imageEvent->image_path, L'\\');
            
            if (fileName) {
                fileName++; // Skip backslash
                
                // Skip common system DLLs
                if (_wcsicmp(fileName, L"ntdll.dll") == 0 ||
                    _wcsnicmp(fileName, L"wow64", 5) == 0 ||
                    _wcsicmp(fileName, L"kernel32.dll") == 0) {
                    return TRUE;
                }
            }
            break;
        }
        
        case XDR_SOURCE_REGISTRY:
        {
            const XDR_REGISTRY_EVENT* regEvent = &Payload->registry;
            
            // Ignore read-only operations
            if (regEvent->operation == 0) { // Assume 0 is read
                return TRUE;
            }
            
            // Ignore certain noisy keys
            if (wcsstr(regEvent->key_path, L"\\CurrentVersion\\Explorer\\") ||
                wcsstr(regEvent->key_path, L"\\MRU\\") ||
                wcsstr(regEvent->key_path, L"\\Recent\\")) {
                return TRUE;
            }
            break;
        }
        
        case XDR_SOURCE_PROCESS:
        {
            const XDR_PROCESS_EVENT* procEvent = &Payload->process;
            
            // Skip system processes
            if (wcsstr(procEvent->image_path, L"\\Windows\\System32\\") &&
                procEvent->operation == XDR_PROCESS_START) {
                return TRUE;
            }
            break;
        }
        
        default:
            break;
    }

    return FALSE;
}