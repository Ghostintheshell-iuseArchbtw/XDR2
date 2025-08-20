//
// System Callback Implementations for XDR Core Driver
// Handles process, thread, image, and registry notifications
//

#include "xdrk_core.h"

//
// Register system callbacks
//
NTSTATUS
XdrRegisterCallbacks(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext
)
{
    NTSTATUS status;

    FuncEntry();

    // Register process create/exit callback
    status = PsSetCreateProcessNotifyRoutineEx(XdrProcessCreateNotifyRoutineEx, FALSE);
    if (!NT_SUCCESS(status)) {
        LogError(status, "Failed to register process callback");
        goto Exit;
    }
    DeviceContext->ProcessCallbackRegistered = TRUE;
    TraceCallbacks(TRACE_LEVEL_INFORMATION, "Process callback registered");

    // Register thread create/exit callback
    status = PsSetCreateThreadNotifyRoutine(XdrThreadCreateNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        LogError(status, "Failed to register thread callback");
        goto Exit;
    }
    DeviceContext->ThreadCallbackRegistered = TRUE;
    TraceCallbacks(TRACE_LEVEL_INFORMATION, "Thread callback registered");

    // Register image load callback
    status = PsSetLoadImageNotifyRoutine(XdrImageLoadNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        LogError(status, "Failed to register image callback");
        goto Exit;
    }
    DeviceContext->ImageCallbackRegistered = TRUE;
    TraceCallbacks(TRACE_LEVEL_INFORMATION, "Image load callback registered");

    // Register registry callback
    status = CmRegisterCallbackEx(XdrRegistryCallback,
                                &DeviceContext->CmCookie,
                                DeviceContext,
                                NULL,
                                NULL,
                                NULL);
    if (!NT_SUCCESS(status)) {
        LogError(status, "Failed to register registry callback");
        goto Exit;
    }
    DeviceContext->RegistryCallbackRegistered = TRUE;
    TraceCallbacks(TRACE_LEVEL_INFORMATION, "Registry callback registered");

    TraceCallbacks(TRACE_LEVEL_INFORMATION, "All system callbacks registered successfully");

Exit:
    if (!NT_SUCCESS(status)) {
        XdrUnregisterCallbacks(DeviceContext);
    }

    FuncExitWithStatus(status);
    return status;
}

//
// Unregister system callbacks
//
VOID
XdrUnregisterCallbacks(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext
)
{
    FuncEntry();

    if (DeviceContext->RegistryCallbackRegistered) {
        CmUnRegisterCallback(DeviceContext->CmCookie);
        DeviceContext->RegistryCallbackRegistered = FALSE;
        TraceCallbacks(TRACE_LEVEL_INFORMATION, "Registry callback unregistered");
    }

    if (DeviceContext->ImageCallbackRegistered) {
        PsRemoveLoadImageNotifyRoutine(XdrImageLoadNotifyRoutine);
        DeviceContext->ImageCallbackRegistered = FALSE;
        TraceCallbacks(TRACE_LEVEL_INFORMATION, "Image load callback unregistered");
    }

    if (DeviceContext->ThreadCallbackRegistered) {
        PsRemoveCreateThreadNotifyRoutine(XdrThreadCreateNotifyRoutine);
        DeviceContext->ThreadCallbackRegistered = FALSE;
        TraceCallbacks(TRACE_LEVEL_INFORMATION, "Thread callback unregistered");
    }

    if (DeviceContext->ProcessCallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(XdrProcessCreateNotifyRoutineEx, TRUE);
        DeviceContext->ProcessCallbackRegistered = FALSE;
        TraceCallbacks(TRACE_LEVEL_INFORMATION, "Process callback unregistered");
    }

    FuncExit();
}

//
// Process create/exit notification callback
//
VOID
XdrProcessCreateNotifyRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    XDR_EVENT_PAYLOAD payload;
    XDR_PROCESS_EVENT* processEvent;
    ULONG64 keyHash;
    LARGE_INTEGER timestamp;
    UNICODE_STRING imagePath = {0};
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Process);

    if (!g_DeviceContext) {
        return;
    }

    processEvent = &payload.process;
    RtlZeroMemory(processEvent, sizeof(XDR_PROCESS_EVENT));

    if (CreateInfo) {
        // Process creation
        processEvent->operation = XDR_PROCESS_START;
        processEvent->parent_process_id = HandleToUlong(CreateInfo->ParentProcessId);
        
        // Get image path
        if (CreateInfo->ImageFileName) {
            RtlStringCchCopyNW(processEvent->image_path,
                             RTL_NUMBER_OF(processEvent->image_path),
                             CreateInfo->ImageFileName->Buffer,
                             CreateInfo->ImageFileName->Length / sizeof(WCHAR));
            
            keyHash = XdrComputeKeyHash(CreateInfo->ImageFileName->Buffer,
                                      CreateInfo->ImageFileName->Length);
        } else {
            // Fallback to process object
            status = XdrGetProcessImagePath(Process, &imagePath);
            if (NT_SUCCESS(status) && imagePath.Buffer) {
                RtlStringCchCopyNW(processEvent->image_path,
                                 RTL_NUMBER_OF(processEvent->image_path),
                                 imagePath.Buffer,
                                 imagePath.Length / sizeof(WCHAR));
                
                keyHash = XdrComputeKeyHash(imagePath.Buffer, imagePath.Length);
                ExFreePool(imagePath.Buffer);
            } else {
                wcscpy_s(processEvent->image_path, RTL_NUMBER_OF(processEvent->image_path), L"<unknown>");
                keyHash = XdrComputeKeyHash(&ProcessId, sizeof(ProcessId));
            }
        }

        // Get command line hash
        XdrGetProcessCommandLine(Process, &processEvent->cmdline_hash);
        
        // Get integrity level and token flags
        processEvent->integrity_level = XdrGetProcessIntegrityLevel(Process);
        
        // Get SID hash (simplified)
        processEvent->sid_hash = XdrComputeKeyHash(&ProcessId, sizeof(ProcessId));

        TraceCallbacks(TRACE_LEVEL_VERBOSE, 
                      "Process created: PID=%lu, PPID=%lu, Image=%S",
                      HandleToUlong(ProcessId),
                      processEvent->parent_process_id,
                      processEvent->image_path);
    } else {
        // Process exit
        processEvent->operation = XDR_PROCESS_EXIT;
        processEvent->exit_code = (ULONG)PsGetProcessExitStatus(Process);
        
        // For exit events, use PID as key
        keyHash = XdrComputeKeyHash(&ProcessId, sizeof(ProcessId));

        TraceCallbacks(TRACE_LEVEL_VERBOSE, 
                      "Process exited: PID=%lu, ExitCode=%lu",
                      HandleToUlong(ProcessId),
                      processEvent->exit_code);
    }

    // Enqueue the event
    XdrNormalizeAndEnqueue(g_DeviceContext,
                          XDR_SOURCE_PROCESS,
                          XDR_SEVERITY_LOW,
                          HandleToUlong(ProcessId),
                          0, // No specific thread for process events
                          &payload,
                          keyHash);
}

//
// Thread create/exit notification callback
//
VOID
XdrThreadCreateNotifyRoutine(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
)
{
    XDR_EVENT_PAYLOAD payload;
    XDR_THREAD_EVENT* threadEvent;
    ULONG64 keyHash;
    PEPROCESS process;
    PETHREAD thread;
    NTSTATUS status;

    if (!g_DeviceContext) {
        return;
    }

    // Skip system process threads unless specifically configured
    if (HandleToUlong(ProcessId) <= 4) {
        return;
    }

    threadEvent = &payload.thread;
    RtlZeroMemory(threadEvent, sizeof(XDR_THREAD_EVENT));

    if (Create) {
        threadEvent->operation = XDR_THREAD_CREATE;
        
        // Get thread start address
        status = PsLookupThreadByThreadId(ThreadId, &thread);
        if (NT_SUCCESS(status)) {
            threadEvent->start_address = (ULONG64)PsGetThreadStartAddress(thread);
            ObDereferenceObject(thread);
        }

        // Get owner process image hash
        status = PsLookupProcessByProcessId(ProcessId, &process);
        if (NT_SUCCESS(status)) {
            UNICODE_STRING imagePath;
            status = XdrGetProcessImagePath(process, &imagePath);
            if (NT_SUCCESS(status) && imagePath.Buffer) {
                threadEvent->owner_image_hash = XdrComputeKeyHash(imagePath.Buffer, imagePath.Length);
                ExFreePool(imagePath.Buffer);
            }
            ObDereferenceObject(process);
        }

        TraceCallbacks(TRACE_LEVEL_VERBOSE, 
                      "Thread created: PID=%lu, TID=%lu, StartAddr=0x%llx",
                      HandleToUlong(ProcessId),
                      HandleToUlong(ThreadId),
                      threadEvent->start_address);
    } else {
        threadEvent->operation = XDR_THREAD_EXIT;
        
        TraceCallbacks(TRACE_LEVEL_VERBOSE, 
                      "Thread exited: PID=%lu, TID=%lu",
                      HandleToUlong(ProcessId),
                      HandleToUlong(ThreadId));
    }

    // Use thread ID as key
    keyHash = XdrComputeKeyHash(&ThreadId, sizeof(ThreadId));

    // Enqueue the event
    XdrNormalizeAndEnqueue(g_DeviceContext,
                          XDR_SOURCE_THREAD,
                          XDR_SEVERITY_LOW,
                          HandleToUlong(ProcessId),
                          HandleToUlong(ThreadId),
                          &payload,
                          keyHash);
}

//
// Image load notification callback
//
VOID
XdrImageLoadNotifyRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
)
{
    XDR_EVENT_PAYLOAD payload;
    XDR_IMAGE_EVENT* imageEvent;
    ULONG64 keyHash;
    UNICODE_STRING imagePath = {0};
    PWCHAR fileName;

    if (!g_DeviceContext) {
        return;
    }

    // Skip system process images unless configured
    if (HandleToUlong(ProcessId) <= 4) {
        return;
    }

    imageEvent = &payload.image;
    RtlZeroMemory(imageEvent, sizeof(XDR_IMAGE_EVENT));

    // Extract basic image information
    imageEvent->base_address = (ULONG64)ImageInfo->ImageBase;
    imageEvent->image_size = (ULONG64)ImageInfo->ImageSize;

    // Handle image path
    if (FullImageName && FullImageName->Buffer) {
        RtlStringCchCopyNW(imageEvent->image_path,
                         RTL_NUMBER_OF(imageEvent->image_path),
                         FullImageName->Buffer,
                         FullImageName->Length / sizeof(WCHAR));
        
        keyHash = XdrComputeKeyHash(FullImageName->Buffer, FullImageName->Length);
        
        // Extract file name for noise reduction
        fileName = wcsrchr(FullImageName->Buffer, L'\\');
        if (fileName) {
            fileName++; // Skip the backslash
            
            // Skip common system DLLs unless high severity
            if (_wcsicmp(fileName, L"ntdll.dll") == 0 ||
                _wcsnicmp(fileName, L"wow64", 5) == 0) {
                return; // Skip unless specifically requested
            }
        }
    } else {
        wcscpy_s(imageEvent->image_path, RTL_NUMBER_OF(imageEvent->image_path), L"<unknown>");
        keyHash = XdrComputeKeyHash(&ImageInfo->ImageBase, sizeof(ImageInfo->ImageBase));
    }

    // Get signature information (simplified)
    if (FullImageName) {
        XdrGetImageSignatureInfo(FullImageName, 
                               &imageEvent->is_signed,
                               &imageEvent->signer_category);
    }

    // Compute simplified image hash (using base address for now)
    imageEvent->image_hash = XdrComputeKeyHash(&ImageInfo->ImageBase, sizeof(ImageInfo->ImageBase));

    // Set timestamp from image info if available
    imageEvent->timestamp = 0; // TODO: Extract PE timestamp

    TraceCallbacks(TRACE_LEVEL_VERBOSE, 
                  "Image loaded: PID=%lu, Base=0x%llx, Size=0x%llx, Image=%S",
                  HandleToUlong(ProcessId),
                  imageEvent->base_address,
                  imageEvent->image_size,
                  imageEvent->image_path);

    // Enqueue the event
    XdrNormalizeAndEnqueue(g_DeviceContext,
                          XDR_SOURCE_IMAGE,
                          XDR_SEVERITY_LOW,
                          HandleToUlong(ProcessId),
                          HandleToUlong(PsGetCurrentThreadId()),
                          &payload,
                          keyHash);
}

//
// Registry callback
//
NTSTATUS
XdrRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
)
{
    REG_NOTIFY_CLASS notifyClass;
    XDR_EVENT_PAYLOAD payload;
    XDR_REGISTRY_EVENT* regEvent;
    ULONG64 keyHash;
    HANDLE processId;
    HANDLE threadId;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (!g_DeviceContext || !Argument1) {
        return STATUS_SUCCESS;
    }

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    regEvent = &payload.registry;
    RtlZeroMemory(regEvent, sizeof(XDR_REGISTRY_EVENT));

    processId = PsGetCurrentProcessId();
    threadId = PsGetCurrentThreadId();

    // Only monitor specific registry operations to reduce noise
    switch (notifyClass) {
        case RegNtPostCreateKeyEx:
        case RegNtPostOpenKeyEx:
        {
            PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
            PREG_CREATE_KEY_INFORMATION preInfo;
            UNICODE_STRING keyPath;
            
            if (!NT_SUCCESS(postInfo->Status)) {
                break;
            }
            
            preInfo = (PREG_CREATE_KEY_INFORMATION)postInfo->PreInformation;
            if (!preInfo || !preInfo->CompleteName) {
                break;
            }

            regEvent->operation = (notifyClass == RegNtPostCreateKeyEx) ? 
                                XDR_REG_CREATE_KEY : XDR_REG_CREATE_KEY;

            // Copy key path (truncated if necessary)
            RtlStringCchCopyNW(regEvent->key_path,
                             RTL_NUMBER_OF(regEvent->key_path),
                             preInfo->CompleteName->Buffer,
                             min(preInfo->CompleteName->Length / sizeof(WCHAR),
                                 RTL_NUMBER_OF(regEvent->key_path) - 1));

            keyHash = XdrComputeKeyHash(preInfo->CompleteName->Buffer, preInfo->CompleteName->Length);
            
            TraceCallbacks(TRACE_LEVEL_VERBOSE, 
                          "Registry key %s: PID=%lu, Key=%S",
                          (notifyClass == RegNtPostCreateKeyEx) ? "created" : "opened",
                          HandleToUlong(processId),
                          regEvent->key_path);
            break;
        }

        case RegNtPostSetValueKey:
        {
            PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
            PREG_SET_VALUE_KEY_INFORMATION preInfo;
            UNICODE_STRING keyPath;
            
            if (!NT_SUCCESS(postInfo->Status)) {
                break;
            }
            
            preInfo = (PREG_SET_VALUE_KEY_INFORMATION)postInfo->PreInformation;
            if (!preInfo) {
                break;
            }

            regEvent->operation = XDR_REG_SET_VALUE;
            regEvent->value_type = preInfo->Type;
            regEvent->data_size = preInfo->DataSize;

            // Get key path
            status = XdrGetRegistryKeyPath(preInfo->Object, &keyPath);
            if (NT_SUCCESS(status) && keyPath.Buffer) {
                RtlStringCchCopyNW(regEvent->key_path,
                                 RTL_NUMBER_OF(regEvent->key_path),
                                 keyPath.Buffer,
                                 keyPath.Length / sizeof(WCHAR));
                ExFreePool(keyPath.Buffer);
            }

            // Copy value name
            if (preInfo->ValueName && preInfo->ValueName->Buffer) {
                RtlStringCchCopyNW(regEvent->value_name,
                                 RTL_NUMBER_OF(regEvent->value_name),
                                 preInfo->ValueName->Buffer,
                                 preInfo->ValueName->Length / sizeof(WCHAR));
            }

            // Hash the data
            if (preInfo->Data && preInfo->DataSize > 0) {
                regEvent->data_hash = XdrComputeKeyHash(preInfo->Data, preInfo->DataSize);
            }

            keyHash = XdrComputeKeyHash(regEvent->key_path, wcslen(regEvent->key_path) * sizeof(WCHAR));
            
            TraceCallbacks(TRACE_LEVEL_VERBOSE, 
                          "Registry value set: PID=%lu, Key=%S, Value=%S",
                          HandleToUlong(processId),
                          regEvent->key_path,
                          regEvent->value_name);
            break;
        }

        case RegNtPostDeleteKey:
        case RegNtPostDeleteValueKey:
        {
            PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
            UNICODE_STRING keyPath;
            
            if (!NT_SUCCESS(postInfo->Status)) {
                break;
            }

            regEvent->operation = (notifyClass == RegNtPostDeleteKey) ? 
                                XDR_REG_DELETE_KEY : XDR_REG_DELETE_VALUE;

            if (notifyClass == RegNtPostDeleteKey) {
                PREG_DELETE_KEY_INFORMATION preInfo = (PREG_DELETE_KEY_INFORMATION)postInfo->PreInformation;
                if (preInfo) {
                    status = XdrGetRegistryKeyPath(preInfo->Object, &keyPath);
                    if (NT_SUCCESS(status) && keyPath.Buffer) {
                        RtlStringCchCopyNW(regEvent->key_path,
                                         RTL_NUMBER_OF(regEvent->key_path),
                                         keyPath.Buffer,
                                         keyPath.Length / sizeof(WCHAR));
                        ExFreePool(keyPath.Buffer);
                    }
                }
            } else {
                PREG_DELETE_VALUE_KEY_INFORMATION preInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)postInfo->PreInformation;
                if (preInfo) {
                    status = XdrGetRegistryKeyPath(preInfo->Object, &keyPath);
                    if (NT_SUCCESS(status) && keyPath.Buffer) {
                        RtlStringCchCopyNW(regEvent->key_path,
                                         RTL_NUMBER_OF(regEvent->key_path),
                                         keyPath.Buffer,
                                         keyPath.Length / sizeof(WCHAR));
                        ExFreePool(keyPath.Buffer);
                    }
                    
                    if (preInfo->ValueName && preInfo->ValueName->Buffer) {
                        RtlStringCchCopyNW(regEvent->value_name,
                                         RTL_NUMBER_OF(regEvent->value_name),
                                         preInfo->ValueName->Buffer,
                                         preInfo->ValueName->Length / sizeof(WCHAR));
                    }
                }
            }

            keyHash = XdrComputeKeyHash(regEvent->key_path, wcslen(regEvent->key_path) * sizeof(WCHAR));
            
            TraceCallbacks(TRACE_LEVEL_VERBOSE, 
                          "Registry %s deleted: PID=%lu, Key=%S",
                          (notifyClass == RegNtPostDeleteKey) ? "key" : "value",
                          HandleToUlong(processId),
                          regEvent->key_path);
            break;
        }

        default:
            // Ignore other registry operations
            return STATUS_SUCCESS;
    }

    // Enqueue the event if we processed it
    if (regEvent->operation != 0 || wcslen(regEvent->key_path) > 0) {
        XdrNormalizeAndEnqueue(g_DeviceContext,
                              XDR_SOURCE_REGISTRY,
                              XDR_SEVERITY_LOW,
                              HandleToUlong(processId),
                              HandleToUlong(threadId),
                              &payload,
                              keyHash);
    }

    return STATUS_SUCCESS;
}

//
// Normalize and enqueue an event
//
NTSTATUS
XdrNormalizeAndEnqueue(
    _In_ PXDR_DEVICE_CONTEXT DeviceContext,
    _In_ XDR_EVENT_SOURCE Source,
    _In_ XDR_SEVERITY Severity,
    _In_ ULONG ProcessId,
    _In_ ULONG ThreadId,
    _In_ const XDR_EVENT_PAYLOAD* Payload,
    _In_ ULONG64 KeyHash
)
{
    XDR_EVENT_RECORD record;
    LARGE_INTEGER timestamp;

    if (!DeviceContext || !Payload) {
        return STATUS_INVALID_PARAMETER;
    }

    // Initialize record
    RtlZeroMemory(&record, sizeof(record));
    record.total_size = sizeof(XDR_EVENT_RECORD);

    // Fill header
    record.header.version = XDR_ABI_VERSION;
    record.header.source = (USHORT)Source;
    record.header.severity = (USHORT)Severity;
    record.header.flags = 0;
    record.header.process_id = ProcessId;
    record.header.thread_id = ThreadId;
    record.header.session_id = 0; // TODO: Get session ID
    record.header.key_hash = KeyHash;

    // Set timestamp
    XdrGetCurrentTimeStamp(&timestamp);
    record.header.timestamp_100ns = timestamp.QuadPart;

    // Set sequence number
    record.header.sequence_number = InterlockedIncrement64(&DeviceContext->SequenceCounter);
    record.header.prev_seq_same_key = 0; // TODO: Implement correlation tracking

    // Copy payload
    record.payload = *Payload;

    // Enqueue the event
    return XdrEnqueueEvent(DeviceContext, &record);
}