#include <fltKernel.h>
#include <ntstrsafe.h>
#include "..\..\shared\xdr_shared.h"
#include "xdrfs_publish.h"
#include "xdrfs_wire.h"

static UINT64 fnv1a64_bytes(const void* data, SIZE_T len) {
    const unsigned char* p=(const unsigned char*)data;
    UINT64 h=1469598103934665603ULL;
    while (len--) { h ^= *p++; h *= 1099511628211ULL; }
    return h;
}

static UINT64 hash_process_image(void) {
    const char* name = PsGetProcessImageFileName(PsGetCurrentProcess());
    if (!name) return 0;
    size_t len = 0; while (name[len] && len < 260) len++;
    return fnv1a64_bytes(name, len);
}

static VOID fill_common_header(XDR_EVENT_RECORD* rec, USHORT source, UINT64 key_hash) {
    LARGE_INTEGER t; KeQuerySystemTimePrecise(&t);
    rec->total_size = sizeof(*rec);
    rec->header.version = XDR_ABI_VERSION;
    rec->header.source = source;
    rec->header.severity = XDR_SEVERITY_LOW;
    rec->header.flags = 0;
    rec->header.timestamp_100ns = (UINT64)t.QuadPart;
    rec->header.process_id = HandleToULong(PsGetCurrentProcessId());
    rec->header.thread_id  = HandleToULong(PsGetCurrentThreadId());
    rec->header.session_id = 0;
    __try {
        PEPROCESS pe = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId(PsGetCurrentProcessId(), &pe))) {
            rec->header.session_id = PsGetProcessSessionId(pe);
            ObDereferenceObject(pe);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    rec->header.reserved = 0;
    rec->header.sequence_number = 0; // Core will stamp real sequence
    rec->header.prev_seq_same_key = 0;
    rec->header.key_hash = key_hash;
}

static VOID publish_record(XDR_EVENT_RECORD* rec) {
    PFILE_OBJECT fo=NULL; PDEVICE_OBJECT dev=NULL;
    if (NT_SUCCESS(XdrCoreOpenForKernel(&fo, &dev))) {
        (void)XdrCorePublishEvent(fo, dev, rec, sizeof(*rec), IOCTL_XDR_PUBLISH_EVENT);
    }
}

static VOID copy_wstr_trunc(wchar_t* dst, SIZE_T dstElems, PCUNICODE_STRING src) {
    if (!dst || !src) return;
    size_t n = src->Length / sizeof(WCHAR);
    if (n >= dstElems) n = dstElems - 1;
    RtlCopyMemory(dst, src->Buffer, n * sizeof(WCHAR));
    dst[n] = L'\0';
}

VOID XdrfsWire_OnPostCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    UNREFERENCED_PARAMETER(FltObjects);
    XDR_EVENT_RECORD rec; RtlZeroMemory(&rec, sizeof(rec));
    XDR_FILE_EVENT* fe = &rec.payload.file;

    // File name
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    if (NT_SUCCESS(FltGetFileNameInformation(Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
            &nameInfo))) {
        FltParseFileNameInformation(nameInfo);
        UINT64 key = fnv1a64_bytes(nameInfo->Name.Buffer, nameInfo->Name.Length);
        fill_common_header(&rec, XDR_SOURCE_FILE, key);
        fe->operation = XDR_FILE_CREATE;
        fe->create_disposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
        fe->file_size = 0;
        fe->process_image_hash = hash_process_image();
        fe->file_attributes = Data->Iopb->Parameters.Create.FileAttributes;
        copy_wstr_trunc(fe->file_path, XDR_MAX_PATH, &nameInfo->Name);
        copy_wstr_trunc(fe->file_extension, 16, &nameInfo->Extension);
        publish_record(&rec);
        FltReleaseFileNameInformation(nameInfo);
    }
}

VOID XdrfsWire_OnPostWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    UNREFERENCED_PARAMETER(FltObjects);
    XDR_EVENT_RECORD rec; RtlZeroMemory(&rec, sizeof(rec));
    XDR_FILE_EVENT* fe = &rec.payload.file;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    if (NT_SUCCESS(FltGetFileNameInformation(Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
            &nameInfo))) {
        FltParseFileNameInformation(nameInfo);
        UINT64 key = fnv1a64_bytes(nameInfo->Name.Buffer, nameInfo->Name.Length);
        fill_common_header(&rec, XDR_SOURCE_FILE, key);
        fe->operation = XDR_FILE_WRITE;
        fe->create_disposition = 0;
        fe->file_size = Data->Iopb->Parameters.Write.Length;
        fe->process_image_hash = hash_process_image();
        fe->file_attributes = 0;
        copy_wstr_trunc(fe->file_path, XDR_MAX_PATH, &nameInfo->Name);
        copy_wstr_trunc(fe->file_extension, 16, &nameInfo->Extension);
        publish_record(&rec);
        FltReleaseFileNameInformation(nameInfo);
    }
}

VOID XdrfsWire_OnPostSetInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    UNREFERENCED_PARAMETER(FltObjects);
    XDR_EVENT_RECORD rec; RtlZeroMemory(&rec, sizeof(rec));
    XDR_FILE_EVENT* fe = &rec.payload.file;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    if (NT_SUCCESS(FltGetFileNameInformation(Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
            &nameInfo))) {
        FltParseFileNameInformation(nameInfo);
        UINT64 key = fnv1a64_bytes(nameInfo->Name.Buffer, nameInfo->Name.Length);
        fill_common_header(&rec, XDR_SOURCE_FILE, key);
        fe->operation = XDR_FILE_SETINFO;
        fe->create_disposition = 0;
        fe->file_size = 0;
        fe->process_image_hash = hash_process_image();
        fe->file_attributes = 0;
        copy_wstr_trunc(fe->file_path, XDR_MAX_PATH, &nameInfo->Name);
        copy_wstr_trunc(fe->file_extension, 16, &nameInfo->Extension);
        publish_record(&rec);
        FltReleaseFileNameInformation(nameInfo);
    }
}
