#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include "..\..\shared\xdr_shared.h"

extern NTSTATUS XdrCoreOpenForKernelWfp(OUT PFILE_OBJECT* FileObject, OUT PDEVICE_OBJECT* DeviceObject);
extern NTSTATUS XdrCorePublishEventWfp(_In_ PFILE_OBJECT CoreFile, _In_ PDEVICE_OBJECT CoreDev,
                             _In_reads_bytes_(InputSize) PVOID InputBuffer, _In_ ULONG InputSize,
                             _In_ ULONG IoctlCode);

static UINT64 fnv1a64_bytes(const void* data, SIZE_T len) {
    const unsigned char* p=(const unsigned char*)data;
    UINT64 h=1469598103934665603ULL;
    while (len--) { h ^= *p++; h *= 1099511628211ULL; }
    return h;
}

static VOID fill_common_header(XDR_EVENT_RECORD* rec, USHORT source, UINT64 key_hash) {
    LARGE_INTEGER t; KeQuerySystemTimePrecise(&t);
    rec->total_size = sizeof(*rec);
    rec->header.version = XDR_ABI_VERSION;
    rec->header.source = source;
    rec->header.severity = XDR_SEVERITY_LOW;
    rec->header.flags = 0;
    rec->header.timestamp_100ns = (UINT64)t.QuadPart;
    rec->header.process_id = 0;
    rec->header.thread_id  = 0;
    rec->header.session_id = 0;
    rec->header.reserved = 0;
    rec->header.sequence_number = 0;
    rec->header.prev_seq_same_key = 0;
    rec->header.key_hash = key_hash;
}

VOID XdrwfpWire_PublishConnectV4(const FWPS_INCOMING_VALUES0* v, const FWPS_INCOMING_METADATA_VALUES0* m, XDR_NETWORK_VERDICT verdict)
{
    XDR_EVENT_RECORD rec; RtlZeroMemory(&rec, sizeof(rec));
    XDR_NETWORK_EVENT* ne = &rec.payload.network;
    RtlZeroMemory(ne, sizeof(*ne));

    UINT32 laddr = v->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
    UINT32 raddr = v->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    UINT16 lport = v->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
    UINT16 rport = v->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
    UINT8 proto  = v->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;

    ne->operation = XDR_NET_CONNECT;
    ne->verdict = verdict;
    ne->protocol = proto;
    ne->direction = 0; // outbound
    ne->local_port = lport;
    ne->remote_port = rport;
    ne->bytes_in = 0;
    ne->bytes_out = 0;
    ne->process_image_hash = 0;
    ne->local_addr_v4 = laddr;
    ne->remote_addr_v4 = raddr;

    UINT64 key = fnv1a64_bytes(&raddr, sizeof(raddr)) ^ ((UINT64)rport<<16) ^ proto;
    fill_common_header(&rec, XDR_SOURCE_NETWORK, key);

    PFILE_OBJECT fo=NULL; PDEVICE_OBJECT dev=NULL;
    if (NT_SUCCESS(XdrCoreOpenForKernelWfp(&fo, &dev))) {
        (void)XdrCorePublishEventWfp(fo, dev, &rec, sizeof(rec), IOCTL_XDR_PUBLISH_EVENT);
    }
}
