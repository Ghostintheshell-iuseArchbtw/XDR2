#include <ntifs.h>
#include <ntddk.h>
#include "..\..\shared\xdr_shared.h"
#include "xdrfs_publish.h"

NTSTATUS XdrCoreOpenForKernel(OUT PFILE_OBJECT* FileObject, OUT PDEVICE_OBJECT* DeviceObject)
{
    static PFILE_OBJECT g_File = NULL;
    static PDEVICE_OBJECT g_Dev = NULL;

    if (g_Dev && g_File) {
        *FileObject = g_File;
        *DeviceObject = g_Dev;
        return STATUS_SUCCESS;
    }

    UNICODE_STRING us = RTL_CONSTANT_STRING(L"\\DosDevices\\XdrCore");
    OBJECT_ATTRIBUTES oa;
    HANDLE h = NULL;
    IO_STATUS_BLOCK ios = {0};
    InitializeObjectAttributes(&oa, &us, OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS st = ZwCreateFile(&h, GENERIC_READ|GENERIC_WRITE, &oa, &ios,
                               NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ|FILE_SHARE_WRITE,
                               FILE_OPEN, FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT,
                               NULL, 0);
    if (!NT_SUCCESS(st)) return st;

    st = ObReferenceObjectByHandle(h, FILE_READ_DATA|FILE_WRITE_DATA, *IoFileObjectType,
                                   KernelMode, (PVOID*)&g_File, NULL);
    ZwClose(h);
    if (!NT_SUCCESS(st)) return st;

    g_Dev = IoGetRelatedDeviceObject(g_File);
    *FileObject = g_File;
    *DeviceObject = g_Dev;
    return STATUS_SUCCESS;
}

NTSTATUS XdrCorePublishEvent(_In_ PFILE_OBJECT CoreFile, _In_ PDEVICE_OBJECT CoreDev,
                             _In_reads_bytes_(InputSize) PVOID InputBuffer, _In_ ULONG InputSize,
                             _In_ ULONG IoctlCode)
{
    KEVENT evt; KeInitializeEvent(&evt, NotificationEvent, FALSE);
    IO_STATUS_BLOCK ios = {0};
    PIRP irp = IoBuildDeviceIoControlRequest(IoctlCode,
                                             CoreDev, InputBuffer, InputSize,
                                             NULL, 0, FALSE, &evt, &ios);
    if (!irp) return STATUS_INSUFFICIENT_RESOURCES;
    IoGetNextIrpStackLocation(irp)->FileObject = CoreFile;

    NTSTATUS st = IoCallDriver(CoreDev, irp);
    if (st == STATUS_PENDING) {
        KeWaitForSingleObject(&evt, Executive, KernelMode, FALSE, NULL);
        st = ios.Status;
    }
    return st;
}
