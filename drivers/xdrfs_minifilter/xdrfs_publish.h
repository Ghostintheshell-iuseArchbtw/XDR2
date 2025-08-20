#pragma once
#include <ntifs.h>
#include <ntddk.h>

NTSTATUS XdrCoreOpenForKernel(OUT PFILE_OBJECT* FileObject, OUT PDEVICE_OBJECT* DeviceObject);
NTSTATUS XdrCorePublishEvent(_In_ PFILE_OBJECT CoreFile, _In_ PDEVICE_OBJECT CoreDev,
                             _In_reads_bytes_(InputSize) PVOID InputBuffer, _In_ ULONG InputSize,
                             _In_ ULONG IoctlCode);
