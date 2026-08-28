/*++
Module Name:
    ZETA_DiskFilter.c

Description:
    Standalone WDM disk class filter driver.
    Intercepts IRP_MJ_WRITE to \Device\HarddiskX\DR0
    and blocks writes to the MBR (byte offset 0) from untrusted processes.

    This is a PURE WDM driver (NOT a minifilter), so it has its own
    DRIVER_OBJECT dispatch table with NO FLTMGR conflicts.

    Purpose: rainbow-cat-style MBR wiper protection.
--*/

#include <ntifs.h>
#include <ntstatus.h>
#include <ntstrsafe.h>
#include <ntdddisk.h>
#include <ntddscsi.h>

/* ================================================================
   Debug logging
   ================================================================ */
#ifdef DBG
    #define DPF(_x_) DbgPrint _x_
#else
    #define DPF(_x_)
#endif

/* ================================================================
   Device extension
   ================================================================ */
#define DISKFILTER_SIG 'kSD#'  /* Disk Signature */

typedef struct _DEVICE_EXTENSION {
    ULONG           Signature;
    PDEVICE_OBJECT  LowerDevice;
    ULONG           DiskNumber;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

#define MAX_DISKS 32
static PDEVICE_OBJECT g_FilterDevices[MAX_DISKS] = {0};
static ULONG          g_FilterCount = 0;
static PDRIVER_OBJECT g_DriverObject = NULL;

/* ================================================================
   Forward declarations
   ================================================================ */
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DispatchPassThrough;
DRIVER_DISPATCH DispatchCreateClose;
DRIVER_DISPATCH DispatchWrite;
DRIVER_DISPATCH DispatchDeviceControl;

/* ================================================================
   PassThrough — forward IRP to lower device
   ================================================================ */
NTSTATUS DispatchPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PDEVICE_EXTENSION ext = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDevice, Irp);
}

/* ================================================================
   CreateClose
   ================================================================ */
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PDEVICE_EXTENSION ext = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDevice, Irp);
}

/* ================================================================
   IsTrustedProcess — simple path-based trust check
   ================================================================ */
static BOOLEAN IsTrustedProcess(void) {
    HANDLE pid = PsGetCurrentProcessId();
    if (!pid || pid <= (HANDLE)4) return TRUE;  /* SYSTEM / Idle */

    PEPROCESS proc = PsGetCurrentProcess();
    PUNICODE_STRING imgName = NULL;
    NTSTATUS ns = SeLocateProcessImageName(proc, &imgName);
    if (!NT_SUCCESS(ns) || !imgName || !imgName->Buffer) return FALSE;

    /* Trusted system paths */
    UNICODE_STRING winPath = RTL_CONSTANT_STRING(L"\\Windows\\");
    UNICODE_STRING pfPath  = RTL_CONSTANT_STRING(L"\\Program Files\\");
    UNICODE_STRING pf86Path = RTL_CONSTANT_STRING(L"\\Program Files (x86)\\");

    BOOLEAN trusted = FALSE;
    if (FsRtlIsNameInExpression(&winPath, imgName, TRUE, NULL) ||
        FsRtlIsNameInExpression(&pfPath,  imgName, TRUE, NULL) ||
        FsRtlIsNameInExpression(&pf86Path, imgName, TRUE, NULL)) {
        trusted = TRUE;
    }

    ExFreePool(imgName);
    return trusted;
}

/* ================================================================
   DispatchWrite — intercept MBR writes
   ================================================================ */
NTSTATUS DispatchWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PDEVICE_EXTENSION ext = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    LONGLONG offset = irpSp->Parameters.Write.ByteOffset.QuadPart;
    ULONG length = irpSp->Parameters.Write.Length;

    DPF(("ZETA_DiskFilter: Write irpSp->MajorFunction=%d MinorFunction=%d\n",
         irpSp->MajorFunction, irpSp->MinorFunction));
    DPF(("ZETA_DiskFilter: Write Disk%lu offset=0x%llx len=%lu\n",
         ext->DiskNumber, offset, length));

    /* MBR check: offset == 0 (absolute) or -1 (file pointer, first write = MBR) */
    BOOLEAN isMbr = (offset == 0 || offset == -1) && length > 0;

    if (isMbr) {
        DPF(("ZETA_DiskFilter: MBR write from PID=%lu, trusted=%s\n",
             (ULONG)(ULONG_PTR)PsGetCurrentProcessId(), IsTrustedProcess() ? "YES" : "NO"));

        if (!IsTrustedProcess()) {
            DPF(("ZETA_DiskFilter: *** BLOCKED MBR write PID=%lu ***\n",
                 (ULONG)(ULONG_PTR)PsGetCurrentProcessId()));
            Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_ACCESS_DENIED;
        }
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDevice, Irp);
}

/* ================================================================
   DispatchDeviceControl — intercept dangerous IOCTLs
   ================================================================ */
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PDEVICE_EXTENSION ext = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;

    /* Dangerous IOCTLs: partition table change, SCSI pass-through, format */
    if (code == IOCTL_DISK_SET_DRIVE_LAYOUT_EX ||
        code == IOCTL_SCSI_PASS_THROUGH_DIRECT ||
        code == IOCTL_DISK_FORMAT_TRACKS ||
        code == IOCTL_DISK_FORMAT_TRACKS_EX) {

        if (!IsTrustedProcess()) {
            DPF(("ZETA_DiskFilter: BLOCKED IOCTL 0x%08X PID=%lu\n",
                 code, (ULONG)(ULONG_PTR)PsGetCurrentProcessId()));
            Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_ACCESS_DENIED;
        }
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDevice, Irp);
}

/* ================================================================
   AttachToDisk — create and attach a filter device
   ================================================================ */
static NTSTATUS AttachToDisk(ULONG DiskNumber) {
    WCHAR path[64];
    UNICODE_STRING name;
    PFILE_OBJECT fileObj = NULL;
    PDEVICE_OBJECT targetDev = NULL;
    PDEVICE_OBJECT filterDev = NULL;
    NTSTATUS status;

    /* Try \Device\Harddisk%lu\DR0, fallback to \Partition0 */
    RtlStringCbPrintfW(path, sizeof(path),
        L"\\Device\\Harddisk%lu\\DR0", DiskNumber);
    RtlInitUnicodeString(&name, path);
    status = IoGetDeviceObjectPointer(&name, FILE_READ_ATTRIBUTES,
                                      &fileObj, &targetDev);
    if (!NT_SUCCESS(status)) {
        RtlStringCbPrintfW(path, sizeof(path),
            L"\\Device\\Harddisk%lu\\Partition0", DiskNumber);
        RtlInitUnicodeString(&name, path);
        status = IoGetDeviceObjectPointer(&name, FILE_READ_ATTRIBUTES,
                                          &fileObj, &targetDev);
        if (!NT_SUCCESS(status)) {
            DPF(("ZETA_DiskFilter: Disk%lu not found\n", DiskNumber));
            return status;
        }
    }

    /* Create unnamed filter device */
    status = IoCreateDevice(
        g_DriverObject,
        sizeof(DEVICE_EXTENSION),
        NULL,                  /* no name */
        targetDev->DeviceType,
        0,                     /* no characteristics */
        FALSE,                 /* not exclusive */
        &filterDev);
    if (!NT_SUCCESS(status)) {
        DPF(("ZETA_DiskFilter: IoCreateDevice failed %08X\n", status));
        ObDereferenceObject(fileObj);
        return status;
    }

    /* Init extension */
    PDEVICE_EXTENSION ext = (PDEVICE_EXTENSION)filterDev->DeviceExtension;
    ext->Signature = DISKFILTER_SIG;
    ext->LowerDevice = targetDev;
    ext->DiskNumber = DiskNumber;

    /* Flags */
    filterDev->Flags |= DO_DIRECT_IO;
    filterDev->Flags &= ~DO_DEVICE_INITIALIZING;

    /* Attach to device stack */
    PDEVICE_OBJECT attached = IoAttachDeviceToDeviceStack(filterDev, targetDev);
    if (!attached) {
        DPF(("ZETA_DiskFilter: IoAttachDeviceToDeviceStack failed\n"));
        IoDeleteDevice(filterDev);
        ObDereferenceObject(fileObj);
        return STATUS_UNSUCCESSFUL;
    }

    if (g_FilterCount >= MAX_DISKS) {
        IoDetachDevice(attached);
        IoDeleteDevice(filterDev);
        ObDereferenceObject(fileObj);
        return STATUS_TOO_MANY_NAMES;
    }

    g_FilterDevices[g_FilterCount++] = filterDev;
    ObDereferenceObject(fileObj);
    DPF(("ZETA_DiskFilter: ATTACHED to Harddisk%lu [%ws]\n", DiskNumber, path));
    return STATUS_SUCCESS;
}

/* ================================================================
   DriverEntry
   ================================================================ */
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    ULONG i;

    DPF(("ZETA_DiskFilter: DriverEntry\n"));

    g_DriverObject = DriverObject;

    /* Set dispatch routines */
    for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = DispatchPassThrough;

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_WRITE]          = DispatchWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload                          = DriverUnload;

    /* Attach to all physical disks */
    g_FilterCount = 0;
    for (i = 0; i < 32; i++) {
        status = AttachToDisk(i);
        if (!NT_SUCCESS(status)) break;
    }

    DPF(("ZETA_DiskFilter: DriverEntry OK - %lu disk(s) monitored\n", g_FilterCount));
    return STATUS_SUCCESS;
}

/* ================================================================
   DriverUnload
   ================================================================ */
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    ULONG i;

    DPF(("ZETA_DiskFilter: DriverUnload (%lu devices)\n", g_FilterCount));

    for (i = 0; i < g_FilterCount; i++) {
        if (g_FilterDevices[i]) {
            PDEVICE_EXTENSION ext = (PDEVICE_EXTENSION)
                g_FilterDevices[i]->DeviceExtension;
            if (ext && ext->LowerDevice)
                IoDetachDevice(ext->LowerDevice);
            IoDeleteDevice(g_FilterDevices[i]);
            g_FilterDevices[i] = NULL;
        }
    }
    g_FilterCount = 0;
    DPF(("ZETA_DiskFilter: DriverUnload complete\n"));
}
