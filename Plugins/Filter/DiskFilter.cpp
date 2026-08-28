#include "DriverCommon.h"

// ============================================================
// Disk Class Filter — 拦截对 \\.\PhysicalDriveX 的 MBR 写入
//
// 彩虹猫等恶意软件通过 WriteFile(\\.\PhysicalDrive0) 直接写 MBR，
// 文件系统微过滤器（minifilter）无法看到原始磁盘设备的 IRP，
// 因此需要一个单独的磁盘类过滤器。
//
// 工作原理：
// 1. 枚举 \Device\Harddisk0\DR0 ~ Harddisk31\DR0
// 2. 为每个磁盘设备创建一个过滤器设备并附加到其设备栈
// 3. 通过 DRIVER_OBJECT 的 MajorFunction 拦截 IRP_MJ_WRITE
//    和 IRP_MJ_DEVICE_CONTROL
// 4. 在分发函数中判断 DeviceObject 是否属于磁盘过滤器设备
// 5. 拦截 MBR 写入（偏移 0），阻止不可信进程
// ============================================================

#define DISK_FILTER_SIGNATURE 'KSD#'

typedef struct _DISK_FILTER_EXT {
    ULONG       Signature;
    PDEVICE_OBJECT LowerDevice;
    ULONG       DiskNumber;
} DISK_FILTER_EXT, *PDISK_FILTER_EXT;

#define MAX_DISK_DEVICES 32
static PDEVICE_OBJECT g_DiskFilterDevices[MAX_DISK_DEVICES] = {0};
static ULONG g_DiskFilterCount = 0;

// 保存原始分发函数指针
static PDRIVER_DISPATCH g_OrigWrite = NULL;
static PDRIVER_DISPATCH g_OrigDevCtrl = NULL;
static PDRIVER_DISPATCH g_OrigCreate = NULL;
static PDRIVER_DISPATCH g_OrigClose = NULL;

// ============================================================
// 判断 DeviceObject 是否是我们的磁盘过滤器设备
// ============================================================
static BOOLEAN IsDiskFilterDevice(PDEVICE_OBJECT DevObj) {
    if (!DevObj || !DevObj->DeviceExtension) return FALSE;
    PDISK_FILTER_EXT ext = (PDISK_FILTER_EXT)DevObj->DeviceExtension;
    return ext->Signature == DISK_FILTER_SIGNATURE;
}

// ============================================================
// 基于 NT 路径判断进程是否应受保护
// 如果进程路径不可获取，默认阻止（安全优先）
// ============================================================
static BOOLEAN ShouldBlockProcess() {
    HANDLE pid = PsGetCurrentProcessId();
    if (!pid || pid <= (HANDLE)4) return FALSE;  // SYSTEM/Idle 放行

    // 检查信任级别
    if (IsProcessTrusted(pid)) {
        ZETA_DBG("DiskFilter: PID=%lu is trusted, allowing\n", (ULONG)(ULONG_PTR)pid);
        return FALSE;
    }

    // 额外路径白名单
    PUNICODE_STRING imageName = NULL;
    NTSTATUS ns = SeLocateProcessImageName(PsGetCurrentProcess(), &imageName);
    if (NT_SUCCESS(ns) && imageName && imageName->Buffer) {
        // 系统路径放行
        if (WildcardMatch(L"*\\Windows\\*", imageName->Buffer, imageName->Length) ||
            WildcardMatch(L"*\\Program Files\\*", imageName->Buffer, imageName->Length) ||
            WildcardMatch(L"*\\Program Files (x86)\\*", imageName->Buffer, imageName->Length)) {
            ZETA_DBG("DiskFilter: PID=%lu sys-path, allowing\n", (ULONG)(ULONG_PTR)pid);
            ExFreePool(imageName);
            return FALSE;
        }
        ZETA_DBG("DiskFilter: PID=%lu path=%.*ls (blocking)\n",
            (ULONG)(ULONG_PTR)pid,
            imageName->Length / sizeof(WCHAR), imageName->Buffer);
        ExFreePool(imageName);
    } else {
        ZETA_DBG("DiskFilter: PID=%lu no-path (blocking)\n", (ULONG)(ULONG_PTR)pid);
    }

    return TRUE;
}

// ============================================================
// Write 分发 — 拦截 MBR 写入
// ============================================================
NTSTATUS DiskFilter_DispatchWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    // Step 1: 检查是不是我们的设备
    if (!IsDiskFilterDevice(DeviceObject)) {
        return g_OrigWrite(DeviceObject, Irp);
    }

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    LONGLONG byteOffset = irpSp->Parameters.Write.ByteOffset.QuadPart;
    ULONG writeLen = irpSp->Parameters.Write.Length;

    ZETA_DBG("DiskFilter: Write IRP offset=0x%llx len=%lu\n", byteOffset, writeLen);

    // Step 2: 检查是否是 MBR 扇区写入
    //   byteOffset == 0      → 绝对偏移 0
    //   byteOffset == -1     → 文件指针，首次写入即 MBR
    BOOLEAN isMbr = FALSE;
    if (byteOffset == 0 && writeLen > 0) {
        isMbr = TRUE;
        ZETA_DBG("DiskFilter: offset==0 MBR match\n");
    } else if (byteOffset == -1 && writeLen > 0) {
        isMbr = TRUE;
        ZETA_DBG("DiskFilter: offset==-1 MBR match\n");
    } else {
        ZETA_DBG("DiskFilter: non-MBR offset, passing through\n");
    }

    // Step 3: MBR 写入 → 进程检查
    if (isMbr) {
        if (g_IsUnloading || !g_SystemProtectEnabled) {
            ZETA_DBG("DiskFilter: unloaded/system-diasabled, passing\n");
            goto passthrough;
        }
        if (ShouldBlockProcess()) {
            ZETA_WARN("DiskFilter: BLOCKED MBR write from PID=%lu Len=%lu\n",
                (ULONG)(ULONG_PTR)PsGetCurrentProcessId(), writeLen);
            Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_ACCESS_DENIED;
        }
    }

passthrough:;
    PDISK_FILTER_EXT ext = (PDISK_FILTER_EXT)DeviceObject->DeviceExtension;
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDevice, Irp);
}

// ============================================================
// DeviceControl 分发 — 拦截危险 IOCTL
// ============================================================
NTSTATUS DiskFilter_DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    if (!IsDiskFilterDevice(DeviceObject)) {
        return g_OrigDevCtrl(DeviceObject, Irp);
    }

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;

    if (code == IOCTL_DISK_SET_DRIVE_LAYOUT_EX ||
        code == IOCTL_SCSI_PASS_THROUGH_DIRECT ||
        code == IOCTL_DISK_FORMAT_TRACKS ||
        code == IOCTL_DISK_FORMAT_TRACKS_EX) {

        if (g_IsUnloading || !g_SystemProtectEnabled) goto passthrough_dc;

        if (ShouldBlockProcess()) {
            ZETA_WARN("DiskFilter: BLOCKED IOCTL 0x%08X from PID=%lu\n",
                code, (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
            Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_ACCESS_DENIED;
        }
    }

passthrough_dc:;
    PDISK_FILTER_EXT ext = (PDISK_FILTER_EXT)DeviceObject->DeviceExtension;
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDevice, Irp);
}

// ============================================================
// Create/Close — 直接通过
// ============================================================
NTSTATUS DiskFilter_DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    if (!IsDiskFilterDevice(DeviceObject)) {
        PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
        if (irpSp->MajorFunction == IRP_MJ_CREATE)
            return g_OrigCreate(DeviceObject, Irp);
        else
            return g_OrigClose(DeviceObject, Irp);
    }
    PDISK_FILTER_EXT ext = (PDISK_FILTER_EXT)DeviceObject->DeviceExtension;
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDevice, Irp);
}

// ============================================================
// 附加到指定物理磁盘
// 尝试 HarddiskN\DR0，失败则试 HarddiskN\Partition0
// ============================================================
static NTSTATUS DiskFilter_AttachToDisk(ULONG DiskNumber) {
    WCHAR path[64];
    UNICODE_STRING name;
    PFILE_OBJECT fileObj = NULL;
    PDEVICE_OBJECT targetDev = NULL;
    PDEVICE_OBJECT filterDev = NULL;
    NTSTATUS status;

    // 尝试路径1: \Device\Harddisk%lu\DR0
    RtlStringCbPrintfW(path, sizeof(path), L"\\Device\\Harddisk%lu\\DR0", DiskNumber);
    RtlInitUnicodeString(&name, path);
    status = IoGetDeviceObjectPointer(&name, FILE_READ_ATTRIBUTES, &fileObj, &targetDev);
    if (!NT_SUCCESS(status)) {
        // 尝试路径2: \Device\Harddisk%lu\Partition0
        RtlStringCbPrintfW(path, sizeof(path), L"\\Device\\Harddisk%lu\\Partition0", DiskNumber);
        RtlInitUnicodeString(&name, path);
        status = IoGetDeviceObjectPointer(&name, FILE_READ_ATTRIBUTES, &fileObj, &targetDev);
        if (!NT_SUCCESS(status)) {
            ZETA_DBG("DiskFilter: AttachToDisk(%lu) FAILED (disk not found)\n", DiskNumber);
            return status;
        }
    }

    // 创建无名过滤器设备
    status = IoCreateDevice(
        GlobalData.DriverObject,
        sizeof(DISK_FILTER_EXT),
        NULL,
        targetDev->DeviceType,
        0,
        FALSE,
        &filterDev);
    if (!NT_SUCCESS(status)) {
        ZETA_DBG("DiskFilter: IoCreateDevice FAILED %08X\n", status);
        ObDereferenceObject(fileObj);
        return status;
    }

    PDISK_FILTER_EXT ext = (PDISK_FILTER_EXT)filterDev->DeviceExtension;
    ext->Signature = DISK_FILTER_SIGNATURE;
    ext->LowerDevice = targetDev;
    ext->DiskNumber = DiskNumber;

    filterDev->Flags |= DO_DIRECT_IO;
    filterDev->Flags &= ~DO_DEVICE_INITIALIZING;

    // 附加到设备栈顶部
    PDEVICE_OBJECT attached = IoAttachDeviceToDeviceStack(filterDev, targetDev);
    if (!attached) {
        ZETA_DBG("DiskFilter: IoAttachDeviceToDeviceStack(%lu) FAILED\n", DiskNumber);
        IoDeleteDevice(filterDev);
        ObDereferenceObject(fileObj);
        return STATUS_UNSUCCESSFUL;
    }

    if (g_DiskFilterCount >= MAX_DISK_DEVICES) {
        IoDetachDevice(attached);
        IoDeleteDevice(filterDev);
        ObDereferenceObject(fileObj);
        return STATUS_TOO_MANY_NAMES;
    }

    g_DiskFilterDevices[g_DiskFilterCount++] = filterDev;
    ObDereferenceObject(fileObj);
    ZETA_DBG("DiskFilter: ATTACHED to Harddisk%lu [%s]\n", DiskNumber, path);
    return STATUS_SUCCESS;
}

// ============================================================
// 初始化 — 保存原始分发，安装磁盘过滤器
// ============================================================
NTSTATUS DiskFilter_Initialize() {
    PDRIVER_OBJECT drvObj = GlobalData.DriverObject;
    if (!drvObj) {
        ZETA_DBG("DiskFilter: Initialize FAILED - null DriverObject\n");
        return STATUS_INVALID_PARAMETER;
    }

    // 保存原始 FLTMGR 分发函数
    g_OrigWrite   = drvObj->MajorFunction[IRP_MJ_WRITE];
    g_OrigDevCtrl = drvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    g_OrigCreate  = drvObj->MajorFunction[IRP_MJ_CREATE];
    g_OrigClose   = drvObj->MajorFunction[IRP_MJ_CLOSE];

    ZETA_DBG("DiskFilter: orig Write=0x%p DevCtrl=0x%p Create=0x%p Close=0x%p\n",
        g_OrigWrite, g_OrigDevCtrl, g_OrigCreate, g_OrigClose);

    // 覆盖分发
    drvObj->MajorFunction[IRP_MJ_WRITE]         = DiskFilter_DispatchWrite;
    drvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DiskFilter_DispatchDeviceControl;
    drvObj->MajorFunction[IRP_MJ_CREATE]        = DiskFilter_DispatchCreateClose;
    drvObj->MajorFunction[IRP_MJ_CLOSE]         = DiskFilter_DispatchCreateClose;

    ZETA_DBG("DiskFilter: MF[WRITE]=0x%p MF[DEVCTRL]=0x%p MF[CREATE]=0x%p MF[CLOSE]=0x%p\n",
        drvObj->MajorFunction[IRP_MJ_WRITE],
        drvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL],
        drvObj->MajorFunction[IRP_MJ_CREATE],
        drvObj->MajorFunction[IRP_MJ_CLOSE]);

    g_DiskFilterCount = 0;
    RtlZeroMemory(g_DiskFilterDevices, sizeof(g_DiskFilterDevices));

    // 枚举并附加到所有物理磁盘
    for (ULONG i = 0; i < 32; i++) {
        NTSTATUS status = DiskFilter_AttachToDisk(i);
        if (!NT_SUCCESS(status)) break;
    }

    ZETA_INFO("DiskFilter: Initialized - monitoring %lu disk(s)\n", g_DiskFilterCount);
    return STATUS_SUCCESS;
}

// ============================================================
// 清理 — 恢复分发函数 + 拆除设备
// ============================================================
VOID DiskFilter_Cleanup() {
    ZETA_DBG("DiskFilter: Cleanup starting (%lu devices)\n", g_DiskFilterCount);

    // 恢复原始 FLTMGR 分发函数
    if (GlobalData.DriverObject) {
        GlobalData.DriverObject->MajorFunction[IRP_MJ_WRITE]         = g_OrigWrite;
        GlobalData.DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = g_OrigDevCtrl;
        GlobalData.DriverObject->MajorFunction[IRP_MJ_CREATE]        = g_OrigCreate;
        GlobalData.DriverObject->MajorFunction[IRP_MJ_CLOSE]         = g_OrigClose;
    }

    // 拆除所有磁盘过滤器设备
    for (ULONG i = 0; i < g_DiskFilterCount; i++) {
        if (g_DiskFilterDevices[i]) {
            PDISK_FILTER_EXT ext = (PDISK_FILTER_EXT)g_DiskFilterDevices[i]->DeviceExtension;
            if (ext && ext->LowerDevice) IoDetachDevice(ext->LowerDevice);
            IoDeleteDevice(g_DiskFilterDevices[i]);
            g_DiskFilterDevices[i] = NULL;
        }
    }
    g_DiskFilterCount = 0;
    ZETA_DBG("DiskFilter: Cleanup complete\n");
}
