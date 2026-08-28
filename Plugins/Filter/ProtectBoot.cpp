#include "DriverCommon.h"

#ifndef IOCTL_DISK_FORMAT_TRACKS
#define IOCTL_DISK_FORMAT_TRACKS CTL_CODE(IOCTL_DISK_BASE, 0x0006, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif
#ifndef IOCTL_DISK_FORMAT_TRACKS_EX
#define IOCTL_DISK_FORMAT_TRACKS_EX CTL_CODE(IOCTL_DISK_BASE, 0x000b, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

FLT_PREOP_CALLBACK_STATUS ProtectBoot_PreDeviceControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
 UNREFERENCED_PARAMETER(FltObjects);
 UNREFERENCED_PARAMETER(CompletionContext);

 if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (g_IsUnloading) return FLT_PREOP_SUCCESS_NO_CALLBACK;

 // P1-1: 系统保护开关 - 关闭时跳过磁盘擦除/格式化等系统级检查
 if (!g_SystemProtectEnabled) return FLT_PREOP_SUCCESS_NO_CALLBACK;

	ULONG IoControlCode = Data->Iopb->Parameters.DeviceIoControl.Common.IoControlCode;

	if (IoControlCode == IOCTL_DISK_SET_DRIVE_LAYOUT_EX ||
	IoControlCode == IOCTL_SCSI_PASS_THROUGH_DIRECT ||
	IoControlCode == IOCTL_DISK_FORMAT_TRACKS ||
	IoControlCode == IOCTL_DISK_FORMAT_TRACKS_EX) {

	HANDLE Pid = PsGetCurrentProcessId();
	if (!IsProcessTrusted(Pid)) {
	UNICODE_STRING MsgStr = RTL_CONSTANT_STRING(L"Disk_Wiper_Attempt");
	if (NT_SUCCESS(FltLockUserBuffer(Data))) {
		if (NT_SUCCESS(PendOperation(Data, FltObjects, (ULONG)(ULONG_PTR)Pid, 4001, MsgStr.Buffer, MsgStr.Length))) {
		 SendMessageToUser(4001, (ULONG)(ULONG_PTR)Pid, MsgStr.Buffer, MsgStr.Length);
		 return FLT_PREOP_PENDING;
		} else {
		 DbgPrint("ZETA: PendOperation failed - allowing disk write\n");
		}
	} else {
		DbgPrint("ZETA: FltLockUserBuffer failed - allowing disk write\n");
	}
	}
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}