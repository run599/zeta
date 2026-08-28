#include "DriverCommon.h"

PVOID g_ObRegistrationHandle = NULL;  // P0-1: 去掉 static 以便 watchdog 跨文件校验（与 DriverCommon.h 声明一致）
static OB_CALLBACK_REGISTRATION ObRegistration;
static OB_OPERATION_REGISTRATION ObCallbacks[2];

static BOOLEAN IsSystemImage(PUNICODE_STRING FullImageName) {
 if (!FullImageName || !FullImageName->Buffer) return FALSE;

 if (WildcardMatch(L"*\\Windows\\System32\\*", FullImageName->Buffer, FullImageName->Length) ||
 WildcardMatch(L"*\\Windows\\SysWOW64\\*", FullImageName->Buffer, FullImageName->Length) ||
 WildcardMatch(L"*\\Windows\\WinSxS\\*", FullImageName->Buffer, FullImageName->Length) ||
 WildcardMatch(L"*\\Windows\\Microsoft.NET\\*", FullImageName->Buffer, FullImageName->Length) ||
 WildcardMatch(L"*\\Common Files\\Microsoft Shared\\*", FullImageName->Buffer, FullImageName->Length) ||
 WildcardMatch(L"*\\Program Files*\\*", FullImageName->Buffer, FullImageName->Length)) {
 return TRUE;
 }
 return FALSE;
}

static BOOLEAN IsSuspiciousDllPath(PUNICODE_STRING FullImageName) {
 if (!FullImageName || !FullImageName->Buffer) return FALSE;

 // DLL
 if (WildcardMatch(L"*\\Temp\\*", FullImageName->Buffer, FullImageName->Length) ||
 WildcardMatch(L"*\\AppData\\Local\\Temp\\*", FullImageName->Buffer, FullImageName->Length) ||
 WildcardMatch(L"*\\Downloads\\*", FullImageName->Buffer, FullImageName->Length) ||
 WildcardMatch(L"*\\Desktop\\*", FullImageName->Buffer, FullImageName->Length) ||
 WildcardMatch(L"*\\AppData\\Roaming\\*", FullImageName->Buffer, FullImageName->Length)) {
 return TRUE;
 }
 return FALSE;
}

VOID ImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
 UNREFERENCED_PARAMETER(ImageInfo);

 if (KeGetCurrentIrql() > PASSIVE_LEVEL) return;
	if (!FullImageName || !FullImageName->Buffer) return;
	if (ProcessId == (HANDLE)0 || ProcessId == (HANDLE)4) return;

	if (g_LearningModeActive) return;

	if (IsSystemImage(FullImageName)) return;

	// P1-状态机: 驱动加载事件上报 (ZETA_MSG_IMAGE_LOAD 7010)
	// 无论目标是否受保护，对 .sys 驱动加载都上报到行为引擎，
	// 供状态机规则 (BYOVD: 无签名进程拉起驱动) 关联判定。
	// 注意：进程 PID 即"加载该驱动的进程"，符合"进程拉起驱动"语义。
	BOOLEAN isSysFile = FALSE;
	if (FullImageName->Length >= 8 * sizeof(WCHAR)) {
		PCWSTR ext = FullImageName->Buffer + (FullImageName->Length / sizeof(WCHAR)) - 4;
		if (RtlDowncaseUnicodeChar(ext[0]) == L'.' &&
			RtlDowncaseUnicodeChar(ext[1]) == L's' &&
			RtlDowncaseUnicodeChar(ext[2]) == L'y' &&
			RtlDowncaseUnicodeChar(ext[3]) == L's') {
			isSysFile = TRUE;
		}
	}
	if (isSysFile) {
		SendMessageToUser(ZETA_MSG_IMAGE_LOAD, (ULONG)(ULONG_PTR)ProcessId,
			FullImageName->Buffer, FullImageName->Length);
	}

	// P1-1: 驱动保护开关 - 对 .sys 文件加载检查生效
	// 关闭时跳过驱动加载相关检查 (但仍检查 DLL 注入)
	if (isSysFile && !g_DriverProtectEnabled) return;

	BOOLEAN isDll = FALSE;
	if (FullImageName->Length >= 8 * sizeof(WCHAR)) {
	PCWSTR ext = FullImageName->Buffer + (FullImageName->Length / sizeof(WCHAR)) - 4;
	if (RtlDowncaseUnicodeChar(ext[0]) == L'.' &&
	RtlDowncaseUnicodeChar(ext[1]) == L'd' &&
	RtlDowncaseUnicodeChar(ext[2]) == L'l' &&
	RtlDowncaseUnicodeChar(ext[3]) == L'l') {
	isDll = TRUE;
	}
	}

	if (IsTargetProtected(ProcessId)) {
	if (isDll && IsSuspiciousDllPath(FullImageName)) {
	DbgPrint("ZETA: Suspicious DLL loading detected - PID=%lu", (ULONG)(ULONG_PTR)ProcessId);
	SendMessageToUser(6001, (ULONG)(ULONG_PTR)ProcessId, FullImageName->Buffer, FullImageName->Length);
	return;
	}

	if (CheckFileExtensionRule(FullImageName)) {
	DbgPrint("ZETA: Rule check matched for image load - PID=%lu", (ULONG)(ULONG_PTR)ProcessId);
	SendMessageToUser(6001, (ULONG)(ULONG_PTR)ProcessId, FullImageName->Buffer, FullImageName->Length);
	}
	}
}

static BOOLEAN IsCriticalSystemProcess(HANDLE ProcessId) {
 if (ProcessId == (HANDLE)4) return TRUE;

 if (KeGetCurrentIrql() != PASSIVE_LEVEL) return FALSE;

 NTSTATUS status;
 BOOLEAN isCritical = FALSE;
 PEPROCESS Process = NULL;
 PUNICODE_STRING imageFileName = NULL;

 status = PsLookupProcessByProcessId(ProcessId, &Process);
 if (!NT_SUCCESS(status)) return FALSE;

 status = SeLocateProcessImageName(Process, &imageFileName);

 if (NT_SUCCESS(status) && imageFileName && imageFileName->Buffer) {
 if (WildcardMatch(L"*\\Windows\\System32\\lsass.exe", imageFileName->Buffer, imageFileName->Length) ||
 WildcardMatch(L"*\\Windows\\System32\\winlogon.exe", imageFileName->Buffer, imageFileName->Length) ||
 WildcardMatch(L"*\\Windows\\System32\\services.exe", imageFileName->Buffer, imageFileName->Length) ||
 WildcardMatch(L"*\\Windows\\System32\\smss.exe", imageFileName->Buffer, imageFileName->Length) ||
 WildcardMatch(L"*\\Windows\\System32\\csrss.exe", imageFileName->Buffer, imageFileName->Length) ||
 WildcardMatch(L"*\\Windows\\System32\\wininit.exe", imageFileName->Buffer, imageFileName->Length)) {
 isCritical = TRUE;
 }
 ExFreePool(imageFileName);
 }

 ObDereferenceObject(Process);
 return isCritical;
}

static BOOLEAN IsBlacklistedAdminTool(HANDLE ProcessId) {
 if (KeGetCurrentIrql() != PASSIVE_LEVEL) return FALSE;

 PEPROCESS Process = NULL;
 if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) return FALSE;

 PUNICODE_STRING imageFileName = NULL;
 BOOLEAN isBlacklisted = FALSE;

 if (NT_SUCCESS(SeLocateProcessImageName(Process, &imageFileName)) && imageFileName && imageFileName->Buffer) {

 if (WildcardMatch(L"*\\ProcessHacker.exe", imageFileName->Buffer, imageFileName->Length) ||
 WildcardMatch(L"*\\procexp.exe", imageFileName->Buffer, imageFileName->Length) ||
 WildcardMatch(L"*\\procexp64.exe", imageFileName->Buffer, imageFileName->Length) ||
 WildcardMatch(L"*\\GMER.exe", imageFileName->Buffer, imageFileName->Length) ||
 WildcardMatch(L"*\\x64dbg.exe", imageFileName->Buffer, imageFileName->Length) ||
 WildcardMatch(L"*\\x32dbg.exe", imageFileName->Buffer, imageFileName->Length) ||
 WildcardMatch(L"*\\ollydbg.exe", imageFileName->Buffer, imageFileName->Length) ||
 WildcardMatch(L"*\\ida64.exe", imageFileName->Buffer, imageFileName->Length) ||
 WildcardMatch(L"*\\ida.exe", imageFileName->Buffer, imageFileName->Length) ||
 WildcardMatch(L"*\\cheatengine*.exe", imageFileName->Buffer, imageFileName->Length) ||
 WildcardMatch(L"*\\pchunter*.exe", imageFileName->Buffer, imageFileName->Length) ||
 WildcardMatch(L"*\\wireshark.exe", imageFileName->Buffer, imageFileName->Length)) {
 isBlacklisted = TRUE;
 }

 ExFreePool(imageFileName);
 }

 ObDereferenceObject(Process);
 return isBlacklisted;
}

static OB_PREOP_CALLBACK_STATUS PreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
 UNREFERENCED_PARAMETER(RegistrationContext);

 if (KeGetCurrentIrql() > PASSIVE_LEVEL) return OB_PREOP_SUCCESS;
 if (OperationInformation->KernelHandle) return OB_PREOP_SUCCESS;

 PEPROCESS TargetProcess = (PEPROCESS)OperationInformation->Object;
 if (!TargetProcess) return OB_PREOP_SUCCESS;

 HANDLE TargetPid = PsGetProcessId(TargetProcess);
 HANDLE SourcePid = PsGetCurrentProcessId();

 if (SourcePid == TargetPid) return OB_PREOP_SUCCESS;
 if ((ULONG)(ULONG_PTR)SourcePid == GlobalData.ZetaPid) return OB_PREOP_SUCCESS;
 if (SourcePid == (HANDLE)4) return OB_PREOP_SUCCESS;

 // Learning mode: allow all process operations
 if (g_LearningModeActive) return OB_PREOP_SUCCESS;

 if (IsTargetProtected(TargetPid)) {
  if (IsCriticalSystemProcess(SourcePid)) return OB_PREOP_SUCCESS;

  BOOLEAN bIsTrusted = IsProcessTrusted(SourcePid);

  if (bIsTrusted) {
   if (IsBlacklistedAdminTool(SourcePid)) {
    bIsTrusted = FALSE;
   }
  }

  if (bIsTrusted) return OB_PREOP_SUCCESS;

  DbgPrint("ZETA: Process BLOCKED access by PID=%lu to TargetPID=%lu",
           (ULONG)(ULONG_PTR)SourcePid, (ULONG)(ULONG_PTR)TargetPid);

  ACCESS_MASK DenyMask = PROCESS_TERMINATE |
 PROCESS_VM_OPERATION |
 PROCESS_VM_WRITE |
 PROCESS_CREATE_THREAD |
 PROCESS_VM_READ |
 PROCESS_DUP_HANDLE |
 PROCESS_SUSPEND_RESUME |
 PROCESS_SET_INFORMATION |
 PROCESS_SET_QUOTA;

 OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= (ACCESS_MASK)(~DenyMask);

 if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
 OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= (ACCESS_MASK)(~DenyMask);
 }
 }

 return OB_PREOP_SUCCESS;
}

static OB_PREOP_CALLBACK_STATUS PreOpenThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
 UNREFERENCED_PARAMETER(RegistrationContext);

 if (KeGetCurrentIrql() > PASSIVE_LEVEL) return OB_PREOP_SUCCESS;
 if (OperationInformation->KernelHandle) return OB_PREOP_SUCCESS;

 PETHREAD TargetThread = (PETHREAD)OperationInformation->Object;
 if (!TargetThread) return OB_PREOP_SUCCESS;

 HANDLE TargetPid = (HANDLE)0;
 PEPROCESS TargetProcess = IoThreadToProcess(TargetThread);
 if (TargetProcess) {
 TargetPid = PsGetProcessId(TargetProcess);
 }

 if (TargetPid == (HANDLE)0) return OB_PREOP_SUCCESS;

 HANDLE SourcePid = PsGetCurrentProcessId();

 if (SourcePid == TargetPid) return OB_PREOP_SUCCESS;
 if ((ULONG)(ULONG_PTR)SourcePid == GlobalData.ZetaPid) return OB_PREOP_SUCCESS;
 if (SourcePid == (HANDLE)4) return OB_PREOP_SUCCESS;

 if (IsTargetProtected(TargetPid)) {
 if (IsCriticalSystemProcess(SourcePid)) return OB_PREOP_SUCCESS;

 BOOLEAN bIsTrusted = IsProcessTrusted(SourcePid);

 if (bIsTrusted) {
 if (IsBlacklistedAdminTool(SourcePid)) {
 bIsTrusted = FALSE;
 }
 }

 if (bIsTrusted) return OB_PREOP_SUCCESS;

 ACCESS_MASK DenyMask = THREAD_TERMINATE |
 THREAD_SUSPEND_RESUME |
 THREAD_SET_CONTEXT |
 THREAD_SET_INFORMATION |
 THREAD_SET_THREAD_TOKEN;

 OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= (ACCESS_MASK)(~DenyMask);

 if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
 OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= (ACCESS_MASK)(~DenyMask);
 }
 }

 return OB_PREOP_SUCCESS;
}

NTSTATUS InitializeProcessProtection() {
 static UNICODE_STRING Altitude = RTL_CONSTANT_STRING(L"320000.ZETA.Ob");

 ObCallbacks[0].ObjectType = PsProcessType;
 ObCallbacks[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
 ObCallbacks[0].PreOperation = PreOpenProcess;
 ObCallbacks[0].PostOperation = NULL;

 ObCallbacks[1].ObjectType = PsThreadType;
 ObCallbacks[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
 ObCallbacks[1].PreOperation = PreOpenThread;
 ObCallbacks[1].PostOperation = NULL;

 ObRegistration.Version = OB_FLT_REGISTRATION_VERSION;
 ObRegistration.OperationRegistrationCount = 2;
 ObRegistration.Altitude = Altitude;
 ObRegistration.RegistrationContext = NULL;
 ObRegistration.OperationRegistration = ObCallbacks;

 NTSTATUS status = ObRegisterCallbacks(&ObRegistration, &g_ObRegistrationHandle);

    if (!NT_SUCCESS(status) && (status == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION || status == STATUS_OBJECT_NAME_COLLISION)) {
        static UNICODE_STRING FallbackAltitude = RTL_CONSTANT_STRING(L"320000.ZETA.Ob.Fallback");
        ObRegistration.Altitude = FallbackAltitude;
        status = ObRegisterCallbacks(&ObRegistration, &g_ObRegistrationHandle);
    }

    DbgPrint("ZETA: InitializeProcessProtection status=0x%08lX", status);
    return status;
}

VOID UninitializeProcessProtection() {
 if (g_ObRegistrationHandle) {
 ObUnRegisterCallbacks(g_ObRegistrationHandle);
 g_ObRegistrationHandle = NULL;
 }
}

