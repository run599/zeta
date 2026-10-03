#include "DriverCommon.h"

PVOID g_ObRegistrationHandle = NULL;  // P0-1: 去掉 static 以便 watchdog 跨文件校验（与 DriverCommon.h 声明一致）
// P0-BSOD修复: 串行化 ObRegisterCallbacks/ObUnRegisterCallbacks。
// 每次 ZETA.exe 连接都会重新注册; 若不先注销旧句柄就覆盖全局句柄, 之前的注册会
// 永久泄漏在 OB 回调链上 → 驱动卸载后任何 OpenProcess 都会执行已释放代码 → 0xCE。
KMUTEX g_ObCallbackMutex;             // 在 DriverEntry 中 KeInitializeMutex
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
	SendMessageToUser(ZETA_MSG_CODE_INJECT, (ULONG)(ULONG_PTR)ProcessId, FullImageName->Buffer, FullImageName->Length);
	return;
	}

	if (CheckFileExtensionRule(FullImageName)) {
	DbgPrint("ZETA: Rule check matched for image load - PID=%lu", (ULONG)(ULONG_PTR)ProcessId);
	SendMessageToUser(ZETA_MSG_CODE_INJECT, (ULONG)(ULONG_PTR)ProcessId, FullImageName->Buffer, FullImageName->Length);
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

// =============================================================================
// 内核句柄访问受保护对象 —— 无法阻断, 但绝不静默放行
//
// 背景(2026-09-30 审计): PreOpenProcess / PreOpenThread 原本对
//   OperationInformation->KernelHandle == TRUE 直接 return OB_PREOP_SUCCESS。
// 后果: 任何**内核态**发起的句柄打开(恶意驱动 / 被滥用的 BYOVD / 另一个安全产品)
//   都能绕过 ZETA 的全部 Ob 保护去碰受保护进程与线程, 且不留任何痕迹。
//
// 为什么只告警不阻断:
//   1) ObRegisterCallbacks 本身没有"拒绝"语义 —— OB_PREOP_CALLBACK_STATUS 只有
//      OB_PREOP_SUCCESS 一个值, 它只能改 DesiredAccess 掩码(降级原语);
//   2) 对内核句柄强行清掩码会破坏正常系统组件(csrss/wininit 等)的内核句柄操作,
//      代价远大于收益;
//   3) 这是"同权限对打"的固有边界 —— 内核层不存在比 Ob 回调更早的拦截点(无 Tier 1)。
// 所以正确做法: 让它可见 + 可审计, 由行为引擎/运维侧处置。
//
// 限流: 只对受保护目标上报(否则内核正常活动会刷爆通道), 且首次 + 每 50 次一条。
// =============================================================================
static volatile LONG g_KernelHandleAlerts = 0;
// 用非 const 静态数组: SendMessageToUser 的形参是 PWCHAR(非 const), 直接传字面量编不过;
// 同时 sizeof() 在编译期就给出含结尾 NUL 的字节数, 省掉任何字符串 API。
static WCHAR g_KhMsgProc[]   = L"内核句柄访问受保护进程(无法阻断,仅告警)";
static WCHAR g_KhMsgThread[] = L"内核句柄访问受保护线程(无法阻断,仅告警)";

static VOID ReportKernelHandleAccess(HANDLE TargetPid, BOOLEAN IsThread) {
 LONG n;
 if (KeGetCurrentIrql() != PASSIVE_LEVEL) return;   // 上报通道要求 <= APC_LEVEL
 if (TargetPid == NULL || TargetPid == (HANDLE)4) return;
 if (!IsTargetProtected(TargetPid)) return;         // 只关心受保护目标, 否则会刷屏
 n = InterlockedIncrement(&g_KernelHandleAlerts);
 if (n != 1 && (n % 50) != 0) return;               // 限流: 其余仅计数
 DbgPrint("ZETA: KERNEL-HANDLE access to protected %s pid=%lu (total=%ld)\\n",
          IsThread ? "thread" : "process", (ULONG)(ULONG_PTR)TargetPid, n);
 if (IsThread) {
  SendMessageToUser(ZETA_MSG_KERNEL_HANDLE_ALERT, (ULONG)(ULONG_PTR)TargetPid,
                    g_KhMsgThread, (USHORT)sizeof(g_KhMsgThread));
 } else {
  SendMessageToUser(ZETA_MSG_KERNEL_HANDLE_ALERT, (ULONG)(ULONG_PTR)TargetPid,
                    g_KhMsgProc, (USHORT)sizeof(g_KhMsgProc));
 }
}

static OB_PREOP_CALLBACK_STATUS PreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
 UNREFERENCED_PARAMETER(RegistrationContext);

 // P0-自保护探针(2026-10-02): 必须放在所有提前 return 之前 —— 否则探针会被
 // 早退逻辑(IRQL / KernelHandle / 同PID)吃掉, 变成"永远不命中"的假阳性。
 // 原理见 ProtectProcessDkom.cpp 文件头。
 if (g_ObProbeArmed) InterlockedIncrement(&g_ObProbeHits);

 if (KeGetCurrentIrql() > PASSIVE_LEVEL) return OB_PREOP_SUCCESS;
 if (OperationInformation->KernelHandle) {
  // 内核句柄: 内核态打开不受用户态访问检查约束, 我们拦不住 —— 但绝不能静默放行。
  ReportKernelHandleAccess(PsGetProcessId((PEPROCESS)OperationInformation->Object), FALSE);
  return OB_PREOP_SUCCESS;
 }

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

 // P0-自保护探针(2026-10-02): 同 PreOpenProcess, 必须在所有提前 return 之前。
 if (g_ObProbeArmed) InterlockedIncrement(&g_ObProbeHits);

 if (KeGetCurrentIrql() > PASSIVE_LEVEL) return OB_PREOP_SUCCESS;
 if (OperationInformation->KernelHandle) {
  // 同 PreOpenProcess: 拦不住, 但不静默放行
  {
   HANDLE tpid = (HANDLE)0;
   PEPROCESS tp = IoThreadToProcess((PETHREAD)OperationInformation->Object);
   if (tp) tpid = PsGetProcessId(tp);
   ReportKernelHandleAccess(tpid, TRUE);
  }
  return OB_PREOP_SUCCESS;
 }

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
 NTSTATUS status;

 // 幂等注册: 先注销上一次连接/上一实例残留的注册, 保证任何时刻全驱动
 // 最多只有一组 OB 回调在链上 (否则泄漏的旧回调在驱动卸载后导致 0xCE)。
 KeWaitForSingleObject(&g_ObCallbackMutex, Executive, KernelMode, FALSE, NULL);
 if (g_ObRegistrationHandle) {
  ObUnRegisterCallbacks(g_ObRegistrationHandle);
  g_ObRegistrationHandle = NULL;
 }

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

 status = ObRegisterCallbacks(&ObRegistration, &g_ObRegistrationHandle);

    if (!NT_SUCCESS(status) && (status == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION || status == STATUS_OBJECT_NAME_COLLISION)) {
        static UNICODE_STRING FallbackAltitude = RTL_CONSTANT_STRING(L"320000.ZETA.Ob.Fallback");
        ObRegistration.Altitude = FallbackAltitude;
        status = ObRegisterCallbacks(&ObRegistration, &g_ObRegistrationHandle);
    }

    KeReleaseMutex(&g_ObCallbackMutex, FALSE);

    DbgPrint("ZETA: InitializeProcessProtection status=0x%08lX", status);
    return status;
}

VOID UninitializeProcessProtection() {
 KeWaitForSingleObject(&g_ObCallbackMutex, Executive, KernelMode, FALSE, NULL);
 if (g_ObRegistrationHandle) {
 ObUnRegisterCallbacks(g_ObRegistrationHandle);
 g_ObRegistrationHandle = NULL;
 }
 KeReleaseMutex(&g_ObCallbackMutex, FALSE);
}

