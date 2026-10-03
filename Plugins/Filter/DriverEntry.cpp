#include "DriverCommon.h"

DRIVER_DATA GlobalData;
volatile BOOLEAN g_SelfDkomInProgress = FALSE;  // P0-自伤免疫: ZETA 自修改内核动作标记
static BOOLEAN g_ImageNotifyRegistered = FALSE;
BOOLEAN g_ProcessNotifyExActive = FALSE;
BOOLEAN g_ThreadNotifyActive = FALSE;
WORK_ITEM_TRACKER g_WorkItemTracker = { 0 };

// Trust window global variables
LIST_ENTRY g_TrustWindowList;
KSPIN_LOCK g_TrustWindowLock;

// Driver log level (default: INFO, can be changed via ZETA_CMD_SET_LOG_LEVEL)
ULONG g_DriverLogLevel = ZETA_LOG_INFO;

// DriverEntry initialization state (tracked for log summary on connect)
// Also includes rule counts set by ProtectRules.cpp during LoadRulesFromDisk
static LARGE_INTEGER g_DriverStartTick = {0};
DRIVER_STATE g_DriverState = {0};

// PDB 解析下发的通用内核结构偏移 (0 = 未设置, 使用点回退硬编码宏)
ULONG g_OffEprocessPeb = 0;
ULONG g_OffKthreadTrapFrame = 0;
ULONG g_OffKtrapFrameRip = 0;
ULONG g_OffPebLdr = 0;
ULONG g_OffLdrInMemoryLinks = 0;
ULONG g_OffLdrDllBase = 0;
ULONG g_OffLdrSizeOfImage = 0;
ULONG g_OffLdrBaseDllName = 0;
ULONG g_OffKldrFlags = 0;
ULONG g_OffKldrSignatureLevel = 0;

// ============================================================
// KernelOffsets_Apply — 解析 "key=value,key=value" 应用到偏移全局
// 偏移合理性: < 一页 (内核结构字段偏移不可能超过 0x1000)
// ============================================================
NTSTATUS KernelOffsets_Apply(PCWSTR Encoded) {
    if (!Encoded) return STATUS_INVALID_PARAMETER;

    const WCHAR* p = Encoded;
    while (*p) {
        // 提取 key
        const WCHAR* eq = wcschr(p, L'=');
        if (!eq) break;
        WCHAR key[32];
        SIZE_T keyLen = (SIZE_T)(eq - p);
        if (keyLen >= sizeof(key) / sizeof(WCHAR)) keyLen = sizeof(key) / sizeof(WCHAR) - 1;
        RtlCopyMemory(key, p, keyLen * sizeof(WCHAR));
        key[keyLen] = 0;

        // 提取 value (十进制)
        const WCHAR* v = eq + 1;
        ULONG value = 0;
        while (*v && *v >= L'0' && *v <= L'9') {
            value = value * 10 + (ULONG)(*v - L'0');
            v++;
        }
        if (value > 0x1000) {  // 越界值忽略
            value = 0;
        }

        // 应用
        if (_wcsicmp(key, L"Peb") == 0)          g_OffEprocessPeb = value;
        else if (_wcsicmp(key, L"TrapFrame") == 0)   g_OffKthreadTrapFrame = value;
        else if (_wcsicmp(key, L"Rip") == 0)         g_OffKtrapFrameRip = value;
        else if (_wcsicmp(key, L"Ldr") == 0)         g_OffPebLdr = value;
        else if (_wcsicmp(key, L"InMemLinks") == 0)  g_OffLdrInMemoryLinks = value;
        else if (_wcsicmp(key, L"DllBase") == 0)     g_OffLdrDllBase = value;
        else if (_wcsicmp(key, L"SizeImage") == 0)   g_OffLdrSizeOfImage = value;
        else if (_wcsicmp(key, L"BaseName") == 0)    g_OffLdrBaseDllName = value;
        else if (_wcsicmp(key, L"KldrFlags") == 0)   g_OffKldrFlags = value;
        else if (_wcsicmp(key, L"KldrSig") == 0)     g_OffKldrSignatureLevel = value;

        // 跳到下一个 key (逗号)
        while (*v && *v != L',') v++;
        if (*v == L',') v++;
        p = v;
    }

    ZETA_INFO("KernelOffsets applied: Peb=0x%X TrapFrame=0x%X Rip=0x%X Ldr=0x%X "
              "InMem=0x%X Dll=0x%X Size=0x%X Name=0x%X KF=0x%X KS=0x%X\n",
              g_OffEprocessPeb, g_OffKthreadTrapFrame, g_OffKtrapFrameRip,
              g_OffPebLdr, g_OffLdrInMemoryLinks, g_OffLdrDllBase,
              g_OffLdrSizeOfImage, g_OffLdrBaseDllName,
              g_OffKldrFlags, g_OffKldrSignatureLevel);
    return STATUS_SUCCESS;
}

// ============================================================
// ProcessCreateNotifyEx — PsSetCreateProcessNotifyRoutineEx callback
//
// Primary path: captures process creation with ImageFileName,
// CommandLine and ParentProcessId from PS_CREATE_NOTIFY_INFO.
// Sends to user-mode so EDR can log command line and lineage info.
//
// Fallback: if this registration fails, the existing user-mode
// ProcessMonitor (CreateToolhelp32Snapshot polling) continues
// to work with basic PID/PPID/name visibility.
// ============================================================
#define PROCESS_NOTIFY_PATH_DELIM L'\n'

static VOID ProcessCreateNotifyEx(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    UNREFERENCED_PARAMETER(Process);

    if (g_IsUnloading) return;

    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;
    if (pid <= 4) return;

    if (CreateInfo != NULL) {
        // ── Process creation ──
        ULONG ppid = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;

        WCHAR buf[MAX_PATH_LEN];
        RtlZeroMemory(buf, sizeof(buf));
        PWCHAR ptr = buf;
        ULONG remaining = MAX_PATH_LEN;

        // Section 1: ImageFileName (NT device path)
        if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer) {
            ULONG copyChars = CreateInfo->ImageFileName->Length / sizeof(WCHAR);
            if (copyChars > MAX_PATH_LEN - 4) copyChars = MAX_PATH_LEN - 4;
            RtlCopyMemory(ptr, CreateInfo->ImageFileName->Buffer, copyChars * sizeof(WCHAR));
            ptr += copyChars;
            remaining -= copyChars;
        }

        // Delimiter 1: end of image path
        if (remaining > 1) { *ptr++ = PROCESS_NOTIFY_PATH_DELIM; remaining--; }

        // Section 2: CommandLine
        if (CreateInfo->CommandLine && CreateInfo->CommandLine->Buffer && remaining > 2) {
            ULONG cmdChars = CreateInfo->CommandLine->Length / sizeof(WCHAR);
            if (cmdChars > remaining - 2) cmdChars = remaining - 2;
            RtlCopyMemory(ptr, CreateInfo->CommandLine->Buffer, cmdChars * sizeof(WCHAR));
            ptr += cmdChars;
            remaining -= cmdChars;
        }

        // Delimiter 2: end of command line
        if (remaining > 1) { *ptr++ = PROCESS_NOTIFY_PATH_DELIM; remaining--; }

        // Section 3: PPID as decimal string
        WCHAR ppidStr[16];
        RtlStringCbPrintfW(ppidStr, sizeof(ppidStr), L"%lu", ppid);
        ULONG ppidLen = (ULONG)wcslen(ppidStr);
        if (ppidLen < remaining) {
            RtlCopyMemory(ptr, ppidStr, ppidLen * sizeof(WCHAR));
            ptr += ppidLen;
        }

        ULONG totalBytes = (ULONG)((ULONG_PTR)ptr - (ULONG_PTR)buf);
        // A/B 实验开关 (2026-10-03): 置 ZETA_TEST_NO_CREATE_MSG=1 时跳过上报。
        // 目的: 把"cmd 创建子进程 → 子进程初始线程永挂起"的嫌疑在
        //   ① 进程创建通知里向用户态发消息 (SendMessageToUser)
        //   ② 仅在连接期存在的 Ob 句柄回调 / DKOM
        // 两者之间分开 (断开客户端时两者同时消失, 故需本开关单独隔离①)。
        // 默认(未定义或 0) 保持原行为。
#if !defined(ZETA_TEST_NO_CREATE_MSG) || (ZETA_TEST_NO_CREATE_MSG == 0)
        if (totalBytes > sizeof(WCHAR)) {
            SendMessageToUser(ZETA_MSG_PROCESS_CREATE, pid, buf, totalBytes);
        }
#endif
    }
    else {
        // P2-15: Process exit (CreateInfo == NULL) — notify user-mode for cleanup/logging
        WCHAR exitMark[] = L"exit";
#if !defined(ZETA_TEST_NO_CREATE_MSG) || (ZETA_TEST_NO_CREATE_MSG == 0)
        SendMessageToUser(ZETA_MSG_PROCESS_EXIT, pid, exitMark, (USHORT)sizeof(exitMark));
#else
        UNREFERENCED_PARAMETER(exitMark);
#endif
    }
}

// =============================================================================
// ThreadNotifyRoutine — PsSetCreateThreadNotifyRoutine callback
// 监控线程创建，上报到用户态行为引擎
// 注意: 线程创建非常频繁（系统每秒创建/销毁数百个），加限速防刷屏
// =============================================================================
static VOID ThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
    if (!Create) return;  // 线程销毁太频繁，不报

    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;

    // 限速: 同一进程每秒最多报 1 次线程创建
    // 使用静态哈希表做简单限速
    static struct {
        ULONG Pid;
        ULONG LastTick;
    } throttle[32] = {0};
    static KSPIN_LOCK throttleLock = {0};
    LARGE_INTEGER tickCount;
    KeQueryTickCount(&tickCount);
    ULONG currentTick = (ULONG)tickCount.QuadPart;  // ~10ms per tick

    KIRQL irql;
    KeAcquireSpinLock(&throttleLock, &irql);

    BOOLEAN shouldReport = TRUE;
    for (int i = 0; i < 32; i++) {
        if (throttle[i].Pid == pid) {
            // 上次上报在 100 tick (约1秒) 以内的跳过
            if (currentTick - throttle[i].LastTick < 100) {
                shouldReport = FALSE;
            } else {
                throttle[i].LastTick = currentTick;
            }
            break;
        }
        if (throttle[i].Pid == 0) {
            // 空槽，占用
            throttle[i].Pid = pid;
            throttle[i].LastTick = currentTick;
            break;
        }
    }

    KeReleaseSpinLock(&throttleLock, irql);

    if (!shouldReport) return;

    // ── P0: 跨进程线程注入检测 ──
    // ThreadNotifyRoutine 在创建者线程上下文中运行，
    // PsGetCurrentProcessId() = 创建者, ProcessId = 目标进程
    BOOLEAN isRemoteThread = FALSE;
    HANDLE creatorPid = PsGetCurrentProcessId();
    if (creatorPid != ProcessId) {
        isRemoteThread = TRUE;
    }

    // 上报线程创建: PID,TID[,R,CreatorPid]  (R = remote thread)
    //
    // A/B 实验开关 (2026-10-03): ZETA_TEST_NO_THREAD_MSG=1 时跳过本上报。
    // 依据: 本回调运行在【创建者线程上下文】, 且对于新进程的初始线程, 它是在
    //       NtCreateUserProcess 内部、初始线程尚未插入/被恢复之前被调用的。
    //       因此本函数内任何阻塞都会让新进程的初始线程永久停留在内核创建时的
    //       悬挂态 —— 与实测 "ResumeThread 返回 previousSuspendCount 恰为 1、
    //       恢复后进程立即跑通" 完全吻合。
    // 默认(未定义或 0) 保持原行为。
    WCHAR buf[64];
    if (isRemoteThread) {
        NTSTATUS len = RtlStringCbPrintfW(buf, sizeof(buf), L"%lu,%lu,R,%lu",
            pid, (ULONG)(ULONG_PTR)ThreadId, (ULONG)(ULONG_PTR)creatorPid);
#if !defined(ZETA_TEST_NO_THREAD_MSG) || (ZETA_TEST_NO_THREAD_MSG == 0)
        if (NT_SUCCESS(len)) {
            SendMessageToUser(ZETA_MSG_THREAD_CREATE, pid, buf, (USHORT)(wcslen(buf) * sizeof(WCHAR)));
        }
#else
        UNREFERENCED_PARAMETER(len);
#endif
    } else {
        NTSTATUS len = RtlStringCbPrintfW(buf, sizeof(buf), L"%lu,%lu",
            pid, (ULONG)(ULONG_PTR)ThreadId);
#if !defined(ZETA_TEST_NO_THREAD_MSG) || (ZETA_TEST_NO_THREAD_MSG == 0)
        if (NT_SUCCESS(len)) {
            SendMessageToUser(ZETA_MSG_THREAD_CREATE, pid, buf, (USHORT)(wcslen(buf) * sizeof(WCHAR)));
        }
#else
        UNREFERENCED_PARAMETER(len);
#endif
    }
}

static NTSTATUS InstanceSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType) {
 UNREFERENCED_PARAMETER(FltObjects);
 UNREFERENCED_PARAMETER(Flags);
 UNREFERENCED_PARAMETER(VolumeDeviceType);
 UNREFERENCED_PARAMETER(VolumeFilesystemType);
 return STATUS_SUCCESS;
}

static NTSTATUS InstanceQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags) {
 UNREFERENCED_PARAMETER(FltObjects);
 UNREFERENCED_PARAMETER(Flags);
 return STATUS_SUCCESS;
}

static VOID InstanceTeardownStart(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags) {
 UNREFERENCED_PARAMETER(FltObjects);
 UNREFERENCED_PARAMETER(Flags);
}

static VOID InstanceTeardownComplete(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags) {
 UNREFERENCED_PARAMETER(FltObjects);
 UNREFERENCED_PARAMETER(Flags);
}

/* =============================================================================
   UnloadDiag_Write — 记录 FilterUnloadCallback 收到的 Flags 与授权状态

   用途: 判定"用回调返回值否决卸载"这条路为什么没生效(实测 sc stop 未被拦住):
     Flags == FLTFL_FILTER_UNLOAD_MANDATORY(1) → 守卫条件本身不成立, 从未激活
                                                   (说明"sc stop 需先授权"的假设是错的)
     Flags == 0                                 → 守卫激活并返回了 ACCESS_DENIED,
                                                   但卸载仍然发生 → 返回值被忽略
   写到 HKLM\...\Services\ZETA_Drv\Parameters\LastUnloadFlags (REG_DWORD):
     低 16 位 = Flags, 最高位 = 当时 g_UnloadAuthorized。
   回调运行在 PASSIVE_LEVEL, 可安全 Zw*。
   ============================================================================= */
static VOID UnloadDiag_Write(ULONG flags, BOOLEAN authorized)
{
	UNICODE_STRING keyPath, valName;
	OBJECT_ATTRIBUTES oa;
	HANDLE hKey = NULL;
	ULONG value = (flags & 0xFFFFu) | (authorized ? 0x80000000u : 0u);

	RtlInitUnicodeString(&keyPath,
		L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ZETA_Drv\\Parameters");
	InitializeObjectAttributes(&oa, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	if (!NT_SUCCESS(ZwOpenKey(&hKey, KEY_SET_VALUE, &oa))) {
		if (!NT_SUCCESS(ZwCreateKey(&hKey, KEY_SET_VALUE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL)))
			return;
	}
	RtlInitUnicodeString(&valName, L"LastUnloadFlags");
	ZwSetValueKey(hKey, &valName, 0, REG_DWORD, &value, sizeof(value));
	ZwClose(hKey);
}

static NTSTATUS DriverUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
	UnloadDiag_Write((ULONG)Flags, g_UnloadAuthorized);
 // ── 防卸载 (官方机制, 不依赖 SSDT): 未授权卸载 → 拒绝 ──
 // 系统强制卸载(关机/崩溃, FLTFL_FILTER_UNLOAD_MANDATORY)必须放行;
 // 常规 sc stop / fltmc unload 必须先经 ZETA_CMD_AUTHORIZE_UNLOAD(27) 授权,
 // 否则返回非成功码 → fltmgr 拒绝卸载 → 恶意软件卸不掉驱动。
 if (Flags != FLTFL_FILTER_UNLOAD_MANDATORY && !g_UnloadAuthorized) {
  DbgPrint("ZETA: DriverUnload BLOCKED (unauthorized). Send ZETA_CMD_AUTHORIZE_UNLOAD first.\n");
  return STATUS_ACCESS_DENIED;
 }

 DbgPrint("ZETA: DriverUnload: begin\n");

 // 1. Set unload flag
 g_IsUnloading = TRUE;

 // 1a. 先同步停止 DKOM watchdog 线程(join)。若后停, watchdog 会在卸载中途
 //     恢复被还原的 SSDT hook / 在句柄置空后重注册 OB 回调 → 残留回调
 //     在镜像卸载后触发 0xCE (DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS)。
 UninitializeDkomProcessProtection();

#if ZETA_ENABLE_SSDT
 // 1b. Restore SSDT APC hook BEFORE the image can be unmapped
 ApcHook_Disable();
 DbgPrint("ZETA: DriverUnload: APC hook disabled\n");

 // 1c. Restore UnloadGuard SSDT hook (NtUnloadDriver) before image unmap
 UnloadGuard_Disable();
 DbgPrint("ZETA: DriverUnload: UnloadGuard disabled\n");

 // 1d. Restore InjectHook SSDT (NtCreateThreadEx/NtWriteVirtualMemory) before unmap
 InjectHook_Disable();
 DbgPrint("ZETA: DriverUnload: InjectHook disabled\n");
#endif

 // 2. Wait for any pending deferred work items to complete
 // This prevents use-after-free if work items are still accessing g_PendingOps
 if (InterlockedCompareExchange(&g_WorkItemTracker.PendingCount, 0, 0) > 0) {
  LARGE_INTEGER timeout;
  timeout.QuadPart = -50000000LL; // 5 seconds
  KeWaitForSingleObject(&g_WorkItemTracker.CompletionEvent, Executive, KernelMode, FALSE, &timeout);
  KeResetEvent(&g_WorkItemTracker.CompletionEvent);
  DbgPrint("ZETA: DriverUnload: pending work items drained\n");
 }

 // 3. Remove process creation notify for LineageTracker
 if (g_LineageTrackerEnabled) {
  PsSetCreateProcessNotifyRoutine(LineageTracker_OnProcessCreate, TRUE);
  g_LineageTrackerEnabled = FALSE;
  DbgPrint("ZETA: DriverUnload: process notify removed\n");
 }

 // 3b. Remove process creation notify (Ex) for user-mode command line reporting
 if (g_ProcessNotifyExActive) {
  PsSetCreateProcessNotifyRoutineEx(ProcessCreateNotifyEx, TRUE);
  g_ProcessNotifyExActive = FALSE;
  DbgPrint("ZETA: DriverUnload: process notify (Ex) removed\n");
 }

 // 3c. Remove thread creation notify
 if (g_ThreadNotifyActive) {
  PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);
  g_ThreadNotifyActive = FALSE;
  DbgPrint("ZETA: DriverUnload: thread notify removed\n");
 }

 // 4. Remove image load notify
 if (g_ImageNotifyRegistered) {
  PsRemoveLoadImageNotifyRoutine(ImageLoadNotify);
  g_ImageNotifyRegistered = FALSE;
  DbgPrint("ZETA: DriverUnload: image notify removed\n");
 }

 // 5. Unregister CmCallback (registry protection)
 UninitializeRegistryProtection();
 DbgPrint("ZETA: DriverUnload: registry protection uninitialized\n");

 // 6. Close communication port (prevents new user-mode commands)
 if (GlobalData.ServerPort) {
  FltCloseCommunicationPort(GlobalData.ServerPort);
  GlobalData.ServerPort = NULL;
  DbgPrint("ZETA: DriverUnload: communication port closed\n");
 }

 // 7. Stop timeout checker thread
 StopTimeoutChecker();

 // 7a. M1-5: 勒索挂起进程兜底 — 超时线程已停, 对仍挂起等待决策的进程执行默认策略
 //     (默认 Kill; 否则驱动卸载后这些进程将永久冻结)
 RansomExp_CleanupSuspendTrack();

 // 7b. Complete ALL pending operations BEFORE filter unregistration.
 //     FltCompletePendedPreOperation 使 FLTMGR 释放其内部对 CallbackData 的引用，
 //     然后才释放 PENDING_OP 内存。之后再 FltUnregisterFilter 时就安全了。
 CompleteAllPendingOperations();
 CleanupTrustWindow();
 DbgPrint("ZETA: DriverUnload: timeout checker stopped, pending ops and trust window cleaned up\n");

 
 
 // 8. Unregister filter (waits for minifilter callbacks to drain)
 if (GlobalData.FilterHandle) {
  FltUnregisterFilter(GlobalData.FilterHandle);
  GlobalData.FilterHandle = NULL;
  DbgPrint("ZETA: DriverUnload: filter unregistered\n");
 }

 // 8b. Unregister ObRegisterCallbacks (if registered)
 UninitializeProcessProtection();
 DbgPrint("ZETA: DriverUnload: Ob callbacks unregistered\n");

 // 8c. Stop DKOM PPL watchdog (after filter unregister, before rules cleanup)
 UninitializeDkomProcessProtection();
 DbgPrint("ZETA: DriverUnload: DKOM PPL protection uninitialized\n");

 // 9. Cleanup rules and engine (MUST happen AFTER filter unregistration)
 UnloadRules();
 UninitializeRulesEngine();
 DbgPrint("ZETA: DriverUnload: rules and engine cleaned up\n");

 DbgPrint("ZETA: DriverUnload: complete\n");
 return STATUS_SUCCESS;
}

static NTSTATUS PortMessage(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnOutputBufferLength) {
 UNREFERENCED_PARAMETER(PortCookie);

 if (!InputBuffer || InputBufferLength < sizeof(ZETA_USER_MESSAGE)) {
 return STATUS_INVALID_PARAMETER;
 }

 PZETA_USER_MESSAGE msg = (PZETA_USER_MESSAGE)InputBuffer;

 // Handle init log request: build the DriverInit summary string in OutputBuffer
 if (msg->Command == ZETA_CMD_GET_INITLOG) {
  WCHAR LogBuf[2048];
  ULONG LogLen;
  RtlStringCbPrintfW(LogBuf, sizeof(LogBuf),
	 L"DriverInit: RulesEngine=%ls Filter=%ls Port=%ls ProcessProt=%ls(0x%08lX) RegProt=%ls ImageNotify=%ls LineageNotify=%ls ProcessNotifyEx=%ls(0x%08lX) FilterStart=%ls AnyFail=%ls\n"
   L"Kernel Rules: Rules_Driver_P1=%ls(0x%08lX) Rules_User=%ls(0x%08lX)\n"
   L"Rules: RegistryBlock=%lu RegistryTrust=%lu ProcessTrust=%lu ProcessExploit=%lu FileProtect=%lu FileExcept=%lu FileSafe=%lu FileRansom=%lu",
   g_DriverState.RulesEngineOK ? L"OK" : L"FAIL",
   g_DriverState.FilterRegistered ? L"OK" : L"FAIL",
   g_DriverState.PortCreated ? L"OK" : L"FAIL",
   g_DriverState.ProcessProtectionOK ? L"OK" : L"FAIL",
   g_DriverState.ProcessProtectionStatus,
   g_DriverState.RegistryProtectionOK ? L"OK" : L"FAIL",
   g_DriverState.ImageNotifyOK ? L"OK" : L"FAIL",
   g_DriverState.LineageTrackerOK ? L"OK" : L"FAIL",
   g_DriverState.ProcessNotifyExOK ? L"OK" : L"FAIL",
   g_DriverState.ProcessNotifyExStatus,
   g_DriverState.FilterStarted ? L"OK" : L"FAIL",
   g_DriverState.AnyFailure ? L"YES" : L"NO",
   NT_SUCCESS(g_DriverState.SystemRulesStatus) ? L"OK" : L"FAIL",
   g_DriverState.SystemRulesStatus,
   NT_SUCCESS(g_DriverState.UserRulesStatus) ? L"OK" : L"FAIL",
   g_DriverState.UserRulesStatus,
   g_DriverState.RegistryBlockCount,
   g_DriverState.RegistryTrustedCount,
   g_DriverState.ProcessTrustedCount,
   g_DriverState.ProcessExploitCount,
   g_DriverState.FileProtectedCount,
   g_DriverState.FileExceptionCount,
   g_DriverState.FileSafeExceptionCount,
   g_DriverState.FileRansomCount
  );

  LogLen = (ULONG)((wcslen(LogBuf) + 1) * sizeof(WCHAR));
  if (OutputBuffer && OutputBufferLength >= LogLen) {
   RtlCopyMemory(OutputBuffer, LogBuf, LogLen);
   if (ReturnOutputBufferLength) *ReturnOutputBufferLength = LogLen;
  } else if (ReturnOutputBufferLength) {
   *ReturnOutputBufferLength = 0;
  }
  return STATUS_SUCCESS;
 }

 // Handle allow/deny pending operation commands - use deferred work item for IRQL safety
if (msg->Command == ZETA_CMD_ALLOW_OP || msg->Command == ZETA_CMD_DENY_OP) {
 ULONG targetPid = 0;
 for (int i = 0; i < MAX_PATH_LEN && msg->Path[i]; i++) {
 targetPid = targetPid * 10 + (ULONG)(msg->Path[i] - L'0');
 }
  if (targetPid > 0) {
  // Queue deferred work item to complete at PASSIVE_LEVEL (for IRP pending ops)
  QueueCompletePendingOperation(targetPid, msg->Command == ZETA_CMD_ALLOW_OP);

  // P1-2: 同时处理勒索软件挂起进程的用户态决策
  // - ALLOW_OP: 恢复被 PsSuspendProcess 挂起的进程
  // - DENY_OP:  终止被挂起的勒索进程
  // 若 PID 不在挂起列表，这些调用会无害失败
  if (msg->Command == ZETA_CMD_ALLOW_OP) {
  ResumeSuspendedProcess(targetPid);
  } else {
  KillSuspendedProcess(targetPid);
  }

#if ZETA_ENABLE_SSDT
  // APC hook: 完成挂起的 NtQueueApcThread 决策 (源进程)
  // Lite 版无 APC 钩子、无 g_ApcPending 待决表，CompletePendingApc 的
  // 定义随 ApcHook.cpp 整文件空编而消失 → 调用点必须一并剔除，否则 LNK2019。
  // 语义上 Lite 也不会有 APC 待决项，剔除后行为等价（原本即为无害空操作）。
  CompletePendingApc(targetPid, msg->Command == ZETA_CMD_ALLOW_OP);
#endif

  ZETA_INFO("Queued %s operation for PID=%lu\n",
  msg->Command == ZETA_CMD_ALLOW_OP ? "ALLOW" : "DENY", targetPid);
  }
 if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
 return STATUS_SUCCESS;
}

 // Handle experimental feature toggle commands
 if (msg->Command == ZETA_CMD_SET_LINEAGE_TRACKER) {
  // Path[0] = L'1' means enable, anything else means disable
  BOOLEAN enable = (msg->Path[0] == L'1');
  LineageTracker_SetEnabled(enable);
  if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
  return STATUS_SUCCESS;
 }

 if (msg->Command == ZETA_CMD_SET_RANSOM_EXPERIMENTAL) {
  BOOLEAN enable = (msg->Path[0] == L'1');
  RansomExp_SetEnabled(enable);
  if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
  return STATUS_SUCCESS;
 }

 // P1-状态机: 勒索写重定向开关 (ZETA_CMD_SET_RANSOM_REDIRECT=21)
 if (msg->Command == ZETA_CMD_SET_RANSOM_REDIRECT) {
  g_RansomRedirectEnabled = (msg->Path[0] == L'1');
  ZETA_INFO("Ransom redirect enabled=%u\n", g_RansomRedirectEnabled);
  if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
  return STATUS_SUCCESS;
 }

 // P0: 文档写前备份开关 (ZETA_CMD_SET_DOC_BACKUP=26)
 if (msg->Command == ZETA_CMD_SET_DOC_BACKUP) {
  DocBackup_SetEnabled(msg->Path[0] == L'1');
  if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
  return STATUS_SUCCESS;
 }

 // 防卸载授权 (ZETA_CMD_AUTHORIZE_UNLOAD=27): 卸载前先置授权, 否则 FilterUnload 拒绝
 if (msg->Command == ZETA_CMD_AUTHORIZE_UNLOAD) {
  g_UnloadAuthorized = (msg->Path[0] == L'1');
  ZETA_INFO("Unload authorized=%u\n", g_UnloadAuthorized);
  if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
  return STATUS_SUCCESS;
 }

 // ── P1-1: 6 个运行时模块开关命令 ─────────────────────────────
 // 通过 ZETA_CMD_SET_* 命令启用/禁用各保护模块
 // Path[0] = L'1' 启用，其他值禁用
 if (msg->Command >= ZETA_CMD_SET_PROCESS_PROTECT &&
     msg->Command <= ZETA_CMD_SET_NETWORK_PROTECT) {
  BOOLEAN enable = (msg->Path[0] == L'1');
  PBOOLEAN pFlag = NULL;
  PCWSTR  flagName = L"";

  switch (msg->Command) {
   case ZETA_CMD_SET_PROCESS_PROTECT:
    pFlag = &g_ProcessProtectEnabled;  flagName = L"ProcessProtect"; break;
   case ZETA_CMD_SET_SUSPEND_ENABLE:
    pFlag = &g_SuspendEnabled;         flagName = L"SuspendPending"; break;
   case ZETA_CMD_SET_FILE_PROTECT:
    pFlag = &g_FileProtectEnabled;      flagName = L"FileProtect";    break;
   case ZETA_CMD_SET_SYSTEM_PROTECT:
    pFlag = &g_SystemProtectEnabled;   flagName = L"SystemProtect";  break;
   case ZETA_CMD_SET_DRIVER_PROTECT:
    pFlag = &g_DriverProtectEnabled;    flagName = L"DriverProtect";  break;
   case ZETA_CMD_SET_NETWORK_PROTECT:
    pFlag = &g_NetworkProtectEnabled;   flagName = L"NetworkProtect"; break;
   default:
    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
    return STATUS_INVALID_PARAMETER;
  }

  if (pFlag) {
   *pFlag = enable;
   ZETA_INFO("Module switch %ls = %ls\n", flagName, enable ? L"ENABLED" : L"DISABLED");
  }
  if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
  return STATUS_SUCCESS;
 }

 if (msg->Command == ZETA_CMD_ROLLBACK_MARK) {
  ULONG targetPid = 0;
  for (int i = 0; i < MAX_PATH_LEN && msg->Path[i]; i++) {
   targetPid = targetPid * 10 + (ULONG)(msg->Path[i] - L'0');
  }
  if (targetPid > 0) {
   Rollback_MarkTerminated(targetPid);
  }
  if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
  return STATUS_SUCCESS;
 }

 if (msg->Command == ZETA_CMD_SET_LEARNING_MODE) {
  BOOLEAN enable = (msg->Path[0] == L'1');
  LearningMode_SetEnabled(enable);
  if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
  return STATUS_SUCCESS;
 }

 if (msg->Command == ZETA_CMD_RELOAD_RULES) {
    // Reload all rules from disk (reads JSON files again)
    UnloadRules();
    NTSTATUS reloadStatus = LoadRulesFromDisk(NULL);
    if (NT_SUCCESS(reloadStatus)) {
        ZETA_INFO("Rules reloaded successfully via CMD_RELOAD_RULES\n");
    } else {
        ZETA_ERROR("Rules reload FAILED via CMD_RELOAD_RULES (0x%08X)\n", reloadStatus);
    }
    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
    return STATUS_SUCCESS;
 }

 if (msg->Command == ZETA_CMD_SET_AUDIT_MODE) {
    ULONG mode = (ULONG)(msg->Path[0] - L'0');
    if (mode > AUDIT_MODE_SAMPLING) mode = AUDIT_MODE_OFF;
    g_AuditMode = mode;
    ZETA_INFO("Audit mode set to %lu\n", g_AuditMode);
    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
    return STATUS_SUCCESS;
 }

 if (msg->Command == ZETA_CMD_SET_APC_HOOK) {
    // Path = "ApcSysno,ValidateSysno" (由用户态从 ntdll stub 解析)
    ULONG apcSysno = 0, validateSysno = 0;
    PCWSTR p = msg->Path;
    while (*p && *p >= L'0' && *p <= L'9') { apcSysno = apcSysno * 10 + (ULONG)(*p - L'0'); p++; }
    if (*p == L',') {
        p++;
        while (*p && *p >= L'0' && *p <= L'9') { validateSysno = validateSysno * 10 + (ULONG)(*p - L'0'); p++; }
    }
#if ZETA_ENABLE_SSDT
    NTSTATUS hookStatus = ApcHook_Enable(apcSysno, validateSysno);
    ZETA_INFO("APC hook cmd: apc=%lu validate=%lu status=0x%08X\n",
              apcSysno, validateSysno, hookStatus);
#else
    ZETA_INFO("APC hook cmd ignored (Lite build, SSDT disabled): apc=%lu\n", apcSysno);
#endif
    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
    return STATUS_SUCCESS;
 }

 if (msg->Command == ZETA_CMD_SET_UNLOAD_GUARD) {
    // Path = "UnloadSysno,ValidateSysno" (由用户态从 ntdll stub 解析)
    ULONG unloadSysno = 0, validateSysno = 0;
    PCWSTR p = msg->Path;
    while (*p && *p >= L'0' && *p <= L'9') { unloadSysno = unloadSysno * 10 + (ULONG)(*p - L'0'); p++; }
    if (*p == L',') {
        p++;
        while (*p && *p >= L'0' && *p <= L'9') { validateSysno = validateSysno * 10 + (ULONG)(*p - L'0'); p++; }
    }
#if ZETA_ENABLE_SSDT
    NTSTATUS guardStatus = UnloadGuard_Enable(unloadSysno, validateSysno);
    ZETA_INFO("UnloadGuard cmd: unload=%lu validate=%lu status=0x%08X\n",
              unloadSysno, validateSysno, guardStatus);
#else
    ZETA_INFO("UnloadGuard cmd ignored (Lite build, SSDT disabled): unload=%lu\n", unloadSysno);
#endif
    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
    return STATUS_SUCCESS;
 }

 if (msg->Command == ZETA_CMD_SET_INJECT_HOOK) {
    // Path = "CreateThreadSysno,WriteMemSysno,UnmapSysno,ValidateSysno" (用户态从 ntdll stub 解析)
    // P2-优先级2: 增加 NtUnmapViewOfSection (进程镂空前置"清空")
    ULONG ctSysno = 0, wmSysno = 0, unmapSysno = 0, validateSysno = 0;
    PCWSTR p = msg->Path;
    while (*p && *p >= L'0' && *p <= L'9') { ctSysno = ctSysno * 10 + (ULONG)(*p - L'0'); p++; }
    if (*p == L',') {
        p++;
        while (*p && *p >= L'0' && *p <= L'9') { wmSysno = wmSysno * 10 + (ULONG)(*p - L'0'); p++; }
    }
    if (*p == L',') {
        p++;
        while (*p && *p >= L'0' && *p <= L'9') { unmapSysno = unmapSysno * 10 + (ULONG)(*p - L'0'); p++; }
    }
    if (*p == L',') {
        p++;
        while (*p && *p >= L'0' && *p <= L'9') { validateSysno = validateSysno * 10 + (ULONG)(*p - L'0'); p++; }
    }
#if ZETA_ENABLE_SSDT
    NTSTATUS hookStatus = InjectHook_Enable(ctSysno, wmSysno, unmapSysno, validateSysno);
    ZETA_INFO("InjectHook cmd: ct=%lu wm=%lu unmap=%lu validate=%lu status=0x%08X\n",
              ctSysno, wmSysno, unmapSysno, validateSysno, hookStatus);
#else
    ZETA_INFO("InjectHook cmd ignored (Lite build, SSDT disabled)\n");
#endif
    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
    return STATUS_SUCCESS;
 }

 if (msg->Command == ZETA_CMD_SET_PROTECTION_OFFSET) {
    // Path = "十进制偏移" (用户态 dbghelp 从 ntoskrnl PDB 解析 _EPROCESS.Protection)
    ULONG offset = 0;
    PCWSTR p = msg->Path;
    while (*p && *p >= L'0' && *p <= L'9') { offset = offset * 10 + (ULONG)(*p - L'0'); p++; }
    NTSTATUS offStatus = DkomSetProtectionOffset(offset);
    ZETA_INFO("ProtectionOffset cmd: 0x%X status=0x%08X\n", offset, offStatus);
    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
    return STATUS_SUCCESS;
 }

 if (msg->Command == ZETA_CMD_SET_SYSCALL_SPOOF_BLOCK) {
    // Path = "0/1" — 间接 syscall 反制开关
    BOOLEAN enable = (msg->Path[0] == L'1') ? TRUE : FALSE;
#if ZETA_ENABLE_SSDT
    NTSTATUS sbStatus = InjectHook_SetSyscallSpoofBlock(enable);
    ZETA_INFO("SyscallSpoofBlock cmd: %u status=0x%08X\n", enable, sbStatus);
#else
    ZETA_INFO("SyscallSpoofBlock cmd ignored (Lite build, SSDT disabled)\n");
#endif
    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
    return STATUS_SUCCESS;
 }

 if (msg->Command == ZETA_CMD_SET_KERNEL_OFFSETS) {
    // Path = "key=value,key=value" — PDB 解析的通用内核结构偏移表
    NTSTATUS koStatus = KernelOffsets_Apply(msg->Path);
    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
    return koStatus;
 }

 if (msg->Command == ZETA_CMD_QUERY_AUDIT_LOG) {
    // Copy ring buffer to output for user-mode consumption
    if (!g_AuditRing || !OutputBuffer || OutputBufferLength < sizeof(AUDIT_RING_BUFFER)) {
        if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlCopyMemory(OutputBuffer, g_AuditRing, sizeof(AUDIT_RING_BUFFER));
    *ReturnOutputBufferLength = sizeof(AUDIT_RING_BUFFER);
    // Advance tail to mark all entries as consumed
    InterlockedExchange(&g_AuditRing->Tail, g_AuditRing->Head);
    return STATUS_SUCCESS;
 }

 if (msg->Command != ZETA_CMD_ADD_WHITELIST && msg->Command != ZETA_CMD_REMOVE_WHITELIST) {
 return STATUS_INVALID_PARAMETER;
 }

 ULONG pathLenBytes = 0;
 ULONG maxPathOffset = InputBufferLength - sizeof(ULONG);
 ULONG maxPathChars = maxPathOffset / sizeof(WCHAR);
 
 for (ULONG i = 0; i < maxPathChars && i < MAX_PATH_LEN; i++) {
 if (msg->Path[i] == L'\0') {
 pathLenBytes = i * sizeof(WCHAR);
 break;
 }
 }
 
 if (pathLenBytes == 0) {
 return STATUS_INVALID_PARAMETER;
 }

 UNICODE_STRING us;
 us.Buffer = msg->Path;
 us.Length = (USHORT)pathLenBytes;
 us.MaximumLength = (USHORT)min(maxPathOffset, MAX_PATH_LEN * sizeof(WCHAR));

 if (msg->Command == ZETA_CMD_ADD_WHITELIST) {
 AddDynamicWhitelist(&us);
 } else {
 RemoveDynamicWhitelist(&us);
 }

 if (ReturnOutputBufferLength) {
 *ReturnOutputBufferLength = 0;
 }
 return STATUS_SUCCESS;
}

/* =============================================================================
   BuildExpectedClientPath — 由驱动自身映像路径反推期望的客户端路径

   =============================================================================
   背景（2026-09-29 实测确认的安全缺陷）:
     PortConnect 原先只做 WildcardMatch(L"*\\ZETA.exe", imageName) —— 任何进程
     只要把自己命名为 ZETA.exe 就能连上通信端口(实测: 复制 pwsh.exe 改名即可),
     进而下发 cmd 27(授权卸载) / cmd 12(关闭驱动保护) 等任意命令。
     名字不是身份。

   现改为路径钉死: 期望客户端 = <安装根>\ZETA.exe, 其中 <安装根> 由驱动自身
   映像路径反推。驱动位于 <安装根>\Plugins\Filter\ZETA_Drv.sys, 故
     去文件名 → …\Plugins\Filter
     去两段   → <安装根>
   然后拼上 \ZETA.exe。

   这样攻击者必须把文件放在应用目录下并命名为 ZETA.exe —— 也就是只能覆盖真正的
   ZETA.exe(破坏性且可检测), 而不是随便丢一个同名文件便能获得端口控制权。

   残余风险(明确记录): 能写应用目录的管理员仍可替换 ZETA.exe。彻底解决需要内核态
   代码签名校验(如用 CiValidateFileObject 对齐本项目证书), 列为后续项。

   成功时 *out->Buffer 为新分配内存, 调用方负责 ExFreePool。
   ============================================================================= */
/* 本 WDK 头里 KLDR_DATA_TABLE_ENTRY 未导出(依赖 NTDDI_VERSION), 故就地声明最小字段集。
   布局稳定且被广泛引用: x64 下 3 个 LIST_ENTRY 各 16 字节 → FullDllName 在 +0x48。 */
typedef struct _ZETA_LDR_ENTRY {
	LIST_ENTRY     InLoadOrderLinks;
	LIST_ENTRY     InMemoryOrderLinks;
	LIST_ENTRY     InInitializationOrderLinks;
	PVOID          DllBase;
	PVOID          EntryPoint;
	ULONG          SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} ZETA_LDR_ENTRY, *PZETA_LDR_ENTRY;

static BOOLEAN BuildExpectedClientPath(PUNICODE_STRING out)
{
	PZETA_LDR_ENTRY ldr;
	UNICODE_STRING driverPath;
	USHORT len, i;
	USHORT bsCount = 0;
	USHORT cutPos  = 0;
	static const WCHAR kSuffix[] = L"\\ZETA.exe";
	USHORT suffixLen;
	USHORT total;
	PWCH   buf;

	if (!out) return FALSE;
	out->Buffer = NULL; out->Length = 0; out->MaximumLength = 0;

	if (!GlobalData.DriverObject || !GlobalData.DriverObject->DriverSection) return FALSE;
	ldr = (PZETA_LDR_ENTRY)GlobalData.DriverObject->DriverSection;
	driverPath = ldr->FullDllName;
	if (!driverPath.Buffer || driverPath.Length < (4 * sizeof(WCHAR))) return FALSE;

	len = (USHORT)(driverPath.Length / sizeof(WCHAR));

	/* 从尾部往前找第 3 个反斜杠: 文件名前一个 + Filter 前 + Plugins 前 */
	for (i = len; i > 0; i--) {
		if (driverPath.Buffer[i - 1] == L'\\') {
			bsCount++;
			if (bsCount == 3) { cutPos = (USHORT)(i - 1); break; }
		}
	}
	/* 层级不足说明部署形态与预期不符 —— 保守拒绝, 不猜 */
	if (bsCount < 3 || cutPos == 0) return FALSE;

	suffixLen = (USHORT)(sizeof(kSuffix) - sizeof(WCHAR));
	total     = (USHORT)(cutPos * sizeof(WCHAR) + suffixLen);

	buf = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)total + sizeof(WCHAR), 'etaZ');
	if (!buf) return FALSE;

	RtlCopyMemory(buf, driverPath.Buffer, (SIZE_T)cutPos * sizeof(WCHAR));
	RtlCopyMemory((PUCHAR)buf + (SIZE_T)cutPos * sizeof(WCHAR), kSuffix, suffixLen);
	buf[total / sizeof(WCHAR)] = L'\0';

	out->Buffer        = buf;
	out->Length        = total;
	out->MaximumLength = (USHORT)(total + sizeof(WCHAR));

	return TRUE;
}

/* =============================================================================
   PortConnectDiag_Write — 把最近一次客户端身份判定写进注册表 (诊断)

   DbgPrint 在没有内核调试器时看不到, 而鉴定失败又恰恰发生在我们最需要证据的时刻。
   这里把【实际调用方路径】与【推导出的期望路径】落成 REG_MULTI_SZ 写在
     HKLM\SYSTEM\CurrentControlSet\Services\ZETA_Drv\Parameters\LastClientCheck
   用户态直接读注册表即可比对差异, 不必上内核调试器。

   写失败不影响判定（诊断是尽力而为）。PortConnect 运行在 PASSIVE_LEVEL, 可安全 Zw*。
   ============================================================================= */
static VOID PortConnectDiag_Write(PCUNICODE_STRING actual, PCUNICODE_STRING expected, BOOLEAN matched)
{
	UNICODE_STRING keyPath, valName;
	OBJECT_ATTRIBUTES oa;
	HANDLE hKey = NULL;
	LONG st;
	ULONG actualLen = (actual && actual->Buffer) ? actual->Length : 0;
	ULONG expectLen = (expected && expected->Buffer) ? expected->Length : 0;
	ULONG total = actualLen + expectLen + 4 * sizeof(WCHAR);
	PWCH buf, p;

	UNREFERENCED_PARAMETER(matched);

	RtlInitUnicodeString(&keyPath,
		L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ZETA_Drv\\Parameters");
	InitializeObjectAttributes(&oa, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	st = ZwOpenKey(&hKey, KEY_SET_VALUE, &oa);
	if (!NT_SUCCESS(st)) {
		st = ZwCreateKey(&hKey, KEY_SET_VALUE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
		if (!NT_SUCCESS(st)) return;
	}

	buf = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, total, 'etaZ');
	if (!buf) { ZwClose(hKey); return; }

	p = buf;
	if (actualLen) { RtlCopyMemory(p, actual->Buffer, actualLen); p += (actualLen / sizeof(WCHAR)); }
	*p++ = L'\0';
	if (expectLen) { RtlCopyMemory(p, expected->Buffer, expectLen); p += (expectLen / sizeof(WCHAR)); }
	*p++ = L'\0';
	*p++ = L'\0';

	RtlInitUnicodeString(&valName, L"LastClientCheck");
	ZwSetValueKey(hKey, &valName, 0, REG_MULTI_SZ, buf, (ULONG)((PUCHAR)p - (PUCHAR)buf));

	ExFreePool(buf);
	ZwClose(hKey);
}

/* =============================================================================
   NormalizeToNtPath — 把 DOS/相对形态的卷前缀归一化为 NT 设备路径

   为什么需要(2026-09-29 实测):
     调用方路径来自 SeLocateProcessImageName → NT 形态
       例: \Device\HarddiskVolume6\远控\zeta\ZETA.exe
     而驱动自身 FullDllName 是 DOS 形态
       例: \??\E:\远控\zeta\ZETA.exe
     两者直接比较永远不等 —— 这是"正向用例也被拒"的真正原因(不是推导算错)。

   处理:
     \Device\...      原样返回
     \??\X:\...       解析 \??\X: 符号链接 → \Device\HarddiskVolumeN, 再拼剩余路径
     \SystemRoot\...  解析 \SystemRoot → \Device\HarddiskVolumeN, 再拼剩余路径
   (解析卷而不是只比后缀, 是为了避免"把文件放到别的卷的同名路径"即可绕过)

   成功时 out 指向调用方提供的栈缓冲 buf, 无需释放; 失败返回 FALSE(调用方保守拒绝)。
   ============================================================================= */
#define ZETA_MAX_NT_PATH 260

static BOOLEAN PrefixEqualCI(PCWSTR a, PCWSTR lit, USHORT litChars)
{
	USHORT i;
	for (i = 0; i < litChars; i++) {
		WCHAR x = a[i], y = lit[i];
		if (x >= L'a' && x <= L'z') x = (WCHAR)(x - 32);
		if (y >= L'a' && y <= L'z') y = (WCHAR)(y - 32);
		if (x != y) return FALSE;
	}
	return TRUE;
}

static BOOLEAN NormalizeToNtPath(PCUNICODE_STRING in, PUNICODE_STRING out, PWCH buf, ULONG bufChars)
{
	UNICODE_STRING prefix, target;
	OBJECT_ATTRIBUTES oa;
	HANDLE hLink = NULL;
	USHORT chars, prefixChars = 0;

	if (!in || !in->Buffer || !out || !buf) return FALSE;
	chars = (USHORT)(in->Length / sizeof(WCHAR));
	if (chars < 3) return FALSE;

	/* 已是 NT 设备路径 */
	if (chars >= 8 && PrefixEqualCI(in->Buffer, L"\\Device\\", 8)) {
		if ((ULONG)chars + 1 > bufChars) return FALSE;
		RtlCopyMemory(buf, in->Buffer, in->Length);
		buf[chars] = L'\0';
		out->Buffer = buf; out->Length = in->Length;
		out->MaximumLength = (USHORT)((chars + 1) * sizeof(WCHAR));
		return TRUE;
	}

	if (chars >= 6 && in->Buffer[0] == L'\\' && in->Buffer[1] == L'?' && in->Buffer[2] == L'?' &&
	    in->Buffer[3] == L'\\' && in->Buffer[5] == L':') {
		prefixChars = 6;                                   /* \??\E: */
	} else if (chars >= 11 && PrefixEqualCI(in->Buffer, L"\\SystemRoot", 11)) {
		prefixChars = 11;                                  /* \SystemRoot */
	} else {
		return FALSE;
	}

	target.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, 260 * sizeof(WCHAR), 'etaZ');
	if (!target.Buffer) return FALSE;
	target.Length = 0;
	target.MaximumLength = 260 * sizeof(WCHAR);

	prefix.Buffer = in->Buffer;
	prefix.Length = (USHORT)(prefixChars * sizeof(WCHAR));
	prefix.MaximumLength = prefix.Length;
	InitializeObjectAttributes(&oa, &prefix, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	if (!NT_SUCCESS(ZwOpenSymbolicLinkObject(&hLink, GENERIC_READ, &oa))) {
		ExFreePool(target.Buffer);
		return FALSE;
	}
	if (!NT_SUCCESS(ZwQuerySymbolicLinkObject(hLink, &target, NULL))) {
		ZwClose(hLink);
		ExFreePool(target.Buffer);
		return FALSE;
	}
	ZwClose(hLink);

	{
		ULONG tChars = target.Length / sizeof(WCHAR);
		ULONG rChars = (ULONG)chars - prefixChars;
		if (tChars + rChars + 1 > bufChars) { ExFreePool(target.Buffer); return FALSE; }
		RtlCopyMemory(buf, target.Buffer, target.Length);
		RtlCopyMemory(buf + tChars, in->Buffer + prefixChars, rChars * sizeof(WCHAR));
		buf[tChars + rChars] = L'\0';
		out->Buffer = buf;
		out->Length = (USHORT)((tChars + rChars) * sizeof(WCHAR));
		out->MaximumLength = (USHORT)((tChars + rChars + 1) * sizeof(WCHAR));
	}
	ExFreePool(target.Buffer);
	return TRUE;
}

static NTSTATUS PortConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID* ConnectionPortCookie) {
 UNREFERENCED_PARAMETER(ServerPortCookie);
 UNREFERENCED_PARAMETER(ConnectionContext);
 UNREFERENCED_PARAMETER(SizeOfContext);
 UNREFERENCED_PARAMETER(ConnectionPortCookie);

 PEPROCESS callingProcess = PsGetCurrentProcess();
 PUNICODE_STRING imageName = NULL;
 NTSTATUS status = SeLocateProcessImageName(callingProcess, &imageName);
 
 if (!NT_SUCCESS(status) || !imageName || !imageName->Buffer) {
 ZETA_ERROR("PortConnect FAILED - cannot get caller image name (0x%08X)\n", status);
 if (imageName) ExFreePool(imageName);
 return STATUS_ACCESS_DENIED;
 }

 /*
    客户端身份校验: 完整路径必须等于 <安装根>\ZETA.exe。
    旧实现是 WildcardMatch(L"*\\ZETA.exe") —— 只认名字, 任何进程改名即可通过
    (实测可复现)。详见 BuildExpectedClientPath 上方说明。
 */
 BOOLEAN isAllowed = FALSE;
 ULONG   callerPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
 {
	 UNICODE_STRING expected;
	 UNICODE_STRING deriveFail;
	 RtlInitUnicodeString(&deriveFail, L"<DERIVE-FAILED>");
	 if (BuildExpectedClientPath(&expected)) {
		 /* 关键: 两侧必须同形态才能比较 —— 驱动路径是 \??\X:\... 而调用方是
		    \Device\HarddiskVolumeN\..., 故先把期望路径归一到 NT 形态。 */
		 WCHAR ntBuf[ZETA_MAX_NT_PATH];
		 UNICODE_STRING expectedNt;
		 if (NormalizeToNtPath(&expected, &expectedNt, ntBuf, ZETA_MAX_NT_PATH)) {
			 if (expectedNt.Length == imageName->Length &&
			     RtlEqualUnicodeString(&expectedNt, imageName, TRUE)) {
				 isAllowed = TRUE;
			 }
			 PortConnectDiag_Write(imageName, &expectedNt, isAllowed);
		 } else {
			 /* 归一化失败: 保守拒绝, 并把原始形态记下来便于排查 */
			 PortConnectDiag_Write(imageName, &expected, FALSE);
		 }
		 ExFreePool(expected.Buffer);
	 } else {
		 PortConnectDiag_Write(imageName, &deriveFail, FALSE);
	 }
 }

 if (!isAllowed) {
	 ZETA_WARN("PortConnect BLOCKED - caller identity mismatch (PID=%lu, Image=%wZ)\n", callerPid, imageName);
	 ExFreePool(imageName);
	 return STATUS_ACCESS_DENIED;
 }

 ExFreePool(imageName);

 KIRQL OldIrql;
 KeAcquireSpinLock(&GlobalData.PortMutex, &OldIrql);

 GlobalData.ClientPort = ClientPort;
 GlobalData.ZetaPid = callerPid;
 ObReferenceObject(callingProcess);
 GlobalData.UserProcess = callingProcess;

 ExReInitializeRundownProtection(&GlobalData.PortRundown);

 KeReleaseSpinLock(&GlobalData.PortMutex, OldIrql);

	 ZETA_INFO("PortConnect SUCCESS - ZETA.exe connected (PID=%lu)\n", callerPid);

	 // 邪门歪道：DKOM 写 EPROCESS.Protection 字段 → PPL 自保
	 // 绕过 CI 签名检查，无需 ObRegisterCallbacks
	 InitializeDkomProcessProtection();

	 // DKOM 设置驱动镜像 Flags |= 0x20，使 ObRegisterCallbacks 验证通过
	 // 原理: MmVerifyCallbackFunctionCheckFlags 检查 DriverSection->Flags & 0x20
	 NTSTATUS driverSigStatus = DkomSetDriverSignatureFlags();
	 if (NT_SUCCESS(driverSigStatus)) {
		 // 现在可以注册 ObRegisterCallbacks
		 //
		 // A/B 实验开关 (2026-10-03): ZETA_TEST_NO_OB_PROTECT=1 时跳过 Ob 注册。
		 // 依据: 创建路径上的上报(进程7006/线程7008)与 PendOperation 均已用单变量
		 //       实验排除; 剩下的"只在客户端连接后存在"的机制就是 Ob 句柄回调与
		 //       DKOM。Ob 回调是唯一能在进程/线程【句柄访问权】层改写的机制,
		 //       故优先隔离它。默认(未定义或 0)保持原行为。
#if !defined(ZETA_TEST_NO_OB_PROTECT) || (ZETA_TEST_NO_OB_PROTECT == 0)
		 NTSTATUS obStatus = InitializeProcessProtection();
		 if (NT_SUCCESS(obStatus)) {
			 ZETA_INFO("ObRegisterCallbacks registered SUCCESS\n");
			 g_DriverState.ProcessProtectionOK = TRUE;
			 g_DriverState.ProcessProtectionStatus = obStatus;
		 } else {
			 ZETA_ERROR("ObRegisterCallbacks FAILED (0x%08lX) - fallback to DKOM only\n", obStatus);
		 }
#else
		 ZETA_WARN("ObRegisterCallbacks SKIPPED - ZETA_TEST_NO_OB_PROTECT (A/B)\n");
#endif
	 } else {
		 ZETA_WARN("DkomSetDriverSignatureFlags FAILED (0x%08lX) - ObRegisterCallbacks unavailable\n",
				   driverSigStatus);
	 }

	 // 在 DKOM Flags 设置后注册 ProcessNotifyEx (需要 Flags |= 0x20)
	 // 原先在 DriverEntry 中注册，因 Flags 未设置而失败
	 if (!g_ProcessNotifyExActive) {
		 status = PsSetCreateProcessNotifyRoutineEx(ProcessCreateNotifyEx, FALSE);
		 if (NT_SUCCESS(status)) {
			 g_ProcessNotifyExActive = TRUE;
			 g_DriverState.ProcessNotifyExOK = TRUE;
			 g_DriverState.ProcessNotifyExStatus = STATUS_SUCCESS;
			 ZETA_INFO("ProcessNotifyEx registered SUCCESS (post-DKOM)\n");
		 } else {
			 g_DriverState.ProcessNotifyExStatus = status;
			 ZETA_WARN("ProcessNotifyEx FAILED (0x%08lX) even post-DKOM\n", status);
		 }
	 }

	 return STATUS_SUCCESS;
}

static VOID PortDisconnect(PVOID ConnectionCookie) {
 UNREFERENCED_PARAMETER(ConnectionCookie);

#if ZETA_ENABLE_SSDT
 // ZETA 退出: 还原 APC hook，避免无用户态决策时拦截所有可疑 APC
 ApcHook_Disable();

 // ZETA 退出: 还原 InjectHook (NtCreateThreadEx/NtWriteVirtualMemory)
 InjectHook_Disable();
#endif

 ULONG oldPid = GlobalData.ZetaPid;
 ZETA_INFO("PortDisconnect - ZETA.exe disconnected (PID=%lu)\n", oldPid);
 DriverLog(oldPid, L"PortDisconnect: ZETA.exe disconnected (PID=%lu)", oldPid);

 KIRQL OldIrql;
 KeAcquireSpinLock(&GlobalData.PortMutex, &OldIrql);

 PEPROCESS oldProcess = GlobalData.UserProcess;
 GlobalData.ClientPort = NULL;
 GlobalData.ZetaPid = 0;
 GlobalData.UserProcess = NULL;

 KeReleaseSpinLock(&GlobalData.PortMutex, OldIrql);

 ExWaitForRundownProtectionRelease(&GlobalData.PortRundown);
 
 if (oldProcess) {
 ObDereferenceObject(oldProcess);
 }

 // P0-BSOD修复(0xCE): ZETA.exe 断开时注销 OB 句柄保护回调。
 // 否则每次连接都注册一组回调且只覆盖句柄不注销, 累积的残留回调在驱动
 // 卸载后仍留在 OB 链上 → 任意 OpenProcess 执行已释放代码 → 0xCE。
 // 回调保护的是 ZETA.exe 自身进程句柄, 断开后无保留必要;
 // 下次 PortConnect 由 InitializeProcessProtection 幂等重注册。
 UninitializeProcessProtection();
 g_DriverState.ProcessProtectionOK = FALSE;
 g_DriverState.ProcessProtectionStatus = STATUS_PENDING;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
 { IRP_MJ_CREATE, 0, ProtectFile_PreCreate, NULL },
 { IRP_MJ_WRITE, 0, ProtectFile_PreWrite, NULL },
 { IRP_MJ_SET_INFORMATION, 0, ProtectFile_PreSetInfo, NULL },
 { IRP_MJ_SET_SECURITY, 0, ProtectFile_SetSecurity, NULL },
 { IRP_MJ_FILE_SYSTEM_CONTROL, 0, ProtectFile_FileSystemControl, NULL },
 { (UCHAR)0xED, 0, ProtectFile_PreSectionSync, NULL },  // IRP_MJ_ACQUIRE_FOR_SECTION_SYNC 拦截内存映射执行
 { IRP_MJ_DEVICE_CONTROL, 0, ProtectBoot_PreDeviceControl, NULL },
 { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
 sizeof(FLT_REGISTRATION),
 FLT_REGISTRATION_VERSION,
 0,
 NULL,
 Callbacks,
 DriverUnload,
 InstanceSetup,
 InstanceQueryTeardown,
 InstanceTeardownStart,
 InstanceTeardownComplete,
 NULL,
 NULL,
 NULL
};

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
 NTSTATUS status = STATUS_SUCCESS;
 PSECURITY_DESCRIPTOR sd = NULL;
 OBJECT_ATTRIBUTES oa = { 0 };
 UNICODE_STRING name = { 0 };

 ZETA_DEBUG("DriverEntry begin\n");

 RtlZeroMemory(&GlobalData, sizeof(GlobalData));
 GlobalData.DriverObject = DriverObject;
 KeInitializeMutex(&g_ObCallbackMutex, 0);   // ProtectProcess.cpp: OB 回调注册/注销串行化
 KeInitializeSpinLock(&GlobalData.PortMutex);
 KeInitializeSpinLock(&GlobalData.TrackerMutex);
 KeInitializeSpinLock(&g_SilverFoxLock);
 RtlZeroMemory(&g_SilverFoxTrackers, sizeof(g_SilverFoxTrackers));
 KeInitializeSpinLock(&g_RollbackLock);
 ZETA_DEBUG("Global data initialized\n");

 ExInitializeRundownProtection(&GlobalData.PortRundown);
 ZETA_DEBUG("Rundown protection initialized\n");

 KeInitializeEvent(&g_WorkItemTracker.CompletionEvent, SynchronizationEvent, FALSE);
 ZETA_DEBUG("WorkItemTracker event initialized\n");

 KeQuerySystemTime(&g_DriverStartTick);

	InitializeRulesEngine();
	g_DriverState.RulesEngineOK = TRUE;
	ZETA_DEBUG("Rules engine initialized\n");

	// [STEP8] Initialize pending operations queue, timeout checker, and trust window
	InitializePendingOps();
	InitializeTrustWindow();
#if ZETA_ENABLE_SSDT
	ApcHook_Init();
	InjectHook_Init();
#endif
	StartTimeoutChecker();
	ZETA_DEBUG("PendingOps, TrustWindow and TimeoutChecker initialized\n");

	ZETA_DEBUG("Registering filter...\n");
 status = FltRegisterFilter(DriverObject, &FilterRegistration, &GlobalData.FilterHandle);
 if (!NT_SUCCESS(status)) {
 ZETA_ERROR("FltRegisterFilter FAILED (0x%08X)\n", status);
 return status;
 }
 g_DriverState.FilterRegistered = TRUE;
 ZETA_INFO("Filter registered (Handle=0x%p)\n", GlobalData.FilterHandle);

 ZETA_DEBUG("Creating communication port...\n");
 status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
 if (NT_SUCCESS(status)) {
 RtlInitUnicodeString(&name, ZETA_PORT_NAME);
 InitializeObjectAttributes(&oa, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
 status = FltCreateCommunicationPort(GlobalData.FilterHandle, &GlobalData.ServerPort, &oa, NULL, PortConnect, PortDisconnect, PortMessage, 5);
 FltFreeSecurityDescriptor(sd);
 }

 if (!NT_SUCCESS(status)) {
 ZETA_ERROR("Communication port creation FAILED (0x%08X)\n", status);
 FltUnregisterFilter(GlobalData.FilterHandle);
 GlobalData.FilterHandle = NULL;
 return status;
 }
 g_DriverState.PortCreated = TRUE;
 DbgPrint("ZETA: Communication port created (Port=0x%p)\n", GlobalData.ServerPort);

 DbgPrint("ZETA: Starting filter...\n");
 status = FltStartFiltering(GlobalData.FilterHandle);
 if (!NT_SUCCESS(status)) {
 g_DriverState.AnyFailure = TRUE;
 DbgPrint("ZETA: FltStartFiltering FAILED (0x%08X) - cleaning up\n", status);

 if (GlobalData.FilterHandle) {
 FltUnregisterFilter(GlobalData.FilterHandle);
 GlobalData.FilterHandle = NULL;
 }

 return status;
 }
 g_DriverState.FilterStarted = TRUE;

 // Network monitoring is handled by ZETA_NetFilter.sys (separate WDM driver)

 status = LoadRulesFromDisk(RegistryPath);
	g_DriverState.RulesLoaded = NT_SUCCESS(status);
	if (!NT_SUCCESS(status)) {
	g_DriverState.AnyFailure = TRUE;
	ZETA_ERROR("LoadRulesFromDisk FAILED (0x%08X) - continuing without rules\n", status);
	} else {
	ZETA_INFO("Rules loaded successfully\n");
	}

	// Initialize learning whitelist
	LearningWhitelist_Init();
	ZETA_DEBUG("LearningWhitelist initialized\n");

	// Enable experimental features
	RansomExp_SetEnabled(TRUE);
	LearningMode_SetEnabled(FALSE);
	ZETA_DEBUG("Experimental features initialized\n");

	// [STEP3] Process creation notify for LineageTracker
	g_LineageTrackerEnabled = TRUE;
	g_DriverState.LineageTrackerOK = FALSE;
	status = PsSetCreateProcessNotifyRoutine(LineageTracker_OnProcessCreate, FALSE);
	if (!NT_SUCCESS(status)) {
	ZETA_ERROR("PsSetCreateProcessNotifyRoutine FAILED (0x%08X) - LineageTracker unavailable\n", status);
	g_DriverState.AnyFailure = TRUE;
	g_LineageTrackerEnabled = FALSE;
	} else {
	g_DriverState.LineageTrackerOK = TRUE;
	ZETA_INFO("Process creation notify registered for LineageTracker\n");
	}

	// [STEP3b] Process creation notify (Ex) — provides CommandLine + PPID
	g_ProcessNotifyExActive = FALSE;
	g_DriverState.ProcessNotifyExOK = FALSE;
	g_DriverState.ProcessNotifyExStatus = STATUS_NOT_SUPPORTED;
	status = PsSetCreateProcessNotifyRoutineEx(ProcessCreateNotifyEx, FALSE);
	if (!NT_SUCCESS(status)) {
	g_DriverState.ProcessNotifyExStatus = status;
	ZETA_WARN("PsSetCreateProcessNotifyRoutineEx FAILED (0x%08X) - fallback to polling\n", status);
	} else {
	g_ProcessNotifyExActive = TRUE;
	g_DriverState.ProcessNotifyExOK = TRUE;
	g_DriverState.ProcessNotifyExStatus = STATUS_SUCCESS;
	ZETA_INFO("Process creation notify (Ex) registered — command line capture active\n");
	}

	// [STEP3c] Thread creation notify — 监控线程创建（检测注入、恶意线程）
	g_ThreadNotifyActive = FALSE;
	status = PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine);
	if (!NT_SUCCESS(status)) {
	ZETA_ERROR("PsSetCreateThreadNotifyRoutine FAILED (0x%08X) - thread monitoring unavailable\n", status);
	g_DriverState.AnyFailure = TRUE;
	} else {
	g_ThreadNotifyActive = TRUE;
	ZETA_INFO("Thread notify registered\n");
	}

	// [STEP4] Image load notify
	g_ImageNotifyRegistered = FALSE;
	g_DriverState.ImageNotifyOK = FALSE;
	status = PsSetLoadImageNotifyRoutine(ImageLoadNotify);
	if (!NT_SUCCESS(status)) {
	ZETA_ERROR("PsSetLoadImageNotifyRoutine FAILED (0x%08X)\n", status);
	g_DriverState.AnyFailure = TRUE;
	} else {
	g_ImageNotifyRegistered = TRUE;
	g_DriverState.ImageNotifyOK = TRUE;
	ZETA_INFO("Image load notify registered\n");
	}

	// [STEP5] Process protection via DKOM (邪门歪道: EPROCESS 直接写 PPL)
	// ObRegisterCallbacks 因测试签名等级不够被禁用。替代方案:
	// 直接写 EPROCESS.Protection 字段为 PPL Antimalware (0x0A)
	// 在 PortConnect 中调用 InitializeDkomProcessProtection()
	// 此处在 DriverEntry 阶段仅标记状态
	g_DriverState.ProcessProtectionOK = FALSE;
	g_DriverState.ProcessProtectionStatus = STATUS_PENDING;
	ZETA_INFO("Process protection DEFERRED to PortConnect (DKOM PPL)\n");

	// [STEP6] Registry protection via CmRegisterCallbackEx
	g_DriverState.RegistryProtectionOK = FALSE;
	status = InitializeRegistryProtection(DriverObject);
	if (!NT_SUCCESS(status)) {
	g_DriverState.AnyFailure = TRUE;
	ZETA_ERROR("InitializeRegistryProtection FAILED (0x%08X)\n", status);
	} else {
	g_DriverState.RegistryProtectionOK = TRUE;
	ZETA_INFO("Registry protection initialized successfully\n");
	}

	// [STEP8] (WDM DiskFilter moved to separate ZETA_DiskFilter.sys)
	// Disable audit ring buffer allocation (~3MB non-paged pool) for now
	// Initialize audit ring buffer
	//InitializeAuditRing();

	DbgPrint("ZETA: DriverEntry SUCCESS - filter is now active\n");
 return status;
}

