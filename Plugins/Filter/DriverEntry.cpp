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
        if (totalBytes > sizeof(WCHAR)) {
            SendMessageToUser(ZETA_MSG_PROCESS_CREATE, pid, buf, totalBytes);
        }
    }
    else {
        // P2-15: Process exit (CreateInfo == NULL) — notify user-mode for cleanup/logging
        SendMessageToUser(ZETA_MSG_PROCESS_EXIT, pid, L"exit", 10);
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
    WCHAR buf[64];
    if (isRemoteThread) {
        NTSTATUS len = RtlStringCbPrintfW(buf, sizeof(buf), L"%lu,%lu,R,%lu",
            pid, (ULONG)(ULONG_PTR)ThreadId, (ULONG)(ULONG_PTR)creatorPid);
        if (NT_SUCCESS(len)) {
            SendMessageToUser(ZETA_MSG_THREAD_CREATE, pid, buf, (USHORT)(wcslen(buf) * sizeof(WCHAR)));
        }
    } else {
        NTSTATUS len = RtlStringCbPrintfW(buf, sizeof(buf), L"%lu,%lu",
            pid, (ULONG)(ULONG_PTR)ThreadId);
        if (NT_SUCCESS(len)) {
            SendMessageToUser(ZETA_MSG_THREAD_CREATE, pid, buf, (USHORT)(wcslen(buf) * sizeof(WCHAR)));
        }
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

static NTSTATUS DriverUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
 UNREFERENCED_PARAMETER(Flags);

 DbgPrint("ZETA: DriverUnload: begin\n");

 // 1. Set unload flag
 g_IsUnloading = TRUE;

 // 1b. Restore SSDT APC hook BEFORE the image can be unmapped
 ApcHook_Disable();
 DbgPrint("ZETA: DriverUnload: APC hook disabled\n");

 // 1c. Restore UnloadGuard SSDT hook (NtUnloadDriver) before image unmap
 UnloadGuard_Disable();
 DbgPrint("ZETA: DriverUnload: UnloadGuard disabled\n");

 // 1d. Restore InjectHook SSDT (NtCreateThreadEx/NtWriteVirtualMemory) before unmap
 InjectHook_Disable();
 DbgPrint("ZETA: DriverUnload: InjectHook disabled\n");

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

  // APC hook: 完成挂起的 NtQueueApcThread 决策 (源进程)
  CompletePendingApc(targetPid, msg->Command == ZETA_CMD_ALLOW_OP);

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
    NTSTATUS hookStatus = ApcHook_Enable(apcSysno, validateSysno);
    ZETA_INFO("APC hook cmd: apc=%lu validate=%lu status=0x%08X\n",
              apcSysno, validateSysno, hookStatus);
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
    NTSTATUS guardStatus = UnloadGuard_Enable(unloadSysno, validateSysno);
    ZETA_INFO("UnloadGuard cmd: unload=%lu validate=%lu status=0x%08X\n",
              unloadSysno, validateSysno, guardStatus);
    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
    return STATUS_SUCCESS;
 }

 if (msg->Command == ZETA_CMD_SET_INJECT_HOOK) {
    // Path = "CreateThreadSysno,WriteMemSysno,ValidateSysno" (用户态从 ntdll stub 解析)
    ULONG ctSysno = 0, wmSysno = 0, validateSysno = 0;
    PCWSTR p = msg->Path;
    while (*p && *p >= L'0' && *p <= L'9') { ctSysno = ctSysno * 10 + (ULONG)(*p - L'0'); p++; }
    if (*p == L',') {
        p++;
        while (*p && *p >= L'0' && *p <= L'9') { wmSysno = wmSysno * 10 + (ULONG)(*p - L'0'); p++; }
    }
    if (*p == L',') {
        p++;
        while (*p && *p >= L'0' && *p <= L'9') { validateSysno = validateSysno * 10 + (ULONG)(*p - L'0'); p++; }
    }
    NTSTATUS hookStatus = InjectHook_Enable(ctSysno, wmSysno, validateSysno);
    ZETA_INFO("InjectHook cmd: ct=%lu wm=%lu validate=%lu status=0x%08X\n",
              ctSysno, wmSysno, validateSysno, hookStatus);
    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
    return STATUS_SUCCESS;
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

 BOOLEAN isAllowed = WildcardMatch(L"*\\ZETA.exe", imageName->Buffer, imageName->Length);
 ULONG callerPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

 if (!isAllowed) {
 ZETA_WARN("PortConnect BLOCKED - caller is not ZETA.exe (PID=%lu, Image=%wZ)\n", callerPid, imageName);
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
		 NTSTATUS obStatus = InitializeProcessProtection();
		 if (NT_SUCCESS(obStatus)) {
			 ZETA_INFO("ObRegisterCallbacks registered SUCCESS\n");
			 g_DriverState.ProcessProtectionOK = TRUE;
			 g_DriverState.ProcessProtectionStatus = obStatus;
		 } else {
			 ZETA_ERROR("ObRegisterCallbacks FAILED (0x%08lX) - fallback to DKOM only\n", obStatus);
		 }
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

 // ZETA 退出: 还原 APC hook，避免无用户态决策时拦截所有可疑 APC
 ApcHook_Disable();

 // ZETA 退出: 还原 InjectHook (NtCreateThreadEx/NtWriteVirtualMemory)
 InjectHook_Disable();

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
	ApcHook_Init();
	InjectHook_Init();
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

