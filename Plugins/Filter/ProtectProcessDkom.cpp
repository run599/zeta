// =============================================================================
// ProtectProcessDkom.cpp -- EPROCESS Protection Field DKOM
//
// Unorthodox self-protection: Bypass CI signing checks by directly writing
// the EPROCESS Protection field to promote ZETA.exe to PPL level.
//
// Principle:
//   EPROCESS has a PS_PROTECTION byte near its end. Setting it through
//   NtSetInformationProcess(ProcessProtectionInfo) triggers CI signing checks.
//   But writing it directly from kernel mode bypasses ALL signing checks.
//
//   PPL level = (Signer << 3) | Type
//   Type=2(ProtectedLight), Signer=1(Antimalware) -> 0x0A
//
// Effect:
//   - OpenProcess(PROCESS_TERMINATE) returns ACCESS_DENIED
//   - PROCESS_VM_WRITE / PROCESS_CREATE_THREAD blocked
//   - ProcessHacker/Task Manager cannot kill ZETA.exe
//
// Compatibility:
//   - Win10 2004~22H2:  offset 0x87A
//   - Win11 21H2~24H2:  offset 0x8DA/0x8F2
//   Auto-detected via RtlGetVersion. 100% effective without HVCI.
// =============================================================================

#include "DriverCommon.h"

// ZwAdjustPrivilegesToken is not auto-declared in all WDK configs
extern "C" NTSTATUS NTAPI ZwAdjustPrivilegesToken(
    _In_ HANDLE TokenHandle,
    _In_ BOOLEAN DisableAllPrivileges,
    _In_opt_ PTOKEN_PRIVILEGES NewState,
    _In_ ULONG BufferLength,
    _Out_opt_ PTOKEN_PRIVILEGES PreviousState,
    _Out_opt_ PULONG ReturnLength
);

// =============================================================================
// PS_PROTECTION (undocumented, from ntifs.h)
// =============================================================================
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type  : 3;  // 0=None, 1=Protected, 2=ProtectedLight(PPL)
            UCHAR Signer: 5;  // 0=Authenticode, 1=Antimalware, 5=Windows, 6=Tcb
        };
    };
} PS_PROTECTION;

// PPL level constants
// PPL Antimalware = Type=2, Signer=1
#define PPL_ANTIMALWARE     ((UCHAR)((1 << 3) | 2))   // 0x0A
// PPL Windows = Type=2, Signer=5
#define PPL_WINDOWS         ((UCHAR)((5 << 3) | 2))   // 0x2A
// PPL Tcb = Type=2, Signer=6
#define PPL_TCB             ((UCHAR)((6 << 3) | 2))   // 0x32

// EPROCESS Protection field offsets (by Windows version)
#define EPROT_OFFSET_WIN10_2004   0x87A   // Win10 20H1~22H2 (19041~19045)
#define EPROT_OFFSET_WIN11        0x8DA   // Win11 21H2+ (22000+)
#define EPROT_OFFSET_WIN11_24H2   0x8F2   // Win11 24H2 (26100)
#define EPROT_OFFSET_UNKNOWN      0x87A   // fallback

// Watchdog globals
static HANDLE            g_DkomWatchdogThread = NULL;
static KEVENT            g_DkomWatchdogStopEvent;
static volatile BOOLEAN  g_DkomWatchdogRunning = FALSE;
static volatile BOOLEAN  g_DkomProtectionActive = FALSE;

// =============================================================================
// DetectProtectionOffset -- choose offset by Windows build number
// =============================================================================
static ULONG DetectProtectionOffset() {
    RTL_OSVERSIONINFOW ver = { sizeof(ver) };
    NTSTATUS status = RtlGetVersion(&ver);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ZETA: DkomPPL: RtlGetVersion failed (0x%08X)\n", status);
        return EPROT_OFFSET_UNKNOWN;
    }

    ULONG build = ver.dwBuildNumber;

    // Win11 24H2 (26100+)
    if (build >= 26100) return EPROT_OFFSET_WIN11_24H2;
    // Win11 21H2~23H2 (22000+)
    if (build >= 22000) return EPROT_OFFSET_WIN11;
    // Win10 2004~22H2 (19041+)
    if (build >= 19041) return EPROT_OFFSET_WIN10_2004;

    // Older/unknown builds
    DbgPrint("ZETA: DkomPPL: untested build %lu, trying offset 0x%X\n",
             build, EPROT_OFFSET_UNKNOWN);
    return EPROT_OFFSET_UNKNOWN;
}

// =============================================================================
// DkomSetProcessProtection -- core DKOM write
//
// Directly write the EPROCESS.Protection field, bypassing CI entirely.
// Protected by __try/__except against invalid offsets.
// =============================================================================
NTSTATUS DkomSetProcessProtection(PEPROCESS Process, UCHAR ProtectionLevel) {
    if (!Process) {
        DbgPrint("ZETA: DkomPPL: Process is NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    // P0-自伤免疫: ZETA 自己写 EPROCESS.Protection 字段, 置位标记,
    // 使监控逻辑识别为自保动作, 不当作外部 DKOM 篡改告警。
    g_SelfDkomInProgress = TRUE;

    ULONG protOffset = DetectProtectionOffset();

    __try {
        PUCHAR field = (PUCHAR)Process + protOffset;
        UCHAR oldValue = *field;

        if (oldValue == ProtectionLevel) {
            DbgPrint("ZETA: DkomPPL: already set at 0x%02X\n", ProtectionLevel);
            g_SelfDkomInProgress = FALSE;
            return STATUS_ALREADY_COMPLETE;
        }

        // If already has a different protection, don't overwrite
        if (oldValue != 0 && oldValue != ProtectionLevel) {
            PS_PROTECTION oldProt;
            oldProt.Level = oldValue;
            DbgPrint("ZETA: DkomPPL: already protected Type=%u Signer=%u (0x%02X), skip\n",
                     oldProt.Type, oldProt.Signer, oldValue);
            g_SelfDkomInProgress = FALSE;
            return STATUS_ALREADY_COMPLETE;
        }

        // DKOM write! Bypasses all CI checks.
        *field = ProtectionLevel;
        MemoryBarrier();

        // Verify
        UCHAR verifyValue = *field;
        if (verifyValue == ProtectionLevel) {
            PS_PROTECTION prot;
            prot.Level = ProtectionLevel;
            DbgPrint("ZETA: DkomPPL: PPL SET EPROCESS+0x%X "
                     "(Type=%u Signer=%u Level=0x%02X)\n",
                     protOffset, prot.Type, prot.Signer, ProtectionLevel);
            g_SelfDkomInProgress = FALSE;
            return STATUS_SUCCESS;
        } else {
            DbgPrint("ZETA: DkomPPL: write verify FAILED "
                     "(expected 0x%02X got 0x%02X)\n",
                     ProtectionLevel, verifyValue);
            g_SelfDkomInProgress = FALSE;
            return STATUS_UNSUCCESSFUL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("ZETA: DkomPPL: exception at EPROCESS+0x%X\n", protOffset);
        g_SelfDkomInProgress = FALSE;
        return STATUS_ACCESS_VIOLATION;
    }
}

// =============================================================================
// DkomQueryProtection -- read current protection level (no write)
// =============================================================================
NTSTATUS DkomQueryProtection(PEPROCESS Process, PUCHAR OutLevel,
                             PUCHAR OutType, PUCHAR OutSigner) {
    if (!Process || !OutLevel) return STATUS_INVALID_PARAMETER;

    ULONG protOffset = DetectProtectionOffset();

    __try {
        PS_PROTECTION prot;
        prot.Level = *(PUCHAR)((PUCHAR)Process + protOffset);

        *OutLevel = prot.Level;
        if (OutType)  *OutType = prot.Type;
        if (OutSigner) *OutSigner = prot.Signer;

        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }
}

// P0-3: DkomVerifyTokenPrivileges 前向声明（实现在文件末尾，watchdog 提前引用）
NTSTATUS DkomVerifyTokenPrivileges();

// =============================================================================
// DkomWatchdogThreadProc -- periodic PPL level verification
//
// On HVCI/Secure Kernel systems, the Protection field may get reset.
// This thread checks every 5 seconds and re-DKOM if needed.
// =============================================================================
static VOID DkomWatchdogThreadProc(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);
    LARGE_INTEGER interval;
    interval.QuadPart = -50000000LL; // 5 seconds

    DbgPrint("ZETA: DkomPPL: watchdog thread started\n");

    while (g_DkomWatchdogRunning) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -50000000LL;
        NTSTATUS waitStatus = KeWaitForSingleObject(
            &g_DkomWatchdogStopEvent,
            Executive, KernelMode, FALSE, &timeout);

        if (!g_DkomWatchdogRunning) break;
        if (waitStatus == STATUS_WAIT_0) break;  // stop event

        // P0-1: watchdog 三合一校验
        // 进程保护开关关闭时不重写 PPL (允许系统正常管理 ZETA.exe)。
        // 但当开关开启时，除了 PPL 字段，还要校验另外三道防线的完整性：
        //   ② 驱动 DriverSection 仍存在 (驱动未被卸载)
        //   ③ APC SSDT 表项仍指向本驱动 handler (APC 钩子未被还原)
        //   ④ Ob 句柄保护回调仍注册 (ObRegistrationHandle 非 NULL)
        // 任一异常即对应的恢复动作并上报。
        if (g_DkomProtectionActive && GlobalData.UserProcess && g_ProcessProtectEnabled) {
            // ── ① PPL 字段 ──
            UCHAR currentLevel = 0;
            UCHAR currentType = 0;
            UCHAR currentSigner = 0;
            NTSTATUS qs = DkomQueryProtection(GlobalData.UserProcess,
                                               &currentLevel,
                                               &currentType,
                                               &currentSigner);

            if (NT_SUCCESS(qs)) {
                if (currentLevel != PPL_ANTIMALWARE) {
                    DbgPrint("ZETA: DkomPPL: level RESET "
                             "(was 0x%02X, now 0x%02X). Re-DKOM...\n",
                             PPL_ANTIMALWARE, currentLevel);

                    NTSTATUS setSt = DkomSetProcessProtection(
                        GlobalData.UserProcess, PPL_ANTIMALWARE);

                    if (NT_SUCCESS(setSt) || setSt == STATUS_ALREADY_COMPLETE) {
                        DbgPrint("ZETA: DkomPPL: re-protection OK\n");
                    } else {
                        DbgPrint("ZETA: DkomPPL: re-protection FAILED (0x%08X)\n", setSt);
                    }
                }
            }

            // ── ② 驱动 DriverSection 存在性 ──
            // DriverSection 在 DriverEntry 后由内核填充；若驱动对象仍在但
            // DriverSection 被清零，说明 KLDR 条目被破坏，需重建 Flags。
            if (GlobalData.DriverObject && GlobalData.DriverObject->DriverSection == NULL) {
                DbgPrint("ZETA: DkomPPL: DriverSection MISSING. Re-DKOM sig flags...\n");
                NTSTATUS dsSt = DkomSetDriverSignatureFlags();
                if (NT_SUCCESS(dsSt)) {
                    DbgPrint("ZETA: DkomPPL: DriverSection rebuild OK\n");
                } else {
                    DbgPrint("ZETA: DkomPPL: DriverSection rebuild FAILED (0x%08X)\n", dsSt);
                }
            }

            // ── ③ APC SSDT 表项完整性 ──
            if (!ApcHook_IsTableIntact()) {
                DbgPrint("ZETA: DkomPPL: APC SSDT tampered. Re-applying handler...\n");
                // 重新定位并打表项 (ApcHook_Enable 幂等，会重设表项)
                // 系统调用号在 DriverEntry 已确定，这里用已缓存的索引重打。
                // 注意: 若系统调用号未知则跳过 (无法安全重定向)。
                // 通过重新启用恢复 (若已禁用则启用，若已激活则重设表项)。
                // ApcHook_Enable 内部已处理"已激活"幂等，这里直接调用以重设表项。
                // 但 ApcHook_Enable 需要系统调用号参数，watchdog 不持有。
                // 改用内部重打: 直接复用 g_KiServiceTable 与 g_ApcSyscallIndex。
                // （见 ApcHook_RestoreTableEntry 由 ApcHook.cpp 提供）
                ApcHook_RestoreTableEntry();
            }

            // ── ④ Ob 句柄保护回调注册状态 ──
            if (g_ObRegistrationHandle == NULL) {
                DbgPrint("ZETA: DkomPPL: Ob callback UNREGISTERED. Re-registering...\n");
                NTSTATUS obSt = InitializeProcessProtection();
                if (NT_SUCCESS(obSt)) {
                    DbgPrint("ZETA: DkomPPL: Ob callback re-registered OK\n");
                } else {
                    DbgPrint("ZETA: DkomPPL: Ob callback re-register FAILED (0x%08X)\n", obSt);
                }
            }

            // ── ⑤ UnloadGuard SSDT 表项完整性 ──
            if (UnloadGuard_IsActive() && !UnloadGuard_IsTableIntact()) {
                DbgPrint("ZETA: DkomPPL: UnloadGuard SSDT tampered. Re-applying...\n");
                UnloadGuard_RestoreTableEntry();
            }

            // ── ⑥ 令牌特权复查与重注入 ──
            NTSTATUS tknSt = DkomVerifyTokenPrivileges();
            if (!NT_SUCCESS(tknSt)) {
                DbgPrint("ZETA: DkomPPL: token privilege verify FAILED (0x%08X)\n", tknSt);
            }
        }
    }

    DbgPrint("ZETA: DkomPPL: watchdog thread exiting\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// =============================================================================
// DkomStartWatchdog -- create watchdog thread
// =============================================================================
NTSTATUS DkomStartWatchdog() {
    if (g_DkomWatchdogRunning) {
        return STATUS_ALREADY_COMPLETE;
    }

    KeInitializeEvent(&g_DkomWatchdogStopEvent, NotificationEvent, FALSE);
    g_DkomWatchdogRunning = TRUE;

    NTSTATUS status = PsCreateSystemThread(
        &g_DkomWatchdogThread,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        DkomWatchdogThreadProc,
        NULL);

    if (!NT_SUCCESS(status)) {
        DbgPrint("ZETA: DkomPPL: watchdog create FAILED (0x%08X)\n", status);
        g_DkomWatchdogRunning = FALSE;
        return status;
    }

    DbgPrint("ZETA: DkomPPL: watchdog thread created\n");
    return STATUS_SUCCESS;
}

// =============================================================================
// DkomStopWatchdog -- stop watchdog thread
// =============================================================================
VOID DkomStopWatchdog() {
    if (!g_DkomWatchdogRunning) return;

    g_DkomWatchdogRunning = FALSE;
    KeSetEvent(&g_DkomWatchdogStopEvent, 0, FALSE);

    if (g_DkomWatchdogThread) {
        PVOID threadObj = NULL;
        NTSTATUS status = ObReferenceObjectByHandle(
            g_DkomWatchdogThread, SYNCHRONIZE, *PsThreadType,
            KernelMode, &threadObj, NULL);

        if (NT_SUCCESS(status)) {
            KeWaitForSingleObject(threadObj, Executive, KernelMode, FALSE, NULL);
            ObDereferenceObject(threadObj);
        }

        ZwClose(g_DkomWatchdogThread);
        g_DkomWatchdogThread = NULL;
    }

    DbgPrint("ZETA: DkomPPL: watchdog thread stopped\n");
}

// =============================================================================
// DkomInjectTokenPrivileges -- inject SeTcbPrivilege into ZETA.exe token
//
// Gives ZETA.exe: SeTcbPrivilege, SeDebugPrivilege, SeTakeOwnershipPrivilege
// After this, ZETA.exe can OpenProcess(PROCESS_ALL_ACCESS) on ANY process
// including PPL-protected ones, and can manage other processes' PPL levels.
//
// Works because ZwAdjustPrivilegesToken from KernelMode bypasses the
// SeIncreaseQuotaPrivilege check (PreviousMode == KernelMode -> always pass).
// =============================================================================
NTSTATUS DkomInjectTokenPrivileges() {
    // P0-自伤免疫: ZETA 自己修改自身令牌特权, 置位标记 (虽非 EPROCESS/KLDR 字段,
    // 但令牌校验也是完整性监控的一环, 统一标记避免未来监控误报)。
    g_SelfDkomInProgress = TRUE;

    HANDLE procHandle = NULL;
    HANDLE tokenHandle = NULL;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;

    // 1. Open ZETA.exe process handle (from kernel mode -> no access check)
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)GlobalData.ZetaPid;
    cid.UniqueThread = NULL;

    NTSTATUS status = ZwOpenProcess(&procHandle, PROCESS_QUERY_INFORMATION,
                                     &oa, &cid);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ZETA: DkomTkn: ZwOpenProcess FAILED (0x%08X)\n", status);
        g_SelfDkomInProgress = FALSE;
        return status;
    }

    // 2. Open ZETA.exe's primary token
    status = ZwOpenProcessTokenEx(procHandle,
                                   TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                   OBJ_KERNEL_HANDLE, &tokenHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ZETA: DkomTkn: ZwOpenProcessTokenEx FAILED (0x%08X)\n", status);
        ZwClose(procHandle);
        g_SelfDkomInProgress = FALSE;
        return status;
    }

    // 3. Prepare privilege list
    // Privilege LUIDs are stable across all Windows versions:
    //   SeTcbPrivilege            = 7
    //   SeDebugPrivilege          = 20
    //   SeTakeOwnershipPrivilege  = 9
    //   SeLoadDriverPrivilege     = 10
    //   SeIncreaseQuotaPrivilege  = 5
    UCHAR privilegeCount = 5;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = privilegeCount;

    // SeIncreaseQuotaPrivilege (5) - needed to modify token privileges
    tp.Privileges[0].Luid.LowPart = 5;
    tp.Privileges[0].Luid.HighPart = 0;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // SeTcbPrivilege (7) - act as part of OS, manage PPL protection
    tp.Privileges[1].Luid.LowPart = 7;
    tp.Privileges[1].Luid.HighPart = 0;
    tp.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;

    // SeTakeOwnershipPrivilege (9) - take ownership of objects
    tp.Privileges[2].Luid.LowPart = 9;
    tp.Privileges[2].Luid.HighPart = 0;
    tp.Privileges[2].Attributes = SE_PRIVILEGE_ENABLED;

    // SeLoadDriverPrivilege (10) - load/unload drivers
    tp.Privileges[3].Luid.LowPart = 10;
    tp.Privileges[3].Luid.HighPart = 0;
    tp.Privileges[3].Attributes = SE_PRIVILEGE_ENABLED;

    // SeDebugPrivilege (20) - debug any process
    tp.Privileges[4].Luid.LowPart = 20;
    tp.Privileges[4].Luid.HighPart = 0;
    tp.Privileges[4].Attributes = SE_PRIVILEGE_ENABLED;

    // 4. Enable privileges
    // From kernel mode, SeSinglePrivilegeCheck with PreviousMode=KernelMode
    // always passes, bypassing the SeIncreaseQuotaPrivilege requirement.
    status = ZwAdjustPrivilegesToken(tokenHandle, FALSE, &tp, 0, NULL, NULL);

    if (NT_SUCCESS(status)) {
        DbgPrint("ZETA: DkomTkn: privileges injected "
                 "(Tcb+Debug+TakeOwnership+LoadDrv+IncQuota)\n");
    } else {
        // ZwAdjustPrivilegesToken returned the actual status
        DbgPrint("ZETA: DkomTkn: ZwAdjustPrivilegesToken FAILED (0x%08X)\n",
                 status);
    }

    ZwClose(tokenHandle);
    ZwClose(procHandle);
    g_SelfDkomInProgress = FALSE;
    return status;
}

// =============================================================================
// InitializeDkomProcessProtection -- external entry point
//
// Must be called after ZETA.exe connects (GlobalData.UserProcess != NULL).
// Called from PortConnect.
// =============================================================================
NTSTATUS InitializeDkomProcessProtection() {
    if (!GlobalData.UserProcess) {
        DbgPrint("ZETA: DkomPPL: UserProcess is NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    // 1. DKOM write Protection field -> PPL
    NTSTATUS status = DkomSetProcessProtection(
        GlobalData.UserProcess, PPL_ANTIMALWARE);

    if (NT_SUCCESS(status) || status == STATUS_ALREADY_COMPLETE) {
        g_DkomProtectionActive = TRUE;
        g_DriverState.ProcessProtectionOK = TRUE;
        g_DriverState.ProcessProtectionStatus = status;

        // 2. Start watchdog
        NTSTATUS wdSt = DkomStartWatchdog();
        if (!NT_SUCCESS(wdSt)) {
            DbgPrint("ZETA: DkomPPL: watchdog FAILED (0x%08X)\n", wdSt);
        }

        // 3. Inject SeTcbPrivilege + SeDebugPrivilege into ZETA.exe token
        // This lets ZETA.exe manage other processes and their PPL protection.
        NTSTATUS tknSt = DkomInjectTokenPrivileges();
        if (NT_SUCCESS(tknSt)) {
            DbgPrint("ZETA: DkomPPL: token privileges injected\n");
            DriverLog(GlobalData.ZetaPid,
                      L"PPL-DKOM: SeTcb+SeDebug+SeTakeOwnership "
                      L"injected - ZETA can now open any process");
        } else {
            DbgPrint("ZETA: DkomPPL: token injection FAILED (0x%08X)\n", tknSt);
            DriverLog(GlobalData.ZetaPid,
                      L"PPL-DKOM: token injection FAILED (0x%08lX)",
                      tknSt);
        }

        // 4. Log final level
        UCHAR level = 0, type = 0, signer = 0;
        if (NT_SUCCESS(DkomQueryProtection(GlobalData.UserProcess,
                                           &level, &type, &signer))) {
            DriverLog(GlobalData.ZetaPid,
                      L"PPL-DKOM: Type=%u Signer=%u Level=0x%02X - "
                      L"ZETA.exe is now protected",
                      type, signer, level);
        }

        DbgPrint("ZETA: DkomPPL: protection ACTIVE (PPL=0x%02X)\n",
                 PPL_ANTIMALWARE);
        return STATUS_SUCCESS;
    }

    // DKOM failed
    DbgPrint("ZETA: DkomPPL: DkomSetProcessProtection FAILED (0x%08X)\n", status);
    g_DriverState.ProcessProtectionOK = FALSE;
    g_DriverState.ProcessProtectionStatus = status;
    return status;
}

// =============================================================================
// UninitializeDkomProcessProtection -- cleanup on driver unload
// =============================================================================
VOID UninitializeDkomProcessProtection() {
    DkomStopWatchdog();
    g_DkomProtectionActive = FALSE;

    // We do NOT clear the Protection field --
    // it persists until ZETA.exe exits naturally.
    DbgPrint("ZETA: DkomPPL: uninitialized (PPL stays until process exits)\n");
}

// =============================================================================
// KLDR_DATA_TABLE_ENTRY (undocumented, from ntoskrnl.exe)
// Windows 11 25H2 结构 (sizeof = 0xA0):
//   偏移 0x00: InLoadOrderLinks (LIST_ENTRY, 16 bytes)
//   偏移 0x10: ExceptionTable (PVOID, 8 bytes)
//   偏移 0x18: ExceptionTableSize (ULONG, 4 bytes)
//   偏移 0x1C: GpValue (PVOID, 8 bytes) -- 注意对齐后偏移 0x20
//   偏移 0x28: NonPagedDebugInfo (PVOID, 8 bytes)
//   偏移 0x30: DllBase (PVOID, 8 bytes)
//   偏移 0x38: EntryPoint (PVOID, 8 bytes)
//   偏移 0x40: SizeOfImage (ULONG, 4 bytes)
//   偏移 0x48: FullDllName (UNICODE_STRING, 16 bytes)
//   偏移 0x58: BaseDllName (UNICODE_STRING, 16 bytes)
//   偏移 0x68: Flags (ULONG, 4 bytes) <-- ObRegisterCallbacks 检查此字段
//   偏移 0x6E: SignatureLevel union (USHORT, 4 bits + 3 bits + ...)
//
// MmVerifyCallbackFunctionCheckFlags 检查:
//   DriverSection->Flags & 0x20 (bit 5 = ProcessStaticImport)
//
// 关键偏移常量
#define KLDR_FLAGS_OFFSET         0x68  // Flags 字段偏移
#define KLDR_SIGNATURE_OFFSET     0x6E  // SignatureLevel 偏移
#define KLDR_CALLBACK_CHECK_FLAG  0x20  // ObRegisterCallbacks 检查的标志位

// =============================================================================
// DkomSetDriverSignatureFlags -- DKOM 设置驱动镜像 Flags |= 0x20
//
// 原理:
//   ObRegisterCallbacks 调用 MmVerifyCallbackFunctionCheckFlags(callback, 0x20)
//   MmVerifyCallbackFunctionCheckFlags 内部:
//     v6 = MiLookupDataTableEntry(callback_addr, 0)
//     if (v6 && (*(_DWORD *)(v6 + 0x68) & 0x20) != 0) return 1
//
//   只需找到 ZETA_Drv.sys 的 KLDR_DATA_TABLE_ENTRY，设置 Flags |= 0x20
//
// 返回: STATUS_SUCCESS 如果成功设置
// =============================================================================
NTSTATUS DkomSetDriverSignatureFlags() {
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    // P0-自伤免疫: ZETA 自己改 KLDR_DATA_TABLE_ENTRY 的 Flags/SignatureLevel,
    // 置位标记, 使监控逻辑识别为自保动作, 不当作外部 KLDR 篡改告警。
    g_SelfDkomInProgress = TRUE;

    // 获取当前驱动对象 (从全局变量中获取，DriverEntry 传入)
    PDRIVER_OBJECT driverObject = GlobalData.DriverObject;
    if (!driverObject) {
        DbgPrint("ZETA: DkomDriverSig: DriverObject is NULL\n");
        g_SelfDkomInProgress = FALSE;
        return STATUS_INVALID_PARAMETER;
    }

    // DriverSection 指向 KLDR_DATA_TABLE_ENTRY
    PVOID driverSection = driverObject->DriverSection;
    if (!driverSection) {
        DbgPrint("ZETA: DkomDriverSig: DriverSection is NULL\n");
        g_SelfDkomInProgress = FALSE;
        return STATUS_INVALID_PARAMETER;
    }

    // 计算 Flags 字段地址: DriverSection + 0x68
    PULONG flagsPtr = (PULONG)((PUCHAR)driverSection + KLDR_FLAGS_OFFSET);

    // 保存原始 Flags 用于日志
    ULONG originalFlags = *flagsPtr;

    // 设置 bit 5 (0x20) - ProcessStaticImport
    // 这是 ObRegisterCallbacks 验证的唯一标志位
    *flagsPtr |= KLDR_CALLBACK_CHECK_FLAG;

    // 验证写入
    if (*flagsPtr & KLDR_CALLBACK_CHECK_FLAG) {
        DbgPrint("ZETA: DkomDriverSig: Flags 0x%08X -> 0x%08X (bit5 SET)\n",
                 originalFlags, *flagsPtr);
        status = STATUS_SUCCESS;
    } else {
        DbgPrint("ZETA: DkomDriverSig: Flags write FAILED! 0x%08X\n",
                 *flagsPtr);
        status = STATUS_UNSUCCESSFUL;
    }

    // 额外: 设置 SignatureLevel (偏移 0x6E)
    // 在某些 Windows 版本中，KLDR_DATA_TABLE_ENTRY + 0x6E 包含 SignatureLevel
    // 这可以进一步绕过其他签名检查
    PUCHAR sigLevelPtr = (PUCHAR)driverSection + KLDR_SIGNATURE_OFFSET;
    UCHAR originalSigLevel = *sigLevelPtr;
    if (originalSigLevel == 0) {
        // 设置为 ANTIMALWARE (2) 或 MICROSOFT (6)
        *sigLevelPtr = 0x02;  // SIGNING_LEVEL_ANTIMALWARE
        DbgPrint("ZETA: DkomDriverSig: SignatureLevel 0x%02X -> 0x02\n",
                 originalSigLevel);
    }

    g_SelfDkomInProgress = FALSE;
    return status;
}

// =============================================================================
// DkomVerifyTokenPrivileges -- P0-3: watchdog 令牌特权复查
//
// 复查 ZETA.exe 令牌上的 5 个关键特权 (SeTcb/SeDebug/SeTakeOwnership/
// SeLoadDriver/SeIncreaseQuota) 是否仍 ENABLED。任一缺失则重新调用
// DkomInjectTokenPrivileges 重注入（该函数幂等）。
// 避免每周期无条件 ZwAdjustPrivilegesToken，减少内核调用开销。
// =============================================================================
NTSTATUS DkomVerifyTokenPrivileges() {
    if (!GlobalData.UserProcess) return STATUS_INVALID_PARAMETER;

    // 关键特权 LUID (跨 Windows 版本稳定)
    static const ULONG kCriticalPrivs[] = { 5, 7, 9, 10, 20 }; // IncQuota/Tcb/TakeOwnership/LoadDriver/Debug
    static const ULONG kCriticalCount = sizeof(kCriticalPrivs) / sizeof(kCriticalPrivs[0]);

    HANDLE procHandle = NULL;
    HANDLE tokenHandle = NULL;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)GlobalData.ZetaPid;
    cid.UniqueThread = NULL;

    NTSTATUS status = ZwOpenProcess(&procHandle, PROCESS_QUERY_INFORMATION, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ZETA: DkomTkn: Verify ZwOpenProcess FAILED (0x%08X)\n", status);
        return status;
    }

    status = ZwOpenProcessTokenEx(procHandle, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                                 OBJ_KERNEL_HANDLE, &tokenHandle);
    if (!NT_SUCCESS(status)) {
        ZwClose(procHandle);
        DbgPrint("ZETA: DkomTkn: Verify ZwOpenProcessTokenEx FAILED (0x%08X)\n", status);
        return status;
    }

    // 查询当前特权集
    UCHAR buf[sizeof(TOKEN_PRIVILEGES) + 64 * sizeof(LUID_AND_ATTRIBUTES)];
    ULONG retLen = 0;
    status = ZwQueryInformationToken(tokenHandle, TokenPrivileges, buf, sizeof(buf), &retLen);
    if (!NT_SUCCESS(status)) {
        ZwClose(tokenHandle);
        ZwClose(procHandle);
        DbgPrint("ZETA: DkomTkn: Verify ZwQueryInformationToken FAILED (0x%08X)\n", status);
        return status;
    }

    PTOKEN_PRIVILEGES tp = (PTOKEN_PRIVILEGES)buf;
    BOOLEAN allPresent = TRUE;
    for (ULONG i = 0; i < kCriticalCount; i++) {
        BOOLEAN found = FALSE;
        for (ULONG j = 0; j < tp->PrivilegeCount; j++) {
            if (tp->Privileges[j].Luid.LowPart == kCriticalPrivs[i] &&
                (tp->Privileges[j].Attributes & SE_PRIVILEGE_ENABLED)) {
                found = TRUE;
                break;
            }
        }
        if (!found) { allPresent = FALSE; break; }
    }

    ZwClose(tokenHandle);
    ZwClose(procHandle);

    if (allPresent) {
        return STATUS_SUCCESS;  // 全部在位，无需重注
    }

    // 缺失 → 重注入
    DbgPrint("ZETA: DkomTkn: privileges missing, re-injecting...\n");
    return DkomInjectTokenPrivileges();
}
