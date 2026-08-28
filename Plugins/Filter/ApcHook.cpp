#include "DriverCommon.h"
#include <intrin.h>

// WDK 未声明 ZwQuerySystemInformation (ntoskrnl 导出，内核驱动可直接调用)
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

// ============================================================================
// APC Hook — NtQueueApcThread 拦截 (SSDT 表项重定向)
//
// 原理:
//   1. 定位 ntoskrnl 的 KiServiceTable (SSDT)。
//   2. 根据用户态上报的 NtQueueApcThread 系统调用号，把 SSDT 表项重定向
//      到本驱动的处理函数 ApcHook_NtQueueApcThread。
//   3. 处理函数在 PASSIVE_LEVEL 检查跨进程 APC 入队:
//      - 同进程 / 系统 / ZETA / 受信任进程 → 直接调用原函数。
//      - 可疑进程 → 挂起等待用户态决策 (允许/阻止)，超时默认阻止。
//   4. 用户态通过 ZETA_CMD_ALLOW_OP/DENY_OP 回传决策。
//
// 相比 inline hook: SSDT 重定向不改动内核代码字节，保存原地址后
// 直接调用原函数，无递归问题；被 PatchGuard 检出的风险低。
//
// 限制:
//   - 表项偏移是相对 KiServiceTable 基址的 32 位有符号偏移，驱动若被
//     映射到超过 ±2GB 的距离则 hook 失败(安全回退)。
//   - 只能拦截走 SSDT 的 NtQueueApcThread 用户态调用，内核自身
//     KeInsertQueueApc 不受影响。
// ============================================================================

#define APC_PENDING_MAX      32
#define APC_WAIT_TIMEOUT_MS  5000

typedef struct _APC_PENDING {
    ULONG       SourcePid;
    ULONG       TargetPid;
    KEVENT      Event;
    BOOLEAN     Allow;      // 用户态决策
    BOOLEAN     InUse;
    LARGE_INTEGER StartTick;
} APC_PENDING, *PAPC_PENDING;

typedef NTSTATUS(NTAPI* pfnNtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);

static pfnNtQueueApcThread g_OrigNtQueueApcThread = nullptr;
static volatile BOOLEAN g_ApcHookActive = FALSE;
static volatile ULONG_PTR g_KiServiceTable = 0;
static volatile ULONG g_ApcSyscallIndex = 0;

static APC_PENDING g_ApcPending[APC_PENDING_MAX];
static KSPIN_LOCK g_ApcPendingLock;

// ============================================================================
// UnloadGuard -- P0-2: 拦截 ZETA_Drv 自卸载
//
// 复用 KiServiceTable 定位 + PatchSsdtEntry 框架，SSDT 重定向 NtUnloadDriver。
// handler 仅拒绝目标为 ZETA_Drv 的卸载请求，其余透传原函数。
// ============================================================================
typedef NTSTATUS(NTAPI* pfnNtUnloadDriver)(PUNICODE_STRING DriverServiceName);

static pfnNtUnloadDriver g_OrigNtUnloadDriver = nullptr;
static volatile BOOLEAN  g_UnloadGuardActive = FALSE;
static volatile ULONG     g_UnloadSyscallIndex = 0;
static KSPIN_LOCK         g_UnloadGuardLock;

// ZETA 驱动服务对象名 (与 INF/服务注册一致)
static const WCHAR g_ZetaDriverServiceName[] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ZETA_Drv";

// ── 用户态 hook 是否在线: 无用户态连接时直接放行，避免系统卡死 ──
static BOOLEAN ApcUserConnected() {
    return (GlobalData.ClientPort != NULL);
}

// ============================================================================
// KiServiceTable (SSDT) 定位
// ============================================================================

typedef struct _ZETA_SYS_MODULE_ENTRY {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} ZETA_SYS_MODULE_ENTRY, *PZETA_SYS_MODULE_ENTRY;

typedef struct _ZETA_SYS_MODULE_INFO {
    ULONG Count;
    ZETA_SYS_MODULE_ENTRY Module[1];
} ZETA_SYS_MODULE_INFO, *PZETA_SYS_MODULE_INFO;

NTSTATUS GetNtoskrnlBase(PVOID* OutBase, ULONG* OutSize) {
    if (!OutBase || !OutSize) return STATUS_INVALID_PARAMETER;

    ULONG size = 0;
    NTSTATUS status = ZwQuerySystemInformation(11 /* SystemModuleInformation */,
        nullptr, 0, &size);
    if (size == 0) return STATUS_UNSUCCESSFUL;

    PZETA_SYS_MODULE_INFO info = (PZETA_SYS_MODULE_INFO)ZetaAllocate(size);
    if (!info) return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQuerySystemInformation(11, info, size, &size);
    if (!NT_SUCCESS(status)) {
        ZetaFree(info);
        return status;
    }

    for (ULONG i = 0; i < info->Count; i++) {
        PZETA_SYS_MODULE_ENTRY m = &info->Module[i];
        PCSTR name = (PCSTR)((PUCHAR)m->FullPathName + m->OffsetToFileName);
        // 不区分大小写比较文件名 (内核无 _stricmp)
        static const char target[] = "ntoskrnl.exe";
        BOOLEAN match = TRUE;
        for (ULONG k = 0; k < sizeof(target) - 1; k++) {
            char c = name[k];
            if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
            if (c != target[k]) { match = FALSE; break; }
        }
        if (match && m->MappedBase) {
            *OutBase = m->MappedBase;
            *OutSize = m->ImageSize;
            ZetaFree(info);
            return STATUS_SUCCESS;
        }
    }

    ZetaFree(info);
    return STATUS_NOT_FOUND;
}

// 扫描 ntoskrnl .text 寻找 "mov eax, [rax*4 + disp32]" (8B 04 85 ?? ?? ?? ??)
// 该指令只在系统调用分发器中出现一次，disp32 相对下一条指令。
// KiServiceTable = instr + 7 + disp32
ULONG_PTR FindKiServiceTable(PVOID Base, ULONG Size, ULONG ValidateSyscall) {
    if (!Base || Size == 0) return 0;

    PUCHAR p = (PUCHAR)Base;
    for (ULONG off = 0; off + 7 <= Size; off++) {
        if (p[off] == 0x8B && p[off+1] == 0x04 && p[off+2] == 0x85) {
            LONG disp = *(PLONG)(p + off + 3);
            ULONG_PTR table = (ULONG_PTR)(p + off + 7) + disp;
            ULONG_PTR start = (ULONG_PTR)Base;
            ULONG_PTR end = start + Size;

            if (table < start || table >= end) continue;  // 目标必须在镜像内

            // 用验证系统调用号校验: 表项偏移解析出的地址必须在镜像内
            if (ValidateSyscall > 0 && ValidateSyscall < 0x800) {
                PLONG entryPtr = (PLONG)(table + (ULONG_PTR)ValidateSyscall * sizeof(LONG));
                if ((ULONG_PTR)entryPtr >= end) continue;
                LONG entryOff = *entryPtr;
                ULONG_PTR resolved = table + (LONG)entryOff;
                if (resolved < start || resolved >= end) continue;
            }

            return table;
        }
    }
    return 0;
}

// ============================================================================
// SSDT 表项重定向 (CR0.WP 清除)
// ============================================================================
NTSTATUS PatchSsdtEntry(ULONG_PTR Table, ULONG Index, ULONG_PTR Handler,
    ULONG_PTR* OutOriginal) {
    if (!Table || !Handler) return STATUS_INVALID_PARAMETER;

    // P0-自伤免疫: 这是 ZETA 自己修改 SSDT 表项的唯一入口, 置位标记,
    // 使未来的内核完整性监控逻辑识别"这是自保动作"而非外部篡改。
    g_SelfDkomInProgress = TRUE;

    LONG* entry = (LONG*)(Table + (ULONG_PTR)Index * sizeof(LONG));
    ULONG_PTR oldAddr = Table + (LONG)*entry;

    ULONG_PTR delta = Handler - Table;
    if ((ULONG_PTR)(LONG)delta != delta) {
        // 32 位有符号偏移装不下 → 无法安全重定向
        g_SelfDkomInProgress = FALSE;
        return STATUS_INTEGER_OVERFLOW;
    }

    // 临时清除 CR0.WP 使表可写；通过 cli/sti 防止写期间被抢占
    KIRQL irql = KeGetCurrentIrql();
    if (irql < DISPATCH_LEVEL) _disable();
    ULONG_PTR cr0 = __readcr0();
    __writecr0(cr0 & ~(ULONG_PTR)0x10000);  // clear WP
    *entry = (LONG)delta;
    __writecr0(cr0);                         // restore WP
    if (irql < DISPATCH_LEVEL) _enable();

    g_SelfDkomInProgress = FALSE;

    if (OutOriginal) *OutOriginal = oldAddr;
    return STATUS_SUCCESS;
}

// ============================================================================
// 待决表
// ============================================================================
static VOID CompletePendingApcInternal(ULONG SourcePid, BOOLEAN Allow) {
    KIRQL irql;
    KeAcquireSpinLock(&g_ApcPendingLock, &irql);
    for (ULONG i = 0; i < APC_PENDING_MAX; i++) {
        PAPC_PENDING e = &g_ApcPending[i];
        if (e->InUse && e->SourcePid == SourcePid) {
            e->Allow = Allow;
            KeSetEvent(&e->Event, IO_NO_INCREMENT, FALSE);
        }
    }
    KeReleaseSpinLock(&g_ApcPendingLock, irql);
}

// 用户态 ALLOW_OP/DENY_OP 决策入口
VOID CompletePendingApc(ULONG SourcePid, BOOLEAN Allow) {
    CompletePendingApcInternal(SourcePid, Allow);

    if (Allow) {
        // 用户放行 → 把源进程加入信任窗口 (30 分钟免重复询问)
        PUNICODE_STRING imageName = NULL;
        if (NT_SUCCESS(GetProcessImageName((HANDLE)(ULONG_PTR)SourcePid, &imageName))
            && imageName && imageName->Buffer) {
            AddToTrustWindow(imageName->Buffer);
        }
        if (imageName) ExFreePool(imageName);
    }
}

// 释放超时的待决表项 (由 DriverEntry 的超时检查线程周期调用)
VOID ApcHook_CheckTimeouts() {
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);

    KIRQL irql;
    KeAcquireSpinLock(&g_ApcPendingLock, &irql);
    for (ULONG i = 0; i < APC_PENDING_MAX; i++) {
        PAPC_PENDING e = &g_ApcPending[i];
        if (e->InUse && (now.QuadPart - e->StartTick.QuadPart) >= (APC_WAIT_TIMEOUT_MS * 10000LL)) {
            e->Allow = FALSE;          // 超时默认阻止
            KeSetEvent(&e->Event, IO_NO_INCREMENT, FALSE);
        }
    }
    KeReleaseSpinLock(&g_ApcPendingLock, irql);
}

// ============================================================================
// NtQueueApcThread 处理函数
// ============================================================================
NTSTATUS NTAPI ApcHook_NtQueueApcThread(HANDLE ThreadHandle, PVOID ApcRoutine,
    PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {
    pfnNtQueueApcThread orig = g_OrigNtQueueApcThread;
    if (!orig) return STATUS_ACCESS_DENIED;

    // 快速路径: 非 PASSIVE / hook 未激活 / 无用户态连接 → 直接放行
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || !g_ApcHookActive || !ApcUserConnected()) {
        return orig(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
    }

    ULONG src = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    // 解析目标线程 → 目标进程
    PETHREAD Thread = nullptr;
    NTSTATUS status = ObReferenceObjectByHandle(ThreadHandle, THREAD_SET_CONTEXT,
        *PsThreadType, KernelMode, (PVOID*)&Thread, nullptr);
    if (!NT_SUCCESS(status) || !Thread) {
        return orig(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
    }
    PEPROCESS TargetProcess = IoThreadToProcess(Thread);
    ULONG dst = TargetProcess ? (ULONG)(ULONG_PTR)PsGetProcessId(TargetProcess) : 0;
    ObDereferenceObject(Thread);

    if (dst == 0) return orig(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);

    // ── 放行快速路径 ──
    if (src == dst)                                   // 自身 APC
        return orig(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
    if (src == (ULONG)GlobalData.ZetaPid)             // ZETA 自身
        return orig(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
    if (src == 4)                                     // System
        return orig(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
    if (dst == 4)                                     // 目标为 System 不拦截
        return orig(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
    if (g_LearningModeActive)                         // 学习模式
        return orig(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
    if (!g_ProcessProtectEnabled)                     // 进程保护开关
        return orig(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);

    // 源进程受信任 → 放行
    if (IsProcessTrusted((HANDLE)(ULONG_PTR)src))
        return orig(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);

    // 目标进程受保护但源不受信任 → 直接拒绝并通知 (高优先级)
    if (IsTargetProtected((HANDLE)(ULONG_PTR)dst)) {
        ZETA_WARN("APC: untrusted PID=%lu -> protected PID=%lu DENIED\n", src, dst);
        return STATUS_ACCESS_DENIED;
    }

    // ── 可疑: 挂起等待用户决策 ──
    // 每次调用独占一个待决槽 (用户态按源进程节流弹窗);
    // 用户一次决策会通过 CompletePendingApc 完成该源的所有待决项。
    PAPC_PENDING slot = nullptr;
    KIRQL irql;
    KeAcquireSpinLock(&g_ApcPendingLock, &irql);
    for (ULONG i = 0; i < APC_PENDING_MAX; i++) {
        if (!g_ApcPending[i].InUse) {
            slot = &g_ApcPending[i];
            KeInitializeEvent(&slot->Event, NotificationEvent, FALSE);
            slot->SourcePid = src;
            slot->TargetPid = dst;
            slot->Allow = FALSE;
            slot->InUse = TRUE;
            KeQuerySystemTime(&slot->StartTick);
            break;
        }
    }
    KeReleaseSpinLock(&g_ApcPendingLock, irql);

    if (!slot) {
        // 待决表已满 → 保守阻止
        ZETA_WARN("APC: pending table full, denying PID=%lu -> PID=%lu\n", src, dst);
        return STATUS_ACCESS_DENIED;
    }

    ZETA_WARN("APC: suspicious PID=%lu -> PID=%lu, waiting for user decision\n", src, dst);
    WCHAR buf[64];
    RtlStringCbPrintfW(buf, sizeof(buf), L"%lu|%lu", src, dst);
    SendMessageToUser(ZETA_MSG_APC_INJECT, src, buf, (USHORT)(wcslen(buf) * sizeof(WCHAR)));

    LARGE_INTEGER timeout;
    timeout.QuadPart = -(APC_WAIT_TIMEOUT_MS * 10000LL);
    KeWaitForSingleObject(&slot->Event, Executive, KernelMode, FALSE, &timeout);

    BOOLEAN allow = slot->Allow;

    KeAcquireSpinLock(&g_ApcPendingLock, &irql);
    slot->InUse = FALSE;
    KeReleaseSpinLock(&g_ApcPendingLock, irql);

    if (allow) {
        return orig(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
    }

    ZETA_WARN("APC: denied PID=%lu -> PID=%lu\n", src, dst);
    return STATUS_ACCESS_DENIED;
}

// ============================================================================
// 启用 / 禁用
// ============================================================================
NTSTATUS ApcHook_Enable(ULONG ApcSyscall, ULONG ValidateSyscall) {
    if (g_ApcHookActive) return STATUS_SUCCESS;  // 已启用，幂等

    if (ApcSyscall == 0 || ValidateSyscall == 0 || ApcSyscall == ValidateSyscall)
        return STATUS_INVALID_PARAMETER;
    if (ApcSyscall >= 0x800 || ValidateSyscall >= 0x800)
        return STATUS_INVALID_PARAMETER;

    PVOID base = nullptr;
    ULONG size = 0;
    NTSTATUS status = GetNtoskrnlBase(&base, &size);
    if (!NT_SUCCESS(status)) {
        ZETA_ERROR("ApcHook: cannot locate ntoskrnl (0x%08X)\n", status);
        return status;
    }

    ULONG_PTR table = FindKiServiceTable(base, size, ValidateSyscall);
    if (!table) {
        ZETA_ERROR("ApcHook: KiServiceTable not found\n");
        return STATUS_NOT_FOUND;
    }

    if ((table + ApcSyscall * 4) >= ((ULONG_PTR)base + size)) {
        ZETA_ERROR("ApcHook: syscall %lu out of range\n", ApcSyscall);
        return STATUS_INVALID_PARAMETER;
    }

    ULONG_PTR original = 0;
    status = PatchSsdtEntry(table, ApcSyscall, (ULONG_PTR)&ApcHook_NtQueueApcThread, &original);
    if (!NT_SUCCESS(status)) {
        ZETA_ERROR("ApcHook: SSDT patch failed (0x%08X)\n", status);
        return status;
    }

    g_OrigNtQueueApcThread = (pfnNtQueueApcThread)original;
    g_KiServiceTable = table;
    g_ApcSyscallIndex = ApcSyscall;
    KeMemoryBarrier();
    g_ApcHookActive = TRUE;

    ZETA_INFO("ApcHook enabled: syscall=%lu original=0x%p\n", ApcSyscall, (PVOID)original);
    return STATUS_SUCCESS;
}

VOID ApcHook_Disable() {
    if (!g_ApcHookActive) return;

    g_ApcHookActive = FALSE;
    KeMemoryBarrier();

    if (g_KiServiceTable && g_OrigNtQueueApcThread) {
        // 还原原表项，避免卸载后指针悬空
        PatchSsdtEntry(g_KiServiceTable, g_ApcSyscallIndex,
            (ULONG_PTR)g_OrigNtQueueApcThread, nullptr);
        ZETA_INFO("ApcHook disabled (SSDT restored)\n");
    }

    g_OrigNtQueueApcThread = nullptr;
    g_KiServiceTable = 0;
}

BOOLEAN ApcHook_IsActive() {
    return g_ApcHookActive;
}

// 初始化待决表 (DriverEntry 调用)
VOID ApcHook_Init() {
    RtlZeroMemory(g_ApcPending, sizeof(g_ApcPending));
    KeInitializeSpinLock(&g_ApcPendingLock);
    KeInitializeSpinLock(&g_UnloadGuardLock);
}

// ============================================================================
// ApcHook_IsTableIntact -- P0-1: watchdog 三合一校验用
//
// 校验 APC SSDT 表项仍指向本驱动 handler (ApcHook_NtQueueApcThread)。
// 用于在 watchdog 周期里发现"表项被还原/被其他钩子覆盖"。
// 返回 TRUE 表示表项完整 (或 hook 未激活/未定位，无可校验对象)。
// ============================================================================
BOOLEAN ApcHook_IsTableIntact() {
    // hook 未激活或表未定位 → 无可校验对象，按"健康"返回
    if (!g_ApcHookActive || !g_KiServiceTable || g_ApcSyscallIndex == 0)
        return TRUE;

    LONG* entry = (LONG*)(g_KiServiceTable + (ULONG_PTR)g_ApcSyscallIndex * sizeof(LONG));

    // 读取表项需临时清 CR0.WP (与 PatchSsdtEntry 一致)，避免在某些配置下
    // 读取不可写页面触发机器检查。读操作不改内容。
    KIRQL irql = KeGetCurrentIrql();
    if (irql < DISPATCH_LEVEL) _disable();
    ULONG_PTR cr0 = __readcr0();
    __writecr0(cr0 & ~(ULONG_PTR)0x10000);  // clear WP

    ULONG_PTR currentHandler = (ULONG_PTR)(g_KiServiceTable + (LONG)*entry);

    __writecr0(cr0);                         // restore WP
    if (irql < DISPATCH_LEVEL) _enable();

    // 表项应指向本驱动 handler；若在 ±2GB 内则比较地址，否则比较相对偏移
    if (currentHandler == (ULONG_PTR)&ApcHook_NtQueueApcThread)
        return TRUE;

    // 指针不相等但可能由于重定位差异，再次比较相对偏移 (SSDT 存的是相对 KiServiceTable 的偏移)
    LONG rel = (LONG)((ULONG_PTR)&ApcHook_NtQueueApcThread - g_KiServiceTable);
    if (*entry == rel)
        return TRUE;

    ZETA_WARN("ApcHook: SSDT entry tampered! idx=%lu cur=0x%p exp=0x%p\n",
              g_ApcSyscallIndex, (PVOID)currentHandler, (PVOID)&ApcHook_NtQueueApcThread);
    return FALSE;
}

// ============================================================================
// ApcHook_RestoreTableEntry -- P0-1: watchdog 三合一校验用
//
// 当 ApcHook_IsTableIntact() 返回 FALSE 时，由 watchdog 调用以重打 SSDT 表项。
// 仅在已定位表 (g_KiServiceTable) 且 handler 与表基址距离在 ±2GB 内时安全重打；
// 否则记录失败（当初 ApcHook_Enable 即会因距离超限失败，不会走到这里）。
// ============================================================================
VOID ApcHook_RestoreTableEntry() {
    if (!g_ApcHookActive || !g_KiServiceTable || g_ApcSyscallIndex == 0) {
        ZETA_WARN("ApcHook: RestoreTableEntry skipped (table not located)\n");
        return;
    }

    ULONG_PTR handler = (ULONG_PTR)&ApcHook_NtQueueApcThread;
    ULONG_PTR delta = handler - g_KiServiceTable;
    if ((ULONG_PTR)(LONG)delta != delta) {
        // 32 位有符号偏移装不下 → 无法安全重定向，放弃并告警
        ZETA_ERROR("ApcHook: RestoreTableEntry FAILED (handler out of ±2GB range)\n");
        return;
    }

    NTSTATUS st = PatchSsdtEntry(g_KiServiceTable, g_ApcSyscallIndex, handler, NULL);
    if (NT_SUCCESS(st)) {
        KeMemoryBarrier();
        ZETA_INFO("ApcHook: SSDT entry restored (idx=%lu)\n", g_ApcSyscallIndex);
    } else {
        ZETA_ERROR("ApcHook: RestoreTableEntry patch FAILED (0x%08X)\n", st);
    }
}

// ============================================================================
// UnloadGuard_NtUnloadDriver -- NtUnloadDriver 重定向处理函数
//
// 仅当待卸载驱动服务对象名匹配 ZETA_Drv 时返回拒绝，其余一律透传原函数。
// 由此防止 sc stop / fltmc unload 卸载本驱动。
// ============================================================================
NTSTATUS NTAPI UnloadGuard_NtUnloadDriver(PUNICODE_STRING DriverServiceName) {
    pfnNtUnloadDriver orig = g_OrigNtUnloadDriver;
    if (!orig) return STATUS_ACCESS_DENIED;

    // 快速路径: 未激活 / 无用户态连接 / 无参数 → 直接放行
    if (!g_UnloadGuardActive || !ApcUserConnected()) {
        return orig(DriverServiceName);
    }

    if (DriverServiceName && DriverServiceName->Buffer && DriverServiceName->Length > 0) {
        // 比较服务对象名 (大小写不敏感)，匹配 ZETA_Drv 则拒绝
        SIZE_T targetLen = (sizeof(g_ZetaDriverServiceName) / sizeof(WCHAR)) - 1;
        SIZE_T nameLen = DriverServiceName->Length / sizeof(WCHAR);
        if (nameLen >= targetLen) {
            PCWSTR p = DriverServiceName->Buffer + (nameLen - targetLen);
            BOOLEAN match = TRUE;
            for (SIZE_T i = 0; i < targetLen; i++) {
                WCHAR c = p[i];
                if (c >= L'A' && c <= L'Z') c += L'a' - L'A';
                WCHAR t = g_ZetaDriverServiceName[i];
                if (t >= L'A' && t <= L'Z') t += L'a' - L'A';
                if (c != t) { match = FALSE; break; }
            }
            if (match) {
                ZETA_WARN("UnloadGuard: ZETA_Drv unload DENIED (from PID=%lu)\n",
                          (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
                return STATUS_ACCESS_DENIED;
            }
        }
    }

    return orig(DriverServiceName);
}

// ============================================================================
// UnloadGuard_Enable -- 重定向 NtUnloadDriver
//
// UnloadSyscall / ValidateSyscall 由用户态从 ntdll stub 解析后通过
// ZETA_CMD_SET_UNLOAD_GUARD 传入 (与 APC hook 一致，避免硬编码)。
// ============================================================================
NTSTATUS UnloadGuard_Enable(ULONG UnloadSyscall, ULONG ValidateSyscall) {
    if (g_UnloadGuardActive) return STATUS_SUCCESS;  // 幂等

    if (UnloadSyscall == 0 || ValidateSyscall == 0 || UnloadSyscall == ValidateSyscall)
        return STATUS_INVALID_PARAMETER;
    if (UnloadSyscall >= 0x800 || ValidateSyscall >= 0x800)
        return STATUS_INVALID_PARAMETER;

    PVOID base = nullptr;
    ULONG size = 0;
    NTSTATUS status = GetNtoskrnlBase(&base, &size);
    if (!NT_SUCCESS(status)) {
        ZETA_ERROR("UnloadGuard: cannot locate ntoskrnl (0x%08X)\n", status);
        return status;
    }

    ULONG_PTR table = FindKiServiceTable(base, size, ValidateSyscall);
    if (!table) {
        ZETA_ERROR("UnloadGuard: KiServiceTable not found\n");
        return STATUS_NOT_FOUND;
    }

    if ((table + UnloadSyscall * 4) >= ((ULONG_PTR)base + size)) {
        ZETA_ERROR("UnloadGuard: syscall %lu out of range\n", UnloadSyscall);
        return STATUS_INVALID_PARAMETER;
    }

    ULONG_PTR original = 0;
    status = PatchSsdtEntry(table, UnloadSyscall, (ULONG_PTR)&UnloadGuard_NtUnloadDriver, &original);
    if (!NT_SUCCESS(status)) {
        ZETA_ERROR("UnloadGuard: SSDT patch failed (0x%08X)\n", status);
        return status;
    }

    g_OrigNtUnloadDriver = (pfnNtUnloadDriver)original;
    g_UnloadSyscallIndex = UnloadSyscall;
    KeMemoryBarrier();
    g_UnloadGuardActive = TRUE;

    ZETA_INFO("UnloadGuard enabled: syscall=%lu original=0x%p\n", UnloadSyscall, (PVOID)original);
    return STATUS_SUCCESS;
}

VOID UnloadGuard_Disable() {
    if (!g_UnloadGuardActive) return;

    g_UnloadGuardActive = FALSE;
    KeMemoryBarrier();

    if (g_UnloadSyscallIndex && g_OrigNtUnloadDriver) {
        // 还原原表项 (需重新定位表；UnloadGuard 与 APC hook 共用同一张表，
        // 但索引不同，这里重新定位以保证卸载时表仍存在)。
        PVOID base = nullptr;
        ULONG size = 0;
        if (NT_SUCCESS(GetNtoskrnlBase(&base, &size))) {
            ULONG_PTR table = FindKiServiceTable(base, size, g_UnloadSyscallIndex);
            if (table) {
                PatchSsdtEntry(table, g_UnloadSyscallIndex,
                    (ULONG_PTR)g_OrigNtUnloadDriver, nullptr);
            }
        }
        ZETA_INFO("UnloadGuard disabled (SSDT restored)\n");
    }

    g_OrigNtUnloadDriver = nullptr;
    g_UnloadSyscallIndex = 0;
}

BOOLEAN UnloadGuard_IsActive() {
    return g_UnloadGuardActive;
}

// watchdog 三合一校验复用: 确认 UnloadGuard 表项未被篡改
BOOLEAN UnloadGuard_IsTableIntact() {
    if (!g_UnloadGuardActive || g_UnloadSyscallIndex == 0) return TRUE;

    PVOID base = nullptr;
    ULONG size = 0;
    if (!NT_SUCCESS(GetNtoskrnlBase(&base, &size))) return TRUE;

    ULONG_PTR table = FindKiServiceTable(base, size, g_UnloadSyscallIndex);
    if (!table) return TRUE;

    LONG* entry = (LONG*)(table + (ULONG_PTR)g_UnloadSyscallIndex * sizeof(LONG));

    KIRQL irql = KeGetCurrentIrql();
    if (irql < DISPATCH_LEVEL) _disable();
    ULONG_PTR cr0 = __readcr0();
    __writecr0(cr0 & ~(ULONG_PTR)0x10000);
    ULONG_PTR currentHandler = (ULONG_PTR)(table + (LONG)*entry);
    __writecr0(cr0);
    if (irql < DISPATCH_LEVEL) _enable();

    if (currentHandler == (ULONG_PTR)&UnloadGuard_NtUnloadDriver)
        return TRUE;
    LONG rel = (LONG)((ULONG_PTR)&UnloadGuard_NtUnloadDriver - table);
    if (*entry == rel)
        return TRUE;

    ZETA_WARN("UnloadGuard: SSDT entry tampered! idx=%lu\n", g_UnloadSyscallIndex);
    return FALSE;
}

// ============================================================================
// UnloadGuard_RestoreTableEntry -- P0-2: watchdog 恢复表项用
//
// 当 UnloadGuard_IsTableIntact() 返回 FALSE 时，由 watchdog 调用以重打
// NtUnloadDriver 表项指向本驱动 handler。
// ============================================================================
VOID UnloadGuard_RestoreTableEntry() {
    if (!g_UnloadGuardActive || g_UnloadSyscallIndex == 0) {
        ZETA_WARN("UnloadGuard: RestoreTableEntry skipped (not active)\n");
        return;
    }

    ULONG_PTR handler = (ULONG_PTR)&UnloadGuard_NtUnloadDriver;

    PVOID base = nullptr;
    ULONG size = 0;
    if (!NT_SUCCESS(GetNtoskrnlBase(&base, &size))) {
        ZETA_ERROR("UnloadGuard: RestoreTableEntry cannot locate ntoskrnl\n");
        return;
    }

    ULONG_PTR table = FindKiServiceTable(base, size, g_UnloadSyscallIndex);
    if (!table) {
        ZETA_ERROR("UnloadGuard: RestoreTableEntry KiServiceTable not found\n");
        return;
    }

    ULONG_PTR delta = handler - table;
    if ((ULONG_PTR)(LONG)delta != delta) {
        ZETA_ERROR("UnloadGuard: RestoreTableEntry FAILED (handler out of ±2GB range)\n");
        return;
    }

    NTSTATUS st = PatchSsdtEntry(table, g_UnloadSyscallIndex, handler, NULL);
    if (NT_SUCCESS(st)) {
        KeMemoryBarrier();
        ZETA_INFO("UnloadGuard: SSDT entry restored (idx=%lu)\n", g_UnloadSyscallIndex);
    } else {
        ZETA_ERROR("UnloadGuard: RestoreTableEntry patch FAILED (0x%08X)\n", st);
    }
}
