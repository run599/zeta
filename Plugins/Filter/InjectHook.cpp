#include "DriverCommon.h"
#include <intrin.h>

// ============================================================================
// InjectHook — NtCreateThreadEx + NtWriteVirtualMemory 前置拦截 (SSDT 重定向)
//
// 背景:
//   远程线程注入 (CreateRemoteThread → NtCreateThreadEx) 与跨进程内存写入
//   (WriteProcessMemory → NtWriteVirtualMemory) 是进程注入/镂空的核心原语。
//   此前 ZETA 仅有 PsSetCreateThreadNotifyRoutine (事后观察) + APC hook，
//   NtCreateThreadEx 完全未被 hook → 恶意注入不会被前置拦截。
//
// 本模块复用 ApcHook 的 SSDT 定位/重定向框架 (PatchSsdtEntry 等)，
// 对两个系统调用做前置检查:
//   - 同进程调用 / ZETA 自身 / System / 学习模式 → 放行
//   - 源进程受信任 (签名/系统/信任窗口) → 放行
//   - 目标为受保护进程且源不受信任 → 直接拒绝 (STATUS_ACCESS_DENIED)
//   - 其余跨进程调用 → 上报用户态行为引擎评分 (记录, 不阻塞发起线程)
//
// 与 APC hook 的区别: 注入类调用是用户态同步+高频的, 挂起等待用户决策
// 会卡死发起线程 (可能整个系统卡顿)。故采用"直接拒绝高危 + 上报记录低危"。
// ============================================================================

typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
    PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
    SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
    PVOID AttributeList);  // PS_ATTRIBUTE_LIST*; 内核透传不检查内容

typedef NTSTATUS(NTAPI* pfnNtWriteVirtualMemory)(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);

static pfnNtCreateThreadEx   g_OrigNtCreateThreadEx = nullptr;
static pfnNtWriteVirtualMemory g_OrigNtWriteVirtualMemory = nullptr;
static volatile BOOLEAN      g_InjectHookActive = FALSE;
static volatile ULONG_PTR    g_KiServiceTable = 0;
static volatile ULONG        g_CreateThreadSyscall = 0;
static volatile ULONG        g_WriteMemSyscall = 0;

// 用户态连接在线检查 (无用户态时直接放行, 避免系统卡死)
static BOOLEAN InjectUserConnected() {
    return (GlobalData.ClientPort != NULL);
}

// 信任判定封装: 源进程是否可信
static BOOLEAN InjectSourceTrusted(ULONG SrcPid) {
    if (SrcPid == 4) return TRUE;                              // System
    if (SrcPid == (ULONG)GlobalData.ZetaPid) return TRUE;      // ZETA 自身
    if (IsProcessTrusted((HANDLE)(ULONG_PTR)SrcPid)) return TRUE;  // 签名/系统/信任窗口
    return FALSE;
}

// 目标保护判定封装: 目标进程是否受保护
static BOOLEAN InjectTargetProtected(ULONG DstPid) {
    if (DstPid == 4) return TRUE;                              // System
    if (DstPid == (ULONG)GlobalData.ZetaPid) return TRUE;      // ZETA 自身
    if (IsTargetProtected((HANDLE)(ULONG_PTR)DstPid)) return TRUE;
    return FALSE;
}

// 上报用户态行为引擎 (记录, 不阻塞)
static VOID InjectReport(ULONG MsgCode, ULONG SrcPid, ULONG DstPid, ULONG Extra) {
    WCHAR buf[96];
    RtlStringCbPrintfW(buf, sizeof(buf), L"%lu|%lu|%lu", SrcPid, DstPid, Extra);
    SendMessageToUser(MsgCode, SrcPid, buf, (USHORT)(wcslen(buf) * sizeof(WCHAR)));
}

// ============================================================================
// NtCreateThreadEx 处理函数
// ============================================================================
NTSTATUS NTAPI InjectHook_NtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
    PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
    SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
    PVOID AttributeList) {
    pfnNtCreateThreadEx orig = g_OrigNtCreateThreadEx;
    if (!orig) return STATUS_ACCESS_DENIED;

    // 快速路径: 非 PASSIVE / 未激活 / 无用户态 / 无目标句柄 → 直接放行
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || !g_InjectHookActive ||
        !InjectUserConnected() || !ProcessHandle) {
        return orig(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
                    StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
                    MaximumStackSize, AttributeList);
    }

    ULONG src = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    // 解析目标句柄 → 目标进程 PID
    PEPROCESS TargetProcess = nullptr;
    NTSTATUS status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_CREATE_THREAD,
        *PsProcessType, KernelMode, (PVOID*)&TargetProcess, nullptr);
    ULONG dst = 0;
    if (NT_SUCCESS(status) && TargetProcess) {
        dst = (ULONG)(ULONG_PTR)PsGetProcessId(TargetProcess);
        ObDereferenceObject(TargetProcess);
    }
    if (dst == 0) {
        // 句柄无效/无法解析 → 透传 (内核后续会返回错误)
        return orig(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
                    StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
                    MaximumStackSize, AttributeList);
    }

    // ── 放行快速路径 ──
    if (src == dst)                       // 同进程创建线程 (正常多线程)
        return orig(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
                    StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
                    MaximumStackSize, AttributeList);
    if (src == (ULONG)GlobalData.ZetaPid) // ZETA 自身 (自我保护/UI)
        return orig(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
                    StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
                    MaximumStackSize, AttributeList);
    if (src == 4)                         // System 创建 (系统服务)
        return orig(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
                    StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
                    MaximumStackSize, AttributeList);
    if (g_LearningModeActive)             // 学习模式
        return orig(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
                    StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
                    MaximumStackSize, AttributeList);
    if (!g_ProcessProtectEnabled)         // 进程保护开关关闭
        return orig(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
                    StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
                    MaximumStackSize, AttributeList);
    if (InjectSourceTrusted(src))         // 源受信任 → 放行
        return orig(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
                    StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
                    MaximumStackSize, AttributeList);

    // ── 目标受保护 + 源不可信 → 直接拒绝 (前置拦截核心) ──
    if (InjectTargetProtected(dst)) {
        ZETA_WARN("InjectHook: CreateRemoteThread PID=%lu -> protected PID=%lu DENIED\n",
                  src, dst);
        InjectReport(ZETA_MSG_THREAD_CREATE_INJECT, src, dst, 1);  // 1 = denied
        return STATUS_ACCESS_DENIED;
    }

    // ── 跨进程 + 源不可信 + 目标未保护 → 上报记录 (放行但留痕) ──
    // 调试器/注入型合法工具会创建远程线程, 直接拒绝会误杀正常软件。
    // 上报行为引擎评分, 由用户态综合判定。
    ZETA_WARN("InjectHook: CreateRemoteThread PID=%lu -> PID=%lu observed\n", src, dst);
    InjectReport(ZETA_MSG_THREAD_CREATE_INJECT, src, dst, 0);  // 0 = observed
    return orig(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
                StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
                MaximumStackSize, AttributeList);
}

// ============================================================================
// NtWriteVirtualMemory 处理函数
// ============================================================================
NTSTATUS NTAPI InjectHook_NtWriteVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten) {
    pfnNtWriteVirtualMemory orig = g_OrigNtWriteVirtualMemory;
    if (!orig) return STATUS_ACCESS_DENIED;

    // 快速路径: 非 PASSIVE / 未激活 / 无用户态 / 无目标句柄 → 放行
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || !g_InjectHookActive ||
        !InjectUserConnected() || !ProcessHandle) {
        return orig(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
    }

    ULONG src = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    // 解析目标句柄 → 目标进程 PID
    PEPROCESS TargetProcess = nullptr;
    NTSTATUS status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_VM_WRITE,
        *PsProcessType, KernelMode, (PVOID*)&TargetProcess, nullptr);
    ULONG dst = 0;
    if (NT_SUCCESS(status) && TargetProcess) {
        dst = (ULONG)(ULONG_PTR)PsGetProcessId(TargetProcess);
        ObDereferenceObject(TargetProcess);
    }
    if (dst == 0) {
        return orig(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
    }

    // ── 放行快速路径 ──
    if (src == dst)                       // 写自己内存 (正常, 如 JIT/加载器)
        return orig(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
    if (src == (ULONG)GlobalData.ZetaPid) // ZETA 自身
        return orig(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
    if (src == 4)                         // System
        return orig(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
    if (g_LearningModeActive)             // 学习模式
        return orig(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
    if (!g_ProcessProtectEnabled)         // 开关关闭
        return orig(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
    if (InjectSourceTrusted(src))         // 源受信任 → 放行
        return orig(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);

    // 跨进程写目标且源不可信 → 若写入量 > 0 才是真实写入, 记录大小
    SIZE_T writeBytes = (BufferSize > 0xFFFFFFFF) ? 0xFFFFFFFF : (SIZE_T)BufferSize;

    // ── 目标受保护 + 源不可信 → 直接拒绝 (内存写入是镂空/注入的前置) ──
    if (InjectTargetProtected(dst)) {
        ZETA_WARN("InjectHook: WriteProcessMemory PID=%lu -> protected PID=%lu (%Iu bytes) DENIED\n",
                  src, dst, writeBytes);
        InjectReport(ZETA_MSG_WRITE_MEM_INJECT, src, dst, 1);
        return STATUS_ACCESS_DENIED;
    }

    // ── 跨进程写未保护目标 → 上报记录 (放行) ──
    ZETA_WARN("InjectHook: WriteProcessMemory PID=%lu -> PID=%lu (%Iu bytes) observed\n",
              src, dst, writeBytes);
    InjectReport(ZETA_MSG_WRITE_MEM_INJECT, src, dst, 0);
    return orig(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

// ============================================================================
// 启用 / 禁用
// ============================================================================
NTSTATUS InjectHook_Enable(ULONG CreateThreadSyscall, ULONG WriteMemSyscall,
    ULONG ValidateSyscall) {
    if (g_InjectHookActive) return STATUS_SUCCESS;  // 幂等

    if (CreateThreadSyscall == 0 || WriteMemSyscall == 0 || ValidateSyscall == 0)
        return STATUS_INVALID_PARAMETER;
    if (CreateThreadSyscall >= 0x800 || WriteMemSyscall >= 0x800 || ValidateSyscall >= 0x800)
        return STATUS_INVALID_PARAMETER;
    if (CreateThreadSyscall == ValidateSyscall || WriteMemSyscall == ValidateSyscall)
        return STATUS_INVALID_PARAMETER;

    PVOID base = nullptr;
    ULONG size = 0;
    NTSTATUS status = GetNtoskrnlBase(&base, &size);
    if (!NT_SUCCESS(status)) {
        ZETA_ERROR("InjectHook: cannot locate ntoskrnl (0x%08X)\n", status);
        return status;
    }

    ULONG_PTR table = FindKiServiceTable(base, size, ValidateSyscall);
    if (!table) {
        ZETA_ERROR("InjectHook: KiServiceTable not found\n");
        return STATUS_NOT_FOUND;
    }

    if ((table + CreateThreadSyscall * 4) >= ((ULONG_PTR)base + size) ||
        (table + WriteMemSyscall * 4) >= ((ULONG_PTR)base + size)) {
        ZETA_ERROR("InjectHook: syscall out of range\n");
        return STATUS_INVALID_PARAMETER;
    }

    // 先打 NtWriteVirtualMemory, 成功后再打 NtCreateThreadEx;
    // 若第二个失败则回滚第一个, 保证要么都激活要么都不激活。
    ULONG_PTR origWrite = 0;
    status = PatchSsdtEntry(table, WriteMemSyscall,
        (ULONG_PTR)&InjectHook_NtWriteVirtualMemory, &origWrite);
    if (!NT_SUCCESS(status)) {
        ZETA_ERROR("InjectHook: WriteVirtualMemory patch failed (0x%08X)\n", status);
        return status;
    }

    ULONG_PTR origCreate = 0;
    status = PatchSsdtEntry(table, CreateThreadSyscall,
        (ULONG_PTR)&InjectHook_NtCreateThreadEx, &origCreate);
    if (!NT_SUCCESS(status)) {
        // 回滚 WriteVirtualMemory
        PatchSsdtEntry(table, WriteMemSyscall, origWrite, nullptr);
        ZETA_ERROR("InjectHook: CreateThreadEx patch failed (0x%08X), rolled back\n", status);
        return status;
    }

    g_OrigNtCreateThreadEx = (pfnNtCreateThreadEx)origCreate;
    g_OrigNtWriteVirtualMemory = (pfnNtWriteVirtualMemory)origWrite;
    g_KiServiceTable = table;
    g_CreateThreadSyscall = CreateThreadSyscall;
    g_WriteMemSyscall = WriteMemSyscall;
    KeMemoryBarrier();
    g_InjectHookActive = TRUE;

    ZETA_INFO("InjectHook enabled: CreateThreadEx=%lu WriteVM=%lu origC=0x%p origW=0x%p\n",
              CreateThreadSyscall, WriteMemSyscall, (PVOID)origCreate, (PVOID)origWrite);
    return STATUS_SUCCESS;
}

VOID InjectHook_Disable() {
    if (!g_InjectHookActive) return;

    g_InjectHookActive = FALSE;
    KeMemoryBarrier();

    if (g_KiServiceTable && g_OrigNtCreateThreadEx && g_CreateThreadSyscall) {
        PatchSsdtEntry(g_KiServiceTable, g_CreateThreadSyscall,
            (ULONG_PTR)g_OrigNtCreateThreadEx, nullptr);
    }
    if (g_KiServiceTable && g_OrigNtWriteVirtualMemory && g_WriteMemSyscall) {
        PatchSsdtEntry(g_KiServiceTable, g_WriteMemSyscall,
            (ULONG_PTR)g_OrigNtWriteVirtualMemory, nullptr);
    }
    ZETA_INFO("InjectHook disabled (SSDT restored)\n");

    g_OrigNtCreateThreadEx = nullptr;
    g_OrigNtWriteVirtualMemory = nullptr;
    g_KiServiceTable = 0;
}

BOOLEAN InjectHook_IsActive() {
    return g_InjectHookActive;
}

VOID InjectHook_Init() {
    // 待决表/锁由 ApcHook_Init 统一初始化; 本模块无独立待决表
}

VOID InjectHook_CheckTimeouts() {
    // 本模块不挂起等待, 无超时处理
}
