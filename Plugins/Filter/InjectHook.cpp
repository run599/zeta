#include "DriverCommon.h"
#include <intrin.h>

#if ZETA_ENABLE_SSDT   // SSDT 模块: Lite 版 (ZETA_ENABLE_SSDT=0) 整个文件空编

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

// P2-优先级2: 进程镂空前置"清空"动作 — NtUnmapViewOfSection (解映射)
typedef NTSTATUS(NTAPI* pfnNtUnmapViewOfSection)(
    HANDLE ProcessHandle, PVOID BaseAddress);

static pfnNtCreateThreadEx   g_OrigNtCreateThreadEx = nullptr;
static pfnNtWriteVirtualMemory g_OrigNtWriteVirtualMemory = nullptr;
static pfnNtUnmapViewOfSection g_OrigNtUnmapViewOfSection = nullptr;
static volatile BOOLEAN      g_InjectHookActive = FALSE;
// P4-反制: 间接/内联 syscall (RIP 非 ntdll) + 跨进程操作 → 直接拒绝
// 由用户态状态机规则 syscall_spoof_block 命中后经命令 24 开启
static volatile BOOLEAN      g_SyscallSpoofBlock = FALSE;
static volatile ULONG_PTR    g_KiServiceTable = 0;
static volatile ULONG        g_CreateThreadSyscall = 0;
static volatile ULONG        g_WriteMemSyscall = 0;
static volatile ULONG        g_UnmapSyscall = 0;

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
// P4-优先级4: 间接/内联 syscall 检测 (观察版)
//
// 现代恶意软件用间接 syscall (jmp 到 ntdll 的 syscall 桩) 或内联 syscall
// (自己代码里直接 syscall 指令) 绕过用户态 hook。ZETA 是内核 SSDT hook
// 不会被绕, 但调用者 RIP 会暴露其手法:
//   - 正常: 用户代码 call ntdll!xxx → syscall 指令在 ntdll, 用户 RIP 在 ntdll
//   - 内联/间接: syscall 指令在恶意代码(非 ntdll), 用户 RIP 不在 ntdll
// 本检测仅"观察上报" (ZETA_MSG_SYSCALL_SPOOF), 不拦截, 防误杀。
// 偏移针对 Win10 19045 x64 硬编码 (与项目支持的构建一致)。
// ============================================================================

#define KTHREAD_TRAPFRAME_OFFSET  0x80   // KTHREAD->TrapFrame (19045 x64)
#define KTRAPFRAME_RIP_OFFSET     0x78   // KTRAP_FRAME->Rip (x64)
// LDR_DATA_TABLE_ENTRY (x64): InMemoryOrderLinks @ +0x10
#define LDR_INMEMORY_OFFSET       0x10
#define LDR_DLLBASE_OFFSET        0x30
#define LDR_SIZEIMAGE_OFFSET      0x40
#define LDR_BASENAME_OFFSET       0x58

static PVOID  g_NtdllBase = nullptr;
static SIZE_T g_NtdllSize = 0;

// PEB_LDR_DATA 布局 (WDK 未完整公开, 自定义; 19045 x64 稳定)
typedef struct _ZETA_PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID      EntryInProgress;
} ZETA_PEB_LDR_DATA;

#define EPROCESS_PEB_OFFSET   0x550   // EPROCESS->Peb (19045 x64)
#define PEB_LDR_OFFSET        0x18    // PEB->Ldr (x64)

// PDB 解析偏移覆盖: Resolved 非 0 用 Resolved (跨 build 精确), 否则回退硬编码宏
static __inline ULONG KOFF(ULONG Resolved, ULONG Fallback) {
    return Resolved ? Resolved : Fallback;
}

// 从当前进程 PEB 遍历找 ntdll (缓存一次; ntdll 基址系统范围内稳定)
static BOOLEAN GetNtdllRange(PVOID* Base, SIZE_T* Size) {
    if (g_NtdllBase && g_NtdllSize) {
        *Base = g_NtdllBase; *Size = g_NtdllSize;
        return TRUE;
    }
    PEPROCESS cur = PsGetCurrentProcess();
    if (!cur) return FALSE;
    PVOID peb = nullptr;
    __try {
        peb = *(PVOID*)((PUCHAR)cur + KOFF(g_OffEprocessPeb, EPROCESS_PEB_OFFSET));
    } __except (EXCEPTION_EXECUTE_HANDLER) { return FALSE; }
    if (!peb) return FALSE;
    __try {
        ZETA_PEB_LDR_DATA* ldr = *(ZETA_PEB_LDR_DATA**)((PUCHAR)peb + KOFF(g_OffPebLdr, PEB_LDR_OFFSET));
        if (!ldr || !ldr->InMemoryOrderModuleList.Flink) return FALSE;
        PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
        for (PLIST_ENTRY le = head->Flink; le != head && le != nullptr; le = le->Flink) {
            PVOID dllBase  = *(PVOID*)((PUCHAR)le -
                KOFF(g_OffLdrInMemoryLinks, LDR_INMEMORY_OFFSET) +
                KOFF(g_OffLdrDllBase, LDR_DLLBASE_OFFSET));
            SIZE_T imgSize = *(SIZE_T*)((PUCHAR)le -
                KOFF(g_OffLdrInMemoryLinks, LDR_INMEMORY_OFFSET) +
                KOFF(g_OffLdrSizeOfImage, LDR_SIZEIMAGE_OFFSET));
            UNICODE_STRING* baseName =
                (UNICODE_STRING*)((PUCHAR)le -
                    KOFF(g_OffLdrInMemoryLinks, LDR_INMEMORY_OFFSET) +
                    KOFF(g_OffLdrBaseDllName, LDR_BASENAME_OFFSET));
            if (baseName->Buffer && baseName->Length >= 16) {
                // 比较 "ntdll.dll" (宽字符 16 字节)
                if (RtlCompareMemory(baseName->Buffer, L"ntdll.dll", 16) == 16) {
                    g_NtdllBase = dllBase;
                    g_NtdllSize = imgSize;
                    *Base = dllBase; *Size = imgSize;
                    return TRUE;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return FALSE;
}

// 读当前线程用户态 RIP (TrapFrame; 校验指针合法性, 失败返回 NULL 不蓝屏)
static PVOID GetUserRip() {
    PKTHREAD thread = KeGetCurrentThread();
    if (!thread) return nullptr;
    PVOID tf = *(PVOID*)((PUCHAR)thread + KOFF(g_OffKthreadTrapFrame, KTHREAD_TRAPFRAME_OFFSET));
    if (!tf || (ULONG_PTR)tf < 0xFFFF000000000000ULL) return nullptr;  // 内核地址
    PVOID rip = *(PVOID*)((PUCHAR)tf + KOFF(g_OffKtrapFrameRip, KTRAPFRAME_RIP_OFFSET));
    if (!rip || (ULONG_PTR)rip < 0x10000 ||
        (ULONG_PTR)rip >= 0x00007FFFFFFFFFFFULL) return nullptr;       // 用户地址
    return rip;
}

// 判断本次 syscall 调用者 RIP 是否非 ntdll (疑似内联/间接 syscall)
static BOOLEAN IsSyscallFromNonNtdll() {
    PVOID rip = GetUserRip();
    if (!rip) return FALSE;
    PVOID nb = nullptr; SIZE_T ns = 0;
    if (!GetNtdllRange(&nb, &ns) || !nb || ns == 0) return FALSE;
    ULONG_PTR r = (ULONG_PTR)rip, b = (ULONG_PTR)nb;
    if (r >= b && r < b + ns) return FALSE;   // RIP 在 ntdll → 正常 syscall
    return TRUE;                               // RIP 非 ntdll → 疑似绕过
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

    // ── P4: 间接/内联 syscall 检测 ──
    // 跨进程注入用非 ntdll 桩调用 (RIP 非 ntdll) = 高级手法
    // 反制模式: 规则 syscall_spoof_block 开启后 → 直接拒绝
    if (IsSyscallFromNonNtdll()) {
        if (g_SyscallSpoofBlock) {
            ZETA_WARN("InjectHook: CreateRemoteThread non-ntdll rip BLOCKED (PID=%lu -> %lu)\n", src, dst);
            InjectReport(ZETA_MSG_SYSCALL_SPOOF, src, dst, 2);  // 2 = blocked
            return STATUS_ACCESS_DENIED;
        }
        ZETA_WARN("InjectHook: CreateRemoteThread PID=%lu non-ntdll rip (spoof syscall) observed\n", src);
        InjectReport(ZETA_MSG_SYSCALL_SPOOF, src, dst, 0);
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

    // ── P2-优先级3: 写入内容轻量级扫描 (MZ / shellcode 特征) ──
    // 采样 Buffer 前 64 字节 (PASSIVE_LEVEL, __try+ProbeForRead 安全读用户缓冲)。
    // 性能: 仅跨进程+源不可信时采样, 非热点路径。
    BOOLEAN hasMZ = FALSE, hasShellcode = FALSE;
    if (writeBytes > 0 && Buffer) {
        __try {
            UCHAR head[64] = { 0 };
            SIZE_T probeLen = (writeBytes < sizeof(head)) ? writeBytes : sizeof(head);
            ProbeForRead(Buffer, probeLen, 1);
            RtlCopyMemory(head, Buffer, probeLen);
            // MZ = PE 头 (跨进程写入 = 注入/镂空载荷)
            if (head[0] == 0x4D && head[1] == 0x5A) hasMZ = TRUE;
            // 0xFC 0x48 0x83 = x64 shellcode 经典开头 (cld; rex.w; opcode)
            if (head[0] == 0xFC && head[1] == 0x48 && head[2] == 0x83) hasShellcode = TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // 用户缓冲不可读 → 跳过扫描 (写入由内核后续处理)
        }
    }

    // ── shellcode 特征 → 直接拒绝 (紧急拦截) ──
    if (hasShellcode) {
        ZETA_WARN("InjectHook: WriteProcessMemory shellcode(0xFC 48 83) PID=%lu -> PID=%lu DENIED\n",
                  src, dst);
        InjectReport(ZETA_MSG_WRITE_MEM_SHELLCODE, src, dst, 1);
        return STATUS_ACCESS_DENIED;
    }

    // ── P4: 间接/内联 syscall 检测 ──
    // 反制模式: 规则 syscall_spoof_block 开启后 → 跨进程写直接拒绝
    if (IsSyscallFromNonNtdll()) {
        if (g_SyscallSpoofBlock) {
            ZETA_WARN("InjectHook: WriteProcessMemory non-ntdll rip BLOCKED (PID=%lu -> %lu)\n", src, dst);
            InjectReport(ZETA_MSG_SYSCALL_SPOOF, src, dst, 2);  // 2 = blocked
            return STATUS_ACCESS_DENIED;
        }
        ZETA_WARN("InjectHook: WriteProcessMemory PID=%lu non-ntdll rip (spoof syscall) observed\n", src);
        InjectReport(ZETA_MSG_SYSCALL_SPOOF, src, dst, 0);
    }

    // ── 跨进程写未保护目标 → 上报记录 (MZ 命中上报载荷特征, 其余常规) ──
    if (hasMZ) {
        ZETA_WARN("InjectHook: WriteProcessMemory MZ(PE) PID=%lu -> PID=%lu observed\n", src, dst);
        InjectReport(ZETA_MSG_WRITE_MEM_PE, src, dst, (ULONG)(writeBytes & 0xFFFFFFFF));
    } else {
        ZETA_WARN("InjectHook: WriteProcessMemory PID=%lu -> PID=%lu (%Iu bytes) observed\n",
                  src, dst, writeBytes);
        InjectReport(ZETA_MSG_WRITE_MEM_INJECT, src, dst, 0);
    }
    return orig(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

// ============================================================================
// NtUnmapViewOfSection 处理函数 (P2-优先级2: 进程镂空前置"清空")
// 跨进程解映射 (目标进程 view 被 unmap) = 镂空第一步。同进程解映射放行。
// ============================================================================
NTSTATUS NTAPI InjectHook_NtUnmapViewOfSection(
    HANDLE ProcessHandle, PVOID BaseAddress) {
    pfnNtUnmapViewOfSection orig = g_OrigNtUnmapViewOfSection;
    if (!orig) return STATUS_ACCESS_DENIED;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL || !g_InjectHookActive ||
        !InjectUserConnected() || !ProcessHandle) {
        return orig(ProcessHandle, BaseAddress);
    }

    ULONG src = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    PEPROCESS TargetProcess = nullptr;
    NTSTATUS status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_VM_OPERATION,
        *PsProcessType, KernelMode, (PVOID*)&TargetProcess, nullptr);
    ULONG dst = 0;
    if (NT_SUCCESS(status) && TargetProcess) {
        dst = (ULONG)(ULONG_PTR)PsGetProcessId(TargetProcess);
        ObDereferenceObject(TargetProcess);
    }
    if (dst == 0) {
        return orig(ProcessHandle, BaseAddress);
    }

    // ── 放行快速路径 ──
    if (src == dst)                       // 解映射自己 (正常: 加载器/运行时)
        return orig(ProcessHandle, BaseAddress);
    if (src == (ULONG)GlobalData.ZetaPid) // ZETA 自身
        return orig(ProcessHandle, BaseAddress);
    if (src == 4)                         // System
        return orig(ProcessHandle, BaseAddress);
    if (g_LearningModeActive)             // 学习模式
        return orig(ProcessHandle, BaseAddress);
    if (!g_ProcessProtectEnabled)         // 开关关闭
        return orig(ProcessHandle, BaseAddress);
    if (InjectSourceTrusted(src))         // 源受信任 → 放行
        return orig(ProcessHandle, BaseAddress);

    // ── 跨进程解映射 = 进程镂空前置"清空" ──
    // 目标受保护 + 源不可信 → 直接拒绝 (镂空第一步就被拦)
    if (InjectTargetProtected(dst)) {
        ZETA_WARN("InjectHook: UnmapViewOfSection PID=%lu -> protected PID=%lu DENIED\n",
                  src, dst);
        InjectReport(ZETA_MSG_UNMAP_VIEW, src, dst, 1);  // 1 = denied
        return STATUS_ACCESS_DENIED;
    }

    // ── 跨进程解映射未保护目标 → 上报 (放行留痕, 行为引擎收镂空链) ──
    ZETA_WARN("InjectHook: UnmapViewOfSection PID=%lu -> PID=%lu observed\n", src, dst);
    InjectReport(ZETA_MSG_UNMAP_VIEW, src, dst, 0);      // 0 = observed
    return orig(ProcessHandle, BaseAddress);
}

// ============================================================================
// P4-反制开关: 间接/内联 syscall + 跨进程操作 → 直接拒绝
// 由用户态状态机规则 syscall_spoof_block 命中后经 ZETA_CMD_SET_SYSCALL_SPOOF_BLOCK 开启
// ============================================================================
NTSTATUS InjectHook_SetSyscallSpoofBlock(BOOLEAN Enable) {
    g_SyscallSpoofBlock = Enable ? TRUE : FALSE;
    KeMemoryBarrier();
    ZETA_INFO("InjectHook: syscall-spoof block mode %s\n", Enable ? "ENABLED" : "disabled");
    return STATUS_SUCCESS;
}

// ============================================================================
// 启用 / 禁用
// ============================================================================
NTSTATUS InjectHook_Enable(ULONG CreateThreadSyscall, ULONG WriteMemSyscall,
    ULONG UnmapSyscall, ULONG ValidateSyscall) {
    if (g_InjectHookActive) return STATUS_SUCCESS;  // 幂等

    if (CreateThreadSyscall == 0 || WriteMemSyscall == 0 ||
        UnmapSyscall == 0 || ValidateSyscall == 0)
        return STATUS_INVALID_PARAMETER;
    if (CreateThreadSyscall >= 0x800 || WriteMemSyscall >= 0x800 ||
        UnmapSyscall >= 0x800 || ValidateSyscall >= 0x800)
        return STATUS_INVALID_PARAMETER;
    if (CreateThreadSyscall == ValidateSyscall || WriteMemSyscall == ValidateSyscall ||
        UnmapSyscall == ValidateSyscall)
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
        (table + WriteMemSyscall * 4) >= ((ULONG_PTR)base + size) ||
        (table + UnmapSyscall * 4) >= ((ULONG_PTR)base + size)) {
        ZETA_ERROR("InjectHook: syscall out of range\n");
        return STATUS_INVALID_PARAMETER;
    }

    // 依次打补丁 (Unmap → Write → Create); 任一失败回滚已打的, 保证原子。
    ULONG_PTR origUnmap = 0, origWrite = 0, origCreate = 0;

    status = PatchSsdtEntry(table, UnmapSyscall,
        (ULONG_PTR)&InjectHook_NtUnmapViewOfSection, &origUnmap);
    if (!NT_SUCCESS(status)) {
        ZETA_ERROR("InjectHook: UnmapViewOfSection patch failed (0x%08X)\n", status);
        return status;
    }

    status = PatchSsdtEntry(table, WriteMemSyscall,
        (ULONG_PTR)&InjectHook_NtWriteVirtualMemory, &origWrite);
    if (!NT_SUCCESS(status)) {
        PatchSsdtEntry(table, UnmapSyscall, origUnmap, nullptr);
        ZETA_ERROR("InjectHook: WriteVirtualMemory patch failed (0x%08X), rolled back\n", status);
        return status;
    }

    status = PatchSsdtEntry(table, CreateThreadSyscall,
        (ULONG_PTR)&InjectHook_NtCreateThreadEx, &origCreate);
    if (!NT_SUCCESS(status)) {
        PatchSsdtEntry(table, UnmapSyscall, origUnmap, nullptr);
        PatchSsdtEntry(table, WriteMemSyscall, origWrite, nullptr);
        ZETA_ERROR("InjectHook: CreateThreadEx patch failed (0x%08X), rolled back\n", status);
        return status;
    }

    g_OrigNtCreateThreadEx = (pfnNtCreateThreadEx)origCreate;
    g_OrigNtWriteVirtualMemory = (pfnNtWriteVirtualMemory)origWrite;
    g_OrigNtUnmapViewOfSection = (pfnNtUnmapViewOfSection)origUnmap;
    g_KiServiceTable = table;
    g_CreateThreadSyscall = CreateThreadSyscall;
    g_WriteMemSyscall = WriteMemSyscall;
    g_UnmapSyscall = UnmapSyscall;
    KeMemoryBarrier();
    g_InjectHookActive = TRUE;

    ZETA_INFO("InjectHook enabled: Create=%lu Write=%lu Unmap=%lu origC=0x%p origW=0x%p origU=0x%p\n",
              CreateThreadSyscall, WriteMemSyscall, UnmapSyscall,
              (PVOID)origCreate, (PVOID)origWrite, (PVOID)origUnmap);
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
    if (g_KiServiceTable && g_OrigNtUnmapViewOfSection && g_UnmapSyscall) {
        PatchSsdtEntry(g_KiServiceTable, g_UnmapSyscall,
            (ULONG_PTR)g_OrigNtUnmapViewOfSection, nullptr);
    }
    ZETA_INFO("InjectHook disabled (SSDT restored)\n");

    g_OrigNtCreateThreadEx = nullptr;
    g_OrigNtWriteVirtualMemory = nullptr;
    g_OrigNtUnmapViewOfSection = nullptr;
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

#endif // ZETA_ENABLE_SSDT
