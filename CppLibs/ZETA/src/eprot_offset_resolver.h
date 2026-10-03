#pragma once
#include <Windows.h>

// ============================================================
// eprot_offset_resolver.h — 通用内核结构偏移解析器
//
// 自研轻量 PDB 解析器 (MSF + TPI), 从本地 PDB 精确解析内核结构
// 字段偏移, 覆盖全部硬编码的内核结构偏移 (跨 build 自适应)。
//
// 用法: 启动时调用 ResolveKernelOffsets() 获取偏移表,
// 经 ZETA_CMD_SET_KERNEL_OFFSETS 下发给驱动替换硬编码宏。
// ============================================================

// 内核结构偏移表 (全部为 0 = 未解析, 驱动回退硬编码)
struct KernelOffsets {
    LONG EprocessProtection;    // _EPROCESS.Protection
    LONG EprocessPeb;           // _EPROCESS.Peb
    LONG KthreadTrapFrame;      // _KTHREAD.TrapFrame
    LONG KtrapFrameRip;         // _KTRAP_FRAME.Rip
    LONG PebLdr;                // _PEB.Ldr
    LONG LdrInMemoryLinks;      // _LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks
    LONG LdrDllBase;            // _LDR_DATA_TABLE_ENTRY.DllBase
    LONG LdrSizeOfImage;        // _LDR_DATA_TABLE_ENTRY.SizeOfImage
    LONG LdrBaseDllName;        // _LDR_DATA_TABLE_ENTRY.BaseDllName
    LONG KldrFlags;             // _KLDR_DATA_TABLE_ENTRY.Flags
    LONG KldrSignatureLevel;    // _KLDR_DATA_TABLE_ENTRY.SignatureLevel
};

#ifdef __cplusplus
extern "C" {
#endif

// 解析全部内核结构偏移 (从 _NT_SYMBOL_PATH 符号目录)。
// 返回成功解析的偏移数量 (0 = 全部失败, 调用方保持硬编码)。
__declspec(dllexport) int ResolveKernelOffsets(KernelOffsets* out);

// 兼容入口: 仅解析 _EPROCESS.Protection (PPL DKOM 用)。
__declspec(dllexport) LONG ResolveEprocessProtectionOffset();

#ifdef __cplusplus
}
#endif
