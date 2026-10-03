#pragma once
#include <Windows.h>

#ifdef ZETA_CORE_EXPORTS
#define ZETA_CORE_API __declspec(dllexport)
#else
#define ZETA_CORE_API __declspec(dllimport)
#endif

// ============================================================
// TrustProvider — 统一信任判定 (P1-1)
//
// 解决历史遗留: 主程序 / 行为引擎 / 扫描引擎三处各自实现 WinVerifyTrust。
//
// 本组件只回答一个问题: 这个文件是否有有效嵌入数字签名?
// (不含路径判定 — 系统目录文件的信任由 main.cpp 的"精确前缀兜底"另行处理)
//
// 历史: 曾加入 Catalog 签名验证 (CryptCATAdmin) 以识别嵌入签名缺失的
// 系统文件, 但该 API 存在阻塞风险 (死循环 + 内部阻塞) 导致行为引擎 worker
// 卡死/退出死锁, 已移除。系统文件信任改由前缀兜底 (P1-2) 承担。
// ============================================================

// 签名判定结果 (C 接口返回对应 int)
enum TrustVerdict {
    TRUST_UNKNOWN        = 0,  // 文件不存在 / 无法打开 (进程已退出等)
    TRUST_UNTRUSTED      = 1,  // 无有效嵌入签名
    TRUST_SIGNED         = 2,  // 嵌入签名验证通过
    TRUST_CATALOG        = 3,  // (保留, 兼容; 当前实现不再返回此值)
};

#ifdef __cplusplus
extern "C" {
#endif

// 验证文件签名 (嵌入签名优先, 失败后走 Catalog 通道)。
// 内部带缓存 (path + LastWriteTime), 高频调用无性能负担。
// 返回 TrustVerdict 枚举值之一。
ZETA_CORE_API int zeta_core_trust_verify(const wchar_t* path);

// 便捷: 是否可信 (SIGNED 或 CATALOG)
ZETA_CORE_API int zeta_core_trust_is_trusted(const wchar_t* path);

#ifdef __cplusplus
}
#endif
