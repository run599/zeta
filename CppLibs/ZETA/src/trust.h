#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <functional>

// ============================================================
// TrustDecider — 统一信任判定模块 (收敛重构)
//
// 收敛此前散落的 6 个函数:
//   isKnownWindowsSystemProcess / isTrustedSystemSource /
//   zetaVerifyFileTrusted / startsWithDrivePath /
//   isSignedProcess / isSafeToAutoKill
//
// 统一入口 (调用方只问这一处, 不再各写组合逻辑):
//   isTrustedProcess(pid)    — 系统进程名 / 系统目录 / 有效签名 → 可信
//   isTrustedSystemSource(pid) — 系统进程名 / 系统目录 (不含签名)
//   isKnownSystemProcess(name) — 已知系统进程名
//   isFileTrusted(path)      — 有效签名 / 系统目录前缀 (供行为引擎)
//   isSafeToAutoKill(pid)    — 处置闸门 (不可信 → 允许自动终结)
//
// 名单 (系统进程/目录前缀/排除子目录) 通过 loadRules 从 JSON 加载,
// 缺失时回退内置默认名单。
// ============================================================
class TrustDecider {
public:
    using NameResolver = std::function<std::wstring(unsigned long)>;
    using PathResolver = std::function<std::wstring(unsigned long)>;
    using SignatureVerifier = std::function<int(const std::wstring&)>;  // 返回 TrustVerdict

    static TrustDecider& instance();

    // 注入依赖 (main.cpp 加载 zeta_core 后调用一次)
    void init(NameResolver nameFn, PathResolver pathFn, SignatureVerifier sigFn);

    // 加载名单 JSON (可选; 文件缺失/解析失败回退内置默认名单)
    bool loadRules(const std::wstring& jsonPath);

    // ── 查询接口 ──
    bool isKnownSystemProcess(const std::wstring& procName) const;
    bool isTrustedSystemSource(unsigned long pid) const;
    bool isFileTrusted(const std::wstring& path) const;
    bool isTrustedProcess(unsigned long pid) const;
    bool isSafeToAutoKill(unsigned long pid) const;

private:
    TrustDecider() = default;
    TrustDecider(const TrustDecider&) = delete;
    TrustDecider& operator=(const TrustDecider&) = delete;

    // 盘符无关精确前缀匹配 (统一: 替代旧 substring 匹配)
    static bool startsWithDrivePath(const std::wstring& lower, const std::wstring& subPath);
    // 路径是否命中可信前缀且不在排除子目录
    bool isTrustedPath(const std::wstring& path) const;

    void loadDefaults();

    std::unordered_set<std::wstring> m_systemProcesses;  // 小写进程名
    std::vector<std::wstring> m_trustedPrefixes;         // 小写路径前缀
    std::vector<std::wstring> m_excludedSubdirs;         // 小写排除子目录

    NameResolver m_nameFn;
    PathResolver m_pathFn;
    SignatureVerifier m_sigFn;
};
