#include "trust.h"

#include <fstream>
#include <sstream>
#include <algorithm>

// ============================================================
// 简单 JSON 辅助: 提取 "key": ["a", "b", ...] 的字符串数组
// (仅支持本项目 TrustRules.json 的扁平结构, 不做通用 JSON 解析)
// ============================================================
static std::wstring toLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

static std::vector<std::wstring> extractStringArray(const std::wstring& json, const std::wstring& key) {
    std::vector<std::wstring> out;
    // 定位 "key"
    std::wstring needle = L"\"" + key + L"\"";
    size_t keyPos = json.find(needle);
    if (keyPos == std::wstring::npos) return out;

    size_t open = json.find(L'[', keyPos);
    if (open == std::wstring::npos) return out;
    size_t close = json.find(L']', open);
    if (close == std::wstring::npos) return out;

    // 提取 [ ... ] 之间的 "字符串"
    size_t i = open + 1;
    while (i < close) {
        size_t q1 = json.find(L'"', i);
        if (q1 == std::wstring::npos || q1 >= close) break;
        size_t q2 = json.find(L'"', q1 + 1);
        if (q2 == std::wstring::npos || q2 > close) break;
        std::wstring item = json.substr(q1 + 1, q2 - q1 - 1);
        if (!item.empty()) out.push_back(item);
        i = q2 + 1;
    }
    return out;
}

// ============================================================
// 内置默认名单 (loadRules 失败时回退)
// ============================================================
void TrustDecider::loadDefaults() {
    m_systemProcesses.clear();
    static const wchar_t* names[] = {
        L"msiexec.exe", L"svchost.exe", L"services.exe", L"lsass.exe",
        L"csrss.exe", L"smss.exe", L"wininit.exe", L"winlogon.exe",
        L"dllhost.exe", L"rundll32.exe", L"regsvr32.exe", L"msbuild.exe",
        L"cmd.exe", L"powershell.exe", L"pwsh.exe", L"conhost.exe",
        L"notepad.exe", L"explorer.exe", L"taskhostw.exe",
        L"SearchFilterHost.exe", L"SearchIndexer.exe", L"SearchProtocolHost.exe",
        L"TiWorker.exe", L"TrustedInstaller.exe", L"DismHost.exe",
        L"WmiPrvSE.exe", L"RuntimeBroker.exe", L"backgroundTaskHost.exe",
        L"WWAHost.exe", L"SystemSettings.exe", L"mmc.exe", L"control.exe",
        L"fontdrvhost.exe", L"sihost.exe", L"ctfmon.exe",
        L"ShellExperienceHost.exe", L"ApplicationFrameHost.exe",
        L"GameInputSvc.exe", L"MoFUsbHost.exe", L"devenv.exe",
        L"compmgmt.exe", L"mshta.exe",
    };
    for (auto* n : names) m_systemProcesses.insert(toLower(n));

    m_trustedPrefixes = {
        L"\\windows\\system32\\",
        L"\\windows\\syswow64\\",
        L"\\windows\\systemapps\\",
        L"\\program files\\",
        L"\\program files (x86)\\",
        L"\\windowsapps\\",
    };

    m_excludedSubdirs = {
        L"\\windows\\system32\\tasks\\",
        L"\\windows\\system32\\spool\\",
        L"\\windows\\system32\\config\\",
        L"\\windows\\system32\\systemprofile\\",
    };
}

// ============================================================
// 依赖注入
// ============================================================
TrustDecider& TrustDecider::instance() {
    static TrustDecider inst;
    return inst;
}

void TrustDecider::init(NameResolver nameFn, PathResolver pathFn, SignatureVerifier sigFn) {
    m_nameFn = std::move(nameFn);
    m_pathFn = std::move(pathFn);
    m_sigFn = std::move(sigFn);
    loadDefaults();
}

// ============================================================
// JSON 名单加载
// ============================================================
bool TrustDecider::loadRules(const std::wstring& jsonPath) {
    std::ifstream f(jsonPath, std::ios::binary);
    if (!f.is_open()) return false;
    std::stringstream ss;
    ss << f.rdbuf();
    std::string utf8 = ss.str();
    if (utf8.empty()) return false;

    // UTF-8 → wstring (名单均为 ASCII 路径/进程名, 简单转换即可)
    std::wstring json;
    json.reserve(utf8.size());
    for (unsigned char c : utf8) json.push_back((wchar_t)c);

    auto procs = extractStringArray(json, L"system_processes");
    auto prefixes = extractStringArray(json, L"trusted_prefixes");
    auto excluded = extractStringArray(json, L"excluded_subdirs");

    if (procs.empty() && prefixes.empty() && excluded.empty()) return false;

    if (!procs.empty()) {
        m_systemProcesses.clear();
        for (auto& p : procs) m_systemProcesses.insert(toLower(p));
    }
    if (!prefixes.empty()) {
        m_trustedPrefixes.clear();
        for (auto& p : prefixes) m_trustedPrefixes.push_back(toLower(p));
    }
    if (!excluded.empty()) {
        m_excludedSubdirs.clear();
        for (auto& p : excluded) m_excludedSubdirs.push_back(toLower(p));
    }
    return true;
}

// ============================================================
// 盘符无关精确前缀匹配 (统一: 替代旧 substring 匹配)
// ============================================================
bool TrustDecider::startsWithDrivePath(const std::wstring& lower, const std::wstring& subPath) {
    size_t n = subPath.size();
    // "c:\..." 形式: 跳过盘符前 2 字符从 ":\" 处对齐
    if (lower.size() >= 3 && lower[1] == L':' && lower[2] == L'\\') {
        return lower.compare(2, n, subPath) == 0;
    }
    // "\\?\..." 或裸路径: 退化为前缀匹配
    return lower.compare(0, n, subPath) == 0;
}

bool TrustDecider::isTrustedPath(const std::wstring& path) const {
    if (path.empty()) return false;
    std::wstring lower = toLower(path);
    if (lower.rfind(L"\\??\\", 0) == 0) lower = lower.substr(4);

    for (const auto& t : m_trustedPrefixes) {
        if (startsWithDrivePath(lower, t)) {
            // 排除 System32 下的恶意藏身子目录
            for (const auto& ex : m_excludedSubdirs) {
                if (startsWithDrivePath(lower, ex)) return false;
            }
            return true;
        }
    }
    return false;
}

// ============================================================
// 查询接口
// ============================================================
bool TrustDecider::isKnownSystemProcess(const std::wstring& procName) const {
    if (procName.empty()) return false;
    return m_systemProcesses.count(toLower(procName)) > 0;
}

bool TrustDecider::isTrustedSystemSource(unsigned long pid) const {
    if (pid == 0 || pid == 4) return true;  // Idle / System
    if (m_nameFn && isKnownSystemProcess(m_nameFn(pid))) return true;
    if (m_pathFn) {
        if (isTrustedPath(m_pathFn(pid))) return true;
    }
    return false;
}

bool TrustDecider::isFileTrusted(const std::wstring& path) const {
    if (path.empty()) return false;
    // 1) 有效签名
    if (m_sigFn) {
        int verdict = m_sigFn(path);
        // 2=TRUST_SIGNED, 3=TRUST_CATALOG (与 zeta_core trust_provider.h 一致)
        if (verdict == 2 || verdict == 3) return true;
    }
    // 2) 系统目录精确前缀兜底
    return isTrustedPath(path);
}

bool TrustDecider::isTrustedProcess(unsigned long pid) const {
    // 系统来源 (进程名/目录) 或 有效签名
    if (isTrustedSystemSource(pid)) return true;
    if (m_pathFn) {
        std::wstring path = m_pathFn(pid);
        if (!path.empty() && m_sigFn) {
            int verdict = m_sigFn(path);
            if (verdict == 2 || verdict == 3) return true;
        }
    }
    return false;
}

bool TrustDecider::isSafeToAutoKill(unsigned long pid) const {
    return !isTrustedProcess(pid);
}
