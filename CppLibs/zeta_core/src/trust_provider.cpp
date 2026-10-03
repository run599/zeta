#include "zeta_core.h"
#include "trust_provider.h"

#include <wintrust.h>
#include <softpub.h>
#include <unordered_map>
#include <mutex>

#pragma comment(lib, "wintrust.lib")

// ============================================================
// TrustProvider — 统一信任判定 (P1-1)
//
// 只做嵌入签名验证 (WinVerifyTrust, WTD_CHOICE_FILE)。
//
// 历史: P1-1 曾加入 Catalog 签名验证 (CryptCATAdmin 系列), 用于识别
// 嵌入签名缺失的系统文件 (签名在 catroot 的 catalog 里)。但实测发现
// CryptCATAdmin 系列 API 存在阻塞风险:
//   1) 枚举游标误重置 → 死循环 (已修复)
//   2) 修复后仍偶发 API 内部阻塞 → 行为引擎 worker 卡死 → 退出时 join 永久等待
// 且系统文件信任已由 main.cpp 的"系统目录精确前缀兜底"(startsWithDrivePath,
// P1-2) 覆盖, catalog 验证价值有限。故移除 catalog 通道, 只保留嵌入签名 + 缓存。
// ============================================================

// ============================================================
// 内部: 嵌入签名验证 (WinVerifyTrust, WTD_CHOICE_FILE)
// ============================================================
static LONG verifyEmbeddedSignature(const std::wstring& normPath) {
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = normPath.c_str();

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wtd{};
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &fileInfo;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG status = WinVerifyTrust(NULL, &policyGUID, &wtd);

    WINTRUST_DATA wtdClose = wtd;
    wtdClose.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &wtdClose);

    return status;
}

// ============================================================
// 路径规范化: 去掉 \??\ 内核前缀
// ============================================================
static std::wstring normalizePath(const std::wstring& path) {
    if (path.empty()) return path;
    std::wstring norm = path;
    if (norm.rfind(L"\\??\\", 0) == 0) norm = norm.substr(4);
    return norm;
}

// ============================================================
// 缓存: path -> (LastWriteTime, verdict)
// 以 LastWriteTime 作为失效依据, 防止文件被替换后缓存误导。
// ============================================================
struct TrustCacheEntry {
    FILETIME lastWrite{};
    int verdict = TRUST_UNKNOWN;
};

static std::unordered_map<std::wstring, TrustCacheEntry> g_trustCache;
static std::mutex g_trustCacheMtx;

static int verifyFileTrust(const std::wstring& path) {
    if (path.empty()) return TRUST_UNKNOWN;

    std::wstring norm = normalizePath(path);
    if (norm.empty()) return TRUST_UNKNOWN;

    // 取文件 LastWriteTime 作为缓存 key 的一部分
    WIN32_FILE_ATTRIBUTE_DATA attr{};
    FILETIME lastWrite{};
    bool attrOk = GetFileAttributesExW(norm.c_str(), GetFileExInfoStandard, &attr) != 0;
    if (attrOk) lastWrite = attr.ftLastWriteTime;
    else {
        // 文件不存在 → 无法验证 (进程已退出等)
        return TRUST_UNKNOWN;
    }

    // 查缓存
    {
        std::lock_guard<std::mutex> lk(g_trustCacheMtx);
        auto it = g_trustCache.find(norm);
        if (it != g_trustCache.end()) {
            if (CompareFileTime(&it->second.lastWrite, &lastWrite) == 0) {
                return it->second.verdict;
            }
            g_trustCache.erase(it);  // 文件已变化, 重新验证
        }
    }

    // 嵌入签名验证
    LONG status = verifyEmbeddedSignature(norm);
    int verdict = (status == ERROR_SUCCESS) ? TRUST_SIGNED : TRUST_UNTRUSTED;

    // 写缓存
    {
        std::lock_guard<std::mutex> lk(g_trustCacheMtx);
        if (g_trustCache.size() > 512) g_trustCache.clear();
        TrustCacheEntry e;
        e.lastWrite = lastWrite;
        e.verdict = verdict;
        g_trustCache[norm] = e;
    }

    return verdict;
}

// ============================================================
// C 导出接口 (供 main.cpp 动态加载)
// ============================================================
extern "C" {

ZETA_CORE_API int zeta_core_trust_verify(const wchar_t* path) {
    if (!path) return TRUST_UNKNOWN;
    return verifyFileTrust(path);
}

ZETA_CORE_API int zeta_core_trust_is_trusted(const wchar_t* path) {
    if (!path) return 0;
    int v = verifyFileTrust(path);
    return (v == TRUST_SIGNED || v == TRUST_CATALOG) ? 1 : 0;
}

}
