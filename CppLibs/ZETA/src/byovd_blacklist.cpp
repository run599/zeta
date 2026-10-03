#include "byovd_blacklist.h"

#include <bcrypt.h>
#include <cstdio>
#include <cstring>

// bcrypt.lib 用 #pragma comment 引入, 而不是改共享的 CppLibs/ZETA/CMakeLists.txt。
// 理由: 该 CMakeLists 是多个目标共用的配置面, 为了一个 .cpp 的依赖去动它,
// 会把改动半径扩大到所有构建者; 而这条 pragma 只在本编译单元生效, 自洽且可发现。
#pragma comment(lib, "bcrypt.lib")

namespace {

// ============================================================================
// 黑名单表
//
// ⚠ 只放【经查证】的条目。宁少勿假 —— 一个错误的哈希要么永远不命中(白写),
//   要么撞上正常文件(误报隔离)。加条目时请照抄 LOLDrivers 的 SHA256 字段,
//   并把来源与收录日期写进 source, 便于日后核对是否已被厂商更新/吊销。
// ============================================================================
const ByovdEntry kBlacklist[] = {
    {
        "HP_SWTOOLS_DRIVER.sys",
        "bf07c46effde8b6b0fd3c9586a5a9636800fb37418c1e8e606c67cb613cbf832",
        L"\\\\.\\HP_WKS_SWTOOLS_DRIVER",
        "LOLDrivers 19f13965-7078-4c19-a2e3-71ab8b77a9b7 (added 2026-08-29), "
        "publisher HP Inc., version 1.5.0.0, MITRE T1068. Exposes MSR read/write, "
        "performance counters, physical/MMIO mapping and read/write, PCI config, "
        "port I/O and a CPU-halt path. Confirmed in use as the BYOVD stage of the "
        "sample analysed at E:\\yuan-kong\\cs (drops to %TEMP%\\<hex>.sys, loads via "
        "NtLoadDriver under a randomised service name, then opens "
        "\\??\\HP_WKS_SWTOOLS_DRIVER)."
    },
};

const size_t kBlacklistCount = sizeof(kBlacklist) / sizeof(kBlacklist[0]);

// SHA256 -> 小写十六进制
std::string ToHexLower(const BYTE* data, size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0x0F]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    return out;
}

// 流式 SHA256 (CNG)。文件可能几十~几百 KB, 分块读, 不整文件进内存。
bool Sha256OfFile(const std::wstring& path, BYTE out[32]) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    BCRYPT_ALG_HANDLE hAlg  = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::vector<BYTE> hashObj;
    std::vector<BYTE> buf;
    bool ok = false;

    do {
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
                &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
            break;
        }

        ULONG objLen = 0, cb = 0;
        if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                                              reinterpret_cast<PUCHAR>(&objLen),
                                              sizeof(objLen), &cb, 0))) {
            break;
        }
        hashObj.resize(objLen);
        if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, hashObj.data(), objLen,
                                             nullptr, 0, 0))) {
            break;
        }

        buf.resize(64 * 1024);
        bool readDone = false;
        for (;;) {
            DWORD rd = 0;
            if (!ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()), &rd, nullptr)) {
                break;                       // 读失败 → ok 保持 false
            }
            if (rd == 0) { readDone = true; break; }   // EOF
            if (!BCRYPT_SUCCESS(BCryptHashData(hHash, buf.data(), rd, 0))) {
                break;
            }
        }
        if (!readDone) break;

        if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, out, 32, 0))) break;
        ok = true;
    } while (false);

    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(h);
    return ok;
}

// 大小写无关比较, 且容忍表里写了 64 字符小写十六进制
bool HexEquals(const std::string& a, const char* b) {
    if (!b) return false;
    size_t n = strlen(b);
    if (a.size() != n) return false;
    for (size_t i = 0; i < n; ++i) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'F') x = static_cast<char>(x - 'A' + 'a');
        if (y >= 'A' && y <= 'F') y = static_cast<char>(y - 'A' + 'a');
        if (x != y) return false;
    }
    return true;
}

} // namespace

namespace ByovdBlacklist {

size_t EntryCount() { return kBlacklistCount; }

std::string Sha256Hex(const std::wstring& path) {
    BYTE digest[32] = {0};
    if (!Sha256OfFile(path, digest)) return std::string();
    return ToHexLower(digest, sizeof(digest));
}

std::wstring NormalizeToWin32Path(const std::wstring& in) {
    // \SystemRoot\... → <Windows>\...
    static const wchar_t kSysRoot[] = L"\\SystemRoot\\";
    const size_t kSysRootLen = 11;   // 不含末尾反斜杠: "\SystemRoot" 共 11 字符
    if (in.size() > kSysRootLen &&
        in.compare(0, kSysRootLen + 1, kSysRoot) == 0) {
        wchar_t winDir[MAX_PATH] = {0};
        UINT n = GetWindowsDirectoryW(winDir, MAX_PATH);
        if (n > 0 && n < MAX_PATH) {
            return std::wstring(winDir) + in.substr(kSysRootLen);
        }
        return in;
    }

    // \??\C:\... → C:\...
    if (in.compare(0, 4, L"\\??\\") == 0) {
        return in.substr(4);
    }

    return in;
}

bool MatchFileHash(const std::wstring& path, const ByovdEntry** outEntry) {
    if (outEntry) *outEntry = nullptr;
    if (path.empty()) return false;

    const std::wstring win32Path = NormalizeToWin32Path(path);
    const std::string sha = Sha256Hex(win32Path);
    if (sha.empty()) return false;      // 读不到就静默放过, 这是尽力检测路径

    for (size_t i = 0; i < kBlacklistCount; ++i) {
        if (HexEquals(sha, kBlacklist[i].sha256)) {
            if (outEntry) *outEntry = &kBlacklist[i];
            return true;
        }
    }
    return false;
}

std::vector<std::wstring> ProbeLoadedDevices() {
    std::vector<std::wstring> live;

    for (size_t i = 0; i < kBlacklistCount; ++i) {
        const wchar_t* dev = kBlacklist[i].devicePath;
        if (!dev) continue;

        // 访问权限刻意传 0: 只要对象存在, 设备打开就会成功, 我们不需要任何权限,
        // 更不发 IOCTL —— 探测必须零副作用(否则等于主动去调一个漏洞驱动的入口)。
        HANDLE h = CreateFileW(dev, 0,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            live.push_back(std::wstring(dev) +
                           L"  [ " + std::wstring(kBlacklist[i].name,
                                                  kBlacklist[i].name + strlen(kBlacklist[i].name)) + L" ]");
            continue;
        }

        // 关键细节: 设备【存在但拒绝访问】同样证明它在本机 —— 报"不存在"会漏报。
        // (ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND 才是真的没有。)
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            live.push_back(std::wstring(dev) +
                           L"  [ " + std::wstring(kBlacklist[i].name,
                                                  kBlacklist[i].name + strlen(kBlacklist[i].name)) +
                           L" , 拒绝访问但对象存在 ]");
        }
    }

    return live;
}

} // namespace ByovdBlacklist
