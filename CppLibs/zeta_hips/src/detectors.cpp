#define _WIN32_WINNT 0x0601
#define WINVER 0x0601
#include "zeta_hips.h"
#include "../../zeta_core/include/zeta_core.h"
#include <Windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <chrono>
#include <algorithm>
#include <set>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

// ============================================================
// SilverFoxDetector
// ============================================================
SilverFoxDetector& SilverFoxDetector::instance() {
    static SilverFoxDetector inst;
    return inst;
}

std::wstring SilverFoxDetector::getPublisher(const std::wstring& filePath) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_publisherCache.find(filePath);
    if (it != m_publisherCache.end()) return it->second;

    std::wstring publisher;

    // Use WinVerifyTrust + CryptQueryObject to get signer
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG hMsg = nullptr;
    DWORD encoding = 0, contentType = 0, formatType = 0;

    if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath.c_str(),
        CERT_QUERY_CONTENT_FLAG_ALL, CERT_QUERY_FORMAT_FLAG_ALL,
        0, &encoding, &contentType, &formatType, &hStore, &hMsg, nullptr)) {

        // Get signer info using the store directly
        // Find the first signer certificate in the store
        PCCERT_CONTEXT pCertCtx = nullptr;
        while ((pCertCtx = CertEnumCertificatesInStore(hStore, pCertCtx)) != nullptr) {
            // Check if certificate has private key / is a signer
            wchar_t nameBuf[512];
            if (CertGetNameStringW(pCertCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0, nullptr, nameBuf, 512)) {
                publisher = nameBuf;
                break;
            }
        }
        if (pCertCtx) CertFreeCertificateContext(pCertCtx);

        if (hMsg) CryptMsgClose(hMsg);
        if (hStore) CertCloseStore(hStore, 0);
    }

    m_publisherCache[filePath] = publisher;

    // Limit cache size
    if (m_publisherCache.size() > 5000) {
        m_publisherCache.clear();
    }

    return publisher;
}

// ── Microsoft signature whitelist ──
// Files signed by Microsoft are excluded from publisher counting,
// since they're a "common denominator" (e.g. VC++ redist DLLs)
// and would cause false positives when threshold is 2.
static bool isMicrosoftPublisher(const std::wstring& pub) {
    return (pub.find(L"Microsoft") != std::wstring::npos);
}

std::wstring SilverFoxDetector::analyze(const std::vector<std::wstring>& filePaths,
    std::wstring& outDetail) {
    if (filePaths.size() < 2) return L"none";

    int signedCount = 0;
    int unsignedCount = 0;
    int msIgnored = 0;
    std::set<std::wstring> uniquePublishers;

    for (const auto& path : filePaths) {
        std::wstring pub = getPublisher(path);
        if (pub.empty()) {
            unsignedCount++;
        } else if (isMicrosoftPublisher(pub)) {
            // Microsoft-signed files are a "common denominator" —
            // skip them entirely so they don't inflate publisher count
            msIgnored++;
        } else {
            signedCount++;
            uniquePublishers.insert(pub);
        }
    }

    int pubCount = (int)uniquePublishers.size();
    int totalRelevant = signedCount + unsignedCount;  // total excluding MS-signed files

    Logger::instance().debug(L"SilverFox", L"Analyze",
        L"Sig=" + std::to_wstring(signedCount) + L" Unsig=" + std::to_wstring(unsignedCount) +
        L" Pubs=" + std::to_wstring(pubCount) + L" MS_ignored=" + std::to_wstring(msIgnored));

    // Early exit: no relevant files left to analyze
    if (totalRelevant == 0) {
        outDetail = L"AllMicrosoft: " + std::to_wstring(msIgnored) + L" files, clean";
        return L"legitimate";
    }

    // SilverFox patterns:
    // 1. All relevant files are signed (regardless of publisher count) → LEGITIMATE
    //    Real SilverFox always includes unsigned or suspiciously signed files
    if (unsignedCount == 0 && totalRelevant == signedCount) {
        outDetail = L"AllSigned: " + std::to_wstring(signedCount) + L" files from " +
                   std::to_wstring(pubCount) + L" publishers";
        return L"legitimate";
    }

    // 2. Mixed signed (non-MS) + unsigned → only SilverFox when
    //    MULTIPLE different publishers are involved.
    //    Single publisher with unsigned helpers = normal installer pattern
    //    (e.g. 360/QQ/Adobe installers with temporary helper executables).
    //    Real "黑加白" SilverFox attacks leverage DIFFERENT publishers'
    //    certificates to vouch for malicious unsigned components.
    if (signedCount > 0 && unsignedCount > 0) {
        if (pubCount >= 2) {
            outDetail = L"MixedSig: " + std::to_wstring(signedCount) + L"Sig+" +
                       std::to_wstring(unsignedCount) + L"Unsig Pubs=" + std::to_wstring(pubCount) +
                       (msIgnored > 0 ? L" (MS=" + std::to_wstring(msIgnored) + L")" : L"");
            return L"silverfox";
        }
        // Single publisher + unsigned → legitimate installer (not SilverFox)
        outDetail = L"SinglePubMixed: " + std::to_wstring(signedCount) + L"Sig+" +
                   std::to_wstring(unsignedCount) + L"Unsig ("
                   + *uniquePublishers.begin() + L")" +
                   (msIgnored > 0 ? L" MS=" + std::to_wstring(msIgnored) : L"");
        return L"legitimate";
    }

    // 3. All unsigned (excluding MS) → SUSPECTED SilverFox when 2+ different characteristics
    //    (Threshold lowered from 3 → 2 since MS-signed files are now excluded)
    if (pubCount >= 2) {
        outDetail = L"MultiPub" + std::to_wstring(pubCount) + L": " +
                   (*uniquePublishers.begin()) + L" etc";
        return L"silverfox";
    }

    outDetail = L"SigAnalysis: " + std::to_wstring(signedCount) + L"Sig/" +
               std::to_wstring(unsignedCount) + L"Unsig Pubs=" + std::to_wstring(pubCount) +
               L" MS=" + std::to_wstring(msIgnored);
    return L"mixed";  // Not SilverFox, but worth noting
}

bool SilverFoxDetector::isProcessSuspicious(unsigned long pid,
    const std::wstring& path) {
    std::wstring lower = path;
    for (auto& c : lower) c = towlower(c);

    // Known script hosts
    if (lower.find(L"\\powershell.exe") != std::wstring::npos) return true;
    if (lower.find(L"\\cmd.exe") != std::wstring::npos) return true;
    if (lower.find(L"\\cscript.exe") != std::wstring::npos) return true;
    if (lower.find(L"\\wscript.exe") != std::wstring::npos) return true;
    if (lower.find(L"\\mshta.exe") != std::wstring::npos) return true;

    // Check if signed by Microsoft (same whitelist as analyze)
    std::wstring pub = getPublisher(path);
    if (isMicrosoftPublisher(pub)) return false;

    return false;
}

// ============================================================
// RansomDetector
// ============================================================
RansomDetector::RansomDetector() : m_enabled(false), m_learningMode(false) {
    // Initialize default whitelist (trusted processes)
    m_whitelist = {
        L"explorer.exe",        // Windows Explorer
        L"steam.exe",           // Steam game client
        L"steamservice.exe",    // Steam service
        L"devenv.exe",          // Visual Studio
        L"msbuild.exe",         // MSBuild
        L"cl.exe",              // C++ compiler
        L"link.exe",            // Linker
        L"node.exe",            // Node.js
        L"npm.cmd",             // npm
        L"python.exe",          // Python
        L"py.exe",              // Python launcher
        L"git.exe",             // Git
        L"gradle.exe",          // Gradle
        L"java.exe",            // Java
        L"javac.exe",           // Java compiler
        L"idea64.exe",          // IntelliJ IDEA
        L"code.exe",            // VS Code
        L"msedgewebview2.exe",  // Edge WebView
        L"msedge.exe",          // Edge browser
        L"chrome.exe",          // Chrome browser
        L"firefox.exe",         // Firefox browser
        L"winword.exe",         // Word
        L"excel.exe",           // Excel
        L"powerpnt.exe",        // PowerPoint
        L"notepad.exe",         // Notepad
        L"wordpad.exe",         // WordPad
        L"dwm.exe",             // Desktop Window Manager
        L"system.exe",          // Windows System
        L"svchost.exe",         // Service Host
        L"searchindexer.exe",   // Windows Search Indexer
        L"antimalware.exe",     // Windows Defender
        L"msmpeng.exe",         // Windows Defender Engine
        L"zeta.exe",            // ZETA itself
        L"zeta_drv.sys",        // ZETA Driver
    };
}

RansomDetector& RansomDetector::instance() {
    static RansomDetector inst;
    return inst;
}

void RansomDetector::enable() {
    m_enabled = true;
    m_learningMode = true;
    m_learningStartTime = std::chrono::steady_clock::now();
    Logger::instance().info(L"Ransom", L"Enable",
        L"Experimental ransomware detection enabled (learning mode for " +
        std::to_wstring(m_learningDuration) + L"s)");
}

void RansomDetector::disable() {
    m_enabled = false;
    m_learningMode = false;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_writeCounts.clear();
    m_firstWriteTime.clear();
    Logger::instance().info(L"Ransom", L"Disable", L"Experimental ransomware detection disabled");
}

void RansomDetector::setLearningDuration(int seconds) {
    m_learningDuration = seconds;
}

bool RansomDetector::isInLearningMode() {
    if (!m_learningMode) return false;
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - m_learningStartTime).count();
    if (elapsed >= m_learningDuration) {
        m_learningMode = false;
        Logger::instance().info(L"Ransom", L"Learning",
            L"Learning mode ended, switching to active protection");
        return false;
    }
    return true;
}

void RansomDetector::addToWhitelist(const std::wstring& processName) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::wstring lower = processName;
    for (auto& c : lower) c = towlower(c);
    if (std::find(m_whitelist.begin(), m_whitelist.end(), lower) == m_whitelist.end()) {
        m_whitelist.push_back(lower);
        Logger::instance().info(L"Ransom", L"Whitelist",
            L"Added " + processName + L" to trusted whitelist");
    }
}

void RansomDetector::removeFromWhitelist(const std::wstring& processName) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::wstring lower = processName;
    for (auto& c : lower) c = towlower(c);
    m_whitelist.erase(std::remove(m_whitelist.begin(), m_whitelist.end(), lower), m_whitelist.end());
}

bool RansomDetector::isWhitelisted(const std::wstring& processName) {
    std::wstring lower = processName;
    for (auto& c : lower) c = towlower(c);
    // Extract filename from path
    size_t pos = lower.find_last_of(L'\\');
    if (pos != std::wstring::npos) lower = lower.substr(pos + 1);
    return std::find(m_whitelist.begin(), m_whitelist.end(), lower) != m_whitelist.end();
}

bool RansomDetector::analyzeWrite(unsigned long pid, const std::wstring& filePath,
                                   const std::wstring& processName) {
    if (!m_enabled) return false;

    // Check whitelist first (trusted processes skip detection)
    if (!processName.empty() && isWhitelisted(processName)) {
        return false;
    }

    // Learning mode: only log, don't block
    bool inLearning = isInLearningMode();

    std::lock_guard<std::mutex> lock(m_mutex);
    auto now = std::chrono::steady_clock::now();

    // Initialize first write time for this PID
    if (m_firstWriteTime.find(pid) == m_firstWriteTime.end()) {
        m_firstWriteTime[pid] = now;
    }

    m_writeCounts[pid]++;

    // Time-based analysis: count writes within last 3 seconds
    auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - m_firstWriteTime[pid]).count();

    // Reset counter every 3 seconds to avoid false positives from long-running operations
    if (elapsedMs > 3000) {
        m_writeCounts[pid] = 1;
        m_firstWriteTime[pid] = now;
        return false;  // Not suspicious if spread over time
    }

    int count = m_writeCounts[pid];

    // Check file extension for documents
    std::wstring ext = filePath.substr(filePath.find_last_of(L'.') + 1);
    for (auto& c : ext) c = towlower(c);

    // Known document extensions targeted by ransomware
    static const std::wstring docExts[] = {
        L"doc", L"docx", L"xls", L"xlsx", L"ppt", L"pptx",
        L"pdf", L"jpg", L"jpeg", L"png", L"zip", L"rar",
        L"7z", L"sql", L"db", L"mdb", L"txt", L"rtf"
    };

    bool isDocTarget = false;
    for (const auto& de : docExts) {
        if (ext == de) { isDocTarget = true; break; }
    }

    // Thresholds adjusted for 3-second window
    // High write rate on documents (5+ writes in 3s) = suspicious
    if (isDocTarget && count >= 5) {
        if (inLearning) {
            Logger::instance().warn(L"Ransom", L"Learning",
                L"PID=" + std::to_wstring(pid) + L" suspicious pattern detected (learning mode, not blocking): " +
                std::to_wstring(count) + L" writes in 3s to " + filePath);
            return false;  // Don't block in learning mode
        }
        Logger::instance().warn(L"Ransom", L"Block",
            L"PID=" + std::to_wstring(pid) + L" writes=" + std::to_wstring(count) +
            L" in 3s to " + filePath + L" PROCESS=" + processName);
        return true;  // Suspicious, block
    }

    // Very high general write count (10+ writes in 3s)
    if (count >= 10) {
        if (inLearning) {
            Logger::instance().warn(L"Ransom", L"Learning",
                L"PID=" + std::to_wstring(pid) + L" high activity (learning mode): " +
                std::to_wstring(count) + L" writes in 3s");
            return false;
        }
        Logger::instance().warn(L"Ransom", L"Block",
            L"PID=" + std::to_wstring(pid) + L" high write count: " + std::to_wstring(count) +
            L" in 3s PROCESS=" + processName);
        return true;
    }

    return false;
}

bool RansomDetector::checkEntropy(const std::wstring& filePath, double* outEntropy) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);

    // Read up to first 64KB for entropy calc
    DWORD readSize = static_cast<DWORD>(min(fileSize.QuadPart, (LONGLONG)65536));
    std::vector<char> data(readSize);
    DWORD bytesRead = 0;
    ReadFile(hFile, data.data(), readSize, &bytesRead, nullptr);
    CloseHandle(hFile);

    if (bytesRead < 256) return false;

    int byteCounts[256] = {0};
    for (DWORD i = 0; i < bytesRead; i++) {
        byteCounts[static_cast<unsigned char>(data[i])]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (byteCounts[i] > 0) {
            double p = static_cast<double>(byteCounts[i]) / bytesRead;
            entropy -= p * log2(p);
        }
    }

    if (outEntropy) *outEntropy = entropy;

    // Encrypted/high entropy = suspicious
    return entropy > 7.5;
}

// ============================================================
// PopupBlocker
// ============================================================
PopupBlocker& PopupBlocker::instance() {
    static PopupBlocker inst;
    return inst;
}

void PopupBlocker::start() {
    if (m_running) return;
    m_running = true;
    m_thread = std::thread(&PopupBlocker::blockerThread, this);
    Logger::instance().info(L"Popup", L"Start", L"Popup blocker started");
}

void PopupBlocker::stop() {
    m_running = false;
    if (m_thread.joinable()) m_thread.join();
    Logger::instance().info(L"Popup", L"Stop", L"Popup blocker stopped");
}

void PopupBlocker::addRule(const std::wstring& title, bool block) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& r : m_blockRules) {
        if (r == title) return;  // Already exists
    }
    m_blockRules.push_back(title);
    Logger::instance().info(L"Popup", L"AddRule", L"Title=" + title);
}

bool PopupBlocker::removeRule(const std::wstring& title) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto it = m_blockRules.begin(); it != m_blockRules.end(); ++it) {
        if (*it == title) {
            m_blockRules.erase(it);
            Logger::instance().info(L"Popup", L"RemoveRule", L"Title=" + title);
            return true;
        }
    }
    return false;
}

std::vector<std::wstring> PopupBlocker::getRules() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_blockRules;
}

void PopupBlocker::blockerThread() {
    while (m_running) {
        EnumWindows(enumWindowsProc, reinterpret_cast<LPARAM>(this));
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

BOOL CALLBACK PopupBlocker::enumWindowsProc(HWND hWnd, LPARAM lParam) {
    auto self = reinterpret_cast<PopupBlocker*>(lParam);
    if (!self || !self->m_running) return FALSE;

    // Check if visible and has no parent
    if (!IsWindowVisible(hWnd)) return TRUE;

    wchar_t title[256];
    GetWindowTextW(hWnd, title, 256);
    if (title[0] == 0) return TRUE;

    std::wstring titleStr(title);

    // Check against block rules
    bool shouldBlock = false;
    {
        std::lock_guard<std::mutex> lock(self->m_mutex);
        for (const auto& rule : self->m_blockRules) {
            if (titleStr.find(rule) != std::wstring::npos) {
                shouldBlock = true;
                break;
            }
        }
    }

    if (shouldBlock) {
        // Block the popup
        PostMessageW(hWnd, WM_CLOSE, 0, 0);

        wchar_t className[256];
        GetClassNameW(hWnd, className, 256);

        Logger::instance().info(L"Popup", L"Blocked",
            L"Title=" + titleStr + L" Class=" + std::wstring(className));

        if (self->m_blockCb) {
            self->m_blockCb(titleStr, className);
        }

        // Also kill the owning process
        DWORD pid = 0;
        GetWindowThreadProcessId(hWnd, &pid);
        if (pid > 0) {
            HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (hProc) {
                TerminateProcess(hProc, 1);
                CloseHandle(hProc);
            }
        }
    }

    return TRUE;
}

// ============================================================
// C DLL Exports
// ============================================================
extern "C" {

__declspec(dllexport) void zeta_hips_ransom_enable() {
    RansomDetector::instance().enable();
}

__declspec(dllexport) void zeta_hips_ransom_disable() {
    RansomDetector::instance().disable();
}

__declspec(dllexport) int zeta_hips_ransom_is_enabled() {
    return RansomDetector::instance().isEnabled() ? 1 : 0;
}

__declspec(dllexport) int zeta_hips_ransom_check_entropy(const wchar_t* path, double* outEntropy) {
    return RansomDetector::instance().checkEntropy(path ? path : L"", outEntropy) ? 1 : 0;
}

__declspec(dllexport) void zeta_hips_ransom_add_whitelist(const wchar_t* processName) {
    if (processName) RansomDetector::instance().addToWhitelist(processName);
}

__declspec(dllexport) void zeta_hips_ransom_remove_whitelist(const wchar_t* processName) {
    if (processName) RansomDetector::instance().removeFromWhitelist(processName);
}

__declspec(dllexport) int zeta_hips_ransom_is_learning() {
    return RansomDetector::instance().isInLearningMode() ? 1 : 0;
}

__declspec(dllexport) int zeta_hips_silverfox_analyze(const wchar_t* const* files, int count,
    wchar_t* outType, int typeSize, wchar_t* outDetail, int detailSize) {
    if (!files || count <= 0) return 0;

    std::vector<std::wstring> fileList;
    for (int i = 0; i < count; i++) {
        if (files[i]) fileList.push_back(files[i]);
    }

    std::wstring detail;
    std::wstring type = SilverFoxDetector::instance().analyze(fileList, detail);

    if (outType && typeSize > 0) {
        wcsncpy_s(outType, typeSize, type.c_str(), _TRUNCATE);
    }
    if (outDetail && detailSize > 0) {
        wcsncpy_s(outDetail, detailSize, detail.c_str(), _TRUNCATE);
    }

    return (type == L"silverfox") ? 1 : 0;
}

__declspec(dllexport) void zeta_hips_popup_start() {
    PopupBlocker::instance().start();
}
__declspec(dllexport) void zeta_hips_popup_stop() {
    PopupBlocker::instance().stop();
}
__declspec(dllexport) void zeta_hips_popup_add_rule(const wchar_t* title) {
    PopupBlocker::instance().addRule(title ? title : L"", true);
}
__declspec(dllexport) int zeta_hips_popup_remove_rule(const wchar_t* title) {
    return PopupBlocker::instance().removeRule(title ? title : L"") ? 1 : 0;
}

} // extern "C"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
