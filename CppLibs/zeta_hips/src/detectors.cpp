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
