#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>

// ============================================================
// SilverFox Detector
// Multi-process signature analysis
// ============================================================
class SilverFoxDetector {
public:
    static SilverFoxDetector& instance();

    // Analyze a set of files for SilverFox patterns
    // Returns detection type: "mixed", "none", "silverfox"
    std::wstring analyze(const std::vector<std::wstring>& filePaths,
                         std::wstring& outDetail);

    // Quick check with caching
    std::wstring getPublisher(const std::wstring& filePath);
    bool isProcessSuspicious(unsigned long pid, const std::wstring& path);

private:
    SilverFoxDetector() {}
    SilverFoxDetector(const SilverFoxDetector&) = delete;
    SilverFoxDetector& operator=(const SilverFoxDetector&) = delete;

    HMODULE m_wintrust{nullptr};
    std::mutex m_mutex;
    std::unordered_map<std::wstring, std::wstring> m_publisherCache;
};

// ============================================================
// Popup Interceptor
// ============================================================
class PopupBlocker {
public:
    static PopupBlocker& instance();
    void start();
    void stop();

    void addRule(const std::wstring& title, bool block);
    bool removeRule(const std::wstring& title);
    std::vector<std::wstring> getRules();

    // Callback when a popup is blocked
    using BlockCallback = std::function<void(const std::wstring& title,
        const std::wstring& className)>;
    void setBlockCallback(BlockCallback cb) { m_blockCb = cb; }

private:
    PopupBlocker() : m_running(false) {}
    PopupBlocker(const PopupBlocker&) = delete;
    PopupBlocker& operator=(const PopupBlocker&) = delete;

    void blockerThread();
    static BOOL CALLBACK enumWindowsProc(HWND hWnd, LPARAM lParam);

    std::atomic<bool> m_running;
    std::thread m_thread;
    std::vector<std::wstring> m_blockRules;
    std::mutex m_mutex;
    BlockCallback m_blockCb;
};

// ============================================================
// DLL Export
// ============================================================
#ifdef ZETA_HIPS_EXPORTS
#define ZETA_HIPS_API __declspec(dllexport)
#else
#define ZETA_HIPS_API __declspec(dllimport)
#endif

extern "C" {
    ZETA_HIPS_API int zeta_hips_silverfox_analyze(const wchar_t*const* files, int count,
        wchar_t* outType, int typeSize, wchar_t* outDetail, int detailSize);

    ZETA_HIPS_API void zeta_hips_popup_start();
    ZETA_HIPS_API void zeta_hips_popup_stop();
    ZETA_HIPS_API void zeta_hips_popup_add_rule(const wchar_t* title);
    ZETA_HIPS_API int zeta_hips_popup_remove_rule(const wchar_t* title);

}
