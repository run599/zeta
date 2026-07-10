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
// Ransomware Detector (Experimental)
// Behavioral + entropy analysis with whitelist + learning mode
// ============================================================
class RansomDetector {
public:
    static RansomDetector& instance();
    void enable();
    void disable();
    bool isEnabled() { return m_enabled; }

    // Set learning mode duration (seconds, default 300 = 5 minutes)
    void setLearningDuration(int seconds);
    bool isInLearningMode();

    // Add/remove trusted process to whitelist
    void addToWhitelist(const std::wstring& processName);
    void removeFromWhitelist(const std::wstring& processName);
    bool isWhitelisted(const std::wstring& processName);

    // Analyze file write pattern
    bool analyzeWrite(unsigned long pid, const std::wstring& filePath, const std::wstring& processName);

    // Check if entropy is suspiciously high
    bool checkEntropy(const std::wstring& filePath, double* outEntropy = nullptr);

private:
    RansomDetector();
    RansomDetector(const RansomDetector&) = delete;
    RansomDetector& operator=(const RansomDetector&) = delete;

    std::atomic<bool> m_enabled;
    std::atomic<bool> m_learningMode;
    std::chrono::steady_clock::time_point m_learningStartTime;
    int m_learningDuration = 300;  // 5 minutes default

    std::mutex m_mutex;
    std::unordered_map<unsigned long, int> m_writeCounts; // PID -> write count
    std::unordered_map<unsigned long, std::chrono::steady_clock::time_point> m_firstWriteTime; // PID -> first write time
    std::vector<std::wstring> m_whitelist;  // Trusted process names (lowercase)
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
    ZETA_HIPS_API void zeta_hips_ransom_enable();
    ZETA_HIPS_API void zeta_hips_ransom_disable();
    ZETA_HIPS_API int zeta_hips_ransom_is_enabled();
    ZETA_HIPS_API int zeta_hips_ransom_check_entropy(const wchar_t* path, double* outEntropy);

    // New: whitelist and learning mode
    ZETA_HIPS_API void zeta_hips_ransom_add_whitelist(const wchar_t* processName);
    ZETA_HIPS_API void zeta_hips_ransom_remove_whitelist(const wchar_t* processName);
    ZETA_HIPS_API int zeta_hips_ransom_is_learning();

    ZETA_HIPS_API int zeta_hips_silverfox_analyze(const wchar_t*const* files, int count,
        wchar_t* outType, int typeSize, wchar_t* outDetail, int detailSize);

    ZETA_HIPS_API void zeta_hips_popup_start();
    ZETA_HIPS_API void zeta_hips_popup_stop();
    ZETA_HIPS_API void zeta_hips_popup_add_rule(const wchar_t* title);
    ZETA_HIPS_API int zeta_hips_popup_remove_rule(const wchar_t* title);

}
