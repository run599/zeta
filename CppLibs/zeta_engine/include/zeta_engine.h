#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <memory>
#include <unordered_map>
#include <mutex>

// Forward declaration for YR_RULES (avoids including yara.h in header)
struct YR_RULES;

// ============================================================
// Scan Result
// ============================================================
struct ScanResult {
    std::wstring type;       // "yara", "pe", "extension", "signature"
    std::wstring path;       // Full file path
    std::wstring status;     // "威胁", "可疑", "安全"
    std::wstring detail;     // Rule name or description
    bool isHigh;             // High severity?
};

// ============================================================
// Signature Scanner
// ============================================================
class SignScanner {
public:
    SignScanner();
    ~SignScanner();
    bool verify(const std::wstring& filePath);
    std::wstring getPublisher(const std::wstring& filePath);

private:
    HMODULE m_wintrust;
    bool m_loaded;
};

// ============================================================
// YARA Scanner (Pure C++ via libyara, no Python dependency)
// ============================================================
class YaraScanner {
public:
    YaraScanner();
    ~YaraScanner();
    bool loadPath(const std::wstring& path);
    bool scan(const std::wstring& filePath,
              std::wstring& outRule, std::wstring& outLabel, bool& outIsHigh);

private:
    void collectRuleFiles(const std::wstring& dir, std::vector<std::wstring>& out);
    bool compileRules();

    std::vector<std::wstring> m_ruleFiles;  // Paths to .yar files
    YR_RULES* m_rules;                      // Compiled rules (cached)
    std::mutex m_mutex;
};

// Forward declaration for Scoring struct
struct EdrScoring;

// ============================================================
// PE Scanner
// ============================================================
class PeScanner {
public:
    PeScanner();
    int scan(const std::wstring& filePath, bool enhancedMode = false);
    std::wstring getDetails();
    void reloadRules();

private:
    std::wstring m_details;
    int analyzeImports(const std::vector<unsigned char>& data, const EdrScoring& scoring);
    int analyzeSections(const std::vector<unsigned char>& data, const EdrScoring& scoring);
    int analyzeEntropy(const std::vector<unsigned char>& data, const EdrScoring& scoring);
    int analyzeEntryPoint(const std::vector<unsigned char>& data, const EdrScoring& scoring);

    // Suspicious API sets
    std::vector<std::wstring> m_suspiciousApis;
    std::vector<std::wstring> m_highRiskApis;
    std::vector<std::wstring> m_suspiciousSections;
};

// ============================================================
// EDR Rule Manager
// ============================================================
struct EdrScoring {
    int suspiciousApi = 15;
    int highRiskApi = 30;
    int suspiciousSection = 30;
    int rwxSection = 20;
    int highEntropy = 25;
    int noEntryPoint = 10;
    int unsignedScore = 20;
    int yaraMatch = 100;
    int threatThreshold = 50;
    int highThreatThreshold = 70;
};

struct EdrScanningEnabled {
    bool enableYara = true;
    bool enablePeHeuristics = true;
    bool enableSignatureCheck = true;
};

class EdrRuleManager {
public:
    std::vector<std::string> suspiciousApis;
    std::vector<std::string> highRiskApis;
    std::vector<std::string> suspiciousSections;
    std::vector<std::string> trustedPublishers;
    std::vector<std::string> requiredExtensions;
    std::vector<std::wstring> yaraPaths;
    EdrScoring scoring;
    EdrScanningEnabled enabled;
    
    bool loadFromConfig(const std::wstring& configPath);
    static EdrRuleManager& instance();
};

// ============================================================
// Scan Engine (Combined)
// ============================================================
class ScanEngine {
public:
    static ScanEngine& instance();

    bool init(const std::wstring& rulesDir);
    ScanResult scanFile(const std::wstring& filePath, bool enhancedMode = false);

    // Multi-file scan
    void startScan(const std::vector<std::wstring>& targets);
    void stopScan();
    bool isScanning() { return m_scanning; }

    // Results
    std::vector<ScanResult> getResults() { return m_results; }
    void clearResults();
    int getProgress() { return m_progress; }

    // Callbacks
    using ProgressCallback = std::function<void(int percent, const std::wstring& currentFile)>;
    using ResultCallback = std::function<void(const ScanResult&)>;
    void setProgressCallback(ProgressCallback cb) { m_progressCb = cb; }
    void setResultCallback(ResultCallback cb) { m_resultCb = cb; }

private:
    ScanEngine();
    ~ScanEngine();
    ScanEngine(const ScanEngine&) = delete;
    ScanEngine& operator=(const ScanEngine&) = delete;

    bool isWhitelisted(const std::wstring& path);

    SignScanner m_signScanner;
    YaraScanner m_yaraScanner;
    PeScanner m_peScanner;

    std::atomic<bool> m_scanning;
    std::atomic<int> m_progress;
    std::vector<ScanResult> m_results;
    std::mutex m_mutex;

    ProgressCallback m_progressCb;
    ResultCallback m_resultCb;

    std::thread m_scanThread;

    // Cache
    std::unordered_map<std::wstring, ScanResult> m_cache;
    static const int MAX_CACHE = 10000;
};

// ============================================================
// DLL Export
// ============================================================
#ifdef ZETA_ENGINE_EXPORTS
#define ZETA_ENGINE_API __declspec(dllexport)
#else
#define ZETA_ENGINE_API __declspec(dllimport)
#endif

extern "C" {
    ZETA_ENGINE_API int zeta_engine_init(const wchar_t* rulesDir);
    ZETA_ENGINE_API int zeta_engine_scan_file(const wchar_t* path, int enhanced,
        wchar_t* outType, int typeSize, wchar_t* outStatus, int statusSize,
        wchar_t* outDetail, int detailSize);

    ZETA_ENGINE_API void zeta_engine_start_scan(const wchar_t* const* targets, int count);
    ZETA_ENGINE_API void zeta_engine_stop_scan();
    ZETA_ENGINE_API int zeta_engine_is_scanning();
    ZETA_ENGINE_API int zeta_engine_get_progress();
    ZETA_ENGINE_API void zeta_engine_clear_results();

    ZETA_ENGINE_API void zeta_engine_set_progress_cb(void* cb);
    ZETA_ENGINE_API void zeta_engine_set_result_cb(void* cb);

    ZETA_ENGINE_API int zeta_engine_check_signature(const wchar_t* path);
}
