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
    std::wstring type;       // "yara", "pe", "extension", "signature", "mem-yara"
    std::wstring path;       // Full file path
    std::wstring status;     // "威胁", "可疑", "安全"
    std::wstring detail;     // Rule name or description
    bool isHigh;             // High severity?
    // P2-8: 处置状态（供 EDR 高分与 HIPS 决策共用统一处置入口）
    enum Disposition { NONE = 0, TERMINATE = 1, QUARANTINE = 2 } disposition = NONE;
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
    // P1 收敛: 签名验证统一走 zeta_core TrustProvider (消除第三套 WinVerifyTrust)
    HMODULE m_coreDll;
    int (*m_trustVerify)(const wchar_t*);
};

// ============================================================
// YARA Scanner (Pure C++ via libyara, no Python dependency)
// ============================================================
// 规则置信档 (2026-10-04 新增)。评分策略的前提: 引擎必须把"命中了几条、
// 分别属于哪一档"如实交给行为引擎, 由后者施加权重。
// 引擎只负责【证据】, 不负责【分值】—— 权重表必须与 ALERT_THRESHOLD 的
// static_assert 放在同一个编译单元里, 否则不变式会被拆散而失效。
enum class RuleTier {
    Weak   = 0,   // 能力型/库型: 是 PE、含 URL、加密常量表、加壳器、编译器/框架指纹
    Normal = 1,   // 默认: 未归入弱/强的规则
    Strong = 2    // 策展的高置信家族签名(产品自带规则 + signature-base 的 mal_/apt_/crime_/rat_/spy_)
};

class YaraScanner {
public:
    YaraScanner();
    ~YaraScanner();
    bool loadPath(const std::wstring& path);
    // outAllRules: 可选出参, 返回【本次命中的全部规则名】(去重, 按命中顺序)。
    // 2026-10-04 新增: 评分策略需要"命中条数"作为独立证据 —— 单条弱规则与
    // 五条弱规则的危害完全不同, 而旧接口只回传一条规则名, 信息在引擎里就丢了。
    bool scan(const std::wstring& filePath,
              std::wstring& outRule, std::wstring& outLabel, bool& outIsHigh,
              std::vector<std::wstring>* outAllRules = nullptr);
    // P1-5: 内存扫描——直接对进程内存缓冲跑 YARA
    bool scanMem(const BYTE* data, size_t size,
                 std::wstring& outRule, std::wstring& outLabel, bool& outIsHigh,
                 std::vector<std::wstring>* outAllRules = nullptr);
    // 2026-10-03 修复: 显式释放已编译规则。
    // 必须在 yr_finalize() 之前调用 —— 否则规则对象会在 libyara 全局状态
    // 已终结之后才被销毁(yr_rules_destroy 在 yr_finalize 之后), 是 UAF 来源。
    void destroyRules();
    // 规则→置信档 查询 (由 compileRules() 在加载期按规则文件路径建立)。
    // 未收录的规则返回 Normal —— 宁可当普通规则也不静默丢弃。
    // 非 const: 实现内部要持 m_mutex 保护 m_ruleTier(加载期会重建)。
    RuleTier tierOfRule(const std::wstring& ruleName);

private:
    void collectRuleFiles(const std::wstring& dir, std::vector<std::wstring>& out);
    bool compileRules();
    // 从规则文件路径判定该文件内全部规则的置信档。
    static RuleTier tierFromRulePath(const std::wstring& fullPath);

    std::vector<std::wstring> m_ruleFiles;  // Paths to .yar files
    YR_RULES* m_rules;                      // Compiled rules (cached)
    std::unordered_map<std::wstring, int> m_ruleTier;  // 规则名 -> RuleTier 值
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
    int scan(const std::wstring& filePath, bool enhancedMode, std::wstring& outDetails);
    std::wstring getDetails();
    void reloadRules();

private:
    int analyzeImports(const std::vector<unsigned char>& data, const EdrScoring& scoring, std::wstring& outDetails);
    int analyzeSections(const std::vector<unsigned char>& data, const EdrScoring& scoring, std::wstring& outDetails);
    int analyzeEntropy(const std::vector<unsigned char>& data, const EdrScoring& scoring, std::wstring& outDetails);
    int analyzeEntryPoint(const std::vector<unsigned char>& data, const EdrScoring& scoring, std::wstring& outDetails);

    // Suspicious API sets
    std::vector<std::string> m_suspiciousApis;
    std::vector<std::string> m_highRiskApis;
    std::vector<std::string> m_suspiciousSections;
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
    // P1-5: 进程内存扫描——遍历目标进程可执行内存区跑 YARA
    // 返回首个命中结果；无命中返回空 type 的 ScanResult
    ScanResult scanProcess(unsigned long pid);

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
    // 2026-10-03 修复: init() 幂等标志。
    // 原先 zeta_engine_create() 每次调用都跑一遍 init() → loadPath() → compileRules(),
    // 即【每扫描一个文件就把全部 YARA 规则销毁重建一次】: 既是 UAF 来源,
    // 也让每次扫描的开销变成"重编译整个规则集"。
    std::atomic<bool> m_inited;
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

    // P1-5: 进程内存扫描（返回命中结果码：0=无，1=可疑，3=高危）
    ZETA_ENGINE_API int zeta_engine_scan_process(unsigned long pid,
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
