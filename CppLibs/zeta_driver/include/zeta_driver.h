#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <atomic>
#include <thread>
#include <unordered_map>

// ============================================================
// Driver Communication - Filter Communication Port
// ============================================================

// Message handler callback
using MessageHandler = std::function<void(unsigned long code, unsigned long pid,
    const std::wstring& path)>;

// Command callback (user -> driver response)
struct CommandResult {
    bool success;
    std::wstring data;
};

class DriverComm {
public:
    static DriverComm& instance();

    bool connect(const std::wstring& portName = L"\\ZETA_Output_Pipe");
    void disconnect();
    bool isConnected();
    void setConnected(HANDLE port);  // set the port handle directly (for direct connect)

    // Start the message receive loop (blocking, run in thread)
    void startMessageLoop();
    void stopMessageLoop();

    // Send command to driver
    bool sendCommand(unsigned long command, const std::wstring& path = L"",
        std::wstring* outData = nullptr);

    // Send allow/deny for pending operation
    bool allowOperation(unsigned long pid);
    bool denyOperation(unsigned long pid);
    bool markRollback(unsigned long pid);

    // Register message handlers
    void registerHandler(unsigned long code, MessageHandler handler);

    // Get init log from driver
    std::wstring getInitLog();

    // C-callable callback registration
    void setExternalCallback(std::function<void(unsigned long, unsigned long,
        const std::wstring&, const std::wstring&)> cb) {
        m_externalCb = cb;
    }

private:
    DriverComm();
    ~DriverComm();
    DriverComm(const DriverComm&) = delete;
    DriverComm& operator=(const DriverComm&) = delete;

    void drainCommandQueue();  // called from message loop thread

    HANDLE m_port;           // Filter Communication Port handle
    std::atomic<bool> m_running;
    std::thread m_messageThread;
    std::mutex m_mutex;
    std::mutex m_cmdMutex;
    std::vector<std::pair<unsigned long, std::wstring>> m_cmdQueue;  // pending commands
    std::atomic<bool> m_cmdPending{false};  // wake the loop on next command

    // Handlers map: code -> handler
    std::unordered_map<unsigned long, MessageHandler> m_handlers;

    // External callback (for C++ UI layer)
    std::function<void(unsigned long, unsigned long,
        const std::wstring&, const std::wstring&)> m_externalCb;
};

// ============================================================
// HIPS Types
// ============================================================
enum HipsAction { HIPS_ALLOW = 0, HIPS_DENY = 1, HIPS_ASK = 2 };

struct HipsRule {
    std::wstring id;
    unsigned long code;
    std::wstring process;
    std::wstring target;
    HipsAction action;
    unsigned long long timestamp;
    bool process_exact;
    int score = 0;         // EDR 评分: 该规则触发时累加到此分数
};

// ============================================================
// DLL Export
// ============================================================
#ifdef ZETA_DRIVER_EXPORTS
#define ZETA_DRIVER_API __declspec(dllexport)
#else
#define ZETA_DRIVER_API __declspec(dllimport)
#endif

// ============================================================
// HIPS Rule Engine
// ============================================================
class ZETA_DRIVER_API HipsEngine {
public:
    static HipsEngine& instance();

    int loadRules();
    void loadDefaultRules();
    void saveRules();

    // Match a rule: returns action (ALLOW/DENY) or ASK if no rule matches
    // After calling, lastMatchedScore() returns the matched rule's EDR score.
    HipsAction matchRule(unsigned long code, const std::wstring& process,
        const std::wstring& target);

    // Get the score of the last matched rule (for EDR linkage)
    int lastMatchedScore() const;

    // Add a rule
    void addRule(unsigned long code, const std::wstring& process,
        const std::wstring& target, HipsAction action, int score = 0,
        bool processExact = false);

    // Delete a rule
    bool deleteRule(const std::wstring& ruleId);

    // Clear all rules
    void clearRules();

    // Get all rules
    std::vector<HipsRule> getRules();

    // Enable/disable learning mode
    void setLearningMode(bool enabled) { m_learningMode = enabled; }
    bool isLearningMode() { return m_learningMode; }

    // Set the path to Rules_Hips.json for persistent rule storage
    void setRulesPath(const std::wstring& path) { m_rulesPath = path; }

    // Whitelist management
    bool isInWhitelist(const std::wstring& path);
    void addToWhitelist(const std::wstring& path);
    void removeFromWhitelist(const std::wstring& path);
    std::vector<std::wstring> getWhitelist();

private:
    HipsEngine() : m_learningMode(false) {}
    HipsEngine(const HipsEngine&) = delete;
    HipsEngine& operator=(const HipsEngine&) = delete;

    std::mutex m_mutex;
    std::vector<HipsRule> m_rules;
    std::vector<std::wstring> m_whitelist;
    bool m_learningMode;
    int m_lastMatchedScore = 0;
    std::wstring m_rulesPath;          // path to Rules_Hips.json

    // Internal: caller must hold m_mutex
    void saveRulesUnlocked();
    bool loadRulesFromFileUnlocked();   // load from m_rulesPath
};

extern "C" {
    ZETA_DRIVER_API int zeta_driver_connect(const wchar_t* portName);
    ZETA_DRIVER_API void zeta_driver_disconnect();
    ZETA_DRIVER_API int zeta_driver_is_connected();

    ZETA_DRIVER_API void zeta_driver_start_loop();
    ZETA_DRIVER_API void zeta_driver_stop_loop();

    ZETA_DRIVER_API int zeta_driver_send_cmd(unsigned long cmd, const wchar_t* path);
    ZETA_DRIVER_API const wchar_t* zeta_driver_get_init_log();
    ZETA_DRIVER_API void zeta_driver_set_msg_callback(void* cb);

    ZETA_DRIVER_API int zeta_driver_allow_op(unsigned long pid);
    ZETA_DRIVER_API int zeta_driver_deny_op(unsigned long pid);

    ZETA_DRIVER_API void zeta_hips_reload_rules();

    ZETA_DRIVER_API int zeta_hips_load_rules();
    ZETA_DRIVER_API void zeta_hips_save_rules();
    ZETA_DRIVER_API void zeta_hips_set_rules_path(const wchar_t* path);
    ZETA_DRIVER_API int zeta_hips_match_rule(unsigned long code, const wchar_t* process, const wchar_t* target);
    ZETA_DRIVER_API int zeta_hips_match_rule_score(unsigned long code, const wchar_t* process, const wchar_t* target);
    ZETA_DRIVER_API void zeta_hips_add_rule(unsigned long code, const wchar_t* process, const wchar_t* target, int action);
    ZETA_DRIVER_API void zeta_hips_add_rule_ex(unsigned long code, const wchar_t* process, const wchar_t* target, int action, int score);
    ZETA_DRIVER_API int zeta_hips_delete_rule(const wchar_t* ruleId);
    ZETA_DRIVER_API void zeta_hips_clear_rules();
    ZETA_DRIVER_API int zeta_hips_is_whitelisted(const wchar_t* path);
    ZETA_DRIVER_API void zeta_hips_add_whitelist(const wchar_t* path);
    ZETA_DRIVER_API void zeta_hips_remove_whitelist(const wchar_t* path);
}
