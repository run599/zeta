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

    // 设置带 IRP 上下文的扩展回调
    void setExternalCtxCallback(std::function<void(unsigned long, unsigned long,
        const std::wstring&, const unsigned char*, unsigned int)> cb) {
        m_externalCtxCb = cb;
    }

    // Audit mode control
    bool setAuditMode(unsigned long mode);

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

    // External callback with IRP context (new)
    std::function<void(unsigned long, unsigned long,
        const std::wstring&, const unsigned char*, unsigned int)> m_externalCtxCb;
};

// ============================================================
// IRP Semantic Context — 内核在 IRP 检查点提取的语义信息
//
// 设计原则：内核传递"语义标签"而非原始 IRP 数据。
// 内核在 IRP 检查点已拥有完整上下文，在那里做语义提取
// 比把原始数据传到用户态再解析高效得多。
// ============================================================
namespace zeta {

enum IrpOperationType {
    IRP_OP_FILE_CREATE     = 0,
    IRP_OP_FILE_WRITE      = 1,
    IRP_OP_FILE_RENAME     = 2,
    IRP_OP_FILE_DELETE     = 3,
    IRP_OP_FILE_SETINFO    = 4,
    IRP_OP_REG_CREATEKEY   = 10,
    IRP_OP_REG_SETVALUE    = 11,
    IRP_OP_REG_DELETEKEY   = 12,
    IRP_OP_REG_RENAMEKEY   = 13,
    IRP_OP_DISK_WRITE      = 20,
    IRP_OP_DISK_IOCTL      = 21,
    IRP_OP_PROCESS_CREATE  = 30,
    IRP_OP_PROCESS_EXIT    = 31,
    IRP_OP_IMAGE_LOAD      = 32,
};

enum FileSemanticFlags {
    FILE_SEM_NONE            = 0x0000,
    FILE_SEM_IS_PE           = 0x0001,
    FILE_SEM_IS_SCRIPT       = 0x0002,
    FILE_SEM_IS_DOCUMENT     = 0x0004,
    FILE_SEM_OFFSET_ZERO     = 0x0008,
    FILE_SEM_LARGE_WRITE     = 0x0010,
    FILE_SEM_HIDDEN_ATTR     = 0x0020,
    FILE_SEM_SYSTEM_ATTR     = 0x0040,
    FILE_SEM_DELETE_OP       = 0x0080,
    FILE_SEM_EXCLUSIVE       = 0x0100,
    FILE_SEM_OVERWRITE       = 0x0200,
    FILE_SEM_NONCACHED       = 0x0400,
    FILE_SEM_PAGING_IO       = 0x0800,
    FILE_SEM_TEMP_PATH       = 0x1000,
    FILE_SEM_APPDATA_PATH    = 0x2000,
    FILE_SEM_SYSTEM_PATH     = 0x4000,
    FILE_SEM_PUBLIC_PATH     = 0x8000,
};

enum RegSemanticFlags {
    REG_SEM_NONE             = 0x0000,
    REG_SEM_RUN_KEY          = 0x0001,
    REG_SEM_SERVICE_KEY      = 0x0002,
    REG_SEM_IFEO_KEY         = 0x0004,
    REG_SEM_UAC_KEY          = 0x0008,
    REG_SEM_DEFENDER_KEY     = 0x0010,
    REG_SEM_FIREWALL_KEY     = 0x0020,
    REG_SEM_APPINIT_KEY      = 0x0040,
    REG_SEM_BCD_KEY          = 0x0080,
    REG_SEM_VALUE_DELETE     = 0x0100,
};

enum ProcessTrustLevel {
    TRUST_UNKNOWN       = 0,
    TRUST_NONE          = 1,
    TRUST_UNSIGNED      = 2,
    TRUST_SIGNED        = 3,
    TRUST_MS_SIGNED     = 4,
    TRUST_SYSTEM        = 5,
    TRUST_ZETA          = 6,
};

#pragma pack(push, 1)
typedef struct _ZETA_IRP_CONTEXT {
    UCHAR OperationType;
    UCHAR TrustLevel;
    USHORT FileFlags;
    USHORT RegFlags;
    UCHAR ScriptDepth;
    UCHAR Flags;
} ZETA_IRP_CONTEXT, *PZETA_IRP_CONTEXT;
#pragma pack(pop)

} // namespace zeta

// ============================================================================
// IRP Audit Types (outside namespace for C/C++ interop with kernel)
// ============================================================================
// Audit mode levels (must match kernel AUDIT_MODE_*)
constexpr unsigned long AUDIT_MODE_OFF      = 0;
constexpr unsigned long AUDIT_MODE_ON       = 1;
constexpr unsigned long AUDIT_MODE_SAMPLING = 2;

// Audit extension (must match kernel ZETA_IRP_AUDIT_EXT)
#pragma pack(push, 1)
typedef struct _ZETA_IRP_AUDIT_EXT {
    unsigned short Size;
    unsigned short IrpMajor;
    unsigned long  DesiredAccess;
    unsigned long  CreateOptions;
    unsigned long  ShareAccess;
    unsigned long  WriteLength;
    unsigned long long ByteOffset;
    unsigned short FileClass;
    unsigned short RegValueType;
    wchar_t        ValueName[64];
    unsigned char  WriteSample[32];
    unsigned short WriteSampleLen;
} ZETA_IRP_AUDIT_EXT, *PZETA_IRP_AUDIT_EXT;
#pragma pack(pop)

// Audit ring entry (must match kernel AUDIT_RING_ENTRY)
constexpr unsigned long AUDIT_RING_SIZE = 4096;
constexpr unsigned long AUDIT_ENTRY_MAX_PATH = 520;

#pragma pack(push, 1)
typedef struct _AUDIT_RING_ENTRY {
    long long     Timestamp;
    unsigned long ProcessId;
    unsigned long MessageCode;
    zeta::ZETA_IRP_CONTEXT Ictx;
    ZETA_IRP_AUDIT_EXT Ext;
    wchar_t       Path[AUDIT_ENTRY_MAX_PATH / sizeof(wchar_t)];
} AUDIT_RING_ENTRY, *PAUDIT_RING_ENTRY;
#pragma pack(pop)

// Audit ring buffer (must match kernel AUDIT_RING_BUFFER)
#pragma pack(push, 1)
typedef struct _AUDIT_RING_BUFFER {
    volatile long Head;
    volatile long Tail;
    AUDIT_RING_ENTRY Entries[AUDIT_RING_SIZE];
} AUDIT_RING_BUFFER, *PAUDIT_RING_BUFFER;
#pragma pack(pop)

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
    bool enabled = true;   // UI 可开关: false 时该规则不参与匹配
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
    ZETA_DRIVER_API void zeta_driver_set_msg_ctx_callback(void* cb);

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
