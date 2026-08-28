#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <cstdint>
#include <queue>
#include <condition_variable>
#include <thread>
#include <atomic>

// ============================================================
// ProcessBehaviorEngine — User-mode behavior risk scoring
//
// Architecture: Producer-Consumer
//   Producer: onDriverMessage (message thread) → ingest() → enqueue
//   Consumer: worker thread → dequeue → score → evaluate → notify
//
// ingest() is O(1) lock-and-push. All heavy work (WinVerifyTrust,
// process lookup, scoring, notification) runs on the worker thread.
// This prevents the driver message thread from ever blocking.
// ============================================================

struct ProcessProfile {
    unsigned long pid = 0;
    unsigned long parentPid = 0;
    long long startTimeMs = 0;
    std::wstring processPath;   // [FIX] 进程完整路径 (用于系统路径检测)

    // ── 基础计数器 ──
    int peReleases = 0;
    int suspiciousDllLoads = 0;
    int fileWriteBursts = 0;
    int diskWriteCount = 0;
    bool hasScriptAncestor = false;
    bool hitHoneypot = false;
    bool wroteToRunKey = false;
    bool hasMixedPublishers = false;
    bool hasUnsignedPE = false;
    bool userApproved = false;

    // ── 上下文感知状态 ──
    unsigned char trustLevel = 0;     // 最近一次事件的进程信任级别
    int untrustedPeCount = 0;         // 无签名进程释放的 PE 数
    int offsetZeroWriteCount = 0;     // offset=0 写入次数 (勒索特征)
    int tempPathPeCount = 0;          // 从 Temp 路径释放的 PE 数
    int scriptChainDepth = 0;         // 最大脚本链深度
    int sensitiveRegWriteCount = 0;   // 敏感注册表写入次数
    int exclusiveWriteCount = 0;      // 独占写入次数
    int honeyFileTouchCount = 0;      // 蜜罐文件触碰次数
    int threadCreateCount = 0;        // 线程创建事件计数
    int remoteThreadCount = 0;        // 远程线程注入事件计数 (驱动标记 ,R)
    int driverLoadCount = 0;          // 驱动加载事件计数 (7010, 供状态机 BYOVD 判定)
    int sameEventRepeatCount = 0;     // 同类型事件连续重复次数
    unsigned long lastEventCode = 0;  // 上次事件码 (用于重复检测)
    long long lastRepeatEventMs = 0;  // 上次重复事件时间
    long long firstEventMs = 0;       // 首次事件时间 (用于速率计算)
    int totalEvents = 0;              // 总事件数

    // ── 行为序列追踪 (新增) ──
    // 记录最近 N 个事件的 (code, path前缀) 用于序列匹配
    static constexpr int SEQ_WINDOW = 16;
    struct SeqEntry {
        unsigned long code;
        unsigned short fileFlags;
        unsigned short regFlags;
        unsigned char trustLevel;
    };
    SeqEntry recentSequence[SEQ_WINDOW] = {};
    int seqHead = 0;  // 环形缓冲区写指针
    int seqCount = 0; // 已填充的事件数

    // Scoring
    int score = 0;
    // P2-6: 二维评分分量
    //   confidence: 证据强度 (0.0~1.0)，来自签名/已知规则/血缘等硬证据
    //   severity:   动作危害 (0.0~1.0)，来自进程注入/文件落地/注册表等危害动作
    // 判定 = confidence * severity >= 阈值，避免"高分低危"(合法安装器)误报
    double confidence = 0.0;
    double severity = 0.0;
    std::vector<std::wstring> reasons;
    std::vector<std::wstring> artifacts;
    long long lastUpdateMs = 0;
};

// IRP 语义标签 (内核提取，8 bytes)
// 与 zeta_driver.h 中的 ZETA_IRP_CONTEXT 保持一致
struct IrpSemantic {
    unsigned char opType;        // IrpOperationType
    unsigned char trustLevel;    // ProcessTrustLevel
    unsigned short fileFlags;    // FileSemanticFlags 位组合
    unsigned short regFlags;     // RegSemanticFlags 位组合
    unsigned char scriptDepth;   // 脚本调用深度
    unsigned char flags;         // ContextFlags (byte 7)

    // 操作类型检测
    bool isFileCreate()  const { return opType == 0; }
    bool isFileWrite()   const { return opType == 1; }
    bool isFileRename()  const { return opType == 2; }
    bool isFileDelete()  const { return opType == 3; }
    bool isRegOp()       const { return opType >= 10 && opType <= 13; }

    // ContextFlags (byte 7)
    bool replaceIfExists()    const { return (flags & 0x01) != 0; }
    bool dispositionEx()      const { return (flags & 0x02) != 0; }
    bool dispositionDelete()  const { return (flags & 0x04) != 0; }
    bool hasTransaction()     const { return (flags & 0x08) != 0; }
    bool isScriptHost()        const { return (flags & 0x10) != 0; }
    bool hasScriptAncestor()   const { return (flags & 0x20) != 0; }

    // 文件语义标志便捷查询
    bool isPeFile()    const { return (fileFlags & 0x0001) != 0; }
    bool isScript()    const { return (fileFlags & 0x0002) != 0; }
    bool isDocument()  const { return (fileFlags & 0x0004) != 0; }
    bool offsetZero()  const { return (fileFlags & 0x0008) != 0; }
    bool largeWrite()  const { return (fileFlags & 0x0010) != 0; }
    bool hiddenFile()  const { return (fileFlags & 0x0020) != 0; }
    bool deleteOp()    const { return (fileFlags & 0x0080) != 0; }
    bool exclusive()   const { return (fileFlags & 0x0100) != 0; }
    bool overwrite()   const { return (fileFlags & 0x0200) != 0; }
    bool isTempPath()  const { return (fileFlags & 0x1000) != 0; }
    bool isAppData()   const { return (fileFlags & 0x2000) != 0; }
    bool isSystem()    const { return (fileFlags & 0x4000) != 0; }
    bool isPublic()    const { return (fileFlags & 0x8000) != 0; }

    // 注册表语义标志便捷查询
    bool isRunKey()    const { return (regFlags & 0x0001) != 0; }
    bool isService()   const { return (regFlags & 0x0002) != 0; }
    bool isIfeo()      const { return (regFlags & 0x0004) != 0; }
    bool isUacBypass() const { return (regFlags & 0x0008) != 0; }
    bool isDefender()  const { return (regFlags & 0x0010) != 0; }

    bool isTrusted() const {
        return trustLevel >= 3;  // SIGNED, MS_SIGNED, SYSTEM, ZETA
    }
    bool isUntrusted() const {
        return trustLevel <= 1;  // UNKNOWN, NONE
    }
};

// ============================================================
// 状态机 HIPS 规则引擎 (P1-状态机)
// 两层 JSON 规则: Rules_Conditions.json(条件库) + Rules_Compose.json(组装规则)
// ============================================================

// 单一条件定义 (对应 Rules_Conditions.json 的 conditions[id])
struct StateMachineCondition {
    std::wstring id;
    std::wstring type;     // process_state / event / relation
    std::wstring field;    // ProcessProfile 字段 或 事件属性
    std::wstring op;       // eq/ne/gt/ge/lt/le/contains/startswith/endswith/exists
    std::wstring value;    // 比较值 (字符串形式, 数字在求值时转换)
    bool expect = true;    // 期望结果, false 表示取反
};

// 组装规则 (对应 Rules_Compose.json 的 rules[i])
struct StateMachineRule {
    std::wstring id;
    std::wstring name;
    int action = 0;        // 0放行 1阻止 2询问 3重定向 4放行+修复
    int score = 0;
    int priority = 10;     // 越小越优先, 豁免规则 priority=1
    std::wstring block_at; // file_write/reg_write/image_load/process_create/disk_write/net_connect/apc_inject
    std::wstring reversibility; // none/full/partial
    std::wstring redirect_to;   // action=3 时重定向目标
    std::vector<std::wstring> all_conds;  // AND 组合的条件 id
    std::vector<std::wstring> any_conds;  // OR 组合的条件 id
    long long window_ms = 0;  // 时间窗 (毫秒), 0=不检查
};

// 状态机判定结果
struct StateMachineVerdict {
    bool hit = false;
    const StateMachineRule* rule = nullptr;
};

// Lightweight event struct for the queue
struct BehaviorEvent {
    unsigned long code;
    unsigned long pid;
    std::wstring path;
    std::wstring detail;   // detailed description (e.g. "MixedSig: 2Sig+1Unsig")
    IrpSemantic ctx;       // 内核提取的语义标签 (8 bytes)
};

class ProcessBehaviorEngine {
public:
    using AlertCallback = void (*)(unsigned long pid, int score, const wchar_t* reasons,
                                   const std::vector<std::wstring>& artifacts);
    using WarnCallback  = void (*)(unsigned long pid, int score, const wchar_t* message,
                                   const std::vector<std::wstring>& artifacts);

    static ProcessBehaviorEngine& instance();

    // Start the worker thread (call once from init)
    void start();

    // Stop gracefully (call from shutdown)
    void stop();

    // Producer: enqueue event, return immediately. O(1) + brief lock.
    void ingest(unsigned long code, unsigned long pid, const std::wstring& path,
                const std::wstring& detail = L"");

    // Producer: enqueue event with IRP context (新接口)
    void ingestWithContext(unsigned long code, unsigned long pid,
                          const std::wstring& path, const IrpSemantic& ctx,
                          const std::wstring& detail = L"");

    // P0-自杀修复: 设置 ZETA.exe 自身 PID, 评分/告警/处置入口对自身绝对豁免
    void setSelfPid(unsigned long pid) { m_selfPid = pid; }
    bool isSelf(unsigned long pid) const { return m_selfPid != 0 && pid == m_selfPid; }

    bool isEngineEnabled() const { return m_enabled; }
    void setEnabled(bool en) { m_enabled = en; }

    void setAlertCallback(AlertCallback cb);
    void setWarnCallback(WarnCallback cb);

    // Auto-block mode: when score >= 60, auto-kill without user prompt
    void setAutoBlock(bool en) { m_autoBlock = en; }
    bool isAutoBlock() const { return m_autoBlock; }

    // Whitelist: load learned process names from driver's registry
    void loadWhitelist(const std::wstring& regKey);
    bool isWhitelisted(unsigned long pid);

    // HIPS-EDR integration: record user decision
    void markUserAllowed(unsigned long pid);         // user clicked Allow → zero score
    void addPenaltyScore(unsigned long pid, int extraScore);  // user clicked Block → +extra

    // HIPS→EDR linkage: report a HIPS rule's score to the process's cumulative score
    // Called when a HIPS rule (with score>0) matches a DENY action.
    void reportHipsScore(unsigned long pid, int score, unsigned long code,
                         const std::wstring& path);

    // HIPS→EDR linkage: clear a process's score when a HIPS ALLOW rule matches
    // (different from markUserAllowed - does NOT set userApproved)
    void clearScore(unsigned long pid);

    // Scan→EDR linkage: report scan score from auto-scan
    void reportScanScore(unsigned long pid, int score, const std::wstring& name, 
                         const std::wstring& path);

    // ── 状态机 HIPS 规则引擎 (P1-状态机) ──
    void loadStateMachineRules(const std::wstring& conditionsPath,
                               const std::wstring& composePath);
    // 状态机命中回调 (由 main.cpp 设置, 用于按 block_at 处置)
    using StateMachineCallback = void (*)(unsigned long pid, const wchar_t* ruleId,
                                          const wchar_t* ruleName, int action, int score);
    void setStateMachineCallback(StateMachineCallback cb) { m_smCallback = cb; }

private:
    ProcessBehaviorEngine() = default;
    ProcessBehaviorEngine(const ProcessBehaviorEngine&) = delete;

    // Worker thread main loop
    void workerLoop();

    // Consumer: process one event
    void processEvent(const BehaviorEvent& evt);

    // 上下文感知评分 (新增)
    int scoreWithContext(const BehaviorEvent& evt, ProcessProfile& p);
    int detectBehaviorSequence(ProcessProfile& p);
    bool isScriptChain(ProcessProfile& p);

    void evaluateAndAlert(unsigned long pid);
    int decayScore(int currentScore, long long elapsedMs);
    bool isProcessAlive(unsigned long pid);
    unsigned long lookupParentPid(unsigned long pid);
    void doMaintenance();
    void drainRemaining();

    // ── 状态机实现 (P1-状态机) ──
    void evaluateStateMachine(const BehaviorEvent& evt, ProcessProfile& p);
    bool evalCondition(const StateMachineCondition& c, const BehaviorEvent& evt, ProcessProfile& p);
    bool evalRelationTrustedChain(ProcessProfile& p, int depth);
    void parseConditionsJson(const std::wstring& json);
    void parseRulesJson(const std::wstring& json);
    std::wstring extractJsonKey(const std::wstring& obj, const std::wstring& key);
    int extractJsonInt(const std::wstring& obj, const std::wstring& key, int def);

    // ── State ──
    std::unordered_map<unsigned long, ProcessProfile> m_profiles;
    std::mutex m_mutex;

    // ── Queue (producer-consumer) ──
    std::queue<BehaviorEvent> m_queue;
    std::mutex m_queueMutex;
    std::condition_variable m_queueCv;
    static constexpr size_t MAX_QUEUE_SIZE = 4096;

    // ── Worker thread ──
    std::thread m_worker;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_enabled{true};
    std::atomic<unsigned long> m_selfPid{0};  // P0-自杀修复: ZETA.exe 自身 PID

    // ── Callbacks (called from worker thread) ──
    AlertCallback m_alertCallback = nullptr;
    WarnCallback  m_warnCallback = nullptr;

    // ── Auto-block mode ──
    std::atomic<bool> m_autoBlock{true};

    // ── Whitelist (learned process names from driver) ──
    std::vector<std::wstring> m_whitelist;
    std::mutex m_whitelistMutex;

    // ── 状态机规则 (P1-状态机) ──
    std::unordered_map<std::wstring, StateMachineCondition> m_smConditions;
    std::vector<StateMachineRule> m_smRules;
    std::mutex m_smMutex;
    StateMachineCallback m_smCallback = nullptr;

    // ── Constants ──
    static constexpr int ALERT_THRESHOLD = 85;    // EDR 累计到 85分 → 弹窗 + 杀进程
    static constexpr int WARN_THRESHOLD = 40;     // 40分以上 → 通知栏提醒
    // P2-6: 二维判定阈值 (confidence * severity)
    static constexpr double ALERT_CONF_SEV = 0.45;  // 置信×危害 ≥ 0.45 → ALERT
    static constexpr double WARN_CONF_SEV = 0.18;   // ≥ 0.18 → WARN
    static constexpr int MAX_PROFILES = 512;
    static constexpr int DECAY_HALF_LIFE_SEC = 120;
    static constexpr double DECAY_LAMBDA = 0.693147 / DECAY_HALF_LIFE_SEC;

    // P2-6: 由 score 反推 severity 的辅助常量 (score∈[0,100] 映射到 [0,1])
    static double severityFromScore(int score) {
        double s = (double)score / 100.0;
        return s > 1.0 ? 1.0 : s;
    }
};
