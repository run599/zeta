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

    // Counters
    int peReleases = 0;
    int suspiciousDllLoads = 0;
    int fileWriteBursts = 0;
    int diskWriteCount = 0;          // 4001 disk write count
    bool hasScriptAncestor = false;
    bool hitHoneypot = false;
    bool wroteToRunKey = false;
    bool hasMixedPublishers = false;
    bool hasUnsignedPE = false;
    bool userApproved = false;   // HIPS 用户手动放行 → 不计分，不清零

    // Scoring
    int score = 0;
    std::vector<std::wstring> reasons;
    std::vector<std::wstring> artifacts;   // file paths involved in scored events
    long long lastUpdateMs = 0;
};

// Lightweight event struct for the queue
struct BehaviorEvent {
    unsigned long code;
    unsigned long pid;
    std::wstring path;
    std::wstring detail;   // detailed description (e.g. "MixedSig: 2Sig+1Unsig")
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

private:
    ProcessBehaviorEngine() = default;
    ProcessBehaviorEngine(const ProcessBehaviorEngine&) = delete;

    // Worker thread main loop
    void workerLoop();

    // Consumer: process one event
    void processEvent(const BehaviorEvent& evt);

    void evaluateAndAlert(unsigned long pid);
    int decayScore(int currentScore, long long elapsedMs);
    bool isProcessAlive(unsigned long pid);
    unsigned long lookupParentPid(unsigned long pid);
    void doMaintenance();
    void drainRemaining();

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

    // ── Callbacks (called from worker thread) ──
    AlertCallback m_alertCallback = nullptr;
    WarnCallback  m_warnCallback = nullptr;

    // ── Auto-block mode ──
    std::atomic<bool> m_autoBlock{true};

    // ── Whitelist (learned process names from driver) ──
    std::vector<std::wstring> m_whitelist;
    std::mutex m_whitelistMutex;

    // ── Constants ──
    static constexpr int ALERT_THRESHOLD = 85;    // EDR 累计到 85分 → 弹窗 + 杀进程
    static constexpr int WARN_THRESHOLD = 40;     // 40分以上 → 通知栏提醒
    static constexpr int MAX_PROFILES = 512;
    static constexpr int DECAY_HALF_LIFE_SEC = 120;
    static constexpr double DECAY_LAMBDA = 0.693147 / DECAY_HALF_LIFE_SEC;
};
