#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <mutex>
#include <cstdint>

// ============================================================
// Verdict — Structured verdict output for ProcessBehaviorEngine
//
// The engine generates scores internally. When the score crosses
// ALERT_THRESHOLD (60), a Verdict is produced and written to
// a JSONL file under D:\ZETA\Verdicts\.
//
// Each line is a complete JSON object (one per alert).
// This is the "2KB 判决书" that can later be uploaded to cloud.
// ============================================================

struct Verdict {
    int schemaVersion = 1;
    std::wstring agentId;               // machine identifier
    uint64_t timestampMs = 0;           // GetTickCount64 at alert time
    unsigned long pid = 0;
    unsigned long ppid = 0;
    std::wstring imageName;             // e.g. "svchost.exe"
    int score = 0;                      // 0-100
    double confidence = 0.0;            // 0.0-1.0
    std::vector<std::wstring> tags;     // e.g. {"SILVERFOX_MIXED_SIG","LINEAGE_SCRIPT"}
    std::wstring verdict;               // "clean"|"suspicious"|"malicious"
    std::vector<std::wstring> artifacts; // key file paths involved
    std::wstring window;                // time window description: "3s-5evt"
    std::vector<std::wstring> reasons;  // human-readable reasons from engine

    // Serialize to one JSON line (UTF-16 -> UTF-8 internally)
    std::string toJson() const;

    // Factory: build from engine callback params + reason strings + artifacts
    static Verdict fromAlert(
        unsigned long pid,
        int score,
        const std::wstring& reasonsText,
        const std::vector<std::wstring>& reasonList,
        const std::vector<std::wstring>& artifacts = {}
    );
};

// ============================================================
// VerdictWriter — thread-safe JSONL append
// ============================================================
class VerdictWriter {
public:
    // Init verdict directory. Call once at startup.
    static void init(const std::wstring& baseDir);

    // Append one verdict (thread-safe, O(1) lock).
    static void write(const Verdict& v);

    // Escape helpers — public so Verdict::toJson() can access them
    static std::wstring escapeJson(const std::wstring& s);
    static std::wstring formatTimestamp();

private:
    friend struct Verdict;  // Verdict::fromAlert needs access to helpers

    static std::wstring s_dirPath;
    static std::wstring s_agentId;
    static std::mutex s_mutex;

    static std::wstring resolveAgentId();
    static std::wstring imageNameFromPid(unsigned long pid);
    static std::vector<std::wstring> parseTags(const std::wstring& reasonsText);
    static double calcConfidence(int score, const std::vector<std::wstring>& tags);
    static std::wstring decideVerdict(int score, double confidence);
};

// Thresholds used by VerdictWritier::decideVerdict
// (These mirror the engine's ALERT_THRESHOLD/WARN_THRESHOLD)
constexpr int VERDICT_ALERT_THRESHOLD = 60;
constexpr int VERDICT_WARN_THRESHOLD = 30;
