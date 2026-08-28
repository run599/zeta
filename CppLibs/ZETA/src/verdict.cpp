#include "verdict.h"
#include <fstream>
#include <sstream>
#include <codecvt>
#include <locale>
#include <algorithm>
#include <cmath>

// ── Static storage ──
std::wstring VerdictWriter::s_dirPath;
std::wstring VerdictWriter::s_agentId;
std::mutex VerdictWriter::s_mutex;

// ============================================================
// JSON escaping (minimal — only what we need)
// ============================================================
std::wstring VerdictWriter::escapeJson(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    for (wchar_t c : s) {
        switch (c) {
            case L'"':  out += L"\\\""; break;
            case L'\\': out += L"\\\\"; break;
            case L'\n': out += L"\\n";  break;
            case L'\r': out += L"\\r";  break;
            case L'\t': out += L"\\t";  break;
            default:    out += c;       break;
        }
    }
    return out;
}

// ============================================================
// toJson — serialize Verdict to a single JSON line (UTF-8)
// ============================================================
std::string Verdict::toJson() const {
    // Build tags array
    std::wstring tagStr;
    for (size_t i = 0; i < tags.size(); i++) {
        if (i > 0) tagStr += L",";
        tagStr += L"\"" + VerdictWriter::escapeJson(tags[i]) + L"\"";
    }

    // Build artifacts array
    std::wstring artStr;
    for (size_t i = 0; i < artifacts.size(); i++) {
        if (i > 0) artStr += L",";
        artStr += L"\"" + VerdictWriter::escapeJson(artifacts[i]) + L"\"";
    }

    // Build reasons array
    std::wstring reasonStr;
    for (size_t i = 0; i < reasons.size(); i++) {
        if (i > 0) reasonStr += L",";
        reasonStr += L"\"" + VerdictWriter::escapeJson(reasons[i]) + L"\"";
    }

    wchar_t jsonBuf[4096];
    swprintf_s(jsonBuf,
        L"{"
        L"\"ver\":%d,"
        L"\"ts\":\"%ls\","
        L"\"aid\":\"%ls\","
        L"\"pid\":%lu,"
        L"\"ppid\":%lu,"
        L"\"img\":\"%ls\","
        L"\"score\":%d,"
        L"\"conf\":%.2f,"
        L"\"tags\":[%ls],"
        L"\"v\":\"%ls\","
        L"\"arts\":[%ls],"
        L"\"win\":\"%ls\","
        L"\"rs\":[%ls]"
        L"}",
        schemaVersion,
        VerdictWriter::formatTimestamp().c_str(),
        agentId.c_str(),
        pid, ppid,
        imageName.c_str(),
        score, confidence,
        tagStr.c_str(),
        verdict.c_str(),
        artStr.c_str(),
        window.c_str(),
        reasonStr.c_str()
    );

    // Convert UTF-16 -> UTF-8
    std::wstring ws(jsonBuf);
    std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
    try {
        return conv.to_bytes(ws);
    } catch (...) {
        // P0-崩溃修复: 判定 JSON 含非法 UTF-16 时降级为逐字节转换
        return std::string(ws.begin(), ws.end());
    }
}

// ============================================================
// fromAlert — factory method
// Builds a Verdict from the alert callback parameters.
// This runs on the behavior engine worker thread.
// ============================================================
Verdict Verdict::fromAlert(
    unsigned long pid,
    int score,
    const std::wstring& reasonsText,
    const std::vector<std::wstring>& reasonList,
    const std::vector<std::wstring>& artifacts /*= {}*/)
{
    Verdict v;
    v.timestampMs = GetTickCount64();
    v.agentId = VerdictWriter::resolveAgentId();
    v.pid = pid;
    v.ppid = 0;  // engine doesn't expose ppid through callback
    v.imageName = VerdictWriter::imageNameFromPid(pid);
    v.score = score;

    // Parse tags from reasons text
    v.tags = VerdictWriter::parseTags(reasonsText);

    // Window: derive from reasons count and the fact that this fired now
    // Format: "Nreasons-Ntags" or "N_events_in_window"
    wchar_t winBuf[64];
    swprintf_s(winBuf, L"%zu-evts-%zu-tags", reasonList.size(), v.tags.size());
    v.window = winBuf;

    // Confidence: score-based with tag boost
    v.confidence = VerdictWriter::calcConfidence(score, v.tags);

    // Verdict string
    v.verdict = VerdictWriter::decideVerdict(score, v.confidence);

    // Artifacts: file paths from the events that triggered this verdict
    v.artifacts = artifacts;

    // Reasons: from the reasons text, split by newline
    if (!reasonsText.empty()) {
        size_t start = 0;
        while (true) {
            size_t end = reasonsText.find(L'\n', start);
            if (end == std::wstring::npos) {
                v.reasons.push_back(reasonsText.substr(start));
                break;
            }
            v.reasons.push_back(reasonsText.substr(start, end - start));
            start = end + 1;
        }
    }

    // Also add individual reasonList entries if available and not duplicating
    for (const auto& r : reasonList) {
        if (std::find(v.reasons.begin(), v.reasons.end(), r) == v.reasons.end()) {
            v.reasons.push_back(r);
        }
    }

    return v;
}

// ============================================================
// VerdictWriter::resolveAgentId — get a stable machine ID
// Uses computer name.
// ============================================================
std::wstring VerdictWriter::resolveAgentId() {
    if (!s_agentId.empty()) return s_agentId;

    wchar_t buf[256];
    DWORD size = 256;
    if (GetComputerNameW(buf, &size)) {
        s_agentId = L"ZETA-";
        s_agentId += buf;
    } else {
        s_agentId = L"ZETA-UNKNOWN";
    }
    return s_agentId;
}

// ============================================================
// VerdictWriter::imageNameFromPid — get process name from PID
// Best-effort; returns empty if process already exited.
// ============================================================
std::wstring VerdictWriter::imageNameFromPid(unsigned long pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return L"";

    wchar_t path[MAX_PATH];
    DWORD size = MAX_PATH;
    std::wstring name;
    if (QueryFullProcessImageNameW(hProc, 0, path, &size)) {
        std::wstring fullPath(path);
        size_t pos = fullPath.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            name = fullPath.substr(pos + 1);
        } else {
            name = fullPath;
        }
    }
    CloseHandle(hProc);
    return name;
}

// ============================================================
// parseTags — map reason keywords to standard tags
// ============================================================
std::vector<std::wstring> VerdictWriter::parseTags(const std::wstring& reasonsText) {
    std::vector<std::wstring> tags;

    // Order matters: most specific first
    if (reasonsText.find(L"SilverFox") != std::wstring::npos || reasonsText.find(L"银狐") != std::wstring::npos) {
        tags.push_back(L"SILVERFOX_MIXED_SIG");
    }
    if (reasonsText.find(L"勒索行为") != std::wstring::npos || reasonsText.find(L"ransom") != std::wstring::npos) {
        tags.push_back(L"RANSOM_BEHAVIOR");
    }
    if (reasonsText.find(L"勒索加密") != std::wstring::npos) {
        tags.push_back(L"RANSOM_HEADER_CHECK");
    }
    if (reasonsText.find(L"DLL") != std::wstring::npos || reasonsText.find(L"临时目录") != std::wstring::npos) {
        tags.push_back(L"SUSPICIOUS_DLL_LOAD");
    }
    if (reasonsText.find(L"脚本") != std::wstring::npos || reasonsText.find(L"script") != std::wstring::npos) {
        tags.push_back(L"LINEAGE_SCRIPT");
    }
    if (reasonsText.find(L"高频") != std::wstring::npos || reasonsText.find(L"写入") != std::wstring::npos) {
        tags.push_back(L"RANSOM_WRITE_BURST");
    }
    if (reasonsText.find(L"挖矿") != std::wstring::npos || reasonsText.find(L"miner") != std::wstring::npos) {
        tags.push_back(L"TRAFFIC_MINER");
    }
    if (reasonsText.find(L"外泄") != std::wstring::npos || reasonsText.find(L"exfil") != std::wstring::npos) {
        tags.push_back(L"TRAFFIC_EXFIL");
    }

    // Deduplicate
    std::sort(tags.begin(), tags.end());
    tags.erase(std::unique(tags.begin(), tags.end()), tags.end());

    return tags;
}

// ============================================================
// calcConfidence — heuristic confidence based on score + tags
// ============================================================
double VerdictWriter::calcConfidence(int score, const std::vector<std::wstring>& tags) {
    // Base: score / 100
    double conf = (std::min)(1.0, score / 100.0);

    // SilverFox tag boosts confidence — very specific signal
    if (std::find(tags.begin(), tags.end(), L"SILVERFOX_MIXED_SIG") != tags.end()) {
        conf = (std::max)(conf, 0.85);
    }

    // Multiple tags → higher confidence (correlated signals)
    if (tags.size() >= 2) {
        conf = (std::min)(1.0, conf + 0.1);
    }
    if (tags.size() >= 3) {
        conf = (std::min)(1.0, conf + 0.1);
    }

    return conf;
}

// ============================================================
// decideVerdict — map (score, confidence) to label
// ============================================================
std::wstring VerdictWriter::decideVerdict(int score, double confidence) {
    if (score >= VERDICT_ALERT_THRESHOLD && confidence >= 0.8) {
        return L"malicious";
    }
    if (score >= VERDICT_WARN_THRESHOLD) {
        return L"suspicious";
    }
    return L"clean";
}

// ============================================================
// formatTimestamp — ISO 8601 timestamp for readability
// ============================================================
std::wstring VerdictWriter::formatTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[32];
    swprintf_s(buf, L"%04d-%02d-%02dT%02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// ============================================================
// VerdictWriter::init — create verdict directory
// Call once at startup.
// ============================================================
void VerdictWriter::init(const std::wstring& baseDir) {
    s_dirPath = baseDir + L"\\Verdicts";
    CreateDirectoryW(s_dirPath.c_str(), nullptr);

    // Resolve agent ID once at init
    resolveAgentId();

    // Log file path for debugging
    std::string logMsg = "[VerdictWriter] Verdicts dir: " +
        std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(s_dirPath) +
        " agent=" +
        std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(s_agentId);
    OutputDebugStringA(logMsg.c_str());
}

// ── Max file size before rotation (10 MB) ──
static constexpr LONGLONG VERDICT_MAX_FILE_SIZE = 10LL * 1024 * 1024;

// ── Format a timestamp safe for filenames (no colons) ──
static std::wstring fileTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[24];
    swprintf_s(buf, L"%04d%02d%02d_%02d%02d%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// ============================================================
// VerdictWriter::write — append one verdict as a JSON line
// Thread-safe via static mutex (very brief lock, just file I/O).
// Auto-rotates when file exceeds VERDICT_MAX_FILE_SIZE.
// ============================================================
void VerdictWriter::write(const Verdict& v) {
    if (s_dirPath.empty()) return;

    std::lock_guard<std::mutex> lock(s_mutex);

    std::wstring filePath = s_dirPath + L"\\ZETA_CPP.verdict.jsonl";

    // ── Check file size and rotate if needed ──
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fad)) {
        ULARGE_INTEGER fileSize;
        fileSize.LowPart = fad.nFileSizeLow;
        fileSize.HighPart = fad.nFileSizeHigh;
        if (fileSize.QuadPart >= VERDICT_MAX_FILE_SIZE) {
            std::wstring rotated = s_dirPath + L"\\ZETA_CPP.verdict." +
                                   fileTimestamp() + L".jsonl";
            MoveFileW(filePath.c_str(), rotated.c_str());
        }
    }

    std::ofstream file(filePath, std::ios::app | std::ios::binary);
    if (!file.is_open()) return;

    std::string json = v.toJson();
    file.write(json.data(), json.size());
    file.put('\n');
    file.close();
}

// ============================================================
// P1-3: 修复 ALERT_THRESHOLD 不一致
// 原 verdict.cpp 中 #define ALERT_THRESHOLD 60 与 behavior_engine.h 的 85 不一致
// 且该 #define 实际未被使用 (decideVerdict 使用 VERDICT_ALERT_THRESHOLD)
// 已删除死代码，统一使用 verdict.h 中的 VERDICT_ALERT_THRESHOLD(85)
// ============================================================
