#include "behavior_engine.h"
#include <algorithm>
#include <TlHelp32.h>

// ============================================================
// Singleton
// ============================================================
ProcessBehaviorEngine& ProcessBehaviorEngine::instance() {
    static ProcessBehaviorEngine s;
    return s;
}

// ============================================================
// start — launch worker thread
// ============================================================
void ProcessBehaviorEngine::start() {
    if (m_running) return;
    m_running = true;
    m_worker = std::thread(&ProcessBehaviorEngine::workerLoop, this);
}

// ============================================================
// stop — graceful shutdown
// ============================================================
void ProcessBehaviorEngine::stop() {
    m_running = false;
    m_queueCv.notify_all();
    if (m_worker.joinable()) {
        m_worker.join();
    }
}

// ============================================================
// ingest — PRODUCER: enqueue only, return immediately
// Called from driver message thread. Must never block.
// ============================================================
void ProcessBehaviorEngine::ingest(unsigned long code, unsigned long pid, const std::wstring& path,
    const std::wstring& detail) {
    if (!m_enabled) return;

    // Quick inline check: only known event codes pass through
    switch (code) {
        case 2001: case 3001: case 4001: case 5001: case 5002:
        case 6001: case 6002: case 7001: case 7003:
        case 8001: case 8002:
            break;
        default:
            return;
    }

    // Push to queue (brief lock)
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        if (m_queue.size() < MAX_QUEUE_SIZE) {
            m_queue.push({code, pid, path, detail});
        }
    }
    m_queueCv.notify_one();
}

// ============================================================
// workerLoop — CONSUMER: runs on dedicated thread
// ============================================================
void ProcessBehaviorEngine::workerLoop() {
    long long lastMaintenance = GetTickCount64();

    while (m_running) {
        BehaviorEvent evt;
        bool hasEvent = false;

        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            m_queueCv.wait_for(lock, std::chrono::seconds(1), [this]() {
                return !m_queue.empty() || !m_running;
            });

            if (!m_queue.empty()) {
                evt = std::move(m_queue.front());
                m_queue.pop();
                hasEvent = true;
            }
        }

        if (hasEvent) {
            processEvent(evt);
        }

        long long now = GetTickCount64();
        if (now - lastMaintenance >= 30000) {
            lastMaintenance = now;
            doMaintenance();
        }
    }

    drainRemaining();
}

// ============================================================
// processEvent — CONSUMER: dynamic score accumulation
//
// Events and base scores (3.8):
//   2001  File intercept      exe/dll→20, other→10
//   3001  Registry intercept  service→30, Run key→25, other→10
//   5001  Ransom pattern      25 + min(10, fileWriteBursts*3)
//   6001  DLL from temp       1st=5, 2nd=10, >=3rd=15
//   6002  SilverFox sig       60 (definitive)
//   7001  Script release      1st=20, >=2nd=25
//   7003  Write burst         1st=10, 2nd=15, >=3rd=20
//
// Combination bonuses:
//   RunKey + (DLL|PE)             → +10  (persistence + execution)
//   writeBursts>=2 + peReleases>=1 → +15  (ransomware)
// ============================================================
void ProcessBehaviorEngine::processEvent(const BehaviorEvent& evt) {
    unsigned long code = evt.code;
    unsigned long pid = evt.pid;
    const std::wstring& path = evt.path;
    long long nowMs = GetTickCount64();

    int scoreAdd = 0;
    std::wstring reason;

    {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Enforce profile limit (evict oldest if full)
        if (m_profiles.size() >= MAX_PROFILES && m_profiles.find(pid) == m_profiles.end()) {
            unsigned long oldestPid = 0;
            long long oldestTime = LLONG_MAX;
            for (auto& [k, v] : m_profiles) {
                if (v.lastUpdateMs < oldestTime) {
                    oldestTime = v.lastUpdateMs;
                    oldestPid = k;
                }
            }
            if (oldestPid != 0) m_profiles.erase(oldestPid);
        }

        ProcessProfile& p = m_profiles[pid];
        p.pid = pid;

        // Process tree propagation: inherit score from parent (one-time on first event)
        if (p.lastUpdateMs == 0 && p.score == 0) {
            unsigned long ppid = lookupParentPid(pid);
            p.parentPid = ppid;
            if (ppid > 0) {
                auto parentIt = m_profiles.find(ppid);
                if (parentIt != m_profiles.end() && parentIt->second.score > 0) {
                    int inherited = (std::max)(1, parentIt->second.score / 2);
                    p.score = inherited;
                    p.hasScriptAncestor = parentIt->second.hasScriptAncestor;
                }
            }
        }

        // Whitelist check: skip scoring for learned processes
        bool whitelisted = isWhitelisted(pid);

        // ── Step 1: Update counters ──
        switch (code) {
            case 2001: {
                size_t dot = path.find_last_of(L'.');
                if (dot != std::wstring::npos) {
                    std::wstring ext = path.substr(dot);
                    if (ext == L".exe" || ext == L".dll" || ext == L".sys" ||
                        ext == L".scr" || ext == L".ocx") {
                        p.peReleases++;
                    }
                }
                break;
            }
            case 3001: {
                if (path.find(L"\\Run") != std::wstring::npos ||
                    path.find(L"\\RunOnce") != std::wstring::npos) {
                    p.wroteToRunKey = true;
                }
                break;
            }
            case 4001: p.diskWriteCount++; break;
            case 5001: break;
            case 5002: break;  // first-write header check (process already terminated by driver)
            case 6001: p.suspiciousDllLoads++; break;
            case 6002: p.hasMixedPublishers = true; break;
            case 7001: p.hasScriptAncestor = true; break;
            case 7003: p.fileWriteBursts++; break;
            case 8001: break;  // miner traffic — counter not needed
            case 8002: break;  // exfil traffic
        }

        // ── Step 2: Dynamic base score ──
        switch (code) {
            case 2001: {
                size_t dot = path.find_last_of(L'.');
                bool isExec = (dot != std::wstring::npos) && (
                    path.compare(dot, 4, L".exe") == 0 ||
                    path.compare(dot, 4, L".dll") == 0 ||
                    path.compare(dot, 4, L".sys") == 0 ||
                    path.compare(dot, 4, L".scr") == 0);
                if (isExec) { scoreAdd = 20; reason = L"拦截释放可执行文件 [20分]"; }
                else        { scoreAdd = 10; reason = L"文件防护拦截 [10分]"; }
                break;
            }
            case 3001: {
                bool isService = (path.find(L"\\Services\\") != std::wstring::npos);
                bool isRunKey  = (!isService && (
                    path.find(L"\\Run") != std::wstring::npos));
                if (isService)       { scoreAdd = 30; reason = L"拦截服务注册 [30分]"; }
                else if (isRunKey)   { scoreAdd = 25; reason = L"拦截自启项注册 [25分]"; }
                else                 { scoreAdd = 10; reason = L"注册表防护拦截 [10分]"; }
                break;
            }
            case 4001:
                scoreAdd = 30;
                reason = L"检测到磁盘擦写操作 [30分]";
                break;
            case 5001:
                scoreAdd = 25 + (std::min)(10, p.fileWriteBursts * 3);
                reason = L"可疑勒索行为模式 [" + std::to_wstring(scoreAdd) + L"分]";
                break;
            case 5002:
                scoreAdd = 70;
                reason = L"首次写文件头完整性检测告警（疑似勒索加密）[" + path + L"]";
                break;
            case 6001:
                if      (p.suspiciousDllLoads <= 1) scoreAdd = 5;
                else if (p.suspiciousDllLoads == 2) scoreAdd = 10;
                else                                scoreAdd = 15;
                reason = L"从临时目录加载DLL [第" + std::to_wstring(p.suspiciousDllLoads) + L"次]";
                break;
            case 6002:
                if (!evt.detail.empty()) {
                    scoreAdd = 60;
                    reason = L"签名不一致检测（银狐/黑加白加载）: " + evt.detail + L" [60分]";
                } else {
                    scoreAdd = 0;   // SilverFox 分析判定为 clean，不记分
                    reason = L"";
                }
                break;
            case 7001: {
                // Path-based scoring for script-released files
                std::wstring lower = path;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

                // Determine if it's an executable PE file
                size_t dot = path.find_last_of(L'.');
                bool isPE = (dot != std::wstring::npos) && (
                    path.compare(dot, 4, L".exe") == 0 ||
                    path.compare(dot, 4, L".dll") == 0 ||
                    path.compare(dot, 4, L".sys") == 0);

                if (!isPE) {
                    scoreAdd = 5;
                    reason = L"脚本进程释放数据文件 [5分]";
                } else {
                    int baseScore = 15;
                    // SilverFox: Users\Public → highly suspicious
                    if (lower.find(L"\\users\\public\\") != std::wstring::npos) {
                        baseScore += 10;
                        reason = L"脚本释放可执行文件到Public目录 [+" + std::to_wstring(baseScore) + L"分]";
                    }
                    // Persistence: AppData\Roaming
                    else if (lower.find(L"\\appdata\\roaming\\") != std::wstring::npos) {
                        baseScore += 5;
                        reason = L"脚本释放可执行文件到Roaming目录 [+" + std::to_wstring(baseScore) + L"分]";
                    }
                    // Legitimate install paths → reduce score
                    else if (lower.find(L"\\program files") != std::wstring::npos ||
                             lower.find(L"\\windows\\system32") != std::wstring::npos ||
                             lower.find(L"\\windows\\syswow64") != std::wstring::npos) {
                        baseScore = 5;
                        reason = L"脚本释放可执行文件到系统目录 [5分]";
                    }
                    // Temp/Downloads → neutral
                    else {
                        reason = L"脚本释放可执行文件 [15分]";
                    }
                    scoreAdd = (std::max)(5, baseScore);
                }
                break;
            }
            case 7003:
                if      (p.fileWriteBursts <= 1) scoreAdd = 10;
                else if (p.fileWriteBursts == 2) scoreAdd = 15;
                else                             scoreAdd = 20;
                reason = L"高频文件写入模式 [第" + std::to_wstring(p.fileWriteBursts) + L"轮]";
                break;
            case 8001:
                scoreAdd = 65;
                if (!evt.detail.empty()) {
                    reason = L"挖矿行为检测（流量上下行比异常）: " + evt.detail;
                } else {
                    reason = L"挖矿行为检测：流量上下行比异常 [" + path + L"]";
                }
                break;
            case 8002:
                scoreAdd = 55;
                if (!evt.detail.empty()) {
                    reason = L"数据外泄检测（流量上下行比异常）: " + evt.detail;
                } else {
                    reason = L"数据外泄检测：流量上下行比异常 [" + path + L"]";
                }
                break;
        }

        // Whitelisted processes: zero out score
        if (whitelisted) {
            scoreAdd = 0;
            reason = L"";
        }

        // HIPS user-approved: zero out score (user manually allowed)
        if (p.userApproved) {
            scoreAdd = 0;
            reason = L"用户已放行 - 此事件不计分";
        }

        // ── Step 3: Combination bonuses ──
        int combo = 0;
        if (p.wroteToRunKey && (p.suspiciousDllLoads >= 1 || p.peReleases >= 1) &&
            (code == 3001 || code == 6001 || code == 2001)) {
            combo += 10;
        }
        if (p.fileWriteBursts >= 2 && p.peReleases >= 1 &&
            (code == 2001 || code == 7003 || code == 5001)) {
            combo += 15;
        }
        scoreAdd += combo;
        if (combo > 0) reason += L" +组合加成";

        // ── Step 4: Decay and accumulate ──
        if (p.lastUpdateMs > 0) {
            long long elapsed = nowMs - p.lastUpdateMs;
            p.score = decayScore(p.score, elapsed);
        }
        p.score += scoreAdd;
        p.lastUpdateMs = nowMs;
        p.reasons.push_back(reason);

        if (!path.empty()) {
            p.artifacts.push_back(path);
        }
    }

    evaluateAndAlert(pid);
}

// ============================================================
// evaluateAndAlert — check threshold, notify if crossed
// ============================================================
void ProcessBehaviorEngine::evaluateAndAlert(unsigned long pid) {
    ProcessProfile profile;
    int score = 0;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_profiles.find(pid);
        if (it == m_profiles.end()) return;
        profile = it->second;
        score = profile.score;
    }

    auto getArtifacts = [&]() -> const std::vector<std::wstring>& {
        return profile.artifacts;
    };

    if (score >= ALERT_THRESHOLD && m_alertCallback) {
        // Only auto-kill if process was NOT user-approved
        if (!profile.userApproved) {
            std::wstring reasonsStr;
            for (size_t i = 0; i < profile.reasons.size() && i < 8; i++) {
                if (i > 0) reasonsStr += L"\n";
                reasonsStr += profile.reasons[i];
            }
            m_alertCallback(pid, score, reasonsStr.c_str(), getArtifacts());
        } else {
            // User-approved: just log to debug output, don't alert/auto-kill
            // The main.cpp HIPS "Allow" log already covers this
            wchar_t buf[256];
            swprintf_s(buf, 256, L"[EDR] PID=%lu Score=%d (user-approved → suppressed)\n",
                       pid, score);
            OutputDebugStringW(buf);
        }

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_profiles.find(pid);
            if (it != m_profiles.end()) {
                it->second.score = 0;
                it->second.reasons.clear();
                // Don't clear userApproved flag
            }
        }
    } else if (score >= WARN_THRESHOLD && m_warnCallback) {
        // User-approved: skip warn callback too (no annoying notifications for allowed procs)
        if (!profile.userApproved) {
            m_warnCallback(pid, score, L"检测到多个可疑行为组合", getArtifacts());
        }
    }
}

// ============================================================
// decayScore
// ============================================================
int ProcessBehaviorEngine::decayScore(int currentScore, long long elapsedMs) {
    if (currentScore <= 0) return 0;
    if (elapsedMs <= 0) return currentScore;
    double tSeconds = elapsedMs / 1000.0;
    double decay = exp(-DECAY_LAMBDA * tSeconds);
    int newScore = (int)(currentScore * decay);
    return newScore < 0 ? 0 : newScore;
}

// ============================================================
// doMaintenance — clean dead profiles
// ============================================================
void ProcessBehaviorEngine::doMaintenance() {
    std::lock_guard<std::mutex> lock(m_mutex);
    long long nowMs = GetTickCount64();

    auto it = m_profiles.begin();
    while (it != m_profiles.end()) {
        ProcessProfile& p = it->second;

        if (p.lastUpdateMs > 0) {
            long long elapsed = nowMs - p.lastUpdateMs;
            p.score = decayScore(p.score, elapsed);
            p.lastUpdateMs = nowMs;
        }

        if (p.score <= 0 && !isProcessAlive(it->first)) {
            it = m_profiles.erase(it);
        } else {
            ++it;
        }
    }
}

// ============================================================
// drainRemaining — cleanup at shutdown
// ============================================================
void ProcessBehaviorEngine::drainRemaining() {
    std::lock_guard<std::mutex> lock(m_queueMutex);
    while (!m_queue.empty()) {
        m_queue.pop();
    }
}

// ============================================================
// isProcessAlive
// ============================================================
bool ProcessBehaviorEngine::isProcessAlive(unsigned long pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h == NULL) return false;
    DWORD exitCode = 0;
    GetExitCodeProcess(h, &exitCode);
    CloseHandle(h);
    return exitCode == STILL_ACTIVE;
}

// ============================================================
// Callbacks
// ============================================================
void ProcessBehaviorEngine::setAlertCallback(AlertCallback cb) { m_alertCallback = cb; }
void ProcessBehaviorEngine::setWarnCallback(WarnCallback cb)   { m_warnCallback = cb; }

// ============================================================
// markUserAllowed — HIPS user clicked Allow
// Clears accumulated score and marks PID so future events
// from this process are excluded from EDR scoring.
// ============================================================
void ProcessBehaviorEngine::markUserAllowed(unsigned long pid) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_profiles.find(pid);
    if (it != m_profiles.end()) {
        it->second.userApproved = true;
        it->second.score = 0;
        it->second.reasons.push_back(L"用户手动放行 - 累计分数清零");
        OutputDebugStringW(L"[EDR] User approved PID, score cleared\n");
    }
}

// ============================================================
// addPenaltyScore — HIPS user clicked Block
// Adds penalty score so EDR can escalate (repeated blocking
// of same process → auto-terminate at threshold).
// ============================================================
void ProcessBehaviorEngine::addPenaltyScore(unsigned long pid, int extraScore) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ProcessProfile& p = m_profiles[pid];
        p.pid = pid;
        p.score += extraScore;
        p.lastUpdateMs = GetTickCount64();
        p.reasons.push_back(L"用户手动阻止 [+" + std::to_wstring(extraScore) + L"分]");
    }
    evaluateAndAlert(pid);
}

// ============================================================
// reportHipsScore — HIPS→EDR 联动上报
//
// 当 HIPS 规则匹配到高危操作（DENY）时，HIPS 将规则中定义
// 的分数上报给 EDR，EDR 将分数累加到进程的累计评分中。
//
// 评分规则:
//   HIPS_ALLOW 规则不计分（白名单，score=0）
//   HIPS_DENY 规则按规则定义的 score 累加
//   已标记 userApproved 的进程不计分
// ============================================================
void ProcessBehaviorEngine::reportHipsScore(unsigned long pid, int score,
    unsigned long code, const std::wstring& path) {
    if (!m_enabled || score <= 0) return;

    {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Enforce profile limit
        if (m_profiles.size() >= MAX_PROFILES && m_profiles.find(pid) == m_profiles.end()) {
            unsigned long oldestPid = 0;
            long long oldestTime = LLONG_MAX;
            for (auto& [k, v] : m_profiles) {
                if (v.lastUpdateMs < oldestTime) {
                    oldestTime = v.lastUpdateMs;
                    oldestPid = k;
                }
            }
            if (oldestPid != 0) m_profiles.erase(oldestPid);
        }

        ProcessProfile& p = m_profiles[pid];
        p.pid = pid;

        // User-approved processes: don't score
        if (p.userApproved) return;

        // Apply decay before adding
        long long nowMs = GetTickCount64();
        if (p.lastUpdateMs > 0) {
            long long elapsed = nowMs - p.lastUpdateMs;
            p.score = decayScore(p.score, elapsed);
        }

        // Map event code to description
        const wchar_t* codeDesc = L"未知";
        switch (code) {
            case 2001: codeDesc = L"文件保护拦截"; break;
            case 3001: codeDesc = L"注册表保护拦截"; break;
            case 4001: codeDesc = L"磁盘防护拦截"; break;
            case 5001: codeDesc = L"勒索行为拦截"; break;
            case 6001: codeDesc = L"注入攻击拦截"; break;
            case 6002: codeDesc = L"银狐行为拦截"; break;
        }

        p.score += score;
        p.lastUpdateMs = nowMs;
        p.reasons.push_back(std::wstring(codeDesc) + L" [HIPS+" + std::to_wstring(score) + L"分]");
        if (!path.empty()) {
            p.artifacts.push_back(path);
        }
    }

    evaluateAndAlert(pid);
}

// ============================================================
// clearScore — HIPS 放行时清零 EDR 评分
//
// 当 HIPS 规则匹配到 ALLOW（白名单放行）时，HIPS 通知 EDR
// 将进程的累计评分清零，表示该进程当前行为已被信任。
//
// 与 markUserAllowed 的区别:
//   markUserAllowed → userApproved=true（永久免检）+ 清零
//   clearScore      → 不清除 userApproved（后续仍可计分）+ 清零
// ============================================================
void ProcessBehaviorEngine::clearScore(unsigned long pid) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_profiles.find(pid);
    if (it != m_profiles.end() && it->second.score > 0) {
        it->second.score = 0;
        it->second.reasons.push_back(L"HIPS规则放行 - 累计分数清零");
        OutputDebugStringW(L"[EDR] HIPS allowed, score cleared for PID ");
        OutputDebugStringW(std::to_wstring(pid).c_str());
        OutputDebugStringW(L"\n");
    }
}

// ============================================================
// reportScanScore — Scan→EDR 联动上报
//
// 当自动扫描检测到威胁时，将扫描分数上报给 EDR，
// EDR 将分数累加到进程的累计评分中。
// ============================================================
void ProcessBehaviorEngine::reportScanScore(unsigned long pid, int score, 
    const std::wstring& name, const std::wstring& path) {
    if (!m_enabled || score <= 0) return;

    {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_profiles.size() >= MAX_PROFILES && m_profiles.find(pid) == m_profiles.end()) {
            unsigned long oldestPid = 0;
            long long oldestTime = LLONG_MAX;
            for (auto& [k, v] : m_profiles) {
                if (v.lastUpdateMs < oldestTime) {
                    oldestTime = v.lastUpdateMs;
                    oldestPid = k;
                }
            }
            if (oldestPid != 0) m_profiles.erase(oldestPid);
        }

        ProcessProfile& p = m_profiles[pid];
        p.pid = pid;

        if (p.userApproved) return;

        long long nowMs = GetTickCount64();
        if (p.lastUpdateMs > 0) {
            long long elapsed = nowMs - p.lastUpdateMs;
            p.score = decayScore(p.score, elapsed);
        }

        p.score += score;
        p.lastUpdateMs = nowMs;
        p.reasons.push_back(L"自动扫描检测 [" + name + L"] [+" + std::to_wstring(score) + L"分]");
        if (!path.empty()) {
            p.artifacts.push_back(path);
        }
    }

    evaluateAndAlert(pid);
}

// ============================================================
// lookupParentPid — one-time parent PID lookup via snapshot
// ============================================================
unsigned long ProcessBehaviorEngine::lookupParentPid(unsigned long pid) {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;
    unsigned long ppid = 0;
    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    if (Process32FirstW(h, &pe)) do {
        if (pe.th32ProcessID == pid) {
            ppid = pe.th32ParentProcessID;
            break;
        }
    } while (Process32NextW(h, &pe));
    CloseHandle(h);
    return ppid;
}

// ============================================================
// loadWhitelist — load learned process names from registry
// Driver stores them at: HKLM\...\ZETA_Drv\Parameters\LearnedProcesses
// ============================================================
void ProcessBehaviorEngine::loadWhitelist(const std::wstring& regKey) {
    HKEY hKey = NULL;
    std::lock_guard<std::mutex> lock(m_whitelistMutex);
    m_whitelist.clear();

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        WCHAR buffer[4096];
        DWORD type = 0, size = sizeof(buffer);
        if (RegQueryValueExW(hKey, L"LearnedProcesses", NULL, &type,
                             (LPBYTE)buffer, &size) == ERROR_SUCCESS && type == REG_MULTI_SZ) {
            const WCHAR* p = buffer;
            while (*p) {
                std::wstring name(p);
                if (!name.empty()) {
                    m_whitelist.push_back(name);
                }
                p += name.length() + 1;
            }
        }
        RegCloseKey(hKey);
    }
}

// ============================================================
// isWhitelisted — check if PID's process name is in whitelist
// ============================================================
bool ProcessBehaviorEngine::isWhitelisted(unsigned long pid) {
    std::lock_guard<std::mutex> lock(m_whitelistMutex);
    if (m_whitelist.empty()) return false;

    // Get process name from PID
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return false;

    std::wstring procName;
    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    if (Process32FirstW(h, &pe)) do {
        if (pe.th32ProcessID == pid) {
            procName = pe.szExeFile;
            break;
        }
    } while (Process32NextW(h, &pe));
    CloseHandle(h);

    if (procName.empty()) return false;

    // Case-insensitive comparison
    std::transform(procName.begin(), procName.end(), procName.begin(), ::towlower);
    for (const auto& wl : m_whitelist) {
        std::wstring lower = wl;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        if (procName == lower) return true;
    }
    return false;
}
