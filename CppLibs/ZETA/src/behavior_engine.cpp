#include "behavior_engine.h"
#include <algorithm>
#include <TlHelp32.h>
#include <wintrust.h>
#include <softpub.h>
#pragma comment(lib, "wintrust.lib")

// Forward declarations
static std::wstring getDefaultReason(unsigned long code, const std::wstring& path,
    const ProcessProfile& p);

// ── 有效数字签名校验 (带缓存) ──
// 直接对文件做 WinVerifyTrust，避免依赖内核 trustLevel 上报是否可靠。
// 用简单的最近命中缓存降低性能开销 (同一进程路径不会被反复校验)。
static bool isSignedProcess(const std::wstring& path) {
    if (path.empty()) return false;
    // 缓存: path -> 结果 (最多 256 条)
    static std::unordered_map<std::wstring, bool> s_cache;
    static std::mutex s_cacheMtx;
    {
        std::lock_guard<std::mutex> lk(s_cacheMtx);
        auto it = s_cache.find(path);
        if (it != s_cache.end()) return it->second;
    }

    std::wstring lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    // 系统目录的程序视为可信 (内核/系统组件绝大多数有签名，且路径本身即信任源)
    bool sysPath = lower.find(L"\\windows\\system32\\") != std::wstring::npos ||
                   lower.find(L"\\windows\\syswow64\\") != std::wstring::npos ||
                   lower.find(L"\\program files\\") != std::wstring::npos ||
                   lower.find(L"\\program files (x86)\\") != std::wstring::npos ||
                   lower.find(L"\\windowsapps\\") != std::wstring::npos;

    bool signedOk = false;
    if (!sysPath) {
        // 仅对系统目录之外的路径做昂贵的 WinVerifyTrust 校验
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = path.c_str();
        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA wtd{};
        wtd.cbStruct = sizeof(wtd);
        wtd.dwUIChoice = WTD_UI_NONE;
        wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wtd.dwUnionChoice = WTD_CHOICE_FILE;
        wtd.pFile = &fileInfo;
        wtd.dwStateAction = WTD_STATEACTION_VERIFY;
        LONG status = WinVerifyTrust(NULL, &policyGUID, &wtd);
        // 关闭状态 (避免句柄泄漏)
        WINTRUST_DATA wtdClose = wtd;
        wtdClose.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &policyGUID, &wtdClose);
        signedOk = (status == ERROR_SUCCESS);
    } else {
        // 系统目录进程: 信任路径即可 (绝大多数已签名，不逐一验)
        signedOk = true;
    }

    {
        std::lock_guard<std::mutex> lk(s_cacheMtx);
        if (s_cache.size() > 256) s_cache.clear();
        s_cache[path] = signedOk;
    }
    return signedOk;
}

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
// ingest — PRODUCER: enqueue only, return immediately (旧接口，兼容)
// ============================================================
void ProcessBehaviorEngine::ingest(unsigned long code, unsigned long pid, const std::wstring& path,
    const std::wstring& detail) {
    ingestWithContext(code, pid, path, IrpSemantic{}, detail);
}

// ============================================================
// ingestWithContext — PRODUCER: 带 IRP 语义上下文的入队
// ============================================================
void ProcessBehaviorEngine::ingestWithContext(unsigned long code, unsigned long pid,
    const std::wstring& path, const IrpSemantic& ctx,
    const std::wstring& detail) {
    if (!m_enabled) return;

    // P0-自杀修复: ZETA.exe 自身进程绝对豁免 — 不评分、不入队
    // ZETA 启动时自检行为 (驱动加载 7010 / 注册表 3001 / APC 6010 / 写配置)
    // 会被引擎对自身 PID 累加评分, 导致启动时 remediateProcess 把自己杀掉。
    if (isSelf(pid)) return;

    switch (code) {
        case 2001: case 3001: case 4001: case 5001: case 5002:
        case 6001: case 6002: case 6010: case 7001: case 7003: case 7006:
        case 7008: case 7010: case 8001: case 8002:
            break;
        default:
            return;
    }

    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        if (m_queue.size() < MAX_QUEUE_SIZE) {
            BehaviorEvent evt;
            evt.code = code;
            evt.pid = pid;
            evt.path = path;
            evt.detail = detail;
            evt.ctx = ctx;
            m_queue.push(std::move(evt));
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
            // P0-崩溃修复(线程兜底): processEvent 内部 (状态机求值/评分/告警回调)
            // 任何 C++ 异常在此捕获, 绝不逃逸到线程边界触发 std::terminate
            // → __fastfail(FAST_FAIL_FATAL_APP_EXIT) → ucrtbase.dll c0000409 崩溃。
            try {
                processEvent(evt);
            } catch (...) {
                // 静默丢弃异常事件, 线程继续
            }
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
// 辅助: 从 PID 获取进程完整路径
// ============================================================
// P0-重大缺陷修复: 原实现用 Toolhelp 的 pe.szExeFile 只返回"纯文件名"
// (如 "git.exe"), 导致 isSignedProcess("git.exe") 的 WinVerifyTrust
// 因找不到文件而永远失败。签名判定 (7008/6010 注入者、trustedCheckPath)
// 全部基于此函数, 使得所有非系统目录的签名进程 (git/bun/QQ/CodeBuddy 等)
// 被误判为"无签名注入者" → 线程/APC 事件被反复加分到 100+ → 误处置。
// 修复: 改用 QueryFullProcessImageNameW 返回完整路径 (与 main.cpp
// 的 getProcessPath 保持一致), 使 WinVerifyTrust 能正确验证签名。
static std::wstring getProcessPathByPid(unsigned long pid) {
    if (pid == 0) return L"";
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return L"";
    WCHAR path[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    BOOL ok = QueryFullProcessImageNameW(h, 0, path, &size);
    CloseHandle(h);
    if (!ok) return L"";
    return std::wstring(path);
}

// ============================================================
// getInjectorPid — 从注入类事件的 path 解析"注入者(源)进程"PID
//   6010 (APC):  path = "SourcePid|TargetPid"  → 返回 SourcePid
//   7008 (远程线程): path = "PID,TID,R,CreatorPid" → 返回 CreatorPid
//   其他: 返回 0 (无注入者概念)
// 注意: 驱动上报时 6010 的 evt.pid=源(注入者)，7008 的 evt.pid=目标(受害者)，
//       两者语义不一致，故统一从 path 解析注入者，避免信任判断误用受害者身份。
// ============================================================
static unsigned long getInjectorPid(unsigned long code, const std::wstring& path) {
    if (code == 6010) {
        // "src|dst"
        size_t bar = path.find(L'|');
        if (bar != std::wstring::npos) {
            unsigned long src = 0;
            for (size_t i = 0; i < bar && path[i] >= L'0' && path[i] <= L'9'; i++)
                src = src * 10 + (unsigned long)(path[i] - L'0');
            return src;
        }
        return 0;
    }
    if (code == 7008) {
        // "pid,tid,R,creatorPid" — 第 4 段
        size_t rpos = path.find(L",R,");
        if (rpos != std::wstring::npos) {
            std::wstring tail = path.substr(rpos + 3);
            unsigned long creator = 0;
            for (size_t i = 0; i < tail.size() && tail[i] >= L'0' && tail[i] <= L'9'; i++)
                creator = creator * 10 + (unsigned long)(tail[i] - L'0');
            return creator;
        }
        return 0;
    }
    return 0;
}

// ============================================================
// processEvent — CONSUMER: context-aware scoring
//
// 评分策略 (v2 上下文感知):
//   基础分值: 与 v1 相同 (基于 event code + path)
//   上下文加成: 基于 IrpSemantic 标签 (内核提取的语义)
//   序列加成: 基于行为序列模式匹配
//   信任修正: 无签名进程加权, 微软签名进程减权
// ============================================================
void ProcessBehaviorEngine::processEvent(const BehaviorEvent& evt) {
    unsigned long code = evt.code;
    unsigned long pid = evt.pid;
    long long nowMs = GetTickCount64();

    int scoreAdd = 0;
    std::wstring reason;

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
        p.totalEvents++;

        // [FIX] 记录进程路径: 从 7006(process_create) 事件提取
        if (code == 7006 && !evt.path.empty()) {
            p.processPath = evt.path;
        }
        // Fallback: 其他事件类型下路径为空时，用快照查询
        if (p.processPath.empty()) {
            p.processPath = getProcessPathByPid(pid);
        }

        // Process tree propagation (unchanged)
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

        // 更新信任级别 (来自内核语义标签)
        if (evt.ctx.trustLevel > 0) {
            p.trustLevel = evt.ctx.trustLevel;
        }

        // 更新脚本链深度
        if (evt.ctx.scriptDepth > p.scriptChainDepth) {
            p.scriptChainDepth = evt.ctx.scriptDepth;
        }

        // 更新行为序列环形缓冲区
        auto& entry = p.recentSequence[p.seqHead];
        entry.code = code;
        entry.fileFlags = evt.ctx.fileFlags;
        entry.regFlags = evt.ctx.regFlags;
        entry.trustLevel = evt.ctx.trustLevel;
        p.seqHead = (p.seqHead + 1) % ProcessProfile::SEQ_WINDOW;
        if (p.seqCount < ProcessProfile::SEQ_WINDOW) p.seqCount++;

        // ── 重复事件检测 (频率加速度) ──
        if (p.lastEventCode == code && p.lastRepeatEventMs > 0) {
            long long elapsed = nowMs - p.lastRepeatEventMs;
            if (elapsed > 0 && elapsed < 3000) {
                p.sameEventRepeatCount++;
            } else {
                p.sameEventRepeatCount = (p.lastEventCode == code) ? 1 : 0;
            }
        } else {
            p.sameEventRepeatCount = 0;
        }
        p.lastEventCode = code;
        p.lastRepeatEventMs = nowMs;

        // ── 蜜罐文件触碰检测 ──
        if (code == 2001) {
            std::wstring lower = evt.path;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
            if (lower.find(L"zeta_honey") != std::wstring::npos ||
                lower.find(L"backup_secret") != std::wstring::npos) {
                p.honeyFileTouchCount++;
            }
        }

        bool whitelisted = isWhitelisted(pid);

        // ── 可信进程直接豁免 (治本降噪) ──
        // 内核已判定签名/系统/微软级 (trustLevel>=3)，或实时 WinVerifyTrust 验证有效签名，
        // 或位于系统/程序目录 → 直接跳过评分与告警，不再累加分数、不再刷屏。
        // 例外: 驱动加载(7010) 仍交给状态机 BYOVD 规则判定 (无签名拉驱动才是风险)。
        //
        // [SECURITY FIX] 注入类事件 (6010 APC / 7008 远程线程) 的信任判断必须基于
        //   "注入者(源进程)"，而非受害者(evt.pid):
        //   - 6010 驱动上报 evt.pid=源(注入者)，path="src|dst"
        //   - 7008 驱动上报 evt.pid=目标(受害者)，path="pid,tid,R,creatorPid"
        //   若用受害者身份判断，无签名恶意进程注入可信进程会被误判为可信而放过。
        unsigned long injectorPid = getInjectorPid(code, evt.path);
        std::wstring trustedCheckPath = p.processPath;
        if (trustedCheckPath.empty()) trustedCheckPath = getProcessPathByPid(pid);
        if (trustedCheckPath.empty()) trustedCheckPath = evt.path;
        // 注入事件: 改用注入者路径做签名校验
        if (injectorPid != 0) {
            std::wstring injectorPath = getProcessPathByPid(injectorPid);
            if (!injectorPath.empty()) trustedCheckPath = injectorPath;
            else trustedCheckPath.clear();  // P0-误判修复: 注入者已退出(查不到路径)时,
                                            // 绝不能用受害者(evt.pid)的身份去豁免/判定注入者。
                                            // 若保留 p.processPath, 无签名受害者会被当成
                                            // "注入者无签名" → 误判为恶意注入。
        }
        bool trustedByKernel = (evt.ctx.trustLevel >= 3);
        bool trustedByPath = isSignedProcess(trustedCheckPath);
        if (code != 7010 && (trustedByKernel || trustedByPath)) {
            // 仅记录到 profile (不加分、不告警)，保持最小可观测性
            p.trustLevel = (std::max)((int)p.trustLevel, trustedByKernel ? (int)evt.ctx.trustLevel : 3);
            return;
        }

        // ── Step 1: 基础评分 (保留 v1 逻辑) ──
        scoreAdd = scoreWithContext(evt, p);
        reason = evt.detail.empty() ? getDefaultReason(code, evt.path, p) : evt.detail;

        // ── Step 2: 上下文加成 (新增) ──
        int ctxBonus = 0;
        std::wstring ctxReason;

        // 无签名进程释放 PE → 加权
        if (evt.ctx.isPeFile() && evt.ctx.isUntrusted()) {
            p.untrustedPeCount++;
            if (p.untrustedPeCount == 1) {
                ctxBonus += 10;
                ctxReason = L"无签名进程释放PE [+" + std::to_wstring(10) + L"]";
            } else if (p.untrustedPeCount >= 3) {
                ctxBonus += 20;
                ctxReason = L"无签名进程多次释放PE(" + std::to_wstring(p.untrustedPeCount) + L"次) [+" + std::to_wstring(20) + L"]";
            }
        }

        // offset=0 写入文档 → 勒索特征
        if (evt.ctx.offsetZero() && evt.ctx.isDocument()) {
            p.offsetZeroWriteCount++;
            ctxBonus += 25;
            ctxReason = L"offset=0写入文档文件(疑似加密覆写) [+" + std::to_wstring(25) + L"]";
        }

        // Temp 路径释放 PE → 高风险
        if (evt.ctx.isPeFile() && evt.ctx.isTempPath()) {
            p.tempPathPeCount++;
            if (p.tempPathPeCount >= 2) {
                ctxBonus += 15;
                ctxReason = L"多次从Temp路径释放PE [+" + std::to_wstring(15) + L"]";
            }
        }

        // 脚本宿主释放 PE 文件 → 高风险（无文件攻击的关键指标）
        if (evt.ctx.isScriptHost() && evt.ctx.isPeFile()) {
            ctxBonus += 15;
            ctxReason = L"脚本解释器释放PE文件(疑似无文件攻击载荷) [+" + std::to_wstring(15) + L"]";
        }

        // 有脚本祖先 + 释放PE → 分层攻击
        if (evt.ctx.hasScriptAncestor() && evt.ctx.isPeFile() && !evt.ctx.isScriptHost()) {
            ctxBonus += 10;
            ctxReason = L"脚本衍生进程释放PE(分层攻击) [+" + std::to_wstring(10) + L"]";
        }

        // 脚本链深度 ≥ 3 → 攻击链
        if (p.scriptChainDepth >= 3) {
            ctxBonus += 20;
            ctxReason = L"脚本链深度=" + std::to_wstring(p.scriptChainDepth) + L"(疑似多级脚本攻击) [+" + std::to_wstring(20) + L"]";
        }

        // 敏感注册表写入 (IFEO/UAC/Defender) → 加权
        if (evt.ctx.isIfeo() || evt.ctx.isUacBypass() || evt.ctx.isDefender()) {
            p.sensitiveRegWriteCount++;
            ctxBonus += 15;
            ctxReason = L"敏感注册表操作(安全机制绕过) [+" + std::to_wstring(15) + L"]";
        }

        // 独占写入 PE → 可疑 (正常程序很少独占写 PE)
        if (evt.ctx.exclusive() && evt.ctx.isPeFile()) {
            p.exclusiveWriteCount++;
            ctxBonus += 10;
            ctxReason = L"独占写入PE文件 [+" + std::to_wstring(10) + L"]";
        }

        // 签名进程 → 减权 (合法系统操作)
        if (evt.ctx.trustLevel >= 3 && scoreAdd > 0) {
            int reduction = scoreAdd / 2;
            scoreAdd -= reduction;
            ctxReason = L"微软签名进程 [-" + std::to_wstring(reduction) + L"]";
        }

        scoreAdd += ctxBonus;
        if (!ctxReason.empty()) {
            reason += L" | " + ctxReason;
        }

        // ── Step 3: 行为序列检测 (新增) ──
        int seqBonus = detectBehaviorSequence(p);
        if (seqBonus > 0) {
            scoreAdd += seqBonus;
            reason += L" +序列加成[" + std::to_wstring(seqBonus) + L"]";
        }

        // Whitelist / userApproved checks (unchanged)
        if (whitelisted) {
            scoreAdd = 0;
            reason = L"";
        }
        if (p.userApproved) {
            scoreAdd = 0;
            reason = L"用户已放行 - 此事件不计分";
        }

        // ── Step 4: Decay and accumulate (unchanged) ──
        if (p.lastUpdateMs > 0) {
            long long elapsed = nowMs - p.lastUpdateMs;
            p.score = decayScore(p.score, elapsed);
        }
        p.score += scoreAdd;
        p.lastUpdateMs = nowMs;
        if (nowMs > 0 && p.firstEventMs == 0) p.firstEventMs = nowMs;
        p.reasons.push_back(reason);
        if (!evt.path.empty()) {
            p.artifacts.push_back(evt.path);
        }

        // P1-状态机: 事件驱动求值状态机规则 (命中按 action 处置)
        // 在锁块内调用 (p 为 m_profiles[pid] 引用), 内部只锁 m_smMutex, 不锁 m_mutex 避免死锁
        evaluateStateMachine(evt, p);
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

    // P2-6: 二维评分判定
    //   confidence: 证据强度 — 无签名/未知来源进程置信度高；微软签名进程置信度低
    //   severity:   危害程度 — 由累计 score 反推 (score 越高代表危害动作越多)
    // 仅当 score 达到传统阈值 "且" 二维乘积达标才告警，避免"高分低危"误报。
    double confidence = (profile.trustLevel <= 1) ? 0.9 : (profile.trustLevel <= 2 ? 0.6 : 0.2);
    double severity = ProcessBehaviorEngine::severityFromScore(score);
    double confSev = confidence * severity;

    if (score >= ALERT_THRESHOLD && confSev >= ALERT_CONF_SEV && m_alertCallback) {
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
            swprintf_s(buf, 256, L"[EDR] PID=%lu Score=%d confSev=%.2f (user-approved → suppressed)\n",
                       pid, score, confSev);
            OutputDebugStringW(buf);
        }

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_profiles.find(pid);
            if (it != m_profiles.end()) {
                it->second.score = 0;
                it->second.reasons.clear();
                it->second.confidence = 0.0;
                it->second.severity = 0.0;
                // Don't clear userApproved flag
            }
        }
    } else if (score >= WARN_THRESHOLD && confSev >= WARN_CONF_SEV && m_warnCallback) {
        // User-approved: skip warn callback too (no annoying notifications for allowed procs)
        if (!profile.userApproved) {
            m_warnCallback(pid, score, L"检测到多个可疑行为组合", getArtifacts());
        }
    } else {
        // 分数达标但二维乘积不足（典型：高分低危的合法安装器）→ 仅记录，不告警
        wchar_t buf[256];
        swprintf_s(buf, 256, L"[EDR] PID=%lu Score=%d confSev=%.2f (below conf×sev gate, suppressed)\n",
                   pid, score, confSev);
        OutputDebugStringW(buf);
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
    // P0-自杀修复: ZETA.exe 自身进程绝对豁免 — 用户惩罚评分
    if (isSelf(pid)) return;
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

    // P0-自杀修复: ZETA.exe 自身进程绝对豁免 — HIPS→EDR 联动评分
    if (isSelf(pid)) return;

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
            case 6010: codeDesc = L"APC注入拦截"; break;
            case 7010: codeDesc = L"驱动加载"; break;
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

    // P0-自杀修复: ZETA.exe 自身进程绝对豁免 — 自动扫描评分
    if (isSelf(pid)) return;

    // P0-4: 扫描分数断裂 — scanner 返回 0/1/3(0=干净,1=可疑,3=威胁), 此前被直接当作
    // 0~100 的分数累加, 导致 YARA/PE 命中只加 1~3 分, severityFromScore(3)=0.03,
    // 二维乘积远低于 ALERT_CONF_SEV=0.45, 自动扫描命中永远无法触发告警/处置.
    // 在此将 0/1/3 语义映射为真实分数: 威胁=100, 可疑=50.
    if (score >= 3) score = 100;
    else if (score == 1) score = 50;
    else return;   // 0 或其他非命中值不累加

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

    std::transform(procName.begin(), procName.end(), procName.begin(), ::towlower);
    for (const auto& wl : m_whitelist) {
        std::wstring lower = wl;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        if (procName == lower) return true;
    }
    return false;
}

// ============================================================
// scoreWithContext — 基础评分 (v1 逻辑提取，保持兼容)
// ============================================================
int ProcessBehaviorEngine::scoreWithContext(const BehaviorEvent& evt, ProcessProfile& p) {
    unsigned long code = evt.code;
    const std::wstring& path = evt.path;

    switch (code) {
        case 2001: {
            // ── 蜜罐文件触碰 → 直接高分 ──
            if (p.honeyFileTouchCount > 0) {
                return 80;
            }

            // ── P0: 基于操作类型分路 ──
            // 内核 PreSetInfo 发送的 rename/delete 也通过 code=2001 上报，
            // 但 IrpSemantic.opType 区分了 IRP_OP_FILE_CREATE / RENAME / DELETE
            if (evt.ctx.isFileRename()) {
                // 文件重命名评分（低基础，重点是频率和扩展名变化）
                int base = 5;
                // 重命名为 PE → 可疑（恶意软件常改名逃避检测）
                if (evt.ctx.isPeFile()) {
                    base = 10;
                    p.peReleases++;
                }
                // 重命名时覆盖已有文件 → +3
                if (evt.ctx.replaceIfExists()) base += 3;
                // 频率加速
                if (p.sameEventRepeatCount >= 3) base += 5;
                if (p.sameEventRepeatCount >= 6) base += 10;
                return base;
            }
            if (evt.ctx.isFileDelete()) {
                // 文件删除评分（低基础，避免误杀正常清理行为）
                int base = 3;
                if (evt.ctx.dispositionEx()) base += 2;     // Win10+ 高级删除
                if (evt.ctx.dispositionDelete()) base += 1; // 硬删除
                // 删除 PE 文件 → 可疑（恶意软件删除自身痕迹）
                if (evt.ctx.isPeFile()) base += 5;
                // 频率加速
                if (p.sameEventRepeatCount >= 5) base += 3;
                if (p.sameEventRepeatCount >= 10) base += 5;
                return base;
            }

            // 使用内核提供的 isPeFile 标签，fallback 到扩展名检测
            if (evt.ctx.isPeFile()) {
                p.peReleases++;
                int base = 20;
                // 频率加速: 连续多次 PE 释放
                if (p.sameEventRepeatCount >= 3) base += 10;
                if (p.sameEventRepeatCount >= 6) base += 20;
                return base;
            }
            size_t dot = path.find_last_of(L'.');
            if (dot != std::wstring::npos) {
                std::wstring ext = path.substr(dot);
                if (ext == L".exe" || ext == L".dll" || ext == L".sys" ||
                    ext == L".scr" || ext == L".ocx") {
                    p.peReleases++;
                    int base = 20;
                    if (p.sameEventRepeatCount >= 3) base += 10;
                    if (p.sameEventRepeatCount >= 6) base += 20;
                    return base;
                }
            }
            return 10;
        }
        case 3001: {
            // 频率加速: 同一进程反复改注册表
            int baseReg = 10;
            if (p.sameEventRepeatCount >= 3) baseReg += 8;
            if (p.sameEventRepeatCount >= 6) baseReg += 15;

            // 使用内核提供的 isService/isRunKey 标签
            if (evt.ctx.isService()) return 30 + baseReg;
            if (evt.ctx.isRunKey()) {
                p.wroteToRunKey = true;
                // 可信进程 (SIGNED/SYSTEM) 写 Run 键：降低评分
                // 可能是合法自注册行为 (如 internat.exe 写 Run\internat.exe)
                if (p.trustLevel >= 3) return 5;
                // [FIX] 信任级别未设置时，fallback 到进程路径检测
                // 系统路径 (System32/SysWOW64/Program Files) 的进程写 Run 键视为合法
                if (p.processPath.find(L"\\System32\\") != std::wstring::npos ||
                    p.processPath.find(L"\\SysWOW64\\") != std::wstring::npos ||
                    p.processPath.find(L"\\Program Files") != std::wstring::npos)
                    return 5;
                return 25 + baseReg;
            }
            // Fallback: path 匹配
            if (path.find(L"\\Services\\") != std::wstring::npos) return 30 + baseReg;
            if (path.find(L"\\Run") != std::wstring::npos) {
                p.wroteToRunKey = true;
                if (p.trustLevel >= 3) return 5;
                // [FIX] 同上: 系统路径进程写 Run 键视为合法
                if (p.processPath.find(L"\\System32\\") != std::wstring::npos ||
                    p.processPath.find(L"\\SysWOW64\\") != std::wstring::npos ||
                    p.processPath.find(L"\\Program Files") != std::wstring::npos)
                    return 5;
                return 25 + baseReg;
            }
            return 10;
        }
        case 5001: {
            // 勒索行为: 频率加速 — 连续爆发递增
            int base = 25 + (std::min)(10, p.fileWriteBursts * 3);
            if (p.sameEventRepeatCount >= 3) base += 15;
            if (p.sameEventRepeatCount >= 8) base += 30;
            return base;
        }
        case 7008: {
            // ── 线程创建评分 ──
            p.threadCreateCount++;
            int base = 5;

            // P0: 检测远程线程注入 (驱动上报格式: "PID,TID,R")
            if (path.find(L",R") != std::wstring::npos) {
                p.remoteThreadCount++;
                base += 15;  // 跨进程创建线程 → 高风险
                // 多处远程线程注入 → 更可疑
                if (p.remoteThreadCount >= 3) base += 15;
                if (p.remoteThreadCount >= 10) base += 20;
            }

            // 同一进程大量线程创建
            if (p.threadCreateCount >= 5) base += 8;
            if (p.threadCreateCount >= 10) base += 12;
            if (p.threadCreateCount >= 20) base += 15;
            // 低信任进程大量创建线程 → 更可疑
            if (p.trustLevel <= 1 && p.threadCreateCount >= 3) base += 10;

            // [SECURITY FIX] 信任判断基于"注入者"签名，而非受害者(evt.pid/trustLevel)
            // 7008 上报 evt.pid=目标(受害者)，trustLevel 亦是受害者语义，故用 path 解析 creatorPid
            // [P0-误判修复] 注入者进程已退出(查不到路径)时, 不可据此判"无签名注入者"重罚:
            //   远程线程注入后注入者立即退出是常见现象, 此时无法验证签名。
            //   正确降级: 无法验证 → 回到基础分(低危), 不加注入加分, 避免误伤受害者。
            unsigned long inj = getInjectorPid(7008, path);
            bool injectorVerified = false;
            bool injectorTrusted = false;
            if (inj != 0) {
                std::wstring injPath = getProcessPathByPid(inj);
                if (!injPath.empty()) {
                    injectorVerified = true;
                    injectorTrusted = isSignedProcess(injPath);
                }
            }
            if (injectorVerified) {
                if (injectorTrusted) {
                    if (path.find(L",R") != std::wstring::npos) return 5;  // 远程线程注入(签名进程): 仅留最小痕迹分
                    return 0;  // 普通线程创建(签名进程): 不加分
                }
                return base;  // 明确无签名注入者 → 按远程线程注入加分
            }
            // 注入者无法验证(已退出/查不到): 不加注入加分, 仅留基础分
            return 5;
        }
        case 5002:
            return 70;
        case 6001:
            p.suspiciousDllLoads++;
            if (p.suspiciousDllLoads <= 1) return 5;
            if (p.suspiciousDllLoads == 2) return 10;
            return 15;
        case 6010: {
            // APC 注入: 高风险，但仅对不可信/无签名进程大幅加分
            // [SECURITY FIX] 基于"注入者"签名判断，而非受害者 trustLevel
            // [P0-误判修复] 注入者已退出(查不到路径)时无法验证签名, 不可判 40 分高危:
            // 降级为基础分, 避免误伤 (APC 注入者常为一次性短命进程)。
            unsigned long inj = getInjectorPid(6010, path);
            bool injectorVerified = false;
            bool injectorTrusted = false;
            if (inj != 0) {
                std::wstring injPath = getProcessPathByPid(inj);
                if (!injPath.empty()) {
                    injectorVerified = true;
                    injectorTrusted = isSignedProcess(injPath);
                }
            }
            if (injectorVerified) {
                if (injectorTrusted) return 0;  // 签名进程合法 APC 注入 (如 360 自我保护)
                return 40;  // 明确无签名进程 APC 注入 → 高危
            }
            return 10;  // 注入者无法验证(已退出): 降级为低危基础分, 不误伤
        }
        case 6002:
            if (!evt.detail.empty()) return 60;
            return 0;
        case 7001: {
            p.hasScriptAncestor = true;
            std::wstring lower = path;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
            size_t dot = path.find_last_of(L'.');
            bool isPE = (dot != std::wstring::npos) && (
                path.compare(dot, 4, L".exe") == 0 ||
                path.compare(dot, 4, L".dll") == 0 ||
                path.compare(dot, 4, L".sys") == 0);
            if (!isPE) return 5;
            if (lower.find(L"\\users\\public\\") != std::wstring::npos) return 25;
            if (lower.find(L"\\appdata\\roaming\\") != std::wstring::npos) return 20;
            if (lower.find(L"\\program files") != std::wstring::npos ||
                lower.find(L"\\windows\\system32") != std::wstring::npos ||
                lower.find(L"\\windows\\syswow64") != std::wstring::npos) return 5;
            return 15;
        }
        case 7003:
            p.fileWriteBursts++;
            if (p.fileWriteBursts <= 1) return 10;
            if (p.fileWriteBursts == 2) return 15;
            return 20;
        case 7010:
            // 驱动加载: 不直接加分 (加载驱动本身合法),
            // 仅记录状态供状态机规则 (BYOVD: 无签名进程拉起驱动) 关联判定
            p.driverLoadCount++;
            return 0;
        case 8001: return 65;
        case 8002: return 55;
    }
    return 0;
}

// ============================================================
// detectBehaviorSequence — 行为序列模式匹配
//
// 检测已知攻击链模式，返回额外加分。
// 基于 ProcessProfile 中的环形缓冲区 recentSequence[]。
// ============================================================
int ProcessBehaviorEngine::detectBehaviorSequence(ProcessProfile& p) {
    if (p.seqCount < 3) return 0;  // 需要至少 3 个事件

    int bonus = 0;

    // ── 模式1: 脚本→持久化→释放PE (银狐部署链) ──
    // 寻找: 7001(脚本释放) + 3001(Run键) + 2001(PE释放) 的组合
    bool hasScript = false, hasRunKey = false, hasPeRelease = false;
    for (int i = 0; i < p.seqCount && i < ProcessProfile::SEQ_WINDOW; i++) {
        auto& e = p.recentSequence[i];
        if (e.code == 7001) hasScript = true;
        if (e.code == 3001 && (e.regFlags & 0x0001)) hasRunKey = true;
        if (e.code == 2001 && (e.fileFlags & 0x0001)) hasPeRelease = true;
    }
    if (hasScript && hasRunKey && hasPeRelease) {
        bonus += 25;
    }

    // ── 模式2: 多级脚本调用 (scriptDepth >= 3) ──
    if (p.scriptChainDepth >= 3) {
        bonus += 15;
    }

    // ── 模式3: 无签名进程 + 多个敏感操作 ──
    if (p.trustLevel <= 1 && p.sensitiveRegWriteCount >= 2) {
        bonus += 20;
    }

    // ── 模式4: 高频 PE 释放 (短时间内释放多个 PE) ──
    if (p.peReleases >= 3 && p.firstEventMs > 0) {
        long long elapsed = GetTickCount64() - p.firstEventMs;
        if (elapsed > 0 && elapsed < 10000) {  // 10秒内
            double rate = (double)p.peReleases / (elapsed / 1000.0);
            if (rate > 2.0) {  // 每秒超过 2 个 PE
                bonus += 20;
            }
        }
    }

    // ── 模式5: 脚本释放PE + 线程创建 (完整攻击链) ──
    // 查找: 7001(脚本) + 2001(PE) + 7008(线程) 的组合
    {
        bool hasScript = false, hasPe = false, hasThread = false;
        for (int i = 0; i < p.seqCount && i < ProcessProfile::SEQ_WINDOW; i++) {
            if (p.recentSequence[i].code == 7001) hasScript = true;
            if (p.recentSequence[i].code == 2001 && (p.recentSequence[i].fileFlags & 0x0001)) hasPe = true;
            if (p.recentSequence[i].code == 7008) hasThread = true;
        }
        if (hasScript && hasPe && hasThread) {
            bonus += 30;  // 脚本→释放→执行 攻击链
        } else if (hasPe && hasThread && p.threadCreateCount >= 3) {
            bonus += 20;  // PE释放+线程创建 (无脚本感染)
        }
    }

    // ── 模式6: 勒索加速模式 ──
    // 同时满足: offset=0写入 + 大量文件操作 + 文件重命名
    {
        bool hasOffsetZero = false, hasRename = false;
        int fileWriteCount = 0;
        for (int i = 0; i < p.seqCount && i < ProcessProfile::SEQ_WINDOW; i++) {
            auto& e = p.recentSequence[i];
            if (e.code == 2001 && (e.fileFlags & 0x0008)) hasOffsetZero = true;
            if (e.code == 2001 && (e.fileFlags & 0x0020)) hasRename = true;
            if (e.code == 2001 || e.code == 7003) fileWriteCount++;
        }
        if (hasOffsetZero && fileWriteCount >= 3) {
            bonus += 25;  // offset=0写入 + 频繁文件操作 → 勒索
        }
        if (p.offsetZeroWriteCount >= 3) {
            bonus += 20;  // 大量 offset=0 写入
        }
    }

    // ── 模式7: 注册表持久化 + PE释放 (木马标准行为) ──
    {
        bool hasRunKey = false, hasPeRelease = false;
        for (int i = 0; i < p.seqCount && i < ProcessProfile::SEQ_WINDOW; i++) {
            auto& e = p.recentSequence[i];
            if (e.code == 3001 && (e.regFlags & 0x0001)) hasRunKey = true;
            if (e.code == 2001 && (e.fileFlags & 0x0001)) hasPeRelease = true;
        }
        if (hasRunKey && hasPeRelease && p.peReleases >= 2) {
            bonus += 25;  // 写Run键 + 多次PE释放 → 典型木马
        }
    }

    // ── 模式8: 蜜罐触碰 → 立即高分 (不管其他条件) ──
    if (p.honeyFileTouchCount > 0) {
        bonus += 60;  // 蜜罐文件触碰 → 高度确定恶意
    }

    // ── 模式9: 全面攻击链 (4+ 种不同高危操作) ──
    {
        int uniqueHighRisk = 0;
        bool seenCodes[16] = {false};
        for (int i = 0; i < p.seqCount && i < ProcessProfile::SEQ_WINDOW; i++) {
            unsigned long c = p.recentSequence[i].code;
            if (c == 2001 || c == 3001 || c == 4001 || c == 5001 ||
                c == 6001 || c == 6010 || c == 7001 || c == 7008 || c == 8001) {
                int idx = 0;
                if (c == 2001) idx = 0; else if (c == 3001) idx = 1;
                else if (c == 4001) idx = 2; else if (c == 5001) idx = 3;
                else if (c == 6001) idx = 4; else if (c == 7001) idx = 5;
                else if (c == 7008) idx = 6; else if (c == 8001) idx = 7;
                else if (c == 6010) idx = 8;
                if (!seenCodes[idx]) { seenCodes[idx] = true; uniqueHighRisk++; }
            }
        }
        if (uniqueHighRisk >= 4) bonus += 35;   // 4种高危操作 → 高度恶意
        else if (uniqueHighRisk >= 3) bonus += 15; // 3种 → 可疑
    }

    // ── 模式10: 跨进程"落盘执行链" (P2-7) ──
    // 父进程是脚本宿主 (hasScriptAncestor / scriptChainDepth>0)，且当前进程
    // 释放了可执行 PE (2001+PE标志) → 脚本→释放exe→执行 的完整攻击链。
    // 这是跨进程关联：需要查询父进程 profile 的脚本属性。
    {
        bool childHasPeRelease = false;
        for (int i = 0; i < p.seqCount && i < ProcessProfile::SEQ_WINDOW; i++) {
            if (p.recentSequence[i].code == 2001 &&
                (p.recentSequence[i].fileFlags & 0x0001)) {
                childHasPeRelease = true;
                break;
            }
        }
        if (childHasPeRelease && p.parentPid != 0) {
            auto pit = m_profiles.find(p.parentPid);
            if (pit != m_profiles.end()) {
                bool parentIsScriptHost = pit->second.hasScriptAncestor ||
                                          pit->second.scriptChainDepth > 0;
                if (parentIsScriptHost) {
                    bonus += 40;  // 脚本宿主子进程释放PE → 高置信落盘执行链
                }
            }
        }
    }

    return bonus;
}

// ============================================================
// isScriptChain — 检查是否为脚本链调用
// ============================================================
bool ProcessBehaviorEngine::isScriptChain(ProcessProfile& p) {
    return p.scriptChainDepth >= 2 || p.hasScriptAncestor;
}

// ============================================================
// getDefaultReason — 生成默认评分原因文本
// ============================================================
static std::wstring getDefaultReason(unsigned long code, const std::wstring& path,
    const ProcessProfile& p) {
    switch (code) {
        case 2001: {
            size_t dot = path.find_last_of(L'.');
            bool isExec = (dot != std::wstring::npos) && (
                path.compare(dot, 4, L".exe") == 0 ||
                path.compare(dot, 4, L".dll") == 0 ||
                path.compare(dot, 4, L".sys") == 0 ||
                path.compare(dot, 4, L".scr") == 0);
            if (isExec) return L"拦截释放可执行文件 [20分]";
            return L"文件防护拦截 [10分]";
        }
        case 3001: {
            if (path.find(L"\\Services\\") != std::wstring::npos) return L"拦截服务注册 [30分]";
            if (path.find(L"\\Run") != std::wstring::npos) return L"拦截自启项注册 [25分]";
            return L"注册表防护拦截 [10分]";
        }
        case 4001: return L"磁盘擦写操作 [30分]";
        case 5001: return L"可疑勒索行为模式";
        case 5002: return L"文件头完整性检测告警(疑似勒索加密)";
        case 6001: return L"从临时目录加载DLL [第" + std::to_wstring(p.suspiciousDllLoads) + L"次]";
        case 6002: return L"签名不一致检测(银狐)";
        case 6010: return L"APC注入(跨线程异步过程调用)";
        case 7001: return L"脚本释放文件";
        case 7003: return L"高频文件写入模式 [第" + std::to_wstring(p.fileWriteBursts) + L"轮]";
        case 7006: return L"进程创建/派生";
        case 7008: return L"线程创建(含远程线程注入)";
        case 7010: return L"加载驱动(.sys)";
        case 8001: return L"挖矿行为检测(流量异常)";
        case 8002: return L"数据外泄检测(流量异常)";
    }
    // [FIX] 未知 code 也带出原始数字，避免日志中出现无意义的"未知事件"
    return L"未知事件(code=" + std::to_wstring(code) + L")";
}

// ============================================================
// 状态机 HIPS 规则引擎 (P1-状态机)
// 两层 JSON: Rules_Conditions.json(条件库) + Rules_Compose.json(组装规则)
// 事件驱动: processEvent → evaluateStateMachine → 命中按 action 处置
// ============================================================

// 从 JSON 对象里按键名提取字符串值 (与 HipsEngine 同风格, 不引入第三方库)
std::wstring ProcessBehaviorEngine::extractJsonKey(const std::wstring& obj, const std::wstring& key) {
    size_t kp = obj.find(L"\"" + key + L"\"");
    if (kp == std::wstring::npos) return L"";
    size_t colon = obj.find(L':', kp);
    if (colon == std::wstring::npos) return L"";
    size_t c = colon + 1;
    while (c < obj.size() && (obj[c] == L' ' || obj[c] == L'\t' || obj[c] == L'\n' || obj[c] == L'\r')) c++;
    if (c >= obj.size()) return L"";
    if (obj[c] == L'"') {
        c++;
        size_t end = obj.find(L'"', c);
        if (end == std::wstring::npos) return L"";
        return obj.substr(c, end - c);
    }
    // 数字/布尔 (无引号)
    size_t end = c;
    while (end < obj.size() && obj[end] != L',' && obj[end] != L'}') end++;
    return obj.substr(c, end - c);
}

int ProcessBehaviorEngine::extractJsonInt(const std::wstring& obj, const std::wstring& key, int def) {
    std::wstring v = extractJsonKey(obj, key);
    if (v.empty()) return def;
    // 去掉可能的值前后空白
    size_t s = v.find_first_not_of(L" \t\r\n");
    if (s == std::wstring::npos) return def;
    return (int)_wtoi(v.substr(s).c_str());
}

// 解析 Rules_Conditions.json 的条件对象
void ProcessBehaviorEngine::parseConditionsJson(const std::wstring& json) {
    // 定位 "conditions" 对象
    size_t pos = json.find(L"\"conditions\"");
    if (pos == std::wstring::npos) return;
    size_t colon = json.find(L':', pos);
    if (colon == std::wstring::npos) return;
    size_t condStart = json.find(L'{', colon);
    size_t condEnd = json.rfind(L'}');
    if (condStart == std::wstring::npos || condEnd == std::wstring::npos || condEnd <= condStart) return;

    std::wstring conds = json.substr(condStart, condEnd - condStart + 1);
    size_t p = 0;
    while (p < conds.size()) {
        // 找条件 id (引号开头)
        size_t idStart = conds.find(L'"', p);
        if (idStart == std::wstring::npos) break;
        size_t idEnd = conds.find(L'"', idStart + 1);
        if (idEnd == std::wstring::npos) break;
        std::wstring id = conds.substr(idStart + 1, idEnd - idStart - 1);
        if (id == L"version" || id == L"comment") { p = idEnd + 1; continue; }

        // 找该条件的对象 {...}
        size_t ob = conds.find(L'{', idEnd);
        if (ob == std::wstring::npos) break;
        size_t cb = conds.find(L'}', ob);
        if (cb == std::wstring::npos) break;
        std::wstring obj = conds.substr(ob, cb - ob + 1);

        StateMachineCondition c;
        c.id = id;
        c.type = extractJsonKey(obj, L"type");
        c.field = extractJsonKey(obj, L"field");
        c.op = extractJsonKey(obj, L"op");
        if (c.op.empty()) c.op = L"eq";
        c.value = extractJsonKey(obj, L"value");
        std::wstring expectStr = extractJsonKey(obj, L"expect");
        c.expect = (expectStr == L"true" || expectStr == L"1") ? true : false;
        m_smConditions[id] = c;
        p = cb + 1;
    }
}

// 解析 Rules_Compose.json 的规则数组
void ProcessBehaviorEngine::parseRulesJson(const std::wstring& json) {
    size_t pos = json.find(L"\"rules\"");
    if (pos == std::wstring::npos) return;
    size_t colon = json.find(L':', pos);
    if (colon == std::wstring::npos) return;
    size_t arrStart = json.find(L'[', colon);
    size_t arrEnd = json.rfind(L']');
    if (arrStart == std::wstring::npos || arrEnd == std::wstring::npos || arrEnd <= arrStart) return;

    std::wstring rules = json.substr(arrStart, arrEnd - arrStart + 1);
    size_t p = 0;
    while (p < rules.size()) {
        size_t ob = rules.find(L'{', p);
        if (ob == std::wstring::npos) break;
        size_t cb = rules.find(L'}', ob);
        if (cb == std::wstring::npos) break;
        std::wstring obj = rules.substr(ob, cb - ob + 1);
        p = cb + 1;

        StateMachineRule r;
        r.id = extractJsonKey(obj, L"id");
        if (r.id.empty()) continue;
        r.name = extractJsonKey(obj, L"name");
        r.action = extractJsonInt(obj, L"action", 0);
        r.score = extractJsonInt(obj, L"score", 0);
        r.priority = extractJsonInt(obj, L"priority", 10);
        r.block_at = extractJsonKey(obj, L"block_at");
        r.reversibility = extractJsonKey(obj, L"reversibility");
        r.redirect_to = extractJsonKey(obj, L"redirect_to");
        r.window_ms = extractJsonInt(obj, L"window_ms", 0);

        // 解析 when.all 和 when.any
        size_t whenPos = obj.find(L"\"when\"");
        if (whenPos != std::wstring::npos) {
            // 找到 when 的值对象
            size_t whenOb = obj.find(L'{', whenPos);
            if (whenOb != std::wstring::npos) {
                // all
                size_t allPos = obj.find(L"\"all\"", whenOb);
                if (allPos != std::wstring::npos && allPos < whenOb + 500) {
                    size_t alStart = obj.find(L'[', allPos);
                    if (alStart != std::wstring::npos) {
                        size_t alEnd = obj.find(L']', alStart);
                        if (alEnd != std::wstring::npos) {
                            std::wstring al = obj.substr(alStart + 1, alEnd - alStart - 1);
                            size_t q = 0;
                            while ((q = al.find(L'"', q)) != std::wstring::npos) {
                                size_t qe = al.find(L'"', q + 1);
                                if (qe == std::wstring::npos) break;
                                r.all_conds.push_back(al.substr(q + 1, qe - q - 1));
                                q = qe + 1;
                            }
                        }
                    }
                }
                // any
                size_t anyPos = obj.find(L"\"any\"", whenOb);
                if (anyPos != std::wstring::npos && anyPos < whenOb + 500) {
                    size_t anStart = obj.find(L'[', anyPos);
                    if (anStart != std::wstring::npos) {
                        size_t anEnd = obj.find(L']', anStart);
                        if (anEnd != std::wstring::npos) {
                            std::wstring an = obj.substr(anStart + 1, anEnd - anStart - 1);
                            size_t q = 0;
                            while ((q = an.find(L'"', q)) != std::wstring::npos) {
                                size_t qe = an.find(L'"', q + 1);
                                if (qe == std::wstring::npos) break;
                                r.any_conds.push_back(an.substr(q + 1, qe - q - 1));
                                q = qe + 1;
                            }
                        }
                    }
                }
            }
        }
        m_smRules.push_back(r);
    }
}

// 加载状态机规则 (条件库 + 组装规则)
void ProcessBehaviorEngine::loadStateMachineRules(const std::wstring& conditionsPath,
                                                  const std::wstring& composePath) {
    std::lock_guard<std::mutex> lock(m_smMutex);
    m_smConditions.clear();
    m_smRules.clear();

    auto readFile = [](const std::wstring& path, std::wstring& out) -> bool {
        FILE* f = nullptr;
        if (_wfopen_s(&f, path.c_str(), L"rb") != 0 || !f) return false;
        fseek(f, 0, SEEK_END);
        long len = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (len <= 0) { fclose(f); return false; }
        std::string utf8(len, '\0');
        fread(&utf8[0], 1, len, f);
        fclose(f);
        int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), nullptr, 0);
        if (wlen <= 0) return false;
        out.resize(wlen);
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), &out[0], wlen);
        return true;
    };

    std::wstring cj, rj;
    if (readFile(conditionsPath, cj)) parseConditionsJson(cj);
    if (readFile(composePath, rj)) parseRulesJson(rj);

    // 按优先级排序 (小优先), 豁免规则(priority=1)排最前
    std::sort(m_smRules.begin(), m_smRules.end(),
        [](const StateMachineRule& a, const StateMachineRule& b) { return a.priority < b.priority; });
}

// 信任链判定: 自身签名 或 父进程签名 或 血缘链签名 (递归, 深度≤4)
bool ProcessBehaviorEngine::evalRelationTrustedChain(ProcessProfile& p, int depth) {
    if (depth > 4) return false;
    if (p.trustLevel >= 3) return true;  // 自身签名
    if (p.parentPid == 0) return false;
    // 注意: 由 processEvent 调用时 m_mutex 已持有, 不重复加锁 (避免死锁)
    // worker 线程是唯一消费者, m_profiles 由它修改, 此处访问安全
    auto it = m_profiles.find(p.parentPid);
    if (it == m_profiles.end()) return false;
    return evalRelationTrustedChain(it->second, depth + 1);
}

// 求值单个条件
bool ProcessBehaviorEngine::evalCondition(const StateMachineCondition& c,
                                          const BehaviorEvent& evt, ProcessProfile& p) {
    bool result = false;

    if (c.type == L"process_state") {
        // 进程状态字段 (映射 ProcessProfile)
        auto getField = [&](const std::wstring& f) -> std::wstring {
            if (f == L"trust_level") return std::to_wstring(p.trustLevel);
            if (f == L"script_chain_depth") return std::to_wstring(p.scriptChainDepth);
            if (f == L"has_script_ancestor") return p.hasScriptAncestor ? L"true" : L"false";
            if (f == L"wrote_runkey") return p.wroteToRunKey ? L"true" : L"false";
            if (f == L"pe_releases") return std::to_wstring(p.peReleases);
            if (f == L"remote_thread_count") return std::to_wstring(p.remoteThreadCount);
            if (f == L"driver_load_count") return std::to_wstring(p.driverLoadCount);
            if (f == L"honey_file_touch_count") return std::to_wstring(p.honeyFileTouchCount);
            if (f == L"process_path") return p.processPath;
            return L"";
        };
        std::wstring val = getField(c.field);
        if (c.op == L"contains") {
            std::wstring v = val; std::transform(v.begin(), v.end(), v.begin(), ::towlower);
            std::wstring sub = c.value; std::transform(sub.begin(), sub.end(), sub.begin(), ::towlower);
            result = (v.find(sub) != std::wstring::npos);
        } else if (c.op == L"startswith") {
            result = (val.rfind(c.value, 0) == 0);
        } else if (c.op == L"endswith") {
            std::wstring v = val; std::transform(v.begin(), v.end(), v.begin(), ::towlower);
            std::wstring sub = c.value; std::transform(sub.begin(), sub.end(), sub.begin(), ::towlower);
            result = (v.size() >= sub.size() && v.compare(v.size() - sub.size(), sub.size(), sub) == 0);
        } else if (c.op == L"eq") {
            std::wstring v = val; std::transform(v.begin(), v.end(), v.begin(), ::towlower);
            std::wstring sub = c.value; std::transform(sub.begin(), sub.end(), sub.begin(), ::towlower);
            result = (v == sub);
        } else if (c.op == L"gt") {
            result = (_wtoi(val.c_str()) > _wtoi(c.value.c_str()));
        } else if (c.op == L"ge") {
            result = (_wtoi(val.c_str()) >= _wtoi(c.value.c_str()));
        } else if (c.op == L"lt") {
            result = (_wtoi(val.c_str()) < _wtoi(c.value.c_str()));
        } else if (c.op == L"le") {
            result = (_wtoi(val.c_str()) <= _wtoi(c.value.c_str()));
        }
    } else if (c.type == L"event") {
        // 事件属性
        if (c.field == L"code") {
            result = (_wtoi(c.value.c_str()) == (int)evt.code);
        } else if (c.field == L"path") {
            std::wstring path = evt.path;
            std::transform(path.begin(), path.end(), path.begin(), ::towlower);
            std::wstring sub = c.value; std::transform(sub.begin(), sub.end(), sub.begin(), ::towlower);
            if (c.op == L"endswith") {
                result = (path.size() >= sub.size() && path.compare(path.size() - sub.size(), sub.size(), sub) == 0);
            } else if (c.op == L"contains") {
                result = (path.find(sub) != std::wstring::npos);
            } else if (c.op == L"eq") {
                result = (path == sub);
            }
        } else if (c.field == L"reg_flag") {
            // 注册表语义标签
            if (c.value == L"is_runkey") result = evt.ctx.isRunKey();
            else if (c.value == L"is_service") result = evt.ctx.isService();
            else result = false;
        }
    } else if (c.type == L"relation") {
        if (c.field == L"trusted_chain") {
            result = evalRelationTrustedChain(p, 0);
        } else if (c.field == L"parent_trust_level") {
            // 由 processEvent 调用时 m_mutex 已持有, 不重复加锁
            auto it = m_profiles.find(p.parentPid);
            if (it != m_profiles.end()) {
                result = (it->second.trustLevel <= _wtoi(c.value.c_str()));
            } else {
                result = (0 <= _wtoi(c.value.c_str()));  // 父未知 → 视为无签名
            }
        }
    }

    // expect 取反
    return c.expect ? result : !result;
}

// 事件驱动求值状态机
void ProcessBehaviorEngine::evaluateStateMachine(const BehaviorEvent& evt, ProcessProfile& p) {
    if (m_smRules.empty()) return;

    std::lock_guard<std::mutex> lock(m_smMutex);
    for (const auto& rule : m_smRules) {
        // 跳过豁免规则在求值处处理: 豁免(action=0) 命中即放行, 不再触发处置
        bool allOk = true;
        if (!rule.all_conds.empty()) {
            for (const auto& cid : rule.all_conds) {
                auto it = m_smConditions.find(cid);
                if (it == m_smConditions.end()) { allOk = false; break; }
                if (!evalCondition(it->second, evt, p)) { allOk = false; break; }
            }
        }
        bool anyOk = rule.any_conds.empty();
        if (!anyOk) {
            for (const auto& cid : rule.any_conds) {
                auto it = m_smConditions.find(cid);
                if (it != m_smConditions.end() && evalCondition(it->second, evt, p)) { anyOk = true; break; }
            }
        }

        if (allOk && anyOk) {
            // 命中
            if (rule.action == 0) {
                // 豁免: 放行, 不触发处置
                if (m_smCallback) m_smCallback(evt.pid, rule.id.c_str(), rule.name.c_str(), 0, 0);
                return;  // 豁免规则优先, 命中即停止后续
            }
            // 拦截/询问/重定向: 触发处置回调
            if (m_smCallback) {
                m_smCallback(evt.pid, rule.id.c_str(), rule.name.c_str(), rule.action, rule.score);
            }
            // 命中后当前事件处置, 不继续 (防止多条规则重复处置)
            return;
        }
    }
}
