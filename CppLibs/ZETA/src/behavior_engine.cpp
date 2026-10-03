#include "behavior_engine.h"
#include "trust.h"
// P2-4c: 事件码统一契约 (唯一定义源)
#include "../../../Plugins/Filter/events.h"
#include <algorithm>
#include <TlHelp32.h>

// Forward declarations
static std::wstring getDefaultReason(unsigned long code, const std::wstring& path,
    const ProcessProfile& p);

// ── 有效数字签名校验 ──
// 收敛重构: 统一走 TrustDecider (签名验证 + 系统目录精确前缀兜底)。
// 不再各自维护 WinVerifyTrust。
static bool isSignedProcess(const std::wstring& path) {
    return TrustDecider::instance().isFileTrusted(path);
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
        // P0 事件码规范化: 5003=勒索高熵写(原错报7003), 5004=蜜罐触碰(原混用7000)
        // P2-4b: 移除 7003(已废弃, 无产生源) / 8001 8002(网络评分死代码 — NetFilter 走独立管道从不 ingest)
        // P2-4a: 4002(卷卸载)/4003(磁盘擦写告警) 由 4001 拆分, 一并进入评分
        case ZETA_MSG_FILE_PROTECT: case ZETA_MSG_REG_PROTECT: case ZETA_MSG_DISK_WRITE: case ZETA_MSG_VOLUME_DISMOUNT: case ZETA_MSG_DISK_WRITE_ALERT: case ZETA_MSG_RANSOM_FIRST_WRITE: case ZETA_MSG_RANSOM_ENTROPY_WRITE: case ZETA_MSG_RANSOM_HONEY_TOUCH:
        case ZETA_MSG_CODE_INJECT: case ZETA_MSG_SILVERFOX_SIGNATURE: case ZETA_MSG_SILVERFOX_RELEASES: case ZETA_MSG_APC_INJECT: case ZETA_MSG_LINEAGE_ALERT: case ZETA_MSG_PROCESS_CREATE:
        case ZETA_MSG_THREAD_CREATE: case ZETA_MSG_IMAGE_LOAD:
        // P2-优先级2: 注入链完整事件流入引擎 (6015 远程线程/6016 写内存/6017 解映射)
        // 用于"进程镂空"链识别: 解映射+写入+恢复线程 组合 → 确定恶意
        // P2-优先级3: 写入内容特征 (6018 MZ/6019 shellcode)
        case ZETA_MSG_THREAD_CREATE_INJECT: case ZETA_MSG_WRITE_MEM_INJECT: case ZETA_MSG_UNMAP_VIEW:
        case ZETA_MSG_WRITE_MEM_PE: case ZETA_MSG_WRITE_MEM_SHELLCODE:
        // P4-优先级4: 间接/内联 syscall 绕过 (6020, 观察)
        case ZETA_MSG_SYSCALL_SPOOF:
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
    if (code ==  ZETA_MSG_APC_INJECT) {
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
    if (code ==  ZETA_MSG_THREAD_CREATE) {
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
// 前向声明: 事件类上限工具 (实现见文件后段 scoreWithContext 之前)。
// processEvent (L212) 在它们之前就调用, 必须先声明。
static int CategoryOfEvent(unsigned long code);
static int ApplyCategoryCap(ProcessProfile& p, int cat, int add);

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
        if (code ==  ZETA_MSG_PROCESS_CREATE && !evt.path.empty()) {
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
        // M1-2: 记录时间戳 + 路径尾部快照, 供状态机 window_ms 窗口匹配
        entry.timeMs = nowMs;
        {
            size_t wlen = evt.path.size();
            size_t start = (wlen > (size_t)ProcessProfile::PATH_TAIL_LEN - 1)
                ? (wlen - ((size_t)ProcessProfile::PATH_TAIL_LEN - 1)) : 0;
            size_t copyN = (std::min)(wlen, (size_t)ProcessProfile::PATH_TAIL_LEN - 1);
            size_t out = 0;
            for (size_t i = start; i < wlen && out < (size_t)ProcessProfile::PATH_TAIL_LEN - 1; i++) {
                wchar_t ch = evt.path[i];
                entry.pathTail[out++] = (ch >= L'A' && ch <= L'Z') ? (wchar_t)(ch - L'A' + L'a') : ch;
            }
            entry.pathTail[out] = L'\0';
        }
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
        // P0-6: 驱动侧蜜罐触碰已改用独立事件码 5004 (ZETA_MSG_RANSOM_HONEY_TOUCH),
        // 原走 7000 (纯日志码) 时 behavior_engine 不消费, 蜜罐评分静默丢失。
        if (code ==  ZETA_MSG_RANSOM_HONEY_TOUCH) {
            p.honeyFileTouchCount++;
        } else if (code ==  ZETA_MSG_FILE_PROTECT) {
            // 辅助校验: 2001 事件路径若命中蜜罐名也计入 (双保险)
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
        bool isTrusted = trustedByKernel || trustedByPath;

        // ── P1-4: 硬闸门判定 — 三类行为任何信任等级都不豁免 ──
        // 原实现: 可信进程整体 return → 恶意软件放入可信目录/伪装签名即评分完全隐身。
        // 硬闸门: 即使进程可信也必须评分 (并在下方排除"签名减权"以避免信号被稀释):
        //   1) BYOVD: 落地 .sys 文件 (驱动加载前必须先落盘)
        //   2) MBR/磁盘写 (code 4001)
        //   3) offset-0 覆写文档 (勒索加密特征)
        bool isHardGate = false;
        if (code ==  ZETA_MSG_DISK_WRITE) {
            isHardGate = true;
        }
        if (evt.ctx.offsetZero() && evt.ctx.isDocument()) {
            isHardGate = true;
        }
        if (!isHardGate) {
            std::wstring lowerPath = evt.path;
            std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
            if (lowerPath.size() >= 4 && lowerPath.compare(lowerPath.size() - 4, 4, L".sys") == 0) {
                isHardGate = true;
            }
        }

        if (code !=  ZETA_MSG_IMAGE_LOAD && isTrusted && !isHardGate) {
            // 仅记录到 profile (不加分、不告警)，保持最小可观测性
            p.trustLevel = (std::max)((int)p.trustLevel, trustedByKernel ? (int)evt.ctx.trustLevel : 3);
            return;
        }

        // ── Step 1: 基础评分 (保留 v1 逻辑) ──
        scoreAdd = scoreWithContext(evt, p);
        // 事件类上限 (2026-10-03): 本次事件的基础分按其所属类别截断。
        // 蜜罐后续加成(2001 且 honeyFileTouchCount>0 返回 80)必须走不设限的 CAT_HONEY,
        // 否则会被 CAT_FILE 的上限削弱 —— 它是决定性证据, 要能单独触发告警。
        int evtCat = CategoryOfEvent(code);
        if (code == ZETA_MSG_FILE_PROTECT && p.honeyFileTouchCount > 0) evtCat = CAT_HONEY;
        scoreAdd = ApplyCategoryCap(p, evtCat, scoreAdd);
        reason = evt.detail.empty() ? getDefaultReason(code, evt.path, p) : evt.detail;

        // ── Step 2: 上下文加成 (新增) ──
        int ctxBonus = 0;
        std::wstring ctxReason;
        const auto& cfc = m_cfg.ctxBonus;  // Rules_Context.json 可调

        // 无签名进程释放 PE → 加权
        if (evt.ctx.isPeFile() && evt.ctx.isUntrusted()) {
            p.untrustedPeCount++;
            if (p.untrustedPeCount == 1) {
                ctxBonus += cfc.untrustedPeFirst;
                ctxReason = L"无签名进程释放PE [+" + std::to_wstring(cfc.untrustedPeFirst) + L"]";
            } else if (p.untrustedPeCount >= cfc.untrustedPeManyCount) {
                ctxBonus += cfc.untrustedPeMany;
                ctxReason = L"无签名进程多次释放PE(" + std::to_wstring(p.untrustedPeCount) + L"次) [+" + std::to_wstring(cfc.untrustedPeMany) + L"]";
            }
        }

        // offset=0 写入文档 → 勒索特征
        if (evt.ctx.offsetZero() && evt.ctx.isDocument()) {
            p.offsetZeroWriteCount++;
            ctxBonus += cfc.offsetZeroDoc;
            ctxReason = L"offset=0写入文档文件(疑似加密覆写) [+" + std::to_wstring(cfc.offsetZeroDoc) + L"]";
        }

        // Temp 路径释放 PE → 高风险
        if (evt.ctx.isPeFile() && evt.ctx.isTempPath()) {
            p.tempPathPeCount++;
            if (p.tempPathPeCount >= cfc.tempPeCount) {
                ctxBonus += cfc.tempPe;
                ctxReason = L"多次从Temp路径释放PE [+" + std::to_wstring(cfc.tempPe) + L"]";
            }
        }

        // 脚本宿主释放 PE 文件 → 高风险（无文件攻击的关键指标）
        if (evt.ctx.isScriptHost() && evt.ctx.isPeFile()) {
            ctxBonus += cfc.scriptHostPe;
            ctxReason = L"脚本解释器释放PE文件(疑似无文件攻击载荷) [+" + std::to_wstring(cfc.scriptHostPe) + L"]";
        }

        // 有脚本祖先 + 释放PE → 分层攻击
        if (evt.ctx.hasScriptAncestor() && evt.ctx.isPeFile() && !evt.ctx.isScriptHost()) {
            ctxBonus += cfc.scriptAncestorPe;
            ctxReason = L"脚本衍生进程释放PE(分层攻击) [+" + std::to_wstring(cfc.scriptAncestorPe) + L"]";
        }

        // 脚本链深度 ≥ 3 → 攻击链
        if (p.scriptChainDepth >= 3) {
            ctxBonus += cfc.scriptChainDepth3;
            ctxReason = L"脚本链深度=" + std::to_wstring(p.scriptChainDepth) + L"(疑似多级脚本攻击) [+" + std::to_wstring(cfc.scriptChainDepth3) + L"]";
        }

        // 敏感注册表写入 (IFEO/UAC/Defender) → 加权
        if (evt.ctx.isIfeo() || evt.ctx.isUacBypass() || evt.ctx.isDefender()) {
            p.sensitiveRegWriteCount++;
            ctxBonus += cfc.sensitiveReg;
            ctxReason = L"敏感注册表操作(安全机制绕过) [+" + std::to_wstring(cfc.sensitiveReg) + L"]";
        }

        // 独占写入 PE → 可疑 (正常程序很少独占写 PE)
        if (evt.ctx.exclusive() && evt.ctx.isPeFile()) {
            p.exclusiveWriteCount++;
            ctxBonus += cfc.exclusivePe;
            ctxReason = L"独占写入PE文件 [+" + std::to_wstring(cfc.exclusivePe) + L"]";
        }

        // 签名进程 → 减权 (合法系统操作)
        // P1-4: 硬闸门行为 (.sys 落地/MBR 写/offset-0) 不减权, 避免高危信号被稀释
        if (evt.ctx.trustLevel >= 3 && scoreAdd > 0 && !isHardGate) {
            int reduction = scoreAdd / cfc.trustedReductionDiv;
            scoreAdd -= reduction;
            ctxReason = L"微软签名进程 [-" + std::to_wstring(reduction) + L"]";
        }

        // 上下文加成归入组合证据类 (CAT_MISC), 同样受该类上限约束
        ctxBonus = ApplyCategoryCap(p, CAT_MISC, ctxBonus);
        scoreAdd += ctxBonus;
        if (!ctxReason.empty()) {
            reason += L" | " + ctxReason;
        }

        // ── Step 3: 行为序列检测 (新增) ──
        int seqBonus = detectBehaviorSequence(p);
        seqBonus = ApplyCategoryCap(p, CAT_MISC, seqBonus);   // 归入组合证据类并受上限约束
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
            // 类累计贡献必须与总分【同步衰减】, 否则类上限会变成永久枷锁:
            // 一旦吃满, 即使过了很久同类事件也不再接受加分。
            for (int ci = 0; ci < CAT_COUNT; ci++) {
                if (p.catScore[ci] > 0) p.catScore[ci] = decayScore(p.catScore[ci], elapsed);
            }
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
                // 类累计贡献与总分一起归零: 否则总分为 0 而各类配额仍满,
                // 后续同类事件永远加 0 分, 该进程会被"永久免疫"—— 与归零语义矛盾。
                for (int ci = 0; ci < CAT_COUNT; ci++) it->second.catScore[ci] = 0;
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
            // 类累计贡献同步衰减 (与 processEvent 的 Step4 一致)
            for (int ci = 0; ci < CAT_COUNT; ci++) {
                if (p.catScore[ci] > 0) p.catScore[ci] = decayScore(p.catScore[ci], elapsed);
            }
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
            case ZETA_MSG_FILE_PROTECT: codeDesc = L"文件保护拦截"; break;
            case ZETA_MSG_REG_PROTECT: codeDesc = L"注册表保护拦截"; break;
            case ZETA_MSG_DISK_WRITE: codeDesc = L"磁盘防护拦截"; break;
            case ZETA_MSG_VOLUME_DISMOUNT: codeDesc = L"卷卸载/锁卷拦截"; break;
            case ZETA_MSG_DISK_WRITE_ALERT: codeDesc = L"磁盘擦写监控告警"; break;
            case ZETA_MSG_RANSOM_ENTROPY_WRITE: codeDesc = L"勒索高熵写入"; break;
            case ZETA_MSG_RANSOM_HONEY_TOUCH: codeDesc = L"蜜罐文件触碰"; break;
            case ZETA_MSG_CODE_INJECT: codeDesc = L"注入攻击拦截"; break;
            case ZETA_MSG_SILVERFOX_SIGNATURE: codeDesc = L"银狐行为拦截"; break;
            case ZETA_MSG_SILVERFOX_RELEASES: codeDesc = L"银狐PE释放超量"; break;
            case ZETA_MSG_APC_INJECT: codeDesc = L"APC注入拦截"; break;
            case ZETA_MSG_IMAGE_LOAD: codeDesc = L"驱动加载"; break;
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

// P1-6: clearScore 已删除 — HIPS_ALLOW 规则命中不再清空进程历史评分。
// (原实现会把已累计的高危行为证据洗白, 攻击者可穿插一个 ALLOW 行为绕过。)

// ============================================================
// reportScanScore — Scan→EDR 联动上报
//
// 语义(2026-10-04 收紧): 调用方【明确给定分值】, 本函数照数累加, 不再做任何放大。
//
// 旧实现把扫描器返回的 0/1/3 映射为 50/100 分:
//     if (score >= 3) score = 100; else if (score == 1) score = 50;
// 那条"P0-4 修复"的动机是对的(在它之前命中只加 1~3 分, 真检测永不告警), 但做法
// 把标量 3 当成了严重度 —— 而 3 的真实含义只是"有规则命中"。后果是任何一条
// 能力型规则(IsPE64/with_urls/Chacha_256_constant/QtFrameWork...)都直接把进程
// 推过 ALERT_THRESHOLD(85)。实测: git.exe 命中 with_urls → +100 → 立即告警;
// 10 分钟内 git/bun/node/HYP(原神启动器)/ZETA.exe 自身 全部告警。
// 同一映射还把 AMSI 的 60 分放大成 100 —— 一并修掉。
//
// 现在: YARA 走 reportScanEvidence(按证据强度加权); 本入口只服务
// "畸形路径(10)/扫描失败(5)/AMSI 命中(100)"这类本来就带明确分值的场景。
// ============================================================
void ProcessBehaviorEngine::reportScanScore(unsigned long pid, int score, 
    const std::wstring& name, const std::wstring& path) {
    if (!m_enabled || score <= 0) return;

    // P0-自杀修复: ZETA.exe 自身进程绝对豁免 — 自动扫描评分
    if (isSelf(pid)) return;

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
// reportScanEvidence — Scan→EDR 联动上报 (按证据强度计分, 2026-10-04 新增)
//
// 这是 YARA 命中的【推荐上报路径】。与 reportScanScore 的区别:
//   后者收一个"已经算好的分值", 前者收【证据】(命中几条第几档), 由本函数施加权重。
// 证据串由 zeta_engine 的 scanFile/scanProcess 生成:
//     "Hits=N Weak=w Normal=n Strong=s | rule1;rule2;..."
// 计分(权重与不变式见 behavior_engine.h 的 YaraScoreConfig):
//     弱档  : min(WEAK_CAP,   w*WEAK_PER_HIT)     = min(30, w*10)
//     普通档: min(NORMAL_CAP, n*NORMAL_PER_HIT)   = min(90, n*45)
//     强档  : s*STRONG_PER_HIT                    = s*100
// 效果:
//     1 条弱命中          → 10  分  (无提醒: <40)
//     3 条弱命中          → 30  分  (无提醒)
//     1 条普通命中        → 45  分  (提醒, 但 <85 不告警) ← 单条规则不再能弹框
//     2 条普通命中        → 90  分  (告警)
//     1 条强命中          → 100 分  (告警: 保留单发决定性签名)
//     1 普通 + 1 弱       → 55  分  (提醒)
// ============================================================
static void ParseYaraEvidence_(const std::wstring& detail, int& nWeak, int& nNormal, int& nStrong) {
    nWeak = nNormal = nStrong = 0;
    auto grabValue = [&detail](const wchar_t* key) -> long {
        size_t p = detail.find(key);
        if (p == std::wstring::npos) return -1;
        p += wcslen(key);
        long v = 0;
        bool any = false;
        while (p < detail.size() && detail[p] >= L'0' && detail[p] <= L'9') {
            v = v * 10 + (long)(detail[p] - L'0');
            ++p;
            any = true;
            if (v > 100000) break;   // 防御: 不合理的超大计数
        }
        return any ? v : -1;
    };

    const long w = grabValue(L"Weak=");
    const long n = grabValue(L"Normal=");
    const long s = grabValue(L"Strong=");

    if (w < 0 && n < 0 && s < 0) {
        // 旧格式(只有一条规则名)或其它扫描类型: 按"1 条普通命中"处理 ——
        // 即最多提醒一次, 绝不单独告警。保守但不会静默丢弃。
        nNormal = 1;
        return;
    }

    if (w > 0) nWeak   = (int)w;
    if (n > 0) nNormal = (int)n;
    if (s > 0) nStrong = (int)s;
    if (nWeak + nNormal + nStrong == 0) nNormal = 1;
}

void ProcessBehaviorEngine::reportScanEvidence(unsigned long pid, int scanCode,
    const std::wstring& detail, const std::wstring& name, const std::wstring& path) {
    if (!m_enabled) return;
    if (isSelf(pid)) return;

    // 分派: 只有 YARA 类结果才走"弱/普通/强"证据表; 其余类型是结构证据。
    // 不区分会出问题 —— 实测 signature:Suspicious:Unsigned 落到 YARA 回退分支后,
    // 每个未签名的正常程序(TextInputHost/esbuild/idalib-mcp...)都白拿 45 分并提醒。
    const bool bYaraEvidence = (detail.find(L"Weak=") != std::wstring::npos ||
                                detail.find(L"Normal=") != std::wstring::npos ||
                                detail.find(L"Strong=") != std::wstring::npos);

    int score = 0;
    std::wstring reason;
    if (bYaraEvidence) {
        int nWeak = 0, nNormal = 0, nStrong = 0;
        ParseYaraEvidence_(detail, nWeak, nNormal, nStrong);
        // 兼容: 证据串缺失计数(旧版 DLL 只给一条规则名)时, 用引擎返回码兜底 ——
        // scanCode>=3 表示引擎自己判为高危, 按 1 条强档处理, 不因降级而漏报。
        if (nWeak == 0 && nNormal == 1 && nStrong == 0 && scanCode >= 3) {
            nNormal = 0;
            nStrong = 1;
        }
        const int nWeakPart   = (nWeak * YaraScoreConfig::WEAK_PER_HIT > YaraScoreConfig::WEAK_CAP)
                              ? YaraScoreConfig::WEAK_CAP : nWeak * YaraScoreConfig::WEAK_PER_HIT;
        const int nNormalPart = (nNormal * YaraScoreConfig::NORMAL_PER_HIT > YaraScoreConfig::NORMAL_CAP)
                              ? YaraScoreConfig::NORMAL_CAP : nNormal * YaraScoreConfig::NORMAL_PER_HIT;
        score = nWeakPart + nNormalPart + nStrong * YaraScoreConfig::STRONG_PER_HIT;
        reason = L"YARA 证据 [" + name + L"] 弱" + std::to_wstring(nWeak) +
                 L"/普通" + std::to_wstring(nNormal) +
                 L"/强" + std::to_wstring(nStrong) +
                 L" [+" + std::to_wstring(score) + L"分]";
    } else {
        // 结构证据: PE 高危(引擎已按多信号累积算过)保留告警能力;
        // 其余(未签名/扩展名/路径编码异常)只记 20 分, 不提醒、不告警。
        score = (scanCode >= 3) ? YaraScoreConfig::STRONG_PER_HIT
                                : YaraScoreConfig::STRUCTURAL_SUSPICIOUS;
        reason = L"扫描结构证据 [" + name + L"] " +
                 (scanCode >= 3 ? std::wstring(L"高危") : std::wstring(L"可疑")) +
                 L" [" + detail + L"] [+" + std::to_wstring(score) + L"分]";
    }
    if (score <= 0) return;

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
        // 理由串必须能看出"证据构成", 否则事后无法解释这次加分为何是该分值。
        p.reasons.push_back(reason);
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
// ============================================================
// CategoryOfEvent / ApplyCategoryCap —— 事件类分数上限 (2026-10-03 新增)
//
// 为什么需要: 见 behavior_engine.h 里 ScoreCategory 的说明。简述 ——
// 评分器是"衰减累加器", 稳态 S_eq = s/(1-2^(-T/H))。以驱动限速 T=1s、
// 半衰期 H=120s 计, 系数 173.6 ⇒ 单事件分值 ≥0.5 且持续 2 分钟就必然越阈。
// 类上限把"次数"从判据里拿掉: 任一类吃满后同类事件不再加分,
// 判据退化为"该类行为是否发生过"。所有设限类别的上限都 < ALERT_THRESHOLD
// (头文件 static_assert 锁死), 因此【单类别的重复行为无法独自触发告警】。
// ============================================================

static int CategoryOfEvent(unsigned long code) {
    switch (code) {
    case ZETA_MSG_FILE_PROTECT:
        return CAT_FILE;
    case ZETA_MSG_REG_PROTECT:
        return CAT_REG;
    case ZETA_MSG_RANSOM_FIRST_WRITE:
    case ZETA_MSG_RANSOM_ENTROPY_WRITE:
        return CAT_RANSOM;
    case ZETA_MSG_RANSOM_HONEY_TOUCH:
        return CAT_HONEY;      // 蜜罐: 不设限
    case ZETA_MSG_THREAD_CREATE:
    case ZETA_MSG_CODE_INJECT:
    case ZETA_MSG_APC_INJECT:
    case ZETA_MSG_THREAD_CREATE_INJECT:
    case ZETA_MSG_WRITE_MEM_INJECT:
    case ZETA_MSG_UNMAP_VIEW:
    case ZETA_MSG_WRITE_MEM_PE:
    case ZETA_MSG_WRITE_MEM_SHELLCODE:
    case ZETA_MSG_SYSCALL_SPOOF:
        return CAT_INJECT;
    case ZETA_MSG_SILVERFOX_SIGNATURE:
    case ZETA_MSG_SILVERFOX_RELEASES:
    case ZETA_MSG_LINEAGE_ALERT:
        return CAT_MISC;
    default:
        return CAT_NONE;       // IMAGE_LOAD 等本身返回 0 分的事件无需归类
    }
}

// 按类别剩余配额截断本次加分, 并把实际通过的部分记入 p.catScore[cat]。
// 返回实际可加的分。cap == 0 表示该类不设限 (CAT_HONEY)。
static int ApplyCategoryCap(ProcessProfile& p, int cat, int add) {
    if (add <= 0 || cat <= CAT_NONE || cat >= CAT_COUNT) return add;

    const int cap = ContextScoreConfig::CategoryCaps::Of(cat);
    if (cap <= 0) return add;                       // 不设限

    int room = cap - p.catScore[cat];
    if (room < 0) room = 0;
    if (add <= room) {
        p.catScore[cat] += add;
        return add;
    }
    // 超出剩余配额: 截断(可能为 0)。刻意【不做】"单发强信号全额放行"的例外 ——
    // 那会给"单发分值≥上限"的事件重新打开无界通道。决定性证据(蜜罐)走 CAT_HONEY,
    // 不设限; 其余强信号的分值都已选在各自上限之内(见 CategoryCaps 取值理由)。
    p.catScore[cat] += room;
    return room;
}

int ProcessBehaviorEngine::scoreWithContext(const BehaviorEvent& evt, ProcessProfile& p) {
    unsigned long code = evt.code;
    const std::wstring& path = evt.path;
    // Rules_Context.json 可调权值 (缺省=代码默认)
    const auto& cff = m_cfg.file;
    const auto& cfr = m_cfg.reg;
    const auto& cfrn = m_cfg.ransom;
    const auto& cfi = m_cfg.inject;
    const auto& cfm = m_cfg.misc;

    switch (code) {
        case ZETA_MSG_FILE_PROTECT: {
            // ── 蜜罐文件触碰 → 直接高分 ──
            if (p.honeyFileTouchCount > 0) {
                return cff.honeyTouchFollowUp;
            }

            // ── P0: 基于操作类型分路 ──
            // 内核 PreSetInfo 发送的 rename/delete 也通过 code=2001 上报，
            // 但 IrpSemantic.opType 区分了 IRP_OP_FILE_CREATE / RENAME / DELETE
            if (evt.ctx.isFileRename()) {
                // 文件重命名评分（低基础，重点是频率和扩展名变化）
                int base = cff.renameBase;
                // 重命名为 PE → 可疑（恶意软件常改名逃避检测）
                if (evt.ctx.isPeFile()) {
                    base = cff.renamePe;
                    p.peReleases++;
                }
                // 重命名时覆盖已有文件 → +3
                if (evt.ctx.replaceIfExists()) base += cff.renameOverwrite;
                // 频率加速
                if (p.sameEventRepeatCount >= 3) base += cff.renameRepeat3;
                if (p.sameEventRepeatCount >= 6) base += cff.renameRepeat6;
                return base;
            }
            if (evt.ctx.isFileDelete()) {
                // 文件删除评分（低基础，避免误杀正常清理行为）
                int base = cff.deleteBase;
                if (evt.ctx.dispositionEx()) base += cff.deleteDispEx;     // Win10+ 高级删除
                if (evt.ctx.dispositionDelete()) base += cff.deleteDispDelete; // 硬删除
                // 删除 PE 文件 → 可疑（恶意软件删除自身痕迹）
                if (evt.ctx.isPeFile()) base += cff.deletePe;
                // 频率加速
                if (p.sameEventRepeatCount >= 5) base += cff.deleteRepeat5;
                if (p.sameEventRepeatCount >= 10) base += cff.deleteRepeat10;
                return base;
            }

            // 使用内核提供的 isPeFile 标签，fallback 到扩展名检测
            if (evt.ctx.isPeFile()) {
                p.peReleases++;
                int base = cff.peBase;
                // 频率加速: 连续多次 PE 释放
                if (p.sameEventRepeatCount >= 3) base += cff.peRepeat3;
                if (p.sameEventRepeatCount >= 6) base += cff.peRepeat6;
                return base;
            }
            size_t dot = path.find_last_of(L'.');
            if (dot != std::wstring::npos) {
                std::wstring ext = path.substr(dot);
                if (ext == L".exe" || ext == L".dll" || ext == L".sys" ||
                    ext == L".scr" || ext == L".ocx") {
                    p.peReleases++;
                    int base = cff.peBase;
                    if (p.sameEventRepeatCount >= 3) base += cff.peRepeat3;
                    if (p.sameEventRepeatCount >= 6) base += cff.peRepeat6;
                    return base;
                }
            }
            return cff.writeBase;
        }
        case ZETA_MSG_REG_PROTECT: {
            // 频率加速: 同一进程反复改注册表
            int baseReg = cfr.base;
            if (p.sameEventRepeatCount >= 3) baseReg += cfr.repeat3;
            if (p.sameEventRepeatCount >= 6) baseReg += cfr.repeat6;

            // 使用内核提供的 isService/isRunKey 标签
            if (evt.ctx.isService()) return cfr.service + baseReg;
            if (evt.ctx.isRunKey()) {
                p.wroteToRunKey = true;
                // 可信进程 (SIGNED/SYSTEM) 写 Run 键：降低评分
                // 可能是合法自注册行为 (如 internat.exe 写 Run\internat.exe)
                if (p.trustLevel >= 3) return cfr.runkeyTrusted;
                // [FIX] 信任级别未设置时，fallback 到进程路径检测
                // 系统路径 (System32/SysWOW64/Program Files) 的进程写 Run 键视为合法
                if (p.processPath.find(L"\\System32\\") != std::wstring::npos ||
                    p.processPath.find(L"\\SysWOW64\\") != std::wstring::npos ||
                    p.processPath.find(L"\\Program Files") != std::wstring::npos)
                    return cfr.runkeyTrusted;
                return cfr.runkeyUntrusted + baseReg;
            }
            // Fallback: path 匹配
            if (path.find(L"\\Services\\") != std::wstring::npos) return cfr.service + baseReg;
            if (path.find(L"\\Run") != std::wstring::npos) {
                p.wroteToRunKey = true;
                if (p.trustLevel >= 3) return cfr.runkeyTrusted;
                // [FIX] 同上: 系统路径进程写 Run 键视为合法
                if (p.processPath.find(L"\\System32\\") != std::wstring::npos ||
                    p.processPath.find(L"\\SysWOW64\\") != std::wstring::npos ||
                    p.processPath.find(L"\\Program Files") != std::wstring::npos)
                    return cfr.runkeyTrusted;
                return cfr.runkeyUntrusted + baseReg;
            }
            return cfr.base;
        }
        case ZETA_MSG_RANSOM_FIRST_WRITE:
            // P0-3: 勒索首写信号 — 原硬编码 70 分 (两次命中即 140 过终结阈值,
            // 编译器/解压工具全盘覆写会被误杀)。改为信号权重 30, 由累加制+阈值判定。
            return cfrn.firstWrite;
        case ZETA_MSG_RANSOM_ENTROPY_WRITE: {
            // P0-5: 勒索高熵/高频写信号 (驱动 RansomExp_CheckWrite, 原错报 7003)
            // RansomExp_CheckWrite 同时检测高熵写入与高频写入(3s窗口), 统一走 5003。
            // fileWriteBursts 计数随本信号累加 (原挂在 7003, 7003 已无事件源)。
            p.fileWriteBursts++;
            int base = cfrn.entropyBase +
                (std::min)(cfrn.entropyBurstCap, p.fileWriteBursts * cfrn.entropyBurstScale);
            if (p.sameEventRepeatCount >= 3) base += cfrn.entropyRepeat3;
            if (p.sameEventRepeatCount >= 8) base += cfrn.entropyRepeat8;
            return base;
        }
        case ZETA_MSG_RANSOM_HONEY_TOUCH:
            // P0-6: 蜜罐触碰强信号 — 单次 30 分, 后续任一 2001 事件再 +80 (honeyFileTouchCount>0),
            // 累加过阈值后由 EDR 联动处置。
            return cfrn.honeyTouch;
        case ZETA_MSG_THREAD_CREATE: {
            // ── 线程创建评分 ──
            //
            // 【基数型事件处理 —— 2026-10-03 修复: 这类事件退出评分】
            // 驱动对【每一次】线程创建都上报 7008 (ThreadNotifyRoutine 两种格式都发:
            // 远程发 "pid,tid,R,creatorPid", 本地发 "pid,tid"), 而线程创建是每个进程、
            // 每个线程池、每个 Electron/V8 运行时每秒都在发生的基数型事件。
            //
            // 旧实现的算分根源: 无 R 标记的普通线程创建会走到本函数末尾的
            //   `return cfi.injectorUnverified;` (=5 分) —— 等于每次 CreateThread 加 5 分。
            // 按稳态公式(T=驱动限速1s, H=120s, 系数173.6) 每事件 5 分 ⇒ 稳态 868 分,
            // 约 17 个事件(17 秒)就越过 85 并弹框, 归零后必然复弹 → 无限弹框。
            // 日志实证: (int)(43*0.99424)+5=47, (int)(47*0.99424)+5=51 … 逐条吻合 +5。
            //
            // 现在的规则:
            //   · 只有带 R 标记(驱动判定为跨进程创建) 才具备证据价值;
            //   · 普通本地线程创建一律 0 分, 但【仍保留 threadCreateCount 计数】,
            //     供状态机条件与诊断使用 —— 退出的是"评分", 不是"存在性证据"。
            p.threadCreateCount++;
            const bool isRemote = (path.find(L",R") != std::wstring::npos);

            int base = cfi.threadCreateBase;   // 默认 0 (Rules_Context.json)
            if (isRemote) {
                p.remoteThreadCount++;
                base += cfi.remoteThread;      // 跨进程创建线程 → 高风险
                if (p.remoteThreadCount >= 3) base += cfi.remoteThread3;
                if (p.remoteThreadCount >= 10) base += cfi.remoteThread10;
            }
            // ⚠ 已删除原 threadCount5/10/20 与 lowTrustThread3 加成。
            //   它们以 threadCreateCount 为条件, 而该计数一旦过阈值就【永久】成立,
            //   于是不是"一次性的档位奖励", 而是"永久抬高后续每个事件底分"的乘数,
            //   属纯基数放大器 (会把任意进程的稳态分推到阈值的 20 倍以上)。

            // [SECURITY FIX] 信任判断基于"注入者"签名，而非受害者(evt.pid/trustLevel)
            // 7008 上报 evt.pid=目标(受害者)，trustLevel 亦是受害者语义，故用 path 解析 creatorPid
            // [P0-误判修复] 注入者进程已退出(查不到路径)时, 不可据此判"无签名注入者"重罚:
            //   远程线程注入后注入者立即退出是常见现象, 此时无法验证签名。
            //   正确降级: 无法验证 → 回到基础分(低危), 不加注入加分, 避免误伤受害者。
            unsigned long inj = getInjectorPid(ZETA_MSG_THREAD_CREATE, path);
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
                    if (isRemote) return cfi.injectorTrustedRemote;  // 远程线程注入(签名进程): 仅留最小痕迹分
                    return 0;  // 普通线程创建(签名进程): 不加分
                }
                return base;  // 明确无签名注入者 → 按远程线程注入加分
            }
            // 注入者无法验证(已退出/查不到)。
            // ⚠ 旧实现在此处无条件 return injectorUnverified(5), 使"不带 R 标记的
            //   普通线程创建"也拿 5 分 —— 这正是本次误报的算分关键点, 务必保留 isRemote 判断。
            if (!isRemote) return 0;          // 本地线程创建: 基数型事件, 不计分
            return cfi.injectorUnverified;    // 仅"跨进程但注入者查不到"才留最小痕迹分
        }
        case ZETA_MSG_CODE_INJECT:
            p.suspiciousDllLoads++;
            if (p.suspiciousDllLoads <= 1) return cfi.codeInject1;
            if (p.suspiciousDllLoads == 2) return cfi.codeInject2;
            return cfi.codeInject3;
        case ZETA_MSG_APC_INJECT: {
            // APC 注入: 高风险，但仅对不可信/无签名进程大幅加分
            // [SECURITY FIX] 基于"注入者"签名判断，而非受害者 trustLevel
            // [P0-误判修复] 注入者已退出(查不到路径)时无法验证签名, 不可判 40 分高危:
            // 降级为基础分, 避免误伤 (APC 注入者常为一次性短命进程)。
            unsigned long inj = getInjectorPid(ZETA_MSG_APC_INJECT, path);
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
                return cfi.apcUntrusted;  // 明确无签名进程 APC 注入 → 高危
            }
            return cfi.apcUnverified;  // 注入者无法验证(已退出): 降级为低危基础分, 不误伤
        }
        case ZETA_MSG_SILVERFOX_SIGNATURE:
            if (!evt.detail.empty()) return cfm.silverfoxSignature;
            return 0;
        case ZETA_MSG_SILVERFOX_RELEASES:
            // SilverFox PE 释放超量 (驱动 ProtectFile 检测) — 强信号
            return cfm.silverfoxReleases;
        case ZETA_MSG_THREAD_CREATE_INJECT:
            // P2-优先级2: 跨进程远程线程创建 (NtCreateThreadEx hook) — 注入链环节
            return cfi.createThreadInject;
        case ZETA_MSG_WRITE_MEM_INJECT:
            // 跨进程写内存 (NtWriteVirtualMemory hook) — 注入链环节
            return cfi.writeMemInject;
        case ZETA_MSG_UNMAP_VIEW:
            // 跨进程解映射 (NtUnmapViewOfSection hook) — 进程镂空前置"清空"
            // 单独 40 分; 与 write+thread 组成镂空链在 detectBehaviorSequence 加权到 90+
            return cfi.unmapView;
        case ZETA_MSG_WRITE_MEM_PE:
            // P2-优先级3: 跨进程写入 MZ 头 (PE 注入/镂空载荷) → 强信号
            return cfi.writeMemPe;
        case ZETA_MSG_WRITE_MEM_SHELLCODE:
            // P2-优先级3: 跨进程写入 shellcode 特征 (驱动已拒绝) → 确定恶意
            return cfi.writeMemShellcode;
        case ZETA_MSG_SYSCALL_SPOOF:
            // P4-优先级4: 跨进程调用者 RIP 非 ntdll (间接/内联 syscall) → 高级手法
            // 观察信号, 单事件 30 分; 与注入链组合权重更高
            return cfi.syscallSpoof;
        case ZETA_MSG_LINEAGE_ALERT: {
            p.hasScriptAncestor = true;
            std::wstring lower = path;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
            size_t dot = path.find_last_of(L'.');
            bool isPE = (dot != std::wstring::npos) && (
                path.compare(dot, 4, L".exe") == 0 ||
                path.compare(dot, 4, L".dll") == 0 ||
                path.compare(dot, 4, L".sys") == 0);
            if (!isPE) return cfm.lineageNonPe;
            if (lower.find(L"\\users\\public\\") != std::wstring::npos) return cfm.lineagePublic;
            if (lower.find(L"\\appdata\\roaming\\") != std::wstring::npos) return cfm.lineageRoaming;
            if (lower.find(L"\\program files") != std::wstring::npos ||
                lower.find(L"\\windows\\system32") != std::wstring::npos ||
                lower.find(L"\\windows\\syswow64") != std::wstring::npos) return cfm.lineageSystem;
            return cfm.lineageDefault;
        }
        // case 7003 评分已并入 case 5003 (驱动侧 7003 发送点已全部迁移,
        // RansomExp_CheckWrite 高熵/高频命中统一上报 5003)
        case ZETA_MSG_IMAGE_LOAD:
            // 驱动加载: 不直接加分 (加载驱动本身合法),
            // 仅记录状态供状态机规则 (BYOVD: 无签名进程拉起驱动) 关联判定
            p.driverLoadCount++;
            return 0;
        // P2-4b: 8001/8002(挖矿/数据外泄) 网络评分已删 — NetFilter 事件走独立 ring buffer,
        // netFilterEventLoop 从不 ingest, 此评分分支从未执行 (死代码)。
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
    const auto& cfs = m_cfg.sequence;  // Rules_Context.json 可调

    // ── 模式1: 脚本→持久化→释放PE (银狐部署链) ──
    // 寻找: 7001(脚本释放) + 3001(Run键) + 2001(PE释放) 的组合
    bool hasScript = false, hasRunKey = false, hasPeRelease = false;
    for (int i = 0; i < p.seqCount && i < ProcessProfile::SEQ_WINDOW; i++) {
        auto& e = p.recentSequence[i];
        if (e.code ==  ZETA_MSG_LINEAGE_ALERT) hasScript = true;
        if (e.code ==  ZETA_MSG_REG_PROTECT && (e.regFlags & 0x0001)) hasRunKey = true;
        if (e.code ==  ZETA_MSG_FILE_PROTECT && (e.fileFlags & 0x0001)) hasPeRelease = true;
    }
    if (hasScript && hasRunKey && hasPeRelease) {
        bonus += cfs.scriptRunkeyPe;
    }

    // ── 模式2: 多级脚本调用 (scriptDepth >= 3) ──
    if (p.scriptChainDepth >= 3) {
        bonus += cfs.scriptChainDepth3;
    }

    // ── 模式3: 无签名进程 + 多个敏感操作 ──
    if (p.trustLevel <= 1 && p.sensitiveRegWriteCount >= cfs.sensitiveRegThreshold) {
        bonus += cfs.unsignedSensitiveReg;
    }

    // ── 模式4: 高频 PE 释放 (短时间内释放多个 PE) ──
    if (p.peReleases >= 3 && p.firstEventMs > 0) {
        long long elapsed = GetTickCount64() - p.firstEventMs;
        if (elapsed > 0 && elapsed < cfs.highFreqPeWindowMs) {
            double rate = (double)p.peReleases / (elapsed / 1000.0);
            if (rate > (double)cfs.highFreqPeRate) {
                bonus += cfs.highFreqPe;
            }
        }
    }

    // ── 模式5: 脚本释放PE + 线程创建 (完整攻击链) ──
    // 查找: 7001(脚本) + 2001(PE) + 7008(线程) 的组合
    {
        bool hasScript = false, hasPe = false, hasThread = false;
        for (int i = 0; i < p.seqCount && i < ProcessProfile::SEQ_WINDOW; i++) {
            if (p.recentSequence[i].code ==  ZETA_MSG_LINEAGE_ALERT) hasScript = true;
            if (p.recentSequence[i].code ==  ZETA_MSG_FILE_PROTECT && (p.recentSequence[i].fileFlags & 0x0001)) hasPe = true;
            if (p.recentSequence[i].code ==  ZETA_MSG_THREAD_CREATE) hasThread = true;
        }
        if (hasScript && hasPe && hasThread) {
            bonus += cfs.scriptPeThread;  // 脚本→释放→执行 攻击链
        } else if (hasPe && hasThread && p.threadCreateCount >= 3) {
            bonus += cfs.peThreadNoScript;  // PE释放+线程创建 (无脚本感染)
        }
    }

    // ── 模式6: 勒索加速模式 ──
    // 同时满足: offset=0写入 + 大量文件操作 + 文件重命名
    {
        bool hasOffsetZero = false, hasRename = false;
        int fileWriteCount = 0;
        for (int i = 0; i < p.seqCount && i < ProcessProfile::SEQ_WINDOW; i++) {
            auto& e = p.recentSequence[i];
            if (e.code ==  ZETA_MSG_FILE_PROTECT && (e.fileFlags & 0x0008)) hasOffsetZero = true;
            if (e.code ==  ZETA_MSG_FILE_PROTECT && (e.fileFlags & 0x0020)) hasRename = true;
            if (e.code ==  ZETA_MSG_FILE_PROTECT || e.code ==  ZETA_MSG_RANSOM_ENTROPY_WRITE) fileWriteCount++;
        }
        if (hasOffsetZero && fileWriteCount >= 3) {
            bonus += cfs.offsetZeroChain;  // offset=0写入 + 频繁文件操作 → 勒索
        }
        if (p.offsetZeroWriteCount >= cfs.offsetZeroCountThreshold) {
            bonus += cfs.offsetZeroCount;  // 大量 offset=0 写入
        }
    }

    // ── 模式7: 注册表持久化 + PE释放 (木马标准行为) ──
    {
        bool hasRunKey = false, hasPeRelease = false;
        for (int i = 0; i < p.seqCount && i < ProcessProfile::SEQ_WINDOW; i++) {
            auto& e = p.recentSequence[i];
            if (e.code ==  ZETA_MSG_REG_PROTECT && (e.regFlags & 0x0001)) hasRunKey = true;
            if (e.code ==  ZETA_MSG_FILE_PROTECT && (e.fileFlags & 0x0001)) hasPeRelease = true;
        }
        if (hasRunKey && hasPeRelease && p.peReleases >= cfs.peReleaseThreshold) {
            bonus += cfs.runkeyPe;  // 写Run键 + 多次PE释放 → 典型木马
        }
    }

    // ── 模式8: 进程镂空链 (P2-优先级2) ──
    // 完整事件流: 创建挂起 -> 解映射(6017) -> 写入(6016) -> 恢复线程(6015)
    // 窗口内出现 unmap + write + thread 三个环节 = 进程镂空 → 确定恶意
    {
        bool hasUnmap = false, hasWrite = false, hasThread = false;
        for (int i = 0; i < p.seqCount && i < ProcessProfile::SEQ_WINDOW; i++) {
            auto& e = p.recentSequence[i];
            if (e.code ==  ZETA_MSG_UNMAP_VIEW) hasUnmap = true;
            else if (e.code ==  ZETA_MSG_WRITE_MEM_INJECT) hasWrite = true;
            else if (e.code ==  ZETA_MSG_THREAD_CREATE_INJECT) hasThread = true;
        }
        if (hasUnmap && hasWrite && hasThread) {
            bonus += cfs.hollowFull;  // 镂空三环节齐 → 加 50 (单环节已 40+30+25, 组合到 90+ 确定恶意)
        } else if (hasUnmap && hasWrite) {
            bonus += cfs.hollowPartial;  // 解映射+写入 → 高度可疑 (镂空过半)
        }
    }

    // ── 模式9: 蜜罐触碰 → 立即高分 (不管其他条件) ──
    if (p.honeyFileTouchCount > 0) {
        bonus += cfs.honeyTouchBonus;  // 蜜罐文件触碰 → 高度确定恶意
    }

    // ── 模式9: 全面攻击链 (4+ 种不同高危操作) ──
    {
        int uniqueHighRisk = 0;
        bool seenCodes[16] = {false};
        for (int i = 0; i < p.seqCount && i < ProcessProfile::SEQ_WINDOW; i++) {
            unsigned long c = p.recentSequence[i].code;
            if (c == ZETA_MSG_FILE_PROTECT || c == ZETA_MSG_REG_PROTECT || c == ZETA_MSG_DISK_WRITE || c == ZETA_MSG_RANSOM_FIRST_WRITE ||
                c == ZETA_MSG_CODE_INJECT || c == ZETA_MSG_APC_INJECT || c == ZETA_MSG_LINEAGE_ALERT || c == ZETA_MSG_THREAD_CREATE) {
                int idx = 0;
                if (c == ZETA_MSG_FILE_PROTECT) idx = 0; else if (c == ZETA_MSG_REG_PROTECT) idx = 1;
                else if (c == ZETA_MSG_DISK_WRITE) idx = 2; else if (c == ZETA_MSG_RANSOM_FIRST_WRITE) idx = 3;
                else if (c == ZETA_MSG_CODE_INJECT) idx = 4; else if (c == ZETA_MSG_LINEAGE_ALERT) idx = 5;
                else if (c == ZETA_MSG_THREAD_CREATE) idx = 6;
                else if (c == ZETA_MSG_APC_INJECT) idx = 7;
                if (!seenCodes[idx]) { seenCodes[idx] = true; uniqueHighRisk++; }
            }
        }
        if (uniqueHighRisk >= 4) bonus += cfs.multiAttack4;   // 4种高危操作 → 高度恶意
        else if (uniqueHighRisk >= 3) bonus += cfs.multiAttack3; // 3种 → 可疑
    }

    // ── 模式10: 跨进程"落盘执行链" (P2-7) ──
    // 父进程是脚本宿主 (hasScriptAncestor / scriptChainDepth>0)，且当前进程
    // 释放了可执行 PE (2001+PE标志) → 脚本→释放exe→执行 的完整攻击链。
    // 这是跨进程关联：需要查询父进程 profile 的脚本属性。
    {
        bool childHasPeRelease = false;
        for (int i = 0; i < p.seqCount && i < ProcessProfile::SEQ_WINDOW; i++) {
            if (p.recentSequence[i].code ==  ZETA_MSG_FILE_PROTECT &&
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
                    bonus += cfs.scriptParentPe;  // 脚本宿主子进程释放PE → 高置信落盘执行链
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
        case ZETA_MSG_FILE_PROTECT: {
            size_t dot = path.find_last_of(L'.');
            bool isExec = (dot != std::wstring::npos) && (
                path.compare(dot, 4, L".exe") == 0 ||
                path.compare(dot, 4, L".dll") == 0 ||
                path.compare(dot, 4, L".sys") == 0 ||
                path.compare(dot, 4, L".scr") == 0);
            if (isExec) return L"拦截释放可执行文件 [20分]";
            return L"文件防护拦截 [10分]";
        }
        case ZETA_MSG_REG_PROTECT: {
            if (path.find(L"\\Services\\") != std::wstring::npos) return L"拦截服务注册 [30分]";
            if (path.find(L"\\Run") != std::wstring::npos) return L"拦截自启项注册 [25分]";
            return L"注册表防护拦截 [10分]";
        }
        case ZETA_MSG_DISK_WRITE: return L"磁盘擦写操作 [30分]";
        case ZETA_MSG_VOLUME_DISMOUNT: return L"卷卸载/锁卷操作 [30分]";
        case ZETA_MSG_DISK_WRITE_ALERT: return L"磁盘擦写监控告警 [20分]";
        case ZETA_MSG_RANSOM_FIRST_WRITE: return L"文件头完整性检测告警(疑似勒索加密)";
        case ZETA_MSG_RANSOM_ENTROPY_WRITE: return L"勒索高熵/高频写入 [第" + std::to_wstring(p.fileWriteBursts) + L"轮]";
        case ZETA_MSG_RANSOM_HONEY_TOUCH: return L"蜜罐文件触碰(高度确定恶意)";
        case ZETA_MSG_CODE_INJECT: return L"从临时目录加载DLL [第" + std::to_wstring(p.suspiciousDllLoads) + L"次]";
        case ZETA_MSG_SILVERFOX_SIGNATURE: return L"签名不一致检测(银狐)";
        case ZETA_MSG_SILVERFOX_RELEASES: return L"银狐PE释放超量 [50分]";
        case ZETA_MSG_APC_INJECT: return L"APC注入(跨线程异步过程调用)";
        case ZETA_MSG_LINEAGE_ALERT: return L"脚本释放文件";
        case ZETA_MSG_PROCESS_CREATE: return L"进程创建/派生";
        case ZETA_MSG_THREAD_CREATE: return L"线程创建(含远程线程注入)";
        case ZETA_MSG_IMAGE_LOAD: return L"加载驱动(.sys)";
        // P2-4b: 8001/8002 描述已删 (网络评分死代码, 见 scoreWithContext 注释)
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

// ============================================================
// 第4层上下文评分配置加载 (Rules_Context.json)
// ============================================================

// 提取 JSON 中指定键对应的对象子串 (含花括号, 支持嵌套)
static std::wstring extractJsonObject(const std::wstring& json, const std::wstring& key) {
    size_t kp = json.find(L"\"" + key + L"\"");
    if (kp == std::wstring::npos) return L"";
    size_t colon = json.find(L':', kp);
    if (colon == std::wstring::npos) return L"";
    size_t c = colon + 1;
    while (c < json.size() && (json[c] == L' ' || json[c] == L'\t' ||
                               json[c] == L'\n' || json[c] == L'\r')) c++;
    if (c >= json.size() || json[c] != L'{') return L"";
    int depth = 0;
    for (size_t i = c; i < json.size(); i++) {
        if (json[i] == L'{') depth++;
        else if (json[i] == L'}') {
            depth--;
            if (depth == 0) return json.substr(c, i - c + 1);
        }
    }
    return L"";
}

// 解析一个对象中的数值字段集合 (以分号分隔的键值对风格不可用, 直接逐个 extractJsonInt)
#define CFG_INT(obj, group, field, key) \
    cfg.group.field = extractJsonInt(obj, key, cfg.group.field)

void ProcessBehaviorEngine::loadContextConfig(const std::wstring& path) {
    // 从默认值开始解析, 文件缺失/字段缺省自动回退 (行为不变)
    ContextScoreConfig cfg;

    std::wstring j;
    FILE* f = nullptr;
    if (_wfopen_s(&f, path.c_str(), L"rb") != 0 || !f) {
        m_cfg = cfg;
        return;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len <= 0) { fclose(f); m_cfg = cfg; return; }
    std::string utf8(len, '\0');
    fread(&utf8[0], 1, len, f);
    fclose(f);
    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), nullptr, 0);
    if (wlen <= 0) { m_cfg = cfg; return; }
    j.resize(wlen);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), &j[0], wlen);

    // ── ctx_bonus: processEvent Step2 上下文加成 ──
    {
        std::wstring o = extractJsonObject(j, L"ctx_bonus");
        CFG_INT(o, ctxBonus, untrustedPeFirst,      L"untrusted_pe_first");
        CFG_INT(o, ctxBonus, untrustedPeMany,       L"untrusted_pe_many");
        CFG_INT(o, ctxBonus, untrustedPeManyCount,  L"untrusted_pe_many_count");
        CFG_INT(o, ctxBonus, offsetZeroDoc,         L"offset_zero_doc");
        CFG_INT(o, ctxBonus, tempPe,                L"temp_pe");
        CFG_INT(o, ctxBonus, tempPeCount,           L"temp_pe_count");
        CFG_INT(o, ctxBonus, scriptHostPe,          L"script_host_pe");
        CFG_INT(o, ctxBonus, scriptAncestorPe,      L"script_ancestor_pe");
        CFG_INT(o, ctxBonus, scriptChainDepth3,     L"script_chain_depth3");
        CFG_INT(o, ctxBonus, sensitiveReg,          L"sensitive_reg");
        CFG_INT(o, ctxBonus, exclusivePe,           L"exclusive_pe");
        CFG_INT(o, ctxBonus, trustedReductionDiv,   L"trusted_reduction_div");
        if (cfg.ctxBonus.trustedReductionDiv <= 0) cfg.ctxBonus.trustedReductionDiv = 2;
    }

    // ── event_scores: scoreWithContext 各事件分路 ──
    std::wstring es = extractJsonObject(j, L"event_scores");
    {
        std::wstring o = extractJsonObject(es, L"file");
        CFG_INT(o, file, writeBase,           L"write_base");
        CFG_INT(o, file, peBase,              L"pe_base");
        CFG_INT(o, file, peRepeat3,           L"pe_repeat3");
        CFG_INT(o, file, peRepeat6,           L"pe_repeat6");
        CFG_INT(o, file, renameBase,          L"rename_base");
        CFG_INT(o, file, renamePe,            L"rename_pe");
        CFG_INT(o, file, renameOverwrite,     L"rename_overwrite");
        CFG_INT(o, file, renameRepeat3,       L"rename_repeat3");
        CFG_INT(o, file, renameRepeat6,       L"rename_repeat6");
        CFG_INT(o, file, deleteBase,          L"delete_base");
        CFG_INT(o, file, deleteDispEx,        L"delete_disposition_ex");
        CFG_INT(o, file, deleteDispDelete,    L"delete_disposition_delete");
        CFG_INT(o, file, deletePe,            L"delete_pe");
        CFG_INT(o, file, deleteRepeat5,       L"delete_repeat5");
        CFG_INT(o, file, deleteRepeat10,      L"delete_repeat10");
        CFG_INT(o, file, honeyTouchFollowUp,  L"honey_touch_followup");
    }
    {
        std::wstring o = extractJsonObject(es, L"reg");
        CFG_INT(o, reg, base,           L"base");
        CFG_INT(o, reg, repeat3,        L"repeat3");
        CFG_INT(o, reg, repeat6,        L"repeat6");
        CFG_INT(o, reg, service,        L"service");
        CFG_INT(o, reg, runkeyUntrusted,L"runkey_untrusted");
        CFG_INT(o, reg, runkeyTrusted,  L"runkey_trusted");
    }
    {
        std::wstring o = extractJsonObject(es, L"ransom");
        CFG_INT(o, ransom, firstWrite,       L"first_write");
        CFG_INT(o, ransom, entropyBase,      L"entropy_base");
        CFG_INT(o, ransom, entropyBurstScale,L"entropy_burst_scale");
        CFG_INT(o, ransom, entropyBurstCap,  L"entropy_burst_cap");
        CFG_INT(o, ransom, entropyRepeat3,   L"entropy_repeat3");
        CFG_INT(o, ransom, entropyRepeat8,   L"entropy_repeat8");
        CFG_INT(o, ransom, honeyTouch,       L"honey_touch");
    }
    {
        std::wstring o = extractJsonObject(es, L"inject");
        CFG_INT(o, inject, threadCreateBase,        L"thread_create_base");
        CFG_INT(o, inject, remoteThread,            L"remote_thread");
        CFG_INT(o, inject, remoteThread3,           L"remote_thread3");
        CFG_INT(o, inject, remoteThread10,          L"remote_thread10");
        CFG_INT(o, inject, threadCount5,            L"thread_count5");
        CFG_INT(o, inject, threadCount10,           L"thread_count10");
        CFG_INT(o, inject, threadCount20,           L"thread_count20");
        CFG_INT(o, inject, lowTrustThread3,         L"lowtrust_thread3");
        CFG_INT(o, inject, injectorTrustedRemote,   L"injector_trusted_remote");
        CFG_INT(o, inject, injectorUnverified,      L"injector_unverified");
        CFG_INT(o, inject, codeInject1,             L"code_inject1");
        CFG_INT(o, inject, codeInject2,             L"code_inject2");
        CFG_INT(o, inject, codeInject3,             L"code_inject3");
        CFG_INT(o, inject, apcUntrusted,            L"apc_untrusted");
        CFG_INT(o, inject, apcUnverified,           L"apc_unverified");
        CFG_INT(o, inject, createThreadInject,      L"create_thread_inject");
        CFG_INT(o, inject, writeMemInject,          L"write_mem_inject");
        CFG_INT(o, inject, unmapView,               L"unmap_view");
        CFG_INT(o, inject, writeMemPe,              L"write_mem_pe");
        CFG_INT(o, inject, writeMemShellcode,       L"write_mem_shellcode");
        CFG_INT(o, inject, syscallSpoof,            L"syscall_spoof");
    }
    {
        std::wstring o = extractJsonObject(es, L"misc");
        CFG_INT(o, misc, silverfoxSignature,  L"silverfox_signature");
        CFG_INT(o, misc, silverfoxReleases,   L"silverfox_releases");
        CFG_INT(o, misc, lineageNonPe,        L"lineage_nonpe");
        CFG_INT(o, misc, lineagePublic,       L"lineage_public");
        CFG_INT(o, misc, lineageRoaming,      L"lineage_roaming");
        CFG_INT(o, misc, lineageSystem,       L"lineage_system");
        CFG_INT(o, misc, lineageDefault,      L"lineage_default");
    }

    // ── sequence: detectBehaviorSequence 序列加分 ──
    {
        std::wstring o = extractJsonObject(j, L"sequence");
        CFG_INT(o, sequence, scriptRunkeyPe,       L"script_runkey_pe");
        CFG_INT(o, sequence, scriptChainDepth3,    L"script_chain_depth3");
        CFG_INT(o, sequence, unsignedSensitiveReg, L"unsigned_sensitive_reg");
        CFG_INT(o, sequence, sensitiveRegThreshold,L"sensitive_reg_threshold");
        CFG_INT(o, sequence, highFreqPe,           L"high_freq_pe");
        CFG_INT(o, sequence, highFreqPeRate,       L"high_freq_pe_rate");
        CFG_INT(o, sequence, highFreqPeWindowMs,   L"high_freq_pe_window_ms");
        CFG_INT(o, sequence, scriptPeThread,       L"script_pe_thread");
        CFG_INT(o, sequence, peThreadNoScript,     L"pe_thread_noscript");
        CFG_INT(o, sequence, offsetZeroChain,      L"offset_zero_chain");
        CFG_INT(o, sequence, offsetZeroCount,      L"offset_zero_count");
        CFG_INT(o, sequence, offsetZeroCountThreshold, L"offset_zero_count_threshold");
        CFG_INT(o, sequence, runkeyPe,             L"runkey_pe");
        CFG_INT(o, sequence, peReleaseThreshold,   L"pe_release_threshold");
        CFG_INT(o, sequence, hollowFull,           L"hollow_full");
        CFG_INT(o, sequence, hollowPartial,        L"hollow_partial");
        CFG_INT(o, sequence, honeyTouchBonus,      L"honey_touch_bonus");
        CFG_INT(o, sequence, multiAttack4,         L"multi_attack4");
        CFG_INT(o, sequence, multiAttack3,         L"multi_attack3");
        CFG_INT(o, sequence, scriptParentPe,       L"script_parent_pe");
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    m_cfg = cfg;
}

#undef CFG_INT

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

// 单事件驱动求值状态机
// M1-2: 规则 window_ms>0 时启用"窗口序列"语义 —
//   event 类条件 = 在 [nowMs-window_ms, nowMs] 窗口内(含当前事件)出现过该事件即可,
//   process_state/relation 类条件 = 当前进程状态即时满足。
// 这样如 script_drop_exec(先写PE后创建进程) / syscall_spoof_block(6020+6016)
// 的跨事件组合在窗口内命中; window_ms=0 保持旧语义(全部条件对当前单事件求值)。
void ProcessBehaviorEngine::evaluateStateMachine(const BehaviorEvent& evt, ProcessProfile& p) {
    if (m_smRules.empty()) return;

    std::lock_guard<std::mutex> lock(m_smMutex);
    long long nowMs = GetTickCount64();

    for (const auto& rule : m_smRules) {
        bool windowed = (rule.window_ms > 0);

        // 窗口命中抑制: 同一窗口规则已处置过 → 窗口期内跳过, 防重复处置
        if (windowed && rule.action != 0) {
            auto hitIt = p.smRuleHitMs.find(rule.id);
            if (hitIt != p.smRuleHitMs.end() &&
                (nowMs - hitIt->second) < rule.window_ms) {
                continue;
            }
        }

        bool allOk = true;
        if (!rule.all_conds.empty()) {
            for (const auto& cid : rule.all_conds) {
                auto it = m_smConditions.find(cid);
                if (it == m_smConditions.end()) { allOk = false; break; }
                const auto& cond = it->second;
                bool ok;
                if (windowed && cond.type == L"event") {
                    // 窗口语义: event 条件看窗口内是否出现过
                    ok = evalEventConditionInWindow(cond, p, nowMs, rule.window_ms);
                } else {
                    ok = evalCondition(cond, evt, p);
                }
                if (!ok) { allOk = false; break; }
            }
        }
        bool anyOk = rule.any_conds.empty();
        if (!anyOk) {
            for (const auto& cid : rule.any_conds) {
                auto it = m_smConditions.find(cid);
                if (it != m_smConditions.end()) {
                    const auto& cond = it->second;
                    bool ok;
                    if (windowed && cond.type == L"event") {
                        ok = evalEventConditionInWindow(cond, p, nowMs, rule.window_ms);
                    } else {
                        ok = evalCondition(cond, evt, p);
                    }
                    if (ok) { anyOk = true; break; }
                }
            }
        }

        if (allOk && anyOk) {
            // 命中
            if (rule.action == 0) {
                // 豁免: 放行, 不触发处置
                if (m_smCallback) {
                    m_smCallback(evt.pid, rule.id.c_str(), rule.name.c_str(), 0, 0,
                                 rule.block_at.c_str(), rule.redirect_to.c_str(), rule.window_ms);
                }
                return;  // 豁免规则优先, 命中即停止后续
            }
            // 拦截/询问/重定向: 触发处置回调
            if (m_smCallback) {
                m_smCallback(evt.pid, rule.id.c_str(), rule.name.c_str(), rule.action, rule.score,
                             rule.block_at.c_str(), rule.redirect_to.c_str(), rule.window_ms);
            }
            // 窗口规则: 记录命中时间, 窗口期内不重复处置
            if (windowed) p.smRuleHitMs[rule.id] = nowMs;
            // 命中后当前事件处置, 不继续 (防止多条规则重复处置)
            return;
        }
    }
}

// M1-2: 在窗口历史 recentSequence 中扫描 event 类条件是否已满足。
// 由于事件到达时先写 recentSequence 再 evaluateStateMachine, 当前事件也在窗口内。
bool ProcessBehaviorEngine::evalEventConditionInWindow(const StateMachineCondition& c,
                                                       const ProcessProfile& p,
                                                       long long nowMs, long long windowMs) {
    if (c.type != L"event") return false;
    long long winStart = nowMs - windowMs;
    for (int i = 0; i < p.seqCount && i < ProcessProfile::SEQ_WINDOW; i++) {
        const auto& e = p.recentSequence[i];
        if (e.timeMs < winStart || e.timeMs > nowMs) continue;

        // 复用单事件 event 条件判定: 构造一个临时 BehaviorEvent 指向该历史条目
        BehaviorEvent he;
        he.code = e.code;
        he.ctx.fileFlags = e.fileFlags;
        he.ctx.regFlags = e.regFlags;
        he.ctx.trustLevel = e.trustLevel;
        he.path.clear();
        if (c.field == L"path") {
            // 历史条目只保留 path 尾部快照(小写), 足够 endswith 判定
            he.path = e.pathTail;
        } else if (c.field == L"code") {
            he.path.clear();
        } else if (c.field == L"reg_flag") {
            he.path.clear();
        }
        if (evalCondition(c, he, const_cast<ProcessProfile&>(p))) {
            return true;
        }
    }
    return false;
}
