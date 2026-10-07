// zeta_tlsint 宿主侧：注入调度 + 环消费 + 判定上报（M2-3）
//
//   生产者：TlsIntHost_OnProcessCreate（7006 回调）→ 过滤 → 入队（O(1)，绝不阻塞事件线程）
//   消费者：单一工作线程 → 注入；另一线程 → 读环 → 规则判定 → 告警
#include "tlsint_host.h"
#include "tlsint_host_internal.h"

#include "zeta_tlsint.h"     // 复用 Ring 的布局与名字（单一事实来源，避免两份定义漂移）

#include <sddl.h>
#include <aclapi.h>
#include <tlhelp32.h>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <string>
#include <thread>
#include <cstdio>
#include <cstdarg>
#include <cwchar>

#pragma comment(lib, "advapi32.lib")

namespace {

// ── 与 DLL 完全一致的 Ring DACL ─────────────────────────────────────────────
// 必须逐字与 CppLibs/zeta_tlsint/src/tlsint_hook.cpp 的 RingSa() 保持一致：
// 环可能由提权的 ZETA.exe（本模块）先创建，此时非提权的目标进程要能写进环，
// 否则 DLP 静默失效。自测里有专门的 SDDL 一致性断言拦这个漂移。
const wchar_t* kRingSddl = L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;OW)(A;;GRGW;;;IU)";

// P0-1 同款最小权限：DACL 只给 GRGW，用 FILE_MAP_ALL_ACCESS 会 ACCESS_DENIED(5)
const DWORD kMapAccess = FILE_MAP_READ | FILE_MAP_WRITE;

std::atomic<bool> g_running{ false };
std::thread       g_consumerThread;
std::thread       g_injectThread;
std::thread       g_sweepThread;
std::wstring      g_dllPath;

// 扫荡（补 7006 盲区）：默认开，Start 后延时执行一次
std::atomic<int>                g_sweepEnabled{ 1 };
std::atomic<unsigned long long> g_swept{ 0 };
const DWORD kSweepDelayMs = 5000;   // 等 ZETA 自身启动的进程创建风暴先落定

TlsIntLogFn   g_logFn   = nullptr;
TlsIntAlertFn g_alertFn = nullptr;

std::atomic<unsigned long long> g_injected{ 0 };
std::atomic<unsigned long long> g_skipped{ 0 };
std::atomic<unsigned long long> g_injectFail{ 0 };
std::atomic<unsigned long long> g_consumed{ 0 };
std::atomic<unsigned long long> g_alerts{ 0 };
std::atomic<int>                g_ringError{ 0 };

// 注入任务队列（7006 回调只入队；队列有界，防止进程创建风暴把内存吃光）
// fast: 目标是否"已完全就绪"（扫荡既有进程 = true，可免退避）；
//       7006 刚创建的进程 = false，需要退避重试。
struct InjectJob {
    DWORD        pid;
    std::wstring path;
    bool         fast;
};
const size_t kMaxQueue = 256;
std::mutex                g_qm;
std::condition_variable   g_qcv;
std::deque<InjectJob>     g_queue;

// 高价值目标（浏览器 / IM / 邮件 / Office / 下载器）—— 扫荡时**插队到队首**。
// 实机教训：78 个候选 FIFO 排下来，最重要的 msedge/QQ 排在后面，worker 因为它前面的
// 目标反复退避重试而长时间轮不到它们；等值目标必须优先。
bool IsHighValueTarget(const std::wstring& lowerName)
{
    static const wchar_t* kHv[] = {
        L"msedge.exe", L"chrome.exe", L"firefox.exe", L"iexplore.exe", L"opera.exe",
        L"brave.exe", L"msedgewebview2.exe", L"webview2.exe",
        L"qq.exe", L"wechat.exe", L"weixin.exe", L"dingtalk.exe", L"feishu.exe",
        L"lark.exe", L"telegram.exe", L"discord.exe", L"slack.exe", L"teams.exe",
        L"outlook.exe", L"thunderbird.exe", L"foxmail.exe",
        L"winword.exe", L"excel.exe", L"powerpnt.exe", L"wps.exe", L"et.exe", L"wpp.exe",
        L"m365copilot.exe", L"onenote.exe",
        L"curl.exe", L"wget.exe", L"python.exe", L"node.exe", L"bun.exe",
        L"powershell.exe", L"pwsh.exe", L"bitsadmin.exe", L"certutil.exe",
        L"thunder.exe", L"aria2c.exe", L"idm.exe", L"motrix.exe",
    };
    for (const wchar_t* c : kHv) if (lowerName == c) return true;
    return false;
}

HANDLE g_ringMap = nullptr;
ZETA_TLSINT_RING* g_ring = nullptr;

// ── 工具 ───────────────────────────────────────────────────────────────────
void MakePrintable(const unsigned char* d, ULONG n, wchar_t* out, int cchOut, ULONG limit)
{
    ULONG m = (n < limit) ? n : limit;
    int w = 0;
    for (ULONG i = 0; i < m && w < cchOut - 1; ++i) {
        unsigned char c = d[i];
        out[w++] = (c >= 32 && c < 127) ? (wchar_t)c : L'.';
    }
    out[w] = 0;
}

const wchar_t* SevName(int sev)
{
    switch (sev) {
        case 3: return L"HIGH";
        case 2: return L"WARN";
        default: return L"INFO";
    }
}

// ── 环 ─────────────────────────────────────────────────────────────────────
bool OpenRingOnce()
{
    if (g_ring) return true;

    SECURITY_ATTRIBUTES sa{};
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(kRingSddl, SDDL_REVISION_1, &sd, nullptr)) {
        g_ringError = (int)GetLastError();
        return false;
    }
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;

    // 不存在则创建；已存在则返回既有对象句柄（GetLastError = ERROR_ALREADY_EXISTS）
    HANDLE h = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0,
                                  (DWORD)sizeof(ZETA_TLSINT_RING), ZETA_TLSINT_RING_NAME);
    LocalFree(sd);
    if (!h) h = OpenFileMappingW(kMapAccess, FALSE, ZETA_TLSINT_RING_NAME);
    if (!h) {
        g_ringError = (int)GetLastError();
        return false;
    }
    ZETA_TLSINT_RING* r = (ZETA_TLSINT_RING*)MapViewOfFile(h, kMapAccess, 0, 0,
                                                           sizeof(ZETA_TLSINT_RING));
    if (!r) {
        g_ringError = (int)GetLastError();
        CloseHandle(h);
        return false;
    }
    g_ringMap = h;
    g_ring = r;
    g_ringError = 0;
    return true;
}

// ── 环消费线程 ─────────────────────────────────────────────────────────────
void ConsumerLoop()
{
    LONG lastProcessed = -1;           // -1 = 尚未接管，接管时对齐到当前 nextSeq（不回放历史样本）
    ULONGLONG lastSummary = 0;
    unsigned long long summaryBase = 0;

    while (g_running.load()) {
        if (!OpenRingOnce()) {
            // 环不可达必须可见（同 DLL 侧 P0-2 的教训：静默 = 以为在跑其实没跑）
            tlsint_host::Log(2, L"[TLSINT] 环不可达 err=%d，1s 后重试", (int)g_ringError.load());
            Sleep(1000);
            continue;
        }
        if (lastProcessed < 0) lastProcessed = g_ring->nextSeq;

        const LONG next = g_ring->nextSeq;
        if (next != lastProcessed) {
            LONG maxSeen = lastProcessed;
            for (int i = 0; i < ZETA_TLSINT_RING_SLOTS; ++i) {
                ZETA_TLSINT_RING_SLOT* s = &g_ring->slots[i];
                const LONG seq = s->seq;
                if (seq <= lastProcessed || seq <= 0) continue;
                if (seq > maxSeen) maxSeen = seq;

                // 尽力而为的撕裂防护（消费侧；写侧仍是"最后写 seq 发布"）：
                // 拷贝前后 seq 不一致 ⇒ 该槽在读的过程中被覆盖，丢弃而不是拿半新半旧的明文去判定。
                const LONG before = s->seq;
                LONG   pid, dir; ULONG len;
                unsigned char* body = (unsigned char*)malloc(ZETA_TLSINT_RING_BODY);
                if (!body) continue;
                pid = s->pid; dir = s->dir; len = s->len;
                if (len > ZETA_TLSINT_RING_BODY) len = ZETA_TLSINT_RING_BODY;
                memcpy(body, s->data, len);
                const LONG after = s->seq;
                if (before != after || after != seq) { free(body); continue; }

                const unsigned long long n = ++g_consumed;

                TlsIntFinding findings[8];
                const int nf = TlsIntDetect_Analyze(dir, body, len, findings, 8);
                for (int k = 0; k < nf; ++k) {
                    ++g_alerts;
                    tlsint_host::Log(findings[k].severity,
                        L"[TLSINT] 命中 %s(%d) pid=%ld dir=%s len=%lu :: %s",
                        findings[k].ruleName, findings[k].ruleId, pid,
                        dir ? L"OUT" : L"IN", (unsigned long)len, findings[k].detail);
                    tlsint_host::ReportAlert(findings[k].severity, (unsigned long)pid,
                                             findings[k].ruleId, findings[k].ruleName,
                                             findings[k].detail);
                }

                if (n <= 8) {
                    wchar_t excerpt[201];
                    MakePrintable(body, len, excerpt, 201, 200);
                    tlsint_host::Log(1, L"[TLSINT] 明文样本 pid=%ld dir=%s len=%lu :: %s",
                                     pid, dir ? L"OUT" : L"IN", (unsigned long)len, excerpt);
                }
                free(body);
            }
            if (maxSeen > lastProcessed) lastProcessed = maxSeen;
            g_ring->head = lastProcessed;      // 供观测

            const ULONGLONG now = GetTickCount64();
            if (now - lastSummary > 5000) {
                const unsigned long long total = g_consumed.load();
                if (total != summaryBase) {
                    tlsint_host::Log(1, L"[TLSINT] 近 5s 消费明文 %llu 条（明细已省略）",
                                     total - summaryBase);
                    summaryBase = total;
                }
                lastSummary = now;
            }
        }
        Sleep(200);
    }
}

// ── 注入工作线程 ───────────────────────────────────────────────────────────
void InjectLoop()
{
    while (g_running.load()) {
        InjectJob job{};
        {
            std::unique_lock<std::mutex> lk(g_qm);
            g_qcv.wait_for(lk, std::chrono::milliseconds(500),
                           [] { return !g_queue.empty() || !g_running.load(); });
            if (!g_running.load() && g_queue.empty()) break;
            if (g_queue.empty()) continue;
            job = g_queue.front();
            g_queue.pop_front();
        }
        const int rc = tlsint_host::InjectPidWithBudget(job.pid, job.fast);
        if (rc == 0) {
            ++g_injected;
            tlsint_host::Log(1, L"[TLSINT] 已注入 pid=%lu  %s", job.pid, job.path.c_str());
        } else {
            ++g_injectFail;
            tlsint_host::Log(2, L"[TLSINT] 注入失败 pid=%lu rc=%d  %s",
                             job.pid, rc, job.path.c_str());
        }
    }
}

} // namespace

// ── 内部共享 ───────────────────────────────────────────────────────────────
namespace tlsint_host {

std::wstring& DllPath() { return g_dllPath; }

void Log(int level, const wchar_t* fmt, ...)
{
    wchar_t buf[1024];
    va_list ap;
    va_start(ap, fmt);
    ::_vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    if (g_logFn) g_logFn(level, buf);
    else         OutputDebugStringW(buf);
}

void ReportAlert(int severity, unsigned long pid, int ruleId,
                 const wchar_t* ruleName, const wchar_t* detail)
{
    if (g_alertFn) g_alertFn(severity, pid, ruleId, ruleName, detail);
}

} // namespace tlsint_host

// ── 对外 API ───────────────────────────────────────────────────────────────
extern "C" TLSINT_HOST_API int __stdcall TlsIntHost_Start(const wchar_t* dllPath)
{
    if (g_running.load()) return 0;
    if (!dllPath || !*dllPath) return -1;
    if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
        tlsint_host::Log(2, L"[TLSINT] 启动失败：DLL 不存在 %s", dllPath);
        return -1;
    }
    g_dllPath = dllPath;
    g_running = true;
    g_consumerThread = std::thread(ConsumerLoop);
    g_injectThread   = std::thread(InjectLoop);
    // 延时扫荡既有进程（不阻塞启动；等 ZETA 自身的进程创建风暴先落定）
    g_sweepThread = std::thread([] {
        for (DWORD waited = 0; waited < kSweepDelayMs && g_running.load(); waited += 100)
            Sleep(100);
        if (!g_running.load()) return;
        if (!g_sweepEnabled.load()) {
            tlsint_host::Log(1, L"[TLSINT] 既有进程扫荡已关闭（SetSweepEnabled(0)）");
            return;
        }
        TlsIntHost_SweepExisting(nullptr);
    });
    tlsint_host::Log(1, L"[TLSINT] 宿主已启动（注入器 + 环消费 + 既有进程扫荡）dll=%s", dllPath);
    return 0;
}

extern "C" TLSINT_HOST_API void __stdcall TlsIntHost_Stop(void)
{
    if (!g_running.load()) return;
    g_running = false;
    g_qcv.notify_all();
    if (g_sweepThread.joinable())    g_sweepThread.join();
    if (g_injectThread.joinable())   g_injectThread.join();
    if (g_consumerThread.joinable()) g_consumerThread.join();
    if (g_ring) { UnmapViewOfFile(g_ring); g_ring = nullptr; }
    if (g_ringMap) { CloseHandle(g_ringMap); g_ringMap = nullptr; }
    {
        std::lock_guard<std::mutex> lk(g_qm);
        g_queue.clear();
    }
    tlsint_host::Log(1, L"[TLSINT] 宿主已停止（注入 %llu / 扫荡入队 %llu / 跳过过滤 %llu / 注入失败 %llu / 消费明文 %llu / 告警 %llu）",
                     g_injected.load(), g_swept.load(), g_skipped.load(), g_injectFail.load(),
                     g_consumed.load(), g_alerts.load());
}

extern "C" TLSINT_HOST_API void __stdcall TlsIntHost_OnProcessCreate(unsigned long pid,
                                                                     const wchar_t* imagePath)
{
    if (!g_running.load()) return;
    wchar_t why[128] = { 0 };
    if (!TlsIntHost_IsEligible(pid, imagePath, why, _countof(why))) {
        ++g_skipped;
        return;                       // 过滤掉的连日志都不打，避免刷屏（计数可在 Stop 时看到）
    }
    {
        std::lock_guard<std::mutex> lk(g_qm);
        if (g_queue.size() >= kMaxQueue) {
            ++g_injectFail;
            return;                   // 队列满则丢弃（宁可漏注入，不要拖垮事件线程）
        }
        g_queue.push_back(InjectJob{ (DWORD)pid, std::wstring(imagePath ? imagePath : L""), false });
    }
    g_qcv.notify_one();
}

extern "C" TLSINT_HOST_API int __stdcall TlsIntHost_EnsureRing(void)
{
    return OpenRingOnce() ? 0 : (int)g_ringError.load();
}

// ── 启动时扫荡既有进程 ─────────────────────────────────────────────────────
// 为什么必须做：7006 只报"新建进程"。ZETA 启动前就存在的浏览器/IM/Office 永远不会被注入，
// 而它们是 DLP 的首要目标。实机实测：215 个有路径进程中 86 个合格，含 12×msedge、
// 13×msedgewebview2、9×QQ —— 全部落在 7006 永远看不到的那一侧。
extern "C" TLSINT_HOST_API int __stdcall TlsIntHost_SweepExisting(const wchar_t* nameSubstr)
{
    if (!g_running.load()) return -1;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        tlsint_host::Log(2, L"[TLSINT] 扫荡失败：CreateToolhelp32Snapshot err=%lu", GetLastError());
        return -2;
    }

    int scanned = 0, matched = 0, queued = 0, rejected = 0, dropped = 0, alive = 0, hv = 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            const DWORD pid = pe.th32ProcessID;
            if (pid == 0 || pid == 4) continue;
            ++scanned;
            if (nameSubstr && *nameSubstr && !wcsstr(pe.szExeFile, nameSubstr)) continue;
            ++matched;

            // 取完整镜像路径（拿不到就跳过：多半是受保护进程或已退出）
            std::wstring path;
            {
                HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (!h) { ++alive; continue; }
                wchar_t buf[MAX_PATH * 2]; DWORD cch = _countof(buf);
                if (QueryFullProcessImageNameW(h, 0, buf, &cch)) path = buf;
                CloseHandle(h);
            }
            if (path.empty()) { ++alive; continue; }

            wchar_t why[128] = { 0 };
            if (!TlsIntHost_IsEligible(pid, path.c_str(), why, _countof(why))) { ++rejected; continue; }

            // 既有进程已完全就绪 ⇒ fast（免退避）；高价值目标插队到队首
            std::wstring lower = path;
            for (auto& ch : lower) ch = (wchar_t)towlower(ch);
            const size_t slash = lower.find_last_of(L"\\/");
            const std::wstring name = (slash == std::wstring::npos) ? lower : lower.substr(slash + 1);
            const bool highValue = IsHighValueTarget(name);

            {
                std::lock_guard<std::mutex> lk(g_qm);
                if (g_queue.size() >= kMaxQueue) { ++dropped; continue; }
                InjectJob job{ pid, path, /*fast=*/true };
                if (highValue) { g_queue.push_front(job); ++hv; }
                else           { g_queue.push_back(job); }
            }
            g_qcv.notify_one();
            ++queued;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    g_swept += (unsigned long long)queued;
    tlsint_host::Log(1, L"[TLSINT] 扫荡既有进程: 扫描 %d / 名称匹配 %d / 入队 %d（其中高价值插队 %d）/ 过滤拒绝 %d / 已退出或打不开 %d / 队列满丢弃 %d",
                     scanned, matched, queued, hv, rejected, alive, dropped);
    return queued;
}

extern "C" TLSINT_HOST_API int __stdcall TlsIntHost_SetSweepEnabled(int enable)
{
    return g_sweepEnabled.exchange(enable ? 1 : 0);
}
extern "C" TLSINT_HOST_API int __stdcall TlsIntHost_GetSweepEnabled(void) { return g_sweepEnabled.load(); }
extern "C" TLSINT_HOST_API unsigned long long __stdcall TlsIntHost_GetSweptCount(void) { return g_swept.load(); }

extern "C" TLSINT_HOST_API void __stdcall TlsIntHost_SetLogFn(TlsIntLogFn fn)   { g_logFn = fn; }
extern "C" TLSINT_HOST_API void __stdcall TlsIntHost_SetAlertFn(TlsIntAlertFn fn) { g_alertFn = fn; }

extern "C" TLSINT_HOST_API unsigned long long __stdcall TlsIntHost_GetInjectedCount(void) { return g_injected.load(); }
extern "C" TLSINT_HOST_API unsigned long long __stdcall TlsIntHost_GetSkippedCount(void)  { return g_skipped.load(); }
extern "C" TLSINT_HOST_API unsigned long long __stdcall TlsIntHost_GetInjectFailCount(void) { return g_injectFail.load(); }
extern "C" TLSINT_HOST_API unsigned long long __stdcall TlsIntHost_GetConsumedCount(void) { return g_consumed.load(); }
extern "C" TLSINT_HOST_API unsigned long long __stdcall TlsIntHost_GetAlertCount(void)    { return g_alerts.load(); }
extern "C" TLSINT_HOST_API int __stdcall TlsIntHost_GetRingError(void) { return g_ringError.load(); }
