// zeta_tlsint_host 自测（M2-3）
//
// 目的：**不进 ZETA.exe、不加载内核驱动**的前提下，端到端证明"注入器 + 环消费 + 判定"这条链路。
//
//   victim <sec> <intervalMs> <token>   被注入的目标进程：只做 HTTPS，**自己从不加载 DLL**
//   e2e    <dllPath> [sec]              起 victim → 宿主注入它 → 消费环 → 断言拿到它的明文并命中规则
//   filter                              目标过滤判定单测
//   detect                              规则判定单测（合成样本）
//   ringsddl                            校验本模块创建的环 DACL 与 DLL 侧逐字一致
//
// 关键归因手法：victim 在每个请求里带一个随机 token 头。消费端看到含该 token 的明文且
// pid == victim pid ⇒ 证明这些明文**只能是**被注入的 victim 产生的，不是宿主自己的。
#include "tlsint_host.h"

#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <winhttp.h>
#include <tlhelp32.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <mutex>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")

// 与 tlsint_host.cpp / tlsint_hook.cpp 必须逐字一致
static const wchar_t* kExpectedRingSddl =
    L"O:BAD:(A;;CCDCLCSWRPSDRCWDWO;;;SY)(A;;CCDCLCSWRPSDRCWDWO;;;BA)(A;;CCDCLCRC;;;OW)(A;;CCDCLCRC;;;IU)";

static int g_fail = 0;
static void CHECK(const char* name, bool cond, const char* detail = "")
{
    printf("[%s] %s %s\n", cond ? "PASS" : "FAIL", name, detail);
    if (!cond) ++g_fail;
}

static bool IsProcessAliveLocal(DWORD pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    DWORD ec = 0;
    const bool alive = GetExitCodeProcess(h, &ec) && ec == STILL_ACTIVE;
    CloseHandle(h);
    return alive;
}

// ── 日志采集（e2e 断言用）──────────────────────────────────────────────────
static std::mutex        g_logMutex;
static std::vector<std::string> g_logLines;

static void __stdcall TestLogFn(int level, const wchar_t* msg)
{
    char buf[2048];
    buf[0] = 0;
    WideCharToMultiByte(CP_UTF8, 0, msg, -1, buf, sizeof(buf), nullptr, nullptr);
    printf("  [log/%d] %s\n", level, buf);
    std::lock_guard<std::mutex> lk(g_logMutex);
    g_logLines.push_back(buf);
}
static bool LogHas(const char* needle)
{
    std::lock_guard<std::mutex> lk(g_logMutex);
    for (const auto& s : g_logLines) if (s.find(needle) != std::string::npos) return true;
    return false;
}
static void __stdcall TestAlertFn(int sev, unsigned long pid, int ruleId,
                                  const wchar_t* rule, const wchar_t* detail)
{
    printf("  [ALERT] sev=%d pid=%lu rule=%d(%ws) %ws\n", sev, pid, ruleId, rule, detail);
}

// ── victim：只做 HTTPS，不加载 DLL ─────────────────────────────────────────
static bool HttpsRequest(const wchar_t* method, const wchar_t* path,
                         const wchar_t* headers, const char* body, DWORD bodyLen)
{
    bool ok = false;
    HINTERNET sess = WinHttpOpen(L"zeta_tlsint_hosttest/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!sess) return false;
    HINTERNET conn = WinHttpConnect(sess, L"www.example.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (conn) {
        HINTERNET req = WinHttpOpenRequest(conn, method, path, NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
        if (req) {
            if (headers) WinHttpAddRequestHeaders(req, headers, -1L, WINHTTP_ADDREQ_FLAG_ADD);
            if (WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   (LPVOID)body, bodyLen, bodyLen, 0)) {
                WinHttpReceiveResponse(req, NULL);
                BYTE buf[4096]; DWORD got = 0;
                while (WinHttpReadData(req, buf, sizeof(buf), &got) && got > 0) {}
                ok = true;
            }
            WinHttpCloseHandle(req);
        }
        WinHttpCloseHandle(conn);
    }
    WinHttpCloseHandle(sess);
    return ok;
}

static int VictimMain(int seconds, int intervalMs, const wchar_t* token)
{
    printf("[victim] pid=%lu token=%ws\n", GetCurrentProcessId(), token);
    fflush(stdout);

    std::wstring hdr = L"X-Zeta-TlsInt-Probe: ";
    hdr += token;

    const char* kPost1 =
        "id=110101199003077758&card=4111111111111111&password=Sup3rSecret";
    const char* kPost2 =
        "key=AKIAIOSFODNN7EXAMPLE&pem=-----BEGIN RSA PRIVATE KEY-----";

    const ULONGLONG deadline = GetTickCount64() + (ULONGLONG)seconds * 1000;
    int round = 0;
    while (GetTickCount64() < deadline) {
        HttpsRequest(L"GET", L"/", hdr.c_str(), nullptr, 0);
        if (round % 2 == 0) {
            HttpsRequest(L"POST", L"/", hdr.c_str(), kPost1, (DWORD)strlen(kPost1));
        } else {
            HttpsRequest(L"POST", L"/", hdr.c_str(), kPost2, (DWORD)strlen(kPost2));
        }
        printf("[victim] round %d done\n", round);
        fflush(stdout);
        ++round;
        Sleep(intervalMs);
    }
    printf("[victim] exit, rounds=%d\n", round);
    return 0;
}

// ── filter / detect / ringsddl ─────────────────────────────────────────────
static DWORD FindPidByName(const wchar_t* name, std::wstring* pathOut)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (pid && pathOut) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (h) {
            wchar_t buf[MAX_PATH]; DWORD cch = MAX_PATH;
            if (QueryFullProcessImageNameW(h, 0, buf, &cch)) *pathOut = buf;
            CloseHandle(h);
        }
    }
    return pid;
}

static int FilterMode()
{
    wchar_t why[128];
    struct Case { const wchar_t* desc; DWORD pid; const wchar_t* path; bool expect; };
    std::wstring explorerPath;
    DWORD explorerPid = FindPidByName(L"explorer.exe", &explorerPath);
    printf("[filter] explorer pid=%lu path=%ws\n", explorerPid, explorerPath.c_str());

    std::vector<Case> cases = {
        { L"pid=4 (System)",            4,            L"C:\\Windows\\System32\\ntoskrnl.exe", false },
        { L"pid=0",                     0,            L"C:\\x.exe",                           false },
        { L"self pid",                  GetCurrentProcessId(), L"C:\\Tools\\app.exe",         false },
        { L"system32 image",            explorerPid,  L"C:\\Windows\\System32\\notepad.exe",  false },
        { L"winsxs image",              explorerPid,  L"C:\\Windows\\WinSxS\\x\\y.exe",       false },
        { L"critical name lsass.exe",   explorerPid,  L"C:\\Tools\\lsass.exe",                false },
        { L"critical name csrss.exe",   explorerPid,  L"C:\\Tools\\csrss.exe",                false },
        { L"empty path",                explorerPid,  L"",                                    false },
        { L"normal app (explorer)",     explorerPid,  explorerPath.c_str(),                   true  },
        { L"normal app (fake path)",    explorerPid,  L"C:\\Tools\\myapp.exe",                true  },
        // ── 下面两例是 2026-10-05 实机暴露的真实缺陷的回归用例 ──
        // 驱动上报的是 NT 形态路径；当时只按 "\windows\system32\" 匹配，漏掉了 \SystemRoot\，
        // 结果真的把 Conhost 注了进去（Conhost.exe 不在关键名单里，只能靠路径拦）。
        { L"NT \\SystemRoot\\System32 (live bug)", explorerPid, L"\\SystemRoot\\System32\\Conhost.exe",      false },
        { L"NT \\??\\ prefix + System32",          explorerPid, L"\\??\\C:\\Windows\\System32\\notepad.exe", false },
    };
    for (const auto& c : cases) {
        const int r = TlsIntHost_IsEligible(c.pid, c.path, why, _countof(why));
        const bool got = (r == 1);
        char desc[256], whyA[512], buf[512];
        desc[0] = whyA[0] = 0;
        WideCharToMultiByte(CP_UTF8, 0, c.desc, -1, desc, sizeof(desc), nullptr, nullptr);
        // 原因串含中文：先转 UTF-8 再按 %s 打印，避免 printf("%ls") 在 GBK 控制台上
        // 转换失败而中途截断（会连换行一起吃掉，把后续断言输出挤到同一行）。
        WideCharToMultiByte(CP_UTF8, 0, why, -1, whyA, sizeof(whyA), nullptr, nullptr);
        printf("[filter] %-28s -> %-5s (%s)\n", desc, got ? "ALLOW" : "DENY", whyA);
        sprintf_s(buf, "%-28s -> %s", desc, got ? "ALLOW" : "DENY");
        CHECK("filter case", got == c.expect, buf);
    }
    return 0;
}

static int DetectMode()
{
    auto Run = [](const char* name, int dir, const char* data, int expectMin) {
        TlsIntFinding f[8];
        const int n = TlsIntDetect_Analyze(dir, (const unsigned char*)data,
                                           (unsigned long)strlen(data), f, 8);
        printf("[detect] %-22s dir=%s -> %d finding(s)\n", name, dir ? "OUT" : "IN", n);
        for (int i = 0; i < n; ++i)
            printf("           R%d %-24ws sev=%d %ws\n", f[i].ruleId, f[i].ruleName,
                   f[i].severity, f[i].detail);
        char buf[128]; sprintf_s(buf, "%s (expect>=%d)", name, expectMin);
        CHECK("detect", n >= expectMin, buf);
    };

    Run("plain GET", 1, "GET / HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n", 0);
    Run("private key", 1, "POST / HTTP/1.1\r\n\r\n-----BEGIN RSA PRIVATE KEY-----", 1);
    Run("auth header", 1, "GET / HTTP/1.1\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n", 1);
    Run("password field", 1, "POST / HTTP/1.1\r\n\r\nuser=a&password=Sup3rSecret", 1);
    Run("aws key", 1, "POST / HTTP/1.1\r\n\r\nkey=AKIAIOSFODNN7EXAMPLE", 1);
    Run("cn id 18", 1, "POST / HTTP/1.1\r\n\r\nid=110101199003077758", 1);
    Run("visa card", 1, "POST / HTTP/1.1\r\n\r\ncard=4111111111111111", 1);
    Run("ip literal host", 1, "GET / HTTP/1.1\r\nHost: 1.2.3.4:8080\r\n\r\n", 1);
    Run("curl ua", 1, "GET / HTTP/1.1\r\nUser-Agent: curl/8.0\r\n\r\n", 1);
    Run("hex hash no FP", 1, "POST / HTTP/1.1\r\n\r\nsha=9f2b4c6d8e0a1b3c5d7e9f0a1b2c3d4e", 0);

    // 大样本外传（POST + 32KB）
    {
        std::string big = "POST /up HTTP/1.1\r\n\r\n";
        big.append(40000, 'A');
        TlsIntFinding f[8];
        const int n = TlsIntDetect_Analyze(1, (const unsigned char*)big.data(),
                                           (unsigned long)big.size(), f, 8);
        bool has201 = false;
        for (int i = 0; i < n; ++i) if (f[i].ruleId == 201) has201 = true;
        printf("[detect] large outbound (40KB POST) -> %d finding(s), R201=%d\n", n, (int)has201);
        CHECK("detect large outbound R201", has201);
    }
    return 0;
}

static int RingSddlMode()
{
    const int rc = TlsIntHost_EnsureRing();
    printf("[ringsddl] TlsIntHost_EnsureRing rc=%d\n", rc);
    if (rc != 0) { CHECK("host EnsureRing", false, "ring not created"); return 1; }

    // 注意掩码：查 DACL 需要 READ_CONTROL —— FILE_MAP_READ(=SECTION_MAP_READ) **不含**它，
    // 用它去查 DACL 会 ACCESS_DENIED（正是 P0-1 那条教训的另一面）。
    HANDLE h = OpenFileMappingW(READ_CONTROL | FILE_MAP_READ, FALSE, L"ZETA_TlsInt_Ring");
    if (!h) {
        char e[128]; sprintf_s(e, "OpenFileMapping err=%lu", GetLastError());
        printf("[ringsddl] %s\n", e);
        CHECK("open ring for DACL", false, e);
        return 1;
    }

    PSECURITY_DESCRIPTOR sd = nullptr; PACL dacl = nullptr; PSID owner = nullptr;
    DWORD r = GetSecurityInfo(h, SE_KERNEL_OBJECT,
                              OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                              &owner, nullptr, &dacl, nullptr, &sd);
    if (r != ERROR_SUCCESS) {
        char e[128]; sprintf_s(e, "GetSecurityInfo err=%lu", r);
        printf("[ringsddl] %s\n", e);
        CloseHandle(h);
        CHECK("GetSecurityInfo(DACL)", false, e);
        return 1;
    }
    bool ok = false;
    {
        LPWSTR s = nullptr;
        if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd, SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &s, nullptr)) {
            char got[1024], exp[1024];
            WideCharToMultiByte(CP_ACP, 0, s, -1, got, sizeof(got), nullptr, nullptr);
            WideCharToMultiByte(CP_ACP, 0, kExpectedRingSddl, -1, exp, sizeof(exp), nullptr, nullptr);
            printf("[ringsddl] host  = %s\n", got);
            printf("[ringsddl] expect= %s\n", exp);
            ok = (strcmp(got, exp) == 0);
            LocalFree(s);
        } else {
            char e[128]; sprintf_s(e, "ConvertSDToString err=%lu", GetLastError());
            printf("[ringsddl] %s\n", e);
            CHECK("ConvertSDToString", false, e);
        }
    }
    LocalFree(sd);
    CloseHandle(h);
    CHECK("host-created ring SDDL == DLL SDDL (逐字)", ok);
    return 0;
}

// ── e2e ────────────────────────────────────────────────────────────────────
static int E2eMode(const wchar_t* dllPath, int victimSeconds)
{
    wchar_t self[MAX_PATH]; GetModuleFileNameW(nullptr, self, MAX_PATH);

    // 随机 token：只出现在 victim 的请求头里
    wchar_t token[64];
    ::_snwprintf_s(token, _countof(token), _TRUNCATE, L"ZTI-%08lX%08lX",
                   (unsigned long)GetTickCount(), (unsigned long)GetCurrentProcessId());
    char tokenA[64]; WideCharToMultiByte(CP_ACP, 0, token, -1, tokenA, sizeof(tokenA), nullptr, nullptr);

    wchar_t cmd[1024];
    ::_snwprintf_s(cmd, _countof(cmd), _TRUNCATE, L"\"%s\" victim %d 1500 %s",
                   self, victimSeconds, token);

    printf("=== e2e: dll=%ws victim=%d s token=%ws ===\n", dllPath, victimSeconds, token);
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
        printf("[e2e] CreateProcess victim failed err=%lu\n", GetLastError());
        CHECK("spawn victim", false); return 1;
    }
    const DWORD victimPid = pi.dwProcessId;
    printf("[e2e] victim pid=%lu\n", victimPid);

    TlsIntHost_SetLogFn(TestLogFn);
    TlsIntHost_SetAlertFn(TestAlertFn);
    const int src = TlsIntHost_Start(dllPath);
    CHECK("TlsIntHost_Start", src == 0, dllPath ? "" : "no dll path");

    Sleep(600);   // 等 victim 起来（模块表就绪）

    // 模拟 7006 回调
    std::wstring victimPath = self;   // 同目录，非系统目录
    TlsIntHost_OnProcessCreate(victimPid, victimPath.c_str());

    // 等 victim 跑完
    WaitForSingleObject(pi.hProcess, (DWORD)(victimSeconds + 20) * 1000);
    Sleep(1500);   // 等消费线程把最后几条吃掉

    const unsigned long long inj = TlsIntHost_GetInjectedCount();
    const unsigned long long con = TlsIntHost_GetConsumedCount();
    const unsigned long long alr = TlsIntHost_GetAlertCount();
    printf("[e2e] injected=%llu consumed=%llu alerts=%llu ringError=%d\n",
           inj, con, alr, TlsIntHost_GetRingError());

    TlsIntHost_Stop();

    char buf[256];
    sprintf_s(buf, "injected=%llu", inj);
    CHECK("e2e 注入成功 (injected>=1)", inj >= 1, buf);
    sprintf_s(buf, "consumed=%llu", con);
    CHECK("e2e 消费到明文 (consumed>=2)", con >= 2, buf);

    char needle[128];
    sprintf_s(needle, "pid=%lu", victimPid);
    CHECK("e2e 明文来自 victim pid（注入归因）", LogHas(needle), needle);
    CHECK("e2e victim 的 probe token 出现在截获明文里", LogHas(tokenA), tokenA);
    CHECK("e2e 规则命中（私钥/口令/PII/云凭证任一）",
          LogHas("SECRET_PRIVATE_KEY") || LogHas("CRED_PASSWORD_FIELD") ||
          LogHas("PII_CN_ID") || LogHas("PII_BANK_CARD") || LogHas("CLOUD_KEY"));
    sprintf_s(buf, "alerts=%llu", alr);
    CHECK("e2e 产生告警 (alerts>=1)", alr >= 1, buf);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

// ── sweep：证明"启动前就已存在"的进程也能被覆盖（补 7006 盲区）──────────────
// 与 e2e 的关键差别：victim 在 TlsIntHost_Start **之前**就已启动，且**不**调用
// OnProcessCreate —— 即完全模拟"ZETA 启动前就开着的浏览器"。修复前这种目标永不被注入。
static int SweepMode(const wchar_t* dllPath, int victimSeconds)
{
    wchar_t self[MAX_PATH]; GetModuleFileNameW(nullptr, self, MAX_PATH);

    wchar_t token[64];
    ::_snwprintf_s(token, _countof(token), _TRUNCATE, L"SWP-%08lX%08lX",
                   (unsigned long)GetTickCount(), (unsigned long)GetCurrentProcessId());
    char tokenA[64]; WideCharToMultiByte(CP_ACP, 0, token, -1, tokenA, sizeof(tokenA), nullptr, nullptr);

    // 1) 先起 victim（此即"既有进程"）
    wchar_t cmd[1024];
    ::_snwprintf_s(cmd, _countof(cmd), _TRUNCATE, L"\"%s\" victim %d 1500 %s",
                   self, victimSeconds, token);
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
        printf("[sweep] CreateProcess victim failed err=%lu\n", GetLastError());
        CHECK("sweep spawn victim", false); return 1;
    }
    const DWORD victimPid = pi.dwProcessId;
    printf("=== sweep: victim(既有进程) pid=%lu token=%ws ===\n", victimPid, token);
    Sleep(1200);                       // 让它确实是"先于宿主存在"
    CHECK("sweep 前置条件：victim 在宿主启动前已在运行", IsProcessAliveLocal(victimPid));

    // 2) 起宿主，但关掉自动扫荡，改为**外科式**只扫本测试 exe（避免污染全机进程）
    TlsIntHost_SetLogFn(TestLogFn);
    TlsIntHost_SetAlertFn(TestAlertFn);
    CHECK("sweep TlsIntHost_Start", TlsIntHost_Start(dllPath) == 0);
    TlsIntHost_SetSweepEnabled(0);
    Sleep(400);

    // 关键：**不**调用 OnProcessCreate —— 唯一能让 victim 被注入的路径就是扫荡
    const int queued = TlsIntHost_SweepExisting(L"ZETA_TlsInt_HostTest.exe");
    printf("[sweep] SweepExisting 入队=%d\n", queued);
    char buf[256];
    sprintf_s(buf, "queued=%d", queued);
    CHECK("sweep 扫荡把既有进程纳入候选 (queued>=1)", queued >= 1, buf);

    WaitForSingleObject(pi.hProcess, (DWORD)(victimSeconds + 20) * 1000);
    Sleep(1500);

    const unsigned long long inj = TlsIntHost_GetInjectedCount();
    const unsigned long long con = TlsIntHost_GetConsumedCount();
    const unsigned long long alr = TlsIntHost_GetAlertCount();
    printf("[sweep] injected=%llu consumed=%llu alerts=%llu swept=%llu\n",
           inj, con, alr, TlsIntHost_GetSweptCount());
    TlsIntHost_Stop();

    sprintf_s(buf, "injected=%llu", inj);
    CHECK("sweep 既有进程被注入 (injected>=1)", inj >= 1, buf);
    sprintf_s(buf, "consumed=%llu", con);
    CHECK("sweep 既有进程的明文被消费 (consumed>=2)", con >= 2, buf);
    sprintf_s(buf, "pid=%lu", victimPid);
    CHECK("sweep 明文归因到既有 victim pid", LogHas(buf), buf);
    CHECK("sweep 既有 victim 的 token 出现在截获明文里", LogHas(tokenA), tokenA);
    sprintf_s(buf, "alerts=%llu", alr);
    CHECK("sweep 规则命中并告警 (alerts>=1)", alr >= 1, buf);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2) {
        printf("usage:\n  tlsint_host_test e2e <dllPath> [victimSec]\n"
               "  tlsint_host_test sweep <dllPath> [victimSec]\n"
               "  tlsint_host_test victim <sec> <intervalMs> <token>\n"
               "  tlsint_host_test filter\n  tlsint_host_test detect\n  tlsint_host_test ringsddl\n");
        return 64;
    }
    if (_wcsicmp(argv[1], L"victim") == 0) {
        if (argc < 5) return 64;
        return VictimMain(_wtoi(argv[2]), _wtoi(argv[3]), argv[4]);
    }
    if (_wcsicmp(argv[1], L"filter") == 0)   return FilterMode();
    if (_wcsicmp(argv[1], L"detect") == 0)   return DetectMode();
    if (_wcsicmp(argv[1], L"ringsddl") == 0) return RingSddlMode();
    if (_wcsicmp(argv[1], L"e2e") == 0) {
        if (argc < 3) return 64;
        return E2eMode(argv[2], (argc >= 4) ? _wtoi(argv[3]) : 8);
    }
    if (_wcsicmp(argv[1], L"sweep") == 0) {
        if (argc < 3) return 64;
        return SweepMode(argv[2], (argc >= 4) ? _wtoi(argv[3]) : 8);
    }
    // inject <dllPath> <pid> —— 手工注入指定 pid（跳过过滤）。
    // 用途: 作为**独立于 ZETA 时序**的注入器，验证驱动的跨进程线程事件是否把
    //       "真正的用户态 CreateRemoteThread" 归因到真实注入者（而不是 pid 4 / 目标自身）。
    if (_wcsicmp(argv[1], L"inject") == 0) {
        if (argc < 4) return 64;
        const DWORD pid = (DWORD)_wtoi(argv[3]);
        printf("[inject] 自身 pid=%lu  目标 pid=%lu  dll=%ws\n",
               GetCurrentProcessId(), pid, argv[2]);
        fflush(stdout);
        if (TlsIntHost_Start(argv[2]) != 0) { printf("[inject] Start 失败\n"); return 1; }
        TlsIntHost_SetSweepEnabled(0);            // 只对指定 pid 动手，不做全机扫荡
        Sleep(300);
        const int rc = TlsIntHost_InjectPid(pid);
        printf("[inject] InjectPid(%lu) rc=%d %s\n", pid, rc, rc == 0 ? "(成功)" : "(失败)");
        Sleep(1500);
        printf("[inject] injected=%llu\n", TlsIntHost_GetInjectedCount());
        TlsIntHost_Stop();
        return rc == 0 ? 0 : 1;
    }
    printf("unknown mode\n");
    return 64;
}
