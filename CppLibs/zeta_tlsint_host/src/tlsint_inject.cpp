// zeta_tlsint 宿主侧注入器（M2-3）
//
// 流程：7006 进程创建 → IsEligible 过滤 → CreateRemoteThread(LoadLibraryW) → 回查模块表确认
//
// 两个刻意的设计决定：
//   1) 不用 MH_CreateHookApi 那类"远程调用导出函数"的花活：LoadLibraryW 是最稳的注入原语。
//   2) 成败判定**不依赖**线程退出码 —— x64 下 HMODULE 被 GetExitCodeThread 截断成 DWORD，
//      低位可能恰好为 0 而误判失败；改为注入后回查目标模块表里有没有我们的 DLL。
#include "tlsint_host.h"
#include "tlsint_host_internal.h"

#include <tlhelp32.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdio>
#include <cwchar>
#include <cwctype>

namespace {

const wchar_t* kInjectedDllName = L"ZETA_TlsInt.dll";

std::wstring ToLower(std::wstring s)
{
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return (wchar_t)towlower(c); });
    return s;
}

std::wstring BaseName(const std::wstring& p)
{
    const size_t k = p.find_last_of(L"\\/");
    return (k == std::wstring::npos) ? p : p.substr(k + 1);
}

// 驱动上报的是 **NT 形态路径**，不是 Win32 路径。实机（2026-10-05）观察到两种：
//   \??\D:\DevTools\git\cmd\git.exe
//   \SystemRoot\System32\Conhost.exe     <-- 只按 "\windows\system32\" 匹配会漏掉它
// 当时真的把 Conhost 注进去了。归一化之后"系统目录"判断才成立。
std::wstring NormalizeImagePath(std::wstring p)
{
    p = ToLower(p);
    if (p.rfind(L"\\??\\", 0) == 0) p = p.substr(4);
    // 注意：注释末尾绝不能留反斜杠 —— "//" 注释的行尾反斜杠会续行，把下一行代码吞掉（C4010）。
    const std::wstring kSysRoot = L"\\systemroot\\";   // 等价于 C:\Windows 前缀
    const size_t at = p.find(kSysRoot);
    if (at != std::wstring::npos) {
        p = p.substr(0, at) + L"c:\\windows\\" + p.substr(at + kSysRoot.size());
    }
    return p;
}

// 第三方安全产品：**不注入**。
// 理由：它们都有自保护，注入大概率被拒（白费），更糟的是可能把 ZETA 判成攻击者并反击；
// 而对 DLP 而言，安全产品自身的流量也不是监控目标。实机扫荡时发现候选里混着
// QQPCMgr/QQPCTray/QQPCRtp 这类，故显式排除。
bool IsSecurityProductName(const std::wstring& lowerName)
{
    static const wchar_t* kSec[] = {
        // 腾讯电脑管家
        L"qqpctray.exe", L"qqpcrtp.exe", L"qqpcmgr.exe", L"qqpcmgrservice.exe",
        // 360 全家
        L"360tray.exe", L"360safe.exe", L"360sd.exe", L"360rp.exe",
        L"360sdupd.exe", L"zhudongfangyu.exe",
        // 火绒 / 金山 / 其它
        L"hipstray.exe", L"wsctrl.exe", L"usysdiag.exe",
        L"kxetray.exe", L"kxecenter.exe", L"kxescore.exe",
        L"avp.exe", L"avastui.exe", L"avastsvc.exe", L"mcshield.exe",
        L"nortonsecurity.exe", L"ekrn.exe", L"egui.exe",
        L"mbam.exe", L"mbamservice.exe",
    };
    for (const wchar_t* c : kSec) if (lowerName == c) return true;
    return false;
}

bool IsProcessAlive(DWORD pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    DWORD ec = 0;
    const bool alive = GetExitCodeProcess(h, &ec) && ec == STILL_ACTIVE;
    CloseHandle(h);
    return alive;
}

// 关键系统进程名单。宁可少注入几个，也不要动这些：
// 注错 lsass/csrss 会直接蓝屏或让用户会话崩掉。
bool IsCriticalProcessName(const std::wstring& lowerName)
{
    static const wchar_t* kCrit[] = {
        L"system", L"registry", L"idle", L"memory compression",
        L"smss.exe", L"csrss.exe", L"wininit.exe", L"winlogon.exe",
        L"services.exe", L"lsass.exe", L"svchost.exe", L"dwm.exe",
        L"fontdrvhost.exe", L"lsaiso.exe", L"audiodg.exe", L"wudfhost.exe",
        L"spoolsv.exe", L"msmpeng.exe", L"nissrv.exe", L"securityhealthservice.exe",
        L"zeta.exe"                  // 自身（产品）
        // 注意：不要把宿主自测程序 ZETA_TlsInt_HostTest.exe 放进本名单 ——
        // 它同时充当"注入器"和"被注入的 victim"（同一个 exe 的两个进程），
        // 按名字拉黑会让 e2e 永不注入。自身保护由 TlsIntHost_IsEligible 里的
        // "pid == GetCurrentProcessId()" 负责，不需要靠名字。
    };
    for (const wchar_t* c : kCrit) if (lowerName == c) return true;
    return false;
}

// 系统目录里的镜像一律不注入（覆盖绝大多数核心组件与 KnownDLLs）
bool IsSystemImagePath(const std::wstring& lowerPath)
{
    static const wchar_t* kBanned[] = {
        L"\\windows\\system32\\", L"\\windows\\syswow64\\",
        L"\\windows\\winsxs\\",   L"\\windows\\servicing\\",
        L"\\windows\\systemapps\\"
    };
    for (const wchar_t* b : kBanned) if (lowerPath.find(b) != std::wstring::npos) return true;
    return false;
}

bool SnapshotModules(DWORD pid, std::vector<MODULEENTRY32W>& mods)
{
    mods.clear();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do { mods.push_back(me); } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return !mods.empty();
}

// 目标进程里是否已加载我们的 DLL —— 既做"已注入"判重，也做注入成败的权威判据
bool IsDllLoadedInTarget(DWORD pid)
{
    std::vector<MODULEENTRY32W> mods;
    if (!SnapshotModules(pid, mods)) return false;
    for (const auto& m : mods) {
        if (_wcsicmp(m.szModule, kInjectedDllName) == 0) return true;
    }
    return false;
}

bool RemoteLoadLibrary(DWORD pid, const std::wstring& dllPath, DWORD* lastErr, DWORD threadWaitMs)
{
    *lastErr = 0;
    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    if (!hProc) { *lastErr = GetLastError(); return false; }

    bool ok = false;
    void*  remoteMem = nullptr;
    HANDLE hThread   = nullptr;
    const SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);

    remoteMem = VirtualAllocEx(hProc, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) { *lastErr = GetLastError(); goto done; }
    if (!WriteProcessMemory(hProc, remoteMem, dllPath.c_str(), bytes, nullptr)) {
        *lastErr = GetLastError(); goto done;
    }
    {
        // LoadLibraryW 在本进程与目标进程的 VA 可能不同（ASLR），必须按"目标里 kernel32 的基址 +
        // 本进程里的函数偏移"折算，不能直接把本进程的函数指针丢过去。
        HMODULE k32Local = GetModuleHandleW(L"kernel32.dll");
        FARPROC llLocal  = GetProcAddress(k32Local, "LoadLibraryW");
        if (!k32Local || !llLocal) { *lastErr = ERROR_PROC_NOT_FOUND; goto done; }

        std::vector<MODULEENTRY32W> mods;
        if (!SnapshotModules(pid, mods)) { *lastErr = GetLastError(); goto done; }
        BYTE* k32Remote = nullptr;
        for (const auto& m : mods) {
            if (_wcsicmp(m.szModule, L"kernel32.dll") == 0) { k32Remote = m.modBaseAddr; break; }
        }
        if (!k32Remote) { *lastErr = ERROR_MOD_NOT_FOUND; goto done; }

        const ULONG_PTR offset = reinterpret_cast<ULONG_PTR>(llLocal) -
                                 reinterpret_cast<ULONG_PTR>(k32Local);
        auto remoteStart = reinterpret_cast<LPTHREAD_START_ROUTINE>(
                               reinterpret_cast<ULONG_PTR>(k32Remote) + offset);

        hThread = CreateRemoteThread(hProc, nullptr, 0, remoteStart, remoteMem, 0, nullptr);
        if (!hThread) { *lastErr = GetLastError(); goto done; }
        if (WaitForSingleObject(hThread, threadWaitMs) != WAIT_OBJECT_0) {
            *lastErr = ERROR_TIMEOUT; goto done;
        }
        ok = true;   // 线程已跑完；真正成败由调用方回查模块表判定
    }

done:
    if (hThread)   CloseHandle(hThread);
    if (remoteMem) VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return ok;
}

} // namespace

extern "C" TLSINT_HOST_API int __stdcall TlsIntHost_IsEligible(unsigned long pid,
                                                              const wchar_t* imagePath,
                                                              wchar_t* why, int whyCch)
{
    auto deny = [&](const wchar_t* r) -> int {
        if (why && whyCch > 0) ::_snwprintf_s(why, whyCch, _TRUNCATE, L"%s", r);
        return 0;
    };
    if (pid == 0 || pid == 4) return deny(L"system/idle 进程");
    if (pid == GetCurrentProcessId()) return deny(L"自身进程");
    if (!imagePath || !*imagePath) return deny(L"无镜像路径");

    const std::wstring normPath = NormalizeImagePath(imagePath);
    const std::wstring lowerName = ToLower(BaseName(imagePath));

    if (IsCriticalProcessName(lowerName)) return deny(L"关键系统进程（名单）");
    if (IsSecurityProductName(lowerName))  return deny(L"第三方安全产品（自保护，不注入）");
    if (IsSystemImagePath(normPath))      return deny(L"系统目录镜像");

    // 32 位目标：本 DLL 是 x64，注入必然失败（还可能留下垃圾内存）。
    // 注意：OpenProcess 失败**不能**判死 —— 7006 在进程刚创建时就触发，此刻打开失败
    // 常常只是"还没就绪"。放行给注入器去重试，由它在有退避的情况下做最终判断。
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        BOOL wow64 = FALSE;
        if (IsWow64Process(h, &wow64) && wow64) { CloseHandle(h); return deny(L"32 位（WOW64）目标"); }
        CloseHandle(h);
    }

    if (why && whyCch > 0) ::_snwprintf_s(why, whyCch, _TRUNCATE, L"允许");
    return 1;
}

// 注入重试节奏：7006 在目标"刚创建"时触发，此时它的地址空间/加载器往往还没就绪，
// WriteProcessMemory 会返回 ERROR_PARTIAL_COPY(299)。实机实测（2026-10-05）：
// git.exe 同一种目标 20 次失败 1 次成功、Conhost 22 次失败 2 次成功 —— 完全是时序问题，
// 不是目标不可注入。故退避重试；总窗口约 1.8s，兼顾"尽量成功"与"不拖垮工作线程"。
static const DWORD kRetryDelayMs[] = { 0, 30, 80, 200, 500, 1000 };

// 带预算的注入实现（供 7006 路径与扫荡路径共用）
static int InjectImpl(unsigned long pid, bool fast)
{
    const std::wstring& dll = tlsint_host::DllPath();
    if (dll.empty()) return -1;

    // 快速路径：既有进程已完全就绪，不需要退避；远程线程也只等 3s
    // （原来固定 10s，一旦撞上卡住的目标会让单线程队列停摆数十秒）。
    const DWORD threadWaitMs = fast ? 3000 : 4000;
    const int   attempts     = fast ? 1 : (int)_countof(kRetryDelayMs);

    DWORD lastErr = 0;
    for (int a = 0; a < attempts; ++a) {
        const DWORD delay = fast ? 0 : kRetryDelayMs[a];
        if (delay) Sleep(delay);
        if (IsDllLoadedInTarget(pid)) return 0;          // 已注入（幂等 / 上一轮其实成了）

        // 目标已退出就不必再试：这是正常现象（短命进程），不该记成注入故障
        if (!IsProcessAlive(pid)) return -3;

        DWORD err = 0;
        if (RemoteLoadLibrary(pid, dll, &err, threadWaitMs)) {
            // 权威判据：等目标把模块挂上（LoadLibrary 返回后模块表未必立即稳定）
            const int polls = fast ? 12 : 20;
            for (int i = 0; i < polls; ++i) {
                if (IsDllLoadedInTarget(pid)) return 0;
                Sleep(25);
            }
            lastErr = 0;                                 // 线程跑完但模块没出现
        } else {
            lastErr = err;
        }
    }
    return lastErr ? -(int)lastErr : -2;
}

namespace tlsint_host {
int InjectPidWithBudget(unsigned long pid, bool fast)
{
    return InjectImpl(pid, fast);
}
} // namespace tlsint_host

extern "C" TLSINT_HOST_API int __stdcall TlsIntHost_InjectPid(unsigned long pid)
{
    return InjectImpl(pid, /*fast=*/false);
}
