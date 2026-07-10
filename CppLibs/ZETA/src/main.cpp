#define _WIN32_WINNT 0x0601
#define WINVER 0x0601
#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <atomic>
#include <future>
#include <queue>
#include <condition_variable>
#include <functional>

// zeta_ui.dll header - use dllimport since we're calling it, not defining it
#define ZETA_API __declspec(dllimport)
#include "zeta_ui_export.h"
#undef ZETA_API

// C++ DLL headers - for reference types (actual calls via LoadLibrary)
#include <zeta_core.h>
#include <zeta_driver.h>
#include <zeta_engine.h>
#include <zeta_monitor.h>
#include <zeta_hips.h>
#include "behavior_engine.h"
#include "verdict.h"

// ============================================================
// Global paths (dynamic, not hardcoded)
// ============================================================
static std::wstring g_exeDir;       // EXE 所在目录 (如 D:\ZETA)
static std::wstring g_pluginsDir;   // Plugins 目录
static std::wstring g_rulesDir;     // Rules 目录
static std::wstring g_logsDir;      // Logs 目录
static std::wstring g_configDir;    // Config 目录 (C:\ProgramData\ZETA)

// ============================================================
// Global state
// ============================================================
static bool g_running = true;
static std::wstring g_driverInitLog; // Cached driver init log (fetched before message loop starts)

// ============================================================
// Crash handler - catches unhandled exceptions and writes crash log
// ============================================================
static LONG WINAPI crashHandler(EXCEPTION_POINTERS* ep) {
    std::wstring crashPath = g_logsDir + L"\\ZETA_CRASH.log";
    HANDLE hCrash = CreateFileW(crashPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hCrash != INVALID_HANDLE_VALUE) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char buf[4096];
        int n = sprintf_s(buf,
            "ZETA CRASH REPORT\n"
            "==================\n"
            "Time: %04d-%02d-%02d %02d:%02d:%02d.%03d\n"
            "Exception code: 0x%08X\n"
            "Exception address: 0x%p\n"
            "Exception flags: 0x%08X\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            ep->ExceptionRecord->ExceptionCode,
            ep->ExceptionRecord->ExceptionAddress,
            ep->ExceptionRecord->ExceptionFlags);

        if (ep->ExceptionRecord->NumberParameters > 0) {
            n += sprintf_s(buf + n, sizeof(buf) - n, "Parameters: ");
            for (ULONG i = 0; i < ep->ExceptionRecord->NumberParameters && i < 15; i++) {
                n += sprintf_s(buf + n, sizeof(buf) - n, "0x%p ",
                    (void*)ep->ExceptionRecord->ExceptionInformation[i]);
            }
            n += sprintf_s(buf + n, sizeof(buf) - n, "\n");
        }

        if (ep->ContextRecord) {
#ifdef _M_AMD64
            n += sprintf_s(buf + n, sizeof(buf) - n,
                "RAX=0x%p RBX=0x%p RCX=0x%p RDX=0x%p\n"
                "RSI=0x%p RDI=0x%p RBP=0x%p RSP=0x%p\n"
                "R8=0x%p R9=0x%p R10=0x%p R11=0x%p\n"
                "R12=0x%p R13=0x%p R14=0x%p R15=0x%p\n"
                "RIP=0x%p EFLAGS=0x%08X\n",
                (void*)ep->ContextRecord->Rax, (void*)ep->ContextRecord->Rbx,
                (void*)ep->ContextRecord->Rcx, (void*)ep->ContextRecord->Rdx,
                (void*)ep->ContextRecord->Rsi, (void*)ep->ContextRecord->Rdi,
                (void*)ep->ContextRecord->Rbp, (void*)ep->ContextRecord->Rsp,
                (void*)ep->ContextRecord->R8, (void*)ep->ContextRecord->R9,
                (void*)ep->ContextRecord->R10, (void*)ep->ContextRecord->R11,
                (void*)ep->ContextRecord->R12, (void*)ep->ContextRecord->R13,
                (void*)ep->ContextRecord->R14, (void*)ep->ContextRecord->R15,
                (void*)ep->ContextRecord->Rip, ep->ContextRecord->EFlags);
#else
            n += sprintf_s(buf + n, sizeof(buf) - n,
                "EAX=0x%p EBX=0x%p ECX=0x%p EDX=0x%p\n"
                "ESI=0x%p EDI=0x%p EBP=0x%p ESP=0x%p\n"
                "EIP=0x%p EFLAGS=0x%08X\n",
                (void*)ep->ContextRecord->Eax, (void*)ep->ContextRecord->Ebx,
                (void*)ep->ContextRecord->Ecx, (void*)ep->ContextRecord->Edx,
                (void*)ep->ContextRecord->Esi, (void*)ep->ContextRecord->Edi,
                (void*)ep->ContextRecord->Ebp, (void*)ep->ContextRecord->Esp,
                (void*)ep->ContextRecord->Eip, ep->ContextRecord->EFlags);
#endif
        }
        n += sprintf_s(buf + n, sizeof(buf) - n,
            "==================\n"
            "END CRASH REPORT\n");

        DWORD written;
        WriteFile(hCrash, buf, (DWORD)n, &written, NULL);
        CloseHandle(hCrash);
        printf("%s", buf);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void setupCrashHandler() {
    SetUnhandledExceptionFilter(crashHandler);
    _set_purecall_handler([]() {
        MessageBoxA(NULL, "Pure virtual function call - crash detected", "ZETA", MB_ICONERROR);
    });
}

// ============================================================
// Console control handler - captures Ctrl+C, close, logoff, etc.
// ============================================================
static BOOL WINAPI consoleHandler(DWORD dwCtrlType) {
    FILE* f = nullptr;
    _wfopen_s(&f, (g_logsDir + L"\\ZETA_TERMINATE.log").c_str(), L"a");
    if (f) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d.%03d] Console event: %lu\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            dwCtrlType);
        fprintf(f, "  CTRL_C=0, CTRL_BREAK=1, CTRL_CLOSE=2, CTRL_LOGOFF=5, CTRL_SHUTDOWN=6\n");
        fclose(f);
    }
    // Log to app log as well
    const wchar_t* reason = L"unknown";
    switch (dwCtrlType) {
        case CTRL_C_EVENT:        reason = L"CTRL+C"; break;
        case CTRL_BREAK_EVENT:    reason = L"CTRL+BREAK"; break;
        case CTRL_CLOSE_EVENT:    reason = L"Window closed / taskkill"; break;
        case CTRL_LOGOFF_EVENT:   reason = L"User logoff"; break;
        case CTRL_SHUTDOWN_EVENT: reason = L"System shutdown"; break;
    }
    printf("[ZETA] Termination signal received: %ws\n", reason);
    return FALSE; // Let other handlers process too
}

static std::thread g_repairThread;

// ── NT device path → DOS drive path conversion ──
static std::wstring ntToDosPath(const std::wstring& ntPath) {
    // Build drive mapping
    WCHAR drives[256] = {0};
    DWORD len = GetLogicalDriveStringsW(256, drives);
    if (!len || len >= 256) return ntPath;

    // Try common mapping first (fast path)
    static struct { WCHAR drive[4]; WCHAR ntPrefix[64]; } s_cache[26];
    static int s_cacheCount = -1;

    if (s_cacheCount < 0) {
        s_cacheCount = 0;
        for (WCHAR* p = drives; *p; p += 4) {
            WCHAR target[128] = {0};
            p[2] = L'\0';  // "C:\" → "C:"
            if (QueryDosDeviceW(p, target, 128)) {
                wcsncpy_s(s_cache[s_cacheCount].drive, p, 3);
                wcsncpy_s(s_cache[s_cacheCount].ntPrefix, target, 63);
                s_cacheCount++;
            }
            p[2] = L'\\';
        }
    }

    // Build full map and try matching (in case drives changed)
    for (int i = 0; i < s_cacheCount; i++) {
        size_t prefixLen = wcslen(s_cache[i].ntPrefix);
        if (_wcsnicmp(ntPath.c_str(), s_cache[i].ntPrefix, prefixLen) == 0) {
            std::wstring result = s_cache[i].drive;
            result += &ntPath[prefixLen];
            return result;
        }
    }

    // Fallback: scan all drives fresh
    for (WCHAR* p = drives; *p; p += 4) {
        WCHAR target[128] = {0};
        p[2] = L'\0';
        if (QueryDosDeviceW(p, target, 128)) {
            size_t prefixLen = wcslen(target);
            if (_wcsnicmp(ntPath.c_str(), target, prefixLen) == 0) {
                p[2] = L'\\';
                std::wstring result = p;
                result += &ntPath[prefixLen];
                return result;
            }
        }
        p[2] = L'\\';
    }

    return ntPath;  // Fallback: return original
}

static std::wstring getProcessPath(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return L"";

    WCHAR path[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    if (!QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        CloseHandle(hProcess);
        return L"";
    }

    CloseHandle(hProcess);
    return std::wstring(path);
}

// Forward declaration (defined later, after zeta_core.dll is loaded)
static void appLog(const wchar_t* level, const wchar_t* action, const wchar_t* detail);

// ============================================================
// SafeTerminateProcess — avoid BSOD from critical processes
//
// Problem: malicious software may call RtlSetProcessIsCritical()
// to mark itself as a critical system process. Direct
// TerminateProcess on such a process triggers
// CRITICAL_PROCESS_DIED (0xEF) bluescreen.
//
// Strategy (layered):
//   1. Query ProcessBreakOnTermination flag
//   2. If NOT critical → TerminateProcess (safe, fast)
//   3. If IS critical  → CreateRemoteThread(ExitProcess)
//      Self-termination via ExitProcess → NtTerminateProcess(NULL,0)
//      bypasses the kernel's BreakOnTermination BSOD check.
//      kernel32!ExitProcess has the same VA in all processes
//      thanks to per-boot ASLR, so CreateRemoteThread just works.
// ============================================================

// Process information class for BreakOnTermination
#ifndef ProcessBreakOnTermination
#define ProcessBreakOnTermination 29
#endif

typedef LONG NTSTATUS;

typedef NTSTATUS (NTAPI *fnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,  // PROCESSINFOCLASS
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

static bool SafeTerminateProcess(DWORD pid) {
    // Open with all necessary rights for both paths
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_TERMINATE |
        PROCESS_SUSPEND_RESUME,
        FALSE, pid);
    if (!hProcess) {
        // Fallback: try minimal rights for direct terminate
        hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!hProcess) return false;
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        return true;
    }

    // Step 1: Query BreakOnTermination flag
    BOOL isCritical = FALSE;
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        auto pNtQueryInfo = (fnNtQueryInformationProcess)
            GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (pNtQueryInfo) {
            pNtQueryInfo(hProcess, ProcessBreakOnTermination,
                         &isCritical, sizeof(isCritical), NULL);
        }
    }

    if (!isCritical) {
        // Step 2a: Non-critical — direct terminate, no BSOD risk
        BOOL ok = TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        return ok;
    }

    // Step 2b: Critical process — use ExitProcess self-termination
    appLog(L"WARN", L"SafeTerm", (L"PID=" + std::to_wstring(pid) +
        L" is critical — using ExitProcess self-termination to avoid BSOD").c_str());

    // kernel32!ExitProcess is at the same VA in all processes (per-boot ASLR)
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        CloseHandle(hProcess);
        return false;
    }

    LPTHREAD_START_ROUTINE pExitProcess = (LPTHREAD_START_ROUTINE)
        GetProcAddress(hKernel32, "ExitProcess");
    if (!pExitProcess) {
        CloseHandle(hProcess);
        return false;
    }

    // CreateRemoteThread calls ExitProcess(0) in the target process.
    // ExitProcess → RtlExitUserProcess → NtTerminateProcess(NtCurrentProcess(),0)
    // Self-termination (NULL handle) bypasses the kernel's BreakOnTermination
    // check that triggers CRITICAL_PROCESS_DIED bugcheck.
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        pExitProcess, (LPVOID)0, 0, NULL);
    CloseHandle(hProcess);

    if (hThread) {
        // Wait for the remote thread (and process) to exit
        WaitForSingleObject(hThread, 10000);
        CloseHandle(hThread);
        return true;
    }

    // CreateRemoteThread may fail if the process is already dying or
    // has no threads. In that case, the process is likely already
    // terminating on its own, which is acceptable.
    return false;
}

// ── Driver message throttle ──
// Prevents Qt event loop flooding by limiting notifications per (code, pid) pair
#define THROTTLE_WINDOW_MS 3000
#define THROTTLE_MAX_ENTRIES 64
static struct {
    unsigned long code;
    unsigned long pid;
    unsigned long long lastTimeMs;
} g_throttleEntries[THROTTLE_MAX_ENTRIES];
static int g_throttleCount = 0;
static std::mutex g_throttleMutex;

static bool isThrottled(unsigned long code, unsigned long pid) {
    unsigned long long now = GetTickCount64();
    std::lock_guard<std::mutex> lock(g_throttleMutex);
    for (int i = 0; i < g_throttleCount; i++) {
        if (g_throttleEntries[i].code == code && g_throttleEntries[i].pid == pid) {
            if (now - g_throttleEntries[i].lastTimeMs < THROTTLE_WINDOW_MS) {
                return true;  // throttled: skip notification
            }
            g_throttleEntries[i].lastTimeMs = now;
            return false;
        }
    }
    // New entry
    if (g_throttleCount < THROTTLE_MAX_ENTRIES) {
        g_throttleEntries[g_throttleCount].code = code;
        g_throttleEntries[g_throttleCount].pid = pid;
        g_throttleEntries[g_throttleCount].lastTimeMs = now;
        g_throttleCount++;
    }
    return false;
}

// ============================================================
// Async task queue (for background operations)
// ============================================================
static std::queue<std::function<void()>> g_taskQueue;
static std::mutex g_taskMutex;
static std::condition_variable g_taskCv;
static std::thread g_taskThread;

// ============================================================
// DLL function typedefs
// ============================================================

// ZETA_Core.dll
typedef void (*fn_zeta_core_init)(const wchar_t*);
typedef void (*fn_zeta_core_log)(const wchar_t*, const wchar_t*, const wchar_t*, const wchar_t*);
typedef int  (*fn_zeta_core_config_load)(const wchar_t*);
typedef int  (*fn_zeta_core_config_get_bool)(const wchar_t*, int);
typedef void (*fn_zeta_core_config_set_bool)(const wchar_t*, int);
typedef int  (*fn_zeta_core_config_save)();

// ZETA_Engine.dll
typedef int (*fn_zeta_engine_init)(const wchar_t*);
typedef void* (*fn_zeta_engine_create)();
typedef void  (*fn_zeta_engine_destroy)(void*);
typedef int   (*fn_zeta_engine_scan_file)(void*, const wchar_t*, wchar_t*, int);
typedef void  (*fn_zeta_engine_set_callback)(void*, void*);
typedef int   (*fn_zeta_engine_check_signature)(const wchar_t*);

// ZETA_Driver.dll
typedef int  (*fn_zeta_driver_connect)(const wchar_t*);
typedef void (*fn_zeta_driver_disconnect)();
typedef int  (*fn_zeta_driver_is_connected)();
typedef void (*fn_zeta_driver_set_msg_callback)(void*);
typedef void (*fn_zeta_driver_start_loop)();
typedef void (*fn_zeta_driver_stop_loop)();
typedef int  (*fn_zeta_driver_send_cmd)(unsigned long, const wchar_t*);
typedef const wchar_t* (*fn_zeta_driver_get_init_log)();
typedef int  (*fn_zeta_hips_load_rules)();
typedef void (*fn_zeta_hips_reload_rules)();
typedef int  (*fn_zeta_hips_add_rule)(const wchar_t*, const wchar_t*, int, int);
typedef int  (*fn_zeta_hips_remove_rule)(const wchar_t*);
typedef void (*fn_zeta_hips_set_rules_path)(const wchar_t*);

// ZETA_Monitor.dll
typedef void (*fn_zeta_monitor_start_process_monitor)();
typedef void (*fn_zeta_monitor_stop_process_monitor)();
typedef void (*fn_zeta_monitor_set_new_process_callback)(
    void(*cb)(unsigned long pid, unsigned long ppid, const wchar_t* name, const wchar_t* path));
typedef void (*fn_zeta_monitor_lineage_enable)();
typedef int  (*fn_zeta_monitor_system_repair_exec)();

// ZETA_Hips.dll
typedef void (*fn_zeta_hips_popup_add_rule)(const wchar_t*);
typedef int (*fn_zeta_hips_silverfox_analyze)(const wchar_t* const* files, int count,
    wchar_t* outType, int typeSize, wchar_t* outDetail, int detailSize);

// (TrafficAnalyzer removed)

// zeta_ui.dll
typedef void (*fn_zeta_ui_set_driver_status)(int);
typedef void (*fn_zeta_ui_show_notification)(const wchar_t*, const wchar_t*, int);
typedef void (*fn_zeta_ui_set_hips_response_callback)(void (*cb)(unsigned long, int));
typedef void (*fn_zeta_ui_show_hips_prompt)(const wchar_t*, const wchar_t*, unsigned long, int);

// ============================================================
// Loaded DLL handles
// ============================================================
static HMODULE g_hCore = nullptr;
static HMODULE g_hEngine = nullptr;
static HMODULE g_hDriver = nullptr;
static HMODULE g_hMonitor = nullptr;
static HMODULE g_hHips = nullptr;

// ============================================================
// DLL function pointers
// ============================================================
static fn_zeta_core_log           p_zeta_core_log = nullptr;
static fn_zeta_core_config_load   p_zeta_core_config_load = nullptr;
static fn_zeta_core_config_get_bool p_zeta_core_config_get_bool = nullptr;
static fn_zeta_core_config_set_bool p_zeta_core_config_set_bool = nullptr;
static fn_zeta_core_config_save    p_zeta_core_config_save = nullptr;
static fn_zeta_engine_init         p_zeta_engine_init = nullptr;
static fn_zeta_engine_create       p_zeta_engine_create = nullptr;
static fn_zeta_engine_destroy      p_zeta_engine_destroy = nullptr;
static fn_zeta_engine_scan_file    p_zeta_engine_scan_file = nullptr;
static fn_zeta_engine_check_signature p_zeta_engine_check_signature = nullptr;
static fn_zeta_driver_connect         p_zeta_driver_connect = nullptr;
static fn_zeta_driver_disconnect      p_zeta_driver_disconnect = nullptr;
static fn_zeta_driver_is_connected    p_zeta_driver_is_connected = nullptr;
static fn_zeta_driver_set_msg_callback p_zeta_driver_set_msg_callback = nullptr;
static fn_zeta_driver_start_loop      p_zeta_driver_start_loop = nullptr;
static fn_zeta_driver_stop_loop       p_zeta_driver_stop_loop = nullptr;
static fn_zeta_driver_send_cmd        p_zeta_driver_send_cmd = nullptr;
static fn_zeta_driver_get_init_log   p_zeta_driver_get_init_log = nullptr;
static fn_zeta_hips_load_rules        p_zeta_hips_load_rules = nullptr;
static fn_zeta_hips_reload_rules      p_zeta_hips_reload_rules = nullptr;
static fn_zeta_hips_add_rule          p_zeta_hips_add_rule = nullptr;
static fn_zeta_hips_set_rules_path    p_zeta_hips_set_rules_path = nullptr;
static fn_zeta_monitor_start_process_monitor p_zeta_monitor_start_process_monitor = nullptr;
static fn_zeta_monitor_stop_process_monitor  p_zeta_monitor_stop_process_monitor = nullptr;
static fn_zeta_monitor_set_new_process_callback p_zeta_monitor_set_new_process_callback = nullptr;
static fn_zeta_monitor_lineage_enable        p_zeta_monitor_lineage_enable = nullptr;
static fn_zeta_monitor_system_repair_exec    p_zeta_monitor_system_repair_exec = nullptr;
static fn_zeta_hips_popup_add_rule       p_zeta_hips_popup_add_rule = nullptr;
static fn_zeta_hips_silverfox_analyze    p_zeta_hips_silverfox_analyze = nullptr;

// (TrafficAnalyzer function pointers removed)
static fn_zeta_ui_set_driver_status p_zeta_ui_set_driver_status = nullptr;
static fn_zeta_ui_show_notification p_zeta_ui_show_notification = nullptr;
static fn_zeta_ui_set_hips_response_callback p_zeta_ui_set_hips_response_callback = nullptr;
static fn_zeta_ui_show_hips_prompt p_zeta_ui_show_hips_prompt = nullptr;

// ============================================================
// Initialize paths dynamically
// ============================================================
static void initPaths() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    // EXE 目录 (去掉文件名)
    g_exeDir = exePath;
    size_t pos = g_exeDir.find_last_of(L'\\');
    if (pos != std::wstring::npos) {
        g_exeDir = g_exeDir.substr(0, pos);
    }

    // Plugins 目录
    g_pluginsDir = g_exeDir + L"\\Plugins";

    // Rules 目录
    g_rulesDir = g_exeDir + L"\\Engine\\Heuristic";

    // Logs 目录 (使用 exe 所在目录)
    g_logsDir = g_exeDir;

    // Config 目录 (使用 ProgramData)
    wchar_t programData[MAX_PATH];
    GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);
    g_configDir = std::wstring(programData) + L"\\ZETA";

    // 创建目录（如果不存在）
    CreateDirectoryW(g_logsDir.c_str(), nullptr);
    CreateDirectoryW(g_configDir.c_str(), nullptr);

    // Initialize VerdictWriter (creates Verdicts\ subdirectory)
    VerdictWriter::init(g_configDir);

    printf("[ZETA] Paths initialized: exe=%S, plugins=%S, config=%S\n",
           g_exeDir.c_str(), g_pluginsDir.c_str(), g_configDir.c_str());
}

// ============================================================
// Helper: Load DLL and get proc address
// ============================================================
template<typename T>
bool loadDll(const wchar_t* dllName, HMODULE& handle, const char* funcName, T& funcPtr) {
    wchar_t fullPath[MAX_PATH];
    wsprintfW(fullPath, L"%s\\%s", g_exeDir.c_str(), dllName);
    handle = LoadLibraryW(fullPath);
    if (!handle) {
        printf("[ZETA] Failed to load %S (error=%lu)\n", dllName, GetLastError());
        return false;
    }
    funcPtr = reinterpret_cast<T>(GetProcAddress(handle, funcName));
    if (!funcPtr) {
        printf("[ZETA] Failed to get %s from %S (error=%lu)\n", funcName, dllName, GetLastError());
        return false;
    }
    printf("[ZETA] Loaded %S!%s\n", dllName, funcName);
    return true;
}

#define LOAD_DLL(dll, handle, func) loadDll(dll, handle, #func, p_ ## func)

// ============================================================
// App logging
// ============================================================
static void appLog(const wchar_t* level, const wchar_t* action, const wchar_t* detail) {
    if (p_zeta_core_log) {
        p_zeta_core_log(level, L"App", action, detail);
    }
    // Also log to UI (thread-safe via Bridge)
    zeta_ui_append_log(level, action, detail);
}

// ============================================================
// getProcessName — resolve executable name from PID
// ============================================================
static std::wstring getProcessName(unsigned long pid) {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return L"";
    std::wstring name;
    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    if (Process32FirstW(h, &pe)) do {
        if (pe.th32ProcessID == pid) {
            name = pe.szExeFile;
            break;
        }
    } while (Process32NextW(h, &pe));
    CloseHandle(h);
    return name;
}

// ============================================================
// Auto-scan newly created processes
// ============================================================
static void onNewProcessCreated(unsigned long pid, unsigned long ppid, 
                                const wchar_t* name, const wchar_t* path) {
    if (!p_zeta_engine_scan_file || !p_zeta_engine_create || !p_zeta_engine_destroy) {
        return;
    }

    std::wstring pathStr = path;
    std::wstring nameStr = name;

    // Skip system processes and known safe paths
    if (pathStr.find(L"\\System32\\") != std::wstring::npos ||
        pathStr.find(L"\\SysWOW64\\") != std::wstring::npos ||
        pathStr.find(L"\\Program Files\\") != std::wstring::npos ||
        pathStr.find(L"\\Program Files (x86)\\") != std::wstring::npos) {
        return;
    }

    // Only scan executable files
    std::wstring ext;
    size_t dot = pathStr.find_last_of(L'.');
    if (dot != std::wstring::npos) {
        ext = pathStr.substr(dot);
        for (auto& c : ext) c = (wchar_t)towlower(c);
    }
    if (ext != L".exe" && ext != L".dll" && ext != L".sys") {
        return;
    }

    // Create scanner and scan
    void* scanner = p_zeta_engine_create();
    if (!scanner) {
        std::wstring msg = L"Failed to create scanner for " + nameStr;
        appLog(L"WARN", L"AutoScan", msg.c_str());
        return;
    }

    wchar_t result[2048] = { 0 };
    int ret = p_zeta_engine_scan_file(scanner, pathStr.c_str(), result, 2048);
    p_zeta_engine_destroy(scanner);

    if (ret > 0) {
        std::wstring msg = L"Threat detected: PID=" + std::to_wstring(pid) + L" " + nameStr +
            L"\nScore=" + std::to_wstring(ret) + L"\n" + std::wstring(result);
        appLog(L"ALERT", L"AutoScan", msg.c_str());
        
        // Report to EDR behavior engine
        ProcessBehaviorEngine::instance().reportScanScore(pid, ret, nameStr, pathStr);
    } else if (ret < 0) {
        std::wstring msg = L"Scan failed for " + nameStr + L": " + std::wstring(result);
        appLog(L"WARN", L"AutoScan", msg.c_str());
    } else {
        std::wstring msg = L"Clean: PID=" + std::to_wstring(pid) + L" " + nameStr;
        appLog(L"DEBUG", L"AutoScan", msg.c_str());
    }
}

// ============================================================
// Async scan worker function (runs in background thread)
// ============================================================
static void doScanWork(std::wstring methodStr) {
    if (!p_zeta_engine_scan_file || !p_zeta_engine_create || !p_zeta_engine_destroy) {
        appLog(L"WARN", L"Scan", L"Engine not loaded");
        return;
    }

    // Create scanner
    void* scanner = p_zeta_engine_create();
    if (!scanner) {
        appLog(L"ERROR", L"Scan", L"Failed to create scanner");
        return;
    }

    // Determine scan targets
    std::vector<std::wstring> targets;
    if (methodStr == L"智能扫描") {
        wchar_t temp[MAX_PATH];
        GetEnvironmentVariableW(L"USERPROFILE", temp, MAX_PATH);
        targets.push_back(temp);
        targets.push_back(L"C:\\");
    } else if (methodStr == L"全盘扫描") {
        for (wchar_t drive = L'A'; drive <= L'Z'; drive++) {
            wchar_t root[] = { drive, L':', L'\\', 0 };
            if (GetDriveTypeW(root) == DRIVE_FIXED) {
                targets.push_back(root);
            }
        }
    } else {
        targets.push_back(methodStr);
    }

    // Phase 1: Collect all files (with progress)
    appLog(L"INFO", L"Scan", L"Phase 1: Collecting files...");
    zeta_ui_set_status_text(L"正在收集文件...");

    std::vector<std::wstring> allFiles;
    const wchar_t* scanExts[] = { L".exe", L".dll", L".sys", L".scr", L".ocx" };
    auto isScanExt = [&](const std::wstring& ext) -> bool {
        for (auto e : scanExts) if (_wcsicmp(ext.c_str(), e) == 0) return true;
        return false;
    };

    for (const auto& target : targets) {
        std::vector<std::wstring> stack;
        stack.push_back(target);
        while (!stack.empty()) {
            std::wstring dir = stack.back();
            stack.pop_back();
            std::wstring search = dir + L"\\*";
            WIN32_FIND_DATAW fd;
            HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (fd.cFileName[0] == L'.') continue;
                    // Skip Windows system dirs
                    if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        std::wstring name = fd.cFileName;
                        if (name == L"System32" || name == L"SysWOW64" ||
                            name == L"winsxs" || name == L"WinSxS" ||
                            name == L"AppData" || name == L"$Recycle.Bin" ||
                            name == L"Config" || name == L"Recovery" ||
                            name == L"System Volume Information" ||
                            name == L"Windows" && target != L"C:\\Windows") {
                            std::wstring full = dir + L"\\" + name;
                            // Skip Windows entirely in non-C: drives
                            if (name == L"Windows") {
                                DWORD attrs = GetFileAttributesW(full.c_str());
                                if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT))
                                    continue;
                                // Check if it's junction/volume mount
                                continue;
                            }
                            continue;
                        }
                        std::wstring full = dir + L"\\" + fd.cFileName;
                        stack.push_back(full);
                    }
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
        }
    }

    // Phase 2: Walk again for actual files (limit depth for speed)
    for (const auto& target : targets) {
        std::vector<std::pair<std::wstring, int>> stack; // dir, depth
        stack.push_back({ target, 0 });
        const int MAX_DEPTH = 6;
        while (!stack.empty()) {
            auto [dir, depth] = stack.back();
            stack.pop_back();
            std::wstring search = dir + L"\\*";
            WIN32_FIND_DATAW fd;
            HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (fd.cFileName[0] == L'.') continue;
                    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        if (depth < MAX_DEPTH) {
                            std::wstring full = dir + L"\\" + fd.cFileName;
                            stack.push_back({ full, depth + 1 });
                        }
                    } else {
                        std::wstring name = fd.cFileName;
                        size_t dot = name.find_last_of(L'.');
                        if (dot != std::wstring::npos) {
                            std::wstring ext = name.substr(dot);
                            if (isScanExt(ext)) {
                                allFiles.push_back(dir + L"\\" + name);
                            }
                        }
                    }
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
        }
    }

    // Phase 3: Scan each file
    appLog(L"INFO", L"Scan", (L"Phase 2: Scanning " + std::to_wstring(allFiles.size()) + L" files").c_str());
    
    int total = (int)allFiles.size();
    int threatCount = 0;

    for (int i = 0; i < total; i++) {
        zeta_ui_set_status_text((L"扫描: " + allFiles[i]).c_str());

        wchar_t result[1024] = { 0 };
        int ret = p_zeta_engine_scan_file(scanner, allFiles[i].c_str(), result, 1024);

        if (ret > 0) {
            threatCount++;
        }

        if (i % 5 == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    p_zeta_engine_destroy(scanner);
    zeta_ui_set_status_text((L"扫描完成 - 发现 " + std::to_wstring(threatCount) + L" 个威胁").c_str());
    appLog(L"INFO", L"Scan", (L"Complete: " + std::to_wstring(total) + L" files, " +
           std::to_wstring(threatCount) + L" threats").c_str());
}

// ============================================================
// Async system repair worker function
// ============================================================
static void doRepairWork() {
    zeta_ui_set_status_text(L"Running system repair...");
    appLog(L"INFO", L"Repair", L"Running system repair...");

    // ── Repair Item 0: SFC Scan ──
    zeta_ui_set_repair_item(0, L"运行中", L"-");
    {
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));
        si.cb = sizeof(si);
        wchar_t sfcCmd[] = L" /scannow";
        if (CreateProcessW(L"C:\\Windows\\System32\\sfc.exe", sfcCmd,
                           nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 120000);
            DWORD exitCode = 0;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            zeta_ui_set_repair_item(0, L"完成", exitCode == 0 ? L"系统文件验证通过" : L"SFC 检测到问题");
            appLog(L"INFO", L"Repair", (L"SFC completed, exit=" + std::to_wstring(exitCode)).c_str());
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            zeta_ui_set_repair_item(0, L"完成", L"SFC 启动失败");
            appLog(L"WARN", L"Repair", L"SFC failed to start");
        }
    }

    // ── Repair Item 1: DISM ──
    zeta_ui_set_repair_item(1, L"运行中", L"-");
    {
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));
        si.cb = sizeof(si);
        wchar_t dismCmd[] = L" /Online /Cleanup-Image /RestoreHealth";
        if (CreateProcessW(L"C:\\Windows\\System32\\Dism.exe", dismCmd,
                           nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 300000);
            DWORD exitCode = 0;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            zeta_ui_set_repair_item(1, L"完成", exitCode == 0 ? L"映像修复完成" : L"DISM 已完成");
            appLog(L"INFO", L"Repair", (L"DISM completed, exit=" + std::to_wstring(exitCode)).c_str());
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            zeta_ui_set_repair_item(1, L"完成", L"DISM 启动失败");
            appLog(L"WARN", L"Repair", L"DISM failed to start");
        }
    }

    // ── Repair Item 2: Clean temp files ──
    zeta_ui_set_repair_item(2, L"运行中", L"-");
    {
        int cleaned = 0;
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        std::wstring tempDir = tempPath;
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW((tempDir + L"*").c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    if (DeleteFileW((tempDir + fd.cFileName).c_str())) cleaned++;
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
        hFind = FindFirstFileW(L"C:\\Windows\\Temp\\*", &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    if (DeleteFileW((std::wstring(L"C:\\Windows\\Temp\\") + fd.cFileName).c_str())) cleaned++;
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
        wchar_t msg[128];
        wsprintfW(msg, L"已清理 %d 个临时文件", cleaned);
        zeta_ui_set_repair_item(2, L"完成", msg);
        appLog(L"INFO", L"Repair", msg);
    }

    // ── Repair Item 3: Network/DNS reset ──
    zeta_ui_set_repair_item(3, L"运行中", L"-");
    {
        _wsystem(L"ipconfig /flushdns");
        _wsystem(L"ipconfig /release");
        _wsystem(L"ipconfig /renew");
        _wsystem(L"netsh winsock reset");
        zeta_ui_set_repair_item(3, L"完成", L"DNS 缓存已刷新, Winsock 已重置");
        appLog(L"INFO", L"Repair", L"Network reset completed");
    }

    // Run DLL repair function if available
    if (p_zeta_monitor_system_repair_exec) {
        int fixed = p_zeta_monitor_system_repair_exec();
        wchar_t msg[128];
        wsprintfW(msg, L"系统修复: %d 项已修复", fixed);
        zeta_ui_set_status_text(msg);
        appLog(L"INFO", L"Repair", msg);
    } else {
        zeta_ui_set_status_text(L"系统修复完成");
    }
    appLog(L"INFO", L"Repair", L"All repair tasks completed");
    zeta_ui_set_repair_buttons(1);
}

// ============================================================
// Helper: Send driver command in background thread
// ============================================================
void sendDriverCmdAsync(unsigned long cmd, const wchar_t* param, const wchar_t* cmdName) {
    std::thread([cmd, param, cmdName]() {
        if (p_zeta_driver_send_cmd) {
            try {
                int ret = p_zeta_driver_send_cmd(cmd, param);
                std::wstring msg = std::wstring(cmdName) + L": " + std::wstring(param) + L" (ret=" + std::to_wstring(ret) + L")";
                appLog(L"INFO", L"Driver", msg.c_str());
            } catch (...) {
                appLog(L"ERROR", L"Driver", std::wstring(L"sendDriverCmd failed: " + std::wstring(cmdName)).c_str());
            }
        }
    }).detach();
}

bool sendDriverCmdWithRollback(unsigned long cmd, const wchar_t* param, const wchar_t* cmdName, const wchar_t* switchKey, const wchar_t* enableMsg, const wchar_t* disableMsg, const wchar_t* failMsg, std::wstring& statusMsg) {
    if (!p_zeta_driver_send_cmd) {
        zeta_ui_restore_switch(switchKey, 0);
        if (p_zeta_core_config_set_bool) p_zeta_core_config_set_bool(switchKey, 0);
        if (p_zeta_core_config_save) p_zeta_core_config_save();
        statusMsg = L"启用失败: 驱动未加载";
        return false;
    }
    
    int ret = p_zeta_driver_send_cmd(cmd, param);
    std::wstring msg = std::wstring(cmdName) + L": " + std::wstring(param) + L" (ret=" + std::to_wstring(ret) + L")";
    appLog(L"INFO", L"Driver", msg.c_str());
    
    if (ret != 0) {
        zeta_ui_restore_switch(switchKey, 0);
        if (p_zeta_core_config_set_bool) p_zeta_core_config_set_bool(switchKey, 0);
        if (p_zeta_core_config_save) p_zeta_core_config_save();
        appLog(L"ERROR", L"Driver", (std::wstring(L"Failed: ") + cmdName).c_str());
        statusMsg = failMsg;
        return false;
    }
    
    statusMsg = enableMsg;
    return true;
}

// ============================================================
// Callback: User toggles a config switch
// ============================================================
void __stdcall onConfigCallback(const wchar_t* key, int value) {
    appLog(L"INFO", L"Config", std::wstring(std::wstring(key) + L"=" + std::to_wstring(value)).c_str());

    // Save to config file (quick operation, can be sync)
    if (p_zeta_core_config_set_bool) {
        p_zeta_core_config_set_bool(key, value);
    }
    if (p_zeta_core_config_save) {
        p_zeta_core_config_save();
    }

    // Apply actual functionality based on key
    std::wstring keyStr = key ? key : L"";
    std::wstring statusMsg;

    // ============================================================
    // 驱动级保护开关 (同步执行，失败时回滚UI状态)
    // ============================================================

    if (keyStr == L"lineage_switch") {
        if (value) {
            sendDriverCmdWithRollback(6, L"1", L"Lineage tracker", L"lineage_switch", 
                L"血缘追踪已启用", L"血缘追踪已禁用", L"血缘追踪启用失败", statusMsg);
        } else {
            sendDriverCmdAsync(6, L"0", L"Lineage tracker");
            statusMsg = L"血缘追踪已禁用";
        }
    }

    if (keyStr == L"ransom_exp_switch") {
        if (value) {
            sendDriverCmdWithRollback(7, L"1", L"Ransom exp", L"ransom_exp_switch", 
                L"勒索检测已启用", L"勒索检测已禁用", L"勒索检测启用失败", statusMsg);
        } else {
            sendDriverCmdAsync(7, L"0", L"Ransom exp");
            statusMsg = L"勒索检测已禁用";
        }
    }

    if (keyStr == L"process_switch") {
        if (value) {
            sendDriverCmdWithRollback(8, L"1", L"Self protection", L"process_switch", 
                L"自我保护已启用", L"自我保护已禁用", L"自我保护启用失败", statusMsg);
        } else {
            sendDriverCmdAsync(8, L"0", L"Self protection");
            statusMsg = L"自我保护已禁用";
        }
    }

    if (keyStr == L"suspend_switch") {
        if (value) {
            sendDriverCmdWithRollback(9, L"1", L"Suspend enable", L"suspend_switch", 
                L"进程暂停已启用", L"进程暂停已禁用", L"进程暂停启用失败", statusMsg);
        } else {
            sendDriverCmdAsync(9, L"0", L"Suspend enable");
            statusMsg = L"进程暂停已禁用";
        }
    }

    if (keyStr == L"document_switch") {
        if (value) {
            sendDriverCmdWithRollback(10, L"1", L"File protect", L"document_switch", 
                L"文件防护已启用", L"文件防护已禁用", L"文件防护启用失败", statusMsg);
        } else {
            sendDriverCmdAsync(10, L"0", L"File protect");
            statusMsg = L"文件防护已禁用";
        }
    }

    if (keyStr == L"system_switch") {
        if (value) {
            sendDriverCmdWithRollback(11, L"1", L"System protect", L"system_switch", 
                L"系统防护已启用", L"系统防护已禁用", L"系统防护启用失败", statusMsg);
        } else {
            sendDriverCmdAsync(11, L"0", L"System protect");
            statusMsg = L"系统防护已禁用";
        }
    }

    if (keyStr == L"driver_switch") {
        if (value) {
            sendDriverCmdWithRollback(12, L"1", L"Driver protect", L"driver_switch", 
                L"驱动防护已启用", L"驱动防护已禁用", L"驱动防护启用失败", statusMsg);
        } else {
            sendDriverCmdAsync(12, L"0", L"Driver protect");
            statusMsg = L"驱动防护已禁用";
        }
    }

    if (keyStr == L"network_switch") {
        if (value) {
            sendDriverCmdWithRollback(13, L"1", L"Network protect", L"network_switch", 
                L"网络防护已启用", L"网络防护已禁用", L"网络防护启用失败", statusMsg);
        } else {
            sendDriverCmdAsync(13, L"0", L"Network protect");
            statusMsg = L"网络防护已禁用";
        }
    }

    // (traffic_switch removed)

    if (keyStr == L"learning_switch") {
        if (value) {
            sendDriverCmdWithRollback(14, L"1", L"Learning mode", L"learning_switch", 
                L"学习模式已启用", L"学习模式已禁用", L"学习模式启用失败", statusMsg);
        } else {
            sendDriverCmdAsync(14, L"0", L"Learning mode");
            statusMsg = L"学习模式已禁用";
        }
    }

    // ============================================================
    // UI 反馈 (在主线程执行)
    // ============================================================
    if (!statusMsg.empty()) {
        // Note: 不更新首页状态标签，保持 "此装置已受到防护"
        appLog(L"INFO", L"UI", statusMsg.c_str());
    }
}

// ============================================================
// DriverEventProcessor — Multi-threaded event handler
//
// onDriverMessage (driver message thread) = PRODUCER
//   enqueue only → return immediately. Never blocks.
//
// DriverEventProcessor worker thread = CONSUMER  
//   dequeue → log, throttle, classify, notify, score
//
// 2001/3001 HIPS prompts still run on worker thread
// (driver waits for reply on driver thread side; worker
//  thread shows prompt → user clicks → reply sent to driver).
// 6002 SilverFox sig verification runs on worker (async).
// ============================================================
class DriverEventProcessor {
public:
    static DriverEventProcessor& instance();

    void start() {
        m_running = true;
        m_worker = std::thread(&DriverEventProcessor::workerLoop, this);
    }

    void stop() {
        m_running = false;
        m_cv.notify_all();
        if (m_worker.joinable()) m_worker.join();
    }

    // PRODUCER: called from onDriverMessage (message thread)
    // Must be O(1) and never block.
    void enqueue(unsigned long code, unsigned long pid,
                 const std::wstring& path, const std::wstring& action) {
        if (!m_running) return;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_queue.size() < MAX_QUEUE) {
                m_queue.push({code, pid, path, action});
            }
        }
        m_cv.notify_one();
    }

private:
    struct Event {
        unsigned long code;
        unsigned long pid;
        std::wstring path;
        std::wstring action;
    };

    void workerLoop() {
        while (m_running) {
            Event evt;
            bool hasWork = false;
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_cv.wait_for(lock, std::chrono::milliseconds(100),
                    [this]{ return !m_queue.empty() || !m_running; });
                if (!m_queue.empty()) {
                    evt = std::move(m_queue.front());
                    m_queue.pop();
                    hasWork = true;
                }
            }
            if (hasWork) processEvent(evt);
        }
    }

    // ── Risk level helpers ──
    // CRITICAL (>=20pts): registry, disk write → always HIPS
    // HIGH    (>=15pts): exe/dll/sys release → HIPS
    // MEDIUM  (>=10pts): non-PE file release to protected path → EDR only
    // LOW     (<10pts):  text/config files → EDR only
    static bool IsHighRiskFile(const std::wstring& path) {
        // PE executables (exe, dll, sys, scr, ocx) are always high risk
        size_t dot = path.find_last_of(L'.');
        if (dot == std::wstring::npos) return false;
        std::wstring ext = path.substr(dot);
        for (auto& c : ext) c = (wchar_t)towlower(c);
        return (ext == L".exe" || ext == L".dll" || ext == L".sys" ||
                ext == L".scr" || ext == L".ocx" || ext == L".cpl");
    }

    void processEvent(const Event& evt) {
        unsigned long code = evt.code;
        unsigned long pid = evt.pid;
        const std::wstring& pathStr = evt.path;
        const std::wstring& actionStr = evt.action;

        if (code != 6002) {
            appLog(L"INFO", L"DriverMsg",
                (L"Code=" + std::to_wstring(code) + L" PID=" + std::to_wstring(pid) +
                 L" Action=" + actionStr + L" Path=" + pathStr).c_str());
        }

        // For 6002 (SilverFox), compute analysis BEFORE ingest to pass detail through
        std::wstring sfDetail;
        if (code == 6002) {
            sfDetail = processSilverFoxSignature(pid, pathStr);
        }

        // Always ingest into behavior engine regardless of throttle
        ProcessBehaviorEngine::instance().ingest(code, pid, pathStr, sfDetail);

        // Throttle is for UI notifications only; score engine already got the event
        if (!p_zeta_ui_show_notification) return;

        if (isThrottled(code, pid)) return;

        int level = 0;
        std::wstring title;
        std::wstring message;
        bool needsUserAction = false;

        switch (code) {
            case 2001:
                // ── TIERED FILE PROTECTION ──
                // HIGH risk (PE files) → HIPS popup immediately
                // LOW risk (text/config/data) → silent EDR scoring only
                if (IsHighRiskFile(pathStr)) {
                    level = 2;
                    title = L"文件防护拦截";
                    message = L"高危操作: 进程 " + std::to_wstring(pid) +
                              L" 正在释放可执行文件到受保护路径:\n" + pathStr;
                    needsUserAction = true;

                    // ── HIPS→EDR Linkage ──
                    // Check user-mode HIPS rules for this event and report score to EDR
                    HipsAction ruleAction = HipsEngine::instance().matchRule(code, getProcessName(pid), pathStr);
                    if (ruleAction == HIPS_DENY) {
                        ProcessBehaviorEngine::instance().reportHipsScore(pid,
                            HipsEngine::instance().lastMatchedScore(), code, pathStr);
                    } else if (ruleAction == HIPS_ALLOW) {
                        ProcessBehaviorEngine::instance().clearScore(pid);
                    }
                } else {
                    // LOW risk: silently add to EDR score, no popup
                    level = 0;
                }
                break;
            case 3001:
                // ── REGISTRY PROTECTION ── (always CRITICAL)
                level = 2;
                title = L"注册表防护拦截";
                message = L"高危操作: 进程 " + std::to_wstring(pid) +
                          L" 正在修改受保护注册表:\n" + pathStr;
                needsUserAction = true;

                // ── HIPS→EDR Linkage ──
                {
                    HipsAction ruleAction = HipsEngine::instance().matchRule(code, getProcessName(pid), pathStr);
                    if (ruleAction == HIPS_DENY) {
                        ProcessBehaviorEngine::instance().reportHipsScore(pid,
                            HipsEngine::instance().lastMatchedScore(), code, pathStr);
                    } else if (ruleAction == HIPS_ALLOW) {
                        ProcessBehaviorEngine::instance().clearScore(pid);
                    }
                }
                break;
            case 4001:
                // ── DISK WRITE ── (always CRITICAL)
                level = 2;
                title = L"磁盘防护拦截";
                message = L"高危操作: 进程 " + std::to_wstring(pid) +
                          L" 正在尝试低层级磁盘写入 (疑似勒索/磁盘擦写器):\n" + pathStr;
                needsUserAction = true;

                // ── HIPS→EDR Linkage ──
                {
                    HipsAction ruleAction = HipsEngine::instance().matchRule(code, getProcessName(pid), pathStr);
                    if (ruleAction == HIPS_DENY) {
                        ProcessBehaviorEngine::instance().reportHipsScore(pid,
                            HipsEngine::instance().lastMatchedScore(), code, pathStr);
                    } else if (ruleAction == HIPS_ALLOW) {
                        ProcessBehaviorEngine::instance().clearScore(pid);
                    }
                }
                break;
            case 5001:
                // ── HIPS→EDR Linkage for Ransomware ──
                {
                    HipsAction ruleAction = HipsEngine::instance().matchRule(code, getProcessName(pid), pathStr);
                    if (ruleAction == HIPS_DENY) {
                        ProcessBehaviorEngine::instance().reportHipsScore(pid,
                            HipsEngine::instance().lastMatchedScore(), code, pathStr);
                    } else if (ruleAction == HIPS_ALLOW) {
                        ProcessBehaviorEngine::instance().clearScore(pid);
                    }
                }
                level = -1;
                break;
            case 6001:
                // ── HIPS→EDR Linkage for Code Injection ──
                {
                    HipsAction ruleAction = HipsEngine::instance().matchRule(code, getProcessName(pid), pathStr);
                    if (ruleAction == HIPS_DENY) {
                        ProcessBehaviorEngine::instance().reportHipsScore(pid,
                            HipsEngine::instance().lastMatchedScore(), code, pathStr);
                    } else if (ruleAction == HIPS_ALLOW) {
                        ProcessBehaviorEngine::instance().clearScore(pid);
                    }
                }
                level = -1;
                break;
            case 6002:
                // ── HIPS→EDR Linkage for SilverFox ──
                {
                    HipsAction ruleAction = HipsEngine::instance().matchRule(code, getProcessName(pid), pathStr);
                    if (ruleAction == HIPS_DENY) {
                        ProcessBehaviorEngine::instance().reportHipsScore(pid,
                            HipsEngine::instance().lastMatchedScore(), code, pathStr);
                    } else if (ruleAction == HIPS_ALLOW) {
                        ProcessBehaviorEngine::instance().clearScore(pid);
                    }
                }
                level = -1;
                break;
            case 7001: case 7003: level = -1; break;
            case 7004: level = 1; title = L"血统追踪回退";
                message = L"内核级血统追踪不可用，已切换到用户态轮询模式"; break;
            case 7000: level = 0; title = L"驱动日志";
                message = L"[" + actionStr + L"] " + pathStr; break;
            case 7005: appLog(L"LEARN", L"LearningMode",
                (L"PID=" + std::to_wstring(pid) + L" Path=" + pathStr).c_str());
                level = 0; title = L"学习模式";
                message = L"允许活动 PID=" + std::to_wstring(pid) + L"\n" + pathStr; break;
            default: level = 0; title = L"安全通知";
                message = L"消息码: " + std::to_wstring(code) +
                         L" PID: " + std::to_wstring(pid) +
                         L" [" + actionStr + L"] " + pathStr; break;
        }

        // HIPS: only show for HIGH/CRITICAL risk operations
        if (needsUserAction && p_zeta_ui_show_hips_prompt) {
            p_zeta_ui_show_hips_prompt(title.c_str(), message.c_str(), pid, level);
        } else if (level > 1 && p_zeta_ui_show_notification) {
            p_zeta_ui_show_notification(title.c_str(), message.c_str(), level);
        }
    }

    std::wstring processSilverFoxSignature(unsigned long pid, const std::wstring& pathStr) {
        // Core logic: If the PROCESS ITSELF has a valid digital signature,
        // skip SilverFox detection entirely.
        // 
        // SilverFox attack pattern: an unsigned malicious launcher releases
        // signed legitimate installers + unsigned malware. The malicious
        // launcher itself can NEVER have a valid signature because that
        // would require stealing the legitimate publisher's private key.
        // 
        // Legitimate scenario: A signed installer (e.g., 360 installer)
        // releases signed components + unsigned temporary helpers. This is
        // NORMAL and should NOT be flagged as SilverFox.
        // 
        // Therefore: ONLY run SilverFox detection on UNSIGNED processes.
        if (p_zeta_engine_check_signature) {
            std::wstring processPath = getProcessPath(pid);
            if (!processPath.empty()) {
                if (p_zeta_engine_check_signature(processPath.c_str())) {
                    appLog(L"INFO", L"SilverFox",
                        (L"PID=" + std::to_wstring(pid) + L" has valid signature - skipping detection").c_str());
                    return L"";
                }
            }
        }

        std::vector<std::wstring> dosPaths;
        size_t start = 0;
        for (size_t i = 0; i <= pathStr.size(); i++) {
            if (i == pathStr.size() || pathStr[i] == L'|') {
                if (i > start) {
                    dosPaths.push_back(ntToDosPath(pathStr.substr(start, i - start)));
                }
                start = i + 1;
            }
        }

        if (!p_zeta_hips_silverfox_analyze || dosPaths.size() < 2) return L"";

        std::vector<const wchar_t*> ptrs;
        for (auto& p : dosPaths) ptrs.push_back(p.c_str());

        wchar_t resultType[32] = {0}, resultDetail[256] = {0};
        if (!p_zeta_hips_silverfox_analyze(
                ptrs.data(), (int)ptrs.size(),
                resultType, 32, resultDetail, 256)) {
            return L""; // Clean
        }

        appLog(L"WARN", L"SilverFox",
            (L"PID=" + std::to_wstring(pid) +
             L" Result=" + resultType +
             L" Detail=" + resultDetail).c_str());

        return std::wstring(resultDetail);
    }

    std::queue<Event> m_queue;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::thread m_worker;
    std::atomic<bool> m_running{false};
    static constexpr size_t MAX_QUEUE = 8192;
};

DriverEventProcessor& DriverEventProcessor::instance() {
    static DriverEventProcessor s;
    return s;
}

// ============================================================
// Callback: Driver message received (from kernel)
// ============================================================
void __stdcall onDriverMessage(unsigned long code, unsigned long pid, 
                               const wchar_t* path, const wchar_t* action) {
    // Pure PRODUCER: enqueue only, return immediately.
    // ALL processing (logging, throttle, switch/case, notification,
    // SilverFox signature verification, behavior scoring) runs on
    // the DriverEventProcessor worker thread.
    DriverEventProcessor::instance().enqueue(
        code, pid,
        path ? std::wstring(path) : std::wstring(),
        action ? std::wstring(action) : std::wstring());
}

// ============================================================
// Callback: User clicks a tool button
// ============================================================
void __stdcall onToolCallback(const wchar_t* tool) {
    appLog(L"INFO", L"Tool", tool);

    std::wstring toolStr = tool ? tool : L"";
    if (toolStr.empty()) return;

    // Handle experimental toggles
    if (toolStr.find(L"toggle_lineage:") == 0) {
        bool enabled = toolStr.find(L":1") != std::wstring::npos;
        onConfigCallback(L"lineage_switch", enabled ? 1 : 0);
        return;
    }

    if (toolStr.find(L"toggle_ransom:") == 0) {
        bool enabled = toolStr.find(L":1") != std::wstring::npos;
        onConfigCallback(L"ransom_exp_switch", enabled ? 1 : 0);
        return;
    }
    
    // (toggle_traffic removed)

    if (toolStr.find(L"toggle_learning:") == 0) {
        bool enabled = toolStr.find(L":1") != std::wstring::npos;
        onConfigCallback(L"learning_switch", enabled ? 1 : 0);
        return;
    }

    // Tool actions
    if (toolStr == L"系统修复") {
        // Launch repair in background thread (non-blocking)
        if (g_repairThread.joinable()) {
            g_repairThread.detach();
        }
        g_repairThread = std::thread(doRepairWork);
        return;
    }

    if (toolStr == L"垃圾清理") {
        std::thread([]() {
             zeta_ui_set_status_text(L"扫描垃圾文件中...");
             appLog(L"INFO", L"Junk", L"Scanning for junk files...");

             std::vector<std::wstring> junkDirs = {
                 L"C:\\Windows\\Temp",
                 L"C:\\Users\\Public\\Downloads"
             };
             wchar_t tempPath[MAX_PATH];
             GetTempPathW(MAX_PATH, tempPath);
             junkDirs.push_back(tempPath);

             int totalFiles = 0;
             for (const auto& dir : junkDirs) {
                 std::wstring searchPath = dir + L"\\*.*";
                 WIN32_FIND_DATAW findData;
                 HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
                 if (hFind != INVALID_HANDLE_VALUE) {
                     do {
                         if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                             totalFiles++;
                         }
                     } while (FindNextFileW(hFind, &findData));
                     FindClose(hFind);
                 }
             }
             wchar_t msg[128];
             wsprintfW(msg, L"找到 %d 个垃圾文件", totalFiles);
             zeta_ui_set_status_text(msg);
             appLog(L"INFO", L"Junk", msg);
        }).detach();
        return;
    }

    if (toolStr == L"HIPS 规则管理") {
        if (p_zeta_hips_popup_add_rule) {
            p_zeta_hips_popup_add_rule(L"HIPS Manager");
        }
        zeta_ui_set_status_text(L"HIPS 规则管理");
        return;
    }

    if (toolStr == L"进程管理") {
        zeta_ui_set_status_text(L"进程管理 - 按 Ctrl+Shift+Esc 打开任务管理器");
        appLog(L"INFO", L"Tool", L"Process Manager: Use Task Manager");
        return;
    }

    if (toolStr == L"启动项管理") {
        zeta_ui_set_status_text(L"启动项管理 - 按 Ctrl+Shift+Esc > 启动项");
        appLog(L"INFO", L"Tool", L"Startup Manager: Use Task Manager");
        return;
    }

    // (流量监控 tool handler removed)

    if (toolStr == L"白名单") {
        zeta_ui_set_status_text(L"白名单管理");
        appLog(L"INFO", L"Tool", L"Whitelist Manager");
        return;
    }

    if (toolStr == L"隔离区") {
        zeta_ui_set_status_text(L"隔离区");
        appLog(L"INFO", L"Tool", L"Quarantine");
        return;
    }

    // Unknown tool
    appLog(L"INFO", L"Tool", std::wstring(L"Unknown tool: " + toolStr).c_str());
    zeta_ui_set_status_text(std::wstring(L"工具: " + toolStr).c_str());
}

// ============================================================
// Forward declarations
// ============================================================
static bool installAndStartDriver();

// ============================================================
// Load all DLLs
// ============================================================
bool loadAllDlls() {
    printf("[ZETA] Loading C++ DLLs...\n");

    // 1. ZETA_Core.dll
    if (!LOAD_DLL(L"ZETA_Core.dll", g_hCore, zeta_core_log)) return false;
    LOAD_DLL(L"ZETA_Core.dll", g_hCore, zeta_core_config_get_bool);
    LOAD_DLL(L"ZETA_Core.dll", g_hCore, zeta_core_config_set_bool);
    LOAD_DLL(L"ZETA_Core.dll", g_hCore, zeta_core_config_save);
    LOAD_DLL(L"ZETA_Core.dll", g_hCore, zeta_core_config_load);

    // Init core first
    // Load config so save() has a valid path
    if (p_zeta_core_config_load) {
        p_zeta_core_config_load(L"C:\\ProgramData\\ZETA\\Config.json");
    }
    fn_zeta_core_init p_zeta_core_init = nullptr;
    LOAD_DLL(L"ZETA_Core.dll", g_hCore, zeta_core_init);
    if (p_zeta_core_init) {
        p_zeta_core_init(g_logsDir.c_str());
    }

    // 2. ZETA_Engine.dll
    LOAD_DLL(L"ZETA_Engine.dll", g_hEngine, zeta_engine_init);
    LOAD_DLL(L"ZETA_Engine.dll", g_hEngine, zeta_engine_create);
    LOAD_DLL(L"ZETA_Engine.dll", g_hEngine, zeta_engine_destroy);
    LOAD_DLL(L"ZETA_Engine.dll", g_hEngine, zeta_engine_check_signature);
    loadDll(L"ZETA_Engine.dll", g_hEngine, "zeta_engine_wrapper_scan", p_zeta_engine_scan_file);
    if (p_zeta_engine_init) {
        std::wstring edrRulesDir = g_pluginsDir + L"\\Rules";
        int edrRet = p_zeta_engine_init(edrRulesDir.c_str());
        if (edrRet != 0) {
            appLog(L"INFO", L"EDR", (L"EDR engine initialized: " + edrRulesDir).c_str());
        } else {
            appLog(L"WARN", L"EDR", L"EDR engine init failed, using defaults");
        }
    }

    // 3. ZETA_Driver.dll
    LOAD_DLL(L"ZETA_Driver.dll", g_hDriver, zeta_driver_connect);
    LOAD_DLL(L"ZETA_Driver.dll", g_hDriver, zeta_driver_disconnect);
    LOAD_DLL(L"ZETA_Driver.dll", g_hDriver, zeta_driver_is_connected);
    LOAD_DLL(L"ZETA_Driver.dll", g_hDriver, zeta_driver_set_msg_callback);
    LOAD_DLL(L"ZETA_Driver.dll", g_hDriver, zeta_driver_start_loop);
    LOAD_DLL(L"ZETA_Driver.dll", g_hDriver, zeta_driver_stop_loop);
    LOAD_DLL(L"ZETA_Driver.dll", g_hDriver, zeta_driver_send_cmd);
    LOAD_DLL(L"ZETA_Driver.dll", g_hDriver, zeta_driver_get_init_log);
    LOAD_DLL(L"ZETA_Driver.dll", g_hDriver, zeta_hips_load_rules);
    LOAD_DLL(L"ZETA_Driver.dll", g_hDriver, zeta_hips_reload_rules);
    LOAD_DLL(L"ZETA_Driver.dll", g_hDriver, zeta_hips_add_rule);
    LOAD_DLL(L"ZETA_Driver.dll", g_hDriver, zeta_hips_set_rules_path);

    // 4. ZETA_Monitor.dll
    LOAD_DLL(L"ZETA_Monitor.dll", g_hMonitor, zeta_monitor_start_process_monitor);
    LOAD_DLL(L"ZETA_Monitor.dll", g_hMonitor, zeta_monitor_stop_process_monitor);
    LOAD_DLL(L"ZETA_Monitor.dll", g_hMonitor, zeta_monitor_set_new_process_callback);
    LOAD_DLL(L"ZETA_Monitor.dll", g_hMonitor, zeta_monitor_lineage_enable);
    LOAD_DLL(L"ZETA_Monitor.dll", g_hMonitor, zeta_monitor_system_repair_exec);
    // zeta_monitor_junk_clean_exec not exported yet, use fallback

    // 5. ZETA_Hips.dll
    LOAD_DLL(L"ZETA_Hips.dll", g_hHips, zeta_hips_popup_add_rule);
    p_zeta_hips_silverfox_analyze = (fn_zeta_hips_silverfox_analyze)
        GetProcAddress(g_hHips, "zeta_hips_silverfox_analyze");

    // (TrafficAnalyzer exports removed)

    printf("[ZETA] All DLLs loaded successfully\n");

    return true;
}

// ── Async driver install (runs in background, non-blocking) ──
static void doDriverInstallWork() {
    printf("[ZETA] Starting async driver install...\n");

    bool driverLoaded = false;
    try {
    if (installAndStartDriver()) {
        if (p_zeta_driver_connect) {
            int connected = p_zeta_driver_connect(L"\\ZETA_Output_Pipe");
            printf("[ZETA] Driver connect: %s\n", connected ? "OK" : "FAILED");
            if (connected) {
                driverLoaded = true;
                // Register driver message callback
                if (p_zeta_driver_set_msg_callback) {
                    p_zeta_driver_set_msg_callback(reinterpret_cast<void*>(onDriverMessage));
                    printf("[ZETA] Driver message callback registered\n");
                }
                // Register HIPS response callback (user clicks allow/block → driver)
                // Called after dialog is already closed; FilterSendMessage returns fast (~μs)
                if (p_zeta_ui_set_hips_response_callback) {
                    p_zeta_ui_set_hips_response_callback([](unsigned long pid, int allow) {
                        // ── HIPS-EDR Integration ──
                        // User clicked Allow → tell EDR not to score this process
                        if (allow) {
                            ProcessBehaviorEngine::instance().markUserAllowed(pid);
                            appLog(L"INFO", L"HIPS",
                                (L"Allow PID=" + std::to_wstring(pid) + L" (EDR: user approved → stopped scoring)").c_str());
                        }
                        // User clicked Block → tell EDR to add penalty score
                        else {
                            ProcessBehaviorEngine::instance().addPenaltyScore(pid, 20);
                            appLog(L"INFO", L"HIPS",
                                (L"Block PID=" + std::to_wstring(pid) + L" (EDR: penalty +20)").c_str());
                        }

                        // Send decision to driver (ALLOW_OP=4, DENY_OP=5)
                        if (p_zeta_driver_send_cmd) {
                            unsigned long cmd = allow ? 4 : 5;
                            p_zeta_driver_send_cmd(cmd, std::to_wstring(pid).c_str());
                        }

                        // If blocked, terminate the offending process
                        if (!allow) {
                            SafeTerminateProcess(pid);
                            appLog(L"WARN", L"HIPS", (L"Terminated PID=" + std::to_wstring(pid)).c_str());
                        }
                    });
                    printf("[ZETA] HIPS response callback registered\n");
                }
                // Register behavior engine callbacks
                ProcessBehaviorEngine::instance().setAlertCallback(
                    [](ULONG pid, int score, const wchar_t* reasons,
                       const std::vector<std::wstring>& artifacts) {
                        // Resolve process name
                        std::wstring procName = getProcessName(pid);
                        if (procName.empty()) procName = L"<未知进程>";

                        // Log the alert (always show in log)
                        appLog(L"WARN", L"BehaviorAlert",
                            (L"PID=" + std::to_wstring(pid) +
                             L" Proc=" + procName +
                             L" Score=" + std::to_wstring(score) +
                             L" Reasons=" + (reasons ? reasons : L"")).c_str());

                        // Write verdict (before UI action — file I/O is fast and non-blocking)
                        if (reasons) {
                            Verdict v = Verdict::fromAlert(pid, score, reasons, {}, artifacts);
                            VerdictWriter::write(v);
                        }

                        // EDR score >= 85 → definitive malicious → kill process
                        // This is the cumulative risk verdict from many low-risk behaviors
                        // that individually wouldn't trigger HIPS but together prove malice.
                        if (score >= 85) {
                            SafeTerminateProcess(pid);
                            appLog(L"WARN", L"EDR",
                                (L"EDR累计评分=" + std::to_wstring(score) +
                                 L" 已达到阈值，自动终止进程 PID=" + std::to_wstring(pid)).c_str());
                        }

                        // Show HIPS prompt regardless, so user knows what happened
                        if (p_zeta_ui_show_hips_prompt) {
                            p_zeta_ui_show_hips_prompt(
                                L"行为风险告警",
                                (L"进程: " + procName +
                                 L" (PID: " + std::to_wstring(pid) + L")\n" +
                                 L"风险评分: " + std::to_wstring(score) + L"\n\n" +
                                 (reasons ? reasons : L"")).c_str(),
                                pid, 2);
                        }
                    });
                ProcessBehaviorEngine::instance().setWarnCallback(
                    [](ULONG pid, int score, const wchar_t* message,
                       const std::vector<std::wstring>& artifacts) {
                        // Write warn-level verdict (score 30-59)
                        if (message) {
                            Verdict v = Verdict::fromAlert(pid, score, message, {}, artifacts);
                            VerdictWriter::write(v);
                        }
                        if (p_zeta_ui_show_notification) {
                            p_zeta_ui_show_notification(
                                L"可疑行为", (message ? message : L""), 1);
                        }
                    });
                // Start engine maintenance thread (30s interval)
                ProcessBehaviorEngine::instance().start();
                ProcessBehaviorEngine::instance().loadWhitelist(
                    L"SYSTEM\\CurrentControlSet\\Services\\ZETA_Drv\\Parameters");
                printf("[ZETA] Behavior engine initialized\n");
                // Start event processor worker thread (processes all driver messages)
                DriverEventProcessor::instance().start();
                printf("[ZETA] Event processor started\n");
                // Start the driver message loop
                // Fetch driver init log BEFORE message loop starts (after start the
                // sendCommand goes through queue path and won't get the response)
                if (p_zeta_driver_get_init_log) {
                    const wchar_t* log = p_zeta_driver_get_init_log();
                    if (log) g_driverInitLog = log;
                }
                if (p_zeta_driver_start_loop) {
                    p_zeta_driver_start_loop();
                    printf("[ZETA] Driver message loop started\n");
                }
                // Start process monitor
                if (p_zeta_monitor_start_process_monitor) {
                    p_zeta_monitor_start_process_monitor();
                    printf("[ZETA] Process monitor started\n");
                }

                // Set new process callback for auto-scanning
                if (p_zeta_monitor_set_new_process_callback) {
                    p_zeta_monitor_set_new_process_callback(onNewProcessCreated);
                    printf("[ZETA] New process callback registered for auto-scan\n");
                }

                // Always enable lineage tracking (user-mode ETW fallback)
                if (p_zeta_monitor_lineage_enable) {
                    p_zeta_monitor_lineage_enable();
                    printf("[ZETA] Lineage tracking enabled\n");
                }

                // (TrafficAnalyzer polling thread removed)
            }
        }
    }

    // Sync driver status to UI (thread-safe via invokeMethod)
    if (p_zeta_ui_set_driver_status) {
        p_zeta_ui_set_driver_status(driverLoaded ? 1 : 0);
    }
    if (driverLoaded) {
        zeta_ui_set_status_text(L"此装置已受到防护");
        appLog(L"INFO", L"Driver", L"Driver loaded successfully");
        // Use cached driver init log (fetched before message loop started)
        if (!g_driverInitLog.empty()) {
            std::wstring cleanLog = g_driverInitLog;
            for (size_t i = 0; i < cleanLog.size(); i++) {
                if (cleanLog[i] == L'\n') cleanLog[i] = L' ';
                if (cleanLog[i] == L'\r') cleanLog[i] = L' ';
            }
            appLog(L"INFO", L"Driver", cleanLog.c_str());
            printf("[ZETA] %ws\n", g_driverInitLog.c_str());

            // Parse driver init log to sync UI status with actual driver state
            // ProcessProt=FAIL means self-protection is not supported/enabled
            if (g_driverInitLog.find(L"ProcessProt=FAIL") != std::wstring::npos) {
                zeta_ui_restore_switch(L"process_switch", 0);
                if (p_zeta_core_config_set_bool) {
                    p_zeta_core_config_set_bool(L"process_switch", 0);
                }
                appLog(L"WARN", L"Driver", L"Self-protection not supported on this system");
            }
        }
        
        appLog(L"INFO", L"Rules", L"========== Rule Loading Status ==========");

        // Set Rules_Hips.json path before loading
        if (p_zeta_hips_set_rules_path) {
            std::wstring hipsRulesPath = g_pluginsDir + L"\\Rules\\Rules_Hips.json";
            p_zeta_hips_set_rules_path(hipsRulesPath.c_str());
            appLog(L"INFO", L"HIPS", (L"Rules path: " + hipsRulesPath).c_str());
        }

        // Load user-mode HIPS rules from config and log result
        if (p_zeta_hips_load_rules) {
            appLog(L"INFO", L"HIPS", L"Loading Rules_Hips.json...");
            printf("[ZETA] Loading Rules_Hips.json...\n");
            int ruleCount = p_zeta_hips_load_rules();
            if (ruleCount > 0) {
                wchar_t msg[256];
                swprintf_s(msg, 256, L"[OK] Rules_Hips.json: Loaded (%d rules)",
                    ruleCount);
                appLog(L"INFO", L"HIPS", msg);
                printf("[ZETA] %ws\n", msg);
            } else {
                appLog(L"WARN", L"HIPS", L"[WARN] Rules_Hips.json: Not found or empty");
                printf("[ZETA] WARN: Rules_Hips.json not found or empty\n");
            }
        } else {
            appLog(L"ERROR", L"HIPS", L"[FAIL] Rules_Hips.json: DLL export not available");
            printf("[ZETA] ERROR: zeta_hips_load_rules not available\n");
        }

        // Load EDR rules
        std::wstring edrConfigPath = g_pluginsDir + L"\\Rules\\Rules_EDR.json";
        appLog(L"INFO", L"EDR", (L"Loading Rules_EDR.json from: " + edrConfigPath).c_str());
        printf("[ZETA] Loading Rules_EDR.json from: %ws\n", edrConfigPath.c_str());
        
        bool edrLoaded = false;
        int edrInitResult = 0;
        if (p_zeta_engine_init) {
            std::wstring rulesDir = g_pluginsDir + L"\\Rules";
            edrInitResult = p_zeta_engine_init(rulesDir.c_str());
            edrLoaded = (edrInitResult != 0);
        }
        
        if (edrLoaded) {
            wchar_t msg[256];
            swprintf_s(msg, 256, L"[OK] Rules_EDR.json: Loaded successfully");
            appLog(L"INFO", L"EDR", msg);
            printf("[ZETA] %ws\n", msg);
        } else {
            wchar_t msg[256];
            swprintf_s(msg, 256, L"[WARN] Rules_EDR.json: Using defaults (init=%d)", edrInitResult);
            appLog(L"WARN", L"EDR", msg);
            printf("[ZETA] %ws\n", msg);
        }
        
        appLog(L"INFO", L"Rules", L"==================================");
    }
    } catch (const std::exception& e) {
        printf("[ZETA] doDriverInstallWork exception: %s\n", e.what());
        appLog(L"ERROR", L"Driver", L"doDriverInstallWork crashed");
    } catch (...) {
        printf("[ZETA] doDriverInstallWork crashed (SEH exception caught)\n");
        appLog(L"ERROR", L"Driver", L"doDriverInstallWork crashed (SEH)");
    }

    if (p_zeta_ui_set_driver_status) {
        p_zeta_ui_set_driver_status(driverLoaded ? 1 : 0);
    }
}

// ============================================================
// Restore UI state from config
// ============================================================
void restoreUiState() {
    appLog(L"INFO", L"App", L"Restoring UI state from config");

    // Restore theme
    zeta_ui_set_theme(L"system_switch");
    zeta_ui_restore_combo(L"theme", L"system_switch");

    // Restore settings switches (lineage, ransom, learning)
    const wchar_t* switches[] = {
        L"lineage_switch", L"ransom_exp_switch",
        L"learning_switch"
    };
    for (const auto& key : switches) {
        int val = 1;
        if (p_zeta_core_config_get_bool) {
            val = p_zeta_core_config_get_bool(key, 1);
        }
        zeta_ui_restore_switch(key, val);
    }
}

// ============================================================
// Admin elevation + driver install
// ============================================================
static bool isAdmin() {
    BOOL isElevated = FALSE;
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION tokenInfo;
        DWORD size = sizeof(tokenInfo);
        if (GetTokenInformation(hToken, TokenElevation, &tokenInfo, size, &size)) {
            isElevated = tokenInfo.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return isElevated;
}

static void ensureAdmin() {
    if (isAdmin()) {
        printf("[ZETA] Running with admin privileges\n");
        return;
    }

    printf("[ZETA] Not running as admin, requesting elevation...\n");

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.lpParameters = L"--admin";
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        printf("[ZETA] Elevation failed (error=%lu), continuing without driver\n", GetLastError());
        return;
    }

    // Exit current (non-admin) process
    printf("[ZETA] Elevated instance launched, exiting...\n");
    ExitProcess(0);
}

static bool installAndStartDriver() {
    const wchar_t* serviceName = L"ZETA_Drv";

    // Use driver path directly from Plugins\Filter (no CopyFile to System32)
    std::wstring driverPath = g_pluginsDir + L"\\Filter\\ZETA_Drv.sys";

    if (GetFileAttributesW(driverPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        printf("[ZETA] Driver not found at %S\n", driverPath.c_str());
        return false;
    }

    printf("[ZETA] Driver path: %S\n", driverPath.c_str());

    // Try to force-unload any stuck driver instance first (with 5s timeout)
    printf("[ZETA] Attempting to unload any stuck driver instance...\n");
    {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        wchar_t cmdLine[] = L"fltmc unload ZETA_Drv";
        if (CreateProcessW(L"C:\\Windows\\System32\\fltmc.exe", cmdLine,
                           nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 5000);  // 5s timeout
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
    Sleep(500);

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        printf("[ZETA] OpenSCManager failed (error=%lu)\n", GetLastError());
        return false;
    }

    // Step 2: Check if service already exists
    SC_HANDLE hSvc = OpenServiceW(hSCM, serviceName,
        SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | DELETE);
    if (hSvc) {
        // Service exists - check its state
        SERVICE_STATUS_PROCESS ssStatus;
        DWORD bytesNeeded = 0;
        if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(ssStatus), &bytesNeeded)) {
            if (ssStatus.dwCurrentState == SERVICE_RUNNING) {
                printf("[ZETA] Driver already running\n");
                CloseServiceHandle(hSvc);
                CloseServiceHandle(hSCM);
                return true;
            }
            // Stopped - try to start it
            printf("[ZETA] Driver service exists but stopped - starting...\n");
            if (StartServiceW(hSvc, 0, nullptr)) {
                printf("[ZETA] Driver started successfully\n");
                CloseServiceHandle(hSvc);
                CloseServiceHandle(hSCM);
                Sleep(1000);
                return true;
            }
            DWORD startErr = GetLastError();
            // Error 1058 = ERROR_SERVICE_DISABLED (BSOD recovery disabled the driver)
            if (startErr == 1058) {
                printf("[ZETA] Service is disabled (BSOD recovery) - re-enabling...\n");
                ChangeServiceConfigW(hSvc, SERVICE_NO_CHANGE, SERVICE_DEMAND_START,
                                     SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr,
                                     nullptr, nullptr, nullptr);
                if (StartServiceW(hSvc, 0, nullptr)) {
                    printf("[ZETA] Driver started after re-enable\n");
                    CloseServiceHandle(hSvc);
                    CloseServiceHandle(hSCM);
                    Sleep(1000);
                    return true;
                }
            }
            printf("[ZETA] StartService failed (error=%lu) - will recreate\n", startErr);
        }
        printf("[ZETA] Deleting old service...\n");
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
        for (int retry = 0; retry < 5; retry++) {
            Sleep(2000);
            SC_HANDLE hCheck = OpenServiceW(hSCM, serviceName, DELETE);
            if (!hCheck) {
                printf("[ZETA] Service deletion confirmed\n");
                break;
            }
            CloseServiceHandle(hCheck);
        }
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            printf("[ZETA] Service is marked for delete (driver stuck), trying to force unload...\n");
            _wsystem(L"fltmc unload ZETA_Drv > nul 2>&1");
            Sleep(2000);
        }
    }

    // Step 5: Create the service (with retry for ERROR_SERVICE_MARKED_FOR_DELETE 1072)
    hSvc = NULL;
    for (int retry = 0; retry < 10; retry++) {
        if (retry > 0) {
            printf("[ZETA] Retry %d: waiting for service deletion to complete...\n", retry);
            Sleep(3000);
        }

        printf("[ZETA] Creating driver service...\n");
        hSvc = CreateServiceW(
            hSCM, serviceName, serviceName, SERVICE_ALL_ACCESS,
            SERVICE_FILE_SYSTEM_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            driverPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr
        );

        if (hSvc) {
            printf("[ZETA] Service created successfully\n");
            break;
        }

        DWORD err = GetLastError();
        printf("[ZETA] CreateService failed (error=%lu)\n", err);
        if (err != ERROR_SERVICE_MARKED_FOR_DELETE) {
            CloseServiceHandle(hSCM);
            printf("[ZETA] Driver service creation failed - functionality limited\n");
            return false;
        }
        printf("[ZETA] Service still marked for delete, retrying...\n");
    }

    if (!hSvc) {
        printf("[ZETA] Failed to create driver service after retries\n");
        printf("[ZETA] Please reboot to clean up the stuck driver, then try again\n");
        CloseServiceHandle(hSCM);
        return false;
    }

    // Step 6: Set DependOnService = FltMgr (required for minifilter)
    LPCWSTR fltMgrDeps[] = { L"FltMgr", nullptr };
    ChangeServiceConfig2W(hSvc, 3 /*SERVICE_CONFIG_DEPENDENCIES*/, (LPVOID)fltMgrDeps);

    CloseServiceHandle(hSvc);

    // Step 7: Create required Filter Manager registry entries
    HKEY hKey;
    wchar_t regPath[256];
    swprintf_s(regPath, L"SYSTEM\\CurrentControlSet\\Services\\ZETA_Drv");

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, KEY_SET_VALUE | KEY_CREATE_SUB_KEY, &hKey) == ERROR_SUCCESS) {
        HKEY hParams;
        if (RegCreateKeyExW(hKey, L"Parameters", 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hParams, nullptr) == ERROR_SUCCESS) {
            DWORD val = 0;
            RegSetValueExW(hParams, L"DebugFlags", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
            val = 3;
            RegSetValueExW(hParams, L"SupportedFeatures", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
            RegCloseKey(hParams);
        }

        HKEY hInstances;
        if (RegCreateKeyExW(hKey, L"Instances", 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_CREATE_SUB_KEY, nullptr, &hInstances, nullptr) == ERROR_SUCCESS) {
            wchar_t defaultInstance[] = L"ZETA Instance";
            RegSetValueExW(hInstances, L"DefaultInstance", 0, REG_SZ, (BYTE*)defaultInstance, (DWORD)(sizeof(defaultInstance)));

            HKEY hInstance;
            if (RegCreateKeyExW(hInstances, L"ZETA Instance", 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hInstance, nullptr) == ERROR_SUCCESS) {
                wchar_t altitude[] = L"320000";
                RegSetValueExW(hInstance, L"Altitude", 0, REG_SZ, (BYTE*)altitude, (DWORD)(sizeof(altitude)));
                DWORD flags = 0;
                RegSetValueExW(hInstance, L"Flags", 0, REG_DWORD, (BYTE*)&flags, sizeof(flags));
                RegCloseKey(hInstance);
            }
            RegCloseKey(hInstances);
        }
        RegCloseKey(hKey);
    }

    // Step 8: Start the driver
    printf("[ZETA] Starting driver...\n");
    hSvc = OpenServiceW(hSCM, serviceName, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        printf("[ZETA] OpenService after create failed (error=%lu)\n", GetLastError());
        CloseServiceHandle(hSCM);
        return false;
    }

    if (!StartServiceW(hSvc, 0, nullptr)) {
        DWORD err = GetLastError();
        printf("[ZETA] StartService failed (error=%lu)\n", err);
        if (err == 190 /*ERROR_BAD_DRIVER*/) {
            printf("[ZETA] Driver may need signing or test signing mode enabled\n");
        }
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hSCM);
        return false;
    }

    printf("[ZETA] Driver started successfully\n");
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    Sleep(1000);
    return true;
}

// ============================================================
// Main
// ============================================================

static void unloadDriver() {
    const wchar_t* serviceName = L"ZETA_Drv";
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) {
        printf("[ZETA] unloadDriver: OpenSCManager failed (%lu)\n", GetLastError());
        return;
    }

    SC_HANDLE hSvc = OpenServiceW(hSCM, serviceName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_DOES_NOT_EXIST)
            printf("[ZETA] unloadDriver: OpenService failed (%lu)\n", err);
        CloseServiceHandle(hSCM);
        return;
    }

    // Try to stop the driver service
    SERVICE_STATUS ss;
    if (ControlService(hSvc, SERVICE_CONTROL_STOP, &ss)) {
        printf("[ZETA] Driver service stop signal sent\n");
        // Wait up to 3 seconds for service to stop
        for (int i = 0; i < 6; i++) {
            Sleep(500);
            SERVICE_STATUS_PROCESS ssStatus;
            DWORD bytesNeeded;
            if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(ssStatus), &bytesNeeded)) {
                if (ssStatus.dwCurrentState == SERVICE_STOPPED) {
                    printf("[ZETA] Driver service stopped\n");
                    break;
                }
            }
        }
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_NOT_ACTIVE) {
            printf("[ZETA] Driver service was not running\n");
        } else {
            printf("[ZETA] ControlService(STOP) failed (%lu)\n", err);
        }
    }

    // Delete the service
    if (DeleteService(hSvc)) {
        printf("[ZETA] Driver service deleted\n");
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            printf("[ZETA] Driver service already marked for deletion\n");
        } else {
            printf("[ZETA] DeleteService failed (%lu) - may need reboot\n", err);
        }
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
}

int main(int argc, char* argv[]) {
    HANDLE hMutex = CreateMutexA(NULL, TRUE, "ZETA_Security_SingleInstance");
    if (hMutex == NULL || GetLastError() == ERROR_ALREADY_EXISTS) {
        if (hMutex) CloseHandle(hMutex);
        printf("[ZETA] Another instance is already running, exiting...\n");
        return 0;
    }

    printf("[ZETA] ZETA Security v2.0 - C++ Edition\n");
    printf("[ZETA] Initializing...\n");

    // Initialize paths (dynamic, not hardcoded)
    initPaths();

    // Set up crash handler to catch and log crashes
    setupCrashHandler();

    // Set up console control handler to capture termination signals
    SetConsoleCtrlHandler(consoleHandler, TRUE);

    // Check for admin flag to avoid infinite re-launch
    bool alreadyElevated = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--admin") == 0) {
            alreadyElevated = true;
        }
    }

    // Ensure admin privileges
    if (!alreadyElevated) {
        ensureAdmin();
    }

    // Check for hide flag
    bool hideOnStart = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "-hide") == 0) {
            hideOnStart = true;
        }
    }

    // Set Qt plugin paths (dynamic)
    std::wstring platformsPath = g_exeDir + L"\\platforms";
    SetEnvironmentVariableW(L"QT_QPA_PLATFORM_PLUGIN_PATH", platformsPath.c_str());
    SetEnvironmentVariableW(L"QT_QPA_FONTDIR", g_exeDir.c_str());

    // Initialize Qt UI first
    printf("[ZETA] Initializing Qt UI...\n");
    if (zeta_ui_init() == 0) {
        printf("[ZETA] Failed to initialize Qt UI\n");
        return 1;
    }
    printf("[ZETA] Qt UI initialized\n");

    // Register callbacks
    zeta_ui_set_config_callback(onConfigCallback);
    zeta_ui_set_tool_callback(onToolCallback);

    // Get zeta_ui_set_driver_status function pointer
    HMODULE hUi = GetModuleHandleW(L"zeta_ui.dll");
    if (hUi) {
        p_zeta_ui_set_driver_status = (fn_zeta_ui_set_driver_status)GetProcAddress(hUi, "zeta_ui_set_driver_status");
        if (p_zeta_ui_set_driver_status) {
            printf("[ZETA] Loaded zeta_ui_set_driver_status\n");
        }
        p_zeta_ui_show_notification = (fn_zeta_ui_show_notification)GetProcAddress(hUi, "zeta_ui_show_notification");
        if (p_zeta_ui_show_notification) {
            printf("[ZETA] Loaded zeta_ui_show_notification\n");
        }
        p_zeta_ui_set_hips_response_callback = (fn_zeta_ui_set_hips_response_callback)GetProcAddress(hUi, "zeta_ui_set_hips_response_callback");
        if (p_zeta_ui_set_hips_response_callback) {
            printf("[ZETA] Loaded zeta_ui_set_hips_response_callback\n");
        }
        p_zeta_ui_show_hips_prompt = (fn_zeta_ui_show_hips_prompt)GetProcAddress(hUi, "zeta_ui_show_hips_prompt");
        if (p_zeta_ui_show_hips_prompt) {
            printf("[ZETA] Loaded zeta_ui_show_hips_prompt\n");
        }
    }

    // Load all C++ DLLs (fast, no driver install)
    if (!loadAllDlls()) {
        printf("[ZETA] WARNING: Some DLLs failed to load - functionality may be limited\n");
        appLog(L"WARN", L"App", L"Some DLLs failed to load");
    }

    // Restore UI state
    restoreUiState();

    // Show or hide window (show IMMEDIATELY, don't wait for driver)
    if (hideOnStart) {
        zeta_ui_hide();
        printf("[ZETA] Window hidden (start minimized to tray)\n");
    }
    else {
        zeta_ui_show();
        zeta_ui_set_status_text(L"正在加载驱动...");
        printf("[ZETA] Window shown\n");
    }

    // Launch async driver install in background thread (non-blocking)
    printf("[ZETA] Launching async driver install...\n");
    std::thread driverThread(doDriverInstallWork);
    driverThread.detach();

    // Event loop
    printf("[ZETA] Entering event loop\n");
    appLog(L"INFO", L"App", L"ZETA Security started");
    zeta_ui_exec();

    // Cleanup
    printf("[ZETA] Shutting down...\n");

    // 0. Shutdown Qt UI FIRST - removes tray icon and window immediately
    //    This prevents the user from clicking "退出" again during cleanup
    zeta_ui_shutdown();

    // 1. Stop background services first
    if (p_zeta_monitor_stop_process_monitor) p_zeta_monitor_stop_process_monitor();
    if (p_zeta_driver_stop_loop) p_zeta_driver_stop_loop();
    if (p_zeta_driver_disconnect) p_zeta_driver_disconnect();
    ProcessBehaviorEngine::instance().stop();
    DriverEventProcessor::instance().stop();

    // 2. Unload the kernel driver service (ZETA_Drv.sys)
    unloadDriver();

    // 3. Free C++ DLLs
    if (g_hHips) FreeLibrary(g_hHips);
    if (g_hMonitor) FreeLibrary(g_hMonitor);
    if (g_hDriver) FreeLibrary(g_hDriver);
    if (g_hEngine) FreeLibrary(g_hEngine);
    if (g_hCore) FreeLibrary(g_hCore);

    // 4. Wait for background threads to complete
    if (g_repairThread.joinable()) {
        g_repairThread.join();
    }

    // 5. (zeta_ui_shutdown already called above - UI cleanup is done)

    printf("[ZETA] Shutdown complete\n");
    return 0;
}
