#define _WIN32_WINNT 0x0601
#define WINVER 0x0601
// CMake 已通过命令行 -D 定义这两个宏, 这里加 #ifndef 守卫避免 C4005 宏重定义告警
#ifndef _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
#endif
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#include <Windows.h>
#include <Shellapi.h>
#include <TlHelp32.h>
#include <wintrust.h>
#include <softpub.h>
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

// ── 双版本构建开关 (与驱动 DriverCommon.h 保持一致) ──────────────
// Full 版（默认 1）: 解析系统调用号并下发 SSDT hook 命令 (19/20/22/24)
// Lite 版（预处理器加 ZETA_ENABLE_SSDT=0）: 跳过全部 SSDT 相关发送点
#ifndef ZETA_ENABLE_SSDT
#define ZETA_ENABLE_SSDT 1
#endif

// zeta_ui.dll 头文件 — 使用 dllimport 因为我们调用它而非定义它
#define ZETA_API __declspec(dllimport)
#include "zeta_ui_export.h"
#undef ZETA_API

// C++ DLL 头文件 — 供引用类型使用（实际调用通过 LoadLibrary）
#include <zeta_core.h>
#include <zeta_driver.h>
#include <zeta_engine.h>
#include <zeta_monitor.h>
#include <zeta_hips.h>
#include "behavior_engine.h"
#include "verdict.h"
#include "trust.h"
#include "eprot_offset_resolver.h"
#include "amsi_scanner.h"
#include "byovd_blacklist.h"   // BYOVD 已知漏洞驱动黑名单 (内容哈希 + 设备对象存活探测)
// P2-4c: 事件码统一契约 (唯一定义源)
#include "../../../Plugins/Filter/events.h"

// 前向声明: 这些函数在文件后段定义, 但被前段函数 (remediateProcess 等) 调用
static std::wstring getProcessName(unsigned long pid);
static void appendInterceptLog(const wchar_t* src, const std::wstring& proc,
                               unsigned long pid, const std::wstring& path,
                               const wchar_t* action, int score,
                               const std::wstring& detail);

// ============================================================
// 全局路径（动态，非硬编码）
// ============================================================
static std::wstring g_exeDir;       // EXE 所在目录 (如 E:\远控\zeta)
static std::wstring g_pluginsDir;   // Plugins 目录
static std::wstring g_logsDir;      // Logs 目录
static std::wstring g_configDir;    // Config 目录 (C:\ProgramData\ZETA)

// ============================================================
// 全局状态
// ============================================================
static bool g_running = true;
static std::wstring g_driverInitLog; // 缓存的驱动初始化日志（在消息循环启动前获取）

// ── P0-自杀修复: ZETA.exe 自身进程绝对豁免 ──
// ZETA 启动时自身的自检行为 (加载驱动 7010 / 写注册表 3001 / APC hook 6010 / 写配置)
// 会被行为引擎对自身 PID 累加评分, 且用户态三连豁免 (knownWindowsSystemProcess /
// trustedSystemSource / isSignedProcess) 对 ZETA.exe 自身全部失效, 导致启动时
// remediateProcess 把自己 SafeTerminateProcess 掉. 此全局值作为评分/告警/处置三层
// 的最终防线: pid == g_selfPid 一律不评分、不告警、不处置.
static unsigned long g_selfPid = 0;

// ============================================================
// 崩溃处理程序 — 捕获未处理异常并写入崩溃日志
// ============================================================
static LONG WINAPI crashHandler(EXCEPTION_POINTERS* ep) {
    std::wstring crashPath = g_logsDir + L"\\ZETA_CRASH.log";
    HANDLE hCrash = CreateFileW(crashPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hCrash != INVALID_HANDLE_VALUE) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char buf[8192];
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

        // ── 解析崩溃地址所在的模块名 ──
        HMODULE hMod = NULL;
        if (GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                (LPCWSTR)ep->ExceptionRecord->ExceptionAddress, &hMod)) {
            wchar_t modPath[MAX_PATH] = {0};
            DWORD modLen = GetModuleFileNameW(hMod, modPath, MAX_PATH);
            if (modLen > 0) {
                // 提取文件名（不含路径）
                wchar_t* modName = modPath;
                for (DWORD i = modLen - 1; i > 0; i--) {
                    if (modPath[i] == L'\\' || modPath[i] == L'/') {
                        modName = &modPath[i + 1];
                        break;
                    }
                }
                ULONG_PTR offset = (ULONG_PTR)ep->ExceptionRecord->ExceptionAddress
                                 - (ULONG_PTR)hMod;
                n += sprintf_s(buf + n, sizeof(buf) - n,
                    "Module: %S (base=0x%p, offset=0x%IX)\n",
                    modName, (void*)hMod, offset);
            }
        } else {
            n += sprintf_s(buf + n, sizeof(buf) - n,
                "Module: <unknown>\n");
        }

        if (ep->ExceptionRecord->NumberParameters > 0) {
            n += sprintf_s(buf + n, sizeof(buf) - n, "Parameters: ");
            for (ULONG i = 0; i < ep->ExceptionRecord->NumberParameters && i < 15; i++) {
                n += sprintf_s(buf + n, sizeof(buf) - n, "0x%p ",
                    (void*)ep->ExceptionRecord->ExceptionInformation[i]);
            }
            n += sprintf_s(buf + n, sizeof(buf) - n, "\n");

            // ── 检测异常参数中是否包含可打印的字符串数据 ──
            // 常见情况：指针被字符串数据覆盖（如 wchar_t "tor"）
            for (ULONG i = 0; i < ep->ExceptionRecord->NumberParameters && i < 15; i++) {
                ULONG_PTR val = ep->ExceptionRecord->ExceptionInformation[i];
                // 尝试以 wchar_t 字符串解释（最多显示前 8 个字符）
                wchar_t wbuf[9] = {0};
                for (int j = 0; j < 8 && j < (int)sizeof(val)/2; j++) {
                    wchar_t wc = (wchar_t)((val >> (j * 16)) & 0xFFFF);
                    if (wc >= 0x20 && wc < 0x80) wbuf[j] = wc;
                    else if (wc == 0) { wbuf[j] = 0; break; }
                    else { wbuf[j] = L'?'; }
                }
                if (wbuf[0] != 0) {
                    n += sprintf_s(buf + n, sizeof(buf) - n,
                        "  Param[%lu] contains ASCII: \"%S\"\n", i, wbuf);
                }
            }
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

            // ── 检测常见寄存器中是否包含可打印的 ASCII 数据 ──
            struct RegVal { const char* name; ULONG_PTR val; };
            RegVal regs[] = {
                {"RAX", ep->ContextRecord->Rax},
                {"RBX", ep->ContextRecord->Rbx},
                {"RCX", ep->ContextRecord->Rcx},
                {"RDX", ep->ContextRecord->Rdx},
                {"R8 ", ep->ContextRecord->R8},
                {"R9 ", ep->ContextRecord->R9},
                {"R10", ep->ContextRecord->R10},
                {"R11", ep->ContextRecord->R11},
            };
            for (auto& r : regs) {
                wchar_t wbuf[9] = {0};
                for (int j = 0; j < 8 && j < (int)sizeof(r.val)/2; j++) {
                    wchar_t wc = (wchar_t)((r.val >> (j * 16)) & 0xFFFF);
                    if (wc >= 0x20 && wc < 0x80) wbuf[j] = wc;
                    else if (wc == 0) { wbuf[j] = 0; break; }
                    else { wbuf[j] = L'?'; }
                }
                if (wbuf[0] != 0) {
                    n += sprintf_s(buf + n, sizeof(buf) - n,
                        "  %s contains: \"%S\"\n", r.name, wbuf);
                }
            }
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
        // ── 原始调用栈 (每帧: 模块名+模块内偏移; 需符号名时用 WinDbg/IDA 加载对应 PDB) ──
        // wmemcpy 等 CRT 内部崩溃只能看到 faulting IP, 靠这个栈才能定位"是谁在调"。
        {
            void* frames[24] = {0};
            USHORT nFrames = RtlCaptureStackBackTrace(0, 24, frames, nullptr);
            n += sprintf_s(buf + n, sizeof(buf) - n, "Stack trace (%u frames):\n", (unsigned)nFrames);
            for (USHORT i = 0; i < nFrames && n < (int)sizeof(buf) - 256; i++) {
                HMODULE hF = NULL;
                if (GetModuleHandleExW(
                        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                        (LPCWSTR)frames[i], &hF)) {
                    wchar_t mPath[MAX_PATH] = {0};
                    if (GetModuleFileNameW(hF, mPath, MAX_PATH) > 0) {
                        wchar_t* mName = mPath;
                        for (DWORD k = (DWORD)wcslen(mPath); k > 0; k--) {
                            if (mPath[k - 1] == L'\\' || mPath[k - 1] == L'/') { mName = &mPath[k]; break; }
                        }
                        ULONG_PTR off = (ULONG_PTR)frames[i] - (ULONG_PTR)hF;
                        n += sprintf_s(buf + n, sizeof(buf) - n, "  #%u 0x%p %S+0x%IX\n",
                                       (unsigned)i, frames[i], mName, off);
                    } else {
                        n += sprintf_s(buf + n, sizeof(buf) - n, "  #%u 0x%p\n", (unsigned)i, frames[i]);
                    }
                } else {
                    n += sprintf_s(buf + n, sizeof(buf) - n, "  #%u 0x%p\n", (unsigned)i, frames[i]);
                }
            }
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
// 控制台控制处理程序 — 捕获 Ctrl+C、关闭、注销等信号
// ============================================================

// 前向声明: consoleHandler 中调用的清理函数
static void unloadNetFilter();
static void unloadDiskFilter();
static void unloadDriver();

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
    const wchar_t* reason = L"unknown";
    switch (dwCtrlType) {
        case CTRL_C_EVENT:        reason = L"CTRL+C"; break;
        case CTRL_BREAK_EVENT:    reason = L"CTRL+BREAK"; break;
        case CTRL_CLOSE_EVENT:    reason = L"Window closed / taskkill"; break;
        case CTRL_LOGOFF_EVENT:   reason = L"User logoff"; break;
        case CTRL_SHUTDOWN_EVENT: reason = L"System shutdown"; break;
    }
    printf("[ZETA] Termination signal: %ws — cleaning up...\n", reason);

    // 立即卸载驱动和服务, 防止模块残留
    unloadNetFilter();
    unloadDiskFilter();
    unloadDriver();
    printf("[ZETA] Cleanup on signal done\n");
    return FALSE;
}

static std::thread g_repairThread;

// ── NT 设备路径 → DOS 驱动器路径转换 ──
static std::wstring ntToDosPath(const std::wstring& ntPath) {
    // 构建驱动器映射
    WCHAR drives[256] = {0};
    DWORD len = GetLogicalDriveStringsW(256, drives);
    if (!len || len >= 256) return ntPath;

    // 先尝试常用映射（快速路径）
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

    // 构建完整映射并尝试匹配（以防驱动器发生变化）
    for (int i = 0; i < s_cacheCount; i++) {
        size_t prefixLen = wcslen(s_cache[i].ntPrefix);
        if (_wcsnicmp(ntPath.c_str(), s_cache[i].ntPrefix, prefixLen) == 0) {
            std::wstring result = s_cache[i].drive;
            result += &ntPath[prefixLen];
            return result;
        }
    }

    // 回退：重新扫描所有驱动器
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

    return ntPath;  // 回退：返回原始路径
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

// ============================================================
// quarantineFile — 将文件移动到隔离目录
// ============================================================
// 前向声明 (定义见后方 zeta_core.dll 加载之后): 闸门需引用
static void appLog(const wchar_t* level, const wchar_t* action, const wchar_t* detail);
static bool quarantineFile(const std::wstring& srcPath) {
    if (srcPath.empty()) return false;

    // ── 文件类型闸门 (P0-误杀修复): 仅隔离 PE 可执行文件 ──
    // .py / .js / .ts / .txt / .json 等脚本与文本文件是用户的正常文件
    // (如 MCP 桥接脚本 ce-mcp-bridge.ts), 不应被当作恶意产物隔离。
    // 行为引擎会把事件路径直接收集进 artifacts, 若不加此闸门,
    // cmd→bun run xxx.ts 这类脚本链会把用户脚本误隔离。
    // 注: 无扩展名路径 (目录等) 同样不隔离。
    {
        size_t dot = srcPath.find_last_of(L'.');
        if (dot == std::wstring::npos) {
            appLog(L"DEBUG", L"Quarantine",
                (L"跳过隔离无扩展名路径(非PE): " + srcPath).c_str());
            return false;
        }
        std::wstring ext = srcPath.substr(dot);
        for (auto& c : ext) c = (wchar_t)towlower(c);
        bool isPe = (ext == L".exe" || ext == L".dll" || ext == L".sys" ||
                     ext == L".scr" || ext == L".ocx" || ext == L".cpl");
        if (!isPe) {
            appLog(L"DEBUG", L"Quarantine",
                (L"跳过隔离非PE文件(脚本/文本/数据): " + srcPath).c_str());
            return false;
        }
    }

    // ── 系统关键文件绝对保护闸门 (P0-误杀修复) ──
    // 无论信任/签名判定结果如何，下列路径下的文件绝不隔离：
    //   System32\ / SysWOW64\ / WindowsApps\ / Program Files\ 等
    // 防止签名验证在测试签名环境下整体失效时，把 cmd/conhost/svchost
    // 等系统组件误隔离（曾导致 149 个系统/正常软件被隔离）。
    {
        std::wstring lp = srcPath;
        for (auto& c : lp) c = (wchar_t)towlower(c);
        // 去掉 \??\ 设备前缀再匹配
        if (lp.rfind(L"\\??\\", 0) == 0) lp = lp.substr(4);
        bool systemPath = false;
        static const wchar_t* protectedDirs[] = {
            L"\\system32\\", L"\\syswow64\\", L"\\windowsapps\\",
            L"\\program files\\", L"\\program files (x86)\\",
            L"\\windows\\systemapps\\"
        };
        for (const auto* d : protectedDirs) {
            if (lp.find(d) != std::wstring::npos) { systemPath = true; break; }
        }
        if (systemPath) {
            appLog(L"WARN", L"Quarantine",
                (L"拒绝隔离系统路径文件(误杀防护): " + srcPath).c_str());
            return false;
        }
    }

    // 构建隔离目录路径
    std::wstring qDir = L"C:\\ProgramData\\ZETA\\Quarantine";
    CreateDirectoryW(qDir.c_str(), nullptr);

    // 生成唯一名称：原始文件名 + 十六进制时间戳
    wchar_t timestamp[32];
    __int64 now;
    QueryPerformanceCounter((LARGE_INTEGER*)&now);
    swprintf_s(timestamp, L"%016llX", now);

    std::wstring fname;
    size_t pos = srcPath.find_last_of(L'\\');
    if (pos != std::wstring::npos)
        fname = srcPath.substr(pos + 1);
    else
        fname = srcPath;

    std::wstring destPath = qDir + L"\\" + fname + L"." + timestamp;
    std::wstring infoPath = destPath + L".info";

    // 尝试1：MoveFileEx 带延迟到重启标志（处理已锁定/正在使用的文件）
    // 即使文件仍作为可执行映像映射也可工作。
    if (MoveFileExW(srcPath.c_str(), destPath.c_str(), MOVEFILE_WRITE_THROUGH)) {
        // 成功：文件已同步移动
    }
    // 尝试2：跨卷回退（MoveFileEx 不支持跨卷操作）
    else if (CopyFileW(srcPath.c_str(), destPath.c_str(), FALSE)) {
        // 复制成功 → 尝试删除原文件。
        // 重试循环：进程在 TerminateProcess 后可能仍在关闭中，
        // 导致其 exe 文件保持锁定。在回退到重启删除之前，
        // 以短延时重试若干次。
        BOOL deleted = FALSE;
        for (int retry = 0; retry < 10; retry++) {
            deleted = DeleteFileW(srcPath.c_str());
            if (deleted) break;
            // 文件可能已被其他组件删除
            if (GetFileAttributesW(srcPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                deleted = TRUE;
                break;
            }
            Sleep(200);  // 200ms × 10 = 总共 2s 等待
        }
        if (!deleted) {
            // 所有重试均失败 → 标记为下次重启时删除
            MoveFileExW(srcPath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    } else {
        // 移动和复制均失败
        return false;
    }

    // 写入 .info 文件，记录原始路径
    HANDLE hInfo = CreateFileW(infoPath.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hInfo != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hInfo, srcPath.c_str(), (DWORD)(srcPath.size() * sizeof(wchar_t)), &written, nullptr);
        CloseHandle(hInfo);
    }

    return true;
}

// 前向声明（稍后定义，在 zeta_core.dll 加载之后）
static void appLog(const wchar_t* level, const wchar_t* action, const wchar_t* detail);

// ── DiskFilter (ZETA_DiskFilter.sys 控制设备) 前向声明 ──
// 定义在 netFilterEventLoop 之前的“磁盘过滤器用户态接口”一节
static bool diskFilterSetEnabled(bool enabled);
static bool diskFilterSetMode(int mode);        // 0=拦截 1=仅监控
static bool diskFilterRefresh();                // 重新枚举物理磁盘 (热插拔)
static bool diskFilterQueryStats(struct DiskStats* out);
static void diskFilterSyncStatus();

// ============================================================
// SafeTerminateProcess — 避免因关键进程导致蓝屏
//
// 问题：恶意软件可能调用 RtlSetProcessIsCritical()
// 将自身标记为关键系统进程。对此类进程直接调用
// TerminateProcess 会触发
// CRITICAL_PROCESS_DIED (0xEF) 蓝屏。
//
// 策略（分层）：
//   1. 查询 ProcessBreakOnTermination 标志
//   2. 如果非关键 → TerminateProcess（安全、快速）
//   3. 如果是关键 → CreateRemoteThread(ExitProcess)
//      通过 ExitProcess → NtTerminateProcess(NULL,0) 实现自我终止
//      绕过内核的 BreakOnTermination BSOD 检查。
//      kernel32!ExitProcess 在所有进程中具有相同的 VA
//      （得益于每次启动的 ASLR），因此 CreateRemoteThread 可直接工作。
// ============================================================

// BreakOnTermination 的进程信息类
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

// ── 启用 SeDebugPrivilege ──
// 让 OpenProcess(PROCESS_TERMINATE) 能打开同权限级别（管理员）的进程
static bool EnableSeDebugPrivilege() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueA(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(hToken);

    if (!ok || err != ERROR_SUCCESS) {
        return false;
    }
    return true;
}

static bool SafeTerminateProcess(DWORD pid) {
    // ── ZETA.exe 自身绝对豁免 (P0-自杀修复, 最终防线) ──
    // 覆盖所有调用路径 (remediateProcess / HIPS 手动拦截回调等):
    // 任何情况下都不允许终止自己, 防止误判链路把自己杀掉。
    if (g_selfPid != 0 && pid == g_selfPid) {
        appLog(L"WARN", L"Terminate",
            (L"拒绝终止 ZETA.exe 自身进程(自杀防护): PID=" +
             std::to_wstring(pid)).c_str());
        return false;
    }

    // 以两条路径所需的所有权限打开
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_TERMINATE |
        PROCESS_SUSPEND_RESUME,
        FALSE, pid);
    if (!hProcess) {
        // 回退：尝试最小权限直接终止
        hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!hProcess) return false;
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        return true;
    }

    // 步骤1：查询 BreakOnTermination 标志
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
        // 步骤2a：非关键进程 — 直接终止，无蓝屏风险
        BOOL ok = TerminateProcess(hProcess, 1);
        if (ok) {
            // 等待进程完全退出（最多 15 秒）。
            // TerminateProcess 是异步的 — 它通知所有线程
            // 退出，但进程对象在真正终止前仍然存活。
            // 如不等待，exe 文件将保持锁定状态，
            // 后续的 quarantineFile() 将无法删除/移动它。
            WaitForSingleObject(hProcess, 15000);
        }
        CloseHandle(hProcess);
        return ok;
    }

    // 步骤2b：关键进程 — 使用 ExitProcess 自我终止
    appLog(L"WARN", L"SafeTerm", (L"PID=" + std::to_wstring(pid) +
        L" is critical — using ExitProcess self-termination to avoid BSOD").c_str());

    // kernel32!ExitProcess 在所有进程中具有相同的 VA（每次启动的 ASLR）
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

    // CreateRemoteThread 在目标进程中调用 ExitProcess(0)。
    // ExitProcess → RtlExitUserProcess → NtTerminateProcess(NtCurrentProcess(),0)
    // 自我终止（NULL 句柄）绕过内核的 BreakOnTermination
    // 检查（该检查会触发 CRITICAL_PROCESS_DIED bugcheck）。
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        pExitProcess, (LPVOID)0, 0, NULL);
    CloseHandle(hProcess);

    if (hThread) {
        // 等待远程线程（和进程）退出
        WaitForSingleObject(hThread, 10000);
        CloseHandle(hThread);
        return true;
    }

    // CreateRemoteThread 可能在进程即将消亡或
    // 没有线程时失败。此时，进程很可能已经
    // 自行终止，这是可接受的。
    return false;
}

// P2-8: p_zeta_driver_send_cmd 提前声明（原定义在 LOAD_DLL 段，此处前移以便 remediateProcess 引用）
// 通过命令码 ZETA_CMD_ROLLBACK_MARK(18) 标记进程为 HIPS 终止（驱动在进程退出时回滚其衍生物）。
// P0-1: 原误用 cmd 8(设为 SET_PROCESS_PROTECT)导致回滚子系统失效，已改为 18。
static int (*p_zeta_driver_send_cmd)(unsigned long, const wchar_t*) = nullptr;

// ============================================================
// remediateProcess — P2-8: 统一处置闭环
//
// 将分散在 EDR 告警回调与 HIPS 回调中的
// "隔离衍生物 → 标记 HIPS 终止 → 终止进程 → 隔离主 exe（带重试）→ 审计"
// 收敛为单一入口，供两类高分判定共用，杜绝重复/冲突逻辑。
// 返回是否成功终止进程。
// ============================================================
static bool remediateProcess(unsigned long pid,
                             const std::vector<std::wstring>& artifacts,
                             const std::wstring& procPath,
                             const wchar_t* src = L"EDR") {
    std::wstring procName = getProcessName(pid);
    if (procName.empty()) procName = L"<未知进程>";

    // ── ZETA.exe 自身绝对豁免 (P0-自杀修复) ──
    // ZETA 启动时自检行为 (驱动加载/注册表/APC hook/写配置) 会被行为引擎对自身
    // PID 累加高分, 而用户态三连豁免对 ZETA.exe 自身全部失效 (不在系统进程名单、
    // 不在系统目录、自编译无签名)。此处是处置层最终防线: 永不处置自己。
    if (g_selfPid != 0 && pid == g_selfPid) {
        appLog(L"WARN", L"Remediate",
            (L"拒绝处置 ZETA.exe 自身进程(自杀防护): PID=" +
             std::to_wstring(pid) + L" " + procName).c_str());
        return false;
    }

    // ── 系统/可信进程绝对保护闸门 (P0-误杀修复) ──
    // 即使 isSafeToAutoKill 因签名验证失效返回 true，已知系统进程或来自
    // 受信任系统目录的进程也绝不终止、绝不隔离。这是防误杀的最后一道防线。
    if (TrustDecider::instance().isKnownSystemProcess(procName) || TrustDecider::instance().isTrustedSystemSource(pid)) {
        appLog(L"WARN", L"Remediate",
            (L"拒绝处置系统/可信进程(误杀防护): " + procName +
             L" PID=" + std::to_wstring(pid)).c_str());
        return false;
    }

    // 1. 先隔离衍生物（进程还在运行，衍生物未被锁定）
    for (const auto& art : artifacts) {
        if (!art.empty() && quarantineFile(art)) {
            appLog(L"WARN", L"Remediate",
                (L"已隔离衍生物: " + art).c_str());
        }
    }

    // 2. 标记进程为 HIPS 终止（驱动在进程退出时回滚其衍生物）
    //    必须在 SafeTerminateProcess 之前标记。P0-1: cmd 8→ZETA_CMD_ROLLBACK_MARK(18)
    if (p_zeta_driver_send_cmd) {
        p_zeta_driver_send_cmd(ZETA_CMD_ROLLBACK_MARK, std::to_wstring(pid).c_str());
    }

    // 3. 终止进程（等待完全退出以释放 exe 文件锁）
    bool terminated = SafeTerminateProcess(pid);

    // 4. 进程退出后，隔离主 exe（带重试等待文件锁释放）
    if (terminated) {
        for (int retry = 0; retry < 5; retry++) {
            if (!procPath.empty() && quarantineFile(procPath)) {
                appLog(L"WARN", L"Remediate",
                    (L"已隔离主文件: " + procPath).c_str());
                break;
            }
            Sleep(500);  // 等待文件锁释放
        }
    } else {
        // P0-误删修复: 处置失败(未终止)时绝不隔离主 exe。
        // 进程仍存活却移走其 exe，会造成"进程在跑、文件已丢"的坏状态
        // (bun.exe 案例: SafeTerminateProcess 失败但 quarantineFile 仍把
        //  C:\Users\时\.bun\bin\bun.exe 移走, 导致 bun 命令"不是内部或外部命令")。
        // 此时仅记录告警, 交由用户手动处理。
        appLog(L"WARN", L"Remediate",
            (L"处置失败未隔离主文件: " + procPath +
             L" (进程未终止, 保留原文件待手动处理)").c_str());
    }

    appLog(terminated ? L"WARN" : L"ERROR", L"Remediate",
        (terminated
            ? (L"处置完成: 自动终止进程 PID=" + std::to_wstring(pid))
            : (L"处置失败: 终止进程失败 PID=" + std::to_wstring(pid) +
               L"，请手动处理")).c_str());

    // ── 持久化拦截记录 (仅当真正发生处置动作) ──
    if (terminated) {
        appendInterceptLog(src, procName, pid, procPath,
            L"终止并隔离", 0,
            L"衍生物 " + std::to_wstring(artifacts.size()) + L" 项已隔离");
    } else {
        appendInterceptLog(src, procName, pid, procPath,
            L"处置失败(未终止)", 0,
            L"进程未终止，请手动处理");
    }
    return terminated;
}

// ── 驱动消息节流 ──
// 通过限制每个 (code, pid) 对的通知频率来防止 Qt 事件循环淹没
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
                return true;  // 已节流：跳过通知
            }
            g_throttleEntries[i].lastTimeMs = now;
            return false;
        }
    }
    // 新条目
    if (g_throttleCount < THROTTLE_MAX_ENTRIES) {
        g_throttleEntries[g_throttleCount].code = code;
        g_throttleEntries[g_throttleCount].pid = pid;
        g_throttleEntries[g_throttleCount].lastTimeMs = now;
        g_throttleCount++;
    }
    return false;
}

// ============================================================
// 异步任务队列（用于后台操作）
// ============================================================
static std::queue<std::function<void()>> g_taskQueue;
static std::mutex g_taskMutex;
static std::condition_variable g_taskCv;
static std::thread g_taskThread;

// ============================================================
// DLL 函数类型定义
// ============================================================

// ZETA_Core.dll
typedef void (*fn_zeta_core_init)(const wchar_t*);
typedef void (*fn_zeta_core_log)(const wchar_t*, const wchar_t*, const wchar_t*, const wchar_t*);
typedef int  (*fn_zeta_core_config_load)(const wchar_t*);
typedef int  (*fn_zeta_core_config_get_bool)(const wchar_t*, int);
typedef void (*fn_zeta_core_config_set_bool)(const wchar_t*, int);
typedef int  (*fn_zeta_core_config_save)();
// P1-1: TrustProvider 统一信任判定 (嵌入+Catalog 双通道签名验证)
typedef int  (*fn_zeta_core_trust_verify)(const wchar_t*);

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
typedef void (*fn_zeta_driver_set_msg_ctx_callback)(void*);
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
typedef int  (*fn_zeta_monitor_system_repair_exec)(const wchar_t* type);

// ZETA_Hips.dll
typedef void (*fn_zeta_hips_popup_add_rule)(const wchar_t*);
typedef int (*fn_zeta_hips_silverfox_analyze)(const wchar_t* const* files, int count,
    wchar_t* outType, int typeSize, wchar_t* outDetail, int detailSize);

// (TrafficAnalyzer 已移除)

// zeta_ui.dll
typedef void (*fn_zeta_ui_set_driver_status)(int);
typedef void (*fn_zeta_ui_show_notification)(const wchar_t*, const wchar_t*, int);
typedef void (*fn_zeta_ui_set_hips_response_callback)(void (*cb)(unsigned long, int));
typedef void (*fn_zeta_ui_show_hips_prompt)(const wchar_t*, const wchar_t*, unsigned long, int);
typedef void (*fn_zeta_ui_set_rules_path)(const wchar_t*);
// 磁盘底层防护真实状态 (attached/blocked/observed/mode/enabled/lastInfo)
typedef void (*fn_zeta_ui_set_disk_status)(int, int, int, int, int, const wchar_t*);

// ============================================================
// 已加载的 DLL 句柄
// ============================================================
static HMODULE g_hCore = nullptr;
static HMODULE g_hEngine = nullptr;
static HMODULE g_hDriver = nullptr;
static HMODULE g_hMonitor = nullptr;
static HMODULE g_hHips = nullptr;

// ============================================================
// DLL 函数指针
// ============================================================
static fn_zeta_core_log           p_zeta_core_log = nullptr;
static fn_zeta_core_config_load   p_zeta_core_config_load = nullptr;
static fn_zeta_core_config_get_bool p_zeta_core_config_get_bool = nullptr;
static fn_zeta_core_config_set_bool p_zeta_core_config_set_bool = nullptr;
static fn_zeta_core_config_save    p_zeta_core_config_save = nullptr;
static fn_zeta_core_trust_verify   p_zeta_core_trust_verify = nullptr;
static fn_zeta_engine_init         p_zeta_engine_init = nullptr;
static fn_zeta_engine_create       p_zeta_engine_create = nullptr;
static fn_zeta_engine_destroy      p_zeta_engine_destroy = nullptr;
static fn_zeta_engine_scan_file    p_zeta_engine_scan_file = nullptr;
static fn_zeta_engine_check_signature p_zeta_engine_check_signature = nullptr;
static fn_zeta_driver_connect         p_zeta_driver_connect = nullptr;
static fn_zeta_driver_disconnect      p_zeta_driver_disconnect = nullptr;
static fn_zeta_driver_is_connected    p_zeta_driver_is_connected = nullptr;
static fn_zeta_driver_set_msg_callback p_zeta_driver_set_msg_callback = nullptr;
static fn_zeta_driver_set_msg_ctx_callback p_zeta_driver_set_msg_ctx_callback = nullptr;
static fn_zeta_driver_start_loop      p_zeta_driver_start_loop = nullptr;
static fn_zeta_driver_stop_loop       p_zeta_driver_stop_loop = nullptr;

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

// (TrafficAnalyzer 函数指针已移除)
static fn_zeta_ui_set_driver_status p_zeta_ui_set_driver_status = nullptr;
static fn_zeta_ui_show_notification p_zeta_ui_show_notification = nullptr;
static fn_zeta_ui_set_hips_response_callback p_zeta_ui_set_hips_response_callback = nullptr;
static fn_zeta_ui_show_hips_prompt p_zeta_ui_show_hips_prompt = nullptr;
static fn_zeta_ui_set_rules_path p_zeta_ui_set_rules_path = nullptr;
static fn_zeta_ui_set_disk_status p_zeta_ui_set_disk_status = nullptr;

// ============================================================
// BYOVD 已知易受攻击驱动检测 —— byovd_blacklist.h 的接入层 (2026-10-02)
//
// 【与既有 BYOVD 防线的分工, 互补而非重复】
//   · ProtectFile.cpp:393 "无签名进程写 .sys → 写入期直接拒绝"
//   · 规则 byovd_unsigned_loads_driver (状态机打分, block_at=image_load)
//     —— 上面两条都以【进程无签名】为前提。所以由已签名程序释放的驱动、或事先
//        就已落在盘上、之后才被加载的驱动, 两条都不响。
//   · 本模块: 按【内容哈希】与【设备对象】判定, 与进程签名完全无关
//     ⇒ 恰好补上前两条的共同盲区。
//
// 【为什么必须两条通道都有】
//   哈希通道: 抗改名/抗换路径(内容不变), 但要先拿到一个文件路径, 依赖 7010/7014
//             事件还能送达。
//   设备通道: 不依赖任何内核事件 —— 攻击者摘掉回调之后事件本身就没了, 那时
//             只剩它能看见; 而且设备名是驱动内部硬编码的, 攻击者改不了。
// ============================================================

// ASCII 窄串 → 宽串 (不依赖 locale, 表里都是 ASCII)
static std::wstring WidenAscii(const char* s) {
    std::wstring w;
    if (!s) return w;
    for (; *s; ++s) w.push_back(static_cast<wchar_t>(static_cast<unsigned char>(*s)));
    return w;
}

// 内容哈希通道。命中返回 true 表示已处置并通知完毕, 调用方应停止后续常规流程。
static bool ReportKnownBadDriverByHash(const std::wstring& path,
                                       unsigned long pid,
                                       const wchar_t* channel) {
    const ByovdEntry* hit = nullptr;
    if (!ByovdBlacklist::MatchFileHash(path, &hit) || !hit) return false;

    const std::wstring name      = WidenAscii(hit->name);
    const std::wstring win32Path = ByovdBlacklist::NormalizeToWin32Path(path);

    appLog(L"CRITICAL", L"BYOVD",
        (L"命中已知易受攻击驱动黑名单[" + std::wstring(channel) + L"]: " + name +
         L" | 路径=" + path + L" | 加载者PID=" + std::to_wstring(pid)).c_str());

    // 反制: 隔离该 .sys。quarantineFile 自带两道安全闸(仅 PE 文件 + 拒绝系统路径),
    // 所以正常系统驱动不会被误隔离。
    const bool quarantined = quarantineFile(win32Path);

    const std::wstring title = L"检测到已知漏洞驱动 (BYOVD)";
    const std::wstring message =
        L"驱动文件命中已知易受攻击驱动黑名单:\n" + win32Path +
        L"\n\n驱动名: " + name +
        L"\n命中通道: " + channel +
        L"\n加载者 PID: " + std::to_wstring(pid) +
        L"\n\n此类驱动被用于先关闭安全软件的自我保护"
        L"(剥离 Ob 回调 / 清零 EPROCESS 保护字节), 再投递勒索载荷。"
        + (quarantined ? std::wstring(L"\n\n该驱动文件已被隔离。")
                       : std::wstring(L"\n\n隔离未执行(可能被占用或属系统路径), 请立即人工核查。"));

    if (p_zeta_ui_show_notification) {
        p_zeta_ui_show_notification(title.c_str(), message.c_str(), 2);
    }
    return true;
}

// 设备对象存活通道。没探测到就静默(这是常态)。
static void ReportLiveKnownBadDevices(const wchar_t* reason) {
    const std::vector<std::wstring> live = ByovdBlacklist::ProbeLoadedDevices();
    if (live.empty()) return;

    std::wstring joined;
    for (size_t i = 0; i < live.size(); ++i) {
        if (i) joined += L"\n";
        joined += live[i];
    }

    appLog(L"CRITICAL", L"BYOVD",
        (L"检测到正在运行的已知漏洞驱动设备对象[" + std::wstring(reason) +
         L"]: " + joined).c_str());

    const std::wstring message =
        L"本机存在【正在运行】的已知易受攻击驱动设备对象:\n" + joined +
        L"\n\n触发原因: " + reason +
        L"\n\n这类驱动可被用来关闭安全软件的自我保护"
        L"(剥离 Ob 回调 / 清零 EPROCESS 保护字节)。\n请立即排查加载者, 重启后清理。";

    if (p_zeta_ui_show_notification) {
        p_zeta_ui_show_notification(L"检测到已知漏洞驱动 (BYOVD)", message.c_str(), 2);
    }
}

// ============================================================
// 动态初始化路径
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

    // Plugins 目录 (规则统一放在 Plugins\Rules\ 下)
    g_pluginsDir = g_exeDir + L"\\Plugins";

    // Logs 目录 (使用 exe 所在目录)
    g_logsDir = g_exeDir;

    // Config 目录 (使用 ProgramData)
    wchar_t programData[MAX_PATH];
    GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);
    g_configDir = std::wstring(programData) + L"\\ZETA";

    // 创建目录（如果不存在）
    CreateDirectoryW(g_logsDir.c_str(), nullptr);
    CreateDirectoryW(g_configDir.c_str(), nullptr);

    // 初始化 VerdictWriter（创建 Verdicts\ 子目录）
    VerdictWriter::init(g_configDir);

    printf("[ZETA] Paths initialized: exe=%S, plugins=%S, config=%S\n",
           g_exeDir.c_str(), g_pluginsDir.c_str(), g_configDir.c_str());
}

// ============================================================
// 辅助：加载 DLL 并获取函数地址
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
// 应用日志
// ============================================================
static void appLog(const wchar_t* level, const wchar_t* action, const wchar_t* detail) {
    if (p_zeta_core_log) {
        p_zeta_core_log(level, L"App", action, detail);
    }
    // 同时记录到 UI（通过 Bridge 实现线程安全）
    zeta_ui_append_log(level, action, detail);
}

// ============================================================
// appendInterceptLog — 持久化拦截记录 (ZETA_Intercepts.log)
//
// 与 ZETA_CPP.log (全量调试日志) 分离，专门记录"真实拦截/处置"事件。
// 采用追加写 + 结构化 JSON 单行，程序重启后仍在磁盘上，UI 启动时加载。
// 字段: ts, src, proc, pid, path, action, score, detail, false_positive(预留)
// 线程安全: 独立 mutex，可被 EDR/HIPS/状态机 多线程回调并发调用。
// ============================================================
static std::mutex g_interceptLogMutex;
static void appendInterceptLog(const wchar_t* src, const std::wstring& proc,
                               unsigned long pid, const std::wstring& path,
                               const wchar_t* action, int score,
                               const std::wstring& detail) {
    // 1) 始终进全量调试日志（保留原行为）
    appLog(L"ALERT", src,
        (proc + L" PID=" + std::to_wstring(pid) +
         (path.empty() ? L"" : (L" [" + path + L"]")) +
         L" -> " + action +
         (score > 0 ? (L" score=" + std::to_wstring(score)) : L"")).c_str());

    // 2) 写结构化拦截记录文件（持久化，重启不丢）
    if (g_logsDir.empty()) return;
    std::wstring fpath = g_logsDir + L"\\ZETA_Intercepts.log";
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t ts[32];
    swprintf_s(ts, L"%04d-%02d-%02d %02d:%02d:%02d",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    // 简易 JSON 转义（双引号/反斜杠）
    auto jesc = [](const std::wstring& s) -> std::wstring {
        std::wstring o; o.reserve(s.size() + 8);
        for (wchar_t c : s) {
            if (c == L'"' || c == L'\\') { o += L'\\'; o += c; }
            else if (c == L'\n') o += L"\\n";
            else o += c;
        }
        return o;
    };

    std::wstring line = L"{";
    line += L"\"ts\":\"" + std::wstring(ts) + L"\",";
    line += L"\"src\":\"" + jesc(src) + L"\",";
    line += L"\"proc\":\"" + jesc(proc) + L"\",";
    line += L"\"pid\":" + std::to_wstring(pid) + L",";
    line += L"\"path\":\"" + jesc(path) + L"\",";
    line += L"\"action\":\"" + jesc(action) + L"\",";
    line += L"\"score\":" + std::to_wstring(score) + L",";
    line += L"\"detail\":\"" + jesc(detail) + L"\",";
    line += L"\"fp\":false";
    line += L"}";

    std::lock_guard<std::mutex> lock(g_interceptLogMutex);

    // 轮转: 超过 5MB 时, 把旧文件备份为 .old (只保留最近一份), 避免无限增长
    {
        HANDLE h = CreateFileW(fpath.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER sz;
            if (GetFileSizeEx(h, &sz) && sz.QuadPart > (LONGLONG)5 * 1024 * 1024) {
                CloseHandle(h);
                std::wstring old = fpath + L".old";
                // 覆盖旧备份
                DeleteFileW(old.c_str());
                CopyFileW(fpath.c_str(), old.c_str(), FALSE);
                // 截断当前文件 (重新开始累积)
                FILE* ft = nullptr;
                if (_wfopen_s(&ft, fpath.c_str(), L"w, ccs=UTF-8") == 0 && ft) {
                    fwprintf(ft, L"{\"ts\":\"%s\",\"src\":\"SYSTEM\",\"proc\":\"\",\"pid\":0,\"path\":\"\",\"action\":\"轮转\",\"score\":0,\"detail\":\"日志超过5MB,旧记录已备份至 ZETA_Intercepts.log.old\",\"fp\":false}\n", ts);
                    fclose(ft);
                }
            } else {
                CloseHandle(h);
            }
        }
    }

    FILE* f = nullptr;
    errno_t e = _wfopen_s(&f, fpath.c_str(), L"a, ccs=UTF-8");
    if (f) {
        fwprintf(f, L"%s\n", line.c_str());
        fflush(f);
        fclose(f);
    }
}

// ============================================================
// readNtdllSyscallNumber — 从 ntdll 的 Nt* stub 解析系统调用号
// 老式 stub:  4C 8B D1 B8 xx xx xx xx 0F 05 C3
// 新版 stub:  4C 8B D1 B8 xx xx xx xx F6 04 25 ... 0F 05 C3
//             (mov r10,rcx; mov eax,imm32; [CFG 检查]; syscall; ret)
// 通用解析: 先定位 syscall 指令 (0F 05)，再往前找 mov eax,imm32 (B8)
// ============================================================
static int readNtdllSyscallNumber(const char* funcName) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return -1;
    auto stub = (const unsigned char*)GetProcAddress(hNtdll, funcName);
    if (!stub) return -1;

    int syscallPos = -1;
    for (int i = 0; i < 96; i++) {
        if (stub[i] == 0x0F && stub[i + 1] == 0x05) { syscallPos = i; break; }
    }
    if (syscallPos < 0) return -1;

    for (int i = syscallPos - 1; i >= 0 && i >= syscallPos - 24; i--) {
        if (stub[i] == 0xB8) return *(const int*)(stub + i + 1);
    }
    return -1;
}

// ============================================================
// getProcessName — 从 PID 解析可执行文件名
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
// 自动扫描新创建的进程
// ============================================================
static void onNewProcessCreated(unsigned long pid, unsigned long ppid, 
                                const wchar_t* name, const wchar_t* path) {
    if (!p_zeta_engine_scan_file || !p_zeta_engine_create || !p_zeta_engine_destroy) {
        return;
    }

    // 防御：path/name 可能为 NULL，直接构造 wstring 会在 ucrtbase 崩溃
    std::wstring pathStr = (path ? path : L"");
    std::wstring nameStr = (name ? name : L"");

    // 跳过系统进程和已知安全路径
    if (pathStr.find(L"\\System32\\") != std::wstring::npos ||
        pathStr.find(L"\\SysWOW64\\") != std::wstring::npos ||
        pathStr.find(L"\\Program Files\\") != std::wstring::npos ||
        pathStr.find(L"\\Program Files (x86)\\") != std::wstring::npos) {
        return;
    }

    // 仅扫描可执行文件
    std::wstring ext;
    size_t dot = pathStr.find_last_of(L'.');
    if (dot != std::wstring::npos) {
        ext = pathStr.substr(dot);
        for (auto& c : ext) c = (wchar_t)towlower(c);
    }
    if (ext != L".exe" && ext != L".dll" && ext != L".sys") {
        // P0-逃逸修复: 畸形路径 (含换行/控制字符, 如
        // "\??\C:\...\bun.exe\ncmdline\nPID" 混合串) 会被扩展名检查
        // 判为非 PE 而直接 return → 恶意软件可构造此类路径绕过扫描。
        // 检测到路径含控制字符时, 不静默放行, 上报行为引擎"可疑"分,
        // 由评分链路审计 (低分不自动处置, 但绝不无痕通过)。
        bool malformed = false;
        for (wchar_t c : pathStr) {
            if (c == L'\n' || c == L'\r' || (c < 0x20 && c != L'\t')) {
                malformed = true;
                break;
            }
        }
        if (malformed) {
            appLog(L"WARN", L"AutoScan",
                (L"畸形路径(含控制字符)已标记可疑, 拒绝静默放行: PID=" +
                 std::to_wstring(pid) + L" " + nameStr).c_str());
            ProcessBehaviorEngine::instance().reportScanScore(pid, 10, nameStr, pathStr);
        }
        return;
    }

    // 创建扫描器并扫描
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
        // 2026-10-04: 日志级别必须与证据强度一致。
        // 原先凡 ret>0 一律记 ALERT 级 —— 于是一条 10 分的弱档命中也会在日志里
        // 写成 ALERT, 任何"数 ALERT 行"的统计(包括用户与我自己)都会被误导。
        // 现在: 引擎判为高危(ret>=3, 即存在强档命中)才记 ALERT, 其余记 INFO;
        // 真正的告警/提醒由行为引擎按累计分输出 (BehaviorAlert / BehaviorEngine)。
        appLog(ret >= 3 ? L"ALERT" : L"INFO", L"AutoScan", msg.c_str());
        
        // 2026-10-04 评分策略: 不再把 ret(0/1/3) 当严重度上报。
        // ret=3 的含义只是"存在强档命中", ret=1 只是"有命中" —— 把它映射成
        // 100/50 分正是"任意一条能力型规则命中即告警"的根源。
        // 改报【证据】: result 里带着 "Hits=N Weak=w Normal=n Strong=s | 规则名...",
        // 由行为引擎按档位加权(单条弱命中 10 分, 单条普通 45 分不告警, 单条强 100 分告警)。
        ProcessBehaviorEngine::instance().reportScanEvidence(
            pid, ret, std::wstring(result), nameStr, pathStr);
    } else if (ret < 0) {
        // P0-逃逸修复: 扫描失败 (畸形路径/不可读) 不可静默放行。
        // 恶意软件构造畸形路径 → 扫描失败 → 若只记日志不上报, 即绕过检测。
        // 上报行为引擎一个保守"可疑"分, 走评分/审计链路 (低分不自动处置,
        // 但会被记录、可在 UI 查看, 且达到阈值仍会告警)。
        std::wstring msg = L"Scan failed for " + nameStr + L": " + std::wstring(result);
        appLog(L"WARN", L"AutoScan", msg.c_str());
        ProcessBehaviorEngine::instance().reportScanScore(pid, 5, nameStr, pathStr);
    } else {
        std::wstring msg = L"Clean: PID=" + std::to_wstring(pid) + L" " + nameStr;
        appLog(L"DEBUG", L"AutoScan", msg.c_str());
    }
}

// ============================================================
// 异步系统修复工作函数
// ============================================================
static void doRepairWork() {
    zeta_ui_set_status_text(L"Running system repair...");
    appLog(L"INFO", L"Repair", L"Running system repair...");

    // ── 修复项 0：SFC 扫描 ──
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

    // ── 修复项 1：DISM ──
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

    // ── 修复项 2：清理临时文件 ──
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

    // ── 修复项 3：网络/DNS 重置 ──
    zeta_ui_set_repair_item(3, L"运行中", L"-");
    {
        _wsystem(L"ipconfig /flushdns");
        _wsystem(L"ipconfig /release");
        _wsystem(L"ipconfig /renew");
        _wsystem(L"netsh winsock reset");
        zeta_ui_set_repair_item(3, L"完成", L"DNS 缓存已刷新, Winsock 已重置");
        appLog(L"INFO", L"Repair", L"Network reset completed");
    }

    // 如果可用，运行 DLL 修复函数 (修复 zeta_monitor 的 SystemRepair: MBR/限制/文件关联/图标/IFEO/壁纸)
    if (p_zeta_monitor_system_repair_exec) {
        int fixed = p_zeta_monitor_system_repair_exec(L"all");
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
// 辅助：在后台线程中发送驱动命令
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
        } else {
            // 2026-10-04: 原先这里是【无声 no-op】—— 通道不可用时既不发送也不记录,
            // 于是"命令没发出去"与"命令发了没用"完全无法区分。文档写前备份的
            // 开关失效问题正是被这种静默吞掉的(见 pushSwitchStatesToDriver 的说明)。
            appLog(L"WARN", L"Driver",
                std::wstring(L"命令未下发(驱动通道不可用): " + std::wstring(cmdName) +
                             L" cmd=" + std::to_wstring(cmd)).c_str());
        }
    }).detach();
}

// ============================================================
// P2-1 修复 (2026-10-04): 启动时把配置里的开关状态【真正下发给驱动】
//
// 缺陷(实测): restoreUiState() 逐个开关读配置并调用 zeta_ui_restore_switch(),
//   但 UI 侧 MainWindow::onRestoreSwitch 里 blockSignals(true) —— 只回填复选框,
//   不发 toggled 信号, 于是 main.cpp 的 config 回调不触发, 驱动命令永远不发。
//   而驱动默认值是 FALSE(如 g_DocBackupEnabled)。
//   ⇒ 实测后果: Config.json 里 doc_backup_switch=true, UI 显示"已开启",
//     驱动实际却是关闭 —— 文档写前备份功能完全失效, 且开关显示与真实状态不一致。
//   ⇒ 反向后果同样存在: 驱动默认 ON 而用户手动关过的开关, 重启后 UI 显示关、
//     驱动其实还开着。
//
// 为什么必须挂在这里而不是 restoreUiState(): 驱动是【异步安装】的
//   (main 里先 restoreUiState() 才起 driverThread), 在驱动就绪前下发会失败。
//   本函数在 doDriverInstallWork 末尾(驱动已连接)调用。
//
// 为什么不用 sendDriverCmdWithRollback: 那条路径在下发失败时会把开关【回滚成 0
//   并持久化配置】。启动期一次失败就抹掉用户已保存的设置是不可接受的, 这里只发
//   并记录真实返回码。注意 ZETA_Driver 的约定是 **ret == 0 表示失败**。
// ============================================================
struct SwitchCmdEntry {
    const wchar_t* key;
    unsigned long  cmd;
    const wchar_t* name;
};

void pushSwitchStatesToDriver() {
    static const SwitchCmdEntry kMap[] = {
        { L"process_switch",           8, L"Self protection"  },
        { L"suspend_switch",           9, L"Suspend enable"   },
        { L"document_switch",         10, L"File protect"     },
        { L"system_switch",           11, L"System protect"   },
        { L"driver_switch",           12, L"Driver protect"   },
        { L"network_switch",          13, L"Network protect"  },
        { L"learning_switch",         14, L"Learning mode"    },
        { L"ransom_redirect_switch",  21, L"Ransom redirect"  },
        { L"doc_backup_switch",       26, L"Doc backup"       },
    };
    // (disk_write_switch / disk_monitor_switch 走 ZETA_DiskFilter 的独立控制设备,
    //  状态由驱动回包给 UI, 不在这条命令通道上, 故不在此下发)

    if (!p_zeta_driver_send_cmd) {
        appLog(L"WARN", L"Driver",
            L"Switch restore: 驱动命令通道不可用, 配置中的开关状态未能下发 (功能将保持驱动默认值)");
        return;
    }

    for (size_t i = 0; i < sizeof(kMap) / sizeof(kMap[0]); ++i) {
        int val = 1;   // 缺省开启, 与 restoreUiState 的取值口径一致
        if (p_zeta_core_config_get_bool) {
            val = p_zeta_core_config_get_bool(kMap[i].key, 1);
        }
        int ret = -1;
        try {
            ret = p_zeta_driver_send_cmd(kMap[i].cmd, val ? L"1" : L"0");
        } catch (...) {
            ret = -1;
        }
        std::wstring msg = std::wstring(L"Switch restore: ") + kMap[i].name +
                           L" -> " + (val ? L"1" : L"0") +
                           L" (cmd=" + std::to_wstring(kMap[i].cmd) +
                           L", ret=" + std::to_wstring(ret) +
                           L", key=" + kMap[i].key + L")";
        appLog(ret == 0 ? L"WARN" : L"INFO", L"Driver", msg.c_str());
    }
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
    
    if (ret == 0) {
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
// 回调：用户切换配置开关
// ============================================================
void __stdcall onConfigCallback(const wchar_t* key, int value) {
    appLog(L"INFO", L"Config", std::wstring(std::wstring(key) + L"=" + std::to_wstring(value)).c_str());

    // 保存到配置文件（快速操作，可同步执行）
    if (p_zeta_core_config_set_bool) {
        p_zeta_core_config_set_bool(key, value);
    }
    if (p_zeta_core_config_save) {
        p_zeta_core_config_save();
    }

    // 根据键名应用实际功能
    std::wstring keyStr = key ? key : L"";
    std::wstring statusMsg;

    // ============================================================
    // 驱动级保护开关 (同步执行，失败时回滚UI状态)
    // ============================================================

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

    // (traffic_switch 已移除)

    if (keyStr == L"learning_switch") {
        if (value) {
            sendDriverCmdWithRollback(14, L"1", L"Learning mode", L"learning_switch", 
                L"学习模式已启用", L"学习模式已禁用", L"学习模式启用失败", statusMsg);
        } else {
            sendDriverCmdAsync(14, L"0", L"Learning mode");
            statusMsg = L"学习模式已禁用";
        }
    }

    // P1-状态机: 勒索写重定向开关 (cmd 21)
    if (keyStr == L"ransom_redirect_switch") {
        sendDriverCmdAsync(21, value ? L"1" : L"0", L"Ransom redirect");
        statusMsg = value ? L"勒索重定向已启用" : L"勒索重定向已禁用";
    }

    // P0: 文档写前备份开关 (cmd 26)
    if (keyStr == L"doc_backup_switch") {
        sendDriverCmdAsync(26, value ? L"1" : L"0", L"Doc backup");
        statusMsg = value ? L"文档写前备份已启用" : L"文档写前备份已禁用";
    }

    // 磁盘底层写防护开关 (ZETA_DiskFilter.sys, 直接走独立控制设备)
    if (keyStr == L"disk_write_switch") {
        bool ok = diskFilterSetEnabled(value);
        if (!ok && value) {
            // 启用失败: 回滚 UI 状态, 并提示驱动不可用
            zeta_ui_restore_switch(L"disk_write_switch", 0);
            statusMsg = L"磁盘写防护启用失败 (ZETA_DiskFilter 未运行)";
        } else {
            statusMsg = value ? L"磁盘写防护已启用" : L"磁盘写防护已禁用";
        }
        diskFilterSyncStatus();
    }

    // 磁盘防护模式: 拦截 / 仅监控
    if (keyStr == L"disk_monitor_switch") {
        diskFilterSetMode(value ? 1 : 0);
        statusMsg = value ? L"磁盘防护已切换为仅监控(不拦截)" : L"磁盘防护已切换为拦截模式";
        diskFilterSyncStatus();
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
// DriverEventProcessor — 多线程事件处理器
//
// onDriverMessage（驱动消息线程）= 生产者
//   仅入队 → 立即返回。永不阻塞。
//
// DriverEventProcessor 工作线程 = 消费者
//   出队 → 记录日志、节流、分类、通知、评分
//
// 2001/3001 HIPS 提示仍在工作线程上运行
//（驱动在驱动线程侧等待回复；工作
//  线程显示提示 → 用户点击 → 回复发送给驱动）。
// 6002 SilverFox 签名验证在工作线程上运行（异步）。
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

    // 生产者：从 onDriverMessage 调用（消息线程）
    // 必须为 O(1) 且永不阻塞。
    void enqueue(unsigned long code, unsigned long pid,
                 const std::wstring& path, const std::wstring& action) {
        enqueueWithContext(code, pid, path, action, IrpSemantic{});
    }

    // 生产者：带 IRP 上下文的入队 (新接口)
    void enqueueWithContext(unsigned long code, unsigned long pid,
                           const std::wstring& path, const std::wstring& action,
                           const IrpSemantic& ctx) {
        if (!m_running) return;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_queue.size() < MAX_QUEUE) {
                Event evt;
                evt.code = code;
                evt.pid = pid;
                evt.path = path;
                evt.action = action;
                evt.ctx = ctx;
                m_queue.push(std::move(evt));
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
        IrpSemantic ctx;
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
            if (hasWork) {
                // P0-崩溃修复(最终防线): 事件处理线程最外层兜底。
                // processEvent 内部 (scan_file/行为引擎/VerdictWriter/路径解析)
                // 任何 C++ 异常在此被捕获, 绝不逃逸到线程边界触发 std::terminate
                // → __fastfail(FAST_FAIL_FATAL_APP_EXIT) → ucrtbase.dll c0000409 崩溃。
                // 异常事件仅记录后丢弃, 线程继续处理下一条, 保证引擎永不因单条
                // 异常事件而整体崩溃。
                try {
                    processEvent(evt);
                } catch (const std::exception& e) {
                    try {
                        std::wstring emsg(e.what(), e.what() + strlen(e.what()));
                        appLog(L"ERROR", L"EventLoop",
                            (L"事件处理异常已捕获(线程继续): code=" +
                             std::to_wstring(evt.code) + L" pid=" +
                             std::to_wstring(evt.pid) + L" " + emsg).c_str());
                    } catch (...) {
                    }
                } catch (...) {
                    appLog(L"ERROR", L"EventLoop",
                        (L"事件处理未知异常已捕获(线程继续): code=" +
                         std::to_wstring(evt.code) + L" pid=" +
                         std::to_wstring(evt.pid)).c_str());
                }
            }
        }
    }

    // ── 风险等级辅助 ──
    // 严重（>=20分）：注册表、磁盘写入 → 始终触发 HIPS
    // 高（>=15分）：exe/dll/sys 释放 → 触发 HIPS
    // 中（>=10分）：非 PE 文件释放到受保护路径 → 仅 EDR
    // 低（<10分）：文本/配置文件 → 仅 EDR
    static bool IsHighRiskFile(const std::wstring& path) {
        // 仅 PE 可执行文件触发 HIPS 弹窗。非 PE 文件（.dat, .tmp, .bin, .txt 等）
        // 在驱动层被静默允许，由 EDR 引擎评分。
        // 无扩展名的路径通常是目录（如 Norton 的 GUID 文件夹），而非可执行文件，
        // 驱动层的渐进响应已正确处理此类情况，不再视其为高风险。
        size_t dot = path.find_last_of(L'.');
        if (dot == std::wstring::npos) {
            return false;
        }
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

        // 对于 6002（SilverFox），在 ingest 之前先计算分析结果以传递详细信息
        std::wstring sfDetail;
        if (code ==  ZETA_MSG_SILVERFOX_SIGNATURE) {
            sfDetail = processSilverFoxSignature(pid, pathStr);
        }

        // 无论节流如何，始终摄入行为引擎（EDR 评分需要所有事件）
        // 使用新接口 ingestWithContext 传递 IRP 语义标签
        ProcessBehaviorEngine::instance().ingestWithContext(code, pid, pathStr, evt.ctx, sfDetail);

        // 节流：相同 (code, pid) 在 3 秒内只记录一次日志和一次 UI 通知
        // 例外(2026-10-02): 自保护完整性事件(7012/7013/7014) 不能按 (code,pid) 节流 ——
        // 驱动侧模块比对会用【同一个 pid(ZETA 自身)】连发多条【不同驱动路径】候选,
        // 按 pid 去重会把后续候选路径全部吃掉(只看到第一条)。
        // 7014 的去重改为按 path 做, 见下方 case (含 5 分钟过期)。
        bool isIntegrityEvt = (code == ZETA_MSG_SELF_INTEGRITY_FAIL ||
                               code == ZETA_MSG_KERNEL_TAMPER_SUSPECT ||
                               code == ZETA_MSG_ROGUE_DRIVER_LOADED);
        if (!isIntegrityEvt && isThrottled(code, pid)) return;

        // 7011: 内核句柄访问受保护对象 —— 内核态打开不受 Ob 访问检查约束, 我们拦不住;
        // 但绝不能混在 INFO 流水里被淹没(那等于给恶意驱动/BYOVD 一条无痕通道)。
        // 上面的 isThrottled(code,pid) 已做 3 秒去重, 不会刷屏。
        if (code == ZETA_MSG_KERNEL_HANDLE_ALERT) {
            appLog(L"WARN", L"安全告警",
                (L"内核句柄访问受保护对象(无法阻断): 目标PID=" + std::to_wstring(pid) +
                 L" 详情=" + pathStr +
                 L" —— 内核态调用者不受 Ob 保护约束, 请排查来源驱动/安全产品").c_str());
        }

        if (code !=  ZETA_MSG_SILVERFOX_SIGNATURE && code !=  ZETA_MSG_THREAD_CREATE && code !=  ZETA_MSG_THREAD_EXIT) {
            appLog(L"INFO", L"DriverMsg",
                (L"Code=" + std::to_wstring(code) + L" PID=" + std::to_wstring(pid) +
                 L" Action=" + actionStr + L" Path=" + pathStr).c_str());
        }

        // 如果完全关闭通知/弹窗，这里直接返回
        if (!p_zeta_ui_show_notification) return;

        int level = 0;
        std::wstring title;
        std::wstring message;
        bool needsUserAction = false;

        switch (code) {
            case ZETA_MSG_FILE_PROTECT:
                // ── 分层文件防护 ──
                // 高风险（PE 文件）→ 立即弹出 HIPS
                // 低风险（文本/配置/数据）→ 仅静默 EDR 评分
                if (IsHighRiskFile(pathStr)) {
                    // [降噪] 可信进程 (系统/签名/受信任目录) 释放 PE 属正常行为
                    // (安装器、IDE 编译、浏览器下载等)，直接静默放行，不弹交互窗。
                    if (!TrustDecider::instance().isSafeToAutoKill(pid)) {
                        level = 2;
                        title = L"文件防护拦截";
                        message = L"高危操作: 进程 " + std::to_wstring(pid) +
                                  L" 正在释放可执行文件到受保护路径:\n" + pathStr;
                        needsUserAction = true;

                        // ── HIPS→EDR 联动 ──
                        // 检查此事件的用户态 HIPS 规则并向 EDR 报告评分
                        HipsAction ruleAction = HipsEngine::instance().matchRule(code, getProcessName(pid), pathStr);
                        if (ruleAction == HIPS_DENY) {
                            ProcessBehaviorEngine::instance().reportHipsScore(pid,
                                HipsEngine::instance().lastMatchedScore(), code, pathStr);
                        }
                        // P1-6: HIPS_ALLOW 规则只表示"该行为放行", 不清空进程历史评分。
                    } else {
                        // 可信进程: 静默放行，加最小 EDR 评分痕迹 (不弹窗)
                        appLog(L"DEBUG", L"HIPS",
                            (L"文件防护静默放行: 可信进程 PID=" + std::to_wstring(pid) +
                             L" (" + pathStr + L")").c_str());
                        level = 0;
                    }
                } else {
                    // 低风险：静默添加到 EDR 评分，无弹窗
                    level = 0;
                }
                break;
            case ZETA_MSG_HIDDEN_PE:
                // ── 隐藏文件防御 ──
                // 无签名进程创建隐藏文件 → 自动终止 + 隔离（无弹窗）
                level = -1;
                {
                    // P3-1: 可信来源进程 (Program Files/WindowsApps 等) 或
                    // 具有效数字签名进程 创建的隐藏文件 一律视为合法
                    // (软件常用隐藏属性存配置)，跳过自动终结避免误杀 (QQ/CodeBuddy 等)。
                    if (!TrustDecider::instance().isSafeToAutoKill(pid)) {
                        appLog(L"INFO", L"EDR",
                            (L"HIDDEN FILE 跳过: 可信进程 PID=" + std::to_wstring(pid) +
                             L" (" + pathStr + L")").c_str());
                        break;
                    }

                    ProcessBehaviorEngine::instance().addPenaltyScore(pid, 50);
                    appLog(L"WARN", L"EDR",
                        (L"HIDDEN FILE auto-kill PID=" + std::to_wstring(pid) +
                         L" (" + pathStr + L") penalty+50").c_str());

                    // 在终止前解析路径 — 终止后无法
                    // 打开进程句柄查询其映像路径。
                    std::wstring dosPath = ntToDosPath(pathStr);
                    std::wstring procPath = getProcessPath(pid);

                    // 统一处置闭环（隔离衍生物 + 终止 + 隔离主 exe）
                    std::vector<std::wstring> arts = { dosPath };
                    remediateProcess(pid, arts, procPath);
                }
                break;
            case ZETA_MSG_LEARN_PATH:
                // ── 学习模式：受保护路径事件 ──
                // EDR 摄入以建立基线，无 HIPS 弹窗，无拦截
                level = -1;
                appLog(L"INFO", L"Learning",
                    (L"PID=" + std::to_wstring(pid) + L" -> " + pathStr).c_str());
                break;
            case ZETA_MSG_LEARN_HIDDEN:
                // ── 学习模式：隐藏文件事件 ──
                // 无签名进程在学习模式下创建隐藏文件
                level = -1;
                appLog(L"WARN", L"Learning",
                    (L"HIDDEN FILE PID=" + std::to_wstring(pid) + L" -> " + pathStr).c_str());
                break;
            case ZETA_MSG_REG_PROTECT:
                // ── 注册表保护 ──（始终为严重）
                // [降噪] 可信进程写注册表 (自注册 Run 键/服务) 属正常安装行为，不弹交互窗
                if (!TrustDecider::instance().isSafeToAutoKill(pid)) {
                    level = 2;
                    title = L"注册表防护拦截";
                    message = L"高危操作: 进程 " + std::to_wstring(pid) +
                              L" 正在修改受保护注册表:\n" + pathStr;
                    needsUserAction = true;
                } else {
                    appLog(L"DEBUG", L"HIPS",
                        (L"注册表防护静默放行: 可信进程 PID=" + std::to_wstring(pid) +
                         L" (" + pathStr + L")").c_str());
                    level = 0;
                }

                // ── HIPS→EDR 联动 ──
                {
                    HipsAction ruleAction = HipsEngine::instance().matchRule(code, getProcessName(pid), pathStr);
                    if (ruleAction == HIPS_DENY) {
                        ProcessBehaviorEngine::instance().reportHipsScore(pid,
                            HipsEngine::instance().lastMatchedScore(), code, pathStr);
                    }
                    // P1-6: HIPS_ALLOW 规则只表示"该行为放行", 不清空进程历史评分 (原 clearScore 会洗白历史证据)。
                }
                break;
            case ZETA_MSG_DISK_WRITE:
                // ── 磁盘写入 ──（始终为严重）
                level = 2;
                title = L"磁盘防护拦截";
                message = L"高危操作: 进程 " + std::to_wstring(pid) +
                          L" 正在尝试低层级磁盘写入 (疑似勒索/磁盘擦写器):\n" + pathStr;
                needsUserAction = true;

                // ── HIPS→EDR 联动 ──
                {
                    HipsAction ruleAction = HipsEngine::instance().matchRule(code, getProcessName(pid), pathStr);
                    if (ruleAction == HIPS_DENY) {
                        ProcessBehaviorEngine::instance().reportHipsScore(pid,
                            HipsEngine::instance().lastMatchedScore(), code, pathStr);
                    }
                    // P1-6: HIPS_ALLOW 规则只表示"该行为放行", 不清空进程历史评分 (原 clearScore 会洗白历史证据)。
                }
                break;
            case ZETA_MSG_VOLUME_DISMOUNT:
                // ── 卷卸载/锁卷拦截 (P2-4a: 从 4001 独立拆分) ──（始终为严重）
                level = 2;
                title = L"卷卸载/锁卷拦截";
                message = L"高危操作: 进程 " + std::to_wstring(pid) +
                          L" 正在尝试卸载/锁定卷 (疑似破坏数据或关闭防护):\n" + pathStr;
                needsUserAction = true;

                // ── HIPS→EDR 联动 ──
                {
                    HipsAction ruleAction = HipsEngine::instance().matchRule(code, getProcessName(pid), pathStr);
                    if (ruleAction == HIPS_DENY) {
                        ProcessBehaviorEngine::instance().reportHipsScore(pid,
                            HipsEngine::instance().lastMatchedScore(), code, pathStr);
                    }
                }
                break;
            case ZETA_MSG_DISK_WRITE_ALERT:
                // ── 磁盘擦写监控告警 (P2-4a: 原误用 7000 日志码) ──
                // 仅监控上报 (驱动不拦截), 记录 + EDR 评分, 不弹交互窗。
                appLog(L"WARN", L"DiskAlert",
                    (L"磁盘擦写监控告警 PID=" + std::to_wstring(pid) + L" -> " + pathStr).c_str());
                {
                    HipsAction ruleAction = HipsEngine::instance().matchRule(code, getProcessName(pid), pathStr);
                    if (ruleAction == HIPS_DENY) {
                        ProcessBehaviorEngine::instance().reportHipsScore(pid,
                            HipsEngine::instance().lastMatchedScore(), code, pathStr);
                    }
                }
                level = -1;
                break;
            case ZETA_MSG_REG_BAM:
                // ── BAM 注册表访问拦截 (Background Activity Moderator) ──
                // P0-4: 原事件发出后无人消费 (断层)。驱动层已 ACCESS_DENIED,
                // 这里仅记录 + HIPS 规则联动评分, 不弹交互窗。
                appLog(L"WARN", L"HIPS",
                    (L"BAM 注册表访问拦截 PID=" + std::to_wstring(pid) + L" -> " + pathStr).c_str());
                {
                    HipsAction ruleAction = HipsEngine::instance().matchRule(code, getProcessName(pid), pathStr);
                    if (ruleAction == HIPS_DENY) {
                        ProcessBehaviorEngine::instance().reportHipsScore(pid,
                            HipsEngine::instance().lastMatchedScore(), code, pathStr);
                    }
                }
                level = -1;
                break;
            case ZETA_MSG_RANSOM_HEADER_ALERT:
                // ── 勒索确认: 进程已被驱动挂起 (PsSuspendProcess), 等待用户决策 ──
                // P0 修复: 原事件无消费 case, 挂起的进程永远等不到弹窗决策。
                // 决策链: 本弹窗 → 用户点击 → hips_response_callback →
                //         ZETA_CMD_ALLOW_OP(4)=恢复进程 / DENY_OP(5)=终止进程
                level = 2;
                title = L"勒索行为确认";
                message = L"检测到勒索行为, 进程已被挂起:\nPID=" + std::to_wstring(pid) +
                          L"\n目标文件: " + pathStr +
                          L"\n\n选择[拦截]将终止该进程, 选择[允许]将恢复其运行。";
                needsUserAction = true;
                break;
            case ZETA_MSG_RANSOM_FIRST_WRITE:
            case ZETA_MSG_RANSOM_ENTROPY_WRITE:
            case ZETA_MSG_RANSOM_HONEY_TOUCH:
                // ── 勒索信号 (首写/高熵/蜜罐) 的 HIPS→EDR 联动 ──
                // P0-2/P0-5: 原 case 5001 是死链 (驱动无 5001 事件源)。
                // 真实勒索信号: 5002=首写检查, 5003=高熵写(原错报7003), 5004=蜜罐触碰。
                // 处置交由 behavior_engine 累加评分达到阈值后由 EDR 告警/处置 (level=-1 不弹窗)。
                {
                    HipsAction ruleAction = HipsEngine::instance().matchRule(code, getProcessName(pid), pathStr);
                    if (ruleAction == HIPS_DENY) {
                        ProcessBehaviorEngine::instance().reportHipsScore(pid,
                            HipsEngine::instance().lastMatchedScore(), code, pathStr);
                    }
                    // P1-6: HIPS_ALLOW 规则只表示"该行为放行", 不清空进程历史评分 (原 clearScore 会洗白历史证据)。
                }
                level = -1;
                break;
            case ZETA_MSG_CODE_INJECT:
                // ── 代码注入 / LOLBin 滥用 ──
                // 驱动 ImageLoadNotify 检测到向受保护进程加载可疑 DLL，
                // 或用户态 HIPS 规则命中高危进程 (rundll32/regsvr32/mshta 等)。
                // 处置: 允许一次 / 终止源进程。
                {
                    HipsAction ruleAction = HipsEngine::instance().matchRule(code, getProcessName(pid), pathStr);
                    if (ruleAction == HIPS_DENY) {
                        ProcessBehaviorEngine::instance().reportHipsScore(pid,
                            HipsEngine::instance().lastMatchedScore(), code, pathStr);
                    }
                    // P1-6: HIPS_ALLOW 规则只表示"该行为放行", 不清空进程历史评分 (原 clearScore 会洗白历史证据)。
                }
                level = 2;
                title = L"注入 / 高危进程";
                message = L"进程 " + getProcessName(pid) + L" (PID=" + std::to_wstring(pid) +
                          L") 触发代码注入或高危程序 (LOLBin) 检测:\n" + pathStr;
                needsUserAction = true;
                break;
            case ZETA_MSG_SILVERFOX_SIGNATURE:
                // ── SilverFox 的 HIPS→EDR 联动 ──
                {
                    HipsAction ruleAction = HipsEngine::instance().matchRule(code, getProcessName(pid), pathStr);
                    if (ruleAction == HIPS_DENY) {
                        ProcessBehaviorEngine::instance().reportHipsScore(pid,
                            HipsEngine::instance().lastMatchedScore(), code, pathStr);
                    }
                    // P1-6: HIPS_ALLOW 规则只表示"该行为放行", 不清空进程历史评分 (原 clearScore 会洗白历史证据)。
                }
                level = -1;
                break;
            case ZETA_MSG_SILVERFOX_RELEASES:
                // ── SilverFox: 进程释放 PE 文件超量 (P2-4a: 原混用 6001 被当代码注入) ──
                {
                    HipsAction ruleAction = HipsEngine::instance().matchRule(code, getProcessName(pid), pathStr);
                    if (ruleAction == HIPS_DENY) {
                        ProcessBehaviorEngine::instance().reportHipsScore(pid,
                            HipsEngine::instance().lastMatchedScore(), code, pathStr);
                    }
                }
                level = 2;
                title = L"SilverFox 行为检测";
                message = L"进程 " + getProcessName(pid) + L" (PID=" + std::to_wstring(pid) +
                          L") 短时间内释放大量可执行文件 (疑似银狐释放载荷):\n" + pathStr;
                needsUserAction = true;
                break;
            // P2-4a: 7003(勒索实验) 已废弃 — 驱动无产生源, 消费已并入 5003
            case ZETA_MSG_LINEAGE_ALERT: level = -1; break;
            case ZETA_MSG_PROCESS_CREATE: {
                // ── 进程创建（来自驱动 PsSetCreateProcessNotifyRoutineEx）──
                // Path 格式: "ImagePath(NT)\nCommandLine\nPPID"
                level = -1;

                size_t delim1 = pathStr.find(L'\n');
                if (delim1 == std::wstring::npos) break;

                std::wstring ntImagePath = pathStr.substr(0, delim1);
                std::wstring cmdLine;
                unsigned long ppid = 0;

                size_t delim2 = pathStr.find(L'\n', delim1 + 1);
                if (delim2 != std::wstring::npos) {
                    cmdLine = pathStr.substr(delim1 + 1, delim2 - delim1 - 1);
                    std::wstring ppidStr = pathStr.substr(delim2 + 1);
                    ppid = _wtoi(ppidStr.c_str());
                } else {
                    cmdLine = pathStr.substr(delim1 + 1);
                }

                std::wstring dosPath = ntToDosPath(ntImagePath);
                std::wstring procName;
                size_t pos = dosPath.find_last_of(L'\\');
                if (pos != std::wstring::npos) procName = dosPath.substr(pos + 1);

                // 截断过长的命令行方便日志阅读
                std::wstring logCmd = cmdLine;
                if (logCmd.size() > 256) { logCmd.resize(256); logCmd += L"..."; }

                appLog(L"INFO", L"ProcCreate",
                    (L"PID=" + std::to_wstring(pid) + L" PPID=" + std::to_wstring(ppid) +
                     L" " + procName + L"\n  Cmd: " + logCmd).c_str());

                // 触发自动扫描（ProcessMonitor 轮询也会触发，但回调更快）
                // 注意：LineageTracker 由 Polling ProcessMonitor 内部维护
                if (!procName.empty()) {
                    onNewProcessCreated(pid, ppid, procName.c_str(), dosPath.c_str());
                }

                // ── P5: AMSI 扫描脚本宿主命令行 (无文件攻击检测) ──
                // powershell IEX (New-Object Net.WebClient).DownloadString 等
                // 只看到 powershell.exe 启动而不知脚本内容 → 用 AMSI 补盲区。
                // 命中 → 进程 +60 分 (相当于一次 YARA 命中)。
                if (IsScriptHostProcess(procName) && !cmdLine.empty()) {
                    int ares = AmsiScanner::instance().Scan(cmdLine.c_str(), procName.c_str());
                    if (ares >= 32768) {  // AMSI_RESULT_DETECTED
                        appLog(L"WARN", L"AMSI",
                            (L"AMSI 检测到脚本载荷: " + procName +
                             L" PID=" + std::to_wstring(pid) + L" (+100分)").c_str());
                        printf("[ZETA] AMSI DETECTED: %ls PID=%lu (+100)\n",
                               procName.c_str(), pid);
                        // 2026-10-04: 显式传 100 —— 在旧的 reportScanScore 里
                        // "score>=3 → 100" 的映射下, 60 会被放大成 100, 数值与
                        // 语义都是巧合; 现在该映射已删除, 这里直接把"AMSI 检出脚本
                        // 载荷"声明为高置信单发信号(与 YaraScoreConfig::STRONG_PER_HIT
                        // 同档), 保持"单发决定性证据即告警"的行为。
                        ProcessBehaviorEngine::instance().reportScanScore(
                            pid, 100, procName, dosPath);
                    }
                }

                // 记录命令行到行为引擎的 detail 字段
                ProcessBehaviorEngine::instance().ingest(ZETA_MSG_PROCESS_CREATE, pid, dosPath, cmdLine);
                break;
            }
            case ZETA_MSG_PROCESS_EXIT: {
                // ── 进程退出通知（驱动回调，仅作参考）──
                // ProcessMonitor 轮询已覆盖退出检测，这里仅记录日志
                level = -1;
                appLog(L"DEBUG", L"ProcExit",
                    (L"PID=" + std::to_wstring(pid)).c_str());
                break;
            }
            case ZETA_MSG_THREAD_CREATE: {
                // ── 线程创建事件 ──
                // 格式: "pid,tid" (本地线程) 或 "pid,tid,R,creatorPid" (远程线程注入)
                // 注意: 跨进程创建线程在 Windows 上非常常见 (System/svchost/IDE/游戏
                // 等正常行为)，逐条弹窗误报率极高。这里不做交互弹窗，仅由行为引擎
                // ingestWithContext 对远程线程累计评分，达到阈值后由 EDR 告警弹窗。
                level = -1;

                // ── 远程线程 StartAddress 模块校验 (官方事件源, Full/Lite 通用) ──
                // Lite(去 SSDT) 下这是注入检测的主要替代: 远程线程入口若不在任何已加载
                // 模块 (MEM_IMAGE) 内 → 疑似 shellcode/手动映射注入。
                if (pathStr.find(L",R,") != std::wstring::npos) {
                    size_t c1 = pathStr.find(L',');
                    size_t c2 = pathStr.find(L',', c1 + 1);
                    if (c1 != std::wstring::npos && c2 != std::wstring::npos) {
                        DWORD tid = (DWORD)_wtoi(pathStr.substr(c1 + 1, c2 - c1 - 1).c_str());
                        HANDLE hTh = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
                        if (hTh) {
                            PVOID startAddr = nullptr;
                            // 动态加载 ntdll!NtQueryInformationThread (避免工程链接 ntdll.lib)
                            typedef LONG(NTAPI* pfnNtQIT)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                            static pfnNtQIT pNtQIT = nullptr;
                            if (!pNtQIT) {
                                HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
                                if (ntdll)
                                    pNtQIT = (pfnNtQIT)GetProcAddress(ntdll, "NtQueryInformationThread");
                            }
                            LONG qst = (pNtQIT ? pNtQIT(hTh, 9 /* ThreadQuerySetWin32StartAddress */,
                                &startAddr, sizeof(startAddr), nullptr) : -1);
                            CloseHandle(hTh);
                            if (qst >= 0 && startAddr) {
                                MEMORY_BASIC_INFORMATION mbi{};
                                if (VirtualQuery(startAddr, &mbi, sizeof(mbi)) &&
                                    mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE) {
                                    wchar_t addrHex[32];
                                    swprintf_s(addrHex, L"0x%p", startAddr);
                                    appLog(L"WARN", L"InjectDetect",
                                        (L"远程线程入口不在合法模块 (疑似注入): PID=" +
                                         std::to_wstring(pid) + L" tid=" + std::to_wstring(tid) +
                                         L" start=" + addrHex).c_str());
                                }
                            }
                        }
                    }
                }
                break;
            }
            case ZETA_MSG_IMAGE_LOAD: {
                // ── 驱动加载事件 (ZETA_MSG_IMAGE_LOAD) ──
                // pid = 加载驱动的进程，path = 驱动 .sys 路径
                // 供状态机规则 (BYOVD: 无签名进程拉起驱动) 关联判定
                level = 1;
                appLog(L"INFO", L"DriverLoad",
                    (L"PID=" + std::to_wstring(pid) + L" 加载驱动: " + pathStr).c_str());
                // 记录到行为引擎（含进程信任级别上下文）
                IrpSemantic dctx{};
                dctx.trustLevel = 0;  // 内核侧 ImageLoadNotify 未提供，行为引擎按现有 Profile 判定
                ProcessBehaviorEngine::instance().ingestWithContext(ZETA_MSG_IMAGE_LOAD, pid, pathStr, dctx, L"driver_load");

                // ── BYOVD 内容哈希比对 (2026-10-02 新增) ──
                // 刻意放在状态机之外: 哈希命中是【确定性】证据(文件内容一致),
                // 而状态机是按行为打分、且以"进程无签名"为前提。
                // 命中即处置, 并压掉下方的重复 level 分发。
                if (ReportKnownBadDriverByHash(pathStr, pid, L"7010 驱动加载")) {
                    level = 0;   // 已直接通知, 阻止下方重复弹窗
                }
                break;
            }
            // P2-4b: 7004(血统回退) 幽灵消费已删 — 驱动无产生源 (仅宏定义)
            case ZETA_MSG_LOG: level = 0; title = L"驱动日志";
                message = L"[" + actionStr + L"] " + pathStr; break;
            case ZETA_MSG_LEARNING_LOG: appLog(L"LEARN", L"LearningMode",
                (L"PID=" + std::to_wstring(pid) + L" Path=" + pathStr).c_str());
                level = 0; title = L"学习模式";
                message = L"允许活动 PID=" + std::to_wstring(pid) + L"\n" + pathStr; break;
#if ZETA_ENABLE_SSDT
            // ── SSDT 注入拦截事件 (仅 Full/SSDT 版产生; Lite 无来源, 由 7008 StartAddress 校验替代) ──
            case ZETA_MSG_APC_INJECT: {
                // ── APC 注入拦截 (NtQueueApcThread hook) ──
                // Path 格式: "SourcePid|TargetPid"，pid 即 SourcePid
                unsigned long tgtPid = 0;
                size_t bar = pathStr.find(L'|');
                if (bar != std::wstring::npos) {
                    tgtPid = (unsigned long)_wtoi(pathStr.substr(bar + 1).c_str());
                }
                level = 2;
                title = L"APC 注入拦截";
                message = L"进程 " + getProcessName(pid) + L" (PID=" + std::to_wstring(pid) +
                          L") 尝试通过 QueueUserAPC (NtQueueApcThread) 向进程 " +
                          getProcessName(tgtPid) + L" (PID=" + std::to_wstring(tgtPid) +
                          L") 注入代码，已挂起等待决策。";
                needsUserAction = true;
                break;
            }
            case ZETA_MSG_THREAD_CREATE_INJECT:
            case ZETA_MSG_WRITE_MEM_INJECT: {
                // ── 注入前置拦截记录 (NtCreateThreadEx / NtWriteVirtualMemory hook) ──
                // Path 格式: "SourcePid|TargetPid|Flag"，pid 即 SourcePid
                // Flag: 1 = 驱动已拒绝 (STATUS_ACCESS_DENIED), 0 = 仅观察放行
                unsigned long tgtPid = 0, flag = 0;
                size_t bar = pathStr.find(L'|');
                if (bar != std::wstring::npos) {
                    tgtPid = (unsigned long)_wtoi(pathStr.substr(bar + 1).c_str());
                    size_t bar2 = pathStr.find(L'|', bar + 1);
                    if (bar2 != std::wstring::npos) {
                        flag = (unsigned long)_wtoi(pathStr.substr(bar2 + 1).c_str());
                    }
                }
                const wchar_t* opName = (code ==  ZETA_MSG_THREAD_CREATE_INJECT) ? L"CreateRemoteThread (NtCreateThreadEx)"
                                                       : L"WriteProcessMemory (NtWriteVirtualMemory)";
                level = (flag == 1) ? 2 : 0;
                title = (flag == 1) ? L"注入已拦截" : L"注入行为观察";
                message = L"进程 " + getProcessName(pid) + L" (PID=" + std::to_wstring(pid) +
                          L") 尝试通过 " + opName + L" 对进程 " +
                          getProcessName(tgtPid) + L" (PID=" + std::to_wstring(tgtPid) +
                          L") " + ((flag == 1) ? L"操作已被驱动拒绝。" :
                                        L"执行跨进程操作 (已记录)。");
                appLog((flag == 1) ? L"WARN" : L"INFO", L"InjectHook",
                    (L"src=" + std::to_wstring(pid) + L" dst=" + std::to_wstring(tgtPid) +
                     L" op=" + std::wstring(opName) + L" flag=" + std::to_wstring(flag)).c_str());
                break;
            }
#endif
            // ── 自保护完整性 (7012/7013/7014) —— 2026-10-02 新增 ──
            // 背景: 驱动侧"功能探针"判定防护回调已被外部禁用(连续>=3轮), 意味着本机
            // 已存在持有任意内核写的对手(BYOVD/恶意驱动)。见 ProtectProcessDkom.cpp。
            //
            // 【两条重要的处理约束】
            //  ① 这类事件的 pid 一律是 ZETA 自身(驱动用 GlobalData.ZetaPid 上报),
            //     所以绝不能走 needsUserAction 的 HIPS 交互弹窗 —— 那个弹窗按 pid
            //     绑定 ALLOW/DENY 回传驱动, 用户点"拦截"会去终止 ZETA 自己。
            //  ② 也不能依赖下方 level>1 的通知分支 —— 那里会因"可信进程"判定
            //     (!isSafeToAutoKill) 把通知静默掉, 而 ZETA.exe 正是可信进程。
            // 因此本组 case 直接调用通知接口, 并把 level 归零阻止重复分发。
            case ZETA_MSG_SELF_INTEGRITY_FAIL:
                level = 2;
                title = L"自保护失效（严重）";
                message = L"ZETA 的防护回调已被外部禁用, 本机可能存在 BYOVD / 恶意驱动:\n"
                          + pathStr +
                          L"\n\n驱动侧已启动内核模块比对, 随后将报告可疑驱动路径。";
                appLog(L"CRITICAL", L"SelfIntegrity",
                    (L"防护组件失效: " + pathStr).c_str());

                // ── BYOVD 设备对象存活探测 (2026-10-02 新增) ──
                // 自保护回调失效正是 BYOVD 攻击的标志性时刻; 而此后 7010/7014 事件
                // 可能已经送不出来(回调被摘的另一面)。设备探测不依赖任何内核事件,
                // 是此刻仍然可用的独立通道。
                ReportLiveKnownBadDevices(L"自保护回调失效(7012)");
                if (p_zeta_ui_show_notification) {
                    p_zeta_ui_show_notification(title.c_str(), message.c_str(), level);
                }
                level = 0;   // 已直接通知, 阻止下方 level 分发重复弹窗
                break;

            case ZETA_MSG_KERNEL_TAMPER_SUSPECT:
                // 探针失效后触发模块比对的次数(计数性质, 仅记录)
                appLog(L"WARN", L"SelfIntegrity",
                    (L"内核篡改嫌疑 - 已触发模块比对: " + pathStr).c_str());
                level = 0;
                break;

            case ZETA_MSG_ROGUE_DRIVER_LOADED: {
                // 模块比对定位到的候选驱动路径。同一路径只处置一次(5 分钟过期)——
                // 之所以不用 isThrottled(code,pid): 驱动以同一 pid 连发多条不同路径。
                static std::unordered_map<std::wstring, long long> s_handledRogue;
                static std::mutex s_rogueMtx;
                bool first = false;
                {
                    std::lock_guard<std::mutex> lk(s_rogueMtx);
                    long long nowMsR = GetTickCount64();
                    auto it = s_handledRogue.find(pathStr);
                    if (it == s_handledRogue.end() || nowMsR - it->second > 300000) {
                        s_handledRogue[pathStr] = nowMsR;
                        first = true;
                    }
                    if (s_handledRogue.size() > 256) s_handledRogue.clear();
                }
                if (!first) break;

                appLog(L"CRITICAL", L"SelfIntegrity",
                    (L"可疑内核驱动(自保护失效期间新增): " + pathStr).c_str());

                // ── BYOVD 内容哈希比对 (2026-10-02 新增) ──
                // 7014 的路径来自内核 SystemModuleInformation 的 FullPathName
                // (形如 \SystemRoot\...), 哈希通道内部会先转成 Win32 路径再打开。
                // 命中时该通道已完成 CRITICAL 日志 + 隔离 + 通知, 这里直接结束,
                // 避免与下面的"可疑驱动"通知重复弹两次。
                if (ReportKnownBadDriverByHash(pathStr, pid, L"7014 可疑模块")) {
                    level = 0;
                    break;
                }

                // 反制: 隔离该 .sys。quarantineFile 自带两道安全闸 ——
                // ① 仅 PE 文件; ② 拒绝系统路径。
                // 所以正常的 System32\drivers\*.sys 不会被误隔离,
                // 只有 temp / 用户目录里就地加载的 BYOVD 驱动会命中。
                bool quarantined = quarantineFile(pathStr);
                title = L"可疑内核驱动";
                message = L"自保护失效期间检测到新增内核模块:\n" + pathStr +
                          (quarantined ? L"\n\n该驱动文件已被隔离。"
                                       : L"\n\n隔离未执行(可能被占用或属系统路径), 请人工核查。");
                appLog(quarantined ? L"CRITICAL" : L"WARN", L"SelfIntegrity",
                    ((quarantined ? L"已隔离: " : L"未隔离: ") + pathStr).c_str());
                if (p_zeta_ui_show_notification) {
                    p_zeta_ui_show_notification(title.c_str(), message.c_str(), 2);
                }
                level = 0;   // 已直接通知, 阻止下方重复分发
                break;
            }
            default: level = 0; title = L"安全通知";
                message = L"消息码: " + std::to_wstring(code) +
                         L" PID: " + std::to_wstring(pid) +
                         L" [" + actionStr + L"] " + pathStr; break;
        }

        // HIPS：仅在高/严重风险操作时显示
        // [降噪] 同一进程 10 秒内最多弹一次交互窗，避免不可信进程高频事件刷屏弹窗
        if (needsUserAction && p_zeta_ui_show_hips_prompt) {
            static std::unordered_map<unsigned long, long long> s_lastPrompt;
            static std::mutex s_promptMtx;
            long long nowMs = GetTickCount64();
            bool doPrompt = false;
            {
                std::lock_guard<std::mutex> lk(s_promptMtx);
                auto it = s_lastPrompt.find(pid);
                if (it == s_lastPrompt.end() || nowMs - it->second > 10000) {
                    s_lastPrompt[pid] = nowMs;
                    doPrompt = true;
                }
                if (s_lastPrompt.size() > 512) s_lastPrompt.clear();
            }
            if (doPrompt) {
                p_zeta_ui_show_hips_prompt(title.c_str(), message.c_str(), pid, level);
            } else {
                appLog(L"DEBUG", L"HIPS",
                    (L"弹窗节流: PID=" + std::to_wstring(pid) +
                     L" 10s 内已提示过，跳过重复弹窗").c_str());
            }
        } else if (level > 1 && p_zeta_ui_show_notification) {
            // [降噪] 可信进程的高危通知 (如签名进程的 APC 注入) 不弹窗
            if (TrustDecider::instance().isKnownSystemProcess(getProcessName(pid)) || !TrustDecider::instance().isSafeToAutoKill(pid)) {
                appLog(L"DEBUG", L"HIPS",
                    (L"高危通知静默放行: 可信进程 PID=" + std::to_wstring(pid) +
                     L" (" + title + L")").c_str());
            } else {
                p_zeta_ui_show_notification(title.c_str(), message.c_str(), level);
            }
        }
    }

    std::wstring processSilverFoxSignature(unsigned long pid, const std::wstring& pathStr) {
        // 核心逻辑：如果进程本身具有有效的数字签名，
        // 则完全跳过 SilverFox 检测。
        // 
        // SilverFox 攻击模式：无签名的恶意启动器释放
        // 已签名的合法安装程序 + 无签名恶意软件。恶意
        // 启动器本身绝不可能拥有有效签名，因为那
        // 需要窃取合法发布者的私钥。
        // 
        // 合法场景：有签名的安装程序（如 360 安装程序）
        // 释放已签名的组件 + 无签名的临时辅助程序。这是
        // 正常的，不应被标记为 SilverFox。
        // 
        // 因此：仅对无签名进程运行 SilverFox 检测。
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
            return L""; // 干净
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
// 回调：收到驱动消息（来自内核）
// ============================================================
void __stdcall onDriverMessage(unsigned long code, unsigned long pid, 
                               const wchar_t* path, const wchar_t* action) {
    // 纯生产者：仅入队，立即返回。
    DriverEventProcessor::instance().enqueue(
        code, pid,
        path ? std::wstring(path) : std::wstring(),
        action ? std::wstring(action) : std::wstring());
}

// ============================================================
// 回调：收到驱动消息（带 IRP 语义上下文）
// ============================================================
void __stdcall onDriverMessageCtx(unsigned long code, unsigned long pid,
                                   const wchar_t* path, const unsigned char* ctx, size_t ctxSize) {
    IrpSemantic semantic = {};
    if (ctx && ctxSize >= sizeof(zeta::ZETA_IRP_CONTEXT)) {
        auto irpCtx = reinterpret_cast<const zeta::ZETA_IRP_CONTEXT*>(ctx);
        semantic.opType = irpCtx->OperationType;
        semantic.trustLevel = irpCtx->TrustLevel;
        semantic.fileFlags = irpCtx->FileFlags;
        semantic.regFlags = irpCtx->RegFlags;
        semantic.scriptDepth = irpCtx->ScriptDepth;
        semantic.flags = irpCtx->Flags;
    }

    DriverEventProcessor::instance().enqueueWithContext(
        code, pid,
        path ? std::wstring(path) : std::wstring(),
        L"irp_context",
        semantic);
}

// ============================================================
// 回调：用户点击工具按钮
// ============================================================
// P1-状态机: 网络黑名单下发 (前向声明, 供 onToolCallback 使用)
static bool blockNetIp(const std::string& ip, unsigned short port);
// P1-状态机: 白名单增删 (写入驱动注册表 LearnedProcesses, 供 onToolCallback 使用)
static void whitelistAddRemove(const std::wstring& path, bool add);

void __stdcall onToolCallback(const wchar_t* tool) {
    appLog(L"INFO", L"Tool", tool);

    std::wstring toolStr = tool ? tool : L"";
    if (toolStr.empty()) return;

    // 处理实验性开关
    // (toggle_traffic 已移除)

    if (toolStr.find(L"toggle_learning:") == 0) {
        bool enabled = toolStr.find(L":1") != std::wstring::npos;
        onConfigCallback(L"learning_switch", enabled ? 1 : 0);
        return;
    }

    // P1-状态机: 网络黑名单下发 (net_block:<ip>:<port>)
    if (toolStr.find(L"net_block:") == 0) {
        std::wstring rest = toolStr.substr(9);
        size_t colon = rest.find(L':');
        std::wstring ip = (colon == std::wstring::npos) ? rest : rest.substr(0, colon);
        unsigned short port = 0;
        if (colon != std::wstring::npos) port = (unsigned short)_wtoi(rest.substr(colon + 1).c_str());
        // 显式窄化 (wchar_t→char): 仅接受 ASCII 数字/点, 避免隐式转换告警 (C4244) 与非法 IP 静默变形
        std::string ipA;
        ipA.reserve(ip.size());
        bool ipAscii = true;
        for (wchar_t wc : ip) {
            if (wc < 0 || wc > 0x7F) { ipAscii = false; break; }
            ipA.push_back(static_cast<char>(wc));
        }
        if (!ipAscii) {
            appLog(L"WARN", L"NetBlock", L"IP 含非 ASCII 字符, 已忽略");
            return;
        }
        bool ok = blockNetIp(ipA, port);
        appLog(ok ? L"INFO" : L"WARN", L"NetBlock",
            (L"下发黑名单 " + ip + L":" + std::to_wstring(port) +
             (ok ? L" 成功" : L" 失败")).c_str());
        return;
    }

    // HIPS 规则重载 (UI 勾选启用/禁用后调用)
    if (toolStr == L"hips_reload") {
        if (p_zeta_hips_reload_rules) {
            p_zeta_hips_reload_rules();
            appLog(L"INFO", L"HIPS", L"HIPS 规则已重载");
        }
        return;
    }

    // P1-状态机: 白名单增删 (whitelist_add:<path> / whitelist_remove:<path>)
    if (toolStr.find(L"whitelist_add:") == 0) {
        whitelistAddRemove(toolStr.substr(14), true);
        return;
    }
    if (toolStr.find(L"whitelist_remove:") == 0) {
        whitelistAddRemove(toolStr.substr(17), false);
        return;
    }

    // 工具操作
    if (toolStr == L"系统修复") {
        // 在后台线程中启动修复（非阻塞）
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

    // (流量监控 tool handler 已移除)

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

    // 未知工具
    appLog(L"INFO", L"Tool", std::wstring(L"Unknown tool: " + toolStr).c_str());
    zeta_ui_set_status_text(std::wstring(L"工具: " + toolStr).c_str());
}

// ============================================================
// 前向声明
// ============================================================
static bool installAndStartDriver();

// ============================================================
// 加载所有 DLL
// ============================================================
bool loadAllDlls() {
    printf("[ZETA] Loading C++ DLLs...\n");

    // 1. ZETA_Core.dll
    if (!LOAD_DLL(L"ZETA_Core.dll", g_hCore, zeta_core_log)) return false;
    LOAD_DLL(L"ZETA_Core.dll", g_hCore, zeta_core_config_get_bool);
    LOAD_DLL(L"ZETA_Core.dll", g_hCore, zeta_core_config_set_bool);
    LOAD_DLL(L"ZETA_Core.dll", g_hCore, zeta_core_config_save);
    LOAD_DLL(L"ZETA_Core.dll", g_hCore, zeta_core_config_load);
    LOAD_DLL(L"ZETA_Core.dll", g_hCore, zeta_core_trust_verify);

    // ── 初始化统一信任判定模块 (TrustDecider) ──
    TrustDecider::instance().init(
        getProcessName,
        getProcessPath,
        [](const std::wstring& path) -> int {
            if (!p_zeta_core_trust_verify) return 0;
            return p_zeta_core_trust_verify(path.c_str());
        });
    // 加载信任名单 (缺失则回退内置默认)
    std::wstring trustRulesPath = g_pluginsDir + L"\\Rules\\TrustRules.json";
    if (!TrustDecider::instance().loadRules(trustRulesPath)) {
        appLog(L"INFO", L"Trust", L"TrustRules.json 未加载, 使用内置默认信任名单");
    }

    // 先初始化核心
    // 加载配置，使 save() 有有效路径
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
    LOAD_DLL(L"ZETA_Driver.dll", g_hDriver, zeta_driver_set_msg_ctx_callback);
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
    // zeta_monitor_junk_clean_exec 尚未导出，使用回退

    // 5. ZETA_Hips.dll
    LOAD_DLL(L"ZETA_Hips.dll", g_hHips, zeta_hips_popup_add_rule);
    p_zeta_hips_silverfox_analyze = (fn_zeta_hips_silverfox_analyze)
        GetProcAddress(g_hHips, "zeta_hips_silverfox_analyze");

    // (TrafficAnalyzer 导出已移除)

    printf("[ZETA] All DLLs loaded successfully\n");

    return true;
}

// ── NetFilter 全局变量与前向声明 ──
static std::atomic<bool> g_netFilterRunning{false};
static HANDLE g_netFilterDevice = INVALID_HANDLE_VALUE;
static std::thread g_netFilterThread;
static bool installAndStartNetFilter();
static void unloadNetFilter();
static bool installAndStartDiskFilter();
static void unloadDiskFilter();
static void unloadDriver();
static void netFilterEventLoop();

// ── DiskFilter 全局变量 (函数前向声明见文件前部) ──
static std::atomic<bool> g_diskFilterRunning{false};
static HANDLE g_diskFilterDevice = INVALID_HANDLE_VALUE;
static std::thread g_diskFilterThread;
static std::mutex g_diskFilterMutex;
static void diskFilterEventLoop();

// ── 异步驱动安装（在后台运行，非阻塞） ──
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
                // M1-3: 只注册带 IRP 语义上下文的扩展回调 (onDriverMessageCtx)。
                // 内核消息始终携带 ZETA_IRP_CONTEXT; 旧 plain 回调 (onDriverMessage)
                // 仅多一个日志 action 标签但 ctx 为空, 双注册会导致每条驱动消息
                // 被 DriverEventProcessor 入队两次 → ingestWithContext 评分翻倍。
                // 行为评分依赖 evt.ctx (IrpSemantic), plain 路径的 action 标签仅
                // 影响日志可读性, 故废弃 plain 回调注册 (兼容保留导出/回调函数定义)。
                if (p_zeta_driver_set_msg_ctx_callback) {
                    p_zeta_driver_set_msg_ctx_callback(reinterpret_cast<void*>(onDriverMessageCtx));
                    printf("[ZETA] Driver context message callback registered\n");
                }
                // 注册 HIPS 响应回调（用户点击允许/拦截 → 驱动）
                // 在对话框关闭后调用；FilterSendMessage 返回很快（~μs）
                if (p_zeta_ui_set_hips_response_callback) {
                    p_zeta_ui_set_hips_response_callback([](unsigned long pid, int allow) {
                        // ── HIPS-EDR 集成 ──
                        // 用户点击允许 → 告诉 EDR 不要对该进程评分
                        if (allow) {
                            ProcessBehaviorEngine::instance().markUserAllowed(pid);
                            appLog(L"INFO", L"HIPS",
                                (L"Allow PID=" + std::to_wstring(pid) + L" (EDR: user approved → stopped scoring)").c_str());
                        }
                        // 用户点击拦截 → 告诉 EDR 添加惩罚评分
                        else {
                            ProcessBehaviorEngine::instance().addPenaltyScore(pid, 20);
                            appLog(L"INFO", L"HIPS",
                                (L"Block PID=" + std::to_wstring(pid) + L" (EDR: penalty +20)").c_str());
                        }

                        // 向驱动发送决策（ALLOW_OP=4, DENY_OP=5）
                        if (p_zeta_driver_send_cmd) {
                            unsigned long cmd = allow ? 4 : 5;
                            p_zeta_driver_send_cmd(cmd, std::to_wstring(pid).c_str());
                        }

                        // 如果拦截，终止违规进程
                        if (!allow) {
                            if (p_zeta_driver_send_cmd) {
                                p_zeta_driver_send_cmd(ZETA_CMD_ROLLBACK_MARK, std::to_wstring(pid).c_str());
                            }
                            SafeTerminateProcess(pid);
                            appLog(L"WARN", L"HIPS", (L"Terminated PID=" + std::to_wstring(pid)).c_str());
                            std::wstring p = getProcessPath(pid);
                            appendInterceptLog(L"HIPS", getProcessName(pid), pid, p,
                                L"用户拦截并终止", 0, L"用户在 HIPS 弹窗中手动拦截");
                        }
                    });
                    printf("[ZETA] HIPS response callback registered\n");
                }
                // 注册行为引擎回调
                ProcessBehaviorEngine::instance().setAlertCallback(
                    [](ULONG pid, int score, const wchar_t* reasons,
                       const std::vector<std::wstring>& artifacts) {
                        // 解析进程名称
                        std::wstring procName = getProcessName(pid);
                        if (procName.empty()) procName = L"<未知进程>";

                        // ── ZETA.exe 自身绝对豁免 (P0-自杀修复) ──
                        // 启动自检行为会给自身打分, 若此处不豁免, 分数破 130 后
                        // remediateProcess 会把自己终止掉。评分层直接拦截。
                        if (g_selfPid != 0 && pid == g_selfPid) {
                            appLog(L"DEBUG", L"BehaviorAlert",
                                (L"PID=" + std::to_wstring(pid) +
                                 L" (ZETA.exe 自身 → 已静默豁免, 不计分告警)").c_str());
                            return;
                        }

                        // ── 可信进程直接豁免 (治本降噪) ──
                        // 已知系统进程 / 受信任目录 / 有效数字签名 → 不评分、不告警、不写入判定，
                        // 彻底避免 QQ/CodeBuddy/svchost 等正常软件刷屏 (参考 isSafeToAutoKill 语义)。
                        if (TrustDecider::instance().isKnownSystemProcess(procName) || !TrustDecider::instance().isSafeToAutoKill(pid)) {
                            // 仅记一条 DEBUG 级别的静默放行记录，便于事后追溯
                            appLog(L"DEBUG", L"BehaviorAlert",
                                (L"PID=" + std::to_wstring(pid) +
                                 L" Proc=" + procName +
                                 L" Score=" + std::to_wstring(score) +
                                 L" (可信进程 → 已静默豁免, 不计分告警)").c_str());
                            return;
                        }

                        // 记录告警（始终显示在日志中）
                        appLog(L"WARN", L"BehaviorAlert",
                            (L"PID=" + std::to_wstring(pid) +
                             L" Proc=" + procName +
                             L" Score=" + std::to_wstring(score) +
                             L" Reasons=" + (reasons ? reasons : L"")).c_str());

                        // 写入判定（在 UI 操作之前 — 文件 I/O 快速且非阻塞）
                        if (reasons) {
                            Verdict v = Verdict::fromAlert(pid, score, reasons, {}, artifacts);
                            VerdictWriter::write(v);
                        }

                        // ── Safety: never auto-kill known Windows system processes ──
                        // msiexec.exe, svchost.exe etc. may accumulate high scores
                        // due to legitimate I/O patterns, but should never be terminated.
                        if (score >= 85 && TrustDecider::instance().isKnownSystemProcess(procName)) {
                            // [降噪] 已知系统进程跳过终结，不弹窗 (DEBUG 留痕)
                            appLog(L"DEBUG", L"EDR",
                                (L"跳过自动终结: 已知系统进程 " + procName +
                                 L" (PID=" + std::to_wstring(pid) +
                                 L" Score=" + std::to_wstring(score) + L")").c_str());
                            return;  // Skip auto-termination for known system processes
                        }

                        // ── P3-1: 可信来源进程 (Program Files / WindowsApps / System32 等)
                        //    或具有效数字签名 (腾讯/字节/Adobe 等) → 绝不自动终结。
                        //    QQ、CodeBuddy、各类 IDE、微软服务都属此类，行为引擎可能误判
                        //    (如 ZETA.exe 自身被打 95 分)，但这类进程是用户安装的正规软件。
                        //    仅记告警、跳过终结，交由用户手动处置。
                        if (score >= 85 && !TrustDecider::instance().isSafeToAutoKill(pid)) {
                            // [降噪] 可信进程 (签名/受信任目录) 跳过终结，不弹窗 (DEBUG 留痕)
                            appLog(L"DEBUG", L"EDR",
                                (L"跳过自动终结: 可信进程 " + procName +
                                 L" (PID=" + std::to_wstring(pid) +
                                 L" Score=" + std::to_wstring(score) + L")").c_str());
                            return;  // Skip auto-termination for trusted-source/signed processes
                        }

                        // EDR 评分 >= 130 → 确定恶意 → 终止进程
                        // 阈值从 85 提高到 130: 避免正常软件 (QQ/IDE/浏览器) 因合法行为
                        // 累积到 85 就被杀。只有真正高危的累积行为才触发自动终结。
                        bool terminated = false;
                        if (score >= 130) {
                            // 在终止进程前解析进程路径。
                            std::wstring procPath = getProcessPath(pid);

                            // 统一处置闭环（隔离衍生物 + 终止 + 隔离主 exe + 审计）
                            terminated = remediateProcess(pid, artifacts, procPath, L"EDR");
                        }

                        // 自动终结成功后 → 只读通知（无 Allow/Block 按钮，避免用户困惑）
                        // 自动终结失败后 → HIPS 交互弹窗（让用户手动决策）
                        if (score >= 85 && terminated) {
                            if (p_zeta_ui_show_notification) {
                                p_zeta_ui_show_notification(
                                    L"行为风险告警 - 已自动终结",
                                    (L"进程: " + procName +
                                     L" (PID: " + std::to_wstring(pid) + L")\n" +
                                     L"风险评分: " + std::to_wstring(score) + L"\n\n" +
                                     (reasons ? reasons : L"") + L"\n\n"
                                     L"进程已被自动终结并隔离。如确认无风险，请在设置中添加到白名单。").c_str(),
                                    2);
                            }
                        } else if (p_zeta_ui_show_hips_prompt) {
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
                        // ZETA.exe 自身绝对豁免 (P0-自杀修复): 不写判定、不弹通知
                        if (g_selfPid != 0 && pid == g_selfPid) {
                            return;
                        }
                        // 写入警告级判定（评分 30-59）
                        if (message) {
                            Verdict v = Verdict::fromAlert(pid, score, message, {}, artifacts);
                            VerdictWriter::write(v);
                        }
                        // [降噪] 可信进程 (系统/签名/受信任目录) 的"可疑行为"警告不弹窗，
                        // 避免 QQ/CodeBuddy/普通软件因合法行为打分 30+ 就频繁弹通知。
                        if (TrustDecider::instance().isKnownSystemProcess(getProcessName(pid)) || !TrustDecider::instance().isSafeToAutoKill(pid)) {
                            return;
                        }
                        // 黄色警告弹窗已移除: 判定已由上面 VerdictWriter::write 落盘,
                        // 此处仅记日志。此类告警无用户决策价值, 且容易连发刷屏。
                        appLog(L"WARN", L"BehaviorEngine",
                            (std::wstring(L"可疑行为 PID=") + std::to_wstring(pid) +
                             L" score=" + std::to_wstring(score) +
                             (message ? (std::wstring(L" | ") + message) : L"")).c_str());
                    });
                // 启动引擎维护线程（30 秒间隔）
                // P0-自杀修复: 告知引擎自身 PID, 使评分/告警/处置入口对 ZETA.exe 自身绝对豁免
                ProcessBehaviorEngine::instance().setSelfPid(g_selfPid);
                ProcessBehaviorEngine::instance().start();
                ProcessBehaviorEngine::instance().loadWhitelist(
                    L"SYSTEM\\CurrentControlSet\\Services\\ZETA_Drv\\Parameters");
                printf("[ZETA] Behavior engine initialized\n");
                // 启动事件处理器工作线程（处理所有驱动消息）
                DriverEventProcessor::instance().start();
                printf("[ZETA] Event processor started\n");
                // 启动驱动消息循环
                // 在消息循环启动前获取驱动初始化日志（启动后
                // sendCommand 走队列路径，无法获取响应）
                if (p_zeta_driver_get_init_log) {
                    const wchar_t* log = p_zeta_driver_get_init_log();
                    if (log) g_driverInitLog = log;
                }
                if (p_zeta_driver_start_loop) {
                    p_zeta_driver_start_loop();
                    printf("[ZETA] Driver message loop started\n");
                }

                // ── 下发 PDB 解析的通用内核结构偏移表 (覆盖全部硬编码偏移) ──
                // 自研 PDB 解析器从本地符号目录解析 _EPROCESS/_KTHREAD/_PEB/
                // _LDR_DATA_TABLE_ENTRY/_KLDR_DATA_TABLE_ENTRY 各字段偏移,
                // 一次下发驱动替换硬编码宏。失败则驱动回退硬编码表 (双保险)。
                {
                    KernelOffsets ko = {};
                    int n = ResolveKernelOffsets(&ko);
                    if (n > 0 && p_zeta_driver_send_cmd) {
                        // 编码 "key=value,..." 下发 (命令 25)
                        wchar_t offBuf[512];
                        swprintf_s(offBuf, 512,
                            L"Peb=%ld,TrapFrame=%ld,Rip=%ld,Ldr=%ld,"
                            L"InMemLinks=%ld,DllBase=%ld,SizeImage=%ld,BaseName=%ld,"
                            L"KldrFlags=%ld,KldrSig=%ld",
                            ko.EprocessPeb, ko.KthreadTrapFrame, ko.KtrapFrameRip, ko.PebLdr,
                            ko.LdrInMemoryLinks, ko.LdrDllBase, ko.LdrSizeOfImage, ko.LdrBaseDllName,
                            ko.KldrFlags, ko.KldrSignatureLevel);
                        int ret = p_zeta_driver_send_cmd(25, offBuf);  // ZETA_CMD_SET_KERNEL_OFFSETS
                        appLog(L"INFO", L"PPL",
                            (L"Kernel offsets PDB-resolved: " + std::to_wstring(n) +
                             L" fields, sent=" + std::to_wstring(ret)).c_str());
                        printf("[ZETA] Kernel offsets PDB-resolved: %d fields, sent: %s\n",
                               n, ret ? "OK" : "FAILED");

                        // Protection 单独下发 (命令 23, 兼容 PPL DKOM 注册表缓存)
                        if (ko.EprocessProtection > 0) {
                            wchar_t protBuf[32];
                            wsprintfW(protBuf, L"%ld", ko.EprocessProtection);
                            p_zeta_driver_send_cmd(23, protBuf);
                            printf("[ZETA] PPL offset 0x%lX (PDB) sent to driver: OK\n",
                                   ko.EprocessProtection);
                        }
                    } else {
                        appLog(L"INFO", L"PPL",
                            L"Kernel offsets PDB resolve failed - driver uses hardcoded table");
                        printf("[ZETA] WARN: Kernel offsets PDB resolve failed, driver falls back to hardcoded table\n");
                    }
                }

#if ZETA_ENABLE_SSDT
                // ── 启用 APC 注入 hook (NtQueueApcThread) ──
                // 从 ntdll stub 解析系统调用号 (构建无关)。
                // validate 用 NtQuerySystemInformation 而非 NtCreateFile：
                // Win10 22H2 的 NtCreateFile 是被 Windows 转成"慢路径"stub
                // (无 0F 05 syscall 指令)，readNtdllSyscallNumber 会返回 -1。
                if (p_zeta_driver_send_cmd) {
                    int apcSysno = readNtdllSyscallNumber("NtQueueApcThread");
                    int validSysno = readNtdllSyscallNumber("NtQuerySystemInformation");
                    if (apcSysno >= 0 && validSysno >= 0) {
                        wchar_t apcBuf[32];
                        wsprintfW(apcBuf, L"%d,%d", apcSysno, validSysno);
                        int ret = p_zeta_driver_send_cmd(19, apcBuf);  // ZETA_CMD_SET_APC_HOOK
                        appLog(L"INFO", L"APC",
                            (L"APC hook cmd: syscall=" + std::to_wstring(apcSysno) +
                             L" validate=" + std::to_wstring(validSysno) +
                             L" ret=" + std::to_wstring(ret)).c_str());
                    } else {
                        appLog(L"WARN", L"APC", L"无法解析 NtQueueApcThread 系统调用号，APC hook 未启用");
                    }
                }
#endif
                // 启动进程监控
                if (p_zeta_monitor_start_process_monitor) {
                    p_zeta_monitor_start_process_monitor();
                    printf("[ZETA] Process monitor started\n");
                }

#if ZETA_ENABLE_SSDT
                // ── 启用卸载守卫 (NtUnloadDriver) ──
                // P0-2: 防止 sc stop / fltmc unload 卸载 ZETA_Drv
                // validate 同样用 NtQuerySystemInformation（NtCreateFile 在 22H2 无 syscall stub）
                if (p_zeta_driver_send_cmd) {
                    int unloadSysno = readNtdllSyscallNumber("NtUnloadDriver");
                    int validSysno2 = readNtdllSyscallNumber("NtQuerySystemInformation");
                    if (unloadSysno >= 0 && validSysno2 >= 0) {
                        wchar_t unloadBuf[32];
                        wsprintfW(unloadBuf, L"%d,%d", unloadSysno, validSysno2);
                        int ret = p_zeta_driver_send_cmd(20, unloadBuf);  // ZETA_CMD_SET_UNLOAD_GUARD
                        appLog(L"INFO", L"UnloadGuard",
                            (L"UnloadGuard cmd: syscall=" + std::to_wstring(unloadSysno) +
                             L" validate=" + std::to_wstring(validSysno2) +
                             L" ret=" + std::to_wstring(ret)).c_str());
                    } else {
                        appLog(L"WARN", L"UnloadGuard", L"无法解析 NtUnloadDriver 系统调用号，卸载守卫未启用");
                    }
                }
#endif

#if ZETA_ENABLE_SSDT
                // ── 启用注入前置拦截 (NtCreateThreadEx + NtWriteVirtualMemory) ──
                // P0: 远程线程注入/跨进程内存写入的前置 SSDT 拦截。
                // validate 用 NtQuerySystemInformation (与 APC hook 一致)。
                if (p_zeta_driver_send_cmd) {
                    int ctSysno = readNtdllSyscallNumber("NtCreateThreadEx");
                    int wmSysno = readNtdllSyscallNumber("NtWriteVirtualMemory");
                    int unmapSysno = readNtdllSyscallNumber("NtUnmapViewOfSection");
                    int validSysno3 = readNtdllSyscallNumber("NtQuerySystemInformation");
                    if (ctSysno >= 0 && wmSysno >= 0 && unmapSysno >= 0 && validSysno3 >= 0) {
                        wchar_t injectBuf[64];
                        wsprintfW(injectBuf, L"%d,%d,%d,%d", ctSysno, wmSysno, unmapSysno, validSysno3);
                        int ret = p_zeta_driver_send_cmd(22, injectBuf);  // ZETA_CMD_SET_INJECT_HOOK
                        appLog(L"INFO", L"InjectHook",
                            (L"InjectHook cmd: ct=" + std::to_wstring(ctSysno) +
                             L" wm=" + std::to_wstring(wmSysno) +
                             L" unmap=" + std::to_wstring(unmapSysno) +
                             L" validate=" + std::to_wstring(validSysno3) +
                             L" ret=" + std::to_wstring(ret)).c_str());
                    } else {
                        appLog(L"WARN", L"InjectHook",
                            L"无法解析注入 syscall 号 (NtCreateThreadEx/NtWriteVirtualMemory/NtUnmapViewOfSection)，注入拦截未启用");
                    }
                }
#endif

                // 设置新进程回调以进行自动扫描
                if (p_zeta_monitor_set_new_process_callback) {
                    p_zeta_monitor_set_new_process_callback(onNewProcessCreated);
                    printf("[ZETA] New process callback registered for auto-scan\n");
                }

                // 始终启用血统追踪
                if (p_zeta_monitor_lineage_enable) {
                    p_zeta_monitor_lineage_enable();
                    printf("[ZETA] Lineage tracking enabled\n");
                }

                // 始终启用勒索软件检测
                sendDriverCmdAsync(7, L"1", L"Ransom exp");
                // P1-状态机: 开启勒索写重定向 (写隔离副本, 原文件保留)
                sendDriverCmdAsync(21, L"1", L"Ransom redirect");

                // (TrafficAnalyzer 轮询线程已移除)
            }
        }
    }

    // ── 安装并启动网络过滤器驱动 (独立 Legacy WDM) ──
    if (installAndStartNetFilter()) {
        g_netFilterRunning = true;
        g_netFilterThread = std::thread(netFilterEventLoop);
        appLog(L"INFO", L"NetFilter", L"ZETA_NetFilter started");
    } else {
        appLog(L"WARN", L"NetFilter", L"ZETA_NetFilter not available");
    }

    // ── 安装并启动磁盘过滤器驱动 (纯 WDM, 拦截 MBR/GPT 写入) ──
    if (installAndStartDiskFilter()) {
        appLog(L"INFO", L"DiskFilter", L"ZETA_DiskFilter started");
        g_diskFilterRunning = true;
        g_diskFilterThread = std::thread(diskFilterEventLoop);
    } else {
        appLog(L"WARN", L"DiskFilter", L"ZETA_DiskFilter not available");
    }

    // 同步驱动状态到 UI（通过 invokeMethod 实现线程安全）
    if (p_zeta_ui_set_driver_status) {
        p_zeta_ui_set_driver_status(driverLoaded ? 1 : 0);
    }
    if (driverLoaded) {
        zeta_ui_set_status_text(L"此装置已受到防护");
        appLog(L"INFO", L"Driver", L"Driver loaded successfully");
        // 使用缓存的驱动初始化日志（在消息循环启动前获取）
        if (!g_driverInitLog.empty()) {
            std::wstring cleanLog = g_driverInitLog;
            for (size_t i = 0; i < cleanLog.size(); i++) {
                if (cleanLog[i] == L'\n') cleanLog[i] = L' ';
                if (cleanLog[i] == L'\r') cleanLog[i] = L' ';
            }
            appLog(L"INFO", L"Driver", cleanLog.c_str());
            printf("[ZETA] %ws\n", g_driverInitLog.c_str());

            // 解析驱动初始化日志，使 UI 状态与实际驱动状态同步
            // ProcessProt=FAIL 表示本系统不支持/未启用自我保护
            if (g_driverInitLog.find(L"ProcessProt=FAIL") != std::wstring::npos) {
                zeta_ui_restore_switch(L"process_switch", 0);
                if (p_zeta_core_config_set_bool) {
                    p_zeta_core_config_set_bool(L"process_switch", 0);
                }
                appLog(L"WARN", L"Driver", L"Self-protection not supported on this system");
            }
        }
        
        appLog(L"INFO", L"Rules", L"========== Rule Loading Status ==========");

        // 在加载前设置 Rules_Hips.json 路径
        if (p_zeta_hips_set_rules_path) {
            std::wstring hipsRulesPath = g_pluginsDir + L"\\Rules\\Rules_Hips.json";
            p_zeta_hips_set_rules_path(hipsRulesPath.c_str());
            appLog(L"INFO", L"HIPS", (L"Rules path: " + hipsRulesPath).c_str());
        }

        // 从配置加载用户态 HIPS 规则并记录结果
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

        // 加载 EDR 规则
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

        // ── 第4层上下文评分配置 (Rules_Context.json) ──
        {
            std::wstring ctxPath = g_pluginsDir + L"\\Rules\\Rules_Context.json";
            ProcessBehaviorEngine::instance().loadContextConfig(ctxPath);
            appLog(L"INFO", L"EDR",
                (L"Rules_Context.json: context score weights loaded: " + ctxPath).c_str());
            printf("[ZETA] Rules_Context.json: context score weights loaded\n");
        }

        // ── P1-状态机: 加载两层规则 + 设置命中回调 ──
        {
            std::wstring condPath = g_pluginsDir + L"\\Rules\\Rules_Conditions.json";
            std::wstring compPath = g_pluginsDir + L"\\Rules\\Rules_Compose.json";
            ProcessBehaviorEngine::instance().loadStateMachineRules(condPath, compPath);
            ProcessBehaviorEngine::instance().setStateMachineCallback(
                [](unsigned long pid, const wchar_t* ruleId, const wchar_t* ruleName,
                   int action, int score, const wchar_t* blockAt,
                   const wchar_t* redirectTo, long long windowMs) {
                    std::wstring rid = ruleId ? ruleId : L"";
                    std::wstring rn = ruleName ? ruleName : L"";
                    std::wstring ba = blockAt ? blockAt : L"";
                    std::wstring rt = redirectTo ? redirectTo : L"";
                    if (action == 0) {
                        // 豁免: 放行
                        // [降噪] 签名链正常放行(trusted_chain_allowed)属预期行为，降级为 DEBUG 避免刷屏；
                        // 其他真实豁免仍保持 INFO 可见。
                        const wchar_t* lvl = (rid.find(L"trusted_chain") != std::wstring::npos)
                            ? L"DEBUG" : L"INFO";
                        appLog(lvl, L"SMExempt",
                            (L"状态机豁免 PID=" + std::to_wstring(pid) +
                             L" rule=" + rid + L" " + rn).c_str());
                        return;
                    }
                    if (action == 1) {
                        // 阻止: 走统一处置闭环 (终止+隔离+审计)
                        std::wstring procName = getProcessName(pid);
                        std::wstring procPath = getProcessPath(pid);

                        // ── 状态机处置也须过可信/签名闸门 (P0-误杀修复) ──
                        // bun.exe 案例: 有效数字签名 (Codeblog CORP/DigiCert) 的进程
                        // 因状态机 LINEAGE_SCRIPT 规则 (cmd→bun run xxx.ts 脚本链) 命中
                        // 而被直接处置。此处与 EDR 告警回调保持同一豁免标准:
                        // 已知系统进程 / 系统目录 / 有效数字签名 → 不终止不隔离。
                        if (g_selfPid != 0 && pid == g_selfPid) {
                            appLog(L"WARN", L"SMBlock",
                                (L"状态机跳过处置 ZETA.exe 自身: PID=" +
                                 std::to_wstring(pid)).c_str());
                            return;
                        }
                        // 系统进程名/系统目录/有效签名 → 统一信任判定
                        if (TrustDecider::instance().isTrustedProcess(pid)) {
                            appLog(L"INFO", L"SMBlock",
                                (L"状态机跳过处置可信/签名进程(误杀防护): " +
                                 procName + L" PID=" + std::to_wstring(pid) +
                                 L" rule=" + rid + L" " + rn).c_str());
                            return;
                        }

#if ZETA_ENABLE_SSDT
                        // P4-反制: syscall_spoof_block 规则命中 → 开启驱动层间接 syscall 拦截
                        // 后续非 ntdll RIP 发起的跨进程写/远程线程直接返回 STATUS_ACCESS_DENIED
                        if (rid == L"syscall_spoof_block") {
                            if (p_zeta_driver_send_cmd) {
                                p_zeta_driver_send_cmd(24, L"1");  // ZETA_CMD_SET_SYSCALL_SPOOF_BLOCK
                            }
                            appLog(L"WARN", L"SMSpoof",
                                L"间接 syscall 反制已开启: 非 ntdll RIP 跨进程操作将直接拒绝");
                        }
#endif

                        std::vector<std::wstring> arts;
                        ProcessBehaviorEngine::instance().addPenaltyScore(pid, score);
                        bool term = remediateProcess(pid, arts, procPath, L"状态机");
                        appLog(term ? L"WARN" : L"ERROR", L"SMBlock",
                            (L"状态机处置 PID=" + std::to_wstring(pid) +
                             L" rule=" + rid + L" " + rn +
                             L" action=" + std::to_wstring(action) +
                             L" block_at=" + ba +
                             (term ? L" 已终止" : L" 终止失败")).c_str());
                    } else if (action == 3) {
                        // P1-3: 重定向 — 不终止进程, 由驱动 cmd 21 全局重定向机制写隔离副本.
                        // 用户态仅加分 + 记录, 避免误杀正常进程.
                        // M1-2: block_at 已透传, 此处可读 redirect_to 目标(供后续隔离区联动)。
                        ProcessBehaviorEngine::instance().addPenaltyScore(pid, score);
                        appLog(L"WARN", L"SMRedirect",
                            (L"状态机重定向 PID=" + std::to_wstring(pid) +
                             L" rule=" + rid + L" " + rn +
                             L" block_at=" + ba +
                             L" redirect_to=" + rt).c_str());
                    } else if (action == 2) {
                        // 询问: 通知 + 加分 (不直接杀)
                        ProcessBehaviorEngine::instance().addPenaltyScore(pid, score);
                        appLog(L"WARN", L"SMAsk",
                            (L"状态机命中(询问) PID=" + std::to_wstring(pid) +
                             L" rule=" + rid + L" " + rn +
                             L" block_at=" + ba).c_str());
                    }
                });
            appLog(L"INFO", L"Rules", L"状态机规则引擎已加载");
            printf("[ZETA] State machine rules loaded\n");
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

    // 2026-10-04 (P2-1 修复): 驱动已就绪 —— 把配置里的开关状态真正下发给驱动。
    // 必须放在此处: restoreUiState() 跑在驱动异步安装【之前】, 那里下发会失败。
    if (driverLoaded) {
        pushSwitchStatesToDriver();
    } else {
        appLog(L"WARN", L"Driver",
            L"驱动未加载, 配置中的开关状态未能下发 (UI 显示可能与驱动实际状态不一致)");
    }
}

// ============================================================
// 从配置恢复 UI 状态
// ============================================================
void restoreUiState() {
    appLog(L"INFO", L"App", L"Restoring UI state from config");

    // 恢复主题
    zeta_ui_set_theme(L"system_switch");
    zeta_ui_restore_combo(L"theme", L"system_switch");

    // P2-1: 恢复全部防护开关的真实状态(含学习模式).
    // 8 个 key 与 UI 防护页 / 驱动 cmd 8-14,21 对齐.
    // 从配置读值, 缺省默认开启(与驱动默认一致); 用户手动关过的开关重启后保持关闭.
    const wchar_t* switches[] = {
        L"process_switch",
        L"suspend_switch",
        L"document_switch",
        L"system_switch",
        L"driver_switch",
        L"network_switch",
        L"ransom_redirect_switch",
        L"doc_backup_switch",
        L"learning_switch",
        L"disk_write_switch",
        L"disk_monitor_switch"
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
// 管理员权限提升 + 驱动安装
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

    // 退出当前（非管理员）进程
    printf("[ZETA] Elevated instance launched, exiting...\n");
    ExitProcess(0);
}

// ============================================================
// 静默安装本地 TSA CA 到受信任根（驱动签名时间戳验证必需）
// CA 文件: Plugins\Rules\ZETA_CA.crt （随程序分发）
// 作用: Windows 验证驱动签名的时间戳时，需要信任 TSA 证书链
// ============================================================
static bool ensureTSACertInstalled() {
    // 查找 CA 证书文件（优先 Plugins\Rules，回退 exe 目录）
    std::wstring caPath = g_pluginsDir + L"\\Rules\\ZETA_CA.crt";
    if (GetFileAttributesW(caPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        caPath = g_exeDir + L"\\ZETA_CA.crt";
    }
    if (GetFileAttributesW(caPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        printf("[ZETA] CA cert not found at %S\n", caPath.c_str());
        return false;
    }

    // 先检查是否已安装（用 certutil 查询）
    std::wstring queryCmd = L"cmd /c certutil -store Root \"Local Timestamp CA\" >nul 2>&1";
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    wchar_t qbuf[512];
    wcscpy_s(qbuf, queryCmd.c_str());
    if (CreateProcessW(nullptr, qbuf, nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                       nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        if (exitCode == 0) {
            printf("[ZETA] TSA CA already trusted\n");
            return true;
        }
    }

    // 安装到当前用户受信任根
    printf("[ZETA] Installing TSA CA to trusted root...\n");
    std::wstring addCmd = L"cmd /c certutil -addstore -f Root \""
        + caPath + L"\"";
    wchar_t buf[1024];
    wcscpy_s(buf, addCmd.c_str());
    if (CreateProcessW(nullptr, buf, nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                       nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        if (exitCode == 0) {
            printf("[ZETA] TSA CA installed successfully\n");
            return true;
        }
        printf("[ZETA] CA install returned error=%lu\n", exitCode);
    } else {
        printf("[ZETA] CA install CreateProcess failed (error=%lu)\n", GetLastError());
    }
    return false;
}

static bool installAndStartDriver() {
    const wchar_t* serviceName = L"ZETA_Drv";

    // 0. 先确保 TSA CA 被信任（驱动签名时间戳验证必需）
    ensureTSACertInstalled();

    // 直接从 Plugins\Filter 使用驱动路径（不 CopyFile 到 System32）
    std::wstring driverPath = g_pluginsDir + L"\\Filter\\ZETA_Drv.sys";

    if (GetFileAttributesW(driverPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        printf("[ZETA] Driver not found at %S\n", driverPath.c_str());
        return false;
    }

    printf("[ZETA] Driver path: %S\n", driverPath.c_str());

    // 先尝试强制卸载任何卡住的驱动实例（带 5s 超时）
    printf("[ZETA] Attempting to unload any stuck driver instance...\n");
    {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        wchar_t cmdLine[] = L"fltmc unload ZETA_Drv";
        if (CreateProcessW(L"C:\\Windows\\System32\\fltmc.exe", cmdLine,
                           nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 5000);  // 5s 超时
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

    // 步骤2：检查服务是否已存在
    SC_HANDLE hSvc = OpenServiceW(hSCM, serviceName,
        SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | DELETE);
    if (hSvc) {
        // 服务已存在 — 检查其状态
        SERVICE_STATUS_PROCESS ssStatus;
        DWORD bytesNeeded = 0;
        if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(ssStatus), &bytesNeeded)) {
            if (ssStatus.dwCurrentState == SERVICE_RUNNING) {
                printf("[ZETA] Driver already running\n");
                CloseServiceHandle(hSvc);
                CloseServiceHandle(hSCM);
                return true;
            }
            // 已停止 — 尝试启动
            printf("[ZETA] Driver service exists but stopped - starting...\n");
            if (StartServiceW(hSvc, 0, nullptr)) {
                printf("[ZETA] Driver started successfully\n");
                CloseServiceHandle(hSvc);
                CloseServiceHandle(hSCM);
                Sleep(1000);
                return true;
            }
            DWORD startErr = GetLastError();
            // 错误 1058 = ERROR_SERVICE_DISABLED（BSOD 恢复禁用了驱动）
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

    // 步骤5：创建服务（带 ERROR_SERVICE_MARKED_FOR_DELETE 1072 重试）
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

    // 步骤6：设置 DependOnService = FltMgr（迷你过滤器必需）
    LPCWSTR fltMgrDeps[] = { L"FltMgr", nullptr };
    ChangeServiceConfig2W(hSvc, 3 /*SERVICE_CONFIG_DEPENDENCIES*/, (LPVOID)fltMgrDeps);

    CloseServiceHandle(hSvc);

    // 步骤7：创建所需的过滤器管理器注册表项
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

    // 步骤8：启动驱动
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
// ZETA_NetFilter.sys — 独立网络过滤器驱动管理
// ============================================================

#define NET_EVENT_SOCKET_CREATE  8001
#define NET_EVENT_SOCKET_SEND    8002
#define NET_EVENT_SOCKET_CONNECT 8003
// P0: 驱动还会推这两个码, 旧 switch 无分支 → 静默丢弃
#define NET_EVENT_RECV           8004
#define NET_EVENT_BIND           8005
// 8091: CONNECT 输入解析失败上报 (驱动侧 EVT_CONNECT_PARSEFAIL)
// 这是"拦截可能已失效"的最高价值信号, 必须落日志, 不能被静默丢弃
#define NET_EVENT_CONNECT_PARSEFAIL 8091
// P1: 驱动侧聚合摘要 (socket/send/recv 的按 PID 累计量)。载荷 = NetAggData。
#define NET_EVENT_AGG            8010
// P1 诊断: SEND 输入原始字节抓样 (驱动侧 EVT_SEND_DIAG), 用于反推 WSABUF 布局
#define NET_EVENT_SEND_DIAG      8092

// ⚠ ABI 契约: 必须与 ZETA_NetFilter.sys 的 NET_EVENT 逐字节一致。
//   驱动侧没有 #pragma pack → 自然对齐 → sizeof(NET_EVENT) = 536 (尾部 6 字节填充)。
//   这里原来加了 pack(1) → 算成 530 → 驱动端 `ol >= sizeof(NET_EVENT)` 判定失败 →
//   GET_EVENT 永远返回 STATUS_BUFFER_TOO_SMALL (Win32 err=122) →
//   事件环一条都读不出来 (2026-09-30 实测: 530 → err=122; 536 → OK)。
//   更糟的是旧错误分支对非 NO_MORE_ITEMS 错误只 Sleep 不报错, 于是网络传感器
//   静默哑掉、日志里没有任何异常 —— 这就是"EDR 信息获取不全"的直接来源。
//   修法: 与磁盘侧 DiskEvent 一样使用默认对齐, 并用 static_assert 锁死尺寸。
struct NetEvent {
    LONGLONG  Ts;    ULONG Pid;    ULONG Code;
    USHORT    Len;   USHORT Reserved;  ULONG TrueLen;   UCHAR  Data[512];
};
static_assert(sizeof(NetEvent) == 536,
              "NetEvent ABI 必须与驱动 NET_EVENT 一致 (默认对齐 = 536, 勿加 #pragma pack)");
// ⚠ P1 加了 TrueLen 之后 sizeof 仍是 536(吃掉原来的尾部填充), 所以**只断言 sizeof
//   会漏掉 Data 偏移 18→24 的变化** —— 下面三条 offsetof 断言才是真正的守门人。
//   TrueLen 语义随 Code: AGG=本条聚合了多少原始事件; 其余同 Len。
static_assert(offsetof(NetEvent, Len)     == 16, "NetEvent.Len 偏移必须为 16");
static_assert(offsetof(NetEvent, TrueLen) == 20, "NetEvent.TrueLen 偏移必须为 20");
static_assert(offsetof(NetEvent, Data)    == 24, "NetEvent.Data 偏移必须为 24");

// P1: 驱动侧聚合摘要载荷 (事件码 8010), 布局必须与驱动 NET_AGG_DATA 逐字节一致。
// 驱动把高频的 socket/send/recv 按 PID 累加后每 2 秒 flush 一条, 字节数是驱动侧
// 真实累加值 —— 不再受旧的 512 截断影响。
struct NetAggData {
    unsigned long      pid;
    unsigned long      sockets, sends, recvs;
    unsigned long long sendBytes, recvBytes;
    unsigned long      intervalMs;
    unsigned long      ringDrops;      // 驱动累计被环溢出丢弃的事件数
};
static_assert(sizeof(NetAggData) == 40, "NetAggData 必须与驱动 NET_AGG_DATA 一致 (40 字节)");
static_assert(offsetof(NetAggData, sendBytes)  == 16, "NetAggData.sendBytes 偏移必须为 16");
static_assert(offsetof(NetAggData, recvBytes)  == 24, "NetAggData.recvBytes 偏移必须为 24");
static_assert(offsetof(NetAggData, intervalMs) == 32, "NetAggData.intervalMs 偏移必须为 32");
static_assert(offsetof(NetAggData, ringDrops)  == 36, "NetAggData.ringDrops 偏移必须为 36");

static unsigned long s_netRingDropsSeen = 0;   // 已上报过的驱动环丢弃计数

#define IOCTL_ZETA_NET_GET_EVENT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_OUT_DIRECT, FILE_READ_DATA)
// P1-状态机: 下发目标 IP 黑名单 (输入 6 字节: IPv4[4] + Port[2], 与 ZETA_NetFilter.sys 的 IOCTL_BLOCK_IP 对应)
#define IOCTL_ZETA_NET_BLOCK_IP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)

// 下发 IP 黑名单到 NetFilter 驱动
static bool blockNetIp(const std::string& ip, unsigned short port) {
    if (g_netFilterDevice == INVALID_HANDLE_VALUE) return false;
    unsigned char buf[6] = {0};
    // 解析 "a.b.c.d" 为 4 字节
    unsigned int a[4] = {0};
    int n = sscanf_s(ip.c_str(), "%u.%u.%u.%u", &a[0], &a[1], &a[2], &a[3]);
    if (n != 4) return false;
    buf[0] = (unsigned char)a[0]; buf[1] = (unsigned char)a[1];
    buf[2] = (unsigned char)a[2]; buf[3] = (unsigned char)a[3];
    buf[4] = (unsigned char)(port & 0xFF);
    buf[5] = (unsigned char)((port >> 8) & 0xFF);
    DWORD returned = 0;
    return DeviceIoControl(g_netFilterDevice, IOCTL_ZETA_NET_BLOCK_IP,
        buf, sizeof(buf), nullptr, 0, &returned, nullptr);
}

// P1-状态机: 白名单增删 (写入驱动注册表 LearnedProcesses REG_MULTI_SZ, 行为引擎启动时读取)
// 同时调用 loadWhitelist 让行为引擎立即生效
static void whitelistAddRemove(const std::wstring& path, bool add) {
    if (path.empty()) return;
    const wchar_t* regPath = L"SYSTEM\\CurrentControlSet\\Services\\ZETA_Drv\\Parameters";

    HKEY hKey = nullptr;
    DWORD disp = 0;
    LONG ret = RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, nullptr, &hKey, &disp);
    if (ret != ERROR_SUCCESS) {
        appLog(L"WARN", L"白名单", L"打开注册表白名单失败");
        return;
    }

    // 读现有白名单 (REG_MULTI_SZ)
    std::vector<std::wstring> list;
    WCHAR buf[8192] = {0};
    DWORD type = 0, size = sizeof(buf);
    if (RegQueryValueExW(hKey, L"LearnedProcesses", nullptr, &type,
        (LPBYTE)buf, &size) == ERROR_SUCCESS && type == REG_MULTI_SZ) {
        const WCHAR* p = buf;
        while (*p) {
            std::wstring s(p);
            if (!s.empty()) list.push_back(s);
            p += s.length() + 1;
        }
    }

    if (add) {
        // 去重
        bool exists = false;
        for (const auto& s : list) {
            if (_wcsicmp(s.c_str(), path.c_str()) == 0) { exists = true; break; }
        }
        if (!exists) list.push_back(path);
    } else {
        list.erase(std::remove_if(list.begin(), list.end(),
            [&](const std::wstring& s) { return _wcsicmp(s.c_str(), path.c_str()) == 0; }),
            list.end());
    }

    // 写回 REG_MULTI_SZ
    std::wstring multi;
    for (const auto& s : list) { multi += s; multi += L'\0'; }
    multi += L'\0';  // 结尾双 null

    ret = RegSetValueExW(hKey, L"LearnedProcesses", 0, REG_MULTI_SZ,
        (const BYTE*)multi.c_str(), (DWORD)(multi.size() * sizeof(wchar_t)));
    RegCloseKey(hKey);

    if (ret == ERROR_SUCCESS) {
        appLog(L"INFO", L"白名单", (std::wstring(add ? L"已添加: " : L"已移除: ") + path).c_str());
        // 让行为引擎立即重载白名单
        ProcessBehaviorEngine::instance().loadWhitelist(regPath);
    } else {
        appLog(L"WARN", L"白名单", L"写注册表白名单失败");
    }
}

static bool installAndStartNetFilter() {
    const wchar_t* serviceName = L"ZETA_NetFilter";

    // ── Step 1: 定位 .sys 文件 ──
    // ⚠ 只使用 Release 版驱动, 禁止 Debug 构建 (历史蓝屏根因):
    //   Debug 下 sizeof(IO_REMOVE_LOCK) = 0x78 (含 IO_REMOVE_LOCK_DBG_BLOCK),
    //   IoReleaseRemoveLockAndWait 会把该尺寸传给 nt, nt 据此走"调试追踪"分支
    //   去解引用 RemoveLock->Dbg.Blocks; 该块未建立时为 NULL
    //   → 驱动卸载瞬间 BSOD 0x7E (ACCESS_VIOLATION, 读地址 0x8).
    //   Release 下 sizeof(IO_REMOVE_LOCK) = 0x20, 不会进入该分支.
    std::wstring sysPath = g_pluginsDir + L"\\NetFilter\\x64\\Release\\ZETA_NetFilter.sys";
    if (GetFileAttributesW(sysPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        printf("[ZETA_NET] Not found (Release): %S\n", sysPath.c_str());
        appLog(L"ERROR", L"NetFilter", L"ZETA_NetFilter.sys (Release) not found");
        return false;
    }
    printf("[ZETA_NET] Driver: %S\n", sysPath.c_str());

    std::wstring imagePath = L"\\??\\" + sysPath;

    // ── Step 2: 打开 SCM ──
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        DWORD err = GetLastError();
        printf("[ZETA_NET] OpenSCManager failed (%lu)\n", err);
        appLog(L"ERROR", L"NetFilter", (L"OpenSCManager: " + std::to_wstring(err)).c_str());
        return false;
    }

    // ── Step 3: 彻底清理旧服务 ──
    // 内核中同名模块只能加载一份, 旧服务不删干净会导致新服务 error 2
    auto stopAndDeleteService = [&](SC_HANDLE hMgr, const wchar_t* name) -> bool {
        SC_HANDLE hSvc = OpenServiceW(hMgr, name,
            SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | DELETE);
        if (!hSvc) {
            DWORD e = GetLastError();
            if (e == ERROR_SERVICE_DOES_NOT_EXIST) return true; // 不存在就是干净的
            if (e == ERROR_ACCESS_DENIED) {
                // 可能是残留的标记删除服务, 尝试用 DELETE 权限打开
                hSvc = OpenServiceW(hMgr, name, DELETE);
                if (hSvc) {
                    DeleteService(hSvc);
                    CloseServiceHandle(hSvc);
                    printf("[ZETA_NET] Marked stale service '%S' for deletion\n", name);
                    Sleep(2000);
                    return false; // 需要重试
                }
            }
            return true;
        }

        // 查询状态
        SERVICE_STATUS_PROCESS ssp = {};
        DWORD needed = 0;
        QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                             (LPBYTE)&ssp, sizeof(ssp), &needed);

        printf("[ZETA_NET] Service '%S' state: %lu\n", name, ssp.dwCurrentState);

        // 如果已停止且退出码正常, 直接删除
        if (ssp.dwCurrentState == SERVICE_STOPPED && ssp.dwWin32ExitCode == ERROR_SUCCESS) {
            DeleteService(hSvc);
            CloseServiceHandle(hSvc);
            Sleep(1500);
            return true;
        }

        // 如果正在运行或处于中间状态, 先尝试停止
        if (ssp.dwCurrentState != SERVICE_STOPPED &&
            ssp.dwCurrentState != SERVICE_STOP_PENDING) {
            printf("[ZETA_NET] Stopping '%S'...\n", name);
            ControlService(hSvc, SERVICE_CONTROL_STOP, (SERVICE_STATUS*)&ssp);
        }

        // 等待停止完成 (最多 15s)
        for (int i = 0; i < 30; i++) {
            Sleep(500);
            QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                                 (LPBYTE)&ssp, sizeof(ssp), &needed);
            if (ssp.dwCurrentState == SERVICE_STOPPED) {
                printf("[ZETA_NET] '%S' stopped\n", name);
                break;
            }
        }

        if (ssp.dwCurrentState != SERVICE_STOPPED) {
            printf("[ZETA_NET] WARNING: '%S' did not stop (state=%lu), forcing delete\n",
                   name, ssp.dwCurrentState);
        }

        // 删除服务
        DeleteService(hSvc);
        CloseServiceHandle(hSvc); // 关闭句柄触发真正删除
        Sleep(2000);
        return true;
    };

    // 先清理主服务
    for (int attempt = 0; attempt < 5; attempt++) {
        if (stopAndDeleteService(hSCM, serviceName)) break;
        printf("[ZETA_NET] Retry %d: waiting for deletion...\n", attempt + 1);
        Sleep(3000);
    }

    // 验证服务确实已删除
    {
        SC_HANDLE hCheck = OpenServiceW(hSCM, serviceName, SERVICE_QUERY_STATUS);
        if (hCheck) {
            printf("[ZETA_NET] WARNING: Old service still exists after cleanup\n");
            CloseServiceHandle(hCheck);
            // 等待更久
            for (int i = 0; i < 10; i++) {
                Sleep(2000);
                SC_HANDLE hRetry = OpenServiceW(hSCM, serviceName, SERVICE_QUERY_STATUS);
                if (!hRetry) { printf("[ZETA_NET] Old service finally removed\n"); break; }
                CloseServiceHandle(hRetry);
            }
        }
    }

    // ── Step 4: 创建服务 (带 MARKED_FOR_DELETE 重试) ──
    SC_HANDLE hSvc = nullptr;
    for (int retry = 0; retry < 10; retry++) {
        if (retry > 0) {
            printf("[ZETA_NET] CreateService retry %d, waiting...\n", retry);
            Sleep(3000);
        }
        hSvc = CreateServiceW(hSCM, serviceName, serviceName,
            SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL, imagePath.c_str(),
            nullptr, nullptr, nullptr, nullptr, nullptr);
        if (hSvc) { printf("[ZETA_NET] Service created\n"); break; }

        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            printf("[ZETA_NET] Service marked for delete, waiting...\n");
            continue;
        }
        printf("[ZETA_NET] CreateService failed (%lu)\n", err);
        appLog(L"ERROR", L"NetFilter", (L"CreateService: " + std::to_wstring(err)).c_str());
        CloseServiceHandle(hSCM); return false;
    }
    if (!hSvc) {
        printf("[ZETA_NET] Failed to create service after retries\n");
        appLog(L"ERROR", L"NetFilter", L"CreateService: too many retries");
        CloseServiceHandle(hSCM); return false;
    }

    // ── Step 5: 启动驱动 ──
    if (!StartServiceW(hSvc, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[ZETA_NET] Already running\n");
        } else {
            // ⚠ ERROR_FILE_NOT_FOUND(2) 在这里几乎从不是"文件不存在" —— 上面已用
            //   GetFileAttributesW 确认过文件在。真因是内核里存在同路径镜像的残留注册:
            //   驱动卸载时若泄漏了设备对象(IoDetachDevice 后忘记 IoDeleteDevice),
            //   驱动对象释放不掉 → 镜像段永久驻留内核模块表 → 该路径本次开机内
            //   永久无法再加载, SCM 就报 error 2。
            //   (2026-09-30 实测: NetFilter 的 DetachAll 正是这个 bug, 已修)
            //   自愈: 把 .sys 复制到一条全新路径并改服务 ImagePath 重试一次。
            bool recovered = false;
            if (err == ERROR_FILE_NOT_FOUND) {
                appLog(L"WARN", L"NetFilter",
                    L"StartService=2: 该路径被内核残留镜像注册占用, 改用新路径加载");
                std::wstring stagedDir = g_pluginsDir + L"\\NetFilter\\staged";
                std::wstring stagedSys = stagedDir + L"\\ZETA_NF_" +
                    std::to_wstring(GetTickCount64()) + L".sys";
                CreateDirectoryW(stagedDir.c_str(), nullptr);
                if (CopyFileW(sysPath.c_str(), stagedSys.c_str(), FALSE)) {
                    std::wstring stagedImage = L"\\??\\" + stagedSys;
                    if (ChangeServiceConfigW(hSvc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                            SERVICE_NO_CHANGE, stagedImage.c_str(),
                            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)
                        && StartServiceW(hSvc, 0, nullptr)) {
                        printf("[ZETA_NET] Started OK via staged path: %S\n", stagedSys.c_str());
                        appLog(L"INFO", L"NetFilter",
                            (L"原路径被残留镜像注册占用, 已改用新路径加载: " + stagedSys).c_str());
                        recovered = true;
                    } else {
                        appLog(L"ERROR", L"NetFilter",
                            (L"staged 路径启动仍失败: " + std::to_wstring(GetLastError())).c_str());
                    }
                } else {
                    appLog(L"WARN", L"NetFilter",
                        (L"复制到 staged 路径失败: " + std::to_wstring(GetLastError())).c_str());
                }
            }
            if (!recovered) {
                printf("[ZETA_NET] StartService failed (%lu)\n", err);
                appLog(L"ERROR", L"NetFilter", (L"StartService: " + std::to_wstring(err)).c_str());
                if (err == 190)  appLog(L"ERROR", L"NetFilter", L"Bad driver image");
                else if (err == 2) appLog(L"ERROR", L"NetFilter",
                    L"文件存在但内核拒绝加载: 该路径有残留镜像注册(驱动卸载泄漏), 需重启系统");
                else if (err == 577) appLog(L"ERROR", L"NetFilter", L"Driver signing required");
                else if (err == 1053) appLog(L"ERROR", L"NetFilter", L"Timeout (driver init crash?)");
                // 启动失败, 删除服务保持干净
                DeleteService(hSvc);
                CloseServiceHandle(hSvc); CloseServiceHandle(hSCM); return false;
            }
        }
    }
    printf("[ZETA_NET] Started OK\n");
    CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
    Sleep(500);
    return true;
}

static void unloadNetFilter() {
    const wchar_t* serviceName = L"ZETA_NetFilter";

    g_netFilterRunning = false;
    if (g_netFilterThread.joinable()) {
        g_netFilterThread.join();
    }

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return;

    SC_HANDLE hSvc = OpenServiceW(hSCM, serviceName,
        SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!hSvc) { CloseServiceHandle(hSCM); return; }

    // 先查询状态
    SERVICE_STATUS_PROCESS ssp;
    DWORD needed = 0;
    QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                         (LPBYTE)&ssp, sizeof(ssp), &needed);

    if (ssp.dwCurrentState == SERVICE_RUNNING) {
        printf("[ZETA_NET] Stopping service...\n");
        ControlService(hSvc, SERVICE_CONTROL_STOP, (SERVICE_STATUS*)&ssp);
        // 等待驱动模块完全卸载 (最多 10s)
        for (int i = 0; i < 20; i++) {
            Sleep(500);
            QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                                 (LPBYTE)&ssp, sizeof(ssp), &needed);
            if (ssp.dwCurrentState == SERVICE_STOPPED) {
                printf("[ZETA_NET] Service stopped\n");
                break;
            }
        }
    }

    DeleteService(hSvc);
    printf("[ZETA_NET] Service marked for deletion\n");
    // 关闭句柄触发真正的删除
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    // 等待内核模块引用计数归零, 确保 .sys 文件解锁
    Sleep(2000);

    // 清理自愈用的 staged 副本 (正常路径下这个目录根本不会存在).
    // 必须先停服务再删: 驱动在跑时镜像文件是锁的, 删不掉(忽略失败即可).
    {
        std::wstring stagedDir = g_pluginsDir + L"\\NetFilter\\staged";
        WIN32_FIND_DATAW fd;
        HANDLE hf = FindFirstFileW((stagedDir + L"\\*.sys").c_str(), &fd);
        if (hf != INVALID_HANDLE_VALUE) {
            do {
                DeleteFileW((stagedDir + L"\\" + fd.cFileName).c_str());
            } while (FindNextFileW(hf, &fd));
            FindClose(hf);
        }
    }
    printf("[ZETA_NET] Cleanup complete\n");
}

// ── 磁盘过滤器驱动 (ZETA_DiskFilter.sys, 纯 WDM, 拦截 MBR 写入) ──
static bool installAndStartDiskFilter() {
    const wchar_t* serviceName = L"ZETA_DiskFilter";

    // Step 1: 定位 .sys 文件
    std::wstring sysPath = g_pluginsDir + L"\\DiskFilter\\ZETA_DiskFilter.sys";
    if (GetFileAttributesW(sysPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        sysPath = g_pluginsDir + L"\\Filter\\ZETA_DiskFilter.sys";
        if (GetFileAttributesW(sysPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            printf("[ZETA_DISK] Not found: ZETA_DiskFilter.sys\n");
            appLog(L"WARN", L"DiskFilter", L"ZETA_DiskFilter.sys not found");
            return false;
        }
    }
    printf("[ZETA_DISK] Driver: %S\n", sysPath.c_str());

    std::wstring imagePath = L"\\??\\" + sysPath;

    // Step 2: 打开 SCM
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        DWORD err = GetLastError();
        printf("[ZETA_DISK] OpenSCManager failed (%lu)\n", err);
        return false;
    }

    // Step 3: 清理旧服务
    auto stopAndDeleteService = [&](SC_HANDLE hMgr, const wchar_t* name) -> bool {
        SC_HANDLE hSvc = OpenServiceW(hMgr, name,
            SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | DELETE);
        if (!hSvc) {
            DWORD e = GetLastError();
            if (e == ERROR_SERVICE_DOES_NOT_EXIST) return true;
            if (e == ERROR_ACCESS_DENIED) {
                hSvc = OpenServiceW(hMgr, name, DELETE);
                if (hSvc) { DeleteService(hSvc); CloseServiceHandle(hSvc); Sleep(2000); return false; }
            }
            return true;
        }
        SERVICE_STATUS_PROCESS ssp = {};
        DWORD needed = 0;
        QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed);
        if (ssp.dwCurrentState == SERVICE_STOPPED && ssp.dwWin32ExitCode == ERROR_SUCCESS) {
            DeleteService(hSvc); CloseServiceHandle(hSvc); Sleep(1500); return true;
        }
        if (ssp.dwCurrentState != SERVICE_STOPPED && ssp.dwCurrentState != SERVICE_STOP_PENDING)
            ControlService(hSvc, SERVICE_CONTROL_STOP, (SERVICE_STATUS*)&ssp);
        for (int i = 0; i < 30; i++) {
            Sleep(500);
            QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed);
            if (ssp.dwCurrentState == SERVICE_STOPPED) break;
        }
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
        Sleep(2000);
        return true;
    };

    for (int attempt = 0; attempt < 5; attempt++) {
        if (stopAndDeleteService(hSCM, serviceName)) break;
        printf("[ZETA_DISK] Retry %d: waiting for deletion...\n", attempt + 1);
        Sleep(3000);
    }

    // Step 4: 创建服务
    SC_HANDLE hSvc = nullptr;
    for (int retry = 0; retry < 10; retry++) {
        if (retry > 0) { printf("[ZETA_DISK] CreateService retry %d\n", retry); Sleep(3000); }
        hSvc = CreateServiceW(hSCM, serviceName, serviceName,
            SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL, imagePath.c_str(),
            nullptr, nullptr, nullptr, nullptr, nullptr);
        if (hSvc) { printf("[ZETA_DISK] Service created\n"); break; }
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) continue;
        printf("[ZETA_DISK] CreateService failed (%lu)\n", err);
        appLog(L"ERROR", L"DiskFilter", (L"CreateService: " + std::to_wstring(err)).c_str());
        CloseServiceHandle(hSCM); return false;
    }
    if (!hSvc) {
        printf("[ZETA_DISK] Failed to create service\n");
        CloseServiceHandle(hSCM); return false;
    }

    // Step 5: 启动驱动
    if (!StartServiceW(hSvc, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[ZETA_DISK] Already running\n");
        } else {
            printf("[ZETA_DISK] StartService failed (%lu)\n", err);
            if (err == 2)  appLog(L"ERROR", L"DiskFilter", L"File not found");
            else if (err == 577) appLog(L"ERROR", L"DiskFilter", L"Driver signing required");
            else if (err == 1053) appLog(L"ERROR", L"DiskFilter", L"Timeout (driver init crash?)");
            else appLog(L"ERROR", L"DiskFilter", (L"StartService: " + std::to_wstring(err)).c_str());
            DeleteService(hSvc);
            CloseServiceHandle(hSvc); CloseServiceHandle(hSCM); return false;
        }
    }
    printf("[ZETA_DISK] Started OK\n");
    CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
    Sleep(500);
    return true;
}

static void unloadDiskFilter() {
    const wchar_t* serviceName = L"ZETA_DiskFilter";

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return;

    SC_HANDLE hSvc = OpenServiceW(hSCM, serviceName,
        SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!hSvc) { CloseServiceHandle(hSCM); return; }

    SERVICE_STATUS_PROCESS ssp;
    DWORD needed = 0;
    QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed);

    if (ssp.dwCurrentState == SERVICE_RUNNING) {
        printf("[ZETA_DISK] Stopping service...\n");
        ControlService(hSvc, SERVICE_CONTROL_STOP, (SERVICE_STATUS*)&ssp);
        for (int i = 0; i < 20; i++) {
            Sleep(500);
            QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed);
            if (ssp.dwCurrentState == SERVICE_STOPPED) { printf("[ZETA_DISK] Stopped\n"); break; }
        }
    }

    DeleteService(hSvc);
    printf("[ZETA_DISK] Service marked for deletion\n");
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    Sleep(2000);
}

// ============================================================
// 磁盘过滤器 (ZETA_DiskFilter.sys) 用户态接口
//   控制设备: \\.\ZETA_DiskMon
//   结构与 IOCTL 编号必须与 Plugins/Filter/ZETA_DiskFilter.c 严格一致
//   (两端都用默认对齐, 不要加 #pragma pack)
// ============================================================
struct DiskEvent {
    LONGLONG           Ts;
    unsigned long      Pid;
    unsigned long      Code;
    unsigned long      DiskNumber;
    unsigned long      Flags;      // DISK_FLAG_*: 0=仅记录 1=已拦截 2=可信工具放行
    unsigned long long Offset;
    unsigned long      Length;
    unsigned short     Len;        // Data 有效字节数
    unsigned char      Data[512];  // UTF-16LE: "<进程映像名> | <原因>"
};

struct DiskStats {
    unsigned long      Enabled;
    unsigned long      Mode;       // 0=拦截 1=仅监控
    unsigned long      DiskCount;
    unsigned long      BlockedCount;
    unsigned long      ObservedCount;
    unsigned long      LastPid;
    unsigned long      LastDiskNumber;
    unsigned long      TrustedCount; // 可信工具豁免放行次数 (原 Reserved 字段, 布局不变)
    unsigned long long LastOffset;
    unsigned long long LastTime;
};

#define IOCTL_DISK_GET_EVENT   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_OUT_DIRECT, FILE_READ_DATA)
#define IOCTL_DISK_GET_STATS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED,  FILE_READ_DATA)
#define IOCTL_DISK_SET_ENABLED CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED,  FILE_WRITE_DATA)
#define IOCTL_DISK_SET_MODE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED,  FILE_WRITE_DATA)
#define IOCTL_DISK_REFRESH     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED,  FILE_WRITE_DATA)
#define IOCTL_DISK_RESET_STATS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED,  FILE_WRITE_DATA)

// 每次单独开句柄: 避免与事件线程的阻塞式 GET_EVENT 抢同一个句柄
static HANDLE OpenDiskFilterDevice() {
    return CreateFileW(L"\\\\.\\ZETA_DiskMon", GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, nullptr);
}

static bool diskFilterSetEnabled(bool enabled) {
    HANDLE h = OpenDiskFilterDevice();
    if (h == INVALID_HANDLE_VALUE) {
        printf("[ZETA_DISK] Open device failed (%lu)\n", GetLastError());
        return false;
    }
    unsigned long v = enabled ? 1u : 0u;
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_DISK_SET_ENABLED, &v, sizeof(v), nullptr, 0, &returned, nullptr);
    CloseHandle(h);
    printf("[ZETA_DISK] protection %s (%d)\n", enabled ? "ENABLED" : "DISABLED", ok ? 0 : (int)GetLastError());
    return ok != FALSE;
}

static bool diskFilterSetMode(int mode) {
    HANDLE h = OpenDiskFilterDevice();
    if (h == INVALID_HANDLE_VALUE) return false;
    unsigned long v = (mode == 1) ? 1u : 0u;
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_DISK_SET_MODE, &v, sizeof(v), nullptr, 0, &returned, nullptr);
    CloseHandle(h);
    return ok != FALSE;
}

static bool diskFilterRefresh() {
    HANDLE h = OpenDiskFilterDevice();
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_DISK_REFRESH, nullptr, 0, nullptr, 0, &returned, nullptr);
    CloseHandle(h);
    return ok != FALSE;
}

static bool diskFilterQueryStats(DiskStats* out) {
    if (!out) return false;
    HANDLE h = OpenDiskFilterDevice();
    if (h == INVALID_HANDLE_VALUE) return false;
    ZeroMemory(out, sizeof(DiskStats));
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_DISK_GET_STATS, nullptr, 0,
                              out, sizeof(DiskStats), &returned, nullptr);
    CloseHandle(h);
    return (ok && returned >= sizeof(DiskStats)) ? true : false;
}

// 把驱动的真实状态推给 UI (挂接磁盘数 / 拦截数 / 模式 / 开关)
static void diskFilterSyncStatus() {
    DiskStats st;
    if (!diskFilterQueryStats(&st)) {
        if (p_zeta_ui_set_disk_status)
            p_zeta_ui_set_disk_status(0, 0, 0, 0, 0, L"驱动未响应 (控制设备不可用)");
        return;
    }
    if (p_zeta_ui_set_disk_status) {
        p_zeta_ui_set_disk_status((int)st.DiskCount, (int)st.BlockedCount,
                                  (int)st.ObservedCount, (int)st.Mode,
                                  (int)st.Enabled, L"");
    }
}

// ── 磁盘事件读取线程 ──
static void diskFilterEventLoop() {
    printf("[ZETA_DISK] Event loop started\n");

    HANDLE dev = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(g_diskFilterMutex);
        g_diskFilterDevice = OpenDiskFilterDevice();
        dev = g_diskFilterDevice;
    }
    if (dev == INVALID_HANDLE_VALUE) {
        printf("[ZETA_DISK] Open device failed (%lu)\n", GetLastError());
        g_diskFilterRunning = false;
        return;
    }
    printf("[ZETA_DISK] Control device opened\n");

    // 首帧: 回填真实防护状态 (旧实现 UI 只有一个写死的"已启动")
    diskFilterSyncStatus();

    // 首帧自检: 把挂接磁盘数/模式/计数写进控制台与日志。
    // 之前这些值只推给 UI, 排障时从日志里看不出驱动到底挂上了几块盘。
    {
        DiskStats st0;
        if (diskFilterQueryStats(&st0)) {
            WCHAR line[256];
            swprintf_s(line, L"防护%s, 模式=%s, 已挂接 %lu 个物理磁盘, 累计拦截 %lu 次, 仅记录 %lu 次, 可信工具放行 %lu 次",
                st0.Enabled ? L"已开启" : L"已关闭",
                st0.Mode ? L"仅监控" : L"拦截",
                st0.DiskCount, st0.BlockedCount, st0.ObservedCount, st0.TrustedCount);
            printf("[ZETA_DISK] Self-check: %ls\n", line);
            appLog(L"INFO", L"DiskFilter", line);
        } else {
            printf("[ZETA_DISK] Self-check failed: IOCTL_DISK_GET_STATS error %lu\n", GetLastError());
            appLog(L"WARN", L"DiskFilter", L"无法读取驱动统计 (IOCTL_DISK_GET_STATS 失败)");
        }
    }

    // 热插拔: 驱动只在加载时枚举一次磁盘, 这里定期让它重新扫描
    diskFilterRefresh();
    DWORD lastRefresh = GetTickCount();

    DWORD lastSync = GetTickCount();
    DWORD lastLog = GetTickCount();
    int loggedInWindow = 0;
    int suppressed = 0;

    while (g_diskFilterRunning) {
        DiskEvent evt;
        DWORD returned = 0;
        BOOL ok = DeviceIoControl(dev, IOCTL_DISK_GET_EVENT,
                                  nullptr, 0, &evt, sizeof(evt), &returned, nullptr);

        if (!ok) {
            DWORD err = GetLastError();
            // 每 60 秒重新枚举一次磁盘 (U 盘/移动硬盘热插拔后也能纳入保护)
            if (GetTickCount() - lastRefresh >= 60000) {
                diskFilterRefresh();
                lastRefresh = GetTickCount();
            }
            // 周期性刷新状态, 让 UI 上的拦截计数保持鲜活
            if (GetTickCount() - lastSync >= 3000) {
                if (suppressed > 0) {
                    appLog(L"INFO", L"DiskFilter",
                        (L"另有 " + std::to_wstring(suppressed) + L" 条磁盘写事件已被节流省略").c_str());
                    suppressed = 0;
                }
                diskFilterSyncStatus();
                lastSync = GetTickCount();
            }
            if (err == ERROR_NO_MORE_ITEMS) { Sleep(15); continue; }
            Sleep(200);
            continue;
        }
        if (returned < sizeof(DiskEvent)) continue;

        // Data 是 UTF-16LE, Len 为字节数
        std::wstring info;
        if (evt.Len > 0 && evt.Len <= sizeof(evt.Data)) {
            info.assign(reinterpret_cast<const wchar_t*>(evt.Data), evt.Len / sizeof(wchar_t));
            while (!info.empty() && info.back() == L'\0') info.pop_back();
        }
        if (info.empty()) info = L"(未知来源)";

        // Flags 三态: 0=仅记录 1=已拦截 2=可信工具豁免放行
        // 不能写成 (evt.Flags != 0) —— 那会把"可信放行"误报成"已拦截"。
        const bool blocked = (evt.Flags == 1);
        const bool trusted = (evt.Flags == 2);

        // 日志节流: 每秒最多 5 条, 其余合并计数, 防止恶意程序刷爆 UI 日志
        if (GetTickCount() - lastLog >= 1000) { lastLog = GetTickCount(); loggedInWindow = 0; }
        if (loggedInWindow >= 5) { suppressed++; continue; }
        loggedInWindow++;

        std::wstring msg = std::wstring(L"物理磁盘 ") + std::to_wstring(evt.DiskNumber) +
            (blocked ? L" 写入已拦截: "
                     : (trusted ? L" 可信工具放行(未拦截): " : L" 底层写入(仅记录): ")) + info +
            L" [偏移=" + std::to_wstring(evt.Offset) + L" 长度=" + std::to_wstring(evt.Length) + L"]";

        printf("[ZETA_DISK] %ls\n", msg.c_str());
        appLog(blocked ? L"WARN" : L"INFO", L"DiskFilter", msg.c_str());

        if (GetTickCount() - lastSync >= 1000) {
            diskFilterSyncStatus();
            lastSync = GetTickCount();
        }
    }

    {
        std::lock_guard<std::mutex> lock(g_diskFilterMutex);
        if (dev != INVALID_HANDLE_VALUE) CloseHandle(dev);
        g_diskFilterDevice = INVALID_HANDLE_VALUE;
    }
    printf("[ZETA_DISK] Event loop ended\n");
}

// ══════════════════════════════════════════════════════════════════════════════
// P0 网络事件分轨 (2026-09-30)
//
// 为什么改: 实测一轮 25,014 条 NetFilter 日志行的构成 ——
//     send 21,660 (86.6%) / socket created 2,938 (11.7%) / connect 213 (0.85%)
//     / loopback 94 / 连接告警 77 (0.3%)   ⇒  信噪比 1.2%
// 即 98% 的日志行来自"单条几乎没有安全价值"的基数型事件, 而价值最高的
// connect/告警只占 1.2%。appLog 是 5MB 上限、触顶即整体轮转的文本日志
// (见 appLog 尾部实现), 噪声会把 connect 证据一并清掉 —— 这等于给攻击者一条
// "刷流量销毁证据"的遥测致盲通道; 内核事件环(2048, FIFO 覆盖最旧)同理,
// 高频事件会把高价值事件顶出环。
//
// 处理: 高频低值事件(socket/send/recv/bind/loopback) 只进内存计数器, 不落日志;
//       只有逐条价值高的 connect 与"越过阈值"的事件才写日志, 并按 (pid,ip,port)
//       去重 + 单进程告警配额; 另保留一条 60 秒紧凑汇总用于确认管道存活与 TOP 说话者。
//       计数器留在内存, 供后续 UI / 行为引擎 / 驱动侧聚合(P1) 取用。
//
// ⚠ send 字节数受驱动侧 512 截断 (RingPush 把 Len 与拷贝长度都夹到 NET_EVENT_MAX),
//   只能当"下限"看, 所以阈值判定一律用**计数**, 不用字节;
//   真实长度需 P1 给 NET_EVENT 加独立 TrueLen 字段解决。
// ══════════════════════════════════════════════════════════════════════════════
#define NET_STAT_MAX_PID        64
#define NET_CONNDEDUP_MAX      512
#define NET_CONN_DEDUP_MS    60000   // 同 (pid,ip,port) 60 秒内只报一次
#define NET_FANOUT_WARN         30   // 单进程 60 秒内不同外联目标数告警阈值
#define NET_ALERT_CAP_PER_PID   20   // 单进程 60 秒内最多落 20 条告警, 超出只计数
#define NET_SUMMARY_MS       60000

struct NetPidStat {
    unsigned long      pid;
    unsigned long long lastMs;
    unsigned long long sendBytes, recvBytes;   // P1: 驱动侧真实字节(64 位, 不再被 512 截断)
    unsigned long      sockets, sends, recvs, binds, conns, alerts, dropped;
};
static NetPidStat s_netPid[NET_STAT_MAX_PID];
static int        s_netPidCount = 0;

struct NetConnKey {
    unsigned long      pid;
    unsigned int       ip;
    unsigned short     port;
    unsigned long long lastMs;
};
static NetConnKey s_netConn[NET_CONNDEDUP_MAX];
static int        s_netConnCount = 0;
static unsigned long long s_netWinStart = 0;
static unsigned long      s_netWinReported = 0;   // 本窗口内已落日志的条数

// 取/建某 PID 的统计槽; 表满时淘汰"最久未活动"的槽。
// ⚠ 原实现(32 槽 netThrottle)满表后直接停止插入, 于是新 PID 永远不受节流、
//   可以无界刷告警日志 —— 这里改成可回收, 从根上避免该类缺陷。
static NetPidStat* netPidStatGet(unsigned long pid) {
    NetPidStat* oldest = &s_netPid[0];
    for (int i = 0; i < s_netPidCount; i++) {
        if (s_netPid[i].pid == pid) return &s_netPid[i];
        if (s_netPid[i].lastMs < oldest->lastMs) oldest = &s_netPid[i];
    }
    if (s_netPidCount < NET_STAT_MAX_PID) {
        NetPidStat* slot = &s_netPid[s_netPidCount++];
        *slot = NetPidStat();
        slot->pid = pid;
        return slot;
    }
    *oldest = NetPidStat();
    oldest->pid = pid;
    return oldest;
}

// connect 去重: 返回 true = 该 (pid,ip,port) 在本窗口内首次出现, 应上报。
// 浏览器对同一 CDN 开 50 条连接 = 1 条证据, 不是 50 条。
// 旧实现按 PID 节流 30 秒: 既把"同进程访问 50 个不同目标"压成 1 条(丢证据),
// 又会在前 32 个 PID 占满后完全失效(可无界刷)。
static bool netConnDedupNew(unsigned long pid, unsigned int ip, unsigned short port,
                            unsigned long long nowMs) {
    NetConnKey* oldest = &s_netConn[0];
    for (int i = 0; i < s_netConnCount; i++) {
        NetConnKey* k = &s_netConn[i];
        if (k->pid == pid && k->ip == ip && k->port == port) {
            bool isNew = (nowMs - k->lastMs >= NET_CONN_DEDUP_MS);
            k->lastMs = nowMs;
            return isNew;
        }
        if (k->lastMs < oldest->lastMs) oldest = k;
    }
    if (s_netConnCount < NET_CONNDEDUP_MAX) {
        NetConnKey* k = &s_netConn[s_netConnCount++];
        k->pid = pid; k->ip = ip; k->port = port; k->lastMs = nowMs;
        return true;
    }
    oldest->pid = pid; oldest->ip = ip; oldest->port = port; oldest->lastMs = nowMs;
    return true;
}

// 某 PID 在窗口内的不同外联目标数(扇出) —— 扫描/蠕虫特征
static unsigned long netConnFanout(unsigned long pid, unsigned long long nowMs) {
    unsigned long n = 0;
    for (int i = 0; i < s_netConnCount; i++)
        if (s_netConn[i].pid == pid && nowMs - s_netConn[i].lastMs < NET_CONN_DEDUP_MS) n++;
    return n;
}

// 每 60 秒一条紧凑汇总, 然后清空窗口计数。返回 true = 刚汇总过。
static bool netStatsFlush(unsigned long long nowMs, unsigned long* unhandled) {
    if (s_netWinStart == 0) { s_netWinStart = nowMs; return false; }
    if (nowMs - s_netWinStart < NET_SUMMARY_MS) return false;

    if (s_netPidCount > 0) {
        // TOP3: 按 (socket+send+conn) 次数排
        int rank[3] = { -1, -1, -1 };
        for (int t = 0; t < 3; t++) {
            unsigned long best = 0;
            for (int i = 0; i < s_netPidCount; i++) {
                if (rank[0] == i || rank[1] == i || rank[2] == i) continue;
                unsigned long w = s_netPid[i].sockets + s_netPid[i].sends + s_netPid[i].conns;
                if (rank[t] < 0 || w > best) { rank[t] = i; best = w; }
            }
        }
        std::wstring top;
        unsigned long long winSendBytes = 0, winRecvBytes = 0;
        for (int i = 0; i < s_netPidCount; i++) {
            winSendBytes += s_netPid[i].sendBytes;
            winRecvBytes += s_netPid[i].recvBytes;
        }
        for (int t = 0; t < 3; t++) {
            if (rank[t] < 0) continue;
            NetPidStat* p = &s_netPid[rank[t]];
            if (!top.empty()) top += L"; ";
            top += getProcessName(p->pid) + L"(" + std::to_wstring(p->pid) + L") " +
                   std::to_wstring(p->sockets + p->sends + p->conns) + L"次";
            // 字节来自驱动侧真实累加(不再被 512 截断) —— 旧实现下 上行/次数 永远 <=512
            if (p->sendBytes) top += L"/上行" + std::to_wstring(p->sendBytes / 1024) + L"KB";
            if (p->alerts)  top += L"/告警" + std::to_wstring(p->alerts);
            if (p->dropped) top += L"/合并" + std::to_wstring(p->dropped);
        }
        appLog(L"INFO", L"NetFilter",
            (L"近 60 秒网络事件汇总: 落日志 " + std::to_wstring(s_netWinReported) +
             L" 条, 高频事件已聚合未落盘(避免噪声挤掉 5MB 轮转内的 connect 证据);"
             L" 未细分 " + std::to_wstring(*unhandled) + L" 条;" +
             // 字节统计在 WSABUF 布局验证完成前不输出 —— 宁缺勿错
             (winSendBytes ? (L" 上行合计 " + std::to_wstring(winSendBytes / 1024) + L" KB;") : L"") +
             L" TOP: " + top).c_str());
    }

    s_netPidCount   = 0;
    s_netConnCount  = 0;
    s_netWinReported = 0;
    *unhandled = 0;
    s_netWinStart = nowMs;
    return true;
}

// ── 网络事件读取线程 ──
static void netFilterEventLoop() {
    printf("[ZETA_NET] Event loop started\n");

    g_netFilterDevice = CreateFileW(L"\\\\.\\ZETA_NetMon", GENERIC_READ,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_netFilterDevice == INVALID_HANDLE_VALUE) {
        printf("[ZETA_NET] Open device failed (%lu)\n", GetLastError());
        g_netFilterRunning = false;
        return;
    }
    printf("[ZETA_NET] Device opened\n");

    // P1-状态机: 演示下发 IP 黑名单 (203.0.113.x 为 TEST-NET 保留地址, 不会误伤真实流量)
    // 实际生产: 应由状态机规则/威胁情报下发 C2 服务器 IP
    blockNetIp("203.0.113.1", 0);   // 端口0=全部端口
    blockNetIp("203.0.113.2", 443); // 指定端口
    printf("[ZETA_NET] IP blacklist applied (test entries)\n");

    // 事件读取失败必须可见: 历史上 err=122(输出缓冲过小) 在这里被静默吞掉,
    // 网络传感器一条事件都上报不了却毫无迹象. 现在首次/每 10 秒(或错误码变化)报一次.
    unsigned long netErrStreak = 0;
    DWORD         netErrLastCode = 0;
    DWORD         netErrLastReport = 0;
    unsigned long netUnhandled = 0;          // 未细分事件码计数, 并入 60 秒汇总

    while (g_netFilterRunning) {
        // P0: 每 60 秒汇总一次并清空窗口计数(循环本身是常驻轮询, 不必另起定时器)
        netStatsFlush(GetTickCount64(), &netUnhandled);

        NetEvent evt;
        DWORD returned = 0;
        BOOL ok = DeviceIoControl(g_netFilterDevice, IOCTL_ZETA_NET_GET_EVENT,
            nullptr, 0, &evt, sizeof(evt), &returned, nullptr);

        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS) {
                Sleep(10);
                continue;
            }
            // ⚠ 非 NO_MORE_ITEMS 的错误一律上报. 旧代码在此静默 Sleep(100) 死循环,
            //   把"结构体尺寸不匹配导致永远读不到事件"这类致命故障藏了整整一版.
            netErrStreak++;
            DWORD now = GetTickCount();
            if (err != netErrLastCode || now - netErrLastReport >= 10000) {
                netErrLastCode = err;
                netErrLastReport = now;
                appLog(L"WARN", L"NetFilter",
                    (L"事件读取失败 err=" + std::to_wstring(err) + L" (连续 " +
                     std::to_wstring(netErrStreak) + L" 次) — 网络事件无法上报").c_str());
            }
            Sleep(100);
            continue;
        }

        netErrStreak = 0;

        if (returned < sizeof(NetEvent)) continue;

        switch (evt.Code) {
        case NET_EVENT_AGG: {
            // P1: 驱动侧聚合摘要 —— socket/send/recv 不再逐条上报, 由驱动按 PID 累加后
            // 每 2 秒 flush 一条。字节数是驱动侧真实累加值(旧实现恒被截到 512)。
            if (evt.Len < sizeof(NetAggData)) break;
            NetAggData agg;
            memcpy(&agg, evt.Data, sizeof(agg));
            NetPidStat* pst = netPidStatGet(agg.pid);
            pst->sockets   += agg.sockets;
            pst->sends     += agg.sends;
            pst->recvs     += agg.recvs;
            pst->sendBytes += agg.sendBytes;
            pst->recvBytes += agg.recvBytes;
            // 事件环溢出必须可见 —— 驱动丢过事件就意味着证据缺失(旧实现完全无感)
            if (agg.ringDrops && agg.ringDrops != s_netRingDropsSeen) {
                unsigned long lost = (agg.ringDrops > s_netRingDropsSeen)
                                   ? (agg.ringDrops - s_netRingDropsSeen) : agg.ringDrops;
                s_netRingDropsSeen = agg.ringDrops;
                s_netWinReported++;
                appLog(L"WARN", L"NetFilter",
                    (L"事件环溢出: 驱动累计丢弃 " + std::to_wstring(agg.ringDrops) +
                     L" 条(本次新增 " + std::to_wstring(lost) + L" 条) —— 有证据被顶出环").c_str());
            }
            break;
        }
        case NET_EVENT_SEND_DIAG: {
            // 驱动侧固定布局(见 NetFilter.cpp SendDiagDump):
            //   [0..1]hdrLen [2..3]ilen [4..5]bufLen [6..7]bufCount
            //   [8..39]输入头 32B   [40..87]BufferArray 指向内容 48B
            if (evt.Len < 8) break;
            unsigned int hdrLen = (unsigned)(evt.Data[0] | (evt.Data[1] << 8));
            unsigned int ilen   = (unsigned)(evt.Data[2] | (evt.Data[3] << 8));
            unsigned int bufLen = (unsigned)(evt.Data[4] | (evt.Data[5] << 8));
            unsigned int bufCnt = (unsigned)(evt.Data[6] | (evt.Data[7] << 8));
            if (hdrLen > 32) hdrLen = 32;
            if (bufLen > 48) bufLen = 48;
            if (evt.Len < (USHORT)(40 + bufLen)) bufLen = 0;
            std::wstring h1, h2;
            for (unsigned int i = 0; i < hdrLen; i++) {
                wchar_t b[8]; swprintf_s(b, L"%02X ", evt.Data[8 + i]); h1 += b;
            }
            for (unsigned int i = 0; i < bufLen; i++) {
                wchar_t b[8]; swprintf_s(b, L"%02X ", evt.Data[40 + i]); h2 += b;
            }
            s_netWinReported++;
            appLog(L"INFO", L"NetFilter",
                (L"SEND 布局抓样 PID=" + std::to_wstring(evt.Pid) + L" ilen=" + std::to_wstring(ilen) +
                 L" bufCount=" + std::to_wstring(bufCnt) + L" hdr: " + h1 +
                 L"| BufferArray(" + std::to_wstring(bufLen) + L"B): " + h2).c_str());
            break;
        }
        case NET_EVENT_SOCKET_CREATE:
            // P1 后驱动不再逐条推这三个码; 保留分支以兼容旧驱动, 也防未来回退
            netPidStatGet(evt.Pid)->sockets++;
            break;
        case NET_EVENT_SOCKET_SEND: {
            NetPidStat* pst = netPidStatGet(evt.Pid);
            pst->sends++;
            pst->sendBytes += evt.Len;
            break;
        }
        case NET_EVENT_RECV:
            netPidStatGet(evt.Pid)->recvs++;
            break;
        case NET_EVENT_BIND:
            netPidStatGet(evt.Pid)->binds++;
            break;
        case NET_EVENT_CONNECT_PARSEFAIL: {
            // 驱动解析不出 CONNECT 目标 = AFD 布局可能又变了 / 该连接完全不受黑名单拦截。
            // 旧 switch 无分支 → 完全静默; 只打 PID 也仍属"信息不全"。
            // 驱动把诊断字节放在 Data: [0..1]cl(小端) [2..3]ilen(小端) [4..]原始输入头部。
            // 一并打成 hex, 现场即可判定属哪一类失败:
            //   ilen<0x1C 输入过短 / +0x18 地址族非 2 也非 23 / IPv4 需 0x20 / IPv6 需 0x30 /
            //   纯 IPv6(非 ::ffff: 映射) 本轮不参与 IPv4 黑名单比对。
            unsigned int cl   = (evt.Len >= 2) ? (unsigned)(evt.Data[0] | (evt.Data[1] << 8)) : 0u;
            unsigned int ilen = (evt.Len >= 4) ? (unsigned)(evt.Data[2] | (evt.Data[3] << 8)) : 0u;
            unsigned int n    = (evt.Len > 4) ? (unsigned)(evt.Len - 4) : 0u;
            // 上限必须是 52(0x34) 以上, 否则会恰好切掉 +0x20 起的 IPv6 地址 ——
            // 之前写 32 就踩过这个坑: 只能看到 type=23 却看不到地址, 无法区分
            // "纯 IPv6"(本轮不比对) 与 "::ffff: 映射"(已还原)。驱动侧 NET_DIAG_RAW_MAX=64,
            // 所以 52 字节输入本来就完整送达, 是这里截断的。
            if (n > 56) n = 56;
            std::wstring hex;
            for (unsigned int i = 0; i < n; i++) {
                wchar_t b[8];
                swprintf_s(b, L"%02X ", evt.Data[4 + i]);
                hex += b;
            }
            s_netWinReported++;
            appLog(L"WARN", L"NetFilter",
                (L"CONNECT 地址解析失败 PID=" + std::to_wstring(evt.Pid) +
                 L" —— 该连接不受网络黑名单拦截 (cl=" + std::to_wstring(cl) +
                 L" ilen=" + std::to_wstring(ilen) + L") raw: " + hex).c_str());
            break;
        }
        case NET_EVENT_SOCKET_CONNECT: {
            // Data = SOCKADDR (IPv4: family[2] port[2]BE addr[4]; IPv6: family=23)
            unsigned short family = (evt.Len >= 2) ? (unsigned short)(evt.Data[0] | (evt.Data[1] << 8)) : 0;
            unsigned short port = 0;
            std::wstring ipStr;

            if (family == 2 /* AF_INET */ && evt.Len >= 8) {
                port = (unsigned short)((evt.Data[2] << 8) | evt.Data[3]);
                wchar_t ipBuf[24];
                swprintf_s(ipBuf, L"%u.%u.%u.%u",
                    evt.Data[4], evt.Data[5], evt.Data[6], evt.Data[7]);
                ipStr = ipBuf;
            } else if (family == 23 /* AF_INET6 */ && evt.Len >= 24) {
                port = (unsigned short)((evt.Data[2] << 8) | evt.Data[3]);
                wchar_t ipBuf[48];
                ipBuf[0] = 0;
                for (int g = 0; g < 8; g++) {
                    unsigned short w = (unsigned short)((evt.Data[8 + g*2] << 8) | evt.Data[8 + g*2 + 1]);
                    if (g > 0) wcscat_s(ipBuf, L":");
                    swprintf_s(ipBuf + wcslen(ipBuf), 8, L"%x", w);
                }
                ipStr = ipBuf;
            } else {
                break;  // 未知地址族，忽略
            }

            NetPidStat* pst = netPidStatGet(evt.Pid);
            pst->conns++;

            // P0: 回环只计数不落日志 —— 安全价值≈0, 而本机 node/DSH 自连会刷屏
            if (ipStr == L"127.0.0.1" || ipStr == L"::1") break;

            // P0: 按 (pid, ip, port) 去重 60 秒 (取代原来那个"32 槽满即失效"的按 PID 节流)
            unsigned int ipKey = 0;
            if (family == 2 && evt.Len >= 8) {
                ipKey = ((unsigned int)evt.Data[4] << 24) | ((unsigned int)evt.Data[5] << 16) |
                        ((unsigned int)evt.Data[6] << 8)  |  (unsigned int)evt.Data[7];
            } else if (family == 23 && evt.Len >= 24) {
                ipKey = ((unsigned int)evt.Data[20] << 24) | ((unsigned int)evt.Data[21] << 16) |
                        ((unsigned int)evt.Data[22] << 8)  |  (unsigned int)evt.Data[23];
            }
            unsigned long long nowMs = GetTickCount64();
            if (!netConnDedupNew(evt.Pid, ipKey, port, nowMs)) break;   // 窗口内重复, 只计数

            // 扇出告警: 恰好跨过阈值时报一次 —— 单进程短时间连大量不同目标 = 扫描/蠕虫
            unsigned long fanout = netConnFanout(evt.Pid, nowMs);
            if (fanout == NET_FANOUT_WARN) {
                pst->alerts++;
                s_netWinReported++;
                appLog(L"WARN", L"NetFilter",
                    (L"疑似扫描/蠕虫: PID " + std::to_wstring(evt.Pid) + L" " + getProcessName(evt.Pid) +
                     L" 在 60 秒内连接了 " + std::to_wstring(fanout) + L" 个不同目标").c_str());
            }

            // 抑制误报: 系统进程/已安装程序联网是正常行为，仅 EDR 记录
            if (TrustDecider::instance().isTrustedSystemSource(evt.Pid)) {
                pst->alerts++;
                s_netWinReported++;
                appLog(L"INFO", L"NetFilter",
                    (std::to_wstring(evt.Pid) + L" trusted process connect " + ipStr + L":" +
                     std::to_wstring(port)).c_str());
                break;
            }

            // 单进程告警配额: 超出只计数并合并进 60 秒汇总, 防止单进程无界刷日志
            if (pst->alerts >= NET_ALERT_CAP_PER_PID) { pst->dropped++; break; }
            pst->alerts++;
            s_netWinReported++;
            printf("[ZETA_NET] Connect PID=%lu %ls:%u\n", evt.Pid, ipStr.c_str(), port);
            // 网络连接告警: 改为仅记日志, 不再弹窗。
            // 原实现弹的是"无超时 HIPS 交互框", 但调用后既不等待也不处理用户选择,
            // 结果就是弹窗堆叠十几个、点了"阻止"也不会真正阻断。
            appLog(L"WARN", L"NetFilter",
                (std::wstring(L"连接告警 PID=") + std::to_wstring(evt.Pid) + L" " +
                 getProcessName(evt.Pid) + L" -> " + ipStr + L":" + std::to_wstring(port)).c_str());
            break;
        }
        default:
            // 驱动若有新增事件码, 计进"未细分", 由 60 秒汇总统一呈现(不再单独打日志)
            netUnhandled++;
            break;
        }
    }

    if (g_netFilterDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(g_netFilterDevice);
        g_netFilterDevice = INVALID_HANDLE_VALUE;
    }
    printf("[ZETA_NET] Event loop ended\n");
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

    // 尝试停止驱动服务
    SERVICE_STATUS ss;
    if (ControlService(hSvc, SERVICE_CONTROL_STOP, &ss)) {
        printf("[ZETA] Driver service stop signal sent\n");
        // 最多等待 3 秒让服务停止
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

    // 删除服务
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

    // ── P0-自杀修复: 记录自身 PID, 供评分/告警/处置三层绝对豁免 ──
    g_selfPid = GetCurrentProcessId();
    printf("[ZETA] Self PID = %lu\n", g_selfPid);

    // 初始化路径（动态，非硬编码）
    initPaths();

    // 设置崩溃处理程序以捕获并记录崩溃
    setupCrashHandler();

    // 设置控制台控制处理程序以捕获终止信号
    SetConsoleCtrlHandler(consoleHandler, TRUE);

    // 检查管理员标志以避免无限重新启动
    bool alreadyElevated = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--admin") == 0) {
            alreadyElevated = true;
        }
    }

    // 确保管理员权限
    if (!alreadyElevated) {
        ensureAdmin();
    }

    // 启用调试权限，让 SafeTerminateProcess 能打开同权限级别的进程
    EnableSeDebugPrivilege();

    // 检查隐藏标志
    bool hideOnStart = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "-hide") == 0) {
            hideOnStart = true;
        }
    }

    // 设置 Qt 插件路径（动态）
    std::wstring platformsPath = g_exeDir + L"\\platforms";
    SetEnvironmentVariableW(L"QT_QPA_PLATFORM_PLUGIN_PATH", platformsPath.c_str());
    SetEnvironmentVariableW(L"QT_QPA_FONTDIR", g_exeDir.c_str());

    // 先初始化 Qt UI
    printf("[ZETA] Initializing Qt UI...\n");
    if (zeta_ui_init() == 0) {
        printf("[ZETA] Failed to initialize Qt UI\n");
        return 1;
    }
    printf("[ZETA] Qt UI initialized\n");

    // 注册回调
    zeta_ui_set_config_callback(onConfigCallback);
    zeta_ui_set_tool_callback(onToolCallback);

    // 获取 zeta_ui_set_driver_status 函数指针
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
        p_zeta_ui_set_disk_status = (fn_zeta_ui_set_disk_status)GetProcAddress(hUi, "zeta_ui_set_disk_status");
        if (p_zeta_ui_set_disk_status) {
            printf("[ZETA] Loaded zeta_ui_set_disk_status\n");
        }
        p_zeta_ui_set_hips_response_callback = (fn_zeta_ui_set_hips_response_callback)GetProcAddress(hUi, "zeta_ui_set_hips_response_callback");
        if (p_zeta_ui_set_hips_response_callback) {
            printf("[ZETA] Loaded zeta_ui_set_hips_response_callback\n");
        }
        p_zeta_ui_show_hips_prompt = (fn_zeta_ui_show_hips_prompt)GetProcAddress(hUi, "zeta_ui_show_hips_prompt");
        if (p_zeta_ui_show_hips_prompt) {
            printf("[ZETA] Loaded zeta_ui_show_hips_prompt\n");
        }
        p_zeta_ui_set_rules_path = (fn_zeta_ui_set_rules_path)GetProcAddress(hUi, "zeta_ui_set_rules_path");
        if (p_zeta_ui_set_rules_path) {
            printf("[ZETA] Loaded zeta_ui_set_rules_path\n");
            std::wstring rulesPath = g_pluginsDir + L"\\Rules\\Rules_Hips.json";
            p_zeta_ui_set_rules_path(rulesPath.c_str());
        }
    }

    // 加载所有 C++ DLL（快速，无需驱动安装）
    if (!loadAllDlls()) {
        printf("[ZETA] WARNING: Some DLLs failed to load - functionality may be limited\n");
        appLog(L"WARN", L"App", L"Some DLLs failed to load");
    }

    // 恢复 UI 状态
    restoreUiState();

    // 显示或隐藏窗口（立即显示，不等待驱动）
    if (hideOnStart) {
        zeta_ui_hide();
        printf("[ZETA] Window hidden (start minimized to tray)\n");
    }
    else {
        zeta_ui_show();
        zeta_ui_set_status_text(L"正在加载驱动...");
        printf("[ZETA] Window shown\n");
    }

    // 在后台线程中启动异步驱动安装（非阻塞）
    printf("[ZETA] Launching async driver install...\n");
    std::thread driverThread(doDriverInstallWork);
    driverThread.detach();

    // BYOVD 启动自检 (2026-10-02): 探测已知漏洞驱动的设备对象是否【此刻已经存在】——
    // 覆盖"ZETA 启动之前本机就已被植入驱动"的情形, 那种情况不会产生任何 7010 事件。
    // 纯 Win32 探测(CreateFileW, 不发 IOCTL), 不需要驱动已就绪, 所以放在驱动安装
    // 线程之后、事件循环之前即可; 代价一次 CreateFileW, 无需另起线程。
    ReportLiveKnownBadDevices(L"ZETA 启动自检");

    // 事件循环
    printf("[ZETA] Entering event loop\n");
    appLog(L"INFO", L"App", L"ZETA Security started");
    zeta_ui_exec();

    // 清理
    printf("[ZETA] Shutting down...\n");

    // 0. 首先关闭 Qt UI — 立即移除托盘图标和窗口
    //    防止用户在清理期间再次点击"退出"
    zeta_ui_shutdown();

    // 1. 先停止后台服务
    if (p_zeta_monitor_stop_process_monitor) p_zeta_monitor_stop_process_monitor();
    if (p_zeta_driver_stop_loop) p_zeta_driver_stop_loop();
    if (p_zeta_driver_disconnect) p_zeta_driver_disconnect();
    ProcessBehaviorEngine::instance().stop();
    DriverEventProcessor::instance().stop();

    // 1b. 停止网络过滤器事件线程并卸载驱动
    g_netFilterRunning = false;
    Sleep(100);  // 给线程时间退出
    unloadNetFilter();

    // 1b. 停止磁盘过滤器事件线程 (GET_EVENT 为非阻塞轮询, 可立即退出)
    g_diskFilterRunning = false;
    if (g_diskFilterThread.joinable()) {
        g_diskFilterThread.join();
    }

    // 1b. 卸载磁盘过滤器 (ZETA_DiskFilter.sys)
    unloadDiskFilter();

    // 2. 卸载内核驱动服务 (ZETA_Drv.sys)
    unloadDriver();

    // 3. 释放 C++ DLL
    if (g_hHips) FreeLibrary(g_hHips);
    if (g_hMonitor) FreeLibrary(g_hMonitor);
    if (g_hDriver) FreeLibrary(g_hDriver);
    if (g_hEngine) FreeLibrary(g_hEngine);
    if (g_hCore) FreeLibrary(g_hCore);

    // 4. 等待后台线程完成
    if (g_repairThread.joinable()) {
        g_repairThread.join();
    }

    // 5. (zeta_ui_shutdown 已在上面调用 — UI 清理已完成)

    printf("[ZETA] Shutdown complete\n");
    return 0;
}