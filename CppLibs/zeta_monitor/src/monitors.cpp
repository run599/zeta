#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WIN32_WINNT 0x0601
#define WINVER 0x0601

#ifndef PROCESS_TRACE_MODE_REAL_TIME
#define PROCESS_TRACE_MODE_REAL_TIME 0x00000100
#endif
#ifndef PROCESS_TRACE_MODE_EVENT_RECORD
#define PROCESS_TRACE_MODE_EVENT_RECORD 0x10000000
#endif
#ifndef INVALID_PROCESSTRACE_HANDLE
#define INVALID_PROCESSTRACE_HANDLE ((TRACEHANDLE)(ULONG_PTR)-1)
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#define INITGUID
#include <tdh.h>
#undef INITGUID
#include <Windows.h>
#include "zeta_monitor.h"
#include "../../zeta_core/include/zeta_core.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <codecvt>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// ============================================================
// ProcessMonitor
// ============================================================
ProcessMonitor::ProcessMonitor() : m_running(false) {}

ProcessMonitor::~ProcessMonitor() { stop(); }

void ProcessMonitor::start() {
    if (m_running) return;
    m_running = true;
    m_thread = std::thread(&ProcessMonitor::monitorThread, this);
    Logger::instance().info(L"Monitor", L"ProcessMon", L"Started");
}

void ProcessMonitor::stop() {
    m_running = false;
    if (m_thread.joinable()) m_thread.join();
    Logger::instance().info(L"Monitor", L"ProcessMon", L"Stopped");
}

void ProcessMonitor::monitorThread() {
    while (m_running) {
        auto currentPids = enumProcesses();

        // Check for new processes
        for (auto pid : currentPids) {
            if (!m_running) break;

            // Filter kernel/system processes (PID <= 4)
            // PID 0 = Idle, PID 1 = System init (minimal), PID 2 = Session Manager, 
            // PID 3 = unknown, PID 4 = System kernel process
            if (pid <= 4) {
                continue;
            }

            if (m_knownPids.find(pid) == m_knownPids.end()) {
                m_knownPids[pid] = true;
                std::wstring path = getProcessPath(pid);
                unsigned long ppid = getParentPid(pid);

                // Skip if path is empty (process may have exited)
                if (path.empty()) {
                    continue;
                }

                std::wstring name = path.substr(path.find_last_of(L"\\/") + 1);

                Logger::instance().debug(L"Monitor", L"NewProc",
                    L"PID=" + std::to_wstring(pid) + L" PPID=" + std::to_wstring(ppid) +
                    L" " + name);

                if (m_newProcCb) {
                    m_newProcCb(pid, ppid, name, path);
                }

                // Also feed into LineageTracker for process ancestry tracking
                LineageTracker::instance().addProcess(pid, ppid, name, path);
            }
        }

        // Check for removed processes
        for (auto it = m_knownPids.begin(); it != m_knownPids.end();) {
            bool found = false;
            for (auto pid : currentPids) {
                if (it->first == pid) { found = true; break; }
            }
            if (!found) {
                it = m_knownPids.erase(it);
            } else {
                ++it;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

std::vector<unsigned long> ProcessMonitor::enumProcesses() {
    std::vector<unsigned long> pids;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return pids;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            pids.push_back(pe.th32ProcessID);
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return pids;
}

std::wstring ProcessMonitor::getProcessPath(unsigned long pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return L"";

    wchar_t path[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        CloseHandle(hProcess);
        return path;
    }
    CloseHandle(hProcess);
    return L"";
}

unsigned long ProcessMonitor::getParentPid(unsigned long pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { sizeof(pe) };
    unsigned long ppid = 0;
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                ppid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return ppid;
}

// ============================================================
// FileMonitor
// ============================================================
FileMonitor::FileMonitor() : m_running(false) {}
FileMonitor::~FileMonitor() { stop(); }

void FileMonitor::start(const std::vector<std::wstring>& watchDirs) {
    if (m_running) return;
    m_watchDirs = watchDirs;
    m_running = true;
    m_thread = std::thread(&FileMonitor::monitorThread, this);
    Logger::instance().info(L"Monitor", L"FileMon", L"Started watching " + std::to_wstring(watchDirs.size()) + L" dirs");
}

void FileMonitor::stop() {
    m_running = false;
    if (m_thread.joinable()) m_thread.join();
    Logger::instance().info(L"Monitor", L"FileMon", L"Stopped");
}

void FileMonitor::monitorThread() {
    // Use ReadDirectoryChangesW for each watched directory
    std::vector<HANDLE> dirHandles;
    std::vector<OVERLAPPED> overlapped;
    std::vector<std::vector<char>> buffers;

    for (const auto& dir : m_watchDirs) {
        HANDLE hDir = CreateFileW(dir.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            nullptr);
        if (hDir == INVALID_HANDLE_VALUE) {
            Logger::instance().warn(L"Monitor", L"FileMon", L"Cannot watch: " + dir);
            continue;
        }
        dirHandles.push_back(hDir);
        overlapped.push_back({0});
        buffers.push_back(std::vector<char>(65536));
    }

    Logger::instance().info(L"Monitor", L"FileMon", L"Watching " + std::to_wstring(dirHandles.size()) + L" directories");

    while (m_running) {
        for (size_t i = 0; i < dirHandles.size(); i++) {
            if (!m_running) break;
            DWORD bytesReturned = 0;
            BOOL ok = ReadDirectoryChangesW(
                dirHandles[i],
                buffers[i].data(),
                static_cast<DWORD>(buffers[i].size()),
                TRUE,  // Watch subtree
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                &bytesReturned,
                &overlapped[i],
                nullptr);
            if (ok) {
                GetOverlappedResult(dirHandles[i], &overlapped[i], &bytesReturned, TRUE);
                if (bytesReturned > 0) {
                    FILE_NOTIFY_INFORMATION* fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffers[i].data());
                    while (true) {
                        std::wstring fileName(fni->FileName, fni->FileNameLength / sizeof(wchar_t));
                        std::wstring fullPath = m_watchDirs[i] + L"\\" + fileName;
                        std::wstring action;
                        switch (fni->Action) {
                            case FILE_ACTION_ADDED: action = L"added"; break;
                            case FILE_ACTION_REMOVED: action = L"removed"; break;
                            case FILE_ACTION_MODIFIED: action = L"modified"; break;
                            case FILE_ACTION_RENAMED_OLD_NAME: action = L"renamed_from"; break;
                            case FILE_ACTION_RENAMED_NEW_NAME: action = L"renamed_to"; break;
                            default: action = L"unknown"; break;
                        }
                        Logger::instance().trace(L"Monitor", L"FileMon",
                            action + L": " + fileName);
                        if (m_newFileCb) {
                            m_newFileCb(fullPath, action);
                        }
                        if (fni->NextEntryOffset == 0) break;
                        fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                            reinterpret_cast<char*>(fni) + fni->NextEntryOffset);
                    }
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    for (auto h : dirHandles) {
        CancelIoEx(h, nullptr);
        CloseHandle(h);
    }
    Logger::instance().info(L"Monitor", L"FileMon", L"Monitor thread ended");
}

// ============================================================
// NetworkMonitor
// ============================================================
NetworkMonitor::NetworkMonitor() : m_running(false) {}
NetworkMonitor::~NetworkMonitor() { stop(); }

void NetworkMonitor::start() {
    if (m_running) return;
    m_running = true;
    m_thread = std::thread(&NetworkMonitor::monitorThread, this);
    Logger::instance().info(L"Monitor", L"NetMon", L"Started");
}

void NetworkMonitor::stop() {
    m_running = false;
    if (m_thread.joinable()) m_thread.join();
    Logger::instance().info(L"Monitor", L"NetMon", L"Stopped");
}

void NetworkMonitor::addToBlacklist(const std::wstring& addr) {
    m_blacklist.push_back(addr);
    Logger::instance().info(L"Monitor", L"NetBlacklist", L"Added: " + addr);
}

void NetworkMonitor::removeFromBlacklist(const std::wstring& addr) {
    for (auto it = m_blacklist.begin(); it != m_blacklist.end(); ++it) {
        if (*it == addr) { m_blacklist.erase(it); break; }
    }
}

void NetworkMonitor::monitorThread() {
    // Simple TCP connection monitor using GetExtendedTcpTable
    while (m_running) {
        auto conns = getConnections();
        for (const auto& conn : conns) {
            for (const auto& bl : m_blacklist) {
                if (conn.remoteAddr.find(bl) != std::wstring::npos) {
                    if (m_newConnCb) m_newConnCb(conn);
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

std::vector<NetConnection> NetworkMonitor::getConnections() {
    std::vector<NetConnection> result;

    typedef DWORD(WINAPI* GetExtendedTcpTable_t)(PVOID, PDWORD, BOOL, ULONG, ULONG, ULONG);
    HMODULE iphlpapi = GetModuleHandleW(L"iphlpapi.dll");
    if (!iphlpapi) return result;

    auto fnGetExtendedTcpTable = (GetExtendedTcpTable_t)
        GetProcAddress(iphlpapi, "GetExtendedTcpTable");
    if (!fnGetExtendedTcpTable) return result;

    ULONG size = 0;
    fnGetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return result;

    std::vector<char> buf(size);
    auto table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buf.data());
    if (fnGetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return result;

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        NetConnection conn;
        conn.pid = table->table[i].dwOwningPid;
        conn.localPort = ntohs((u_short)table->table[i].dwLocalPort);
        conn.remotePort = ntohs((u_short)table->table[i].dwRemotePort);
        conn.state = table->table[i].dwState;

        struct in_addr localAddr, remoteAddr;
        localAddr.S_un.S_addr = table->table[i].dwLocalAddr;
        remoteAddr.S_un.S_addr = table->table[i].dwRemoteAddr;

        char buf[32];
        inet_ntop(AF_INET, &localAddr, buf, sizeof(buf));
        conn.localAddr = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(buf);
        inet_ntop(AF_INET, &remoteAddr, buf, sizeof(buf));
        conn.remoteAddr = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(buf);

        result.push_back(conn);
    }

    return result;
}

// ============================================================
// ETW Monitor
// ============================================================
EtwMonitor::EtwMonitor() : m_running(false), m_sessionHandle(0) {}

EtwMonitor::~EtwMonitor() { stop(); }

bool EtwMonitor::start() {
    Logger::instance().info(L"Monitor", L"ETW", L"Starting ETW session");

    // Start trace session
    EVENT_TRACE_PROPERTIES* props = nullptr;
    ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAMEW);
    std::vector<char> buf(bufSize);
    props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf.data());
    ZeroMemory(props, bufSize);
    props->Wnode.BufferSize = bufSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;  // QPC timestamps
    props->Wnode.Guid = SystemTraceControlGuid;
    props->EnableFlags = EVENT_TRACE_FLAG_PROCESS;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(&m_sessionHandle, KERNEL_LOGGER_NAMEW, props);
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
        Logger::instance().error(L"Monitor", L"ETW",
            L"StartTraceW failed: " + WinHelpers::formatError(status));
        return false;
    }

    // Open trace
    EVENT_TRACE_LOGFILEW logfile = {0};
    logfile.LoggerName = const_cast<wchar_t*>(KERNEL_LOGGER_NAMEW);
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = eventRecordCallback;
    logfile.Context = this;

    TRACEHANDLE hTrace = OpenTraceW(&logfile);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
        Logger::instance().error(L"Monitor", L"ETW", L"OpenTraceW failed");
        return false;
    }

    m_running = true;
    m_traceThread = std::thread([hTrace]() mutable {
        ProcessTrace(&hTrace, 1, nullptr, nullptr);
    });

    Logger::instance().info(L"Monitor", L"ETW", L"ETW session started");
    return true;
}

void EtwMonitor::stop() {
    m_running = false;
    if (m_sessionHandle) {
        ControlTraceW(m_sessionHandle, KERNEL_LOGGER_NAMEW, nullptr, EVENT_TRACE_CONTROL_STOP);
        m_sessionHandle = 0;
    }
    if (m_traceThread.joinable()) m_traceThread.join();
    Logger::instance().info(L"Monitor", L"ETW", L"ETW session stopped");
}

void WINAPI EtwMonitor::eventRecordCallback(PEVENT_RECORD pEvent) {
    if (!pEvent) return;

    // Process events (ID=1 = create, ID=2 = delete)
    USHORT eid = pEvent->EventHeader.EventDescriptor.Id;
    if (eid == 1 || eid == 2) {
        // Parse process event data
        // Format depends on Windows version
        // Simplified: just log that we got an event
        Logger::instance().trace(L"Monitor", L"ETW",
            L"Event ID=" + std::to_wstring(eid));
    }
}

// C DLL exports
extern "C" {

static ProcessMonitor g_processMon;
static EtwMonitor g_etwMon;

static void(*g_newProcCb)(unsigned long pid, unsigned long ppid, const wchar_t* name, const wchar_t* path) = nullptr;

__declspec(dllexport) void zeta_monitor_start_process_monitor() {
    g_processMon.start();
}

__declspec(dllexport) void zeta_monitor_stop_process_monitor() {
    g_processMon.stop();
}

__declspec(dllexport) void zeta_monitor_set_new_process_callback(
    void(*cb)(unsigned long pid, unsigned long ppid, const wchar_t* name, const wchar_t* path)) {
    g_newProcCb = cb;
    g_processMon.setNewProcessCallback([](unsigned long pid, unsigned long ppid, 
        const std::wstring& name, const std::wstring& path) {
        if (g_newProcCb) {
            g_newProcCb(pid, ppid, name.c_str(), path.c_str());
        }
    });
}

__declspec(dllexport) void zeta_monitor_start_etw() {
    g_etwMon.start();
}

__declspec(dllexport) void zeta_monitor_stop_etw() {
    g_etwMon.stop();
}

__declspec(dllexport) void zeta_monitor_lineage_enable() {
    LineageTracker::instance().enable();
}

__declspec(dllexport) void zeta_monitor_lineage_disable() {
    LineageTracker::instance().disable();
}

__declspec(dllexport) int zeta_monitor_lineage_is_enabled() {
    return LineageTracker::instance().isEnabled() ? 1 : 0;
}

__declspec(dllexport) void zeta_monitor_system_repair_scan(wchar_t* outJson, int maxSize) {
    auto items = SystemRepair::instance().scan();
    std::wstring json = L"[";
    for (size_t i = 0; i < items.size(); i++) {
        if (i > 0) json += L",";
        json += L"{\"type\":\"" + items[i].type + L"\",\"detail\":\"" +
                items[i].detail + L"\",\"canRepair\":" +
                (items[i].canRepair ? L"true" : L"false") + L"}";
    }
    json += L"]";
    if (outJson && maxSize > 0) {
        wcsncpy_s(outJson, maxSize, json.c_str(), _TRUNCATE);
    }
}

__declspec(dllexport) int zeta_monitor_system_repair_exec(const wchar_t* type) {
    return SystemRepair::instance().repair(type ? type : L"") ? 1 : 0;
}

} // extern "C"
