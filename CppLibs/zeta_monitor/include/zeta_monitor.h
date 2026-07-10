#pragma once
#include <Windows.h>
#include <evntrace.h>
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>

// ============================================================
// Lineage Node (Process Ancestry)
// ============================================================
struct LineageNode {
    unsigned long pid;
    unsigned long ppid;
    std::wstring name;
    std::wstring path;
    unsigned long long createTime;
    unsigned long long lastActivity;
    bool isScriptHost;
    int childCount;
    std::vector<std::wstring> releasedFiles;  // Files released by this process
};

// ============================================================
// System Repair Item
// ============================================================
struct RepairItem {
    std::wstring type;     // "mbr", "restrict", "file_type", "file_icon", "image", "wallpaper"
    std::wstring detail;
    bool canRepair;
};

// ============================================================
// Network Connection Info
// ============================================================
struct NetConnection {
    unsigned long pid;
    std::wstring localAddr;
    unsigned short localPort;
    std::wstring remoteAddr;
    unsigned short remotePort;
    unsigned long state;
};

// ============================================================
// Process Monitor
// ============================================================
class ProcessMonitor {
public:
    ProcessMonitor();
    ~ProcessMonitor();
    void start();
    void stop();
    bool isRunning() { return m_running; }

    using NewProcessCallback = std::function<void(unsigned long pid, unsigned long ppid,
        const std::wstring& name, const std::wstring& path)>;
    void setNewProcessCallback(NewProcessCallback cb) { m_newProcCb = cb; }

private:
    void monitorThread();
    std::vector<unsigned long> enumProcesses();
    std::wstring getProcessPath(unsigned long pid);
    unsigned long getParentPid(unsigned long pid);

    std::atomic<bool> m_running;
    std::thread m_thread;
    NewProcessCallback m_newProcCb;
    std::unordered_map<unsigned long, bool> m_knownPids;
};

// ============================================================
// File Monitor (ReadDirectoryChangesW)
// ============================================================
class FileMonitor {
public:
    FileMonitor();
    ~FileMonitor();
    void start(const std::vector<std::wstring>& watchDirs);
    void stop();
    bool isRunning() { return m_running; }

    using NewFileCallback = std::function<void(const std::wstring& path,
        const std::wstring& action)>;
    void setNewFileCallback(NewFileCallback cb) { m_newFileCb = cb; }

private:
    void monitorThread();

    std::atomic<bool> m_running;
    std::thread m_thread;
    std::vector<std::wstring> m_watchDirs;
    NewFileCallback m_newFileCb;
};

// ============================================================
// Network Monitor
// ============================================================
class NetworkMonitor {
public:
    NetworkMonitor();
    ~NetworkMonitor();
    void start();
    void stop();

    std::vector<NetConnection> getConnections();
    std::vector<std::wstring> getBlacklist() { return m_blacklist; }
    void addToBlacklist(const std::wstring& addr);
    void removeFromBlacklist(const std::wstring& addr);

    using NewConnectionCallback = std::function<void(const NetConnection&)>;
    void setNewConnectionCallback(NewConnectionCallback cb) { m_newConnCb = cb; }

private:
    void monitorThread();

    std::atomic<bool> m_running;
    std::thread m_thread;
    std::vector<std::wstring> m_blacklist;
    NewConnectionCallback m_newConnCb;
};

// ============================================================
// ETW Session (Process Events)
// ============================================================
class EtwMonitor {
public:
    EtwMonitor();
    ~EtwMonitor();
    bool start();
    void stop();
    bool isRunning() { return m_running; }

    using ProcessEventCallback = std::function<void(unsigned long pid,
        unsigned long ppid, const std::wstring& name, bool isStart)>;
    void setCallback(ProcessEventCallback cb) { m_callback = cb; }

private:
    static void WINAPI eventRecordCallback(PEVENT_RECORD pEvent);

    std::atomic<bool> m_running;
    std::thread m_traceThread;
    ProcessEventCallback m_callback;
    ULONGLONG m_sessionHandle;
};

// ============================================================
// Lineage Tracker
// ============================================================
class LineageTracker {
public:
    static LineageTracker& instance();

    void enable();
    void disable();
    bool isEnabled() { return m_enabled; }

    void addProcess(unsigned long pid, unsigned long ppid,
        const std::wstring& name, const std::wstring& path);
    void removeProcess(unsigned long pid);
    LineageNode* getNode(unsigned long pid);

    void addReleasedFile(unsigned long pid, const std::wstring& filePath);
    std::vector<std::wstring> getRecentFiles(unsigned long pid, int seconds = 30);

    // Alert analysis
    bool analyzeAlert(unsigned long parentPid,
        std::wstring& outAlertType, std::wstring& outDetail);

    // SilverFox detection
    bool detectSilverFox(const std::vector<std::wstring>& files,
        std::wstring& outDetail);

private:
    LineageTracker() : m_enabled(false) {}
    LineageTracker(const LineageTracker&) = delete;
    LineageTracker& operator=(const LineageTracker&) = delete;

    void cleanup();

    std::mutex m_mutex;
    std::atomic<bool> m_enabled;
    std::unordered_map<unsigned long, LineageNode> m_nodes;
};

// ============================================================
// System Repair
// ============================================================
class SystemRepair {
public:
    static SystemRepair& instance();

    std::vector<RepairItem> scan();
    bool repair(const std::wstring& type);

private:
    SystemRepair() {}
    SystemRepair(const SystemRepair&) = delete;
    SystemRepair& operator=(const SystemRepair&) = delete;

    bool checkMbr();
    bool checkRestrict();
    bool checkFileType();
    bool checkFileIcon();
    bool checkImageHijack();
    bool checkWallpaper();

    bool repairMbr();
    bool repairRestrict();
    bool repairFileType();
    bool repairFileIcon();
    bool repairImageHijack();
    bool repairWallpaper();
};

// ============================================================
// DLL Export
// ============================================================
#ifdef ZETA_MONITOR_EXPORTS
#define ZETA_MONITOR_API __declspec(dllexport)
#else
#define ZETA_MONITOR_API __declspec(dllimport)
#endif

extern "C" {
    ZETA_MONITOR_API void zeta_monitor_start_process_monitor();
    ZETA_MONITOR_API void zeta_monitor_stop_process_monitor();
    ZETA_MONITOR_API void zeta_monitor_set_new_process_callback(
        void(*cb)(unsigned long pid, unsigned long ppid, const wchar_t* name, const wchar_t* path));

    ZETA_MONITOR_API void zeta_monitor_start_etw();
    ZETA_MONITOR_API void zeta_monitor_stop_etw();

    ZETA_MONITOR_API void zeta_monitor_lineage_enable();
    ZETA_MONITOR_API void zeta_monitor_lineage_disable();
    ZETA_MONITOR_API int zeta_monitor_lineage_is_enabled();

    ZETA_MONITOR_API void zeta_monitor_system_repair_scan(wchar_t* outJson, int maxSize);
    ZETA_MONITOR_API int zeta_monitor_system_repair_exec(const wchar_t* type);
}
