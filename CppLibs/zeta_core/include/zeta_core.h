#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <fstream>
#include <sstream>
#include <ctime>
#include <unordered_map>
#include <atomic>
#include <queue>
#include <thread>
#include <condition_variable>

// ============================================================
// DLL Export macro
// ============================================================
#ifdef ZETA_CORE_EXPORTS
#define ZETA_CORE_API __declspec(dllexport)
#else
#define ZETA_CORE_API __declspec(dllimport)
#endif

// ============================================================
// Common Types & Constants
// ============================================================
#pragma pack(push, 1)
struct ZETA_MESSAGE {
    unsigned long MessageCode;
    unsigned long ProcessId;
    wchar_t Path[1024];
};

struct ZETA_USER_MESSAGE {
    unsigned long Command;
    wchar_t Path[1024];
};
#pragma pack(pop)

// Message codes (driver -> user)
const unsigned long ZETA_MSG_LOG = 7000;
const unsigned long ZETA_MSG_LINEAGE_ALERT = 7001;
const unsigned long ZETA_MSG_RANSOM_HEADER_ALERT = 7002;
const unsigned long ZETA_MSG_RANSOM_EXPERIMENTAL = 7003;
const unsigned long ZETA_MSG_LINEAGE_FALLBACK = 7004;

// Command codes (user -> driver)
const unsigned long ZETA_CMD_GET_INITLOG = 3;
const unsigned long ZETA_CMD_ALLOW_OP = 4;
const unsigned long ZETA_CMD_DENY_OP = 5;
const unsigned long ZETA_CMD_SET_LINEAGE_TRACKER = 6;
const unsigned long ZETA_CMD_SET_RANSOM_EXPERIMENTAL = 7;
const unsigned long ZETA_CMD_ROLLBACK_MARK = 8;
const unsigned long ZETA_CMD_RELOAD_RULES = 15;

// Block codes from driver
const unsigned long BLOCK_CODES[] = { 2001, 3001, 4001, 5001, 6001, 6002 };
const int BLOCK_CODES_COUNT = 6;

// ============================================================
// Log Levels
// ============================================================
enum LogLevel {
    LOG_TRACE = 0,
    LOG_DEBUG = 1,
    LOG_INFO = 2,
    LOG_WARN = 3,
    LOG_ERROR = 4,
    LOG_FATAL = 5
};

// ============================================================
// Logger - Thread-safe, file + callback
// ============================================================
class ZETA_CORE_API Logger {
public:
    static Logger& instance();
    void init(const std::wstring& logDir, bool consoleOutput = false);
    void setCallback(std::function<void(const std::wstring&)> cb);
    void log(LogLevel level, const std::wstring& module, const std::wstring& action, const std::wstring& detail);
    void flush();

    // Convenience methods
    void info(const std::wstring& module, const std::wstring& action, const std::wstring& detail = L"");
    void warn(const std::wstring& module, const std::wstring& action, const std::wstring& detail = L"");
    void error(const std::wstring& module, const std::wstring& action, const std::wstring& detail = L"");
    void debug(const std::wstring& module, const std::wstring& action, const std::wstring& detail = L"");
    void trace(const std::wstring& module, const std::wstring& action, const std::wstring& detail = L"");

private:
    Logger() : m_running(false), m_consoleOutput(false) {}
    ~Logger() { stop(); }
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void writerThread();
    void stop();
    std::wstring levelToString(LogLevel level);
    std::wstring currentTimestamp();

    std::mutex m_mutex;
    std::wstring m_logPath;
    std::ofstream m_file;
    std::queue<std::wstring> m_queue;
    std::thread m_writer;
    std::condition_variable m_cv;
    bool m_running;
    bool m_consoleOutput;
    std::function<void(const std::wstring&)> m_callback;
};

// ============================================================
// Config Manager - JSON-based config
// ============================================================
class ZETA_CORE_API ConfigManager {
public:
    static ConfigManager& instance();
    bool load(const std::wstring& configPath);
    bool save();
    std::wstring getString(const std::wstring& key, const std::wstring& defaultVal = L"");
    int getInt(const std::wstring& key, int defaultVal = 0);
    bool getBool(const std::wstring& key, bool defaultVal = false);
    std::vector<std::wstring> getStringArray(const std::wstring& key);
    void setString(const std::wstring& key, const std::wstring& val);
    void setInt(const std::wstring& key, int val);
    void setBool(const std::wstring& key, bool val);
    std::wstring getConfigDir() { return m_configDir; }

private:
    ConfigManager() {}
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;
    std::wstring escapeJson(const std::wstring& s);
    std::wstring unescapeJson(const std::wstring& s);

    std::mutex m_mutex;
    std::wstring m_configPath;
    std::wstring m_configDir;
    std::unordered_map<std::wstring, std::wstring> m_values;
};

// ============================================================
// Windows Helpers
// ============================================================
namespace WinHelpers {
    ZETA_CORE_API bool isWindowsVistaOrLater();
    ZETA_CORE_API bool isElevated();
    ZETA_CORE_API std::wstring expandEnv(const std::wstring& path);
    ZETA_CORE_API std::wstring getProgramDataPath();
    ZETA_CORE_API bool createDirectoryRecursive(const std::wstring& path);
    ZETA_CORE_API bool fileExists(const std::wstring& path);
    ZETA_CORE_API bool pathIsDirectory(const std::wstring& path);
    ZETA_CORE_API std::wstring getModulePath(HMODULE hModule = nullptr);
    ZETA_CORE_API std::wstring getTempPath();
    ZETA_CORE_API unsigned long getLastError();
    ZETA_CORE_API std::wstring formatError(unsigned long errCode);

    // JSON helper: simple parse for flat key-value
    ZETA_CORE_API bool parseSimpleJson(const std::wstring& json, std::unordered_map<std::wstring, std::wstring>& out);
    ZETA_CORE_API std::wstring toSimpleJson(const std::unordered_map<std::wstring, std::wstring>& map);
}

// ============================================================
// Thread Pool
// ============================================================
class ZETA_CORE_API ThreadPool {
public:
    ThreadPool(int numThreads = 4);
    ~ThreadPool();
    void enqueue(std::function<void()> task);
    void waitAll();

private:
    std::vector<std::thread> m_workers;
    std::queue<std::function<void()>> m_tasks;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    bool m_stop;
};

extern "C" {
    ZETA_CORE_API void zeta_core_init(const wchar_t* logDir);
    ZETA_CORE_API void zeta_core_log(const wchar_t* level, const wchar_t* module, const wchar_t* action, const wchar_t* detail);
    ZETA_CORE_API int zeta_core_config_load(const wchar_t* path);
    ZETA_CORE_API int zeta_core_config_get_bool(const wchar_t* key, int defaultVal);
    ZETA_CORE_API void zeta_core_config_set_bool(const wchar_t* key, int val);
    ZETA_CORE_API int zeta_core_config_save();
}
