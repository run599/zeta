#include "zeta_core.h"
#include <Windows.h>
#include <iomanip>
#include <codecvt>

Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

void Logger::init(const std::wstring& logDir, bool consoleOutput) {
    printf("[logger] init called, logDir=%S\n", logDir.c_str());
    std::wstring logPath;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_running) {
            printf("[logger] already running, returning\n");
            return;
        }

        m_consoleOutput = consoleOutput;
        m_logPath = logDir + L"\\ZETA_CPP.log";
        logPath = m_logPath;
        printf("[logger] logPath=%S\n", m_logPath.c_str());

        // Rotate old log
        printf("[logger] checking if log exists...\n");
        if (WinHelpers::fileExists(m_logPath)) {
            printf("[logger] rotating old log...\n");
            std::wstring bak = m_logPath + L".bak";
            CopyFileW(m_logPath.c_str(), bak.c_str(), FALSE);
        }

        printf("[logger] opening file...\n");
        m_file.open(m_logPath, std::ios::out | std::ios::trunc);
        if (!m_file.is_open()) {
            printf("[logger] fallback to temp...\n");
            // Fallback to temp
            m_logPath = WinHelpers::getTempPath() + L"\\ZETA_CPP.log";
            logPath = m_logPath;
            m_file.open(m_logPath, std::ios::out | std::ios::trunc);
        }
        printf("[logger] file open status: %d\n", m_file.is_open() ? 1 : 0);

        m_running = true;
        printf("[logger] creating writer thread...\n");
        m_writer = std::thread(&Logger::writerThread, this);
        printf("[logger] writer thread created\n");
    } // release lock before log

    info(L"Core", L"LogInit", L"Logger initialized: " + logPath);
    printf("[logger] init done\n");
}

void Logger::setCallback(std::function<void(const std::wstring&)> cb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_callback = cb;
}

void Logger::log(LogLevel level, const std::wstring& module,
    const std::wstring& action, const std::wstring& detail) {
    // Skip low-risk (TRACE/DEBUG) logs — only INFO/WARN/ERROR/FATAL matter
    if (level < LOG_INFO) return;

    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_running) return;

    std::wstringstream ss;
    ss << L"[" << currentTimestamp() << L"] | "
       << std::setw(4) << levelToString(level) << L" | "
       << module;
    if (!action.empty()) ss << L" | " << action;
    if (!detail.empty()) ss << L" | Detail: " << detail;

    m_queue.push(ss.str());
    m_cv.notify_one();
}

void Logger::info(const std::wstring& mod, const std::wstring& act, const std::wstring& det) {
    log(LOG_INFO, mod, act, det);
}
void Logger::warn(const std::wstring& mod, const std::wstring& act, const std::wstring& det) {
    log(LOG_WARN, mod, act, det);
}
void Logger::error(const std::wstring& mod, const std::wstring& act, const std::wstring& det) {
    log(LOG_ERROR, mod, act, det);
}
void Logger::debug(const std::wstring& mod, const std::wstring& act, const std::wstring& det) {
    log(LOG_DEBUG, mod, act, det);
}
void Logger::trace(const std::wstring& mod, const std::wstring& act, const std::wstring& det) {
    log(LOG_TRACE, mod, act, det);
}

void Logger::flush() {
    std::unique_lock<std::mutex> lock(m_mutex);
    if (m_file.is_open()) {
        m_file.flush();
    }
}

void Logger::stop() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_running = false;
    }
    m_cv.notify_all();
    if (m_writer.joinable()) {
        m_writer.join();
    }
    if (m_file.is_open()) {
        m_file.close();
    }
}

void Logger::writerThread() {
    printf("[writer] writer thread started\n");
    while (true) {
        std::unique_lock<std::mutex> lock(m_mutex);
        printf("[writer] waiting for work...\n");
        m_cv.wait(lock, [this]() { return !m_queue.empty() || !m_running; });
        printf("[writer] woke up, running=%d, queue=%zu\n", m_running ? 1 : 0, m_queue.size());

        while (!m_queue.empty()) {
            auto line = m_queue.front();
            m_queue.pop();
            printf("[writer] writing: %S\n", line.c_str());

            if (m_file.is_open()) {
                m_file << std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(line) << std::endl;
            }
            if (m_consoleOutput) {
                OutputDebugStringW((line + L"\n").c_str());
            }
            if (m_callback) {
                m_callback(line);
            }
        }

        if (!m_running && m_queue.empty()) break;
    }
    printf("[writer] writer thread exiting\n");
}

std::wstring Logger::levelToString(LogLevel level) {
    switch (level) {
        case LOG_TRACE: return L"TRACE";
        case LOG_DEBUG: return L"DEBUG";
        case LOG_INFO:  return L"INFO";
        case LOG_WARN:  return L"WARN";
        case LOG_ERROR: return L"ERROR";
        case LOG_FATAL: return L"FATAL";
        default: return L"UNKN";
    }
}

std::wstring Logger::currentTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[64];
    swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d:%02d.%03d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}
