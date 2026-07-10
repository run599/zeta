#include "zeta_core.h"
#include <codecvt>

ThreadPool::ThreadPool(int numThreads) : m_stop(false) {
    for (int i = 0; i < numThreads; i++) {
        m_workers.emplace_back([this, i]() {
            Logger::instance().trace(L"ThreadPool", L"Start", L"Worker " + std::to_wstring(i));
            while (true) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(m_mutex);
                    m_cv.wait(lock, [this]() { return m_stop || !m_tasks.empty(); });
                    if (m_stop && m_tasks.empty()) return;
                    task = std::move(m_tasks.front());
                    m_tasks.pop();
                }
                try {
                    task();
                } catch (const std::exception& e) {
                    Logger::instance().error(L"ThreadPool", L"TaskError",
                        std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(e.what()));
                }
            }
        });
    }
}

ThreadPool::~ThreadPool() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stop = true;
    }
    m_cv.notify_all();
    for (auto& worker : m_workers) {
        if (worker.joinable()) worker.join();
    }
}

void ThreadPool::enqueue(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_tasks.push(std::move(task));
    }
    m_cv.notify_one();
}

void ThreadPool::waitAll() {
    // Busy wait until queue is empty
    while (true) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_tasks.empty()) break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}
