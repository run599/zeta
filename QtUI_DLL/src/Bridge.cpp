#include "Bridge.h"
#include <QApplication>
#include <QDebug>

Bridge* Bridge::s_instance = nullptr;

Bridge::Bridge()
    : QObject(nullptr)
{
    connect(this, &Bridge::messageReady, this, &Bridge::processQueue, Qt::QueuedConnection);
}

Bridge* Bridge::instance() {
    if (!s_instance) {
        s_instance = new Bridge();
    }
    return s_instance;
}

void Bridge::postMessage(const UIMessage& msg) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_queue.push(msg);
    }
    emit messageReady();
}

void Bridge::processQueue() {
    std::queue<UIMessage> local;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::swap(local, m_queue);
    }
    // Messages are forwarded via MainWindow's slots, connected in zeta_ui_export.cpp
    while (!local.empty()) {
        // The actual processing is done by MainWindow via direct signal connections
        local.pop();
    }
}

void Bridge::invokeConfigCallback(const QString& key, int value) {
    if (m_configCb) {
        auto cb = reinterpret_cast<void(*)(const wchar_t*, int)>(m_configCb);
        cb((const wchar_t*)key.utf16(), value);
    }
}

void Bridge::invokeToolCallback(const QString& tool) {
    if (m_toolCb) {
        auto cb = reinterpret_cast<void(*)(const wchar_t*)>(m_toolCb);
        cb((const wchar_t*)tool.utf16());
    }
}
