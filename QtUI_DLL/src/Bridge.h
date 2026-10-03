#ifndef BRIDGE_H
#define BRIDGE_H

#include <QObject>
#include <QString>
#include <QMetaType>
#include <QTimer>
#include <functional>
#include <queue>
#include <mutex>

/* Thread-safe bridge: receives commands from C++ UI layer (any thread)
   and forwards them to the Qt UI thread via queued signals. */

struct UIMessage {
    enum Type {
        MsgNone,
        MsgAppendLog,
        MsgSetTheme,
        MsgSetProtectionSwitch,
        MsgSetStatusText,
        MsgUpdateHipsRules,
        MsgRestoreSwitch,
        MsgRestoreCombo,
        MsgShowWindow,
        MsgHideWindow,
        MsgMinimizeWindow,
        MsgRestoreWindow,
        MsgShutdown,
    };
    Type type = MsgNone;
    QString str1, str2, str3;
    int int1 = 0, int2 = 0;
};

class Bridge : public QObject {
    Q_OBJECT
public:
    static Bridge* instance();

    void postMessage(const UIMessage& msg);
    void processQueue();

    // Callbacks (set from Python)
    void setConfigCallback(void* cb){ m_configCb = cb; }
    void setToolCallback(void* cb)  { m_toolCb = cb; }

    void invokeConfigCallback(const QString& key, int value);
    void invokeToolCallback(const QString& tool);

signals:
    void messageReady(); // connected to processQueue via Qt::QueuedConnection

private:
    Bridge();
    static Bridge* s_instance;
    std::queue<UIMessage> m_queue;
    std::mutex m_mutex;

    void* m_configCb = nullptr;
    void* m_toolCb = nullptr;
};

#endif // BRIDGE_H
