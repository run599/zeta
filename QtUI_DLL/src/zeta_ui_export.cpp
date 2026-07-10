#include "zeta_ui_export.h"
#include "MainWindow.h"
#include "Bridge.h"

#include <QApplication>
#include <QThread>
#include <QTimer>
#include <QDebug>
#include <mutex>
#include <condition_variable>

static QApplication* g_app = nullptr;
static MainWindow* g_window = nullptr;
static std::mutex g_mutex;

// ── Exported C API ───────────────────────────────────────────────

ZETA_API int zeta_ui_init(void) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_app) return 1;

    int argc = 0;
    wchar_t** argv = nullptr;
    g_app = new QApplication(argc, reinterpret_cast<char**>(argv));
    g_app->setApplicationName("ZETA Security");
    g_app->setQuitOnLastWindowClosed(false);

    Bridge* bridge = Bridge::instance();
    g_window = new MainWindow();

    return 1;
}

ZETA_API void zeta_ui_show(void) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_window) {
        g_window->show();
    }
}

ZETA_API void zeta_ui_hide(void) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_window) {
        g_window->hide();
    }
}

ZETA_API void zeta_ui_minimize(void) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_window) {
        g_window->showMinimized();
    }
}

ZETA_API void zeta_ui_restore(void) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_window) {
        g_window->showNormal();
        g_window->activateWindow();
        g_window->raise();
    }
}

ZETA_API void zeta_ui_append_log(const wchar_t* level, const wchar_t* action, const wchar_t* detail) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_window) {
        QString l = QString::fromWCharArray(level);
        QString a = QString::fromWCharArray(action);
        QString d = detail ? QString::fromWCharArray(detail) : QString();
        QMetaObject::invokeMethod(g_window, "onAppendLog", Qt::QueuedConnection,
            Q_ARG(QString, l), Q_ARG(QString, a), Q_ARG(QString, d));
    }
}

ZETA_API void zeta_ui_set_theme(const wchar_t* theme_key) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_window) {
        QString key = QString::fromWCharArray(theme_key);
        QMetaObject::invokeMethod(g_window, "onSetTheme", Qt::QueuedConnection,
            Q_ARG(QString, key));
    }
}

ZETA_API void zeta_ui_set_driver_status(int loaded) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_window) {
        QMetaObject::invokeMethod(g_window, "onSetDriverStatus", Qt::QueuedConnection,
            Q_ARG(bool, loaded != 0));
    }
}

ZETA_API void zeta_ui_set_lineage_tracker(int enabled) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_window) {
        QMetaObject::invokeMethod(g_window, "onSetLineageTracker", Qt::QueuedConnection,
            Q_ARG(bool, enabled != 0));
    }
}

ZETA_API void zeta_ui_set_ransom_exp(int enabled) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_window) {
        QMetaObject::invokeMethod(g_window, "onSetRansomExp", Qt::QueuedConnection,
            Q_ARG(bool, enabled != 0));
    }
}

ZETA_API void zeta_ui_set_status_text(const wchar_t* text) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_window) {
        QString t = QString::fromWCharArray(text);
        QMetaObject::invokeMethod(g_window, "onSetStatusText", Qt::QueuedConnection,
            Q_ARG(QString, t));
    }
}


ZETA_API void zeta_ui_set_repair_item(int index, const wchar_t* status, const wchar_t* result) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_window) {
        QString s = QString::fromWCharArray(status);
        QString r = QString::fromWCharArray(result);
        QMetaObject::invokeMethod(g_window, "onSetRepairItem", Qt::QueuedConnection,
            Q_ARG(int, index), Q_ARG(QString, s), Q_ARG(QString, r));
    }
}

ZETA_API void zeta_ui_set_repair_buttons(int enabled) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_window) {
        QMetaObject::invokeMethod(g_window, "onSetRepairButtons", Qt::QueuedConnection,
            Q_ARG(bool, enabled != 0));
    }
}

// Global HIPS response callback (set by main.cpp)
static fn_hips_response_cb g_hipsResponseCb = nullptr;

ZETA_API void zeta_ui_set_hips_response_callback(fn_hips_response_cb cb) {
    g_hipsResponseCb = cb;
}

ZETA_API fn_hips_response_cb zeta_ui_get_hips_response_callback(void) {
    return g_hipsResponseCb;
}

ZETA_API void zeta_ui_show_hips_prompt(const wchar_t* title, const wchar_t* message, unsigned long pid, int level) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_window) {
        QString t = QString::fromWCharArray(title);
        QString m = QString::fromWCharArray(message);
        QMetaObject::invokeMethod(g_window, "onShowHipsPrompt", Qt::QueuedConnection,
            Q_ARG(QString, t), Q_ARG(QString, m), Q_ARG(unsigned long, pid), Q_ARG(int, level));
    }
}

ZETA_API void zeta_ui_show_notification(const wchar_t* title, const wchar_t* message, int level) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_window) {
        QString t = QString::fromWCharArray(title);
        QString m = QString::fromWCharArray(message);
        QMetaObject::invokeMethod(g_window, "onShowNotification", Qt::QueuedConnection,
            Q_ARG(QString, t), Q_ARG(QString, m), Q_ARG(int, level));
    }
}

ZETA_API void zeta_ui_restore_switch(const wchar_t* key, int checked) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_window) {
        QString k = QString::fromWCharArray(key);
        QMetaObject::invokeMethod(g_window, "onRestoreSwitch", Qt::QueuedConnection,
            Q_ARG(QString, k), Q_ARG(bool, checked != 0));
    }
}

ZETA_API void zeta_ui_restore_combo(const wchar_t* name, const wchar_t* value) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_window) {
        QString n = QString::fromWCharArray(name);
        QString v = QString::fromWCharArray(value);
        QMetaObject::invokeMethod(g_window, "onRestoreCombo", Qt::QueuedConnection,
            Q_ARG(QString, n), Q_ARG(QString, v));
    }
}

ZETA_API void zeta_ui_exec(void) {
    if (g_app) {
        g_app->exec();
    }
}

ZETA_API void zeta_ui_shutdown(void) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_app) {
        g_app->quit();
        g_app = nullptr;
    }
    if (g_window) {
        delete g_window;
        g_window = nullptr;
    }
}

ZETA_API void zeta_ui_process_events(void) {
    if (g_app) {
        g_app->processEvents();
    }
}

// ── Callback registration ────────────────────────────────────────

ZETA_API void zeta_ui_set_config_callback(zeta_config_cb cb) {
    Bridge::instance()->setConfigCallback(reinterpret_cast<void*>(cb));
}

ZETA_API void zeta_ui_set_tool_callback(zeta_tool_cb cb) {
    Bridge::instance()->setToolCallback(reinterpret_cast<void*>(cb));
}
