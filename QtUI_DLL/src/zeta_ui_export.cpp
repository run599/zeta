#include "zeta_ui_export.h"
#include "MainWindow.h"
#include "Bridge.h"

#include <QApplication>
#include <QThread>
#include <QTimer>
#include <QDebug>
#include <mutex>
#include <condition_variable>

// ── 控件树自检探针 (临时诊断, 2026-10-01) ─────────────────────────
// 目的: 定位"看得见点击、但画不出来"的控件(用户实测症状)。
// 只新增 static 函数, 不改任何导出签名 ⇒ ZETA.exe 无需重编。
#include <QWidget>
#include <QAbstractButton>
#include <QLabel>
#include <QFile>
#include <QTextStream>
#include <QDir>
#include <QPalette>
#include <QGraphicsEffect>
#include <QGraphicsOpacityEffect>
#include <QDateTime>
#include <QStringConverter>

static QApplication* g_app = nullptr;
static MainWindow* g_window = nullptr;
static std::mutex g_mutex;
static void dumpWidgetTreeToFile(void);   // 控件树探针(定义在文件末尾)

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
        // 探针: 延迟 2.5s dump 控件树 —— 等页面构建与 applyTheme 都跑完再采
        QTimer::singleShot(2500, g_window, []() { dumpWidgetTreeToFile(); });
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

ZETA_API void zeta_ui_set_disk_status(int attached, int blocked, int observed,
                                      int mode, int enabled, const wchar_t* lastInfo) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_window) {
        QString info = lastInfo ? QString::fromWCharArray(lastInfo) : QString();
        QMetaObject::invokeMethod(g_window, "onDiskStatus", Qt::QueuedConnection,
            Q_ARG(int, attached), Q_ARG(int, blocked), Q_ARG(int, observed),
            Q_ARG(int, mode), Q_ARG(int, enabled), Q_ARG(QString, info));
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

ZETA_API void zeta_ui_set_rules_path(const wchar_t* path) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_window) {
        QString p = QString::fromWCharArray(path);
        QMetaObject::invokeMethod(g_window, "onSetRulesPath", Qt::QueuedConnection,
            Q_ARG(QString, p));
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

// ── 控件树探针实现 ───────────────────────────────────────────────
static QString colStr(const QColor& c) {
    return QString("%1,%2,%3").arg(c.red()).arg(c.green()).arg(c.blue());
}

static void dumpWalk(QTextStream& ts, QWidget* w, QWidget* top, int depth, QStringList& susp) {
    if (!w) return;
    const QRect g = w->geometry();
    const QString cls = QString::fromLatin1(w->metaObject()->className());
    const bool vis = w->isVisible();
    const bool visTop = w->isVisibleTo(top);

    QString text;
    if (auto* b = qobject_cast<QAbstractButton*>(w))      text = b->text();
    else if (auto* l = qobject_cast<QLabel*>(w))          text = l->text();
    text.replace('\n', ' ').replace('\t', ' ');
    if (text.length() > 40) text = text.left(40) + "...";

    const QPalette pal = w->palette();
    const QColor fg = pal.color(QPalette::Active, QPalette::WindowText);
    const QColor bg = pal.color(QPalette::Active, QPalette::Window);
    const bool ssEmpty = w->styleSheet().isEmpty();

    QString eff = "-";
    if (QGraphicsEffect* e = w->graphicsEffect()) {
        eff = QString::fromLatin1(e->metaObject()->className());
        if (auto* oe = qobject_cast<QGraphicsOpacityEffect*>(e))
            eff += QString("(opacity=%1)").arg(oe->opacity(), 0, 'f', 2);
    }

    // R4: 与父控件矩形不相交
    bool r4 = false;
    if (QWidget* p = w->parentWidget()) {
        if (w != top && !p->rect().intersects(g)) r4 = true;
    }

    const int cdist = qAbs(fg.red()-bg.red()) + qAbs(fg.green()-bg.green()) + qAbs(fg.blue()-bg.blue());

    ts << depth << '\t' << cls << '\t' << (w->objectName().isEmpty() ? "-" : w->objectName())
       << '\t' << QString("%1,%2,%3x%4").arg(g.x()).arg(g.y()).arg(g.width()).arg(g.height())
       << '\t' << (vis ? "vis" : "HIDDEN") << '\t' << (visTop ? "visTop" : "notVisTop")
       << '\t' << '"' << text << '"' << '\t' << (ssEmpty ? "ss-empty" : "ss-set")
       << '\t' << colStr(fg) << '\t' << colStr(bg) << '\t' << cdist
       << '\t' << eff << '\t' << (r4 ? "R4" : "-") << '\n';

    if (vis && visTop) {
        if (text.isEmpty() && ssEmpty)                                   susp << QString("R1\t%1\t%2\t%3").arg(cls, w->objectName(), QString("%1,%2,%3x%4").arg(g.x()).arg(g.y()).arg(g.width()).arg(g.height()));
        if (cdist < 30)                                                  susp << QString("R2\t%1\t%2\t色差=%3").arg(cls, w->objectName()).arg(cdist);
        if (!cls.startsWith('Q') && qobject_cast<QAbstractButton*>(w))    susp << QString("R3\t%1\t%2\ttext=\"%3\" ss=%4").arg(cls, w->objectName(), text, ssEmpty ? "empty" : "set");
        if (r4)                                                          susp << QString("R4\t%1\t%2\t与父矩形不相交").arg(cls, w->objectName());
    }

    const QObjectList kids = w->children();
    for (QObject* o : kids) {
        if (QWidget* c = qobject_cast<QWidget*>(o)) dumpWalk(ts, c, top, depth + 1, susp);
    }
}

static void dumpWidgetTreeToFile(void) {
    const QString path = QDir::tempPath() + "/zeta_widget_tree.txt";
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) return;
    QTextStream ts(&f);
    ts.setEncoding(QStringConverter::Utf8);

    const QList<QWidget*> tops = QApplication::topLevelWidgets();
    QStringList susp;
    int total = 0;

    ts << "# ZETA 控件树探针  " << QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss") << '\n';
    ts << "# depth\tclass\tobjectName\tgeometry(x,y,w,h)\tvisible\tvisToTop\ttext\tstyleSheet\tfg\tbg\tcolorDist\tgraphicsEffect\tR4\n";
    for (QWidget* t : tops) {
        if (!t) continue;
        ts << "=== TOPLEVEL: " << QString::fromLatin1(t->metaObject()->className())
           << " \"" << t->windowTitle() << "\" "
           << QString("%1x%2").arg(t->width()).arg(t->height()) << '\n';
        dumpWalk(ts, t, t, 0, susp);
        total++;
    }

    ts << "\n===== 可疑清单 (共 " << susp.size() << " 条) =====\n";
    ts << "R1=可见+文本空+样式表空  R2=前后景色差<30  R3=自定义按钮类(non-Q)  R4=与父矩形不相交\n";
    for (const QString& s : susp) ts << s << '\n';
    ts << "\n===== 统计 =====\n";
    ts << "顶层窗口数: " << total << '\n';
    f.close();
    qDebug() << "[ZETA_PROBE] widget tree dumped to" << path << "suspicious=" << susp.size();
}

ZETA_API void zeta_ui_set_config_callback(zeta_config_cb cb) {
    Bridge::instance()->setConfigCallback(reinterpret_cast<void*>(cb));
}

ZETA_API void zeta_ui_set_tool_callback(zeta_tool_cb cb) {
    Bridge::instance()->setToolCallback(reinterpret_cast<void*>(cb));
}
