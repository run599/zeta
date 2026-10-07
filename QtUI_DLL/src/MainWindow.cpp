#include "MainWindow.h"
#include "Bridge.h"
#include "NotificationDialog.h"
#include "NavSidebar.h"
#include "zeta_ui_export.h"
// P2-4c: 事件码统一契约 (唯一定义源)
#include "../../Plugins/Filter/events.h"
#include <QMouseEvent>
#include <QHeaderView>
#include <QScrollBar>
#include <QFormLayout>
#include <QApplication>
#include <QScreen>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>
#include <QStringConverter>
#include <QFile>
#include <QTextCursor>
#include <QEvent>
#include <QTimer>
#include <QSystemTrayIcon>
#include <QGraphicsDropShadowEffect>
#include <QMenu>
#include <QAction>
#include <QDesktopServices>
#include <QUrl>
#include <QPainter>
#include <QPainterPath>
#include <QResizeEvent>
#include <QGridLayout>
#include <QFileInfo>
#include <QDir>
#include <QHash>
#include <QVector>
#include <algorithm>
#include <QRegularExpression>

// Windows headers (after Qt to avoid conflicts)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <dwmapi.h>
#pragma comment(lib, "dwmapi.lib")

// ============================================================================
// M2-4: 删除一律走回收站（用户铁律）
//
// 背景: 备份副本删除 / 垃圾清理此前走 DeleteFileW = 永久删除, 误删不可恢复。
//      本函数改用 SHFileOperationW(FO_DELETE | FOF_ALLOWUNDO) 送入回收站。
// 例外: 隔离区的"彻底删除"语义即永久销毁(用户显式操作), 不走本函数。
// 注意: SHFileOperationW 的 pFrom 必须是**双 NUL 结尾**的多字符串。
// ============================================================================
static bool zetaDeleteToRecycleBin(const QString& path) {
    if (path.isEmpty()) return false;
    const QString native = QDir::toNativeSeparators(path);
    std::wstring buf(reinterpret_cast<const wchar_t*>(native.utf16()),
                     static_cast<size_t>(native.size()));
    buf.push_back(L'\0');
    buf.push_back(L'\0');
    SHFILEOPSTRUCTW op = {};
    op.wFunc  = FO_DELETE;
    op.pFrom  = buf.c_str();
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    const int rc = SHFileOperationW(&op);
    return rc == 0 && !op.fAnyOperationsAborted;
}

// ============================================================================
// 元数据编码自适应层
//
// 备份索引 / 隔离区 .info / 拦截日志的写入方横跨内核与用户态, 编码并不唯一:
//   1) UTF-8          — 驱动 ZetaVault_AppendIndex (RtlUnicodeToUTF8N) 写 .ZETA_index;
//                        ZETA.exe 以 ccs=UTF-8 写 ZETA_Intercepts.log
//   2) UTF-16LE 无BOM — 旧版内核 Zw 写入 / ZETA.exe 旧版隔离区 .info
//   3) ANSI(GBK)      — 更早的版本, 中文按本地代码页落盘
// 判定顺序与 tools/zeta_meta (Go) 保持一致, 保证命令行工具与 UI 结果同源:
//   BOM → 含 NUL 且长度为偶数 → UTF-16LE; 否则按 UTF-8;
//   若解出替换字符(U+FFFD) 再按 ANSI 重解, 取坏字符更少的一个。
// ============================================================================
static int zetaBadCharCount(const QString& s) {
    int n = 0;
    for (const QChar& c : s) {
        if (c == QChar(0xFFFD)) n++;
    }
    return n;
}

// UTF-16LE 字节流 → QString (去掉尾部 NUL 填充; 奇数字节丢弃末字节)
static QString zetaDecodeUtf16Le(const QByteArray& raw) {
    QString s = QString::fromUtf16(
        reinterpret_cast<const char16_t*>(raw.constData()), raw.size() / 2);
    while (s.endsWith(QChar(0))) s.chop(1);
    return s;
}

static QString zetaDecodeMetaBytes(const QByteArray& raw) {
    if (raw.isEmpty()) return QString();

    // UTF-8 BOM
    if (raw.size() >= 3 && (unsigned char)raw[0] == 0xEF &&
        (unsigned char)raw[1] == 0xBB && (unsigned char)raw[2] == 0xBF) {
        return QString::fromUtf8(raw.mid(3));
    }
    // UTF-16LE BOM
    if (raw.size() >= 2 && (unsigned char)raw[0] == 0xFF && (unsigned char)raw[1] == 0xFE) {
        return zetaDecodeUtf16Le(raw.mid(2));
    }

    // 无 BOM: NUL 字节是 UTF-16 的硬信号 (ASCII 的 UTF-16 字节流里 0x00 也是合法 UTF-8,
    // 单靠 utf8 合法性会把 UTF-16 误判成 UTF-8 → 必须以 NUL 存在性优先)
    if (raw.contains('\0') && raw.size() % 2 == 0) {
        const QString u16 = zetaDecodeUtf16Le(raw);
        if (!u16.isEmpty() && zetaBadCharCount(u16) == 0) return u16;
    }

    const QString utf8 = QString::fromUtf8(raw);
    if (zetaBadCharCount(utf8) == 0) return utf8;

    // UTF-8 解出替换字符 → 大概率是 ANSI/GBK 旧元数据, 取坏字符更少的一个
    const QString ansi = QString::fromLocal8Bit(raw);
    return zetaBadCharCount(ansi) < zetaBadCharCount(utf8) ? ansi : utf8;
}

// 读元数据文件 → 已解码文本 (不存在/为空返回空串)
static QString zetaReadMetaText(const QString& path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return QString();
    const QByteArray raw = f.readAll();
    f.close();
    return zetaDecodeMetaBytes(raw);
}

// ============================================================================
// macOS 风格毛玻璃窗口 (Win10 22H2 Acrylic)
// 通过 SetWindowCompositionAttribute 给无边框主窗口加亚克力毛玻璃背景
// ============================================================================
#ifndef ACCENT_ENABLE_ACRYLICBLURBEHIND
#define ACCENT_ENABLE_ACRYLICBLURBEHIND 4
#endif
enum _WINDOWCOMPOSITIONATTRIB {
    WCA_ACCENT_POLICY = 19
};
struct _ACCENT_POLICY {
    int nAccentState;
    int nFlags;
    int nColor;
    int nAnimationId;
};
struct _WINDOWCOMPOSITIONATTRIBDATA {
    int nAttribute;
    PVOID pData;
    ULONG ulDataSize;
};
typedef BOOL(WINAPI* pfnSetWindowCompositionAttribute)(HWND, _WINDOWCOMPOSITIONATTRIBDATA*);

static void enableAcrylicBlur(HWND hwnd) {
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (!hUser32) return;
    auto fn = (pfnSetWindowCompositionAttribute)
        GetProcAddress(hUser32, "SetWindowCompositionAttribute");
    if (!fn) return;
    // Acrylic 毛玻璃: 优先尝试带渐变(0xAARRGGBB 半透明底), 失败回退纯半透明
    _ACCENT_POLICY accent;
    accent.nAccentState = ACCENT_ENABLE_ACRYLICBLURBEHIND;
    accent.nFlags = 2;  // 使用 nColor (ABGR)
    accent.nColor = 0xE60F0F1A;  // 深蓝紫半透明底 (alpha 0xE6 让背景透出)
    accent.nAnimationId = 0;
    _WINDOWCOMPOSITIONATTRIBDATA data;
    data.nAttribute = WCA_ACCENT_POLICY;
    data.pData = &accent;
    data.ulDataSize = sizeof(accent);
    fn(hwnd, &data);
}

// ── Theme definitions ───────────────────────────────────────────

void MainWindow::initThemes() {
    // 统一浅色主题 — Design Token 集中管理, 所有控件引用 token 不再硬编码
    m_themes["apple_light"] = {
        "#f5f5f7",   // bgWindow  - 窗口底 (macOS 系统灰)
        "#f5f5f7",   // bgNav     - 侧栏底 (macOS 系统灰, 半透明透毛玻璃)
        "#ffffff",   // bgPanel   - 内容面板 (纯白)
        "#e9e9eb",   // bgHover   - 悬停灰 (macOS hover)
        "#e8f0fe",   // bgActive  - 选中/激活浅蓝底 (macOS 选中蓝)
        "#1d1d1f",   // textPrimary  - 主文字 (macOS 主文字)
        "#6e6e73",   // textSecondary - 次要文字 (macOS 次要文字)
        "#aeaeb2",   // textDisabled  - 禁用灰
        "#e5e5ea",   // border    - 分割线 (macOS 细分割线)
        "#d1d1d6",   // borderStrong - 强描边
        "#007aff",   // accent    - macOS 系统蓝
        "#0a84ff",   // accentHover - macOS 亮蓝
        "#ffffff",   // onAccent  - 蓝底上的文字 (白)
        "#34c759",   // success   - macOS 绿
        "#ff9f0a",   // warning   - macOS 黄
        "#ff453a",   // danger    - macOS 红
        "#ffffff",   // onDanger  - 红底文字 (白)
        "rgba(0,0,0,0.08)"  // shadowColor - 柔阴影 (macOS 轻阴影)
    };
}

QString MainWindow::buildStylesheet(const Theme& t) {
    // 统一浅色主题 — Design Token 驱动.
    // 注意: 用命名 token + replace() 而非 QString::arg("%N"),
    //       避免 Qt arg 对 %10~%18 两位数占位符的歧义替换导致 "Argument missing".
    QString css = QStringLiteral(R"(
            QMainWindow, QWidget#centralWidget { background-color: @WINDOW@; border-radius: 12px; border: 1px solid rgba(0,0,0,0.06); }
            QWidget#navPanel { background-color: @NAV@; border-right: 1px solid @BORDER@; }
            QWidget#contentPanel { background-color: @PANEL@; border: 1px solid @BORDER@; border-radius: 14px; }
            QWidget#titleBar { background-color: @NAV@; border-bottom: 1px solid @BORDER@; }
            QWidget#toolbarRow { background-color: @NAV@; border-bottom: 1px solid @BORDER@; }

            QLabel { color: @TEXT@; font-size: 15px; }
            QLabel#titleLabel { color: @TEXT@; font-size: 16px; font-weight: bold; }
            QLabel#secLabel { color: @TEXT2@; font-size: 13px; }
            QLabel#statusTitle { color: @TEXT@; font-size: 28px; font-weight: 600; letter-spacing: -0.5px; }

            QPushButton#navBtn {
                background-color: transparent; color: @TEXT2@; border: none;
                padding: 14px 18px; text-align: left; font-size: 15px;
                border-radius: 12px; margin: 2px 8px;
            }
            QPushButton#navBtn:hover { background-color: @HOVER@; color: @TEXT@; }
            QPushButton#navBtn:checked { background-color: @ACTIVE@; color: @ACCENT@; font-weight: 600; }

            /* 标题栏按钮为 QPainter 自绘 (TitleBarButton), 不套用 QSS, 避免干扰绘制 */

            QPushButton#actionBtn {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @ACCENT@, stop:1 @ACCENTH@);
                color: @ONACCENT@; border: none;
                padding: 11px 30px; border-radius: 22px; font-size: 15px; font-weight: 600;
            }
            QPushButton#actionBtn:hover {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @ACCENTH@, stop:1 @ACCENTH@);
            }
            QPushButton#actionBtn:pressed { padding-top: 12px; padding-bottom: 10px; }
            QPushButton#actionBtn:disabled { background-color: @HOVER@; color: @DISABLED@; }

            QPushButton#actionBtn[danger="true"] {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #f5655a, stop:1 @DANGER@);
                color: @ONDANGER@; border-radius: 22px;
            }
            QPushButton#actionBtn[danger="true"]:hover {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @DANGER@, stop:1 @DANGER@);
            }

            QPushButton#ghostBtn {
                background-color: @PANEL@; color: @TEXT@; border: 1px solid @BORDER2@;
                padding: 9px 18px; border-radius: 10px; font-size: 14px; font-weight: 600;
            }
            QPushButton#ghostBtn:hover { background-color: @HOVER@; border-color: @ACCENT@; color: @ACCENT@; }
            QPushButton#ghostBtn:pressed { background-color: @ACTIVE@; }

            QTextEdit { background-color: @PANEL@; color: @TEXT@; border: 1px solid @BORDER@; border-radius: 12px; padding: 12px; font-size: 13px; }
            QTableWidget { background-color: @PANEL@; color: @TEXT@; border: 1px solid @BORDER@; border-radius: 12px; gridline-color: @BORDER@; }
            QTableWidget::item { padding: 12px; }
            QTableWidget::item:selected { background-color: @ACTIVE@; color: @ACCENT@; }
            QHeaderView::section { background-color: @HOVER@; color: @TEXT@; border: none; border-bottom: 1px solid @BORDER@; padding: 14px; font-weight: 600; }
            QTreeWidget::item:selected, QListWidget::item:selected { background-color: @ACTIVE@; color: @ACCENT@; }

            QCheckBox { color: @TEXT@; font-size: 16px; spacing: 12px; }
            QCheckBox::indicator { width: 22px; height: 22px; border-radius: 6px; border: 2px solid @BORDER2@; }
            QCheckBox::indicator:checked { background-color: @ACCENT@; border-color: @ACCENT@; }
            QCheckBox::indicator:unchecked:hover { border-color: @ACCENT@; }

            QComboBox { background-color: @PANEL@; color: @TEXT@; border: 1px solid @BORDER@; border-radius: 10px; padding: 10px 16px; font-size: 15px; }
            QComboBox:hover { border-color: @BORDER2@; }
            QComboBox QAbstractItemView { background-color: @PANEL@; color: @TEXT@; border: 1px solid @BORDER@; border-radius: 8px; selection-background-color: @ACTIVE@; selection-color: @ACCENT@; }

            QProgressBar { background-color: @HOVER@; border: none; border-radius: 6px; height: 12px; text-align: center; }
            QProgressBar::chunk { background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 @ACCENT@, stop:1 @ACCENTH@); border-radius: 6px; }

            /* title 绘制在 margin 区, 内容从 padding-top 之后开始 — 避免标题压住内部控件 */
            QGroupBox { color: @TEXT@; font-size: 16px; font-weight: 600; border: 1px solid @BORDER@; border-radius: 12px; margin-top: 20px; padding-top: 12px; }
            QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; left: 16px; top: 2px; padding: 0 4px; }
            QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 4px 16px; background-color: @NAV@; }
            QGroupBox#configGroup { background-color: @PANEL@; border: 1px solid @BORDER@; border-radius: 14px; }

            QScrollArea { background-color: transparent; border: none; }
            QScrollArea QWidget { background-color: transparent; }
            QScrollBar:vertical { background-color: @HOVER@; width: 8px; border-radius: 4px; }
            QScrollBar::handle:vertical { background-color: @DISABLED@; border-radius: 4px; min-height: 40px; }
            QScrollBar::handle:vertical:hover { background-color: @TEXT2@; }

            QFrame#listItem { background-color: transparent; border: 1px solid transparent; min-height: 68px; border-radius: 12px; margin: 4px 0; }
            QFrame#listItem:hover { background-color: @HOVER@; border-color: @BORDER@; }
            /* 网格卡片 (工具/防护页双列布局) */
            QFrame#gridCard { background-color: @WINDOW@; border: 1px solid @BORDER@; border-radius: 12px; min-height: 76px; }
            QFrame#gridCard:hover { background-color: @HOVER@; border-color: @ACCENT@; }
            QLabel#groupTitle { color: @TEXT2@; font-size: 13px; font-weight: 600; }

            QFrame#dashCard { background-color: @PANEL@; border: 1px solid @BORDER@; border-radius: 16px; padding: 24px; }
            QFrame#dashCard:hover { border-color: @ACCENT@; }
            QLabel#cardTitle { color: @TEXT2@; font-size: 12px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; }
            QLabel#cardValue { color: @TEXT@; font-size: 15px; }
            QLabel#cardAccent { color: @ACCENT@; font-size: 15px; }
            QLabel#cardDanger { color: @DANGER@; font-size: 15px; }
            QLabel#cardEvent { color: @TEXT2@; font-size: 12px; padding: 4px 0px; border: none; }

            QLineEdit { background-color: @PANEL@; color: @TEXT@; border: 1px solid @BORDER@; border-radius: 10px; padding: 12px 16px; font-size: 15px; }
            QLineEdit:hover { border-color: @BORDER2@; }
            QLineEdit:focus { border-color: @ACCENT@; border: 1.5px solid @ACCENT@; }
            QLineEdit:disabled { color: @DISABLED@; background-color: @HOVER@; }

            QSpinBox { background-color: @PANEL@; color: @TEXT@; border: 1px solid @BORDER@; border-radius: 10px; padding: 8px 12px; font-size: 16px; }
            QSpinBox:hover { border-color: @BORDER2@; }
            QSpinBox:focus { border-color: @ACCENT@; border: 1.5px solid @ACCENT@; }

            QTabWidget::pane { border: none; background-color: @PANEL@; }
            QTabWidget::tab-bar { left: 0px; }
            QTabBar::tab { background-color: transparent; color: @TEXT2@; padding: 8px 24px; margin-right: 4px; border-radius: 10px 10px 0 0; font-size: 15px; min-width: 100px; }
            QTabBar::tab:hover { background-color: @HOVER@; color: @TEXT@; }
            QTabBar::tab:selected { background-color: @PANEL@; color: @TEXT@; font-weight: 600; border-bottom: 2px solid @ACCENT@; }
        )");

    return css
        .replace(QStringLiteral("@WINDOW@"), t.bgWindow)
        .replace(QStringLiteral("@NAV@"), t.bgNav)
        .replace(QStringLiteral("@PANEL@"), t.bgPanel)
        .replace(QStringLiteral("@HOVER@"), t.bgHover)
        .replace(QStringLiteral("@ACTIVE@"), t.bgActive)
        .replace(QStringLiteral("@TEXT@"), t.textPrimary)
        .replace(QStringLiteral("@TEXT2@"), t.textSecondary)
        .replace(QStringLiteral("@DISABLED@"), t.textDisabled)
        .replace(QStringLiteral("@BORDER@"), t.border)
        .replace(QStringLiteral("@BORDER2@"), t.borderStrong)
        .replace(QStringLiteral("@ACCENT@"), t.accent)
        .replace(QStringLiteral("@ACCENTH@"), t.accentHover)
        .replace(QStringLiteral("@ONACCENT@"), t.onAccent)
        .replace(QStringLiteral("@DANGER@"), t.danger)
        .replace(QStringLiteral("@ONDANGER@"), t.onDanger);
}

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    initThemes();
    setWindowTitle("ZETA Security");
    setWindowFlags(Qt::FramelessWindowHint);
    
    setMinimumSize(900, 650);
    setAttribute(Qt::WA_TranslucentBackground);   // 让 Acrylic 毛玻璃 / 半透明 fallback 生效
    
    int targetW = 1100;
    int targetH = 750;
    
    if (auto screen = QApplication::primaryScreen()) {
        auto geo = screen->availableGeometry();
        targetW = qMin(targetW, (int)(geo.width() * 0.85));
        targetH = qMin(targetH, (int)(geo.height() * 0.85));
        resize(targetW, targetH);
        move((geo.width() - width()) / 2, (geo.height() - height()) / 2);
    } else {
        resize(targetW, targetH);
    }

    auto* central = new QWidget();
    central->setObjectName("centralWidget");
    setCentralWidget(central);

    // 注: 不在此挂 QGraphicsDropShadowEffect —— 它会干扰 QSS border-radius 圆角绘制
    auto* mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    setupTitleBar(mainLayout);

    auto* bodyLayout = new QHBoxLayout();
    bodyLayout->setContentsMargins(0, 0, 0, 0);
    bodyLayout->setSpacing(0);
    setupSidebar(bodyLayout);

    m_stack = new QStackedWidget();
    m_stack->setObjectName("contentPanel");
    bodyLayout->addWidget(m_stack, 1);
    mainLayout->addLayout(bodyLayout, 1);

    setupPages();
    applyTheme("apple_light");
    setupTrayIcon();

    // macOS 风格: 启用 Acrylic 毛玻璃背景 (Win10 22H2)
    show();
    QTimer::singleShot(0, this, [this]() {
        enableAcrylicBlur((HWND)winId());
    });
}

MainWindow::~MainWindow() {
    // Remove tray icon immediately so it doesn't persist after app exits
    if (m_trayIcon) {
        m_trayIcon->hide();
        delete m_trayIcon;
        m_trayIcon = nullptr;
    }
    if (m_trayMenu) {
        delete m_trayMenu;
        m_trayMenu = nullptr;
    }
}

// ── Title Bar ───────────────────────────────────────────────────

// ── 标题栏矢量按钮 (QPainter 自绘, 不依赖字体字形) ───────────────
// Windows 11 线条风格: × / − / i, 1.6px 圆头笔画, 默认无底色
class TitleBarButton : public QPushButton {
public:
    enum Type { Close, Minimize, About };

    TitleBarButton(Type type, QWidget* parent = nullptr)
        : QPushButton(parent), m_type(type) {
        setFixedSize(30, 30);
        setCursor(Qt::PointingHandCursor);
        setAttribute(Qt::WA_Hover, true);
        setFocusPolicy(Qt::NoFocus);
        setFlat(true);
    }

    // 由 applyTheme 注入配色, 跟随主题自动适配亮/暗
    void setThemeColors(const QColor& normal, const QColor& active,
                        const QColor& hoverBg, const QColor& closeBg,
                        const QColor& closeFg) {
        m_normal = normal; m_active = active; m_hoverBg = hoverBg;
        m_closeBg = closeBg; m_closeFg = closeFg;
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);

        const bool hover = underMouse() || isDown();
        const bool isClose = (m_type == Close);
        QRectF r = rect();

        if (hover) {
            p.setPen(Qt::NoPen);
            p.setBrush(isClose ? QBrush(m_closeBg) : QBrush(m_hoverBg));
            p.drawRoundedRect(r.adjusted(1, 1, -1, -1), 6, 6);
        }

        const qreal cx = r.center().x();
        const qreal cy = r.center().y();
        const qreal h = 5.0;                       // 图标半边长 (10x10)

        QPen pen(hover && isClose ? m_closeFg : (hover ? m_active : m_normal));
        pen.setWidthF(1.6);
        pen.setCapStyle(Qt::RoundCap);
        pen.setJoinStyle(Qt::RoundJoin);
        p.setPen(pen);
        p.setBrush(Qt::NoBrush);

        switch (m_type) {
        case Close:
            p.drawLine(QLineF(cx - h, cy - h, cx + h, cy + h));
            p.drawLine(QLineF(cx + h, cy - h, cx - h, cy + h));
            break;
        case Minimize:
            p.drawLine(QLineF(cx - h, cy, cx + h, cy));
            break;
        case About:  // 信息图标 "i": 上点 + 下竖线
            p.drawLine(QLineF(cx, cy - 1.2, cx, cy + h));
            p.setBrush(pen.color());
            p.setPen(Qt::NoPen);
            p.drawEllipse(QPointF(cx, cy - 3.6), 1.0, 1.0);
            break;
        }
    }

private:
    Type m_type;
    QColor m_normal = QColor("#8a8a8e");
    QColor m_active = QColor("#1d1d1f");
    QColor m_hoverBg = QColor(0, 0, 0, 20);
    QColor m_closeBg = QColor("#e81123");
    QColor m_closeFg = QColor("#ffffff");
};

void MainWindow::setupTitleBar(QVBoxLayout* parent) {
    m_titleBar = new QWidget();
    m_titleBar->setObjectName("titleBar");
    m_titleBar->setFixedHeight(44);
    auto* layout = new QHBoxLayout(m_titleBar);
    layout->setContentsMargins(14, 0, 10, 0);

    m_titleLabel = new QLabel("ZETA Security");
    m_titleLabel->setObjectName("titleLabel");
    layout->addWidget(m_titleLabel);
    layout->addStretch();

    // 矢量自绘按钮: 关于(i) / 最小化(−) / 关闭(×) — 从左到右, 关闭在最右
    m_ctrlAbout = new TitleBarButton(TitleBarButton::About, m_titleBar);
    m_ctrlAbout->setToolTip("关于");
    connect(m_ctrlAbout, &QPushButton::clicked, this, [this]() {
        QMessageBox::about(this, "关于 ZETA Security",
            "ZETA Security v2.0.0\n\n实时系统安全防护\n(C) 2020-2026 runqp\n保留所有权利");
    });
    layout->addWidget(m_ctrlAbout);

    m_ctrlMin = new TitleBarButton(TitleBarButton::Minimize, m_titleBar);
    m_ctrlMin->setToolTip("最小化");
    connect(m_ctrlMin, &QPushButton::clicked, this, &QWidget::showMinimized);
    layout->addWidget(m_ctrlMin);

    m_ctrlClose = new TitleBarButton(TitleBarButton::Close, m_titleBar);
    m_ctrlClose->setToolTip("退出");
    connect(m_ctrlClose, &QPushButton::clicked, this, [this]() { close(); });
    layout->addWidget(m_ctrlClose);

    parent->addWidget(m_titleBar);
}

// ── Sidebar ─────────────────────────────────────────────────────

void MainWindow::setupSidebar(QHBoxLayout* parent) {
    m_navSidebar = new NavSidebar();
    m_navSidebar->setObjectName("navPanel");
    connect(m_navSidebar, &NavSidebar::currentIndexChanged, this, &MainWindow::switchPage);
    parent->addWidget(m_navSidebar);
}

// ── 通用卡片构造 ─────────────────────────────────────────────────

// 导航入口卡片: 标题 + 描述 + 右箭头, 点击跳转子页 (由 eventFilter 依据属性分发)
QFrame* MainWindow::createNavCard(const QString& title, const QString& desc,
                                  const QString& propName, int index) {
    auto* card = new QFrame();
    card->setObjectName("gridCard");
    card->setFrameShape(QFrame::NoFrame);
    card->setCursor(Qt::PointingHandCursor);
    auto* cl = new QHBoxLayout(card);
    cl->setContentsMargins(18, 14, 16, 14);
    cl->setSpacing(12);

    auto* tl = new QVBoxLayout();
    tl->setSpacing(4);
    auto* t = new QLabel(title);
    t->setObjectName("titleLabel");
    t->setAttribute(Qt::WA_TransparentForMouseEvents);
    auto* d = new QLabel(desc);
    d->setObjectName("secLabel");
    d->setWordWrap(true);
    d->setAttribute(Qt::WA_TransparentForMouseEvents);
    tl->addWidget(t);
    tl->addWidget(d);
    cl->addLayout(tl, 1);

    auto* arrow = new QLabel(QString::fromUtf8("\u203A"));
    arrow->setObjectName("cardAccent");
    arrow->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    arrow->setAttribute(Qt::WA_TransparentForMouseEvents);
    arrow->setStyleSheet("font-size: 20px;");
    cl->addWidget(arrow);

    QByteArray prop = propName.toUtf8();
    card->setProperty(prop.constData(), index);
    card->installEventFilter(this);
    return card;
}

// 防护开关卡片: 注册进 m_protectSwitches 并绑定后端 onConfigCallback
// P2-1: 初始不勾选, 由 onRestoreSwitch 从后端配置回填真实状态 (避免"显示开着"的假防护)
QFrame* MainWindow::createSwitchCard(const QString& title, const QString& desc, const QString& key) {
    auto* card = new QFrame();
    card->setObjectName("gridCard");
    card->setFrameShape(QFrame::NoFrame);
    auto* cl = new QHBoxLayout(card);
    cl->setContentsMargins(18, 14, 18, 14);
    cl->setSpacing(12);

    auto* tl = new QVBoxLayout();
    tl->setSpacing(4);
    auto* t = new QLabel(title);
    t->setObjectName("titleLabel");
    auto* d = new QLabel(desc);
    d->setObjectName("secLabel");
    d->setWordWrap(true);
    tl->addWidget(t);
    tl->addWidget(d);
    cl->addLayout(tl, 1);

    auto* cb = new QCheckBox();
    cb->blockSignals(true);
    cb->setChecked(false);
    cb->blockSignals(false);
    cl->addWidget(cb);
    m_protectSwitches[key] = cb;

    connect(cb, &QCheckBox::toggled, this, [key](bool checked) {
        Bridge::instance()->invokeConfigCallback(key, checked ? 1 : 0);
    });
    return card;
}

// ── Pages ───────────────────────────────────────────────────────

void MainWindow::setupPages() {
    // Home page — Dashboard
    {
        m_homePage = new QWidget();
        m_homePage->setObjectName("contentPanel");
        auto* l = new QVBoxLayout(m_homePage);
        l->setContentsMargins(28, 24, 28, 24);
        l->setSpacing(20);

        auto makeCard = [&](const QString& title, bool hasShadow = true) -> QPair<QFrame*, QVBoxLayout*> {
            auto* card = new QFrame();
            card->setObjectName("dashCard");
            auto* cl = new QVBoxLayout(card);
            cl->setContentsMargins(20, 18, 20, 18);
            cl->setSpacing(10);
            if (!title.isEmpty()) {
                auto* titleL = new QLabel(title);
                titleL->setObjectName("cardTitle");
                cl->addWidget(titleL);
            }
            if (hasShadow) {
                auto* shadow = new QGraphicsDropShadowEffect();
                shadow->setBlurRadius(12);   // macOS 轻阴影
                shadow->setOffset(0, 2);
                shadow->setColor(QColor(0, 0, 0, 55));
                card->setGraphicsEffect(shadow);
            }
            return {card, cl};
        };

        // ── Card 1: 防护状态 + 统计概览 (single card) ──
        auto [mainCard, mc] = makeCard("");
        {
            auto* topRow = new QHBoxLayout();
            topRow->setSpacing(32);

            auto* statusCol = new QVBoxLayout();
            statusCol->setSpacing(6);
            m_statusIcon = new QLabel();
            m_statusIcon->setFixedSize(44, 44);
            m_statusIcon->setStyleSheet("background-color: #34c759; border-radius: 12px;");
            statusCol->addWidget(m_statusIcon, 0, Qt::AlignTop);
            m_statusText = new QLabel("已防护");
            m_statusText->setObjectName("cardAccent");
            m_statusText->setStyleSheet("QLabel#cardAccent { font-size: 18px; font-weight: 700; }");
            statusCol->addWidget(m_statusText);
            m_statusSub = new QLabel("实时防护中");
            m_statusSub->setObjectName("cardValue");
            m_statusSub->setStyleSheet("QLabel#cardValue { font-size: 13px; }");
            statusCol->addWidget(m_statusSub);
            topRow->addLayout(statusCol);

            auto* statsCol = new QVBoxLayout();
            statsCol->setSpacing(0);
            auto makeStat = [&](const QString& label, QLabel*& val, const QString& obj) -> QHBoxLayout* {
                auto* r = new QHBoxLayout();
                r->setContentsMargins(0, 0, 0, 0);
                r->setSpacing(8);
                auto* labelL = new QLabel(label);
                labelL->setObjectName("cardValue");
                labelL->setStyleSheet("QLabel#cardValue { font-size: 13px; }");
                r->addWidget(labelL);
                r->addStretch();
                val = new QLabel("0");
                val->setObjectName(obj);
                val->setStyleSheet("font-weight: 700; font-size: 16px;");
                r->addWidget(val);
                return r;
            };
            auto* statRow1 = new QHBoxLayout();
            statRow1->setSpacing(40);
            statRow1->addLayout(makeStat("HIPS 拦截", m_statHipsLabel, "cardAccent"));
            statRow1->addLayout(makeStat("EDR 告警", m_statEdrLabel, "cardAccent"));
            auto* statRow2 = new QHBoxLayout();
            statRow2->setSpacing(40);
            statRow2->addLayout(makeStat("威胁阻断", m_statKilledLabel, "cardDanger"));
            statsCol->addLayout(statRow1);
            statsCol->addSpacing(12);
            statsCol->addLayout(statRow2);
            topRow->addLayout(statsCol, 1);

            mc->addLayout(topRow);
        }

        // ── Row 2: 最近事件 + 日志 ──
        auto* bottomRow = new QHBoxLayout();
        bottomRow->setSpacing(20);

        // ── Card 3: 最近事件 ──
        auto [eventCard, ec] = makeCard("最 近 事 件");
        {
            auto makeEvent = [&](QLabel*& lbl) {
                lbl = new QLabel("—");
                lbl->setObjectName("cardEvent");
                lbl->setStyleSheet("QLabel#cardEvent { font-size: 12px; padding: 5px 0; }");
                ec->addWidget(lbl);
            };
            makeEvent(m_statEvent1);
            makeEvent(m_statEvent2);
            makeEvent(m_statEvent3);
            makeEvent(m_statEvent4);
            ec->addStretch();
        }
        bottomRow->addWidget(eventCard, 1);

        // ── Card 4: 防护日志 ──
        auto [logCard, ll] = makeCard("防 护 日 志");
        {
            m_logText = new QTextEdit();
            m_logText->setReadOnly(true);
            m_logText->setPlaceholderText("等待防护日志...");
            m_logText->setMaximumHeight(160);
            m_logText->setStyleSheet("QTextEdit { background: transparent; border: none; font-size: 12px; }");
            ll->addWidget(m_logText, 1);
        }
        bottomRow->addWidget(logCard, 2);

        // 启动即加载历史拦截记录 (持久化, 重启不丢)
        loadInterceptHistory();

        // ── Assemble page ──
        l->addWidget(mainCard);
        l->addLayout(bottomRow);
        m_stack->addWidget(m_homePage);
    }

    

    // Tools page
    m_toolsPage = new QWidget();
    m_toolsPage->setObjectName("contentPanel");
    setupToolsPage();
    m_stack->addWidget(m_toolsPage);

    // Protect page
    {
        m_protectPage = new QWidget();
        m_protectPage->setObjectName("contentPanel");
        auto* l = new QVBoxLayout(m_protectPage);
        l->setContentsMargins(28, 28, 28, 28);
        l->setSpacing(16);

        auto* hdr = new QLabel("防护开关");
        hdr->setObjectName("statusTitle");
        l->addWidget(hdr);
        l->addSpacing(16);

        // 真实防护开关 (与后端 onConfigCallback 的 switch key / 驱动命令 cmd 8-14 对齐)
        // 每个开关 toggled → 通过 Bridge 发到后端 onConfigCallback 应用驱动命令
        // 分两组双列网格: 内核防护 / 行为防护 — 纵向减半, 横向利用
        struct SwDef { const char* title; const char* desc; const char* key; };
        const SwDef kernelSw[] = {
            {"自我保护", "PPL 自保护 + Ob 句柄保护，防止本程序被终结", "process_switch"},
            {"进程挂起", "挂起待决操作，等待用户决策",                 "suspend_switch"},
            {"系统防护", "保护系统关键文件、注册表、引导记录",         "system_switch"},
            {"驱动防护", "拦截恶意驱动加载与驱动卸载",                 "driver_switch"},
            {"磁盘写防护", "拦截对物理磁盘 MBR/GPT 及分区表的底层写入", "disk_write_switch"},
            {"磁盘监控模式", "仅记录磁盘底层写事件，不拦截（排障用）",  "disk_monitor_switch"},
        };
        // 勒索重定向 / 学习模式 属高级策略, 已迁入设置页
        const SwDef behavSw[] = {
            {"文件防护", "拦截恶意 PE 释放、BYOVD 驱动写入、勒索加密", "document_switch"},
            {"网络防护", "拦截 C2 外联与恶意 IP 连接（IP 黑名单）",    "network_switch"},
            {"文档备份", "文档/图片被覆盖写前自动留存旧版副本（抗勒索）", "doc_backup_switch"},
        };

        auto addSwitchGroup = [&](const QString& groupTitle, const SwDef* defs, int count) {
            auto* gt = new QLabel(groupTitle);
            gt->setObjectName("groupTitle");
            l->addWidget(gt);

            auto* grid = new QGridLayout();
            grid->setContentsMargins(0, 6, 0, 0);
            grid->setSpacing(14);

            for (int i = 0; i < count; i++) {
                auto* card = createSwitchCard(defs[i].title, defs[i].desc,
                                              QString::fromUtf8(defs[i].key));
                // 奇数个时最后一张卡跨满两列, 不留半边空缺
                int span = (i == count - 1 && (count % 2)) ? 2 : 1;
                grid->addWidget(card, i / 2, i % 2, 1, span);
            }
            l->addLayout(grid);
            l->addSpacing(20);
        };

        addSwitchGroup("内 核 防 护", kernelSw, 6);
        addSwitchGroup("行 为 防 护", behavSw, 2);

        // 磁盘底层防护的真实运行状态 (由驱动 IOCTL_DISK_GET_STATS 回填)
        {
            auto* gt = new QLabel("磁 盘 底 层 防 护 状 态");
            gt->setObjectName("groupTitle");
            l->addWidget(gt);

            auto* card = new QFrame();
            card->setObjectName("gridCard");
            card->setFrameShape(QFrame::NoFrame);
            auto* cl = new QVBoxLayout(card);
            cl->setContentsMargins(18, 14, 18, 14);
            cl->setSpacing(6);

            m_diskStatusLabel = new QLabel("等待 ZETA_DiskFilter 上报…");
            m_diskStatusLabel->setObjectName("secLabel");
            m_diskStatusLabel->setWordWrap(true);
            cl->addWidget(m_diskStatusLabel);

            m_diskStatLabel = new QLabel(QString());
            m_diskStatLabel->setObjectName("secLabel");
            m_diskStatLabel->setWordWrap(true);
            cl->addWidget(m_diskStatLabel);

            l->addWidget(card);
            l->addSpacing(20);
        }

        l->addStretch();
        m_stack->addWidget(m_protectPage);
    }

    // EDR page — 一级页面: 独占整块内容区
    {
        m_edrPage = new QWidget();
        m_edrPage->setObjectName("contentPanel");
        auto* l = new QVBoxLayout(m_edrPage);
        l->setContentsMargins(28, 20, 28, 24);
        l->setSpacing(6);

        // 标题 + 操作按钮同一行, 不再在标题下方留一大块空白
        auto* hdrRow = new QHBoxLayout();
        m_edrPageTitle = new QLabel("EDR 规则");
        m_edrPageTitle->setObjectName("statusTitle");
        hdrRow->addWidget(m_edrPageTitle);
        hdrRow->addStretch();

        auto* refreshBtn = new QPushButton("刷新配置");
        refreshBtn->setObjectName("actionBtn");
        refreshBtn->setCursor(Qt::PointingHandCursor);
        connect(refreshBtn, &QPushButton::clicked, this, &MainWindow::onRefreshEdrRules);
        hdrRow->addWidget(refreshBtn);

        auto* saveBtn = new QPushButton("保存配置");
        saveBtn->setObjectName("actionBtn");
        saveBtn->setCursor(Qt::PointingHandCursor);
        connect(saveBtn, &QPushButton::clicked, this, &MainWindow::onSaveEdrRules);
        hdrRow->addWidget(saveBtn);

        l->addLayout(hdrRow);

        auto* body = new QWidget();
        body->setStyleSheet("background: transparent;");
        l->addWidget(body, 1);
        setupEdrManager(body);

        m_stack->addWidget(m_edrPage);
    }

    // Settings page (配置型功能迁入: 高级策略 + HIPS/白名单/网络黑名单)
    m_settingsPage = new QWidget();
    m_settingsPage->setObjectName("contentPanel");
    setupSettingsPage();
    m_stack->addWidget(m_settingsPage);

    // Default: home
    m_navSidebar->setCurrentIndex(0);
    m_stack->setCurrentIndex(0);
}

void MainWindow::switchPage(int index) {
    m_stack->setCurrentIndex(index);
    // 进入 EDR 一级页时加载规则配置
    if (index == PAGE_EDR) onRefreshEdrRules();
}

// ── Theme ────────────────────────────────────────────────────────

void MainWindow::applyTheme(const QString& themeKey) {
    if (!m_themes.contains(themeKey)) return;
    m_currentTheme = themeKey;
    setStyleSheet(buildStylesheet(m_themes[themeKey]));
    // 同步侧边栏配色 (亮色=白底橙胶囊, 暗色=靛蓝)
    if (m_navSidebar) {
        m_navSidebar->setLightMode(themeKey == "apple_light");
    }
    // 同步标题栏矢量按钮配色
    const Theme& t = m_themes[themeKey];
    QColor hoverBg(t.bgHover);
    if (hoverBg.alpha() == 255) hoverBg.setAlpha(30);
    for (TitleBarButton* b : { m_ctrlAbout, m_ctrlMin, m_ctrlClose }) {
        if (b) b->setThemeColors(QColor(t.textSecondary), QColor(t.textPrimary),
                                 hoverBg, QColor(t.danger), QColor(t.onDanger));
    }
}

// ── Slots ───────────────────────────────────────────────────────

void MainWindow::onAppendLog(const QString& level, const QString& action, const QString& detail) {
    QString line = QString("[%1] [%2] %3").arg(
        QDateTime::currentDateTime().toString("HH:mm:ss"), level, action);
    if (!detail.isEmpty()) line += " | " + detail;
    if (m_logText) {
        m_logText->append(line);
        m_logText->ensureCursorVisible();
    }
    // 真实拦截事件 (后端 appLog level=ALERT) → 同步到首页防护日志卡, 持久化显示
    if (level == "ALERT" && m_logText) {
        QString ts = QDateTime::currentDateTime().toString("MM-dd HH:mm:ss");
        appendInterceptHtml(ts, action, extractProcFromDetail(detail), action, detail);
    }
    // Sync to dashboard
    onUpdateDashboardStats(level, action, detail);
}

// 从详情串 "proc PID=123 [path] -> action score=86" 粗略提取进程名
QString MainWindow::extractProcFromDetail(const QString& detail) {
    int idx = detail.indexOf(" PID=");
    if (idx <= 0) return detail.section(' ', 0, 0);
    return detail.left(idx).trimmed();
}

void MainWindow::appendInterceptHtml(const QString& ts, const QString& src,
                                     const QString& proc, const QString& action,
                                     const QString& detail) {
    if (!m_logText) return;
    // 颜色: 终止/隔离=红, 拦截=橙, 失败=暗红, 其余=灰
    QString color = "#d9534f";
    if (action.contains("失败")) color = "#a94442";
    else if (action.contains("拦截")) color = "#e08e0b";
    else if (action.contains("跳过")) color = "#888888";

    QString srcTag = src.toHtmlEscaped();
    QString procEsc = proc.toHtmlEscaped();
    QString detEsc = detail.toHtmlEscaped();

    QString html = QString(
        "<div style='margin:2px 0;padding:3px 6px;border-left:3px solid %1;"
        "background:rgba(0,0,0,0.03);font-size:12px;'>"
        "<span style='color:#888;'>%2</span> "
        "<span style='color:%3;font-weight:bold;'>[%4]</span> "
        "<span style='color:#222;'>%5</span>"
        "<div style='color:#666;font-size:11px;margin-top:1px;'>%6</div>"
        "</div><br>").arg(color, ts, color, srcTag, procEsc, detEsc);
    QTextCursor cur = m_logText->textCursor();
    cur.movePosition(QTextCursor::End);
    cur.insertHtml(html);
    m_logText->setTextCursor(cur);
    m_logText->ensureCursorVisible();
}

// 启动时从 ZETA_Intercepts.log 加载历史拦截记录 (程序重启不丢)
void MainWindow::loadInterceptHistory() {
    if (!m_logText) return;
    const QString fpath = QCoreApplication::applicationDirPath() + "/ZETA_Intercepts.log";
    QFile f(fpath);
    if (!f.open(QIODevice::ReadOnly)) {
        m_logText->setPlaceholderText("暂无拦截记录");
        return;
    }
    const QByteArray all = f.readAll();
    f.close();

    // 编码自适应: 写入方用 ccs=UTF-8 (日志轮转时首行带 BOM), 早期版本可能写 ANSI/GBK。
    // 逐行走统一解码层 → 中文进程名/路径不再乱码; 整体为 UTF-16 时先整块解码。
    QStringList lines;
    if (all.contains('\0')) {
        lines = zetaDecodeMetaBytes(all).split(QRegularExpression("[\r\n]+"), Qt::SkipEmptyParts);
    } else {
        for (const QByteArray& rawLine : all.split('\n')) {
            QString line = zetaDecodeMetaBytes(rawLine);
            while (line.endsWith('\r') || line.endsWith(QChar(0xFEFF))) line.chop(1);
            lines.append(line);
        }
    }

    int start = (lines.size() > 200) ? (lines.size() - 200) : 0;
    for (int i = start; i < lines.size(); ++i) {
        QString raw = lines[i].trimmed();
        if (raw.isEmpty() || !raw.startsWith('{')) continue;
        QJsonDocument doc = QJsonDocument::fromJson(raw.toUtf8());
        if (!doc.isObject()) continue;
        QJsonObject o = doc.object();
        appendInterceptHtml(
            o.value("ts").toString(),
            o.value("src").toString(),
            o.value("proc").toString(),
            o.value("action").toString(),
            o.value("detail").toString());
    }
}

void MainWindow::onSetTheme(const QString& themeKey) { applyTheme(themeKey); }



void MainWindow::onSetDriverStatus(bool loaded) {
    m_driverLoaded = loaded;
    if (m_navSidebar) {
        m_navSidebar->setDriverStatus(loaded);
    }
    if (m_statusIcon) {
        m_statusIcon->setStyleSheet(loaded
            ? "background-color: #34c759; border-radius: 12px;"
            : "background-color: #ff453a; border-radius: 12px;");
    }
    if (m_statusText) {
        if (loaded) {
            m_statusText->setStyleSheet("QLabel#cardAccent { font-size: 18px; font-weight: 700; color: #34c759; }");
            m_statusText->setText("已防护");
        } else {
            m_statusText->setStyleSheet("QLabel#cardDanger { font-size: 18px; font-weight: 700; color: #ff453a; }");
            m_statusText->setText("未防护");
        }
    }
    // 同步设置页"运行状态"卡
    if (m_setDriverLabel) {
        m_setDriverLabel->setText(loaded ? "已加载" : "未加载");
        m_setDriverLabel->setStyleSheet(loaded
            ? "QLabel#cardValue { color: #34c759; font-weight: 700; }"
            : "QLabel#cardValue { color: #ff453a; font-weight: 700; }");
    }
    if (m_statusSub) {
        m_statusSub->setText(loaded ? "实时防护中" : "驱动未加载，部分功能受限");
    }
    if (m_logText) {
        QString msg = loaded
            ? "[系统] 驱动加载成功，防护功能已启用"
            : "[系统] 驱动加载失败，部分功能受限";
        m_logText->append(msg);
        m_logText->ensureCursorVisible();
    }
}

void MainWindow::onSetStatusText(const QString& text) {
    if (m_statusSub) m_statusSub->setText(text);
    if (m_logText) {
        m_logText->append("[系统] " + text);
        m_logText->ensureCursorVisible();
    }
}


void MainWindow::onRestoreSwitch(const QString& key, bool checked) {
    // P2-1: 回填防护开关的真实状态(由后端 zeta_ui_restore_switch 在启动时下发).
    // 屏蔽信号, 避免回填触发 toggled 再次向后端下发命令(死循环/重复).
    auto it = m_protectSwitches.find(key);
    if (it != m_protectSwitches.end() && it.value()) {
        it.value()->blockSignals(true);
        it.value()->setChecked(checked);
        it.value()->blockSignals(false);
    }
}

// 磁盘底层防护真实状态: 直接来自驱动 IOCTL_DISK_GET_STATS, 不是猜测值
void MainWindow::onDiskStatus(int attached, int blocked, int observed,
                              int mode, int enabled, const QString& info) {
    // 开关状态以驱动实际生效值为准 (驱动默认开启, 与"服务启动了"无关)
    const struct { const char* key; bool on; } sync[] = {
        { "disk_write_switch",    enabled != 0 },
        { "disk_monitor_switch",  mode == 1 },
    };
    for (const auto& s : sync) {
        auto it = m_protectSwitches.find(QString::fromUtf8(s.key));
        if (it != m_protectSwitches.end() && it.value()) {
            it.value()->blockSignals(true);
            it.value()->setChecked(s.on);
            it.value()->blockSignals(false);
        }
    }

    if (m_diskStatusLabel) {
        if (attached <= 0 && !info.isEmpty()) {
            m_diskStatusLabel->setText(QString("未生效：%1").arg(info));
            m_diskStatusLabel->setStyleSheet("color:#e05555;");
        } else if (!enabled) {
            m_diskStatusLabel->setText("防护已关闭（底层磁盘写入不会被拦截）");
            m_diskStatusLabel->setStyleSheet("color:#e0a355;");
        } else if (mode == 1) {
            m_diskStatusLabel->setText(QString("仅监控模式：已挂接 %1 个物理磁盘，事件只记录不拦截").arg(attached));
            m_diskStatusLabel->setStyleSheet("color:#e0a355;");
        } else {
            m_diskStatusLabel->setText(QString("拦截生效：已挂接 %1 个物理磁盘（MBR/GPT/分区表写保护）").arg(attached));
            m_diskStatusLabel->setStyleSheet("color:#4caf50;");
        }
    }
    if (m_diskStatLabel) {
        m_diskStatLabel->setText(QString("累计拦截 %1 次 · 仅记录 %2 次")
                                 .arg(blocked).arg(observed));
    }
}

void MainWindow::onRestoreCombo(const QString& name, const QString& value) {
    Q_UNUSED(name);
    Q_UNUSED(value);
    // 当前界面仅中文, 无语言切换, 预留接口
}

void MainWindow::onSetRepairItem(int index, const QString& status, const QString& result) {
    if (m_repairTable && index >= 0 && index < m_repairTable->rowCount()) {
        m_repairTable->item(index, 1)->setText(status);
        m_repairTable->item(index, 2)->setText(result);
    }
}

void MainWindow::onSetRepairButtons(bool enabled) {
    if (m_repairExecBtn) {
        m_repairExecBtn->setEnabled(enabled);
        m_repairExecBtn->setText(enabled ? "执行系统修复" : "正在修复...");
    }
}

void MainWindow::onSetRulesPath(const QString& path) {
    m_rulesPath = path;
    if (m_setRulesLabel) m_setRulesLabel->setText(path.isEmpty() ? "未设置" : path);
    onRefreshHipsRules();
}

void MainWindow::onShowNotification(const QString& title, const QString& message, int level) {
    // 黄色警告 (Warning) 已移除弹窗: 无用户决策价值且极易连发刷屏, 仅记日志
    if (level == static_cast<int>(NotificationDialog::Level::Warning)) {
        onAppendLog("WARN", title, message);
        return;
    }
    NotificationDialog::showNotification(title, message, 
        static_cast<NotificationDialog::Level>(level));
}

void MainWindow::onShowHipsPrompt(const QString& title, const QString& message, unsigned long pid, int level) {
    auto actionCb = [pid](unsigned long, bool allow) {
        fn_hips_response_cb cb = zeta_ui_get_hips_response_callback();
        if (cb) cb(pid, allow ? 1 : 0);
    };
    NotificationDialog::showHipsPrompt(title, message, pid,
        actionCb, static_cast<NotificationDialog::Level>(level));
}

void MainWindow::onUpdateDashboardStats(const QString& level, const QString& action, const QString& detail) {
    // Update event list (shift events down, newest at top)
    QString shortLine = QString("[%1] [%2] %3").arg(
        QDateTime::currentDateTime().toString("HH:mm"), level, action);
    if (m_statEvent5) m_statEvent5->setText(m_statEvent4->text());
    if (m_statEvent4) m_statEvent4->setText(m_statEvent3->text());
    if (m_statEvent3) m_statEvent3->setText(m_statEvent2->text());
    if (m_statEvent2) m_statEvent2->setText(m_statEvent1->text());
    if (m_statEvent1) m_statEvent1->setText(shortLine);

    // Parse and update stats counts
    if (action == "HIPS" || action == "hips") {
        m_statHipsCount++;
        if (m_statHipsLabel) m_statHipsLabel->setText(QString::number(m_statHipsCount));
    } else if (action == "EDR" || action == "edr") {
        m_statEdrCount++;
        if (m_statEdrLabel) m_statEdrLabel->setText(QString::number(m_statEdrCount));
        // "威胁阻断" — EDR 自动终止或已终止进程
        if (detail.contains("自动终止") || detail.contains("已终止") || detail.contains("auto-kill")) {
            m_statKilledCount++;
            if (m_statKilledLabel) m_statKilledLabel->setText(QString::number(m_statKilledCount));
        }
    }
    refreshSettingsStats();
}

void MainWindow::refreshSettingsStats() {
    if (m_setHipsLabel) m_setHipsLabel->setText(QString::number(m_statHipsCount));
    if (m_setEdrLabel)  m_setEdrLabel->setText(QString::number(m_statEdrCount));
    if (m_setKillLabel) m_setKillLabel->setText(QString::number(m_statKilledCount));
}

// ── Tools Page ───────────────────────────────────────────────────

void MainWindow::setupToolsPage() {
    auto* l = new QVBoxLayout(m_toolsPage);
    l->setContentsMargins(28, 28, 28, 28);
    l->setSpacing(16);

    // Top bar with back button and title
    auto* topBar = new QHBoxLayout();
    m_toolBackBtn = new QPushButton(QString::fromUtf8("\u2190 返回工具"));
    m_toolBackBtn->setObjectName("ghostBtn");
    m_toolBackBtn->setCursor(Qt::PointingHandCursor);
    m_toolBackBtn->setVisible(false);
    connect(m_toolBackBtn, &QPushButton::clicked, this, &MainWindow::showToolList);
    topBar->addWidget(m_toolBackBtn);

    m_toolTitleLabel = new QLabel("工具");
    m_toolTitleLabel->setObjectName("statusTitle");
    topBar->addWidget(m_toolTitleLabel);
    topBar->addStretch();
    l->addLayout(topBar);

    // Sub-stack for tool pages
    // 内缩 12px: 子页面内容不覆盖 contentPanel 的圆角区域
    m_toolStack = new QStackedWidget();
    m_toolStack->setObjectName("contentPanel");
    m_toolStack->setContentsMargins(12, 12, 12, 12);

    // Page 0: tool list
    auto* listPage = new QWidget();
    listPage->setObjectName("contentPanel");
    auto* listL = new QVBoxLayout(listPage);
    listL->setContentsMargins(0, 0, 0, 0);
    listL->setSpacing(4);

    // 只保留"操作型"工具; 规则/名单等"配置型"功能已迁入设置页
    struct ToolDef { const char* name; const char* desc; int index; };
    const ToolDef tools[] = {
        {"进程管理",   "实时查看系统进程，终止可疑进程", PROCESS_MGR},
        {"启动项管理", "管理开机启动项，禁用自启程序",   STARTUP_MGR},
        {"垃圾清理",   "扫描并清理系统暂存垃圾文件",     JUNK_CLEANER},
        {"系统修复",   "修复系统登录档与关键系统组件",   SYSTEM_REPAIR},
        {"隔离区",     "查看、恢复或彻底删除隔离文件",   QUARANTINE_MGR},
        {"勒索防护备份", "文档写前备份与恢复，勒索防篡改", RANSOM_RESTORE},
    };
    const int toolCount = 6;

    auto* grid = new QGridLayout();
    grid->setContentsMargins(0, 6, 0, 0);
    grid->setSpacing(14);

    for (int i = 0; i < toolCount; i++) {
        auto* card = createNavCard(tools[i].name, tools[i].desc, "toolIndex", tools[i].index);
        // 奇数个时最后一张卡跨满两列, 不留半边空缺
        int span = (i == toolCount - 1 && (toolCount % 2)) ? 2 : 1;
        grid->addWidget(card, i / 2, i % 2, 1, span);
    }
    listL->addLayout(grid);
    listL->addStretch();
    m_toolStack->addWidget(listPage); // index 0 = list

    // Create 6 tool sub-pages (操作型)
    for (int i = 0; i < 6; i++) {
        auto* page = new QWidget();
        page->setObjectName("contentPanel");
        m_toolStack->addWidget(page); // indices 1-6
    }

    // Setup each tool page
    setupProcessManager(m_toolStack->widget(PROCESS_MGR));
    setupStartupManager(m_toolStack->widget(STARTUP_MGR));
    setupJunkCleaner(m_toolStack->widget(JUNK_CLEANER));
    setupSystemRepair(m_toolStack->widget(SYSTEM_REPAIR));
    setupQuarantineManager(m_toolStack->widget(QUARANTINE_MGR));
    setupRansomRestoreManager(m_toolStack->widget(RANSOM_RESTORE));

    l->addWidget(m_toolStack, 1);
}

void MainWindow::showToolList() {
    m_toolStack->setCurrentIndex(TOOL_LIST);
    m_toolBackBtn->setVisible(false);
    m_toolTitleLabel->setText("工具");
    // (traffic monitor timer removed)
}

void MainWindow::showToolPage(int toolIndex) {
    if (toolIndex < 1 || toolIndex > 6) return;

    m_toolStack->setCurrentIndex(toolIndex);
    m_toolBackBtn->setVisible(true);

    const char* titles[] = {"进程管理", "启动项管理", "垃圾清理", "系统修复", "隔离区", "勒索防护备份"};
    m_toolTitleLabel->setText(titles[toolIndex - 1]);

    // Auto-refresh when entering a tool page
    switch (toolIndex) {
    case PROCESS_MGR: onRefreshProcessList(); break;
    case STARTUP_MGR: onRefreshStartupList(); break;
    case JUNK_CLEANER: onRefreshJunkScan(); break;
    case SYSTEM_REPAIR: break;
    case QUARANTINE_MGR: onRefreshQuarantine(); break;
    case RANSOM_RESTORE: onRefreshRansom(); break;
    }
}

// ── Settings Page (配置型功能迁入后的新首页) ─────────────────────

void MainWindow::setupSettingsPage() {
    auto* l = new QVBoxLayout(m_settingsPage);
    l->setContentsMargins(28, 28, 28, 28);
    l->setSpacing(16);

    // 顶部: 返回按钮 + 标题
    auto* topBar = new QHBoxLayout();
    m_settingsBackBtn = new QPushButton(QString::fromUtf8("\u2190 返回设置"));
    m_settingsBackBtn->setObjectName("ghostBtn");
    m_settingsBackBtn->setCursor(Qt::PointingHandCursor);
    m_settingsBackBtn->setVisible(false);
    connect(m_settingsBackBtn, &QPushButton::clicked, this, &MainWindow::showSettingsMain);
    topBar->addWidget(m_settingsBackBtn);

    m_settingsTitleLabel = new QLabel("设置");
    m_settingsTitleLabel->setObjectName("statusTitle");
    topBar->addWidget(m_settingsTitleLabel);
    topBar->addStretch();
    l->addLayout(topBar);

    m_settingsStack = new QStackedWidget();
    m_settingsStack->setObjectName("contentPanel");
    m_settingsStack->setContentsMargins(12, 12, 12, 12);

    // ── index 0: 主设置页 (可滚动, 内容多时不出界) ──
    auto* scroll = new QScrollArea();
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setStyleSheet("QScrollArea { background: transparent; border: none; }");
    auto* mainPage = new QWidget();
    mainPage->setStyleSheet("background: transparent;");
    auto* ml = new QVBoxLayout(mainPage);
    ml->setContentsMargins(0, 0, 4, 0);
    ml->setSpacing(0);

    auto addGroup = [&](const QString& title, QGridLayout* grid) {
        auto* gt = new QLabel(title);
        gt->setObjectName("groupTitle");
        ml->addWidget(gt);
        ml->addLayout(grid);
        ml->addSpacing(20);
    };
    auto makeGrid = []() {
        auto* g = new QGridLayout();
        g->setContentsMargins(0, 6, 0, 0);
        g->setSpacing(14);
        return g;
    };

    // 1) 高级防护策略 — 从防护页迁入的开关 (仍走同一套后端 key / 回调)
    {
        auto* grid = makeGrid();
        grid->addWidget(createSwitchCard("勒索重定向", "勒索写入重定向到隔离副本，原文件保留",
                                         "ransom_redirect_switch"), 0, 0);
        grid->addWidget(createSwitchCard("学习模式", "启动后自动放行可疑行为并记录日志",
                                         "learning_switch"), 0, 1);
        addGroup("高 级 防 护 策 略", grid);
    }

    // 2) 规则与名单 — 从工具页迁入的"配置型"功能 (EDR 已升级为一级页, 此处仅作跳转入口)
    {
        auto* grid = makeGrid();
        grid->addWidget(createNavCard("HIPS 规则", "管理 HIPS 拦截规则（允许 / 拒绝 / 询问）",
                                      "settingsIndex", SET_HIPS), 0, 0);
        grid->addWidget(createNavCard("白名单", "管理信任进程与路径白名单",
                                      "settingsIndex", SET_WHITELIST), 0, 1);
        grid->addWidget(createNavCard("网络黑名单", "管理 C2 / 恶意 IP 与端口黑名单",
                                      "settingsIndex", SET_NETWORK), 1, 0);
        grid->addWidget(createNavCard("EDR 规则", "打开 EDR 检测规则页（权重 / YARA / 签名）",
                                      "navIndex", PAGE_EDR), 1, 1);
        addGroup("规 则 与 名 单", grid);
    }

    // 3) 运行状态 / 关于 (双列信息卡)
    {
        auto makeInfoRow = [](const QString& label, QLabel*& val, const QString& init) {
            auto* row = new QHBoxLayout();
            auto* lb = new QLabel(label);
            lb->setObjectName("secLabel");
            val = new QLabel(init);
            val->setObjectName("cardValue");
            val->setWordWrap(true);
            val->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
            row->addWidget(lb, 0);
            row->addWidget(val, 1);
            return row;
        };

        auto* cols = new QHBoxLayout();
        cols->setSpacing(20);

        // 左: 运行状态 (真实数据, 动态刷新)
        auto* stateGroup = new QGroupBox("运行状态");
        stateGroup->setObjectName("configGroup");
        auto* stateL = new QVBoxLayout(stateGroup);
        stateL->setContentsMargins(16, 18, 16, 18);
        stateL->setSpacing(12);
        stateL->addLayout(makeInfoRow("驱动状态", m_setDriverLabel, "检测中…"));
        stateL->addLayout(makeInfoRow("规则目录", m_setRulesLabel, "未设置"));
        stateL->addLayout(makeInfoRow("HIPS 拦截", m_setHipsLabel, "0"));
        stateL->addLayout(makeInfoRow("EDR 告警", m_setEdrLabel, "0"));
        stateL->addLayout(makeInfoRow("威胁阻断", m_setKillLabel, "0"));
        stateL->addStretch();
        cols->addWidget(stateGroup, 1);

        // 右: 关于 (静态信息)
        auto* aboutGroup = new QGroupBox("关于");
        aboutGroup->setObjectName("configGroup");
        auto* aboutL = new QVBoxLayout(aboutGroup);
        aboutL->setContentsMargins(16, 18, 16, 18);
        aboutL->setSpacing(12);
        auto addInfo = [&](const QString& label, const QString& value) {
            auto* row = new QHBoxLayout();
            auto* lb = new QLabel(label);
            lb->setObjectName("secLabel");
            auto* vl = new QLabel(value);
            vl->setObjectName("cardValue");
            vl->setWordWrap(true);
            vl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
            row->addWidget(lb, 0);
            row->addWidget(vl, 1);
            aboutL->addLayout(row);
        };
        addInfo("版本", "ZETA Security v2.0.0");
        addInfo("平台", "Windows 10 22H2 x64");
        addInfo("引擎", "ZETA_Core / ZETA_Engine / ZETA_Monitor");
        addInfo("驱动", "ZETA_Drv / ZETA_NetFilter / ZETA_DiskFilter");
        addInfo("说明", "日常防护开关在“防护”页，高级策略与规则配置在本页。");
        aboutL->addStretch();
        cols->addWidget(aboutGroup, 1);

        ml->addLayout(cols);
    }
    ml->addStretch();

    scroll->setWidget(mainPage);
    m_settingsStack->addWidget(scroll);   // index 0 = 主设置页

    // ── index 1-3: 配置型子页 ──
    for (int i = 0; i < 3; i++) {
        auto* page = new QWidget();
        page->setObjectName("contentPanel");
        m_settingsStack->addWidget(page);
    }
    setupHipsManager(m_settingsStack->widget(SET_HIPS));
    setupWhitelistManager(m_settingsStack->widget(SET_WHITELIST));
    setupNetworkMgr(m_settingsStack->widget(SET_NETWORK));

    l->addWidget(m_settingsStack, 1);
}

void MainWindow::showSettingsMain() {
    m_settingsStack->setCurrentIndex(SETTINGS_MAIN);
    m_settingsBackBtn->setVisible(false);
    m_settingsTitleLabel->setText("设置");
}

void MainWindow::showSettingsPage(int index) {
    if (index < 1 || index > 3) return;

    m_settingsStack->setCurrentIndex(index);
    m_settingsBackBtn->setVisible(true);

    const char* titles[] = {"HIPS 规则", "白名单", "网络黑名单"};
    m_settingsTitleLabel->setText(titles[index - 1]);

    // 进入子页时自动刷新
    switch (index) {
    case SET_HIPS: onRefreshHipsRules(); break;
    case SET_WHITELIST: onRefreshWhitelist(); break;
    case SET_NETWORK: onRefreshNetworkList(); break;
    }
}

// ── Tool: Process Manager ───────────────────────────────────────

void MainWindow::setupProcessManager(QWidget* page) {
    auto* l = new QVBoxLayout(page);
    l->setContentsMargins(0, 0, 0, 0);
    l->setSpacing(8);

    auto* ctrl = new QHBoxLayout();
    auto* refreshBtn = new QPushButton("刷新");
    refreshBtn->setObjectName("actionBtn");
    refreshBtn->setCursor(Qt::PointingHandCursor);
    connect(refreshBtn, &QPushButton::clicked, this, &MainWindow::onRefreshProcessList);
    ctrl->addWidget(refreshBtn);

    auto* killBtn = new QPushButton("结束进程");
    killBtn->setObjectName("actionBtn");
    killBtn->setProperty("danger", true);
    killBtn->setCursor(Qt::PointingHandCursor);
    connect(killBtn, &QPushButton::clicked, this, [this]() {
        auto sel = m_procTable->selectedItems();
        if (sel.isEmpty()) return;
        int row = sel[0]->row();
        QString pidStr = m_procTable->item(row, 1)->text();
        DWORD pid = pidStr.toULong();
        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProc) {
            if (TerminateProcess(hProc, 1)) {
                onRefreshProcessList();
                onAppendLog("INFO", "进程管理", "已终止 PID: " + pidStr);
            }
            CloseHandle(hProc);
        }
    });
    ctrl->addWidget(killBtn);

    m_procCountLabel = new QLabel("进程数: 0");
    m_procCountLabel->setObjectName("secLabel");
    ctrl->addWidget(m_procCountLabel);
    ctrl->addStretch();
    l->addLayout(ctrl);

    m_procTable = new QTableWidget();
    m_procTable->setColumnCount(4);
    m_procTable->setHorizontalHeaderLabels({"进程名", "PID", "线程数", "内存(KB)"});
    m_procTable->horizontalHeader()->setStretchLastSection(true);
    m_procTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_procTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_procTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_procTable->verticalHeader()->setVisible(false);
    l->addWidget(m_procTable, 1);
}

void MainWindow::onRefreshProcessList() {
    if (!m_procTable) return;
    m_procTable->setRowCount(0);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    int count = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            int row = m_procTable->rowCount();
            m_procTable->insertRow(row);
            m_procTable->setItem(row, 0, new QTableWidgetItem(QString::fromWCharArray(pe.szExeFile)));
            m_procTable->setItem(row, 1, new QTableWidgetItem(QString::number(pe.th32ProcessID)));
            m_procTable->setItem(row, 2, new QTableWidgetItem(QString::number(pe.cntThreads)));

            // Get memory info
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProc) {
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
                    m_procTable->setItem(row, 3, new QTableWidgetItem(QString::number(pmc.WorkingSetSize / 1024)));
                }
                CloseHandle(hProc);
            } else {
                m_procTable->setItem(row, 3, new QTableWidgetItem("-"));
            }
            count++;
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    m_procCountLabel->setText(QString("进程数: %1").arg(count));
}

// ── Tool: Startup Manager ───────────────────────────────────────

void MainWindow::setupStartupManager(QWidget* page) {
    auto* l = new QVBoxLayout(page);
    l->setContentsMargins(0, 0, 0, 0);
    l->setSpacing(8);

    auto* ctrl = new QHBoxLayout();
    auto* refreshBtn = new QPushButton("刷新");
    refreshBtn->setObjectName("actionBtn");
    refreshBtn->setCursor(Qt::PointingHandCursor);
    connect(refreshBtn, &QPushButton::clicked, this, &MainWindow::onRefreshStartupList);
    ctrl->addWidget(refreshBtn);

    auto* disableBtn = new QPushButton("禁用");
    disableBtn->setObjectName("actionBtn");
    disableBtn->setCursor(Qt::PointingHandCursor);
    connect(disableBtn, &QPushButton::clicked, this, [this]() {
        auto sel = m_startupTable->selectedItems();
        if (sel.isEmpty()) return;
        int row = sel[0]->row();
        QString name = m_startupTable->item(row, 0)->text();
        QString path = m_startupTable->item(row, 1)->text();
        // Delete the registry value to disable it
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                          0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            std::wstring wname = name.toStdWString();
            RegDeleteValueW(hKey, wname.c_str());
            RegCloseKey(hKey);
            m_startupTable->item(row, 0)->setText(name + " (已禁用)");
            m_startupTable->item(row, 2)->setText("已禁用");
            onAppendLog("INFO", "启动项", "已禁用: " + name);
        }
    });
    ctrl->addWidget(disableBtn);
    ctrl->addStretch();
    l->addLayout(ctrl);

    m_startupTable = new QTableWidget();
    m_startupTable->setColumnCount(3);
    m_startupTable->setHorizontalHeaderLabels({"名称", "路径", "位置"});
    m_startupTable->horizontalHeader()->setStretchLastSection(true);
    m_startupTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_startupTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_startupTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_startupTable->verticalHeader()->setVisible(false);
    l->addWidget(m_startupTable, 1);
}

void MainWindow::onRefreshStartupList() {
    if (!m_startupTable) return;
    m_startupTable->setRowCount(0);

    struct { HKEY hive; const wchar_t* path; const char* location; } regPaths[] = {
        {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM/Run"},
        {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU/Run"},
        {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM/RunOnce"},
        {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU/RunOnce"},
    };

    for (auto& rp : regPaths) {
        HKEY hKey;
        if (RegOpenKeyExW(rp.hive, rp.path, 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &hKey) != ERROR_SUCCESS)
            continue;

        wchar_t valueName[1024];
        wchar_t valueData[4096];
        DWORD valueNameSize, valueDataSize, type;
        DWORD index = 0;
        while (true) {
            valueNameSize = 1024;
            valueDataSize = 4096;
            type = 0;
            LONG ret = RegEnumValueW(hKey, index, valueName, &valueNameSize,
                                      nullptr, &type, (BYTE*)valueData, &valueDataSize);
            if (ret != ERROR_SUCCESS) break;
            index++;

            if (type != REG_SZ && type != REG_EXPAND_SZ) continue;

            int row = m_startupTable->rowCount();
            m_startupTable->insertRow(row);
            m_startupTable->setItem(row, 0, new QTableWidgetItem(QString::fromWCharArray(valueName)));
            m_startupTable->setItem(row, 1, new QTableWidgetItem(QString::fromWCharArray(valueData)));
            m_startupTable->setItem(row, 2, new QTableWidgetItem(rp.location));
        }
        RegCloseKey(hKey);
    }
}

// ── Tool: Junk Cleaner ───────────────────────────────────────────

void MainWindow::setupJunkCleaner(QWidget* page) {
    auto* l = new QVBoxLayout(page);
    l->setContentsMargins(0, 0, 0, 0);
    l->setSpacing(8);

    auto* ctrl = new QHBoxLayout();
    auto* scanBtn = new QPushButton("扫描垃圾");
    scanBtn->setObjectName("actionBtn");
    scanBtn->setCursor(Qt::PointingHandCursor);
    connect(scanBtn, &QPushButton::clicked, this, &MainWindow::onRefreshJunkScan);
    ctrl->addWidget(scanBtn);

    m_junkCleanBtn = new QPushButton("清理选中");
    m_junkCleanBtn->setObjectName("actionBtn");
    m_junkCleanBtn->setProperty("danger", true);
    m_junkCleanBtn->setCursor(Qt::PointingHandCursor);
    connect(m_junkCleanBtn, &QPushButton::clicked, this, [this]() {
        int deleted = 0;
        for (int row = 0; row < m_junkTable->rowCount(); row++) {
            auto* checkItem = m_junkTable->item(row, 0);
            if (checkItem && checkItem->checkState() == Qt::Checked) {
                QString path = m_junkTable->item(row, 2)->text();
                if (zetaDeleteToRecycleBin(path)) {   // M2-4: 走回收站（原 DeleteFileW 为永久删除）
                    deleted++;
                    m_junkTable->item(row, 1)->setText("Deleted");
                }
            }
        }
        onAppendLog("INFO", "垃圾清理", QString("已清理 %1 个文件").arg(deleted));
        onRefreshJunkScan();
    });
    ctrl->addWidget(m_junkCleanBtn);

    m_junkSizeLabel = new QLabel("就绪");
    m_junkSizeLabel->setObjectName("secLabel");
    ctrl->addWidget(m_junkSizeLabel);
    ctrl->addStretch();
    l->addLayout(ctrl);

    m_junkTable = new QTableWidget();
    m_junkTable->setColumnCount(4);
    m_junkTable->setHorizontalHeaderLabels({"选择", "状态", "路径", "大小(KB)"});
    m_junkTable->horizontalHeader()->setStretchLastSection(true);
    m_junkTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_junkTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_junkTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_junkTable->verticalHeader()->setVisible(false);
    l->addWidget(m_junkTable, 1);
}

void MainWindow::onRefreshJunkScan() {
    if (!m_junkTable) return;
    m_junkTable->setRowCount(0);
    int totalSize = 0;

    // Scan standard temp directories
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);

    struct { const wchar_t* path; const char* category; } junkPaths[] = {
        {L"C:\\Windows\\Temp\\*", "Windows Temp"},
        {tempPath, "User Temp"},
    };

    for (auto& jp : junkPaths) {
        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW(jp.path, &findData);
        if (hFind == INVALID_HANDLE_VALUE) continue;

        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            QString fullPath = QString::fromWCharArray(jp.path);
            fullPath = fullPath.left(fullPath.length() - 1); // remove *
            fullPath += QString::fromWCharArray(findData.cFileName);

            int sizeKB = (int)((findData.nFileSizeLow / 1024) +
                               ((findData.nFileSizeHigh * (MAXDWORD + 1ULL)) / 1024));

            int row = m_junkTable->rowCount();
            m_junkTable->insertRow(row);

            auto* checkItem = new QTableWidgetItem();
            checkItem->setCheckState(Qt::Unchecked);
            m_junkTable->setItem(row, 0, checkItem);
            m_junkTable->setItem(row, 1, new QTableWidgetItem("Found"));
            m_junkTable->setItem(row, 2, new QTableWidgetItem(fullPath));
            m_junkTable->setItem(row, 3, new QTableWidgetItem(QString::number(sizeKB)));
            totalSize += sizeKB;
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }

    m_junkSizeLabel->setText(QString("共 %1 个文件, %2 KB")
        .arg(m_junkTable->rowCount())
        .arg(totalSize));
}

// ── Tool: System Repair ─────────────────────────────────────────

void MainWindow::setupSystemRepair(QWidget* page) {
    auto* l = new QVBoxLayout(page);
    l->setContentsMargins(0, 0, 0, 0);
    l->setSpacing(8);

    auto* ctrl = new QHBoxLayout();
    m_repairExecBtn = new QPushButton("执行系统修复");
    m_repairExecBtn->setObjectName("actionBtn");
    m_repairExecBtn->setCursor(Qt::PointingHandCursor);
    connect(m_repairExecBtn, &QPushButton::clicked, this, [this]() {
        onAppendLog("INFO", "系统修复", "正在执行系统修复...");
        m_repairExecBtn->setEnabled(false);
        m_repairExecBtn->setText("正在修复...");

        // Reset table status
        for (int i = 0; i < m_repairTable->rowCount(); i++) {
            m_repairTable->item(i, 1)->setText("运行中");
            m_repairTable->item(i, 2)->setText("-");
        }

        // Call backend repair (runs in background thread)
        Bridge::instance()->invokeToolCallback("系统修复");
    });
    ctrl->addWidget(m_repairExecBtn);
    ctrl->addStretch();
    l->addLayout(ctrl);

    m_repairTable = new QTableWidget();
    m_repairTable->setColumnCount(3);
    m_repairTable->setHorizontalHeaderLabels({"修复项目", "状态", "结果"});
    m_repairTable->horizontalHeader()->setStretchLastSection(true);
    m_repairTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_repairTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_repairTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_repairTable->verticalHeader()->setVisible(false);

    // Add repair items
    const char* items[] = {"系统文件检查(SFC)", "系统映像修复(DISM)", "临时文件清理", "网络重置"};
    for (int i = 0; i < 4; i++) {
        int row = m_repairTable->rowCount();
        m_repairTable->insertRow(row);
        m_repairTable->setItem(row, 0, new QTableWidgetItem(items[i]));
        m_repairTable->setItem(row, 1, new QTableWidgetItem("待执行"));
        m_repairTable->setItem(row, 2, new QTableWidgetItem("-"));
    }
    l->addWidget(m_repairTable, 1);
}

// (TrafficMonitor removed — previously at lines 1132-1195)


// ── Tool: HIPS Manager ──────────────────────────────────────────

void MainWindow::setupHipsManager(QWidget* page) {
    auto* l = new QVBoxLayout(page);
    l->setContentsMargins(0, 0, 0, 0);
    l->setSpacing(8);

    auto* ctrl = new QHBoxLayout();
    auto* refreshBtn = new QPushButton("刷新规则");
    refreshBtn->setObjectName("actionBtn");
    refreshBtn->setCursor(Qt::PointingHandCursor);
    connect(refreshBtn, &QPushButton::clicked, this, &MainWindow::onRefreshHipsRules);
    ctrl->addWidget(refreshBtn);

    auto* editHipsBtn = new QPushButton("编辑 HIPS 规则");
    editHipsBtn->setObjectName("actionBtn");
    editHipsBtn->setCursor(Qt::PointingHandCursor);
    connect(editHipsBtn, &QPushButton::clicked, this, [this]() {
        QString path = m_rulesPath;
        if (path.isEmpty())
            path = QCoreApplication::applicationDirPath() + "/Plugins/Rules/Rules_Hips.json";
        QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    });
    ctrl->addWidget(editHipsBtn);

    auto* editUserBtn = new QPushButton("编辑自定义规则");
    editUserBtn->setObjectName("actionBtn");
    editUserBtn->setCursor(Qt::PointingHandCursor);
    connect(editUserBtn, &QPushButton::clicked, this, [this]() {
        QString rulesPath = QCoreApplication::applicationDirPath() + "/Plugins/Rules/Rules_User.json";
        QDesktopServices::openUrl(QUrl::fromLocalFile(rulesPath));
    });
    ctrl->addWidget(editUserBtn);

    ctrl->addStretch();
    l->addLayout(ctrl);

    auto* infoLabel = new QLabel("实时 HIPS 规则列表（从 Rules_Hips.json 加载）。勾选 = 启用，取消勾选 = 禁用。重启后生效。");
    infoLabel->setObjectName("secLabel");
    infoLabel->setWordWrap(true);
    l->addWidget(infoLabel);

    m_hipsTable = new QTableWidget();
    m_hipsTable->setColumnCount(5);
    m_hipsTable->setHorizontalHeaderLabels({"规则ID", "类型", "进程/路径", "分值", "启用"});
    m_hipsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_hipsTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_hipsTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_hipsTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_hipsTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    m_hipsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_hipsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_hipsTable->verticalHeader()->setVisible(false);
    l->addWidget(m_hipsTable, 1);
}

void MainWindow::onRefreshHipsRules() {
    if (!m_hipsTable) return;
    m_hipsTable->setRowCount(0);
    m_rules.clear();

    // Read rules from JSON file
    QString path = m_rulesPath;
    if (path.isEmpty()) {
        path = QCoreApplication::applicationDirPath() + "/Plugins/Rules/Rules_Hips.json";
    }

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        // Fallback: show message when file can't be read
        m_hipsTable->insertRow(0);
        m_hipsTable->setItem(0, 0, new QTableWidgetItem("无法加载规则文件: " + path));
        return;
    }

    QByteArray data = file.readAll();
    file.close();

    QJsonParseError parseErr;
    QJsonDocument doc = QJsonDocument::fromJson(data, &parseErr);
    if (parseErr.error != QJsonParseError::NoError) {
        m_hipsTable->insertRow(0);
        m_hipsTable->setItem(0, 0, new QTableWidgetItem("JSON 解析错误: " + parseErr.errorString()));
        return;
    }

    QJsonArray rules = doc.object()["rules"].toArray();
    if (rules.isEmpty()) {
        m_hipsTable->insertRow(0);
        m_hipsTable->setItem(0, 0, new QTableWidgetItem("没有找到规则"));
        return;
    }

    for (const auto& ruleVal : rules) {
        QJsonObject obj = ruleVal.toObject();

        // Skip comment objects (they have "//" keys)
        if (obj.contains("//")) continue;

        QString id = obj["id"].toString();
        int code = obj["code"].toInt();
        QString process = obj["process"].toString();
        QString target = obj["target"].toString();
        int action = obj["action"].toInt();
        int score = obj["score"].toInt();

        HipsRuleItem item;
        item.id = id;
        item.code = QString::number(code);
        item.process = process;
        item.target = target;
        item.action = action;
        item.score = score;
        // P0-3: 读回 enabled 字段, 与 hips_engine.cpp 解析对齐.
        // 缺省为启用; 显式 false/"false"/0/"0" 才视为禁用, 避免误启用被禁规则.
        if (!obj.contains("enabled")) {
            item.enabled = true;
        } else {
            QJsonValue ev = obj["enabled"];
            if (ev.isBool()) {
                item.enabled = ev.toBool();
            } else if (ev.isDouble()) {
                item.enabled = (ev.toInt() != 0);
            } else {
                QString es = ev.toString().trimmed().toLower();
                item.enabled = !(es == "false" || es == "0");
            }
        }

        // Determine type label from code
        QString typeLabel;
        switch (code) {
            case ZETA_MSG_FILE_PROTECT: typeLabel = "文件保护"; break;
            case ZETA_MSG_LEARN_PATH: typeLabel = "学习模式"; break;
            case ZETA_MSG_REG_PROTECT: typeLabel = "注册表保护"; break;
            case ZETA_MSG_DISK_WRITE: typeLabel = "磁盘写入"; break;
            case ZETA_MSG_RANSOM_FIRST_WRITE: case ZETA_MSG_RANSOM_ENTROPY_WRITE: case ZETA_MSG_RANSOM_HONEY_TOUCH: typeLabel = "勒索防护"; break;
            case ZETA_MSG_CODE_INJECT: typeLabel = "注入检测"; break;
            case ZETA_MSG_SILVERFOX_SIGNATURE: typeLabel = "银狐检测"; break;
            default:   typeLabel = "其他(" + QString::number(code) + ")"; break;
        }

        QString desc = process;
        if (!target.isEmpty() && target != "") {
            desc += " → " + target;
        }

        QString actionLabel;
        switch (action) {
            case 0: actionLabel = "放行"; break;
            case 1: actionLabel = "拦截"; break;
            case 2: actionLabel = "询问"; break;
            default: actionLabel = "未知"; break;
        }

        int row = m_hipsTable->rowCount();
        m_hipsTable->insertRow(row);

        // Column 0: Rule ID
        m_hipsTable->setItem(row, 0, new QTableWidgetItem(id));

        // Column 1: Type
        m_hipsTable->setItem(row, 1, new QTableWidgetItem(typeLabel));

        // Column 2: Process → Target
        m_hipsTable->setItem(row, 2, new QTableWidgetItem(desc));

        // Column 3: Score
        m_hipsTable->setItem(row, 3, new QTableWidgetItem(
            action == 0 ? QString("放行") : QString::number(score)));

        // Column 4: Enable checkbox
        auto* checkWidget = new QWidget();
        auto* checkLayout = new QHBoxLayout(checkWidget);
        checkLayout->setContentsMargins(0, 0, 0, 0);
        checkLayout->setAlignment(Qt::AlignCenter);
        auto* checkBox = new QCheckBox();
        checkBox->setChecked(item.enabled);
        checkBox->setProperty("ruleIndex", row);
        connect(checkBox, &QCheckBox::toggled, this, [this, row](bool checked) {
            if (row < m_rules.size()) {
                m_rules[row].enabled = checked;
                // 写回 JSON 并通知后端重载 HIPS 规则 (禁用规则不参与匹配)
                saveHipsEnabledToJson();
                Bridge::instance()->invokeToolCallback("hips_reload");
            }
        });
        checkLayout->addWidget(checkBox);
        m_hipsTable->setCellWidget(row, 4, checkWidget);

        m_rules.append(item);
    }

    m_hipsTable->resizeRowsToContents();
}

// HIPS 规则启用状态写回 JSON (勾选时调用, 使禁用规则持久化并让后端重载)
void MainWindow::saveHipsEnabledToJson() {
    QString path = m_rulesPath;
    if (path.isEmpty()) {
        path = QCoreApplication::applicationDirPath() + "/Plugins/Rules/Rules_Hips.json";
    }
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &err);
    file.close();
    if (err.error != QJsonParseError::NoError) return;

    QJsonObject root = doc.object();
    QJsonArray rules = root["rules"].toArray();
    QJsonArray newRules;
    for (const auto& rv : rules) {
        QJsonObject o = rv.toObject();
        if (o.contains("//")) { newRules.append(rv); continue; }  // 保留注释对象
        QString id = o["id"].toString();
        // 从 m_rules 查找 enabled 状态
        bool enabled = true;
        for (const auto& item : m_rules) {
            if (item.id == id) { enabled = item.enabled; break; }
        }
        o["enabled"] = enabled;
        newRules.append(o);
    }
    root["rules"] = newRules;

    QFile outFile(path);
    if (outFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        outFile.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
        outFile.close();
    }
}

// ── Tool: Whitelist Manager ──────────────────────────────────────

void MainWindow::setupWhitelistManager(QWidget* page) {
    auto* l = new QVBoxLayout(page);
    l->setContentsMargins(0, 0, 0, 0);
    l->setSpacing(8);

    auto* ctrl = new QHBoxLayout();
    m_whitelistPathEdit = new QLineEdit();
    m_whitelistPathEdit->setPlaceholderText("输入要添加的路径...");
    ctrl->addWidget(m_whitelistPathEdit, 1);

    auto* addBtn = new QPushButton("添加");
    addBtn->setObjectName("actionBtn");
    addBtn->setCursor(Qt::PointingHandCursor);
    connect(addBtn, &QPushButton::clicked, this, [this]() {
        QString path = m_whitelistPathEdit->text().trimmed();
        if (path.isEmpty()) return;
        // 通知后端写入驱动注册表白名单
        Bridge::instance()->invokeToolCallback("whitelist_add:" + path);
        m_whitelistPathEdit->clear();
        onRefreshWhitelist();
    });
    ctrl->addWidget(addBtn);

    auto* removeBtn = new QPushButton("移除");
    removeBtn->setObjectName("actionBtn");
    removeBtn->setProperty("danger", true);
    removeBtn->setCursor(Qt::PointingHandCursor);
    connect(removeBtn, &QPushButton::clicked, this, [this]() {
        auto sel = m_whitelistTable->selectedItems();
        if (sel.isEmpty()) return;
        int row = sel[0]->row();
        QString path = m_whitelistTable->item(row, 0)->text();
        // 通知后端从驱动注册表白名单移除
        Bridge::instance()->invokeToolCallback("whitelist_remove:" + path);
        onRefreshWhitelist();
    });
    ctrl->addWidget(removeBtn);
    ctrl->addStretch();
    l->addLayout(ctrl);

    m_whitelistTable = new QTableWidget();
    m_whitelistTable->setColumnCount(3);
    m_whitelistTable->setHorizontalHeaderLabels({"路径", "来源", "状态"});
    m_whitelistTable->horizontalHeader()->setStretchLastSection(true);
    m_whitelistTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_whitelistTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_whitelistTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_whitelistTable->verticalHeader()->setVisible(false);
    l->addWidget(m_whitelistTable, 1);
}

void MainWindow::onRefreshWhitelist() {
    if (!m_whitelistTable) return;
    m_whitelistTable->setRowCount(0);

    // 从驱动注册表白名单读取 (与行为引擎 loadWhitelist 同一来源)
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\ZETA_Drv\\Parameters",
        0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return;
    }
    WCHAR buf[8192] = {0};
    DWORD type = 0, size = sizeof(buf);
    if (RegQueryValueExW(hKey, L"LearnedProcesses", nullptr, &type,
        (LPBYTE)buf, &size) == ERROR_SUCCESS && type == REG_MULTI_SZ) {
        const WCHAR* p = buf;
        while (*p) {
            std::wstring s(p);
            if (!s.empty()) {
                int row = m_whitelistTable->rowCount();
                m_whitelistTable->insertRow(row);
                m_whitelistTable->setItem(row, 0, new QTableWidgetItem(QString::fromStdWString(s)));
                m_whitelistTable->setItem(row, 1, new QTableWidgetItem("驱动注册表"));
                m_whitelistTable->setItem(row, 2, new QTableWidgetItem("启用"));
            }
            p += s.length() + 1;
        }
    }
    RegCloseKey(hKey);
}

// ── Tool: Quarantine Manager ─────────────────────────────────────

void MainWindow::setupQuarantineManager(QWidget* page) {
    auto* l = new QVBoxLayout(page);
    l->setContentsMargins(0, 0, 0, 0);
    l->setSpacing(8);

    auto* ctrl = new QHBoxLayout();
    auto* refreshBtn = new QPushButton("刷新");
    refreshBtn->setObjectName("actionBtn");
    refreshBtn->setCursor(Qt::PointingHandCursor);
    connect(refreshBtn, &QPushButton::clicked, this, &MainWindow::onRefreshQuarantine);
    ctrl->addWidget(refreshBtn);

    auto* restoreBtn = new QPushButton("恢复");
    restoreBtn->setObjectName("actionBtn");
    restoreBtn->setCursor(Qt::PointingHandCursor);
    connect(restoreBtn, &QPushButton::clicked, this, [this]() {
        auto sel = m_quarantineTable->selectedItems();
        if (sel.isEmpty()) return;
        int row = sel[0]->row();
        QString origPath = m_quarantineTable->item(row, 3)->text();
        QString qPath = m_quarantineTable->item(row, 0)->text();
        if (origPath.isEmpty() || origPath == "-") {
            onAppendLog("WARN", "隔离区", "无法恢复：原始路径未知");
            return;
        }
        // 创建目标父目录（可能已被删除）
        int lastSlash = origPath.lastIndexOf('\\');
        if (lastSlash > 0) {
            QString dir = origPath.left(lastSlash);
            QDir().mkpath(dir);
        }
        // 用 CopyFile + DeleteFile 代替 MoveFileW（支持跨卷）
        if (CopyFileW((const wchar_t*)qPath.utf16(), (const wchar_t*)origPath.utf16(), FALSE)) {
            DeleteFileW((const wchar_t*)qPath.utf16());
            // 删除 .info 文件
            DeleteFileW((std::wstring((const wchar_t*)qPath.utf16()) + L".info").c_str());
            onRefreshQuarantine();
            onAppendLog("INFO", "隔离区", "已恢复: " + origPath);
        } else {
            DWORD err = GetLastError();
            QString errMsg;
            if (err == 5) errMsg = "访问被拒绝（目标文件可能被占用）";
            else if (err == 80) errMsg = "目标文件已存在";
            else errMsg = "错误码 " + QString::number(err);
            onAppendLog("ERROR", "隔离区", "恢复失败: " + errMsg + " -> " + origPath);
        }
    });
    ctrl->addWidget(restoreBtn);

    auto* deleteBtn = new QPushButton("永久删除");
    deleteBtn->setObjectName("actionBtn");
    deleteBtn->setProperty("danger", true);
    deleteBtn->setCursor(Qt::PointingHandCursor);
    connect(deleteBtn, &QPushButton::clicked, this, [this]() {
        auto sel = m_quarantineTable->selectedItems();
        if (sel.isEmpty()) return;
        int row = sel[0]->row();
        QString qPath = m_quarantineTable->item(row, 0)->text();
        if (DeleteFileW((const wchar_t*)qPath.utf16())) {
            // 同时删除 .info 文件
            DeleteFileW((std::wstring((const wchar_t*)qPath.utf16()) + L".info").c_str());
            onRefreshQuarantine();
            onAppendLog("INFO", "隔离区", "已永久删除隔离文件");
        } else {
            onAppendLog("ERROR", "隔离区", "删除失败: 错误码 " + QString::number(GetLastError()));
        }
    });
    ctrl->addWidget(deleteBtn);
    ctrl->addStretch();
    l->addLayout(ctrl);

    m_quarantineTable = new QTableWidget();
    m_quarantineTable->setColumnCount(4);
    m_quarantineTable->setHorizontalHeaderLabels({"隔离文件", "大小", "隔离时间", "原始路径"});
    m_quarantineTable->horizontalHeader()->setStretchLastSection(true);
    m_quarantineTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_quarantineTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_quarantineTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_quarantineTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_quarantineTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_quarantineTable->verticalHeader()->setVisible(false);
    l->addWidget(m_quarantineTable, 1);
}

void MainWindow::onRefreshQuarantine() {
    if (!m_quarantineTable) return;
    m_quarantineTable->setRowCount(0);

    // Scan quarantine directory
    const wchar_t* quarantineDir = L"C:\\ProgramData\\ZETA\\Quarantine";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW((std::wstring(quarantineDir) + L"\\*").c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (wcslen(findData.cFileName) == 0) continue;

        // 跳过 .info 文件
        std::wstring fname = findData.cFileName;
        if (fname.size() >= 5 && fname.substr(fname.size() - 5) == L".info") continue;

        QString fullPath = QString::fromWCharArray(quarantineDir) + "\\" +
                          QString::fromWCharArray(findData.cFileName);

        // 原始路径来自同名 .info 文件; 编码乱码修复: 旧文件可能是 UTF-16LE/ANSI,
        // 新版可能被其它写入方写成 UTF-8 → 统一走自适应解码, 不做定长截断。
        QString origPath = zetaReadMetaText(fullPath + ".info").trimmed();
        if (origPath.isEmpty()) origPath = "-";

        QFileInfo fi(fullPath);
        const qint64 sizeBytes = fi.size();
        QString sizeText;
        if (sizeBytes < 1024) sizeText = QString::number(sizeBytes) + " B";
        else if (sizeBytes < 1024 * 1024) sizeText = QString::number(sizeBytes / 1024.0, 'f', 1) + " KB";
        else sizeText = QString::number(sizeBytes / 1024.0 / 1024.0, 'f', 1) + " MB";
        const QString timeText = fi.lastModified().toString("yyyy-MM-dd HH:mm:ss");

        int row = m_quarantineTable->rowCount();
        m_quarantineTable->insertRow(row);
        m_quarantineTable->setItem(row, 0, new QTableWidgetItem(fullPath));
        m_quarantineTable->setItem(row, 1, new QTableWidgetItem(sizeText));
        m_quarantineTable->setItem(row, 2, new QTableWidgetItem(timeText));
        m_quarantineTable->setItem(row, 3, new QTableWidgetItem(origPath));
    } while (FindNextFileW(hFind, &findData));
    FindClose(hFind);
}

// ── Tool: 勒索防护备份 (ZETA_DocBackup 文档备份 / ZETA_Quarantine 重定向副本) ──

// 索引/路径以 NT 格式存内核: \SystemRoot\... 或 \??\C:\... → 转成 UI 可用的 DOS 路径
static QString zetaNtToDos(const QString& p, const QString& winDir) {
    if (p.startsWith("\\SystemRoot", Qt::CaseInsensitive))
        return winDir + p.mid(11);               // 去掉 "\SystemRoot"
    if (p.startsWith("\\??\\"))
        return p.mid(4);
    return p;
}

// 文件保护专项规则文件路径 (与 Rules_Hips.json 同目录)
static QString zetaFileProtectRulesPath(const QString& hipsRulesPath) {
    QString p = hipsRulesPath;
    if (p.isEmpty())
        p = QCoreApplication::applicationDirPath() + "/Plugins/Rules/Rules_Hips.json";
    const int cut = qMax(p.lastIndexOf('/'), p.lastIndexOf('\\'));
    if (cut < 0) return QString();
    return p.left(cut + 1) + "Rules_FileProtect.json";
}

// 读 Rule_File_DocBackup_Extensions (空列表 = 驱动回退内置默认表)
static QStringList zetaLoadDocBackupExts(const QString& path) {
    QStringList out;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return out;
    QJsonParseError err;
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &err);
    f.close();
    if (err.error != QJsonParseError::NoError) return out;
    for (const QJsonValue& v : doc.object().value("Rule_File_DocBackup_Extensions").toArray()) {
        const QString s = v.toString().trimmed();
        if (!s.isEmpty()) out << s;
    }
    return out;
}

// 写回扩展名列表 (保留文件内其它键/注释键), 返回是否成功
static bool zetaSaveDocBackupExts(const QString& path, const QStringList& exts) {
    QJsonObject root;
    {
        QFile in(path);
        if (in.open(QIODevice::ReadOnly)) {
            QJsonParseError err;
            const QJsonDocument doc = QJsonDocument::fromJson(in.readAll(), &err);
            in.close();
            if (err.error == QJsonParseError::NoError) root = doc.object();
        }
    }
    if (root.isEmpty()) {
        root["//"] = QString::fromUtf8("ZETA 文件保护专项规则 (驱动文档写前备份使用)。");
        root["//2"] = QString::fromUtf8("条目一律 '.小写扩展名' 格式; 本文件缺失时驱动回退内置默认表。");
    }
    QJsonArray arr;
    for (const QString& e : exts) arr.append(e);
    root["Rule_File_DocBackup_Extensions"] = arr;

    QFile out(path);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    out.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    out.close();
    return true;
}

// "doc, .XLS  *.pdf" → [".doc", ".xls", ".pdf"] (统一小写、补 '.' 前缀)
static QStringList zetaNormalizeExts(const QString& text) {
    QStringList out;
    const QStringList parts = text.split(QRegularExpression("[\\s,;，；]+"), Qt::SkipEmptyParts);
    for (QString s : parts) {
        s = s.trimmed().toLower();
        while (s.startsWith("*.") || s.startsWith("*")) s.remove(0, 1);
        if (s.isEmpty()) continue;
        if (!s.startsWith('.')) s.prepend('.');
        if (s.size() < 2) continue;                  // 只有 '.' 的条目无意义
        if (!out.contains(s)) out << s;
    }
    return out;
}

static QString zetaFormatSize(qint64 bytes) {
    if (bytes < 1024) return QString::number(bytes) + " B";
    if (bytes < 1024 * 1024) return QString::number(bytes / 1024.0, 'f', 1) + " KB";
    if (bytes < 1024LL * 1024 * 1024) return QString::number(bytes / 1024.0 / 1024.0, 'f', 1) + " MB";
    return QString::number(bytes / 1024.0 / 1024.0 / 1024.0, 'f', 2) + " GB";
}

void MainWindow::setupRansomRestoreManager(QWidget* page) {
    auto* l = new QVBoxLayout(page);
    l->setContentsMargins(0, 0, 0, 0);
    l->setSpacing(8);

    // ── 概览条: 备份数量 / 占用 / 最近备份时间 / 异常项 ──
    m_ransomStatLabel = new QLabel(QString::fromUtf8("正在统计…"));
    m_ransomStatLabel->setObjectName("secLabel");
    m_ransomStatLabel->setWordWrap(true);
    l->addWidget(m_ransomStatLabel);

    auto* ctrl = new QHBoxLayout();
    auto* refreshBtn = new QPushButton("刷新");
    refreshBtn->setObjectName("actionBtn");
    refreshBtn->setCursor(Qt::PointingHandCursor);
    connect(refreshBtn, &QPushButton::clicked, this, &MainWindow::onRefreshRansom);
    ctrl->addWidget(refreshBtn);

    auto* restoreBtn = new QPushButton("恢复到原路径");
    restoreBtn->setObjectName("actionBtn");
    restoreBtn->setCursor(Qt::PointingHandCursor);
    connect(restoreBtn, &QPushButton::clicked, this, [this]() {
        auto sel = m_ransomTable->selectedItems();
        if (sel.isEmpty()) return;
        int row = sel[0]->row();
        QString dest = m_ransomTable->item(row, 1)->text();
        QString orig = m_ransomTable->item(row, 2)->text();
        if (orig.isEmpty() || orig == "-") {
            onAppendLog("WARN", "勒索恢复", "无法恢复：原路径未知");
            return;
        }
        // 确认: 会覆盖原路径当前内容 (可能已是勒索加密后的文件)
        if (QMessageBox::question(this, "勒索恢复",
                QString::fromUtf8("确定将备份恢复到：\n") + orig +
                QString::fromUtf8("\n\n若该位置当前已有文件将被覆盖。"),
                QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) {
            return;
        }
        int lastSlash = orig.lastIndexOf('\\');
        if (lastSlash > 0) QDir().mkpath(orig.left(lastSlash));
        if (CopyFileW((const wchar_t*)dest.utf16(), (const wchar_t*)orig.utf16(), FALSE)) {
            zetaDeleteToRecycleBin(dest);   // M2-4: 走回收站（原 DeleteFileW 为永久删除; 本条是自动清理, 最不该绕过回收站）
            onRefreshRansom();
            onAppendLog("INFO", "勒索恢复", "已恢复到原路径: " + orig);
        } else {
            DWORD err = GetLastError();
            onAppendLog("ERROR", "勒索恢复", "恢复失败 错误码 " + QString::number(err) + " -> " + orig);
        }
    });
    ctrl->addWidget(restoreBtn);

    auto* saveAsBtn = new QPushButton("另存为…");
    saveAsBtn->setObjectName("actionBtn");
    saveAsBtn->setCursor(Qt::PointingHandCursor);
    connect(saveAsBtn, &QPushButton::clicked, this, [this]() {
        auto sel = m_ransomTable->selectedItems();
        if (sel.isEmpty()) return;
        int row = sel[0]->row();
        const QString dest = m_ransomTable->item(row, 1)->text();
        QString orig = m_ransomTable->item(row, 2)->text();
        QString suggest = orig.section('\\', -1);        // 原文件名
        if (suggest.isEmpty() || suggest == "-") suggest = "restored_file";
        const QString target = QFileDialog::getSaveFileName(this,
            QString::fromUtf8("备份另存为"), QDir::homePath() + "/" + suggest);
        if (target.isEmpty()) return;
        if (CopyFileW((const wchar_t*)dest.utf16(), (const wchar_t*)target.utf16(), FALSE)) {
            onAppendLog("INFO", "勒索防护备份", "副本已另存为: " + target);
        } else {
            onAppendLog("ERROR", "勒索防护备份",
                "另存失败 错误码 " + QString::number(GetLastError()));
        }
    });
    ctrl->addWidget(saveAsBtn);

    auto* openBtn = new QPushButton("打开所在目录");
    openBtn->setObjectName("actionBtn");
    openBtn->setCursor(Qt::PointingHandCursor);
    connect(openBtn, &QPushButton::clicked, this, [this]() {
        auto sel = m_ransomTable->selectedItems();
        if (sel.isEmpty()) return;
        QString dest = m_ransomTable->item(sel[0]->row(), 1)->text();
        ShellExecuteW(nullptr, L"open", L"explorer.exe",
            (std::wstring(L"/select,\"") + std::wstring((const wchar_t*)dest.utf16()) + L"\"").c_str(),
            nullptr, SW_SHOWNORMAL);
    });
    ctrl->addWidget(openBtn);

    auto* deleteBtn = new QPushButton("删除副本");
    deleteBtn->setObjectName("actionBtn");
    deleteBtn->setProperty("danger", true);
    deleteBtn->setCursor(Qt::PointingHandCursor);
    connect(deleteBtn, &QPushButton::clicked, this, [this]() {
        auto sel = m_ransomTable->selectedItems();
        if (sel.isEmpty()) return;
        QString dest = m_ransomTable->item(sel[0]->row(), 1)->text();
        if (zetaDeleteToRecycleBin(dest)) {   // M2-4: 走回收站
            onRefreshRansom();
            onAppendLog("INFO", "勒索防护备份", "已删除备份副本: " + dest);
        } else {
            onAppendLog("ERROR", "勒索防护备份",
                "删除失败 错误码 " + QString::number(GetLastError()));
        }
    });
    ctrl->addWidget(deleteBtn);

    auto* clearBtn = new QPushButton("清空备份");
    clearBtn->setObjectName("actionBtn");
    clearBtn->setProperty("danger", true);
    clearBtn->setCursor(Qt::PointingHandCursor);
    connect(clearBtn, &QPushButton::clicked, this, [this]() {
        if (m_ransomTable->rowCount() == 0) return;
        if (QMessageBox::question(this, QString::fromUtf8("清空备份"),
                QString::fromUtf8("将删除全部 ") + QString::number(m_ransomTable->rowCount()) +
                QString::fromUtf8(" 个备份副本移入回收站（可从回收站恢复），原路径文件不受影响，是否继续？"),
                QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) {
            return;
        }
        int ok = 0, fail = 0;
        for (int row = 0; row < m_ransomTable->rowCount(); row++) {
            const QString dest = m_ransomTable->item(row, 1)->text();
            if (dest.isEmpty()) continue;
            if (zetaDeleteToRecycleBin(dest)) ok++; else fail++;   // M2-4: 走回收站
        }
        onRefreshRansom();
        onAppendLog(fail ? "WARN" : "INFO", "勒索防护备份",
            QString::fromUtf8("清空备份完成: 成功 %1 个, 失败 %2 个")
                .arg(ok).arg(fail));
    });
    ctrl->addWidget(clearBtn);

    ctrl->addStretch();
    l->addLayout(ctrl);

    m_ransomTable = new QTableWidget();
    m_ransomTable->setColumnCount(7);
    m_ransomTable->setHorizontalHeaderLabels(
        {"类型", "备份/副本", "原路径", "PID", "大小", "备份时间", "状态"});
    m_ransomTable->horizontalHeader()->setStretchLastSection(false);
    m_ransomTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_ransomTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_ransomTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_ransomTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_ransomTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    m_ransomTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    m_ransomTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    m_ransomTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_ransomTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_ransomTable->verticalHeader()->setVisible(false);
    l->addWidget(m_ransomTable, 1);

    // ── 备份策略 (开关 + 备份扩展名规则) ──
    auto* policy = new QGroupBox(QString::fromUtf8("备份策略"));
    auto* pl = new QVBoxLayout(policy);
    pl->setContentsMargins(14, 12, 14, 12);
    pl->setSpacing(10);

    pl->addWidget(createSwitchCard("文档写前备份",
        "文档/图片被覆盖写前自动留存旧版副本（抗勒索）", "doc_backup_switch"));

    auto* extRow = new QHBoxLayout();
    auto* extLabel = new QLabel(QString::fromUtf8("备份扩展名"));
    extLabel->setObjectName("secLabel");
    extRow->addWidget(extLabel);
    m_docBackupExtEdit = new QLineEdit();
    m_docBackupExtEdit->setPlaceholderText(
        QString::fromUtf8(".doc .docx .xlsx .pdf …（空格分隔，可留空表示使用内置默认表）"));
    extRow->addWidget(m_docBackupExtEdit, 1);

    auto* saveExtBtn = new QPushButton("保存规则");
    saveExtBtn->setObjectName("actionBtn");
    saveExtBtn->setCursor(Qt::PointingHandCursor);
    connect(saveExtBtn, &QPushButton::clicked, this, [this]() {
        const QString path = zetaFileProtectRulesPath(m_rulesPath);
        if (path.isEmpty()) {
            onAppendLog("ERROR", "勒索防护备份", "未找到规则目录，无法保存备份扩展名");
            return;
        }
        const QStringList exts = zetaNormalizeExts(m_docBackupExtEdit->text());
        if (!zetaSaveDocBackupExts(path, exts)) {
            onAppendLog("ERROR", "勒索防护备份", "写入失败（权限不足？）: " + path);
            return;
        }
        // 立即让驱动重载规则文件 (LoadRulesFromDisk 会重新解析 Rules_FileProtect.json)
        Bridge::instance()->invokeToolCallback("hips_reload");
        m_docBackupExtEdit->setText(exts.join(' '));
        onAppendLog("INFO", "勒索防护备份",
            QString::fromUtf8("%1 项备份扩展名已生效: %2")
                .arg(exts.size()).arg(exts.join(' ')));
    });
    extRow->addWidget(saveExtBtn);

    auto* openExtBtn = new QPushButton("打开规则文件");
    openExtBtn->setObjectName("actionBtn");
    openExtBtn->setCursor(Qt::PointingHandCursor);
    connect(openExtBtn, &QPushButton::clicked, this, [this]() {
        const QString path = zetaFileProtectRulesPath(m_rulesPath);
        if (!path.isEmpty()) QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    });
    extRow->addWidget(openExtBtn);
    pl->addLayout(extRow);

    auto* hint = new QLabel(QString::fromUtf8(
        "命中扩展名的文件在「被覆盖写 / 改名覆盖」前会先留存旧版副本；"
        "备份保存在 %SystemRoot%\\ZETA_DocBackup，仅本程序与 SYSTEM 可删除。"));
    hint->setObjectName("secLabel");
    hint->setWordWrap(true);
    pl->addWidget(hint);
    l->addWidget(policy);
}

// ── M2-4: 备份区滚动清理（用户态，全部走回收站）────────────────────────────
// 规则:
//   1) 同一"原文件"最多保留 keepVersions 个版本（默认 2），更旧的移入回收站
//   2) 备份区总容量上限 maxBytes（默认 10 GB），超限时按最旧优先移入回收站
// 命名格式（驱动侧 DocBackup_CopyFileToVault / ZetaVault_AppendIndex 约定）:
//   doc_<pid>_<tick>_<原名>    /    ransom_<pid>_<tick>_<原名>
// 删除统一走 zetaDeleteToRecycleBin（SHFileOperationW + FOF_ALLOWUNDO）。
// 返回被清理的条目数；report 非空时写一行人类可读摘要。
static const qint64 kZetaVaultMaxBytes = 10LL * 1024 * 1024 * 1024;   // 10 GB
static const int    kZetaVaultKeepVersions = 2;

static int zetaVaultEnforceQuota(const QString& vaultDir, qint64 maxBytes,
                                 int keepVersions, QString* report) {
    QDir dir(vaultDir);
    if (!dir.exists()) return 0;

    struct VEntry { QString path; QString orig; qint64 tick; qint64 size; };
    QVector<VEntry> entries;

    const QFileInfoList files = dir.entryInfoList(QDir::Files | QDir::NoDotAndDotDot);
    for (const QFileInfo& fi : files) {
        const QString name = fi.fileName();
        if (name.startsWith(QLatin1Char('.'))) continue;
        if (name.endsWith(QStringLiteral(".info"), Qt::CaseInsensitive)) continue;
        const QStringList parts = name.split(QLatin1Char('_'));
        if (parts.size() < 4) continue;
        bool ok = false;
        const qint64 tick = parts.at(2).toLongLong(&ok);
        if (!ok) continue;
        VEntry e;
        e.path = fi.absoluteFilePath();
        e.orig = parts.mid(3).join(QLatin1Char('_'));
        e.tick = tick;
        e.size = fi.size();
        entries.push_back(e);
    }
    if (entries.isEmpty()) return 0;

    QVector<bool> dropped(entries.size(), false);

    // 1) 同原名保留最近 keepVersions 个
    QHash<QString, QVector<int>> byOrig;
    for (int i = 0; i < entries.size(); ++i) byOrig[entries[i].orig].push_back(i);
    for (auto it = byOrig.begin(); it != byOrig.end(); ++it) {
        QVector<int>& idx = it.value();
        std::sort(idx.begin(), idx.end(),
                  [&](int a, int b) { return entries[a].tick > entries[b].tick; });
        for (int k = keepVersions; k < idx.size(); ++k) dropped[idx[k]] = true;
    }

    // 2) 容量上限：剩余项按最旧优先淘汰
    qint64 remain = 0;
    for (int i = 0; i < entries.size(); ++i) if (!dropped[i]) remain += entries[i].size;
    if (maxBytes > 0 && remain > maxBytes) {
        QVector<int> alive;
        for (int i = 0; i < entries.size(); ++i) if (!dropped[i]) alive.push_back(i);
        std::sort(alive.begin(), alive.end(),
                  [&](int a, int b) { return entries[a].tick < entries[b].tick; });
        for (int idx : alive) {
            if (remain <= maxBytes) break;
            dropped[idx] = true;
            remain -= entries[idx].size;
        }
    }

    int removed = 0;
    qint64 freed = 0;
    for (int i = 0; i < entries.size(); ++i) {
        if (!dropped[i]) continue;
        if (zetaDeleteToRecycleBin(entries[i].path)) { removed++; freed += entries[i].size; }
    }

    if (report && removed > 0) {
        *report = QString::fromUtf8("备份区滚动清理 %1: 移入回收站 %2 个（约 %3 MB），上限 %4 MB / 同文件保留 %5 版")
                      .arg(vaultDir)
                      .arg(removed)
                      .arg(freed / 1048576.0, 0, 'f', 1)
                      .arg(maxBytes / 1048576.0, 0, 'f', 0)
                      .arg(keepVersions);
    }
    return removed;
}


void MainWindow::onRefreshRansom() {
    if (!m_ransomTable) return;
    m_ransomTable->setRowCount(0);

    wchar_t winBuf[MAX_PATH] = {0};
    if (GetWindowsDirectoryW(winBuf, MAX_PATH) == 0) return;
    const QString winDir = QString::fromWCharArray(winBuf);

    // M2-4: 刷新前先做一次滚动清理（容量上限 + 同文件保留 N 版），删除全部走回收站
    {
        const wchar_t* vaultDirs[] = { L"ZETA_DocBackup", L"ZETA_Quarantine" };
        for (const wchar_t* vd : vaultDirs) {
            QString rep;
            zetaVaultEnforceQuota(winDir + "\\" + QString::fromWCharArray(vd),
                                  kZetaVaultMaxBytes, kZetaVaultKeepVersions, &rep);
            if (!rep.isEmpty()) onAppendLog("INFO", "勒索防护备份", rep);
        }
    }

    struct VaultSpec { const wchar_t* dir; const wchar_t* kind; };
    const VaultSpec vaults[] = {
        { L"ZETA_DocBackup", L"文档备份" },     // doc_<pid>_<tick>_<原名>
        { L"ZETA_Quarantine", L"勒索重定向" },  // ransom_<pid>_<tick>_<原名>
    };

    int totalCount = 0;
    qint64 totalBytes = 0;
    int missingCount = 0;
    QDateTime latest;

    for (const auto& v : vaults) {
        const QString kind = QString::fromWCharArray(v.kind);
        const QString idxPath =
            winDir + "\\" + QString::fromWCharArray(v.dir) + "\\.ZETA_index";

        // 关键编码修复: 索引行由驱动 ZetaVault_AppendIndex 以 UTF-8 追加
        // (RtlUnicodeToUTF8N), 旧版本/旧索引可能是 UTF-16LE 无 BOM。
        // 之前这里按 UTF-16LE 硬解 → 新索引被按双字节切分, 中文路径乱码、
        // ASCII 路径也会读成垃圾导致条目全丢。现统一走自适应解码。
        const QString text = zetaReadMetaText(idxPath);
        if (text.isEmpty()) continue;

        const QStringList lines = text.split(QRegularExpression("[\r\n]+"), Qt::SkipEmptyParts);
        for (const QString& line : lines) {
            const QStringList f = line.split('\t');
            if (f.size() < 3) continue;
            const QString dest = zetaNtToDos(f.at(0).trimmed(), winDir);
            const QString pid  = f.at(1).trimmed();
            const QString orig = zetaNtToDos(f.at(2).trimmed(), winDir);
            if (dest.isEmpty() || orig.isEmpty()) continue;

            QFileInfo fi(dest);
            const bool exists = fi.exists();
            if (exists) {
                totalCount++;
                totalBytes += fi.size();
                if (!latest.isValid() || fi.lastModified() > latest) latest = fi.lastModified();
            } else {
                missingCount++;
            }

            const int row = m_ransomTable->rowCount();
            m_ransomTable->insertRow(row);
            m_ransomTable->setItem(row, 0, new QTableWidgetItem(kind));
            m_ransomTable->setItem(row, 1, new QTableWidgetItem(dest));
            m_ransomTable->setItem(row, 2, new QTableWidgetItem(orig));
            m_ransomTable->setItem(row, 3, new QTableWidgetItem(pid));
            m_ransomTable->setItem(row, 4,
                new QTableWidgetItem(exists ? zetaFormatSize(fi.size()) : QString::fromUtf8("-")));
            m_ransomTable->setItem(row, 5,
                new QTableWidgetItem(exists
                    ? fi.lastModified().toString("yyyy-MM-dd HH:mm:ss")
                    : QString::fromUtf8("-")));
            auto* stateItem = new QTableWidgetItem(
                exists ? QString::fromUtf8("可用") : QString::fromUtf8("副本已丢失"));
            if (!exists) stateItem->setForeground(QColor(0xD9, 0x53, 0x4F));
            m_ransomTable->setItem(row, 6, stateItem);
        }
    }

    // ── 概览条 ──
    if (m_ransomStatLabel) {
        QString s = QString::fromUtf8("可恢复备份 %1 个 · 占用 %2")
                        .arg(totalCount).arg(zetaFormatSize(totalBytes));
        s += latest.isValid()
            ? QString::fromUtf8(" · 最近备份 %1").arg(latest.toString("yyyy-MM-dd HH:mm:ss"))
            : QString::fromUtf8(" · 暂无备份");
        if (missingCount)
            s += QString::fromUtf8(" · %1 条记录副本已丢失").arg(missingCount);
        m_ransomStatLabel->setText(s);
    }

    // ── 回填备份扩展名规则 (与驱动实际加载的规则文件同源) ──
    if (m_docBackupExtEdit) {
        const QStringList exts = zetaLoadDocBackupExts(zetaFileProtectRulesPath(m_rulesPath));
        m_docBackupExtEdit->setText(exts.join(' '));
    }
}

// ── Event filter ───────────────────────────────────────────────

bool MainWindow::eventFilter(QObject* obj, QEvent* event) {
    if (event->type() == QEvent::MouseButtonRelease) {
        auto* frame = qobject_cast<QFrame*>(obj);
        if (frame) {
            // Check for in-page tool navigation (tools sub-pages)
            QVariant toolIdx = frame->property("toolIndex");
            if (toolIdx.isValid()) {
                showToolPage(toolIdx.toInt());
                return true;
            }
            // Check for in-page settings navigation (config sub-pages)
            QVariant setIdx = frame->property("settingsIndex");
            if (setIdx.isValid()) {
                showSettingsPage(setIdx.toInt());
                return true;
            }
            // Check for in-page EDR navigation (EDR 三个配置子页)
            QVariant edrIdx = frame->property("edrIndex");
            if (edrIdx.isValid()) {
                showEdrPage(edrIdx.toInt());
                return true;
            }
            // Check for cross-page navigation (跳转到一级页面, 如 EDR)
            QVariant navIdx = frame->property("navIndex");
            if (navIdx.isValid()) {
                int idx = navIdx.toInt();
                m_stack->setCurrentIndex(idx);
                if (m_navSidebar) m_navSidebar->setCurrentIndex(idx);
                if (idx == PAGE_EDR) onRefreshEdrRules();
                return true;
            }
            // Check for old-style tool callback (Bridge -> main.cpp)
            QString toolName = frame->property("toolName").toString();
            if (!toolName.isEmpty()) {
                Bridge::instance()->invokeToolCallback(toolName);
                return true;
            }
        }
    }
    return QMainWindow::eventFilter(obj, event);
}

// ── System Tray ─────────────────────────────────────────────────

void MainWindow::setupTrayIcon() {
    if (!QSystemTrayIcon::isSystemTrayAvailable()) return;

    m_trayIcon = new QSystemTrayIcon(this);

    // Create a simple icon (16x16 colored pixmap since we can't rely on resource files)
    QPixmap pixmap(16, 16);
    pixmap.fill(QColor("#0a84ff"));
    m_trayIcon->setIcon(QIcon(pixmap));
    m_trayIcon->setToolTip("ZETA Security - 运行中");

    m_trayMenu = new QMenu(this);
    auto* showAction = m_trayMenu->addAction("显示窗口");
    connect(showAction, &QAction::triggered, this, [this]() {
        showNormal();
        activateWindow();
        raise();
    });

    auto* hideAction = m_trayMenu->addAction("隐藏到托盘");
    connect(hideAction, &QAction::triggered, this, &QWidget::hide);

    m_trayMenu->addSeparator();

    auto* quitAction = m_trayMenu->addAction("退出");
    connect(quitAction, &QAction::triggered, this, [this]() {
        // (traffic timer removed)
        QApplication::quit();
    });

    m_trayIcon->setContextMenu(m_trayMenu);

    connect(m_trayIcon, &QSystemTrayIcon::activated, this, [this](QSystemTrayIcon::ActivationReason reason) {
        if (reason == QSystemTrayIcon::DoubleClick) {
            showNormal();
            activateWindow();
            raise();
        }
    });

    m_trayIcon->show();
}

// ── Window dragging ────────────────────────────────────────────

void MainWindow::mousePressEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton && m_titleBar &&
        m_titleBar->geometry().contains(event->pos())) {
        m_dragging = true;
        m_dragPos = event->globalPos() - frameGeometry().topLeft();
        event->accept();
    }
}

void MainWindow::mouseMoveEvent(QMouseEvent* event) {
    if (m_dragging && event->buttons() == Qt::LeftButton) {
        move(event->globalPos() - m_dragPos);
        event->accept();
    }
}

void MainWindow::mouseReleaseEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) { m_dragging = false; event->accept(); }
}

void MainWindow::closeEvent(QCloseEvent* event) {
    // Minimize to tray instead of closing
    if (m_trayIcon && m_trayIcon->isVisible()) {
        hide();
        m_trayIcon->showMessage("ZETA Security", "程序已最小化到系统托盘，双击可恢复窗口",
                                QSystemTrayIcon::Information, 2000);
    } else {
        hide();
    }
    event->ignore();
}

void MainWindow::resizeEvent(QResizeEvent* event) {
    QMainWindow::resizeEvent(event);
    // 强制窗口轮廓为圆角矩形 (Frameless + Translucent 下 QSS border-radius 不可靠)
    const int radius = 12;
    QPainterPath path;
    path.addRoundedRect(rect(), radius, radius);
    setMask(QRegion(path.toFillPolygon().toPolygon()));
}

// ── Tool: EDR Manager ───────────────────────────────────────────

// EDR 子页通用外壳: QScrollArea 占满整页 (滚动区域最大化, 告别 tab 内嵌小滚动)
static QVBoxLayout* makeEdrScrollPage(QWidget* page) {
    auto* outer = new QVBoxLayout(page);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->setSpacing(0);

    auto* scroll = new QScrollArea();
    scroll->setWidgetResizable(true);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setStyleSheet("QScrollArea { background: transparent; border: none; }");
    auto* content = new QWidget();
    content->setStyleSheet("background: transparent;");
    scroll->setWidget(content);
    outer->addWidget(scroll);

    auto* cl = new QVBoxLayout(content);
    cl->setContentsMargins(6, 4, 16, 4);
    cl->setSpacing(20);
    return cl;
}

// ── EDR: 入口页 + 三个独立配置子页 ─────────────────────────────
void MainWindow::setupEdrManager(QWidget* page) {
    auto* l = new QVBoxLayout(page);
    l->setContentsMargins(0, 0, 0, 0);
    l->setSpacing(0);

    // 返回按钮 (仅子页可见)
    auto* topBar = new QHBoxLayout();
    topBar->setContentsMargins(28, 4, 28, 4);
    m_edrBackBtn = new QPushButton(QString::fromUtf8("\u2190 返回"));
    m_edrBackBtn->setObjectName("ghostBtn");
    m_edrBackBtn->setCursor(Qt::PointingHandCursor);
    m_edrBackBtn->setVisible(false);
    connect(m_edrBackBtn, &QPushButton::clicked, this, &MainWindow::showEdrList);
    topBar->addWidget(m_edrBackBtn);
    topBar->addStretch();
    l->addLayout(topBar);

    m_edrStack = new QStackedWidget();
    m_edrStack->setObjectName("contentPanel");
    m_edrStack->setContentsMargins(12, 12, 12, 12);

    // index 0: 入口页
    {
        auto* listPage = new QWidget();
        auto* listL = new QVBoxLayout(listPage);
        listL->setContentsMargins(0, 0, 0, 0);
        listL->setSpacing(0);
        auto* grid = new QGridLayout();
        grid->setContentsMargins(0, 6, 0, 0);
        grid->setSpacing(14);
        grid->addWidget(createNavCard("扫描引擎", "扫描开关与 YARA 规则路径",
                                      "edrIndex", EDR_SCAN_ENGINE), 0, 0);
        grid->addWidget(createNavCard("评分权重", "各项检测评分权重与告警阈值",
                                      "edrIndex", EDR_SCORE), 0, 1);
        grid->addWidget(createNavCard("API 列表", "危险 / 高危 API 清单",
                                      "edrIndex", EDR_API), 1, 0);
        grid->addWidget(createNavCard("节名列表", "可疑 PE 节名清单",
                                      "edrIndex", EDR_SECTION), 1, 1);
        grid->addWidget(createNavCard("可信发布者", "签名验证直接放行的发布者",
                                      "edrIndex", EDR_TRUSTED), 2, 0);
        grid->addWidget(createNavCard("扩展名", "需要签名验证的文件扩展名",
                                      "edrIndex", EDR_EXT), 2, 1);
        listL->addLayout(grid);
        listL->addStretch();
        m_edrStack->addWidget(listPage);
    }

    // index 1-6: 每个功能一个独立页面
    for (int i = 0; i < 6; i++) {
        auto* p = new QWidget();
        p->setObjectName("contentPanel");
        m_edrStack->addWidget(p);
    }
    setupEdrScanEnginePage(m_edrStack->widget(EDR_SCAN_ENGINE));
    setupEdrScorePage(m_edrStack->widget(EDR_SCORE));
    setupEdrApiPage(m_edrStack->widget(EDR_API));
    setupEdrSectionPage(m_edrStack->widget(EDR_SECTION));
    setupEdrTrustedPage(m_edrStack->widget(EDR_TRUSTED));
    setupEdrExtPage(m_edrStack->widget(EDR_EXT));

    l->addWidget(m_edrStack, 1);
}

void MainWindow::showEdrList() {
    m_edrStack->setCurrentIndex(EDR_LIST);
    m_edrBackBtn->setVisible(false);
    if (m_edrPageTitle) m_edrPageTitle->setText("EDR 规则");
}

void MainWindow::showEdrPage(int index) {
    if (index < 1 || index > 6) return;
    m_edrStack->setCurrentIndex(index);
    m_edrBackBtn->setVisible(true);
    const char* titles[] = {"EDR · 扫描引擎", "EDR · 评分权重", "EDR · API 列表",
                            "EDR · 节名列表", "EDR · 可信发布者", "EDR · 扩展名"};
    if (m_edrPageTitle) m_edrPageTitle->setText(titles[index - 1]);
}

// ────── EDR 子页 1: 扫描引擎 (开关 + YARA 路径) ──────
void MainWindow::setupEdrScanEnginePage(QWidget* page) {
    auto* t1L = makeEdrScrollPage(page);

    auto* scanGroup = new QGroupBox("扫描引擎开关");
    scanGroup->setObjectName("configGroup");
    auto* scanL = new QGridLayout(scanGroup);
    scanL->setSpacing(20);
    scanL->setContentsMargins(20, 16, 20, 16);
    m_chkEnableYara = new QCheckBox("启用 YARA 扫描");
    m_chkEnableYara->setObjectName("configCheckBox");
    scanL->addWidget(m_chkEnableYara, 0, 0);
    m_chkEnablePeHeuristics = new QCheckBox("启用 PE 启发式分析");
    m_chkEnablePeHeuristics->setObjectName("configCheckBox");
    scanL->addWidget(m_chkEnablePeHeuristics, 0, 1);
    m_chkEnableSignature = new QCheckBox("启用签名验证");
    m_chkEnableSignature->setObjectName("configCheckBox");
    scanL->addWidget(m_chkEnableSignature, 1, 0);
    t1L->addWidget(scanGroup);

    auto* yaraGroup = new QGroupBox("YARA 规则路径");
    yaraGroup->setObjectName("configGroup");
    auto* yaraL = new QVBoxLayout(yaraGroup);
    yaraL->setContentsMargins(20, 18, 20, 18);
    yaraL->setSpacing(12);
    auto* yaraDesc = new QLabel("多个路径用分号分隔，支持通配符");
    yaraDesc->setObjectName("secLabel");
    yaraL->addWidget(yaraDesc);
    m_edrYaraPathEdit = new QLineEdit();
    m_edrYaraPathEdit->setPlaceholderText("如: Plugins/Rules/YARA/*.yar");
    m_edrYaraPathEdit->setMinimumHeight(36);
    yaraL->addWidget(m_edrYaraPathEdit);
    t1L->addWidget(yaraGroup);
    t1L->addStretch();
}

// ────── EDR 子页 2: 评分权重 (双列网格 + 阈值) ──────
void MainWindow::setupEdrScorePage(QWidget* page) {
    auto* t1L = makeEdrScrollPage(page);

    auto* scoreGroup = new QGroupBox("评分权重配置");
    scoreGroup->setObjectName("configGroup");
    auto* scoreL = new QVBoxLayout(scoreGroup);
    scoreL->setSpacing(0);
    scoreL->setContentsMargins(0, 0, 0, 0);

    auto* scoreGrid = new QGridLayout();
    scoreGrid->setContentsMargins(12, 12, 12, 12);
    scoreGrid->setSpacing(12);

    auto addScoreRow = [&](const QString& label, QSpinBox*& spin, int val, int row, int col) {
        auto* item = new QFrame();
        item->setObjectName("listItem");
        item->setFrameShape(QFrame::NoFrame);
        auto* rowL = new QHBoxLayout(item);
        rowL->setContentsMargins(16, 12, 16, 12);
        rowL->setSpacing(16);
        auto* lbl = new QLabel(label);
        lbl->setObjectName("titleLabel");
        lbl->setStyleSheet("font-size: 14px;");
        rowL->addWidget(lbl);
        rowL->addStretch();
        auto* valueL = new QHBoxLayout();
        valueL->setSpacing(8);
        spin = new QSpinBox();
        spin->setRange(0, 200);
        spin->setValue(val);
        spin->setFixedWidth(90);
        spin->setMinimumHeight(32);
        valueL->addWidget(spin);
        auto* unit = new QLabel("分");
        unit->setObjectName("secLabel");
        valueL->addWidget(unit);
        rowL->addLayout(valueL);
        scoreGrid->addWidget(item, row, col);
    };

    addScoreRow("危险API调用",  m_spinSuspiciousApi,     15,  0, 0);
    addScoreRow("高危API调用",  m_spinHighRiskApi,       30,  0, 1);
    addScoreRow("可疑节名",     m_spinSuspiciousSection, 30,  1, 0);
    addScoreRow("RWX内存节",    m_spinRwxSection,        20,  1, 1);
    addScoreRow("高熵压缩",     m_spinHighEntropy,       25,  2, 0);
    addScoreRow("无入口点",     m_spinNoEntryPoint,      10,  2, 1);
    addScoreRow("未签名",       m_spinUnsigned,          20,  3, 0);
    addScoreRow("YARA规则匹配", m_spinYaraMatch,        100,  3, 1);

    auto* sepLine = new QFrame();
    sepLine->setFrameShape(QFrame::HLine);
    sepLine->setFrameShadow(QFrame::Sunken);
    sepLine->setStyleSheet("QFrame { color: rgba(42,42,74,0.6); }");
    scoreGrid->addWidget(sepLine, 4, 0, 1, 2);

    addScoreRow("威胁告警阈值", m_spinThreatThreshold,     50, 5, 0);
    addScoreRow("高危拦截阈值", m_spinHighThreatThreshold, 70, 5, 1);

    scoreL->addLayout(scoreGrid);
    t1L->addWidget(scoreGroup);
    t1L->addStretch();
}

// ────── EDR 子页 3: API 列表 (整页表格, 滚动交给表格本身) ──────
void MainWindow::setupEdrApiPage(QWidget* page) {
    auto* t2L = new QVBoxLayout(page);
    t2L->setContentsMargins(0, 0, 0, 0);
    t2L->setSpacing(0);

    auto* apiGroup = new QGroupBox("危险 / 高危 API 列表");
    apiGroup->setObjectName("configGroup");
    auto* apiL = new QVBoxLayout(apiGroup);
    apiL->setContentsMargins(0, 0, 0, 0);
    apiL->setSpacing(0);
    
    auto* apiCtrl = new QHBoxLayout();
    apiCtrl->setContentsMargins(20, 16, 20, 12);
    apiCtrl->setSpacing(12);
    m_edrApiEdit = new QLineEdit();
    m_edrApiEdit->setPlaceholderText("输入API名称，如 VirtualAlloc");
    m_edrApiEdit->setMinimumHeight(34);
    apiCtrl->addWidget(m_edrApiEdit, 1);
    auto* apiTypeCombo = new QComboBox();
    apiTypeCombo->addItems({"危险", "高危"});
    apiTypeCombo->setMinimumHeight(34);
    apiCtrl->addWidget(apiTypeCombo);
    auto* addApiBtn = new QPushButton("添加");
    addApiBtn->setObjectName("actionBtn");
    addApiBtn->setCursor(Qt::PointingHandCursor);
    connect(addApiBtn, &QPushButton::clicked, this, [this, apiTypeCombo]() {
        QString api = m_edrApiEdit->text().trimmed();
        if (!api.isEmpty()) {
            int row = m_edrApiTable->rowCount();
            m_edrApiTable->insertRow(row);
            m_edrApiTable->setItem(row, 0, new QTableWidgetItem(api));
            m_edrApiTable->setItem(row, 1, new QTableWidgetItem(apiTypeCombo->currentText()));
            m_edrApiEdit->clear();
        }
    });
    apiCtrl->addWidget(addApiBtn);
    auto* removeApiBtn = new QPushButton("移除");
    removeApiBtn->setObjectName("actionBtn");
    removeApiBtn->setProperty("danger", true);
    removeApiBtn->setCursor(Qt::PointingHandCursor);
    connect(removeApiBtn, &QPushButton::clicked, this, [this]() {
        auto sel = m_edrApiTable->selectedItems();
        if (!sel.isEmpty()) m_edrApiTable->removeRow(sel[0]->row());
    });
    apiCtrl->addWidget(removeApiBtn);
    apiL->addLayout(apiCtrl);
    
    m_edrApiTable = new QTableWidget();
    m_edrApiTable->setColumnCount(2);
    m_edrApiTable->setHorizontalHeaderLabels({"API名称", "风险等级"});
    m_edrApiTable->horizontalHeader()->setStretchLastSection(true);
    m_edrApiTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_edrApiTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_edrApiTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_edrApiTable->verticalHeader()->setVisible(false);
    m_edrApiTable->setMinimumHeight(180);
    // 不设 maximumHeight: 表格拉伸占满整页, 一屏能看几十行
    apiL->addWidget(m_edrApiTable, 1);
    t2L->addWidget(apiGroup, 1);
}

// ────── EDR 子页 4: 节名列表 (整页表格) ──────
void MainWindow::setupEdrSectionPage(QWidget* page) {
    auto* t2L = new QVBoxLayout(page);
    t2L->setContentsMargins(0, 0, 0, 0);
    t2L->setSpacing(0);

    auto* sectionGroup = new QGroupBox("可疑节名列表");
    sectionGroup->setObjectName("configGroup");
    auto* sectionL = new QVBoxLayout(sectionGroup);
    sectionL->setContentsMargins(0, 0, 0, 0);
    sectionL->setSpacing(0);

    auto* sectionCtrl = new QHBoxLayout();
    sectionCtrl->setContentsMargins(20, 16, 20, 12);
    sectionCtrl->setSpacing(12);
    m_edrSectionEdit = new QLineEdit();
    m_edrSectionEdit->setPlaceholderText("输入节名，如 .upx");
    m_edrSectionEdit->setMinimumHeight(34);
    sectionCtrl->addWidget(m_edrSectionEdit, 1);
    auto* addSectionBtn = new QPushButton("添加");
    addSectionBtn->setObjectName("actionBtn");
    addSectionBtn->setCursor(Qt::PointingHandCursor);
    connect(addSectionBtn, &QPushButton::clicked, this, [this]() {
        QString sec = m_edrSectionEdit->text().trimmed();
        if (!sec.isEmpty()) {
            int row = m_edrSectionTable->rowCount();
            m_edrSectionTable->insertRow(row);
            m_edrSectionTable->setItem(row, 0, new QTableWidgetItem(sec));
            m_edrSectionEdit->clear();
        }
    });
    sectionCtrl->addWidget(addSectionBtn);
    auto* removeSectionBtn = new QPushButton("移除");
    removeSectionBtn->setObjectName("actionBtn");
    removeSectionBtn->setProperty("danger", true);
    removeSectionBtn->setCursor(Qt::PointingHandCursor);
    connect(removeSectionBtn, &QPushButton::clicked, this, [this]() {
        auto sel = m_edrSectionTable->selectedItems();
        if (!sel.isEmpty()) m_edrSectionTable->removeRow(sel[0]->row());
    });
    sectionCtrl->addWidget(removeSectionBtn);
    sectionL->addLayout(sectionCtrl);
    
    m_edrSectionTable = new QTableWidget();
    m_edrSectionTable->setColumnCount(1);
    m_edrSectionTable->setHorizontalHeaderLabels({"节名"});
    m_edrSectionTable->horizontalHeader()->setStretchLastSection(true);
    m_edrSectionTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_edrSectionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_edrSectionTable->verticalHeader()->setVisible(false);
    m_edrSectionTable->setMinimumHeight(180);
    sectionL->addWidget(m_edrSectionTable, 1);
    t2L->addWidget(sectionGroup, 1);
}

// ────── EDR 子页 5: 可信发布者 (整页表格) ──────
void MainWindow::setupEdrTrustedPage(QWidget* page) {
    auto* t3L = new QVBoxLayout(page);
    t3L->setContentsMargins(0, 0, 0, 0);
    t3L->setSpacing(0);

    auto* trustedGroup = new QGroupBox("可信发布者白名单");
    trustedGroup->setObjectName("configGroup");
    auto* trustedL = new QVBoxLayout(trustedGroup);
    trustedL->setContentsMargins(0, 0, 0, 0);
    trustedL->setSpacing(0);
    
    auto* trustedDesc = new QLabel("签名验证直接放行的发布者");
    trustedDesc->setObjectName("secLabel");
    trustedDesc->setStyleSheet("padding: 0 20px 8px;");
    trustedL->addWidget(trustedDesc);
    
    auto* trustedCtrl = new QHBoxLayout();
    trustedCtrl->setContentsMargins(20, 0, 20, 12);
    trustedCtrl->setSpacing(12);
    m_edrTrustedEdit = new QLineEdit();
    m_edrTrustedEdit->setPlaceholderText("如: Microsoft Corporation");
    m_edrTrustedEdit->setMinimumHeight(34);
    trustedCtrl->addWidget(m_edrTrustedEdit, 1);
    auto* addTrustedBtn = new QPushButton("添加");
    addTrustedBtn->setObjectName("actionBtn");
    addTrustedBtn->setCursor(Qt::PointingHandCursor);
    connect(addTrustedBtn, &QPushButton::clicked, this, [this]() {
        QString pub = m_edrTrustedEdit->text().trimmed();
        if (!pub.isEmpty()) {
            int row = m_edrTrustedTable->rowCount();
            m_edrTrustedTable->insertRow(row);
            m_edrTrustedTable->setItem(row, 0, new QTableWidgetItem(pub));
            m_edrTrustedEdit->clear();
        }
    });
    trustedCtrl->addWidget(addTrustedBtn);
    auto* removeTrustedBtn = new QPushButton("移除");
    removeTrustedBtn->setObjectName("actionBtn");
    removeTrustedBtn->setProperty("danger", true);
    removeTrustedBtn->setCursor(Qt::PointingHandCursor);
    connect(removeTrustedBtn, &QPushButton::clicked, this, [this]() {
        auto sel = m_edrTrustedTable->selectedItems();
        if (!sel.isEmpty()) m_edrTrustedTable->removeRow(sel[0]->row());
    });
    trustedCtrl->addWidget(removeTrustedBtn);
    trustedL->addLayout(trustedCtrl);
    
    m_edrTrustedTable = new QTableWidget();
    m_edrTrustedTable->setColumnCount(1);
    m_edrTrustedTable->setHorizontalHeaderLabels({"发布者名称"});
    m_edrTrustedTable->horizontalHeader()->setStretchLastSection(true);
    m_edrTrustedTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_edrTrustedTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_edrTrustedTable->verticalHeader()->setVisible(false);
    m_edrTrustedTable->setMinimumHeight(180);
    trustedL->addWidget(m_edrTrustedTable, 1);
    t3L->addWidget(trustedGroup, 1);
}

// ────── EDR 子页 6: 扩展名 (整页表格) ──────
void MainWindow::setupEdrExtPage(QWidget* page) {
    auto* t3L = new QVBoxLayout(page);
    t3L->setContentsMargins(0, 0, 0, 0);
    t3L->setSpacing(0);

    auto* extGroup = new QGroupBox("需要签名验证的扩展名");
    extGroup->setObjectName("configGroup");
    auto* extL = new QVBoxLayout(extGroup);
    extL->setContentsMargins(0, 0, 0, 0);
    extL->setSpacing(0);

    auto* extDesc = new QLabel("此类扩展名文件未签名将被扣分");
    extDesc->setObjectName("secLabel");
    extDesc->setStyleSheet("padding: 0 20px 8px;");
    extL->addWidget(extDesc);
    
    auto* extCtrl = new QHBoxLayout();
    extCtrl->setContentsMargins(20, 0, 20, 12);
    extCtrl->setSpacing(12);
    m_edrExtEdit = new QLineEdit();
    m_edrExtEdit->setPlaceholderText("如: .exe");
    m_edrExtEdit->setMinimumHeight(34);
    extCtrl->addWidget(m_edrExtEdit, 1);
    auto* addExtBtn = new QPushButton("添加");
    addExtBtn->setObjectName("actionBtn");
    addExtBtn->setCursor(Qt::PointingHandCursor);
    connect(addExtBtn, &QPushButton::clicked, this, [this]() {
        QString ext = m_edrExtEdit->text().trimmed();
        if (!ext.isEmpty()) {
            int row = m_edrRequiredExtTable->rowCount();
            m_edrRequiredExtTable->insertRow(row);
            m_edrRequiredExtTable->setItem(row, 0, new QTableWidgetItem(ext));
            m_edrExtEdit->clear();
        }
    });
    extCtrl->addWidget(addExtBtn);
    auto* removeExtBtn = new QPushButton("移除");
    removeExtBtn->setObjectName("actionBtn");
    removeExtBtn->setProperty("danger", true);
    removeExtBtn->setCursor(Qt::PointingHandCursor);
    connect(removeExtBtn, &QPushButton::clicked, this, [this]() {
        auto sel = m_edrRequiredExtTable->selectedItems();
        if (!sel.isEmpty()) m_edrRequiredExtTable->removeRow(sel[0]->row());
    });
    extCtrl->addWidget(removeExtBtn);
    extL->addLayout(extCtrl);
    
    m_edrRequiredExtTable = new QTableWidget();
    m_edrRequiredExtTable->setColumnCount(1);
    m_edrRequiredExtTable->setHorizontalHeaderLabels({"扩展名"});
    m_edrRequiredExtTable->horizontalHeader()->setStretchLastSection(true);
    m_edrRequiredExtTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_edrRequiredExtTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_edrRequiredExtTable->verticalHeader()->setVisible(false);
    m_edrRequiredExtTable->setMinimumHeight(180);
    extL->addWidget(m_edrRequiredExtTable, 1);
    t3L->addWidget(extGroup, 1);
}

void MainWindow::onRefreshEdrRules() {
    QString rulesPath = QCoreApplication::applicationDirPath() + "/Plugins/Rules/Rules_EDR.json";
    QFile file(rulesPath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        onAppendLog("WARN", "EDR配置", "配置文件不存在");
        return;
    }

    QByteArray data = file.readAll();
    file.close();

    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(data, &error);
    if (error.error != QJsonParseError::NoError) {
        onAppendLog("WARN", "EDR配置", "配置文件解析失败");
        return;
    }

    QJsonObject root = doc.object();

    // Load scan switches
    if (root.contains("Rule_Scanning_Enabled")) {
        QJsonObject enabled = root["Rule_Scanning_Enabled"].toObject();
        m_chkEnableYara->setChecked(enabled["enable_yara"].toBool(true));
        m_chkEnablePeHeuristics->setChecked(enabled["enable_pe_heuristics"].toBool(true));
        m_chkEnableSignature->setChecked(enabled["enable_signature_check"].toBool(true));
    }

    // Load scoring
    if (root.contains("Rule_Scoring")) {
        QJsonObject scoring = root["Rule_Scoring"].toObject();
        m_spinSuspiciousApi->setValue(scoring["suspicious_api_score"].toInt(15));
        m_spinHighRiskApi->setValue(scoring["high_risk_api_score"].toInt(30));
        m_spinSuspiciousSection->setValue(scoring["suspicious_section_score"].toInt(30));
        m_spinRwxSection->setValue(scoring["rwx_section_score"].toInt(20));
        m_spinHighEntropy->setValue(scoring["high_entropy_score"].toInt(25));
        m_spinNoEntryPoint->setValue(scoring["no_entry_point_score"].toInt(10));
        m_spinUnsigned->setValue(scoring["unsigned_score"].toInt(20));
        m_spinYaraMatch->setValue(scoring["yara_match_score"].toInt(100));
        m_spinThreatThreshold->setValue(scoring["threat_threshold"].toInt(50));
        m_spinHighThreatThreshold->setValue(scoring["high_threat_threshold"].toInt(70));
    }

    // Load suspicious APIs
    m_edrApiTable->setRowCount(0);
    if (root.contains("Rule_Pe_SuspiciousApis")) {
        QJsonArray apis = root["Rule_Pe_SuspiciousApis"].toArray();
        for (const QJsonValue& api : apis) {
            QString name = api.toString();
            if (!name.isEmpty() && !name.startsWith("//")) {
                int row = m_edrApiTable->rowCount();
                m_edrApiTable->insertRow(row);
                m_edrApiTable->setItem(row, 0, new QTableWidgetItem(name));
                m_edrApiTable->setItem(row, 1, new QTableWidgetItem("危险"));
            }
        }
    }

    // Load high-risk APIs
    if (root.contains("Rule_Pe_HighRiskApis")) {
        QJsonArray apis = root["Rule_Pe_HighRiskApis"].toArray();
        for (const QJsonValue& api : apis) {
            QString name = api.toString();
            if (!name.isEmpty() && !name.startsWith("//")) {
                int row = m_edrApiTable->rowCount();
                m_edrApiTable->insertRow(row);
                m_edrApiTable->setItem(row, 0, new QTableWidgetItem(name));
                m_edrApiTable->setItem(row, 1, new QTableWidgetItem("高危"));
            }
        }
    }

    // Load suspicious sections
    m_edrSectionTable->setRowCount(0);
    if (root.contains("Rule_Pe_SuspiciousSections")) {
        QJsonArray sections = root["Rule_Pe_SuspiciousSections"].toArray();
        for (const QJsonValue& sec : sections) {
            QString name = sec.toString();
            if (!name.isEmpty() && !name.startsWith("//")) {
                int row = m_edrSectionTable->rowCount();
                m_edrSectionTable->insertRow(row);
                m_edrSectionTable->setItem(row, 0, new QTableWidgetItem(name));
            }
        }
    }

    // Load YARA paths
    if (root.contains("Rule_Yara_Paths")) {
        QJsonArray paths = root["Rule_Yara_Paths"].toArray();
        QStringList pathList;
        for (const QJsonValue& p : paths) {
            QString path = p.toString();
            if (!path.isEmpty() && !path.startsWith("//")) {
                pathList.append(path);
            }
        }
        m_edrYaraPathEdit->setText(pathList.join(";"));
    }

    // Load trusted publishers
    m_edrTrustedTable->setRowCount(0);
    if (root.contains("Rule_Signature_TrustedPublishers")) {
        QJsonArray pubs = root["Rule_Signature_TrustedPublishers"].toArray();
        for (const QJsonValue& p : pubs) {
            QString name = p.toString();
            if (!name.isEmpty() && !name.startsWith("//")) {
                int row = m_edrTrustedTable->rowCount();
                m_edrTrustedTable->insertRow(row);
                m_edrTrustedTable->setItem(row, 0, new QTableWidgetItem(name));
            }
        }
    }

    // Load required extensions
    m_edrRequiredExtTable->setRowCount(0);
    if (root.contains("Rule_Signature_RequiredExtensions")) {
        QJsonArray exts = root["Rule_Signature_RequiredExtensions"].toArray();
        for (const QJsonValue& e : exts) {
            QString ext = e.toString();
            if (!ext.isEmpty() && !ext.startsWith("//")) {
                int row = m_edrRequiredExtTable->rowCount();
                m_edrRequiredExtTable->insertRow(row);
                m_edrRequiredExtTable->setItem(row, 0, new QTableWidgetItem(ext));
            }
        }
    }

    onAppendLog("INFO", "EDR配置", "已加载配置");
}

void MainWindow::onSaveEdrRules() {
    QString rulesPath = QCoreApplication::applicationDirPath() + "/Plugins/Rules/Rules_EDR.json";
    QFile file(rulesPath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        onAppendLog("ERROR", "EDR配置", "无法读取配置文件");
        return;
    }

    QByteArray data = file.readAll();
    file.close();

    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(data, &error);
    if (error.error != QJsonParseError::NoError) {
        onAppendLog("ERROR", "EDR配置", "配置文件解析失败");
        return;
    }

    QJsonObject root = doc.object();

    // Save scan switches
    QJsonObject enabled;
    enabled["enable_yara"] = m_chkEnableYara->isChecked();
    enabled["enable_pe_heuristics"] = m_chkEnablePeHeuristics->isChecked();
    enabled["enable_signature_check"] = m_chkEnableSignature->isChecked();
    root["Rule_Scanning_Enabled"] = enabled;

    // Save scoring
    QJsonObject scoring;
    scoring["suspicious_api_score"] = m_spinSuspiciousApi->value();
    scoring["high_risk_api_score"] = m_spinHighRiskApi->value();
    scoring["suspicious_section_score"] = m_spinSuspiciousSection->value();
    scoring["rwx_section_score"] = m_spinRwxSection->value();
    scoring["high_entropy_score"] = m_spinHighEntropy->value();
    scoring["no_entry_point_score"] = m_spinNoEntryPoint->value();
    scoring["unsigned_score"] = m_spinUnsigned->value();
    scoring["yara_match_score"] = m_spinYaraMatch->value();
    scoring["threat_threshold"] = m_spinThreatThreshold->value();
    scoring["high_threat_threshold"] = m_spinHighThreatThreshold->value();
    root["Rule_Scoring"] = scoring;

    // Save suspicious APIs
    QJsonArray suspiciousApis;
    QJsonArray highRiskApis;
    for (int i = 0; i < m_edrApiTable->rowCount(); i++) {
        QString name = m_edrApiTable->item(i, 0)->text();
        QString type = m_edrApiTable->item(i, 1)->text();
        if (type == "危险") suspiciousApis.append(name);
        else if (type == "高危") highRiskApis.append(name);
    }
    root["Rule_Pe_SuspiciousApis"] = suspiciousApis;
    root["Rule_Pe_HighRiskApis"] = highRiskApis;

    // Save suspicious sections
    QJsonArray sections;
    for (int i = 0; i < m_edrSectionTable->rowCount(); i++) {
        sections.append(m_edrSectionTable->item(i, 0)->text());
    }
    root["Rule_Pe_SuspiciousSections"] = sections;

    // Save YARA paths
    QJsonArray yaraPaths;
    QStringList pathParts = m_edrYaraPathEdit->text().split(";", Qt::SkipEmptyParts);
    for (const QString& p : pathParts) {
        yaraPaths.append(p.trimmed());
    }
    root["Rule_Yara_Paths"] = yaraPaths;

    // Save trusted publishers
    QJsonArray trustedPublishers;
    for (int i = 0; i < m_edrTrustedTable->rowCount(); i++) {
        trustedPublishers.append(m_edrTrustedTable->item(i, 0)->text());
    }
    root["Rule_Signature_TrustedPublishers"] = trustedPublishers;

    // Save required extensions
    QJsonArray requiredExtensions;
    for (int i = 0; i < m_edrRequiredExtTable->rowCount(); i++) {
        requiredExtensions.append(m_edrRequiredExtTable->item(i, 0)->text());
    }
    root["Rule_Signature_RequiredExtensions"] = requiredExtensions;

    QJsonDocument newDoc(root);

    if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        onAppendLog("ERROR", "EDR配置", "无法写入配置文件");
        return;
    }

    file.write(newDoc.toJson(QJsonDocument::Indented));
    file.close();

    onAppendLog("INFO", "EDR配置", "配置已保存，重启程序生效");
}

// ── Tool: Network Blacklist Manager ──────────────────────────────

void MainWindow::setupNetworkMgr(QWidget* page) {
    auto* l = new QVBoxLayout(page);
    l->setContentsMargins(0, 0, 0, 0);
    l->setSpacing(8);

    auto* ctrl = new QHBoxLayout();
    auto* refreshBtn = new QPushButton("刷新");
    refreshBtn->setObjectName("actionBtn");
    refreshBtn->setCursor(Qt::PointingHandCursor);
    connect(refreshBtn, &QPushButton::clicked, this, &MainWindow::onRefreshNetworkList);
    ctrl->addWidget(refreshBtn);
    ctrl->addStretch();
    l->addLayout(ctrl);

    // 黑名单表格
    m_netTable = new QTableWidget();
    m_netTable->setColumnCount(2);
    m_netTable->setHorizontalHeaderLabels({"IP 地址", "端口"});
    m_netTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_netTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_netTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_netTable->setSelectionMode(QAbstractItemView::SingleSelection);
    l->addWidget(m_netTable, 1);

    // 添加行
    auto* addRow = new QHBoxLayout();
    m_netIpEdit = new QLineEdit();
    m_netIpEdit->setPlaceholderText("输入要拦截的 IP 地址, 如 185.100.0.1");
    m_netPortSpin = new QSpinBox();
    m_netPortSpin->setRange(0, 65535);
    m_netPortSpin->setValue(0);
    m_netPortSpin->setPrefix("端口: ");
    m_netPortSpin->setSpecialValueText("端口: 全部");
    auto* addBtn = new QPushButton("添加黑名单");
    addBtn->setObjectName("actionBtn");
    addBtn->setCursor(Qt::PointingHandCursor);
    connect(addBtn, &QPushButton::clicked, this, &MainWindow::onAddNetworkIp);
    auto* delBtn = new QPushButton("移除选中");
    delBtn->setObjectName("actionBtn");
    delBtn->setCursor(Qt::PointingHandCursor);
    connect(delBtn, &QPushButton::clicked, this, &MainWindow::onRemoveNetworkIp);
    addRow->addWidget(m_netIpEdit, 1);
    addRow->addWidget(m_netPortSpin);
    addRow->addWidget(addBtn);
    addRow->addWidget(delBtn);
    l->addLayout(addRow);

    onRefreshNetworkList();
}

void MainWindow::onRefreshNetworkList() {
    // 从本地 JSON 加载黑名单展示 (后端内核黑名单不可枚举, 用本地存储同步)
    if (!m_netTable) return;
    m_netTable->setRowCount(0);

    QString cfgPath = QCoreApplication::applicationDirPath() + "/Plugins/Rules/Network_Blocklist.json";
    QFile file(cfgPath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &err);
    file.close();
    if (err.error != QJsonParseError::NoError) return;

    QJsonArray arr = doc.object().value("blocked").toArray();
    for (const auto& v : arr) {
        QJsonObject o = v.toObject();
        int row = m_netTable->rowCount();
        m_netTable->insertRow(row);
        m_netTable->setItem(row, 0, new QTableWidgetItem(o.value("ip").toString()));
        int port = o.value("port").toInt();
        m_netTable->setItem(row, 1, new QTableWidgetItem(port == 0 ? "全部" : QString::number(port)));
    }
}

void MainWindow::onAddNetworkIp() {
    if (!m_netIpEdit) return;
    QString ip = m_netIpEdit->text().trimmed();
    if (ip.isEmpty()) {
        onAppendLog("WARN", "网络防护", "请输入 IP 地址");
        return;
    }
    int port = m_netPortSpin ? m_netPortSpin->value() : 0;

    // 追加到本地 JSON
    QString cfgPath = QCoreApplication::applicationDirPath() + "/Plugins/Rules/Network_Blocklist.json";
    QJsonArray arr;
    QFile file(cfgPath);
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QJsonParseError err;
        QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &err);
        if (err.error == QJsonParseError::NoError) {
            arr = doc.object().value("blocked").toArray();
        }
        file.close();
    }
    // 去重
    for (const auto& v : arr) {
        QJsonObject o = v.toObject();
        if (o.value("ip").toString() == ip && o.value("port").toInt() == port) {
            onAppendLog("INFO", "网络防护", "该 IP 已在黑名单中");
            return;
        }
    }
    QJsonObject entry;
    entry["ip"] = ip;
    entry["port"] = port;
    arr.append(entry);

    QJsonObject root;
    root["blocked"] = arr;
    QFile outFile(cfgPath);
    if (outFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        outFile.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
        outFile.close();
    }

    // 通知后端下发到 NetFilter 内核黑名单
    Bridge::instance()->invokeToolCallback(QStringLiteral("net_block:%1:%2").arg(ip).arg(port));

    onRefreshNetworkList();
    onAppendLog("INFO", "网络防护", QString("已添加黑名单 %1:%2").arg(ip).arg(port));
}

void MainWindow::onRemoveNetworkIp() {
    if (!m_netTable) return;
    int row = m_netTable->currentRow();
    if (row < 0) {
        onAppendLog("WARN", "网络防护", "请先选中要移除的行");
        return;
    }
    QString ip = m_netTable->item(row, 0)->text();
    int port = m_netTable->item(row, 1)->text() == "全部" ? 0 : m_netTable->item(row, 1)->text().toInt();

    QString cfgPath = QCoreApplication::applicationDirPath() + "/Plugins/Rules/Network_Blocklist.json";
    QFile file(cfgPath);
    QJsonArray arr;
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QJsonParseError err;
        QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &err);
        if (err.error == QJsonParseError::NoError) arr = doc.object().value("blocked").toArray();
        file.close();
    }
    QJsonArray newArr;
    for (const auto& v : arr) {
        QJsonObject o = v.toObject();
        if (o.value("ip").toString() == ip && o.value("port").toInt() == port) continue;
        newArr.append(v);
    }
    QJsonObject root;
    root["blocked"] = newArr;
    QFile outFile(cfgPath);
    if (outFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        outFile.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
        outFile.close();
    }

    onRefreshNetworkList();
    onAppendLog("INFO", "网络防护", QString("已移除黑名单 %1:%2").arg(ip).arg(port));
}
