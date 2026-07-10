#include "MainWindow.h"
#include "Bridge.h"
#include "NotificationDialog.h"
#include "NavSidebar.h"
#include "zeta_ui_export.h"
#include <QMouseEvent>
#include <QHeaderView>
#include <QScrollBar>
#include <QFormLayout>
#include <QApplication>
#include <QScreen>
#include <QDateTime>
#include <QEvent>
#include <QTimer>
#include <QSystemTrayIcon>
#include <QGraphicsDropShadowEffect>
#include <QMenu>
#include <QAction>
#include <QDesktopServices>
#include <QUrl>

// Windows headers (after Qt to avoid conflicts)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>

// ── Theme definitions ───────────────────────────────────────────

void MainWindow::initThemes() {
    m_themes["zeta_dark"] = {
        "#0d0d14",   // bgWindow - 更深的窗口背景
        "#1a1a2e",   // bgNav - 导航栏背景
        "#161628",   // bgPanel - 内容面板背景
        "#25253d",   // bgHover - 悬停背景
        "#e8e8ee",   // textPrimary - 主文本色
        "#6c6c8a",   // textSecondary - 次要文本色
        "#2a2a4a",   // border - 边框色
        "#0a84ff",   // accent - 强调色
        "#0066cc",   // accentHover - 强调色悬停
        "#ff3b30"    // danger - 危险色
    };
}

QString MainWindow::buildStylesheet(const Theme& t) {
    return QString(R"(
        QMainWindow, QWidget#centralWidget { background-color: %1; }
        QWidget#navPanel { background-color: %2; border-right: 1px solid %6; }
        QWidget#contentPanel { background-color: %3; }
        QWidget#titleBar { background-color: %2; border-bottom: 1px solid %6; }
        QWidget#toolbarRow { background-color: %2; border-bottom: 1px solid %6; }
        QLabel { color: %5; font-size: 15px; }
        QLabel#titleLabel { color: %5; font-size: 16px; font-weight: bold; }
        QLabel#secLabel { color: %6; font-size: 13px; }
        QLabel#statusTitle { color: %5; font-size: 26px; font-weight: bold; }
        QPushButton#navBtn {
            background-color: transparent; color: %6; border: none;
            padding: 14px 18px; text-align: left; font-size: 15px;
            border-radius: 8px; margin: 2px 8px;
        }
        QPushButton#navBtn:hover { background-color: %4; color: %5; }
        QPushButton#navBtn:checked { background-color: rgba(10,132,255,0.2); color: %7; font-weight: bold; }
        QPushButton#ctrlBtn {
            background-color: transparent; color: %6; border: none;
            padding: 8px 14px; border-radius: 4px; font-size: 18px;
        }
        QPushButton#ctrlBtn:hover { background-color: %4; color: %5; }
        QPushButton#actionBtn {
            background-color: %7; color: white; border: none;
            padding: 10px 24px; border-radius: 8px; font-size: 15px;
        }
        QPushButton#actionBtn:hover { background-color: %8; }
        QPushButton#actionBtn[danger="true"] { background-color: %9; }
        QTextEdit { background-color: %3; color: %5; border: 1px solid %6; border-radius: 8px; padding: 10px; font-size: 13px; }
        QTableWidget { background-color: %3; color: %5; border: 1px solid %6; border-radius: 8px; gridline-color: rgba(42,42,74,0.6); }
        QTableWidget::item { padding: 10px; }
        QTableWidget::item:selected { background-color: rgba(10,132,255,0.2); color: %7; }
        QHeaderView::section { background-color: rgba(26,26,46,0.8); color: %6; border: none; border-bottom: 1px solid %6; padding: 12px; font-weight: bold; }
        QCheckBox { color: %5; font-size: 16px; spacing: 12px; }
        QCheckBox::indicator { width: 20px; height: 20px; border-radius: 4px; border: 2px solid %6; }
        QCheckBox::indicator:checked { background-color: %7; border-color: %7; }
        QComboBox { background-color: %3; color: %5; border: 1px solid %6; border-radius: 8px; padding: 8px 14px; font-size: 15px; }
        QComboBox:hover { border-color: %7; }
        QComboBox QAbstractItemView { background-color: %3; color: %5; border: 1px solid %6; border-radius: 4px; selection-background-color: rgba(10,132,255,0.2); selection-color: %7; }
        QProgressBar { background-color: rgba(42,42,74,0.4); border: none; border-radius: 4px; height: 10px; text-align: center; }
        QProgressBar::chunk { background-color: %7; border-radius: 4px; }
        QGroupBox { color: %5; font-size: 16px; font-weight: bold; border: 1px solid %6; border-radius: 10px; margin-top: 10px; padding-top: 0px; }
        QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 4px 16px; background-color: %3; }
        QGroupBox#configGroup { 
            background-color: rgba(22,22,40,0.6); 
            border: 1px solid rgba(42,42,74,0.5);
            border-radius: 12px;
        }
        QScrollArea { background-color: transparent; border: none; }
        QScrollArea QWidget { background-color: transparent; }
        QScrollBar:vertical { background-color: %3; width: 10px; border-radius: 4px; }
        QScrollBar::handle:vertical { background-color: rgba(42,42,74,0.8); border-radius: 4px; min-height: 36px; }
        QFrame#listItem { background-color: transparent; border: none; border-bottom: 1px solid rgba(42,42,74,0.3); min-height: 64px; }
        QFrame#listItem:hover { background-color: %4; }
        QFrame#dashCard { 
            background-color: rgba(22,22,40,0.8); 
            border: 1px solid rgba(42,42,74,0.4); 
            border-radius: 12px; 
            padding: 20px;
            border-top: 1px solid rgba(255,255,255,0.04);
        }
        QLabel#cardTitle { color: %6; font-size: 12px; font-weight: bold; letter-spacing: 1.5px; text-transform: uppercase; }
        QLabel#cardValue { color: %5; font-size: 15px; }
        QLabel#cardAccent { color: %7; font-size: 15px; }
        QLabel#cardDanger { color: %9; font-size: 15px; }
        QLabel#cardEvent { color: rgba(118,118,146,0.9); font-size: 12px; padding: 4px 0px; border: none; }
        QLineEdit { background-color: %3; color: %5; border: 1px solid %6; border-radius: 8px; padding: 10px 14px; font-size: 15px; }
        QLineEdit:hover { border-color: %7; }
        QLineEdit:focus { border-color: %7; }
        QSpinBox { background-color: %3; color: %5; border: 1px solid %6; border-radius: 8px; padding: 6px 10px; font-size: 16px; }
        QSpinBox:hover { border-color: %7; }
        QSpinBox:focus { border-color: %7; }
        QTabWidget::pane { border: none; background-color: %3; }
        QTabWidget::tab-bar { left: 0px; }
        QTabBar::tab { 
            background-color: transparent; 
            color: %6; 
            padding: 12px 24px; 
            margin-right: 4px; 
            border-radius: 8px 8px 0 0; 
            font-size: 15px;
            min-width: 90px;
        }
        QTabBar::tab:hover { background-color: %4; color: %5; }
        QTabBar::tab:selected { background-color: %3; color: %5; font-weight: bold; }
    )")
    .arg(t.bgWindow).arg(t.bgNav).arg(t.bgPanel).arg(t.bgHover)
    .arg(t.textPrimary).arg(t.textSecondary)
    .arg(t.accent).arg(t.accentHover).arg(t.danger);
}

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    initThemes();
    setWindowTitle("ZETA Security");
    setWindowFlags(Qt::FramelessWindowHint);
    
    setMinimumSize(900, 650);
    
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
    applyTheme("zeta_dark");
    setupTrayIcon();
    show();
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

void MainWindow::setupTitleBar(QVBoxLayout* parent) {
    m_titleBar = new QWidget();
    m_titleBar->setObjectName("titleBar");
    m_titleBar->setFixedHeight(44);
    auto* layout = new QHBoxLayout(m_titleBar);
    layout->setContentsMargins(12, 0, 8, 0);

    m_titleLabel = new QLabel("ZETA Security");
    m_titleLabel->setObjectName("titleLabel");
    layout->addWidget(m_titleLabel);
    layout->addStretch();

    auto* aboutBtn = new QPushButton(QString::fromUtf8("\u24D8")); // ⓘ
    aboutBtn->setObjectName("ctrlBtn");
    aboutBtn->setFixedSize(32, 28);
    aboutBtn->setCursor(Qt::PointingHandCursor);
    connect(aboutBtn, &QPushButton::clicked, this, [this]() {
        QMessageBox::about(this, "关于 ZETA Security",
            "ZETA Security v2.0.0\n\n实时系统安全防护\n(C) 2020-2026 runqp\n保留所有权利");
    });
    layout->addWidget(aboutBtn);

    auto* minBtn = new QPushButton(QString::fromUtf8("\u2500")); // ─
    minBtn->setObjectName("ctrlBtn");
    minBtn->setFixedSize(32, 28);
    minBtn->setCursor(Qt::PointingHandCursor);
    connect(minBtn, &QPushButton::clicked, this, &QWidget::showMinimized);
    layout->addWidget(minBtn);

    auto* closeBtn = new QPushButton(QString::fromUtf8("\u2715")); // ✕
    closeBtn->setObjectName("ctrlBtn");
    closeBtn->setFixedSize(32, 28);
    closeBtn->setCursor(Qt::PointingHandCursor);
    connect(closeBtn, &QPushButton::clicked, this, [this]() { close(); });
    layout->addWidget(closeBtn);

    parent->addWidget(m_titleBar);
}

// ── Sidebar ─────────────────────────────────────────────────────

void MainWindow::setupSidebar(QHBoxLayout* parent) {
    m_navSidebar = new NavSidebar();
    m_navSidebar->setObjectName("navPanel");
    connect(m_navSidebar, &NavSidebar::currentIndexChanged, this, &MainWindow::switchPage);
    parent->addWidget(m_navSidebar);
}

// ── Pages ───────────────────────────────────────────────────────

void MainWindow::setupPages() {
    // Home page — Dashboard
    {
        m_homePage = new QWidget();
        m_homePage->setObjectName("contentPanel");
        auto* l = new QVBoxLayout(m_homePage);
        l->setContentsMargins(20, 18, 20, 18);
        l->setSpacing(16);

        auto makeCard = [&](const QString& title, bool hasShadow = true) -> QPair<QFrame*, QVBoxLayout*> {
            auto* card = new QFrame();
            card->setObjectName("dashCard");
            auto* cl = new QVBoxLayout(card);
            cl->setContentsMargins(14, 12, 14, 12);
            cl->setSpacing(8);
            if (!title.isEmpty()) {
                auto* titleL = new QLabel(title);
                titleL->setObjectName("cardTitle");
                cl->addWidget(titleL);
            }
            if (hasShadow) {
                auto* shadow = new QGraphicsDropShadowEffect();
                shadow->setBlurRadius(16);
                shadow->setOffset(0, 3);
                shadow->setColor(QColor(0, 0, 0, 80));
                card->setGraphicsEffect(shadow);
            }
            return {card, cl};
        };

        // ── Card 1: 防护状态 + 统计概览 (single card) ──
        auto [mainCard, mc] = makeCard("");
        {
            auto* topRow = new QHBoxLayout();
            topRow->setSpacing(20);

            auto* statusCol = new QVBoxLayout();
            statusCol->setSpacing(4);
            m_statusIcon = new QLabel();
            m_statusIcon->setFixedSize(36, 36);
            m_statusIcon->setStyleSheet("background-color: #34c759; border-radius: 9px;");
            statusCol->addWidget(m_statusIcon, 0, Qt::AlignTop);
            m_statusText = new QLabel("已防护");
            m_statusText->setObjectName("cardAccent");
            m_statusText->setStyleSheet("QLabel#cardAccent { font-size: 15px; font-weight: bold; }");
            statusCol->addWidget(m_statusText);
            m_statusSub = new QLabel("实时防护中");
            m_statusSub->setObjectName("cardValue");
            statusCol->addWidget(m_statusSub);
            topRow->addLayout(statusCol);

            auto* statsCol = new QVBoxLayout();
            statsCol->setSpacing(6);
            auto makeStat = [&](const QString& label, QLabel*& val, const QString& obj) -> QHBoxLayout* {
                auto* r = new QHBoxLayout();
                r->setContentsMargins(0, 0, 0, 0);
                auto* labelL = new QLabel(label);
                labelL->setObjectName("cardValue");
                labelL->setStyleSheet("QLabel#cardValue { font-size: 12px; color: #6c6c8a; }");
                r->addWidget(labelL);
                r->addStretch();
                val = new QLabel("0");
                val->setObjectName(obj);
                val->setStyleSheet("font-weight: bold; font-size: 13px;");
                r->addWidget(val);
                return r;
            };
            statsCol->addLayout(makeStat("HIPS 拦截", m_statHipsLabel, "cardAccent"));
            statsCol->addLayout(makeStat("EDR 告警", m_statEdrLabel, "cardAccent"));
            statsCol->addLayout(makeStat("威胁阻断", m_statKilledLabel, "cardDanger"));
            topRow->addLayout(statsCol, 1);

            mc->addLayout(topRow);
        }

        // ── Row 2: 最近事件 + 日志 ──
        auto* bottomRow = new QHBoxLayout();
        bottomRow->setSpacing(16);

        // ── Card 3: 最近事件 ──
        auto [eventCard, ec] = makeCard("最 近 事 件");
        {
            auto makeEvent = [&](QLabel*& lbl) {
                lbl = new QLabel("—");
                lbl->setObjectName("cardEvent");
                lbl->setStyleSheet("QLabel#cardEvent { font-size: 11px; padding: 3px 0; }");
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
            m_logText->setMaximumHeight(140);
            m_logText->setStyleSheet("QTextEdit { background: transparent; border: none; font-size: 11px; }");
            ll->addWidget(m_logText, 1);
        }
        bottomRow->addWidget(logCard, 2);

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
        l->setContentsMargins(24, 24, 24, 24);
        l->setSpacing(8);

        auto* hdr = new QLabel("防护状态");
        hdr->setObjectName("statusTitle");
        l->addWidget(hdr);
        l->addSpacing(8);

        struct { const char* title; const char* desc; } items[] = {
            {"HIPS拦截", "实时拦截高危系统操作"},
            {"行为分析", "进程行为风险评分"},
            {"签名验证", "检测恶意驱动签名"},
            {"YARA扫描", "基于规则的恶意软件检测"},
            {"血缘追踪", "追踪进程创建关系"},
            {"勒索检测", "实验性功能"},
        };
        for (auto& item : items) {
            auto* frame = new QFrame();
            frame->setObjectName("listItem");
            frame->setFrameShape(QFrame::NoFrame);
            auto* fl = new QHBoxLayout(frame);
            fl->setContentsMargins(16, 14, 16, 14);
            fl->setSpacing(12);

            auto* tl = new QVBoxLayout();
            tl->setSpacing(2);
            auto* t = new QLabel(item.title);
            t->setObjectName("titleLabel");
            auto* d = new QLabel(item.desc);
            d->setObjectName("secLabel");
            tl->addWidget(t);
            tl->addWidget(d);
            fl->addLayout(tl, 1);

            auto* status = new QLabel("运行中");
            status->setObjectName("statusLabel");
            fl->addWidget(status);

            l->addWidget(frame);
        }
        l->addStretch();
        m_stack->addWidget(m_protectPage);
    }

    // Settings page
    {
        m_settingsPage = new QWidget();
        m_settingsPage->setObjectName("contentPanel");
        auto* l = new QVBoxLayout(m_settingsPage);
        l->setContentsMargins(24, 24, 24, 24);
        l->setSpacing(8);

        auto* hdr = new QLabel("设置");
        hdr->setObjectName("statusTitle");
        l->addWidget(hdr);
        l->addSpacing(8);

        // Helper to create toggle rows
        auto makeToggle = [&](const char* title, const char* desc) -> QPair<QFrame*, QCheckBox*> {
            auto* frame = new QFrame();
            frame->setObjectName("listItem");
            frame->setFrameShape(QFrame::NoFrame);
            auto* fl = new QHBoxLayout(frame);
            fl->setContentsMargins(16, 14, 16, 14);
            fl->setSpacing(12);
            auto* tl = new QVBoxLayout();
            tl->setSpacing(2);
            auto* t = new QLabel(title);
            t->setObjectName("titleLabel");
            auto* d = new QLabel(desc);
            d->setObjectName("secLabel");
            tl->addWidget(t);
            tl->addWidget(d);
            fl->addLayout(tl, 1);
            auto* sw = new QCheckBox(); sw->setText("");
            fl->addWidget(sw);
            return {frame, sw};
        };

        // Experimental group
        auto* expGroup = new QGroupBox("实验性功能");
        auto* expL = new QVBoxLayout(expGroup);

        auto [lf1, sw1] = makeToggle("血统追踪", "追踪进程血缘关系，检测脚本解释器释放恶意文件");
        m_lineageSwitch = sw1;
        expL->addWidget(lf1);
        connect(m_lineageSwitch, &QCheckBox::toggled, this, [this](bool checked) {
            Bridge::instance()->invokeToolCallback(checked ? QStringLiteral("toggle_lineage:1") : QStringLiteral("toggle_lineage:0"));
        });

        auto [lf2, sw2] = makeToggle("实验性勒索检测", "使用高级熵分析检测勒索软件行为");
        m_ransomSwitch = sw2;
        expL->addWidget(lf2);
        connect(m_ransomSwitch, &QCheckBox::toggled, this, [this](bool checked) {
            Bridge::instance()->invokeToolCallback(checked ? QStringLiteral("toggle_ransom:1") : QStringLiteral("toggle_ransom:0"));
        });
        l->addWidget(expGroup);


        // General group
        auto* genGroup = new QGroupBox("常规设置");
        auto* genL = new QVBoxLayout(genGroup);

        auto [gf1, gs1] = makeToggle("学习模式", "启动后5分钟内自动放行所有可疑行为并记录日志");
        m_learningSwitch = gs1; genL->addWidget(gf1);
        connect(m_learningSwitch, &QCheckBox::toggled, this, [this](bool checked) {
            Bridge::instance()->invokeToolCallback(checked ? QStringLiteral("toggle_learning:1") : QStringLiteral("toggle_learning:0"));
        });

        l->addWidget(genGroup);

        // Language
        auto* styleGroup = new QGroupBox("外观");
        auto* styleL = new QFormLayout(styleGroup);
        m_langCombo = new QComboBox();
        struct { const char* val; const char* label; } langs[] = {
            {"english_switch", "English"}, {"traditional_switch", "繁體中文"},
            {"simplified_switch", "简体中文"}, {"japanese_switch", "日本語"},
            {"korean_switch", "한국어"}, {"french_switch", "Français"},
            {"spanish_switch", "Español"},
        };
        for (auto& l : langs) {
            m_langCombo->addItem(l.label, l.val);
        }
        styleL->addRow("显示语言:", m_langCombo);
        l->addWidget(styleGroup);

        l->addStretch();
        m_stack->addWidget(m_settingsPage);
    }

    // Default: home
    m_navSidebar->setCurrentIndex(0);
    m_stack->setCurrentIndex(0);
}

void MainWindow::switchPage(int index) {
    m_stack->setCurrentIndex(index);
}

// ── Theme ────────────────────────────────────────────────────────

void MainWindow::applyTheme(const QString& themeKey) {
    if (!m_themes.contains(themeKey)) return;
    m_currentTheme = themeKey;
    setStyleSheet(buildStylesheet(m_themes[themeKey]));
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
    // Sync to dashboard
    QString shortLine = QString("[%1] [%2] %3").arg(
        QDateTime::currentDateTime().toString("HH:mm"), level, action);
    onUpdateDashboardStats(shortLine);
}

void MainWindow::onSetTheme(const QString& themeKey) { applyTheme(themeKey); }



void MainWindow::onSetDriverStatus(bool loaded) {
    m_driverLoaded = loaded;
    if (m_navSidebar) {
        m_navSidebar->setDriverStatus(loaded);
    }
    if (m_statusIcon) {
        m_statusIcon->setStyleSheet(loaded 
            ? "background-color: #34c759; border-radius: 9px;" 
            : "background-color: #ff3b30; border-radius: 9px;");
    }
    if (m_statusText) {
        if (loaded) {
            m_statusText->setStyleSheet("QLabel#cardAccent { font-size: 15px; font-weight: bold; color: #34c759; }");
            m_statusText->setText("已防护");
        } else {
            m_statusText->setStyleSheet("QLabel#cardDanger { font-size: 15px; font-weight: bold; color: #ff3b30; }");
            m_statusText->setText("未防护");
        }
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

void MainWindow::onSetLineageTracker(bool enabled) {
    if (m_lineageSwitch) {
        m_lineageSwitch->blockSignals(true);
        m_lineageSwitch->setChecked(enabled);
        m_lineageSwitch->blockSignals(false);
    }
}

void MainWindow::onSetRansomExp(bool enabled) {
    if (m_ransomSwitch) {
        m_ransomSwitch->blockSignals(true);
        m_ransomSwitch->setChecked(enabled);
        m_ransomSwitch->blockSignals(false);
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
    if (key.startsWith("lineage") && m_lineageSwitch) {
        m_lineageSwitch->blockSignals(true); m_lineageSwitch->setChecked(checked); m_lineageSwitch->blockSignals(false);
    } else if (key.startsWith("ransom") && m_ransomSwitch) {
        m_ransomSwitch->blockSignals(true); m_ransomSwitch->setChecked(checked); m_ransomSwitch->blockSignals(false);
    }
}

void MainWindow::onRestoreCombo(const QString& name, const QString& value) {
    if (name == "language" && m_langCombo) {
        int idx = m_langCombo->findData(value);
        if (idx >= 0) { m_langCombo->blockSignals(true); m_langCombo->setCurrentIndex(idx); m_langCombo->blockSignals(false); }
    }
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

void MainWindow::onShowNotification(const QString& title, const QString& message, int level) {
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

void MainWindow::onUpdateDashboardStats(const QString& eventLine) {
    // Update event list (shift events down, newest at top)
    if (m_statEvent5) m_statEvent5->setText(m_statEvent4->text());
    if (m_statEvent4) m_statEvent4->setText(m_statEvent3->text());
    if (m_statEvent3) m_statEvent3->setText(m_statEvent2->text());
    if (m_statEvent2) m_statEvent2->setText(m_statEvent1->text());
    if (m_statEvent1) m_statEvent1->setText(eventLine);

    // Parse and update stats counts
    if (eventLine.contains("[HIPS]")) {
        m_statHipsCount++;
        if (m_statHipsLabel) m_statHipsLabel->setText(QString::number(m_statHipsCount));
    } else if (eventLine.contains("[EDR]") && eventLine.contains("kill")) {
        m_statKilledCount++;
        if (m_statKilledLabel) m_statKilledLabel->setText(QString::number(m_statKilledCount));
    } else if (eventLine.contains("[EDR]")) {
        m_statEdrCount++;
        if (m_statEdrLabel) m_statEdrLabel->setText(QString::number(m_statEdrCount));
    }
}

// ── Tools Page ───────────────────────────────────────────────────

void MainWindow::setupToolsPage() {
    auto* l = new QVBoxLayout(m_toolsPage);
    l->setContentsMargins(24, 24, 24, 24);
    l->setSpacing(12);

    // Top bar with back button and title
    auto* topBar = new QHBoxLayout();
    m_toolBackBtn = new QPushButton(QString::fromUtf8("\u2190 返回"));
    m_toolBackBtn->setObjectName("actionBtn");
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
    m_toolStack = new QStackedWidget();
    m_toolStack->setObjectName("contentPanel");

    // Page 0: tool list
    auto* listPage = new QWidget();
    listPage->setObjectName("contentPanel");
    auto* listL = new QVBoxLayout(listPage);
    listL->setContentsMargins(0, 0, 0, 0);
    listL->setSpacing(8);

    const char* tools[] = {"进程管理", "启动项管理", "垃圾清理", "系统修复",
                           "HIPS 规则管理", "白名单", "隔离区", "EDR 规则管理"};
    const char* descs[] = {"实时查看系统进程，终止进程", "管理开机启动项",
                           "清理系统暂存垃圾文件", "修复系统登录档",
                           "管理 HIPS 拦截规则",
                           "管理白名单", "管理隔离区", "管理 EDR 检测规则"};

    for (int i = 0; i < 8; i++) {
        auto* frame = new QFrame();
        frame->setObjectName("listItem");
        frame->setFrameShape(QFrame::NoFrame);
        frame->setCursor(Qt::PointingHandCursor);
        auto* fl = new QHBoxLayout(frame);
        fl->setContentsMargins(16, 14, 16, 14);
        fl->setSpacing(12);

        auto* tl = new QVBoxLayout();
        tl->setSpacing(2);
        auto* t = new QLabel(tools[i]);
        t->setObjectName("titleLabel");
        t->setAttribute(Qt::WA_TransparentForMouseEvents);
        auto* d = new QLabel(descs[i]);
        d->setObjectName("secLabel");
        d->setAttribute(Qt::WA_TransparentForMouseEvents);
        tl->addWidget(t);
        tl->addWidget(d);
        fl->addLayout(tl, 1);
        auto* arrow = new QLabel(QString::fromUtf8("\u203A"));
        arrow->setObjectName("cardAccent");
        arrow->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        arrow->setAttribute(Qt::WA_TransparentForMouseEvents);
        fl->addWidget(arrow);

        int idx = i + 1; // page index (1-based for tool pages)
         frame->setProperty("toolIndex", idx);
         frame->installEventFilter(this);
         listL->addWidget(frame);
    }
    listL->addStretch();
    m_toolStack->addWidget(listPage); // index 0 = list

    // Create 8 tool sub-pages
    for (int i = 0; i < 8; i++) {
        auto* page = new QWidget();
        page->setObjectName("contentPanel");
        m_toolStack->addWidget(page); // indices 1-9
    }

    // Setup each tool page
    setupProcessManager(m_toolStack->widget(PROCESS_MGR));
    setupStartupManager(m_toolStack->widget(STARTUP_MGR));
    setupJunkCleaner(m_toolStack->widget(JUNK_CLEANER));
    setupSystemRepair(m_toolStack->widget(SYSTEM_REPAIR));
    setupHipsManager(m_toolStack->widget(HIPS_MGR));
    setupWhitelistManager(m_toolStack->widget(WHITELIST_MGR));
    setupQuarantineManager(m_toolStack->widget(QUARANTINE_MGR));
    setupEdrManager(m_toolStack->widget(EDR_MGR));

    l->addWidget(m_toolStack, 1);
}

void MainWindow::showToolList() {
    m_toolStack->setCurrentIndex(TOOL_LIST);
    m_toolBackBtn->setVisible(false);
    m_toolTitleLabel->setText("工具");
    // (traffic monitor timer removed)
}

void MainWindow::showToolPage(int toolIndex) {
    if (toolIndex < 1 || toolIndex > 8) return;

    // (traffic monitor timer removed in showToolPage)

    m_toolStack->setCurrentIndex(toolIndex);
    m_toolBackBtn->setVisible(true);

    const char* titles[] = {"进程管理", "启动项管理", "垃圾清理", "系统修复",
                            "HIPS 规则管理", "白名单", "隔离区", "EDR 规则管理"};
    m_toolTitleLabel->setText(titles[toolIndex - 1]);

    // Auto-refresh when entering a tool page
    switch (toolIndex) {
    case PROCESS_MGR: onRefreshProcessList(); break;
    case STARTUP_MGR: onRefreshStartupList(); break;
    case JUNK_CLEANER: onRefreshJunkScan(); break;
    case SYSTEM_REPAIR: break;
    case HIPS_MGR: onRefreshHipsRules(); break;
    case WHITELIST_MGR: onRefreshWhitelist(); break;
    case QUARANTINE_MGR: onRefreshQuarantine(); break;
    case EDR_MGR: onRefreshEdrRules(); break;
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
                if (DeleteFileW((const wchar_t*)path.utf16())) {
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

    auto* infoLabel = new QLabel("HIPS 规则通过驱动加载。当前显示默认规则。");
    infoLabel->setObjectName("secLabel");
    infoLabel->setWordWrap(true);
    l->addWidget(infoLabel);

    m_hipsTable = new QTableWidget();
    m_hipsTable->setColumnCount(4);
    m_hipsTable->setHorizontalHeaderLabels({"规则名", "类型", "操作", "状态"});
    m_hipsTable->horizontalHeader()->setStretchLastSection(true);
    m_hipsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_hipsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_hipsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_hipsTable->verticalHeader()->setVisible(false);
    l->addWidget(m_hipsTable, 1);
}

void MainWindow::onRefreshHipsRules() {
    if (!m_hipsTable) return;
    m_hipsTable->setRowCount(0);

    struct { const char* name; const char* type; const char* action; const char* status; } rules[] = {
        // ── 进程保护 ──
        {"LSASS 进程保护", "进程保护", "拦截", "启用"},
        {"SVCHOST 进程保护", "进程保护", "拦截", "启用"},
        {"EXPLORER 进程保护", "进程保护", "拦截", "启用"},
        {"系统关键进程保护", "进程保护", "拦截", "启用"},
        {"恶意进程终止", "进程保护", "拦截", "启用"},
        {"进程注入检测", "进程保护", "告警", "启用"},
        {"父进程欺骗检测", "进程保护", "告警", "启用"},
        {"空洞进程 (Process Hollowing)", "进程保护", "拦截", "启用"},
        {"反射型 DLL 注入", "进程保护", "拦截", "启用"},

        // ── 注册表保护 ──
        {"启动项注册表防护", "注册表保护", "拦截", "启用"},
        {"镜像劫持 (IFEO) 防护", "注册表保护", "拦截", "启用"},
        {"AppInit_DLLs 防护", "注册表保护", "拦截", "启用"},
        {"UAC 设置防护", "注册表保护", "拦截", "启用"},
        {"安全中心禁用防护", "注册表保护", "拦截", "启用"},
        {"Windows Defender 防护", "注册表保护", "拦截", "启用"},
        {"PowerShell 日志防护", "注册表保护", "拦截", "启用"},
        {"防火墙设置防护", "注册表保护", "拦截", "启用"},
        {"BCD 启动项防护", "注册表保护", "拦截", "启用"},
        {"自动登录配置防护", "注册表保护", "拦截", "启用"},

        // ── 文件保护 ──
        {"系统目录文件防护", "文件保护", "拦截", "启用"},
        {"驱动文件保护", "文件保护", "拦截", "启用"},
        {"配置文件保护", "文件保护", "拦截", "启用"},
        {"引导分区保护 (EFI/MBR)", "文件保护", "拦截", "启用"},
        {"SAM/SYSTEM 配置保护", "文件保护", "拦截", "启用"},
        {"Temp 目录可执行文件创建", "文件保护", "告警", "启用"},
        {"脚本解释器文件创建", "文件保护", "告警", "启用"},
        {"ZETA 自身文件保护", "文件保护", "拦截", "启用"},

        // ── 网络保护 ──
        {"可疑网络连接监控", "网络保护", "告警", "启用"},
        {"C2 通信检测", "网络保护", "拦截", "启用"},
        {"DNS 劫持检测", "网络保护", "告警", "启用"},
        {"代理配置篡改防护", "网络保护", "拦截", "启用"},
        {"Hosts 文件保护", "文件保护", "拦截", "启用"},

        // ── 驱动保护 ──
        {"驱动加载保护", "驱动保护", "拦截", "启用"},
        {"未知驱动拦截", "驱动保护", "告警", "启用"},
        {"驱动签名验证", "驱动保护", "拦截", "启用"},
        {"内核回调保护", "驱动保护", "拦截", "启用"},

        // ── 启动项保护 ──
        {"Run 键启动项防护", "启动项保护", "拦截", "启用"},
        {"RunOnce 启动项防护", "启动项保护", "拦截", "启用"},
        {"计划任务防护", "启动项保护", "拦截", "启用"},
        {"服务启动防护", "启动项保护", "拦截", "启用"},
        {"WMI 事件订阅防护", "启动项保护", "告警", "启用"},

        // ── 行为检测 ──
        {"勒索软件行为检测", "行为检测", "拦截", "启用"},
        {"SilverFox 双签名检测", "行为检测", "告警", "启用"},
        {"血缘追踪 (Lineage)", "行为检测", "告警", "启用"},
        {"LOLBins 滥用检测", "行为检测", "告警", "启用"},
        {"UAC 绕过检测", "行为检测", "拦截", "启用"},
        {"凭证窃取检测", "行为检测", "拦截", "启用"},
        {"横向移动检测", "行为检测", "告警", "启用"},
    };
    for (auto& r : rules) {
        int row = m_hipsTable->rowCount();
        m_hipsTable->insertRow(row);
        m_hipsTable->setItem(row, 0, new QTableWidgetItem(r.name));
        m_hipsTable->setItem(row, 1, new QTableWidgetItem(r.type));
        m_hipsTable->setItem(row, 2, new QTableWidgetItem(r.action));
        m_hipsTable->setItem(row, 3, new QTableWidgetItem(r.status));
    }

    // Try to load from backend if available
    Bridge::instance()->invokeToolCallback("HIPS 规则管理");
}

// ── Tool: Whitelist Manager ──────────────────────────────────────

void MainWindow::setupWhitelistManager(QWidget* page) {
    auto* l = new QVBoxLayout(page);
    l->setContentsMargins(0, 0, 0, 0);
    l->setSpacing(8);

    auto* ctrl = new QHBoxLayout();
    m_whitelistPathEdit = new QLineEdit();
    m_whitelistPathEdit->setPlaceholderText("输入要添加的路径...");
    m_whitelistPathEdit->setObjectName("actionBtn");
    ctrl->addWidget(m_whitelistPathEdit, 1);

    auto* addBtn = new QPushButton("添加");
    addBtn->setObjectName("actionBtn");
    addBtn->setCursor(Qt::PointingHandCursor);
    connect(addBtn, &QPushButton::clicked, this, [this]() {
        QString path = m_whitelistPathEdit->text().trimmed();
        if (path.isEmpty()) return;
        int row = m_whitelistTable->rowCount();
        m_whitelistTable->insertRow(row);
        m_whitelistTable->setItem(row, 0, new QTableWidgetItem(path));
        m_whitelistTable->setItem(row, 1, new QTableWidgetItem("手动添加"));
        m_whitelistTable->setItem(row, 2, new QTableWidgetItem("启用"));
        m_whitelistPathEdit->clear();
        onAppendLog("INFO", "白名单", "已添加: " + path);
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
        m_whitelistTable->removeRow(row);
        onAppendLog("INFO", "白名单", "已移除: " + path);
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
    // Whitelist entries are managed via the UI
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
        QString origPath = m_quarantineTable->item(row, 2)->text();
        QString qPath = m_quarantineTable->item(row, 0)->text();
        if (MoveFileW((const wchar_t*)qPath.utf16(), (const wchar_t*)origPath.utf16())) {
            onRefreshQuarantine();
            onAppendLog("INFO", "隔离区", "已恢复: " + origPath);
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
            onRefreshQuarantine();
            onAppendLog("INFO", "隔离区", "已永久删除隔离文件");
        }
    });
    ctrl->addWidget(deleteBtn);
    ctrl->addStretch();
    l->addLayout(ctrl);

    m_quarantineTable = new QTableWidget();
    m_quarantineTable->setColumnCount(3);
    m_quarantineTable->setHorizontalHeaderLabels({"隔离路径", "时间", "原始路径"});
    m_quarantineTable->horizontalHeader()->setStretchLastSection(true);
    m_quarantineTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
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

        QString fullPath = QString::fromWCharArray(quarantineDir) + "\\" +
                          QString::fromWCharArray(findData.cFileName);

        // Read original path from companion .info file
        QString infoPath = fullPath + ".info";
        QString origPath = "-";
        HANDLE hInfo = CreateFileW((const wchar_t*)infoPath.utf16(), GENERIC_READ,
                                    FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hInfo != INVALID_HANDLE_VALUE) {
            char buf[1024] = {0};
            DWORD read = 0;
            if (ReadFile(hInfo, buf, sizeof(buf) - 1, &read, nullptr)) {
                origPath = QString::fromUtf8(buf);
            }
            CloseHandle(hInfo);
        }

        int row = m_quarantineTable->rowCount();
        m_quarantineTable->insertRow(row);
        m_quarantineTable->setItem(row, 0, new QTableWidgetItem(fullPath));
        m_quarantineTable->setItem(row, 1, new QTableWidgetItem("待查"));
        m_quarantineTable->setItem(row, 2, new QTableWidgetItem(origPath));
    } while (FindNextFileW(hFind, &findData));
    FindClose(hFind);
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

// ── Tool: EDR Manager ───────────────────────────────────────────

void MainWindow::setupEdrManager(QWidget* page) {
    auto* l = new QVBoxLayout(page);
    l->setContentsMargins(0, 0, 0, 0);
    l->setSpacing(0);

    auto* toolbar = new QWidget();
    toolbar->setObjectName("toolbarRow");
    auto* tbL = new QHBoxLayout(toolbar);
    tbL->setContentsMargins(20, 12, 20, 12);

    auto* refreshBtn = new QPushButton("刷新配置");
    refreshBtn->setObjectName("actionBtn");
    refreshBtn->setCursor(Qt::PointingHandCursor);
    connect(refreshBtn, &QPushButton::clicked, this, &MainWindow::onRefreshEdrRules);
    tbL->addWidget(refreshBtn);

    auto* saveBtn = new QPushButton("保存配置");
    saveBtn->setObjectName("actionBtn");
    saveBtn->setCursor(Qt::PointingHandCursor);
    connect(saveBtn, &QPushButton::clicked, this, &MainWindow::onSaveEdrRules);
    tbL->addWidget(saveBtn);

    tbL->addStretch();
    l->addWidget(toolbar);

    auto* tabs = new QTabWidget();
    tabs->setDocumentMode(true);
    tabs->setMinimumHeight(500);

    // ────── Tab 1: 扫描配置 ──────
    auto* tabScan = new QWidget();
    auto* scrollScan = new QScrollArea();
    scrollScan->setWidget(tabScan);
    scrollScan->setWidgetResizable(true);
    scrollScan->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto* t1L = new QVBoxLayout(tabScan);
    t1L->setContentsMargins(28, 24, 28, 24);
    t1L->setSpacing(28);

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
    m_chkEnableEntropy = new QCheckBox("启用熵分析");
    m_chkEnableEntropy->setObjectName("configCheckBox");
    scanL->addWidget(m_chkEnableEntropy, 1, 1);
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

    auto* scoreGroup = new QGroupBox("评分权重配置");
    scoreGroup->setObjectName("configGroup");
    auto* scoreL = new QVBoxLayout(scoreGroup);
    scoreL->setSpacing(4);
    scoreL->setContentsMargins(0, 0, 0, 0);
    
    auto addScoreRow = [&](const QString& label, QSpinBox*& spin, int val) {
        auto* row = new QFrame();
        row->setObjectName("listItem");
        auto* rowL = new QHBoxLayout(row);
        rowL->setContentsMargins(20, 14, 20, 14);
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
        scoreL->addWidget(row);
    };
    
    addScoreRow("危险API调用", m_spinSuspiciousApi, 15);
    addScoreRow("高危API调用", m_spinHighRiskApi, 30);
    addScoreRow("可疑节名", m_spinSuspiciousSection, 30);
    addScoreRow("RWX内存节", m_spinRwxSection, 20);
    addScoreRow("高熵压缩", m_spinHighEntropy, 25);
    addScoreRow("无入口点", m_spinNoEntryPoint, 10);
    addScoreRow("未签名", m_spinUnsigned, 20);
    addScoreRow("YARA规则匹配", m_spinYaraMatch, 100);
    
    auto* sepLine = new QFrame();
    sepLine->setFrameShape(QFrame::HLine);
    sepLine->setFrameShadow(QFrame::Sunken);
    sepLine->setStyleSheet("QFrame { color: rgba(42,42,74,0.6); }");
    scoreL->addWidget(sepLine);
    
    addScoreRow("威胁告警阈值", m_spinThreatThreshold, 50);
    addScoreRow("高危拦截阈值", m_spinHighThreatThreshold, 70);
    
    t1L->addWidget(scoreGroup);
    t1L->addStretch();
    tabs->addTab(scrollScan, "扫描配置");

    // ────── Tab 2: API & 节名 ──────
    auto* tabRules = new QWidget();
    auto* scrollRules = new QScrollArea();
    scrollRules->setWidget(tabRules);
    scrollRules->setWidgetResizable(true);
    scrollRules->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto* t2L = new QVBoxLayout(tabRules);
    t2L->setContentsMargins(28, 24, 28, 24);
    t2L->setSpacing(28);

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
    m_edrApiTable->setMaximumHeight(280);
    apiL->addWidget(m_edrApiTable);
    t2L->addWidget(apiGroup);

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
    m_edrSectionTable->setMinimumHeight(120);
    m_edrSectionTable->setMaximumHeight(200);
    sectionL->addWidget(m_edrSectionTable);
    t2L->addWidget(sectionGroup);

    t2L->addStretch();
    tabs->addTab(scrollRules, "API & 节名");

    // ────── Tab 3: 签名验证 ──────
    auto* tabSign = new QWidget();
    auto* scrollSign = new QScrollArea();
    scrollSign->setWidget(tabSign);
    scrollSign->setWidgetResizable(true);
    scrollSign->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto* t3L = new QVBoxLayout(tabSign);
    t3L->setContentsMargins(28, 24, 28, 24);
    t3L->setSpacing(28);

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
    m_edrTrustedTable->setMinimumHeight(120);
    m_edrTrustedTable->setMaximumHeight(200);
    trustedL->addWidget(m_edrTrustedTable);
    t3L->addWidget(trustedGroup);

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
    m_edrRequiredExtTable->setMinimumHeight(100);
    m_edrRequiredExtTable->setMaximumHeight(180);
    extL->addWidget(m_edrRequiredExtTable);
    t3L->addWidget(extGroup);

    t3L->addStretch();
    tabs->addTab(scrollSign, "签名验证");

    l->addWidget(tabs, 1);
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
        m_chkEnableEntropy->setChecked(enabled["enable_entropy_analysis"].toBool(true));
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
    enabled["enable_entropy_analysis"] = m_chkEnableEntropy->isChecked();
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
