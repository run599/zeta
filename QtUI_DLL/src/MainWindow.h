#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStackedWidget>
#include <QPushButton>
#include <QLabel>
#include <QTextEdit>
#include <QListWidget>
#include <QComboBox>
#include <QCheckBox>
#include <QTableWidget>
#include <QProgressBar>
#include <QGroupBox>
#include <QButtonGroup>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QFrame>
#include <QCloseEvent>
#include <QMessageBox>
#include <QFileDialog>
#include <QApplication>
#include <QHeaderView>
#include <QLineEdit>
#include <QMap>
#include <QSpinBox>
#include <QSystemTrayIcon>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>

class NavSidebar;
class TitleBarButton;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    // Public slots for Bridge to call
public slots:
    void onAppendLog(const QString& level, const QString& action, const QString& detail);
    void onSetTheme(const QString& themeKey);
    
    void onSetDriverStatus(bool loaded);  // 驱动状态同步
    void onSetStatusText(const QString& text);
    void onRestoreSwitch(const QString& key, bool checked);
    // 磁盘底层防护真实状态 (由 zeta_ui_set_disk_status 转发)
    void onDiskStatus(int attached, int blocked, int observed, int mode, int enabled, const QString& info);
    void onRestoreCombo(const QString& name, const QString& value);
    void onSetRepairItem(int index, const QString& status, const QString& result);
    void onSetRepairButtons(bool enabled);
    void onSetRulesPath(const QString& path);
    void onShowNotification(const QString& title, const QString& message, int level);
    void onShowHipsPrompt(const QString& title, const QString& message, unsigned long pid, int level);
    void onUpdateDashboardStats(const QString& level, const QString& action, const QString& detail = QString());
    // 刷新设置页"运行状态"卡的计数
    void refreshSettingsStats();

    // Tool page update slots
    void onRefreshProcessList();
    void onRefreshStartupList();
    void onRefreshJunkScan();
    void onRefreshHipsRules();
    void onRefreshWhitelist();
    void onRefreshQuarantine();
    void onRefreshRansom();   // 勒索恢复: 刷新文档备份/勒索隔离副本索引

signals:
    void configChanged(const QString& key, bool value);

protected:
    bool eventFilter(QObject* obj, QEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;
    void closeEvent(QCloseEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;

private:
    void setupTitleBar(QVBoxLayout* parent);
    void setupSidebar(QHBoxLayout* parent);
    void setupPages();
    void applyTheme(const QString& themeKey);
    // 拦截日志持久化: 从 ZETA_Intercepts.log 加载历史到首页防护日志卡
    void loadInterceptHistory();
    // 把一条拦截记录格式化后追加到首页防护日志卡 (HTML 彩色)
    void appendInterceptHtml(const QString& ts, const QString& src,
                             const QString& proc, const QString& action,
                             const QString& detail);
    // 从详情串粗略提取进程名
    QString extractProcFromDetail(const QString& detail);
    void switchPage(int index);

    // Tool page setup
    void setupToolsPage();
    void showToolPage(int toolIndex);
    void showToolList();

    // Settings page setup (配置型功能已迁入: HIPS / 白名单 / EDR / 网络黑名单)
    void setupSettingsPage();
    void showSettingsMain();
    void showSettingsPage(int index);

    // 通用卡片构造 (供工具页/设置页/防护页复用)
    // propName = "toolIndex" | "settingsIndex", 点击后跳转对应子页
    QFrame* createNavCard(const QString& title, const QString& desc,
                          const QString& propName, int index);
    QFrame* createSwitchCard(const QString& title, const QString& desc, const QString& key);

    // System tray
    void setupTrayIcon();

    // Individual tool page setups
    void setupProcessManager(QWidget* page);
    void setupStartupManager(QWidget* page);
    void setupJunkCleaner(QWidget* page);
    void setupSystemRepair(QWidget* page);
    void setupHipsManager(QWidget* page);
    void setupWhitelistManager(QWidget* page);
    void setupQuarantineManager(QWidget* page);
    void setupRansomRestoreManager(QWidget* page);   // 勒索恢复页
    void setupEdrManager(QWidget* page);
    void setupNetworkMgr(QWidget* page);

    // EDR rule management
    void onRefreshEdrRules();
    void onSaveEdrRules();
    void showEdrList();
    void showEdrPage(int index);
    void setupEdrScanEnginePage(QWidget* page);
    void setupEdrScorePage(QWidget* page);
    void setupEdrApiPage(QWidget* page);
    void setupEdrSectionPage(QWidget* page);
    void setupEdrTrustedPage(QWidget* page);
    void setupEdrExtPage(QWidget* page);

    // HIPS enable toggle persistence
    void saveHipsEnabledToJson();

    // Network blacklist
    void onRefreshNetworkList();
    void onAddNetworkIp();
    void onRemoveNetworkIp();

    // UI elements
    NavSidebar* m_navSidebar = nullptr;
    QWidget* m_titleBar = nullptr;
    QLabel* m_titleLabel = nullptr;
    QStackedWidget* m_stack = nullptr;
    // 自绘矢量标题栏按钮 (关闭 / 最小化 / 关于)
    TitleBarButton* m_ctrlClose = nullptr;
    TitleBarButton* m_ctrlMin = nullptr;
    TitleBarButton* m_ctrlAbout = nullptr;

    // Pages
    QWidget* m_homePage = nullptr;
    QWidget* m_toolsPage = nullptr;
    QWidget* m_protectPage = nullptr;
    QWidget* m_edrPage = nullptr;      // EDR 一级页面 (内容多, 独占整块内容区)
    QWidget* m_settingsPage = nullptr;

    // Home page
    QLabel* m_statusIcon = nullptr;
    QLabel* m_statusText = nullptr;
    QLabel* m_statusSub = nullptr;
    QTextEdit* m_logText = nullptr;
    // Dashboard stats
    QLabel* m_statHipsLabel = nullptr;
    QLabel* m_statEdrLabel = nullptr;
    QLabel* m_statKilledLabel = nullptr;
    QLabel* m_statEvent1 = nullptr;
    QLabel* m_statEvent2 = nullptr;
    QLabel* m_statEvent3 = nullptr;
    QLabel* m_statEvent4 = nullptr;
    QLabel* m_statEvent5 = nullptr;
    int m_statHipsCount = 0;
    int m_statEdrCount = 0;
    int m_statKilledCount = 0;

    // Tools page - sub-stack
    QStackedWidget* m_toolStack = nullptr;
    QPushButton* m_toolBackBtn = nullptr;
    QLabel* m_toolTitleLabel = nullptr;

    // Settings page - sub-stack (配置型子页)
    QStackedWidget* m_settingsStack = nullptr;
    QPushButton* m_settingsBackBtn = nullptr;
    QLabel* m_settingsTitleLabel = nullptr;

    // Tool sub-pages (indices 1-5 in toolStack) — 仅保留"操作型"工具
    enum ToolPageIndex {
        TOOL_LIST = 0,
        PROCESS_MGR = 1,
        STARTUP_MGR = 2,
        JUNK_CLEANER = 3,
        SYSTEM_REPAIR = 4,
        QUARANTINE_MGR = 5,
        RANSOM_RESTORE = 6   // 勒索恢复: 文档写前备份 + 勒索重定向副本
    };
    // Settings sub-pages (indices 1-3 in settingsStack) — "配置型"功能迁入设置
    // EDR 已升级为一级页面 (PAGE_EDR), 不再作为设置子页
    enum SettingsPageIndex {
        SETTINGS_MAIN = 0,
        SET_HIPS = 1,
        SET_WHITELIST = 2,
        SET_NETWORK = 3
    };
    // EDR sub-pages (indices 1-6 in edrStack) — 每个功能单开一页, 表格占满整页
    enum EdrPageIndex {
        EDR_LIST = 0,
        EDR_SCAN_ENGINE = 1,   // 扫描引擎开关 + YARA 路径
        EDR_SCORE = 2,         // 评分权重 + 告警阈值
        EDR_API = 3,           // 危险/高危 API 列表
        EDR_SECTION = 4,       // 可疑节名列表
        EDR_TRUSTED = 5,       // 可信发布者白名单
        EDR_EXT = 6            // 需签名验证的扩展名
    };
    // 主 stack 页面索引 (须与 NavSidebar 的 kItems 顺序一致)
    enum MainPageIndex {
        PAGE_HOME = 0,
        PAGE_TOOLS = 1,
        PAGE_PROTECT = 2,
        PAGE_EDR = 3,
        PAGE_SETTINGS = 4
    };

    // Process manager
    QTableWidget* m_procTable = nullptr;
    QLabel* m_procCountLabel = nullptr;

    // Startup manager
    QTableWidget* m_startupTable = nullptr;

    // Junk cleaner
    QTableWidget* m_junkTable = nullptr;
    QLabel* m_junkSizeLabel = nullptr;
    QPushButton* m_junkCleanBtn = nullptr;

    // System repair
    QTableWidget* m_repairTable = nullptr;
    QPushButton* m_repairExecBtn = nullptr;

    // HIPS manager
    QTableWidget* m_hipsTable = nullptr;
    QString m_rulesPath;
    struct HipsRuleItem {
        QString id;
        QString code;
        QString process;
        QString target;
        int action;   // 0=allow, 1=deny, 2=ask
        int score;
        bool enabled;
    };
    QVector<HipsRuleItem> m_rules;

    // Whitelist manager
    QTableWidget* m_whitelistTable = nullptr;
    QLineEdit* m_whitelistPathEdit = nullptr;

    // Quarantine manager
    QTableWidget* m_quarantineTable = nullptr;

    // 勒索防护备份 — ZETA_DocBackup 文档备份 / ZETA_Quarantine 重定向副本
    QTableWidget* m_ransomTable = nullptr;
    QLabel* m_ransomStatLabel = nullptr;      // 概览条: 备份数 / 占用 / 最近备份时间
    QLineEdit* m_docBackupExtEdit = nullptr;  // 备份扩展名规则 (Rules_FileProtect.json)

    // EDR manager
    QStackedWidget* m_edrStack = nullptr;
    QPushButton* m_edrBackBtn = nullptr;
    QLabel* m_edrPageTitle = nullptr;   // EDR 页标题 (进入子页时追加 · 子页名)
    QTableWidget* m_edrApiTable = nullptr;
    QTableWidget* m_edrSectionTable = nullptr;
    QTableWidget* m_edrTrustedTable = nullptr;
    QTableWidget* m_edrRequiredExtTable = nullptr;

    // Network blacklist manager
    QTableWidget* m_netTable = nullptr;
    QLineEdit* m_netIpEdit = nullptr;
    QSpinBox* m_netPortSpin = nullptr;
    QLineEdit* m_edrYaraPathEdit = nullptr;
    QLineEdit* m_edrTrustedEdit = nullptr;
    QLineEdit* m_edrExtEdit = nullptr;
    
    // Score inputs
    QSpinBox* m_spinSuspiciousApi = nullptr;
    QSpinBox* m_spinHighRiskApi = nullptr;
    QSpinBox* m_spinSuspiciousSection = nullptr;
    QSpinBox* m_spinRwxSection = nullptr;
    QSpinBox* m_spinHighEntropy = nullptr;
    QSpinBox* m_spinNoEntryPoint = nullptr;
    QSpinBox* m_spinUnsigned = nullptr;
    QSpinBox* m_spinYaraMatch = nullptr;
    QSpinBox* m_spinThreatThreshold = nullptr;
    QSpinBox* m_spinHighThreatThreshold = nullptr;
    
    // Scan switches
    QCheckBox* m_chkEnableYara = nullptr;
    QCheckBox* m_chkEnablePeHeuristics = nullptr;
    QCheckBox* m_chkEnableSignature = nullptr;
    // (entropy checkbox removed - integrated into PE heuristics)
    
    // API/Section inputs
    QLineEdit* m_edrApiEdit = nullptr;
    QLineEdit* m_edrSectionEdit = nullptr;

    

    // Settings page (学习模式开关已并入"防护"页, 此处不再持有)
    // 运行状态卡 (真实数据, 由 onSetDriverStatus / onSetRulesPath / onUpdateDashboardStats 刷新)
    QLabel* m_setDriverLabel = nullptr;
    QLabel* m_setRulesLabel = nullptr;
    QLabel* m_setHipsLabel = nullptr;
    QLabel* m_setEdrLabel = nullptr;
    QLabel* m_setKillLabel = nullptr;

    // 防护页 8 个开关: key -> QCheckBox, 供 onRestoreSwitch 回填真实状态 (P2-1 修复)
    QMap<QString, QCheckBox*> m_protectSwitches;

    // 磁盘底层防护状态展示 (由驱动 IOCTL 回填真实状态, 不再依赖服务启动结果猜测)
    QLabel* m_diskStatusLabel = nullptr;
    QLabel* m_diskStatLabel = nullptr;

    // Window dragging
    bool m_dragging = false;
    QPoint m_dragPos;

    // System tray
    QSystemTrayIcon* m_trayIcon = nullptr;
    QMenu* m_trayMenu = nullptr;

    // Current theme
    QString m_currentTheme = "system_switch";

    // Driver status
    bool m_driverLoaded = true;

    struct Theme {
        // 背景层
        QString bgWindow, bgNav, bgPanel, bgHover, bgActive;
        // 文字
        QString textPrimary, textSecondary, textDisabled;
        // 描边
        QString border, borderStrong;
        // 主题色
        QString accent, accentHover, onAccent;
        // 语义色
        QString success, warning, danger, onDanger;
        // 阴影
        QString shadowColor;
    };
    QMap<QString, Theme> m_themes;
    void initThemes();
    QString buildStylesheet(const Theme& t);
};

#endif // MAINWINDOW_H
