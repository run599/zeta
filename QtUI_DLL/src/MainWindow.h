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
    void onRestoreCombo(const QString& name, const QString& value);
    void onSetRepairItem(int index, const QString& status, const QString& result);
    void onSetRepairButtons(bool enabled);
    void onSetRulesPath(const QString& path);
    void onShowNotification(const QString& title, const QString& message, int level);
    void onShowHipsPrompt(const QString& title, const QString& message, unsigned long pid, int level);
    void onUpdateDashboardStats(const QString& level, const QString& action, const QString& detail = QString());

    // Tool page update slots
    void onRefreshProcessList();
    void onRefreshStartupList();
    void onRefreshJunkScan();
    void onRefreshHipsRules();
    void onRefreshWhitelist();
    void onRefreshQuarantine();

signals:
    void configChanged(const QString& key, bool value);

protected:
    bool eventFilter(QObject* obj, QEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;
    void closeEvent(QCloseEvent* event) override;

private:
    void setupTitleBar(QVBoxLayout* parent);
    void setupSidebar(QHBoxLayout* parent);
    void setupPages();
    void applyTheme(const QString& themeKey);
    void switchPage(int index);

    // Tool page setup
    void setupToolsPage();
    void showToolPage(int toolIndex);
    void showToolList();

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
    void setupEdrManager(QWidget* page);

    // EDR rule management
    void onRefreshEdrRules();
    void onSaveEdrRules();

    // UI elements
    NavSidebar* m_navSidebar = nullptr;
    QWidget* m_titleBar = nullptr;
    QLabel* m_titleLabel = nullptr;
    QStackedWidget* m_stack = nullptr;

    // Pages
    QWidget* m_homePage = nullptr;
    QWidget* m_toolsPage = nullptr;
    QWidget* m_protectPage = nullptr;
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

    // Tool sub-pages (indices 1-9 in toolStack)
    enum ToolPageIndex {
        TOOL_LIST = 0,
        PROCESS_MGR = 1,
        STARTUP_MGR = 2,
        JUNK_CLEANER = 3,
        SYSTEM_REPAIR = 4,
        HIPS_MGR = 5,
        WHITELIST_MGR = 6,
        QUARANTINE_MGR = 7,
        EDR_MGR = 8
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

    // EDR manager
    QTableWidget* m_edrApiTable = nullptr;
    QTableWidget* m_edrSectionTable = nullptr;
    QTableWidget* m_edrTrustedTable = nullptr;
    QTableWidget* m_edrRequiredExtTable = nullptr;
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

    

    // Settings page
    QCheckBox* m_learningSwitch = nullptr;
    QComboBox* m_langCombo = nullptr;

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
        QString bgWindow, bgNav, bgPanel, bgHover;
        QString textPrimary, textSecondary, border;
        QString accent, accentHover, danger;
    };
    QMap<QString, Theme> m_themes;
    void initThemes();
    QString buildStylesheet(const Theme& t);
};

#endif // MAINWINDOW_H
