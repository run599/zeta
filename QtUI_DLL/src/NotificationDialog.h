#pragma once
#include <QDialog>
#include <QTimer>
#include <functional>

class NotificationDialog : public QDialog {
    Q_OBJECT
public:
    enum class Level { Info, Warning, Critical };

    // Simple notification (no action buttons)
    static void showNotification(const QString& title, const QString& message, 
                                  Level level = Level::Info);

    // HIPS prompt with block/allow actions
    static void showHipsPrompt(const QString& title, const QString& message,
                                unsigned long pid,
                                std::function<void(unsigned long pid, bool allow)> onAction,
                                Level level = Level::Warning);

protected:
    void closeEvent(QCloseEvent* ev) override;
    void paintEvent(QPaintEvent* ev) override;

private:
    explicit NotificationDialog(const QString& title, const QString& message, 
                                Level level);
    explicit NotificationDialog(const QString& title, const QString& message, 
                                unsigned long pid,
                                std::function<void(unsigned long pid, bool allow)> onAction,
                                Level level);
    void setupNotifyUI();
    void setupHipsUI();
    void setupBase();

    // Per-level helpers
    static QColor bgForLevel(Level l);
    static QString iconForLevel(Level l);

    QString m_title;
    QString m_message;
    Level m_level;
    unsigned long m_pid = 0;
    std::function<void(unsigned long pid, bool allow)> m_onAction;
    QTimer* m_autoCloseTimer = nullptr;

    static int s_cnt;
};
