#pragma once
#include <QDialog>
#include <QTimer>
#include <QLabel>
#include <QQueue>
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

    // HIPS 决策只回传一次：按钮点击 / 倒计时归零 / 关窗 三条路径共用
    void sendDecision(bool allow);

    // Per-level helpers
    static QColor bgForLevel(Level l);
    static QString iconForLevel(Level l);

    QString m_title;
    QString m_message;
    Level m_level;
    unsigned long m_pid = 0;
    std::function<void(unsigned long pid, bool allow)> m_onAction;
    QTimer* m_autoCloseTimer = nullptr;

    // ── HIPS 弹窗倒计时相关（2026-10-06）──────────────────────────────
    // 背景：交互弹窗原先既无倒计时、关窗也不回传决策，而驱动侧 30s 超时后
    // 默认拒绝 → 用户看到的"弹窗还在"与"操作已在 30s 时被拒"脱节，
    // 点"放行"实际无效（IRP 已完成）⇒ 幽灵弹窗。
    bool    m_isHips      = false;   // 区分交互弹窗与普通通知（仅前者需回传决策）
    bool    m_decisionSent = false;  // 去重：决策只发一次
    QTimer* m_countdownTimer = nullptr;
    QLabel* m_countdownLbl   = nullptr;
    int     m_remainingSec   = 0;

    // ── HIPS 弹窗队列（2026-10-06）──────────────────────────────────────
    // 问题：原先每来一条 HIPS 事件就新建一个弹窗、按 idx 向屏幕上方堆叠，
    //   ① 越堆越高（第 3~4 个越过屏幕顶），② 越靠上离鼠标越远 → 用户点不到；
    //   ③ 同屏多个待决窗口会分散注意力，容易漏掉真正紧急的那个。
    // 方案：同一时刻只显示 1 个 HIPS 弹窗，其余入队；当前这个关闭后再弹下一个。
    // 约束：驱动侧 PendingOps.cpp 对挂起 IRP 是 30s 硬超时且默认拒绝 ⇒
    //   排队等待超过该时限的请求在驱动侧【早已被判死】，弹出来只会误导用户
    //   （点"放行"也不会生效）。因此轮到它时先做过期检查，过期直接跳过并计数。
    struct HipsRequest {
        QString title;
        QString message;
        unsigned long pid;
        std::function<void(unsigned long pid, bool allow)> onAction;
        Level level;
        qint64 enqueuedMs;      // 入队时刻（毫秒），用于过期判定
    };
    static QQueue<HipsRequest> s_hipsQueue;   // 等待显示的请求
    static NotificationDialog* s_activeHips;  // 当前正在显示的 HIPS 弹窗（无则 nullptr）
    static quint64 s_hipsExpiredSkipped;      // 统计：轮到前已超过驱动程序超时而被跳过
    static quint64 s_hipsRejectedFull;        // 统计：队列满被拒
    static void pumpHipsQueue();              // 显示队首（含过期跳过）

    static int s_cnt;
};
