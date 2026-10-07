#include "NotificationDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScreen>
#include <QApplication>
#include <QCursor>
#include <QCloseEvent>
#include <QDateTime>
#include <QPainter>
#include <QFont>

// ── Static members ──
int NotificationDialog::s_cnt = 0;

// HIPS 队列状态（2026-10-06）
QQueue<NotificationDialog::HipsRequest> NotificationDialog::s_hipsQueue;
NotificationDialog* NotificationDialog::s_activeHips = nullptr;
quint64 NotificationDialog::s_hipsExpiredSkipped = 0;
quint64 NotificationDialog::s_hipsRejectedFull = 0;

namespace {
constexpr int kW = 380, kH = 145, kGap = 12, kMx = 20, kMy = 60;

// HIPS 弹窗改【长条】：原先 430x210 的方块里信息要竖着挤，长路径/长消息看不全。
// 现改为 860x104 的横向条：图标 + 标题 + 详情一行排开，按钮固定在右侧（好点）。
constexpr int kHipsW = 860, kHipsH = 104;

// 队列上限：同时只显示 1 个，其余排队。上限刻意取小 ——
// 驱动侧只有 30s 决策窗口，排太长的队必然全部过期，留着只会误导用户。
constexpr int kHipsQueueMax = 6;


// ── HIPS 决策超时（2026-10-06）────────────────────────────────────────
// 必须与驱动 Plugins\Filter\PendingOps.cpp 的 PENDING_TIMEOUT_100NS（30 秒）
// 保持一致：UI 倒计时先到 → 主动回传默认决策；驱动侧超时仅作后端兜底。
// 两侧若漂移，就会出现"UI 已给结论、驱动还在挂起"或反向的错位。
constexpr int kHipsDecisionTimeoutSec = 30;
}


static QPoint calcPos(int idx, int w, int h) {
    // Use the screen under the cursor — most likely where user attention is
    QScreen* scr = QApplication::screenAt(QCursor::pos());
    if (!scr) scr = QApplication::primaryScreen();
    QRect rc = scr ? scr->availableGeometry() : QRect(0,0,1920,1080);
    // rc.right()/bottom() are absolute virtual-desktop coordinates,
    // rc.width()/height() are relative dimensions → would be wrong
    // when the screen origin isn't (0,0).
    return QPoint(rc.right() - w + 1 - kMx,
                  rc.bottom() - h + 1 - kMy - idx*(h + kGap));
}

// ── Colors ──
QColor NotificationDialog::bgForLevel(Level l) {
    switch (l) {
        case Level::Info:     return QColor(52, 152, 219);   // blue
        case Level::Warning:  return QColor(243, 156, 18);   // orange
        case Level::Critical: return QColor(192, 57, 43);    // red
    }
    return QColor(52, 152, 219);
}

QString NotificationDialog::iconForLevel(Level l) {
    // Use emoji that render reliably on Windows
    switch (l) {
        case Level::Info:     return QString::fromUtf8("\u2139\ufe0f");  // ℹ️
        case Level::Warning:  return QString::fromUtf8("\u26a0\ufe0f");  // ⚠️
        case Level::Critical: return QString::fromUtf8("\u274c");        // ❌
    }
    return QString::fromUtf8("\u2139\ufe0f");
}

// ── Base setup shared by both types ──
void NotificationDialog::setupBase() {
    setWindowFlags(Qt::Tool | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint);
    setAttribute(Qt::WA_ShowWithoutActivating);
    setAttribute(Qt::WA_DeleteOnClose);
    setAttribute(Qt::WA_TranslucentBackground);
}

// ── Simple notification constructor ──
NotificationDialog::NotificationDialog(const QString& title, const QString& message, Level level)
    : QDialog(nullptr), m_title(title), m_message(message), m_level(level) {
    setupBase();
    setupNotifyUI();
}

// ── HIPS prompt constructor ──
NotificationDialog::NotificationDialog(const QString& title, const QString& message,
    unsigned long pid, std::function<void(unsigned long pid, bool allow)> onAction, Level level)
    : QDialog(nullptr), m_title(title), m_message(message), m_level(level),
      m_pid(pid), m_onAction(onAction), m_isHips(true) {
    setupBase();
    setupHipsUI();
}

// ── HIPS 决策回传（去重）──────────────────────────────────────────────
// 只有这里能触达 m_onAction。三条路径都汇到此处，保证：
//   · 决策恰好发送一次（m_decisionSent 去重）
//   · 弹窗被任何方式关闭之前，至少有一次决策发出（杜绝幽灵弹窗）
void NotificationDialog::sendDecision(bool allow) {
    if (m_decisionSent) return;
    m_decisionSent = true;
    if (m_countdownTimer) m_countdownTimer->stop();
    if (m_onAction) m_onAction(m_pid, allow);
}

// ── Factory ──
void NotificationDialog::showNotification(const QString& title, const QString& message, Level level) {
    (new NotificationDialog(title, message, level))->show();
}
// 队列化：同一时刻只显示一个 HIPS 弹窗（2026-10-06）
void NotificationDialog::showHipsPrompt(const QString& title, const QString& message,
    unsigned long pid, std::function<void(unsigned long pid, bool allow)> onAction, Level level) {
    HipsRequest req;
    req.title = title;
    req.message = message;
    req.pid = pid;
    req.onAction = onAction;
    req.level = level;
    req.enqueuedMs = QDateTime::currentMSecsSinceEpoch();

    if (s_activeHips) {
        // 已有弹窗在显示：排队；队列满则拒绝新请求（不替用户做"未展示"的决策）
        if (s_hipsQueue.size() >= kHipsQueueMax) {
            s_hipsRejectedFull++;
            return;
        }
        s_hipsQueue.enqueue(req);
        return;
    }
    // 无弹窗在显示：直接走 pump（内部负责过期检查）
    s_hipsQueue.enqueue(req);
    pumpHipsQueue();
}

// 显示队首请求；若轮到它时已超过驱动侧的决策超时，则跳过（驱动早已默认拒绝）
void NotificationDialog::pumpHipsQueue() {
    while (s_activeHips == nullptr && !s_hipsQueue.isEmpty()) {
        HipsRequest req = s_hipsQueue.dequeue();
        const qint64 waitedMs = QDateTime::currentMSecsSinceEpoch() - req.enqueuedMs;
        if (waitedMs > static_cast<qint64>(kHipsDecisionTimeoutSec) * 1000) {
            // 驱动侧 PendingOps 的 30s 超时已把该 IRP 判为拒绝；
            // 此时再弹窗只会让用户误以为还能改判 ⇒ 直接跳过并计数。
            s_hipsExpiredSkipped++;
            continue;
        }
        auto* dlg = new NotificationDialog(req.title, req.message, req.pid, req.onAction, req.level);
        s_activeHips = dlg;
        dlg->show();
    }
}

// ── Paint rounded rect with background color ──
void NotificationDialog::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    p.setBrush(bgForLevel(m_level));
    p.setPen(Qt::NoPen);
    p.drawRoundedRect(rect().adjusted(1,1,-1,-1), 10, 10);
}

// ── Stylesheet helper ──
static const char* kBtnStyle = R"(
    QPushButton {
        color: white; border:none; border-radius:5px;
        padding:7px 22px; font-size:13px; font-weight:bold;
    }
)";
static const char* kLblTitle = "color:white;font-size:15px;font-weight:bold;background:transparent;";
static const char* kLblMsg   = "color:rgba(255,255,255,0.88);font-size:12px;background:transparent;";
static const char* kLblPid   = "color:rgba(255,255,255,0.55);font-size:11px;background:transparent;";
static const char* kLblIcon  = "font-size:22px;background:transparent;";

// ── Simple notification ──
void NotificationDialog::setupNotifyUI() {
    int idx = s_cnt++;
    setFixedSize(kW, kH);
    move(calcPos(idx, kW, kH));

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(16,12,16,10);
    root->setSpacing(5);

    auto* hdr = new QHBoxLayout();
    auto* icon = new QLabel(iconForLevel(m_level));
    icon->setStyleSheet(kLblIcon);
    icon->setFixedWidth(32);
    auto* tt = new QLabel(m_title);
    tt->setStyleSheet(kLblTitle);
    hdr->addWidget(icon);
    hdr->addWidget(tt, 1);
    root->addLayout(hdr);

    auto* msg = new QLabel(m_message);
    msg->setStyleSheet(kLblMsg);
    msg->setWordWrap(true);
    root->addWidget(msg, 1);

    auto* closeBtn = new QPushButton(QStringLiteral("\u5173\u95ed")); // 关闭
    closeBtn->setStyleSheet(QString(kBtnStyle) + "QPushButton{background-color:rgba(255,255,255,0.18);}"
        "QPushButton:hover{background-color:rgba(255,255,255,0.30);}");
    closeBtn->setFixedSize(58, 28);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::close);
    auto* btm = new QHBoxLayout();
    btm->addStretch();
    btm->addWidget(closeBtn);
    root->addLayout(btm);

    m_autoCloseTimer = new QTimer(this);
    connect(m_autoCloseTimer, &QTimer::timeout, this, &QDialog::close);
    m_autoCloseTimer->start(8000);
}

// ── HIPS prompt ──
void NotificationDialog::setupHipsUI() {
    // ── 长条布局（2026-10-06）────────────────────────────────────────────
    // 由 430x210 的竖排方块改为 860x104 的横条：
    //   [图标]  标题（粗）                 [N 秒后自动拒绝]
    //           详情（单行省略+悬停全文）  [阻止] [放行]
    // 队列化后同屏只会有这一个 HIPS 弹窗，位置固定右下角，不再按 idx 向屏幕上方堆叠
    // （原先堆到第 3~4 个会越过屏幕顶，且越靠上离鼠标越远 → 点不到）。
    setFixedSize(kHipsW, kHipsH);
    move(calcPos(0, kHipsW, kHipsH));   // idx 固定 0：不参与堆叠

    auto* root = new QHBoxLayout(this);
    root->setContentsMargins(16, 10, 16, 10);
    root->setSpacing(12);

    // ── 左：图标 ──
    auto* icon = new QLabel(iconForLevel(m_level));
    icon->setStyleSheet(kLblIcon);
    icon->setFixedWidth(34);
    icon->setAlignment(Qt::AlignTop | Qt::AlignHCenter);
    root->addWidget(icon);

    // ── 中：标题 + 详情（占据剩余宽度）──
    auto* mid = new QVBoxLayout();
    mid->setSpacing(3);
    auto* tt = new QLabel(m_title);
    tt->setStyleSheet(kLblTitle);
    tt->setToolTip(m_title);
    mid->addWidget(tt);

    auto* msg = new QLabel(m_message);
    msg->setStyleSheet(kLblMsg);
    msg->setToolTip(m_message);            // 长文本悬停看全文
    msg->setWordWrap(false);               // 长条：单行 + 右侧省略，避免撑高
    msg->setTextInteractionFlags(Qt::TextSelectableByMouse);
    mid->addWidget(msg);
    mid->addStretch();
    root->addLayout(mid, 1);

    // ── 右：倒计时 + 按钮（固定宽度，按钮位置稳定=好点）──
    auto* right = new QVBoxLayout();
    right->setSpacing(4);

    m_countdownLbl = new QLabel();
    m_countdownLbl->setStyleSheet(kLblPid);
    m_countdownLbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    right->addWidget(m_countdownLbl);

    auto* pidLbl = new QLabel(QString("PID: %1").arg(m_pid));
    pidLbl->setStyleSheet(kLblPid);
    pidLbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    right->addWidget(pidLbl);

    auto* btm = new QHBoxLayout();
    btm->setSpacing(8);

    auto* block = new QPushButton(QStringLiteral("\u963b\u6b62")); // 阻止
    block->setStyleSheet(QString(kBtnStyle) + "QPushButton{background-color:#c0392b;}"
        "QPushButton:hover{background-color:#e74c3c;}");
    block->setFixedSize(84, 32);
    connect(block, &QPushButton::clicked, this, [this]() {
        hide();
        sendDecision(false);   // 去重回传：阻止
        close();
    });
    btm->addWidget(block);

    auto* allow = new QPushButton(QStringLiteral("\u653e\u884c")); // 放行
    allow->setStyleSheet(QString(kBtnStyle) + "QPushButton{background-color:#27ae60;}"
        "QPushButton:hover{background-color:#2ecc71;}");
    allow->setFixedSize(84, 32);
    connect(allow, &QPushButton::clicked, this, [this]() {
        hide();
        sendDecision(true);    // 去重回传：放行
        close();
    });
    btm->addWidget(allow);

    right->addLayout(btm);
    root->addLayout(right);

    // 详情标签按可用宽度做省略（长路径不撑破长条）
    msg->setMinimumWidth(200);

    // ── 倒计时（2026-10-06）─────────────────────────────────────────────
    // 归零即按【默认=拒绝】回传，与驱动 CheckPendingTimeouts 的超时语义一致；
    // 这样窗口消失与决策发出必然成对出现，不会再出现"弹窗还在、操作早被拒"。
    m_remainingSec = kHipsDecisionTimeoutSec;
    auto refreshCountdown = [this]() {
        if (m_countdownLbl) {
            m_countdownLbl->setText(
                QString::fromUtf8("%1 秒后自动拒绝").arg(m_remainingSec));
        }
    };
    refreshCountdown();

    m_countdownTimer = new QTimer(this);
    connect(m_countdownTimer, &QTimer::timeout, this, [this, refreshCountdown]() {
        if (--m_remainingSec <= 0) {
            if (m_countdownTimer) m_countdownTimer->stop();
            sendDecision(false);   // 超时 = 拒绝（与驱动默认策略一致）
            close();
        } else {
            refreshCountdown();
        }
    });
    m_countdownTimer->start(1000);
}

// ── Close ──
void NotificationDialog::closeEvent(QCloseEvent* ev) {
    // 2026-10-06 幽灵弹窗修复：HIPS 弹窗若在【未决策】时被关闭（✕ / Esc / 其它方式），
    // 必须按默认（拒绝）回传决策。否则驱动侧会一直挂起到自己的 30s 超时才收场，
    // 而用户看到的"弹窗已关"并不代表任何决策 —— 事后点"放行"也无从生效。
    // 普通通知（m_isHips=false）不受影响，其 8s 自动关闭不产生决策。
    if (m_isHips) {
        sendDecision(false);
        // 队列续弹：本窗结束（无论按钮/倒计时/✕/Esc）后立即显示下一个。
        // 用 singleShot(0) 延到事件循环下一轮 —— 此刻对象仍在 WA_DeleteOnClose 的
        // 析构路径上，同步新建窗口容易在同一次栈里操作到半销毁状态。
        if (s_activeHips == this) s_activeHips = nullptr;
        QTimer::singleShot(0, []() { pumpHipsQueue(); });
    }
    s_cnt--;
    if (s_cnt < 0) s_cnt = 0;
    QDialog::closeEvent(ev);
}
