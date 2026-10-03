#include "NotificationDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScreen>
#include <QApplication>
#include <QCursor>
#include <QCloseEvent>
#include <QPainter>
#include <QFont>

// ── Static members ──
int NotificationDialog::s_cnt = 0;

namespace { constexpr int kW = 380, kH = 145, kHipsW = 430, kHipsH = 210, kGap = 12, kMx = 20, kMy = 60; }

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
      m_pid(pid), m_onAction(onAction) {
    setupBase();
    setupHipsUI();
}

// ── Factory ──
void NotificationDialog::showNotification(const QString& title, const QString& message, Level level) {
    (new NotificationDialog(title, message, level))->show();
}
void NotificationDialog::showHipsPrompt(const QString& title, const QString& message,
    unsigned long pid, std::function<void(unsigned long pid, bool allow)> onAction, Level level) {
    (new NotificationDialog(title, message, pid, onAction, level))->show();
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
    int idx = s_cnt++;
    setFixedSize(kHipsW, kHipsH);
    move(calcPos(idx, kHipsW, kHipsH));

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(16,12,16,12);
    root->setSpacing(5);

    // ── Header row ──
    auto* hdr = new QHBoxLayout();
    auto* icon = new QLabel(iconForLevel(m_level));
    icon->setStyleSheet(kLblIcon);
    icon->setFixedWidth(32);
    auto* tt = new QLabel(m_title);
    tt->setStyleSheet(kLblTitle);
    hdr->addWidget(icon);
    hdr->addWidget(tt, 1);
    root->addLayout(hdr);

    // ── Message ──
    auto* msg = new QLabel(m_message);
    msg->setStyleSheet(kLblMsg);
    msg->setWordWrap(true);
    root->addWidget(msg, 1);

    // ── PID + details ──
    auto* meta = new QHBoxLayout();
    auto* pidLbl = new QLabel(QString("PID: %1").arg(m_pid));
    pidLbl->setStyleSheet(kLblPid);
    meta->addWidget(pidLbl);
    meta->addStretch();
    root->addLayout(meta);

    // ── Buttons ──
    auto* btm = new QHBoxLayout();
    btm->addStretch();

    auto* block = new QPushButton(QStringLiteral("\u963b\u6b62")); // 阻止
    block->setStyleSheet(QString(kBtnStyle) + "QPushButton{background-color:#c0392b;}"
        "QPushButton:hover{background-color:#e74c3c;}");
    block->setFixedHeight(34);
    connect(block, &QPushButton::clicked, this, [this]() {
        hide();
        if (m_onAction) m_onAction(m_pid, false);
        close();
    });
    btm->addWidget(block);

    btm->addSpacing(10);

    auto* allow = new QPushButton(QStringLiteral("\u653e\u884c")); // 放行
    allow->setStyleSheet(QString(kBtnStyle) + "QPushButton{background-color:#27ae60;}"
        "QPushButton:hover{background-color:#2ecc71;}");
    allow->setFixedHeight(34);
    connect(allow, &QPushButton::clicked, this, [this]() {
        hide();
        if (m_onAction) m_onAction(m_pid, true);
        close();
    });
    btm->addWidget(allow);

    btm->addSpacing(2);  // right edge breathing room
    root->addLayout(btm);
}

// ── Close ──
void NotificationDialog::closeEvent(QCloseEvent* ev) {
    s_cnt--;
    if (s_cnt < 0) s_cnt = 0;
    QDialog::closeEvent(ev);
}
