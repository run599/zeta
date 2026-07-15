#include "NavSidebar.h"
#include <QPainter>
#include <QMouseEvent>
#include <QFontMetrics>

// ═══════════════════════════════════════════════════════════════
// Constructor — initialise nav items with labels and vector icons
// ═══════════════════════════════════════════════════════════════
NavSidebar::NavSidebar(QWidget* parent)
    : QWidget(parent)
{
    setFixedWidth(kFixedWidth);
    setMouseTracking(true);   // needed for hover detection
    setCursor(Qt::ArrowCursor);

    struct { const char* label; QPainterPath(*icon)(); } kItems[] = {
        { "  首页",    makeHomeIcon   },
        { "  工具",    makeToolsIcon  },
        { "  防护",    makeShieldIcon },
        { "  设置",    makeGearIcon   },
    };
    for (auto& ki : kItems)
        m_items.push_back({ QString::fromUtf8(ki.label), ki.icon() });
}

// ═══════════════════════════════════════════════════════════════
// Geometry helpers
// ═══════════════════════════════════════════════════════════════
QRect NavSidebar::itemRect(int idx) const {
    int y = kLogoAreaHeight + idx * kItemHeight;
    return { 0, y, width(), kItemHeight };
}

QRect NavSidebar::iconRect(int idx) const {
    QRect ir = itemRect(idx);
    int x = kItemMarginX + kBarWidth + 8;
    int y = ir.center().y() - kIconSize / 2;
    return { x, y, kIconSize, kIconSize };
}

QRect NavSidebar::labelRect(int idx) const {
    QRect ir = itemRect(idx);
    QRect ic = iconRect(idx);
    int x = ic.right() + 8;
    return { x, ir.top(), ir.right() - x, ir.height() };
}

// ═══════════════════════════════════════════════════════════════
// Vector icon builders (pure QPainterPath — no external files)
// ═══════════════════════════════════════════════════════════════

QPainterPath NavSidebar::makeHomeIcon() {
    QPainterPath path;
    path.moveTo(12, 2);
    path.lineTo(20, 10);
    path.lineTo(20, 20);
    path.lineTo(4, 20);
    path.lineTo(4, 10);
    path.closeSubpath();
    path.moveTo(8, 14);
    path.lineTo(8, 20);
    path.lineTo(16, 20);
    path.lineTo(16, 14);
    path.lineTo(12, 11);
    path.closeSubpath();
    return path;
}

QPainterPath NavSidebar::makeToolsIcon() {
    QPainterPath path;
    path.moveTo(18, 3);
    path.lineTo(20, 5);
    path.lineTo(20, 8);
    path.lineTo(16, 12);
    path.lineTo(13, 9);
    path.lineTo(8, 14);
    path.lineTo(6, 12);
    path.lineTo(10, 8);
    path.lineTo(8, 5);
    path.lineTo(5, 8);
    path.lineTo(3, 6);
    path.lineTo(6, 3);
    path.lineTo(9, 3);
    path.lineTo(13, 4);
    path.lineTo(16, 1);
    path.lineTo(18, 3);
    path.closeSubpath();
    return path;
}

QPainterPath NavSidebar::makeShieldIcon() {
    QPainterPath path;
    path.moveTo(12, 2);
    path.cubicTo(18, 2, 20, 6, 20, 12);
    path.lineTo(12, 21);
    path.lineTo(4, 12);
    path.cubicTo(4, 6, 6, 2, 12, 2);
    path.closeSubpath();
    path.moveTo(8, 13);
    path.lineTo(11, 16);
    path.lineTo(16, 9);
    return path;
}

QPainterPath NavSidebar::makeGearIcon() {
    QPainterPath path;
    const int cx = 12, cy = 12, rOuter = 10, rInner = 6;
    const int teeth = 8;
    for (int i = 0; i < teeth * 2; i++) {
        double angle = (i * 360.0 / (teeth * 2) - 90) * M_PI / 180.0;
        int r = (i % 2 == 0) ? rOuter : rInner;
        double px = cx + r * cos(angle);
        double py = cy + r * sin(angle);
        if (i == 0) path.moveTo(px, py);
        else        path.lineTo(px, py);
    }
    path.closeSubpath();
    path.addEllipse(cx - 4, cy - 4, 8, 8);
    return path;
}

// ═══════════════════════════════════════════════════════════════
// Event handlers
// ═══════════════════════════════════════════════════════════════
void NavSidebar::setCurrentIndex(int index) {
    if (index != m_currentIndex && index >= 0 && index < itemCount()) {
        m_currentIndex = index;
        update();
        emit currentIndexChanged(index);
    }
}

void NavSidebar::setDriverStatus(bool loaded) {
    m_driverLoaded = loaded;
    update();
}

void NavSidebar::mouseMoveEvent(QMouseEvent* event) {
    int oldHover = m_hoverIndex;
    m_hoverIndex = -1;
    for (int i = 0; i < itemCount(); i++) {
        if (itemRect(i).contains(event->pos())) {
            m_hoverIndex = i;
            break;
        }
    }
    if (oldHover != m_hoverIndex)
        update();
}

void NavSidebar::mousePressEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) {
        m_pressedIndex = -1;
        for (int i = 0; i < itemCount(); i++) {
            if (itemRect(i).contains(event->pos())) {
                m_pressedIndex = i;
                update();
                break;
            }
        }
    }
}

void NavSidebar::mouseReleaseEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton && m_pressedIndex >= 0) {
        int idx = m_pressedIndex;
        m_pressedIndex = -1;
        // Only activate if still hovering over the same item
        if (itemRect(idx).contains(event->pos()) && idx != m_currentIndex)
            setCurrentIndex(idx);
        else
            update();
    }
}

void NavSidebar::leaveEvent(QEvent*) {
    if (m_hoverIndex >= 0) {
        m_hoverIndex = -1;
        update();
    }
}

// ═══════════════════════════════════════════════════════════════
// Paint — the main event: every pixel is drawn by QPainter
// ═══════════════════════════════════════════════════════════════
void NavSidebar::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    drawBackground(p);
    drawLogo(p);
    drawItems(p);
    drawStatus(p);
    drawVersion(p);
}

// ── Background fill ──
void NavSidebar::drawBackground(QPainter& p) {
    p.fillRect(rect(), cBg);
}

// ── Logo / title area ──
void NavSidebar::drawLogo(QPainter& p) {
    QRect logoRect(0, 0, width(), kLogoAreaHeight);

    QPainterPath shield = makeShieldIcon();
    QRect sr(18, 18, 32, 32);
    p.setPen(Qt::NoPen);
    p.setBrush(cAccent);
    p.translate(sr.topLeft());
    p.scale(sr.width() / 24.0, sr.height() / 24.0);
    p.drawPath(shield);
    p.resetTransform();

    QFont titleFont = font();
    titleFont.setPixelSize(18);
    titleFont.setBold(true);
    p.setFont(titleFont);
    p.setPen(cText);
    p.drawText(58, 20, 130, 28, Qt::AlignLeft | Qt::AlignVCenter, "ZETA");

    QFont subFont = font();
    subFont.setPixelSize(10);
    subFont.setLetterSpacing(QFont::AbsoluteSpacing, 4);
    p.setFont(subFont);
    p.setPen(cTextDim);
    p.drawText(58, 42, 130, 20, Qt::AlignLeft | Qt::AlignVCenter, "SECURITY");
}

// ── Draw all nav items ──
void NavSidebar::drawItems(QPainter& p) {
    for (int i = 0; i < itemCount(); i++) {
        bool sel = (i == m_currentIndex);
        bool hov = (i == m_hoverIndex);
        bool prs = (i == m_pressedIndex);
        drawItem(p, i, sel, hov, prs);
    }
}

// ── Single nav item ──
void NavSidebar::drawItem(QPainter& p, int idx, bool selected,
                          bool hovered, bool pressed) {
    QRect ir = itemRect(idx);

    // Background
    if (selected)
        p.fillRect(ir, cBgSelected);
    else if (pressed)
        p.fillRect(ir, cBgPressed);
    else if (hovered)
        p.fillRect(ir, cBgHover);

    // Selection bar (left accent line)
    if (selected)
        drawSelectionBar(p, idx);

    // Icon
    drawItemIcon(p, m_items[idx].iconPath, iconRect(idx), selected, hovered);
    // Label
    drawItemLabel(p, m_items[idx].label, labelRect(idx), selected);
}

// ── Selection bar ──
void NavSidebar::drawSelectionBar(QPainter& p, int idx) {
    QRect ir = itemRect(idx);
    QRect bar(0, ir.top() + 4, kBarWidth, ir.height() - 8);
    p.setPen(Qt::NoPen);
    p.setBrush(cAccent);
    p.drawRoundedRect(bar, 2, 2);
}

// ── Icon ──
void NavSidebar::drawItemIcon(QPainter& p, const QPainterPath& path,
                              const QRect& r, bool selected, bool hovered) {
    Q_UNUSED(hovered);

    // Scale & translate the path to fit the icon rect
    QRectF bounds = path.boundingRect();
    double sx = r.width()  / bounds.width();
    double sy = r.height() / bounds.height();
    double s = qMin(sx, sy) * 0.85;   // 85% of cell, leaving padding

    double ox = r.center().x() - bounds.center().x() * s;
    double oy = r.center().y() - bounds.center().y() * s;

    p.save();
    p.translate(ox, oy);
    p.scale(s, s);
    p.setPen(Qt::NoPen);
    p.setBrush(selected ? cAccent : cTextDim);
    p.drawPath(path);
    p.restore();
}

// ── Label ──
void NavSidebar::drawItemLabel(QPainter& p, const QString& text,
                               const QRect& r, bool selected) {
    QFont f = font();
    f.setPixelSize(14);
    f.setBold(selected);
    p.setFont(f);
    p.setPen(selected ? cText : cTextDim);
    p.drawText(r, Qt::AlignLeft | Qt::AlignVCenter, text);
}

// ── Status indicator (green/red dot) ──
void NavSidebar::drawStatus(QPainter& p) {
    int y = height() - kBottomAreaH;
    QRect statusRect(0, y, width(), kBottomAreaH);

    // Dot
    int dotX = kItemMarginX + kBarWidth + 8;
    int dotY = statusRect.center().y();
    p.setPen(Qt::NoPen);
    p.setBrush(m_driverLoaded ? cGreen : cRed);
    p.drawEllipse(QPointF(dotX, dotY), 5, 5);

    // Label
    QFont f = font();
    f.setPixelSize(12);
    p.setFont(f);
    p.setPen(cTextDim);
    p.drawText(dotX + 14, statusRect.top(),
               width() - dotX - 14, statusRect.height(),
               Qt::AlignLeft | Qt::AlignVCenter,
               m_driverLoaded ? "驱动已加载" : "驱动离线");
}

// ── Version text ──
void NavSidebar::drawVersion(QPainter& p) {
    QFont f = font();
    f.setPixelSize(10);
    p.setFont(f);
    p.setPen(cTextDim);
    p.drawText(rect(), Qt::AlignBottom | Qt::AlignHCenter, "v2.0.0");
}
