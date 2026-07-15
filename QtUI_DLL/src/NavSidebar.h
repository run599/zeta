#ifndef NAVSIDEBAR_H
#define NAVSIDEBAR_H

#include <QWidget>
#include <QPainterPath>
#include <QStringList>

// ── Custom-painted navigation sidebar ──────────────────────────
// Draws each nav item entirely with QPainter — no QPushButton,
// no QSS, no system controls. Each pixel is controlled.
// Style: dark sidebar, accent selection bar, vector icons.
// ────────────────────────────────────────────────────────────────

class NavSidebar : public QWidget {
    Q_OBJECT
public:
    explicit NavSidebar(QWidget* parent = nullptr);

    // Page index
    int currentIndex() const { return m_currentIndex; }

signals:
    void currentIndexChanged(int index);

public slots:
    void setCurrentIndex(int index);
    void setDriverStatus(bool loaded);  // green/red dot at bottom

protected:
    void paintEvent(QPaintEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;
    void leaveEvent(QEvent* event) override;

private:
    // ── Data per nav item ──
    struct NavItem {
        QString     label;      // display text
        QPainterPath iconPath;  // cached vector icon
    };

    QVector<NavItem> m_items;

    // Interaction state
    int m_currentIndex   = 0;
    int m_hoverIndex     = -1;
    int m_pressedIndex   = -1;
    bool m_driverLoaded  = true;

    // ── Geometry helpers ──
    QRect  itemRect(int index)  const;
    QRect  iconRect(int index)  const;
    QRect  labelRect(int index) const;
    int    itemCount()          const { return m_items.size(); }

    // ── Icon builders ──
    static QPainterPath makeHomeIcon();
    static QPainterPath makeToolsIcon();
    static QPainterPath makeShieldIcon();
    static QPainterPath makeGearIcon();

    // ── Drawing helpers ──
    void drawBackground(QPainter& p);
    void drawLogo(QPainter& p);
    void drawItems(QPainter& p);
    void drawItem(QPainter& p, int idx, bool selected, bool hovered, bool pressed);
    void drawItemIcon(QPainter& p, const QPainterPath& path, const QRect& r,
                      bool selected, bool hovered);
    void drawItemLabel(QPainter& p, const QString& text, const QRect& r,
                       bool selected);
    void drawSelectionBar(QPainter& p, int idx);
    void drawStatus(QPainter& p);
    void drawVersion(QPainter& p);

    // ── Layout constants (all in one place for easy tuning) ──
    static constexpr int kFixedWidth     = 200;
    static constexpr int kItemHeight     = 48;
    static constexpr int kItemMarginX    = 16;
    static constexpr int kIconSize       = 22;
    static constexpr int kBarWidth       = 3;   // selection bar
    static constexpr int kLogoAreaHeight = 80;
    static constexpr int kBottomAreaH    = 48;

    // ── Colors (hard-coded for now; could be themed later) ──
    static inline QColor cBg        { 0x12, 0x12, 0x1f };     // #12121f
    static inline QColor cBgHover   { 0x2a, 0x2a, 0x42 };     // #2a2a42
    static inline QColor cBgPressed { 0x35, 0x35, 0x50 };     // #353550
    static inline QColor cBgSelected{ 0x1e, 0x1e, 0x32 };     // #1e1e32
    static inline QColor cText      { 0xf0, 0xf0, 0xf5 };     // #f0f0f5
    static inline QColor cTextDim   { 0x7a, 0x7a, 0x9a };     // #7a7a9a
    static inline QColor cAccent    { 0x4f, 0x46, 0xe5 };     // #4f46e5
    static inline QColor cGreen     { 0x22, 0xc5, 0x5e };     // #22c55e (online)
    static inline QColor cRed       { 0xef, 0x44, 0x44 };     // #ef4444 (offline)
};

#endif // NAVSIDEBAR_H
