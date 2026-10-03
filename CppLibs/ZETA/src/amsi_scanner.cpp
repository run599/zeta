// ============================================================
// amsi_scanner.cpp — AMSI 封装实现
//
// 动态加载 amsi.dll (Win10 1607+ 系统自带), 惰性初始化。
// ZETA.exe 以管理员运行, 可正常注册 AMSI provider 上下文。
// ============================================================

#include "amsi_scanner.h"

AmsiScanner& AmsiScanner::instance() {
    static AmsiScanner s;
    return s;
}

AmsiScanner::AmsiScanner() {
    m_hAmsi = LoadLibraryW(L"amsi.dll");
    if (!m_hAmsi) return;
    m_pInit   = (FnInit)GetProcAddress(m_hAmsi, "AmsiInitialize");
    m_pScan   = (FnScanString)GetProcAddress(m_hAmsi, "AmsiScanString");
    m_pUninit = (FnUninit)GetProcAddress(m_hAmsi, "AmsiUninitialize");
    if (!m_pInit || !m_pScan || !m_pUninit) return;
    if (FAILED(m_pInit(L"ZETA", &m_ctx))) return;
    m_ok = true;
}

AmsiScanner::~AmsiScanner() {
    if (m_ok && m_pUninit && m_ctx) m_pUninit(m_ctx);
    if (m_hAmsi) FreeLibrary(m_hAmsi);
}

int AmsiScanner::Scan(const wchar_t* content, const wchar_t* contentName) {
    if (!m_ok || !content) return 0;
    int result = 0;
    HRESULT hr = m_pScan(m_ctx, content, L"ZETA",
                         contentName ? contentName : L"script", &result);
    if (FAILED(hr)) return 0;
    return result;
}
