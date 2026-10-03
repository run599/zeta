#pragma once
#include <Windows.h>
#include <string>
#include <algorithm>

// ============================================================
// amsi_scanner.h — AMSI (反恶意软件扫描接口) 封装
//
// 动态加载 amsi.dll, 对脚本宿主进程的命令行/脚本内容做扫描,
// 弥补"无文件攻击"检测盲区 (IEX DownloadString 等场景)。
// 检测结果: AMSI_RESULT >= 32768 (AMSI_RESULT_DETECTED) 视为命中。
// ============================================================

// 是否为脚本宿主进程 (无文件攻击主要载体)
static inline bool IsScriptHostProcess(const std::wstring& imageName) {
    std::wstring n = imageName;
    std::transform(n.begin(), n.end(), n.begin(), ::towlower);
    return n == L"powershell.exe" || n == L"powershell_ise.exe" ||
           n == L"cscript.exe" || n == L"wscript.exe" ||
           n == L"wmic.exe" || n == L"mshta.exe" || n == L"cmd.exe";
}

class AmsiScanner {
public:
    static AmsiScanner& instance();

    // 扫描一段内容 (如命令行/脚本字符串)
    // 返回 AMSI_RESULT: 0=clean/不可用, 32768+=detected
    int Scan(const wchar_t* content, const wchar_t* contentName);

    bool isAvailable() const { return m_ok; }

private:
    AmsiScanner();
    ~AmsiScanner();
    AmsiScanner(const AmsiScanner&) = delete;

    typedef HRESULT(WINAPI* FnInit)(LPCWSTR appName, void** context);
    typedef HRESULT(WINAPI* FnScanString)(void* context, LPCWSTR string,
                                          LPCWSTR appName, LPCWSTR contentName,
                                          int* result);
    typedef void(WINAPI* FnUninit)(void* context);

    HMODULE m_hAmsi = nullptr;
    void* m_ctx = nullptr;
    bool m_ok = false;
    FnInit m_pInit = nullptr;
    FnScanString m_pScan = nullptr;
    FnUninit m_pUninit = nullptr;
};
