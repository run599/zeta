#include "zeta_core.h"
#include <Windows.h>
#include <codecvt>

// C DLL exports
extern "C" {

// P0-崩溃修复(根治): C++ 异常绝不能穿过 extern "C" DLL 导出边界。
// zeta_core_log 是日志高频入口, 若 detail 含非法 UTF-16 (如 \??\ 混合路径)
// Logger::log 内部 to_bytes 抛异常逃逸 → std::terminate → __fastfail
// → ucrtbase.dll c0000409 崩溃。所有导出函数统一 try/catch 兜底。

__declspec(dllexport) void zeta_core_init(const wchar_t* logDir) {
    try {
        printf("[zeta_core] zeta_core_init called, logDir=%S\n", logDir ? logDir : L"null");
        std::wstring dir = logDir ? logDir : L"C:\\ProgramData\\ZETA\\Logs";
        printf("[zeta_core] Creating directory: %S\n", dir.c_str());
        WinHelpers::createDirectoryRecursive(dir);
        printf("[zeta_core] Initializing logger...\n");
        Logger::instance().init(dir);
        printf("[zeta_core] Logger initialized, logging test message...\n");
        Logger::instance().info(L"Core", L"Init", L"Core DLL initialized");
        printf("[zeta_core] zeta_core_init done\n");
    } catch (...) {
    }
}

__declspec(dllexport) void zeta_core_log(const wchar_t* level, const wchar_t* module,
    const wchar_t* action, const wchar_t* detail) {
    try {
        LogLevel lvl = LOG_INFO;
        std::wstring lvlStr = level ? level : L"INFO";
        if (lvlStr == L"ERROR") lvl = LOG_ERROR;
        else if (lvlStr == L"WARN") lvl = LOG_WARN;
        else if (lvlStr == L"DEBUG") lvl = LOG_DEBUG;
        else if (lvlStr == L"TRACE") lvl = LOG_TRACE;
        else if (lvlStr == L"FATAL") lvl = LOG_FATAL;
        Logger::instance().log(lvl,
            module ? module : L"",
            action ? action : L"",
            detail ? detail : L"");
    } catch (...) {
    }
}

__declspec(dllexport) int zeta_core_config_load(const wchar_t* path) {
    try {
        return ConfigManager::instance().load(path ? path : L"") ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

__declspec(dllexport) int zeta_core_config_get_bool(const wchar_t* key, int defaultVal) {
    try {
        return ConfigManager::instance().getBool(key, defaultVal != 0) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

__declspec(dllexport) void zeta_core_config_set_bool(const wchar_t* key, int val) {
    try {
        ConfigManager::instance().setBool(key, val != 0);
    } catch (...) {
    }
}

__declspec(dllexport) int zeta_core_config_save() {
    return ConfigManager::instance().save() ? 1 : 0;
}

} // extern "C"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            break;
        case DLL_PROCESS_DETACH:
            Logger::instance().flush();
            break;
    }
    return TRUE;
}
