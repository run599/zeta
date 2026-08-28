#include "zeta_core.h"
#include <Windows.h>
#include <shlobj.h>

namespace WinHelpers {

bool isWindowsVistaOrLater() {
    OSVERSIONINFOEXW osvi = { sizeof(osvi) };
    osvi.dwMajorVersion = 6;
    DWORDLONG mask = 0;
    VER_SET_CONDITION(mask, VER_MAJORVERSION, VER_GREATER_EQUAL);
    return VerifyVersionInfoW(&osvi, VER_MAJORVERSION, mask) != FALSE;
}

bool isElevated() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return false;
    TOKEN_ELEVATION elev;
    DWORD size = sizeof(elev);
    BOOL ok = GetTokenInformation(hToken, TokenElevation, &elev, size, &size);
    CloseHandle(hToken);
    return ok && elev.TokenIsElevated != 0;
}

std::wstring expandEnv(const std::wstring& path) {
    wchar_t buf[32768];
    DWORD len = ExpandEnvironmentStringsW(path.c_str(), buf, 32768);
    if (len > 0 && len <= 32768) return buf;
    return path;
}

std::wstring getProgramDataPath() {
    wchar_t buf[MAX_PATH];
    if (SHGetSpecialFolderPathW(nullptr, buf, CSIDL_COMMON_APPDATA, FALSE)) {
        return std::wstring(buf) + L"\\ZETA";
    }
    return L"C:\\ProgramData\\ZETA";
}

bool createDirectoryRecursive(const std::wstring& path) {
    std::wstring p = path;
    for (size_t i = 0; i < p.size(); i++) {
        if (p[i] == L'/' || p[i] == L'\\') {
            if (i > 0) {
                std::wstring sub = p.substr(0, i);
                CreateDirectoryW(sub.c_str(), nullptr);
            }
        }
    }
    return CreateDirectoryW(p.c_str(), nullptr) != 0 ||
           GetLastError() == ERROR_ALREADY_EXISTS;
}

bool fileExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

bool pathIsDirectory(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

std::wstring getModulePath(HMODULE hModule) {
    wchar_t buf[MAX_PATH];
    DWORD len = GetModuleFileNameW(hModule, buf, MAX_PATH);
    if (len > 0) {
        std::wstring path(buf, len);
        size_t pos = path.find_last_of(L"\\/");
        if (pos != std::wstring::npos)
            return path.substr(0, pos);
    }
    return L".";
}

std::wstring getTempPath() {
    wchar_t buf[MAX_PATH];
    DWORD len = GetTempPathW(MAX_PATH, buf);
    if (len > 0) return std::wstring(buf, len);
    return L"C:\\Temp\\";
}

unsigned long getLastError() {
    return ::GetLastError();
}

std::wstring formatError(unsigned long errCode) {
    wchar_t* buf = nullptr;
    DWORD len = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, errCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&buf, 0, nullptr);
    if (len > 0 && buf) {
        std::wstring msg(buf, len);
        LocalFree(buf);
        // Trim trailing whitespace
        while (!msg.empty() && (msg.back() == L'\n' || msg.back() == L'\r' || msg.back() == L' '))
            msg.pop_back();
        return msg;
    }
    wchar_t fallback[64];
    swprintf_s(fallback, L"Error code: 0x%08X", errCode);
    return fallback;
}

bool parseSimpleJson(const std::wstring& json,
    std::unordered_map<std::wstring, std::wstring>& out) {
    // Flat key-value JSON parser
    // {"key1":"val1","key2":"val2",...}
    size_t pos = 0;
    while (pos < json.size() && json[pos] != L'{') pos++;
    if (pos >= json.size()) return false;
    pos++;

    while (pos < json.size()) {
        // Skip whitespace
        while (pos < json.size() && (json[pos] == L' ' || json[pos] == L'\n' || json[pos] == L'\r' || json[pos] == L'\t'))
            pos++;
        if (pos >= json.size() || json[pos] == L'}') break;

        // Read key
        if (json[pos] != L'"') return false;
        pos++;
        size_t keyStart = pos;
        while (pos < json.size() && json[pos] != L'"') {
            if (json[pos] == L'\\') pos++;
            pos++;
        }
        if (pos >= json.size()) return false;
        std::wstring key = json.substr(keyStart, pos - keyStart);
        pos++;

        // Skip colon
        while (pos < json.size() && json[pos] != L':') pos++;
        if (pos >= json.size()) return false;
        pos++;

        // Skip whitespace
        while (pos < json.size() && (json[pos] == L' ' || json[pos] == L'\n' || json[pos] == L'\r' || json[pos] == L'\t'))
            pos++;

        // Read value (string or bool/number)
        if (pos < json.size() && json[pos] == L'"') {
            pos++;
            size_t valStart = pos;
            while (pos < json.size() && json[pos] != L'"') {
                if (json[pos] == L'\\') pos++;
                pos++;
            }
            if (pos >= json.size()) return false;
            std::wstring val = json.substr(valStart, pos - valStart);
            pos++;
            out[key] = val;
        } else {
            // True / False / number
            size_t valStart = pos;
            while (pos < json.size() && json[pos] != L',' && json[pos] != L'}' && json[pos] != L' ')
                pos++;
            if (pos > valStart) {
                out[key] = json.substr(valStart, pos - valStart);
            }
        }

        // Skip comma
        while (pos < json.size() && (json[pos] == L',' || json[pos] == L' ' || json[pos] == L'\n' || json[pos] == L'\r' || json[pos] == L'\t'))
            pos++;
    }
    return true;
}

std::wstring toSimpleJson(const std::unordered_map<std::wstring, std::wstring>& map) {
    std::wstring json = L"{\n";
    bool first = true;
    for (const auto& [key, val] : map) {
        if (!first) json += L",\n";
        first = false;
        json += L"  \"" + key + L"\": \"" + val + L"\"";
    }
    json += L"\n}\n";
    return json;
}

} // namespace WinHelpers
