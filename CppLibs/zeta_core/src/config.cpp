#include "zeta_core.h"
#include <Windows.h>
#include <fstream>
#include <sstream>
#include <codecvt>

ConfigManager& ConfigManager::instance() {
    static ConfigManager inst;
    return inst;
}

bool ConfigManager::load(const std::wstring& configPath) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_configPath = configPath;
    m_configDir = configPath.substr(0, configPath.find_last_of(L"\\/"));

    if (!WinHelpers::fileExists(configPath)) {
        Logger::instance().warn(L"Config", L"Load", L"Config not found, using defaults: " + configPath);
        return false;
    }

    std::ifstream file(configPath);
    if (!file.is_open()) {
        Logger::instance().error(L"Config", L"Load", L"Cannot open: " + configPath);
        return false;
    }

    std::stringstream ss;
    ss << file.rdbuf();
    file.close();

    std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
    std::wstring json = conv.from_bytes(ss.str());

    m_values.clear();
    bool ok = WinHelpers::parseSimpleJson(json, m_values);
    if (ok) {
        Logger::instance().info(L"Config", L"Load",
            L"Loaded " + std::to_wstring(m_values.size()) + L" items from " + configPath);
    } else {
        Logger::instance().error(L"Config", L"Load", L"JSON parse error: " + configPath);
    }
    return ok;
}

bool ConfigManager::save() {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::wstring json = WinHelpers::toSimpleJson(m_values);

    std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
    std::string utf8 = conv.to_bytes(json);

    std::ofstream file(m_configPath, std::ios::out | std::ios::trunc);
    if (!file.is_open()) {
        Logger::instance().error(L"Config", L"Save", L"Cannot write: " + m_configPath);
        return false;
    }
    file << utf8;
    file.close();
    Logger::instance().info(L"Config", L"Save", L"Saved " + std::to_wstring(m_values.size()) + L" items");
    return true;
}

std::wstring ConfigManager::getString(const std::wstring& key, const std::wstring& defaultVal) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_values.find(key);
    if (it != m_values.end()) return it->second;
    return defaultVal;
}

int ConfigManager::getInt(const std::wstring& key, int defaultVal) {
    std::wstring val = getString(key, L"");
    if (val.empty()) return defaultVal;
    try { return std::stoi(val); }
    catch (...) { return defaultVal; }
}

bool ConfigManager::getBool(const std::wstring& key, bool defaultVal) {
    std::wstring val = getString(key, L"");
    if (val.empty()) return defaultVal;
    return (val == L"true" || val == L"1" || val == L"True");
}

std::vector<std::wstring> ConfigManager::getStringArray(const std::wstring& key) {
    std::wstring val = getString(key, L"[]");
    std::vector<std::wstring> result;
    // Simple array parser: ["a","b","c"]
    size_t pos = val.find(L'[');
    if (pos == std::wstring::npos) return result;
    size_t end = val.find(L']', pos);
    if (end == std::wstring::npos) return result;

    std::wstring inner = val.substr(pos + 1, end - pos - 1);
    size_t start = 0;
    while (true) {
        size_t q1 = inner.find(L'"', start);
        if (q1 == std::wstring::npos) break;
        size_t q2 = inner.find(L'"', q1 + 1);
        if (q2 == std::wstring::npos) break;
        result.push_back(inner.substr(q1 + 1, q2 - q1 - 1));
        start = q2 + 1;
    }
    return result;
}

void ConfigManager::setString(const std::wstring& key, const std::wstring& val) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_values[key] = val;
}

void ConfigManager::setInt(const std::wstring& key, int val) {
    setString(key, std::to_wstring(val));
}

void ConfigManager::setBool(const std::wstring& key, bool val) {
    setString(key, val ? L"true" : L"false");
}

std::wstring ConfigManager::escapeJson(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    for (wchar_t c : s) {
        switch (c) {
            case L'"': out += L"\\\""; break;
            case L'\\': out += L"\\\\"; break;
            case L'\n': out += L"\\n"; break;
            case L'\t': out += L"\\t"; break;
            case L'\r': out += L"\\r"; break;
            default: out += c;
        }
    }
    return out;
}

std::wstring ConfigManager::unescapeJson(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == L'\\' && i + 1 < s.size()) {
            switch (s[i + 1]) {
                case L'"': out += L'"'; i++; break;
                case L'\\': out += L'\\'; i++; break;
                case L'n': out += L'\n'; i++; break;
                case L't': out += L'\t'; i++; break;
                case L'r': out += L'\r'; i++; break;
                default: out += s[i];
            }
        } else {
            out += s[i];
        }
    }
    return out;
}
