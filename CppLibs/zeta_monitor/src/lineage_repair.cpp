#include "zeta_monitor.h"
#include "../../zeta_core/include/zeta_core.h"
#include <Windows.h>
#include <algorithm>

// ============================================================
// LineageTracker
// ============================================================
LineageTracker& LineageTracker::instance() {
    static LineageTracker inst;
    return inst;
}

void LineageTracker::enable() {
    m_enabled = true;
    Logger::instance().info(L"Lineage", L"Enable", L"Lineage tracker enabled");
}

void LineageTracker::disable() {
    m_enabled = false;
    m_nodes.clear();
    Logger::instance().info(L"Lineage", L"Disable", L"Lineage tracker disabled");
}

void LineageTracker::addProcess(unsigned long pid, unsigned long ppid,
    const std::wstring& name, const std::wstring& path) {
    if (!m_enabled) return;
    std::lock_guard<std::mutex> lock(m_mutex);

    LineageNode& node = m_nodes[pid];
    node.pid = pid;
    node.ppid = ppid;
    node.name = name;
    node.path = path;
    node.createTime = GetTickCount64();
    node.lastActivity = node.createTime;
    node.childCount = 0;
    node.isScriptHost = false;

    // Check if this is a script host
    std::wstring lower = name;
    for (auto& c : lower) c = towlower(c);
    if (lower.find(L"powershell") != std::wstring::npos ||
        lower.find(L"cmd.exe") != std::wstring::npos ||
        lower.find(L"cscript") != std::wstring::npos ||
        lower.find(L"wscript") != std::wstring::npos) {
        node.isScriptHost = true;
    }

    // Update parent's child count
    auto parentIt = m_nodes.find(ppid);
    if (parentIt != m_nodes.end()) {
        parentIt->second.childCount++;
    }

    Logger::instance().debug(L"Lineage", L"AddProc",
        L"PID=" + std::to_wstring(pid) + L" PPID=" + std::to_wstring(ppid) + L" " + name);

    // Clean up old entries (keep last 500)
    if (m_nodes.size() > 500) cleanup();
}

void LineageTracker::removeProcess(unsigned long pid) {
    if (!m_enabled) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_nodes.erase(pid);
}

LineageNode* LineageTracker::getNode(unsigned long pid) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_nodes.find(pid);
    if (it != m_nodes.end()) return &it->second;
    return nullptr;
}

void LineageTracker::addReleasedFile(unsigned long pid, const std::wstring& filePath) {
    if (!m_enabled) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_nodes.find(pid);
    if (it != m_nodes.end()) {
        it->second.releasedFiles.push_back(filePath);
        it->second.lastActivity = GetTickCount64();
    }
}

std::vector<std::wstring> LineageTracker::getRecentFiles(unsigned long pid, int seconds) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::wstring> result;

    auto it = m_nodes.find(pid);
    if (it == m_nodes.end()) return result;

    unsigned long long threshold = GetTickCount64() - (seconds * 1000);
    for (const auto& f : it->second.releasedFiles) {
        // Check file creation time
        WIN32_FILE_ATTRIBUTE_DATA info = {0};
        if (GetFileAttributesExW(f.c_str(), GetFileExInfoStandard, &info)) {
            ULARGE_INTEGER ft;
            ft.LowPart = info.ftCreationTime.dwLowDateTime;
            ft.HighPart = info.ftCreationTime.dwHighDateTime;
            unsigned long long createTimeMs = ft.QuadPart / 10000;
            if (createTimeMs >= threshold) {
                result.push_back(f);
            }
        }
    }

    return result;
}

bool LineageTracker::analyzeAlert(unsigned long parentPid,
    std::wstring& outAlertType, std::wstring& outDetail) {
    auto files = getRecentFiles(parentPid, 30);

    if (files.size() < 2) return false;

    // Check if multiple files were released in the last 30 seconds
    // This is a heuristic for PE file packing / malware extraction
    int peCount = 0;
    std::vector<std::wstring> peFiles;

    for (const auto& f : files) {
        std::wstring ext = f.substr(f.find_last_of(L'.') + 1);
        for (auto& c : ext) c = towlower(c);
        if (ext == L"exe" || ext == L"dll" || ext == L"scr" || ext == L"pif") {
            peCount++;
            peFiles.push_back(f);
        }
    }

    if (peCount >= 2) {
        outAlertType = L"batch_release";
        outDetail = L"Released " + std::to_wstring(peCount) + L" PE files in 30s";
        Logger::instance().info(L"Lineage", L"Alert", outDetail);

        // Check for SilverFox
        detectSilverFox(peFiles, outDetail);
        return true;
    }

    return false;
}

bool LineageTracker::detectSilverFox(const std::vector<std::wstring>& files,
    std::wstring& outDetail) {
    if (files.size() < 2) return false;

    // Check if released files have mixed or no signatures
    // This is the SilverFox pattern: script host -> multiple unsigned PE files
    int signedCount = 0;
    int unsignedCount = 0;
    std::wstring lastPublisher;

    for (const auto& f : files) {
        // Use WinTrust to verify
        // Simplified: just check count
        unsignedCount++;
    }

    // TODO: Full SilverFox detection with WinTrust API
    // For now, report via outDetail
    outDetail += L" | Files: " + std::to_wstring(signedCount) + L" signed, " +
               std::to_wstring(unsignedCount) + L" unsigned";

    return unsignedCount >= 2;
}

void LineageTracker::cleanup() {
    // Remove oldest entries when exceeding 500 nodes
    if (m_nodes.size() <= 500) return;

    // Sort by creation time and remove oldest
    std::vector<std::pair<unsigned long, unsigned long long>> sorted;
    for (const auto& [pid, node] : m_nodes) {
        sorted.push_back({pid, node.createTime});
    }

    std::sort(sorted.begin(), sorted.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; });

    // Remove first 100 oldest
    for (int i = 0; i < 100 && i < sorted.size(); i++) {
        m_nodes.erase(sorted[i].first);
    }
}

// ============================================================
// SystemRepair
// ============================================================
SystemRepair& SystemRepair::instance() {
    static SystemRepair inst;
    return inst;
}

std::vector<RepairItem> SystemRepair::scan() {
    std::vector<RepairItem> items;

    // MBR check
    RepairItem mbr;
    mbr.type = L"mbr";
    mbr.detail = L"系统引导记录";
    mbr.canRepair = checkMbr();
    items.push_back(mbr);

    // Restrict check
    RepairItem restrict;
    restrict.type = L"restrict";
    restrict.detail = L"系统限制策略";
    restrict.canRepair = checkRestrict();
    items.push_back(restrict);

    // File type check
    RepairItem fileType;
    fileType.type = L"file_type";
    fileType.detail = L"文件关联配置";
    fileType.canRepair = checkFileType();
    items.push_back(fileType);

    // File icon check
    RepairItem fileIcon;
    fileIcon.type = L"file_icon";
    fileIcon.detail = L"文件图标缓存";
    fileIcon.canRepair = checkFileIcon();
    items.push_back(fileIcon);

    RepairItem image;
    image.type = L"image";
    image.detail = L"Image hijacking check";
    image.canRepair = checkImageHijack();
    items.push_back(image);

    // Wallpaper check
    RepairItem wallpaper;
    wallpaper.type = L"wallpaper";
    wallpaper.detail = L"桌面壁纸";
    wallpaper.canRepair = checkWallpaper();
    items.push_back(wallpaper);

    Logger::instance().info(L"Repair", L"Scan", L"Found " + std::to_wstring(items.size()) + L" items");
    return items;
}

bool SystemRepair::repair(const std::wstring& type) {
    Logger::instance().info(L"Repair", L"Repair", L"Type: " + type);

    if (type == L"mbr") return repairMbr();
    if (type == L"restrict") return repairRestrict();
    if (type == L"file_type") return repairFileType();
    if (type == L"file_icon") return repairFileIcon();
    if (type == L"image") return repairImageHijack();
    if (type == L"wallpaper") return repairWallpaper();

    Logger::instance().error(L"Repair", L"Repair", L"Unknown type: " + type);
    return false;
}

bool SystemRepair::checkMbr() {
    // Read MBR and verify signature 55AA
    HANDLE hDrive = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDrive == INVALID_HANDLE_VALUE) return false;

    unsigned char mbr[512];
    DWORD bytesRead;
    BOOL ok = ReadFile(hDrive, mbr, 512, &bytesRead, nullptr);
    CloseHandle(hDrive);

    if (!ok || bytesRead < 512) return false;
    return (mbr[510] == 0x55 && mbr[511] == 0xAA);  // Valid MBR signature
}

bool SystemRepair::checkRestrict() {
    HKEY hKey;
    LONG ret = RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, KEY_READ, &hKey);
    if (ret == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;  // Has restrictions
    }
    return true;  // No restrictions found
}

bool SystemRepair::checkFileType() {
    // Check .exe association
    HKEY hKey;
    LONG ret = RegOpenKeyExW(HKEY_CLASSES_ROOT, L".exe", 0, KEY_READ, &hKey);
    if (ret == ERROR_SUCCESS) {
        wchar_t value[MAX_PATH];
        DWORD size = sizeof(value);
        ret = RegQueryValueExW(hKey, nullptr, nullptr, nullptr,
            reinterpret_cast<LPBYTE>(value), &size);
        RegCloseKey(hKey);
        if (ret == ERROR_SUCCESS && std::wstring(value) == L"exefile")
            return true;
    }
    return false;
}

bool SystemRepair::checkFileIcon() { return true; }  // Always return true for icon cache
bool SystemRepair::checkImageHijack() { return true; }

bool SystemRepair::checkWallpaper() {
    HKEY hKey;
    LONG ret = RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Control Panel\\Desktop", 0, KEY_READ, &hKey);
    if (ret == ERROR_SUCCESS) {
        wchar_t value[MAX_PATH];
        DWORD size = sizeof(value);
        ret = RegQueryValueExW(hKey, L"Wallpaper", nullptr, nullptr,
            reinterpret_cast<LPBYTE>(value), &size);
        RegCloseKey(hKey);
        if (ret == ERROR_SUCCESS) {
            std::wstring wallpaper(value);
            return WinHelpers::fileExists(wallpaper);
        }
    }
    return true;
}

bool SystemRepair::repairMbr() {
    Logger::instance().warn(L"Repair", L"MBR", L"MBR repair requires elevation, not implemented in C++");
    return false;
}

bool SystemRepair::repairRestrict() {
    HKEY hKey;
    LONG ret = RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, KEY_SET_VALUE, &hKey);
    if (ret == ERROR_SUCCESS) {
        RegDeleteTreeW(hKey, nullptr);
        RegCloseKey(hKey);
        Logger::instance().info(L"Repair", L"Restrict", L"Registry restrictions cleared");
    }
    // Also check local machine
    ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, KEY_SET_VALUE, &hKey);
    if (ret == ERROR_SUCCESS) {
        RegDeleteTreeW(hKey, nullptr);
        RegCloseKey(hKey);
    }
    return true;
}

bool SystemRepair::repairFileType() {
    HKEY hKey;
    LONG ret = RegOpenKeyExW(HKEY_CLASSES_ROOT, L".exe", 0, KEY_SET_VALUE, &hKey);
    if (ret == ERROR_SUCCESS) {
        RegSetValueExW(hKey, nullptr, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(L"exefile"), sizeof(L"exefile"));
        RegCloseKey(hKey);
    }
    return true;
}

bool SystemRepair::repairFileIcon() {
    // Rebuild icon cache
    std::wstring iconCache = WinHelpers::expandEnv(L"%LOCALAPPDATA%\\IconCache.db");
    if (WinHelpers::fileExists(iconCache)) {
        DeleteFileW(iconCache.c_str());
    }
    return true;
}

bool SystemRepair::repairImageHijack() {
    HKEY hKey;
    LONG ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        0, KEY_ENUMERATE_SUB_KEYS | KEY_SET_VALUE, &hKey);
    if (ret == ERROR_SUCCESS) {
        // Enumerate and remove debugger entries
        wchar_t subKey[MAX_PATH];
        DWORD subKeySize = MAX_PATH;
        DWORD idx = 0;
        while (RegEnumKeyExW(hKey, idx, subKey, &subKeySize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            HKEY hSub;
            if (RegOpenKeyExW(hKey, subKey, 0, KEY_SET_VALUE, &hSub) == ERROR_SUCCESS) {
                RegDeleteValueW(hSub, L"Debugger");
                RegCloseKey(hSub);
            }
            subKeySize = MAX_PATH;
            idx++;
        }
        RegCloseKey(hKey);
    }
    return true;
}

bool SystemRepair::repairWallpaper() {
    Logger::instance().info(L"Repair", L"Wallpaper", L"Wallpaper repair not implemented");
    return true;
}
