#include "zeta_driver.h"
#include "../../zeta_core/include/zeta_core.h"
#include <Windows.h>
#include <shlwapi.h>
#include <chrono>
#include <cwctype>

#pragma comment(lib, "shlwapi.lib")

// ============================================================
// HipsEngine Implementation
// ============================================================
HipsEngine& HipsEngine::instance() {
    static HipsEngine inst;
    return inst;
}

int HipsEngine::loadRules() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_rules.clear();

    if (!m_rulesPath.empty() && loadRulesFromFileUnlocked()) {
        printf("[ZETA_HIPS] Loaded %zu rules from: %S\n", m_rules.size(), m_rulesPath.c_str());
        return (int)m_rules.size();
    }

    std::wstring json = ConfigManager::instance().getString(L"hips_rules", L"[]");
    if (json == L"[]") {
        printf("[ZETA_HIPS] No rules found, loading defaults\n");
        loadDefaultRules();
        int count = (int)m_rules.size();
        printf("[ZETA_HIPS] Loaded %d default rules\n", count);
        return count;
    }

    size_t pos = 0;
    while (pos < json.size()) {
        size_t ob = json.find(L'{', pos);
        if (ob == std::wstring::npos) break;
        size_t cb = json.find(L'}', ob);
        if (cb == std::wstring::npos) break;

        std::wstring ruleJson = json.substr(ob, cb - ob + 1);
        pos = cb + 1;

        HipsRule rule;
        rule.action = HIPS_ASK;
        rule.timestamp = 0;
        rule.code = 0;
        rule.process_exact = false;

        auto extract = [&](const std::wstring& key) -> std::wstring {
            size_t kp = ruleJson.find(L"\"" + key + L"\"");
            if (kp == std::wstring::npos) return L"";
            size_t colon = ruleJson.find(L':', kp);
            if (colon == std::wstring::npos) return L"";
            size_t start = ruleJson.find(L'"', colon);
            if (start == std::wstring::npos) return L"";
            start++;
            size_t end = ruleJson.find(L'"', start);
            if (end == std::wstring::npos) return L"";
            return ruleJson.substr(start, end - start);
        };

        rule.id = extract(L"id");
        rule.process = extract(L"process");
        rule.target = extract(L"target");

        std::wstring codeStr = extract(L"code");
        if (!codeStr.empty()) rule.code = std::stoul(codeStr);

        std::wstring actionStr = extract(L"action");
        if (!actionStr.empty()) rule.action = static_cast<HipsAction>(std::stoi(actionStr));

        std::wstring tsStr = extract(L"timestamp");
        if (!tsStr.empty()) rule.timestamp = std::stoull(tsStr);

        std::wstring exactStr = extract(L"process_exact");
        rule.process_exact = (exactStr == L"true" || exactStr == L"1");

        std::wstring scoreStr = extract(L"score");
        if (!scoreStr.empty()) rule.score = std::stoi(scoreStr);

        m_rules.push_back(rule);
    }

    printf("[ZETA_HIPS] Loaded %zu rules\n", m_rules.size());

    if (m_rules.empty()) {
        printf("[ZETA_HIPS] Config had 0 rules, falling back to defaults\n");
        loadDefaultRules();
        return (int)m_rules.size();
    }

    return (int)m_rules.size();
}

void HipsEngine::loadDefaultRules() {
    struct DefaultRule {
        const wchar_t* id;
        unsigned long code;
        const wchar_t* process;
        const wchar_t* target;
        HipsAction action;
        bool process_exact;
        int score;
    };

    DefaultRule defaults[] = {
        // P1-5: 同步 C++ 默认规则与 JSON - 补齐 JSON 中存在但 C++ 缺失的关键规则
        {L"def_file_zeta", 2001, L"ZETA.exe",     L"", HIPS_ALLOW, false, 0},
        {L"def_file_exp",  2001, L"explorer.exe", L"", HIPS_ALLOW, false, 0},
        {L"def_file_not",  2001, L"notepad.exe",  L"", HIPS_ALLOW, false, 0},
        {L"def_file_wrd",  2001, L"wordpad.exe",  L"", HIPS_ALLOW, false, 0},
        {L"def_file_chr",  2001, L"chrome.exe",   L"", HIPS_ALLOW, false, 0},
        {L"def_file_edg",  2001, L"msedge.exe",   L"", HIPS_ALLOW, false, 0},
        {L"def_file_fox",  2001, L"firefox.exe",  L"", HIPS_ALLOW, false, 0},
        {L"def_file_rar",  2001, L"winrar.exe",   L"", HIPS_ALLOW, false, 0},
        {L"def_file_7z1",  2001, L"7zFM.exe",    L"", HIPS_ALLOW, false, 0},
        {L"def_file_7z2",  2001, L"7z.exe",      L"", HIPS_ALLOW, false, 0},
        {L"def_file_wwd",  2001, L"WINWORD.EXE", L"", HIPS_ALLOW, false, 0},
        {L"def_file_xcl",  2001, L"EXCEL.EXE",   L"", HIPS_ALLOW, false, 0},
        {L"def_file_ppt",  2001, L"POWERPNT.EXE",L"", HIPS_ALLOW, false, 0},
        {L"def_file_wps",  2001, L"wps.exe",     L"", HIPS_ALLOW, false, 0},
        {L"def_file_vsc",  2001, L"Code.exe",    L"", HIPS_ALLOW, false, 0},
        {L"def_file_vs",   2001, L"devenv.exe",  L"", HIPS_ALLOW, false, 0},
        {L"def_file_txt",  2001, L"typora.exe",  L"", HIPS_ALLOW, false, 0},
        {L"def_file_obs",  2001, L"Obsidian.exe",L"", HIPS_ALLOW, false, 0},
        {L"def_file_pnt",  2001, L"mspaint.exe", L"", HIPS_ALLOW, false, 0},
        {L"def_file_snp",  2001, L"Snipaste.exe",L"", HIPS_ALLOW, false, 0},
        {L"def_file_wgr",  2001, L"WeGram.exe",  L"", HIPS_ALLOW, false, 0},
        {L"def_file_tim",  2001, L"TIM.exe",     L"", HIPS_ALLOW, false, 0},
        {L"def_file_wxg",  2001, L"WeChat.exe",  L"", HIPS_ALLOW, false, 0},
        {L"def_file_qq",   2001, L"QQ.exe",      L"", HIPS_ALLOW, false, 0},
        {L"def_file_tlg",  2001, L"Telegram.exe",L"", HIPS_ALLOW, false, 0},
        {L"def_file_dc",   2001, L"Discord.exe", L"", HIPS_ALLOW, false, 0},
        {L"def_file_pdf",  2001, L"Acrobat.exe", L"", HIPS_ALLOW, false, 0},
        {L"def_file_pdf2", 2001, L"FoxitPDF.exe",L"", HIPS_ALLOW, false, 0},
        {L"def_reg_exp",   3001, L"explorer.exe", L"", HIPS_ALLOW, false, 0},
        {L"def_reg_mmc",   3001, L"mmc.exe",     L"", HIPS_ALLOW, false, 0},
        {L"def_reg_reg",   3001, L"regedit.exe", L"", HIPS_ALLOW, false, 0},
        {L"def_reg_mal1",  3001, L"cmd.exe",      L"CurrentVersion\\Run",       HIPS_DENY, false, 25},
        {L"def_reg_mal2",  3001, L"powershell.exe",L"CurrentVersion\\Run",      HIPS_DENY, false, 25},
        {L"def_reg_mal3",  3001, L"wscript.exe",  L"CurrentVersion\\Run",       HIPS_DENY, false, 25},
        {L"def_reg_mal4",  3001, L"cscript.exe",  L"CurrentVersion\\Run",       HIPS_DENY, false, 25},
        {L"def_reg_mal5",  3001, L"cmd.exe",      L"CurrentVersion\\RunOnce",   HIPS_DENY, false, 25},
        {L"def_ran_01",    5001, L"wscript.exe",  L"",    HIPS_DENY, false, 35},
        {L"def_ran_02",    5001, L"cscript.exe",  L"",    HIPS_DENY, false, 35},
        {L"def_ran_03",    5001, L"mshta.exe",    L"",    HIPS_DENY, false, 35},
        {L"def_ran_04",    5001, L"certutil.exe", L"",    HIPS_DENY, false, 35},
        {L"def_ran_05",    5001, L"bitsadmin.exe",L"",    HIPS_DENY, false, 25},
        {L"def_ran_06",    5001, L"powershell.exe",L"ProgramData", HIPS_DENY, false, 30},
        {L"def_ran_07",    5001, L"rundll32.exe", L"*.tmp", HIPS_DENY, false, 25},
        {L"def_inj_01",    6001, L"rundll32.exe", L"",    HIPS_DENY, false, 30},
        {L"def_inj_02",    6001, L"regsvr32.exe", L"",    HIPS_DENY, false, 25},
        {L"def_inj_03",    6001, L"mshta.exe",    L"",    HIPS_DENY, false, 30},
        {L"def_inj_04",    6001, L"mavinject.exe",L"",    HIPS_DENY, false, 35},
        {L"def_inj_05",    6001, L"msbuild.exe",  L"",    HIPS_DENY, false, 25},
        {L"def_inj_06",    6001, L"cscript.exe",  L"",    HIPS_DENY, false, 20},
        {L"def_inj_07",    6001, L"wmic.exe",     L"",    HIPS_DENY, false, 20},
        {L"def_sf_01",     6002, L"schtasks.exe",       L"",              HIPS_DENY, false, 50},
        {L"def_sf_02",     6002, L"powershell.exe",     L"schtasks",      HIPS_DENY, false, 50},
        {L"def_sf_03",     6002, L"cmd.exe",            L"schtasks",      HIPS_DENY, false, 50},
        {L"def_sf_04",     6002, L"wmic.exe",           L"schtasks",      HIPS_DENY, false, 50},
        {L"def_sf_05",     6002, L"at.exe",             L"",              HIPS_DENY, false, 45},
        {L"def_file_stm",  2001, L"Steam.exe",          L"", HIPS_ALLOW, false, 0},
        {L"def_file_epc",  2001, L"EpicGamesLauncher.exe",L"",HIPS_ALLOW, false, 0},
        {L"def_file_btn",  2001, L"Battle.net.exe",     L"", HIPS_ALLOW, false, 0},
        {L"def_file_ptp",  2001, L"PotPlayer.exe",      L"", HIPS_ALLOW, false, 0},
        {L"def_file_vlc",  2001, L"vlc.exe",            L"", HIPS_ALLOW, false, 0},
        {L"def_file_evy",  2001, L"Everything.exe",     L"", HIPS_ALLOW, false, 0},
        {L"def_file_bdz",  2001, L"Bandizip.exe",       L"", HIPS_ALLOW, false, 0},
        {L"def_file_shx",  2001, L"ShareX.exe",         L"", HIPS_ALLOW, false, 0},
        {L"def_file_git",  2001, L"git.exe",            L"", HIPS_ALLOW, false, 0},
        {L"def_file_ida",  2001, L"idea64.exe",         L"", HIPS_ALLOW, false, 0},
        {L"def_file_pych", 2001, L"pycharm64.exe",       L"", HIPS_ALLOW, false, 0},
        {L"def_file_clion",2001, L"clion64.exe",        L"", HIPS_ALLOW, false, 0},
        {L"def_file_wsl",  2001, L"wsl.exe",            L"", HIPS_ALLOW, false, 0},
        {L"def_file_wscp", 2001, L"WinSCP.exe",         L"", HIPS_ALLOW, false, 0},
        {L"def_file_pty",  2001, L"putty.exe",          L"", HIPS_ALLOW, false, 0},
        {L"def_file_dock", 2001, L"Docker Desktop.exe", L"", HIPS_ALLOW, false, 0},
        // P1-5: 补齐 JSON 中存在但 C++ 缺失的系统进程放行规则 (JSON 加载失败时的回退)
        {L"def_file_sys",  2001, L"services.exe",       L"", HIPS_ALLOW, false, 0},
        {L"def_file_lsas", 2001, L"lsass.exe",          L"", HIPS_ALLOW, false, 0},
        {L"def_file_svch", 2001, L"svchost.exe",        L"", HIPS_ALLOW, false, 0},
        {L"def_file_winl", 2001, L"winlogon.exe",       L"", HIPS_ALLOW, false, 0},
        {L"def_file_wininit", 2001, L"wininit.exe",      L"", HIPS_ALLOW, false, 0},
        {L"def_file_csrs", 2001, L"csrss.exe",           L"", HIPS_ALLOW, false, 0},
        {L"def_file_sms",  2001, L"smss.exe",            L"", HIPS_ALLOW, false, 0},
        {L"def_file_task", 2001, L"Taskmgr.exe",         L"", HIPS_ALLOW, false, 0},
        {L"def_file_conh", 2001, L"conhost.exe",         L"", HIPS_ALLOW, false, 0},
        {L"def_file_dwm",  2001, L"dwm.exe",             L"", HIPS_ALLOW, false, 0},
        {L"def_reg_mal6",  3001, L"cmd.exe",            L"DisableAntiSpyware", HIPS_DENY, false, 30},
        {L"def_reg_mal7",  3001, L"powershell.exe",     L"DisableAntiSpyware", HIPS_DENY, false, 30},
        {L"def_reg_mal8",  3001, L"cmd.exe",            L"EnableLUA",         HIPS_DENY, false, 25},
        {L"def_reg_mal9",  3001, L"powershell.exe",     L"EnableLUA",         HIPS_DENY, false, 25},
        {L"def_reg_mal10", 3001, L"cmd.exe",            L"DisableTaskMgr",    HIPS_DENY, false, 20},
        {L"def_reg_mal11", 3001, L"cmd.exe",            L"Winlogon\\Shell",   HIPS_DENY, false, 30},
        {L"def_reg_mal12", 3001, L"powershell.exe",     L"Winlogon\\Shell",   HIPS_DENY, false, 30},
        {L"def_reg_mal13", 3001, L"cmd.exe",            L"Userinit",          HIPS_DENY, false, 30},
        // P1-5: 补齐关键注册表保护规则 (与 JSON 对齐)
        {L"def_reg_defender", 3001, L"*", L"Windows Defender\\DisableAntiSpyware", HIPS_DENY, false, 40},
        {L"def_reg_tamper",   3001, L"*", L"TamperProtection",                     HIPS_DENY, false, 45},
        {L"def_reg_ifeo",     3001, L"cmd.exe",       L"Image File Execution Options", HIPS_DENY, false, 35},
        {L"def_reg_appinit",  3001, L"cmd.exe",       L"AppInit_DLLs",                 HIPS_DENY, false, 35},
        {L"def_reg_lsa_ppl",  3001, L"*",             L"RunAsPPL",                     HIPS_DENY, false, 40},
        {L"def_reg_lsa_notif",3001, L"*",             L"Notification Packages",         HIPS_DENY, false, 40},
        {L"def_reg_usr1",  3001, L"*", L"CurrentVersion\\Run\\Malware",        HIPS_DENY, false, 25},
        {L"def_reg_usr2",  3001, L"*", L"CurrentControlSet\\Services\\*Suspicious*", HIPS_DENY, false, 30},
        {L"def_reg_usr3",  3001, L"*", L"CurrentVersion\\Run\\KnownGood",      HIPS_ALLOW, false, 0},
        {L"def_inj_usr1",  6001, L"*\\python.exe", L"", HIPS_DENY, false, 20},
        {L"def_inj_usr2",  6001, L"*\\node.exe",   L"", HIPS_DENY, false, 20},
        {L"def_file_usr1", 2001, L"*", L"*\\important_data.db",   HIPS_DENY, false, 15},
        {L"def_file_usr2", 2001, L"*", L"*\\config\\critical.json", HIPS_DENY, false, 15},
        // P1-5: 补齐 Temp 目录拦截规则 (与 JSON 对齐，P0-2: Temp 放行规则必须后置)
        {L"def_file_tmp_exe",  2001, L"*", L"*\\Temp\\*.exe",   HIPS_DENY, false, 25},
        {L"def_file_tmp_dll",  2001, L"*", L"*\\Temp\\*.dll",   HIPS_DENY, false, 25},
        {L"def_file_tmp_ps",   2001, L"*", L"*\\Temp\\*.ps1",   HIPS_DENY, false, 20},
        {L"def_file_tmp_vbs",  2001, L"*", L"*\\Temp\\*.vbs",   HIPS_DENY, false, 20},
        {L"def_file_startup",  2001, L"*", L"*\\Startup\\*.exe", HIPS_DENY, false, 35},
        {L"def_file_sys32_exe",2001, L"*", L"*\\System32\\*.exe", HIPS_DENY, false, 35},
        {L"def_file_sys32_dll",2001, L"*", L"*\\System32\\*.dll", HIPS_DENY, false, 30},
        // P0-2: Temp 目录白名单放在 Temp\\*.exe/dll/ps1/vbs 拦截规则之后
        {L"def_file_usr3", 2001, L"*", L"*\\Temp\\*",             HIPS_ALLOW, false, 0},
        {L"def_ran_usr1",  5001, L"*", L"*.sqlite",  HIPS_DENY, false, 25},
        {L"def_ran_usr2",  5001, L"*", L"*.wallet",  HIPS_DENY, false, 30},
    };

    auto now = static_cast<unsigned long long>(time(nullptr));
    for (auto& d : defaults) {
        HipsRule r;
        r.id = d.id;
        r.code = d.code;
        r.process = d.process;
        r.target = d.target;
        r.action = d.action;
        r.process_exact = d.process_exact;
        r.score = d.score;
        r.timestamp = now;
        m_rules.push_back(r);
    }

    printf("[ZETA_HIPS] Loaded %zu default rules\n", m_rules.size());
    saveRulesUnlocked();
}

void HipsEngine::saveRules() {
    std::lock_guard<std::mutex> lock(m_mutex);
    saveRulesUnlocked();
}

void HipsEngine::saveRulesUnlocked() {
    std::wstring json = L"[";
    for (size_t i = 0; i < m_rules.size(); i++) {
        if (i > 0) json += L",";
        const auto& r = m_rules[i];
        json += L"{\"id\":\"" + r.id + L"\",\"code\":\"" + std::to_wstring(r.code) +
                L"\",\"process\":\"" + r.process + L"\",\"target\":\"" + r.target +
                L"\",\"action\":\"" + std::to_wstring(r.action) + L"\",\"timestamp\":" +
                std::to_wstring(r.timestamp) +
                L",\"process_exact\":\"" + (r.process_exact ? L"true" : L"false") +
                L"\",\"score\":\"" + std::to_wstring(r.score) + L"\"}";
    }
    json += L"]";

    ConfigManager::instance().setString(L"hips_rules", json);
    ConfigManager::instance().save();

    if (!m_rulesPath.empty()) {
        std::wstring fileJson = L"{\n";
        fileJson += L"    \"//\": \"HIPS rules - auto-saved by engine\",\n";
        fileJson += L"    \"version\": 1,\n";
        fileJson += L"    \"rules\": " + json + L"\n";
        fileJson += L"}\n";

        std::string utf8;
        int utf8len = WideCharToMultiByte(CP_UTF8, 0, fileJson.c_str(), (int)fileJson.size(),
            nullptr, 0, nullptr, nullptr);
        if (utf8len > 0) {
            utf8.resize(utf8len);
            WideCharToMultiByte(CP_UTF8, 0, fileJson.c_str(), (int)fileJson.size(),
                &utf8[0], utf8len, nullptr, nullptr);

            FILE* f = nullptr;
            if (_wfopen_s(&f, m_rulesPath.c_str(), L"wb") == 0 && f) {
                fwrite(utf8.c_str(), 1, utf8.size(), f);
                fclose(f);
            }
        }
    }

    printf("[ZETA_HIPS] Saved %zu rules\n", m_rules.size());
}

bool HipsEngine::loadRulesFromFileUnlocked() {
    if (m_rulesPath.empty()) return false;

    FILE* f = nullptr;
    if (_wfopen_s(&f, m_rulesPath.c_str(), L"rb") != 0 || !f) {
        return false;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len <= 0) { fclose(f); return false; }
    fseek(f, 0, SEEK_SET);

    std::string utf8(len, '\0');
    fread(&utf8[0], 1, len, f);
    fclose(f);

    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), nullptr, 0);
    if (wlen <= 0) return false;
    std::wstring json(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), &json[0], wlen);

    size_t rulesPos = json.find(L"\"rules\"");
    if (rulesPos == std::wstring::npos) return false;
    size_t colon = json.find(L':', rulesPos);
    if (colon == std::wstring::npos) return false;
    size_t arrayStart = json.find(L'[', colon);
    if (arrayStart == std::wstring::npos) return false;
    size_t arrayEnd = json.find_last_of(L']');
    if (arrayEnd == std::wstring::npos || arrayEnd <= arrayStart) return false;

    std::wstring rulesJson = json.substr(arrayStart, arrayEnd - arrayStart + 1);

    size_t pos = 0;
    int count = 0;
    while (pos < rulesJson.size()) {
        size_t ob = rulesJson.find(L'{', pos);
        if (ob == std::wstring::npos) break;
        size_t cb = rulesJson.find(L'}', ob);
        if (cb == std::wstring::npos) break;

        std::wstring rj = rulesJson.substr(ob, cb - ob + 1);
        pos = cb + 1;

        HipsRule rule;
        rule.action = HIPS_ASK;
        rule.timestamp = 0;
        rule.code = 0;
        rule.process_exact = false;

        auto extract = [&](const std::wstring& key) -> std::wstring {
            size_t kp = rj.find(L"\"" + key + L"\"");
            if (kp == std::wstring::npos) return L"";
            size_t c = rj.find(L':', kp);
            if (c == std::wstring::npos) return L"";
            c++;
            while (c < rj.size() && (rj[c] == L' ' || rj[c] == L'\t' || rj[c] == L'\n' || rj[c] == L'\r')) {
                c++;
            }
            if (c >= rj.size()) return L"";
            if (rj[c] == L'"') {
                c++;
                size_t end = rj.find(L'"', c);
                if (end == std::wstring::npos) return L"";
                return rj.substr(c, end - c);
            } else {
                size_t end = c;
                while (end < rj.size() && rj[end] != L',' && rj[end] != L'}') {
                    end++;
                }
                return rj.substr(c, end - c);
            }
        };

        rule.id = extract(L"id");
        rule.process = extract(L"process");
        rule.target = extract(L"target");

        std::wstring tmp;
        tmp = extract(L"code");
        if (!tmp.empty()) { try { rule.code = std::stoul(tmp); } catch (...) {} }
        tmp = extract(L"action");
        if (!tmp.empty()) { try { rule.action = static_cast<HipsAction>(std::stoi(tmp)); } catch (...) {} }
        tmp = extract(L"timestamp");
        if (!tmp.empty()) { try { rule.timestamp = std::stoull(tmp); } catch (...) {} }
        tmp = extract(L"process_exact");
        rule.process_exact = (tmp == L"true");
        tmp = extract(L"score");
        if (!tmp.empty()) { try { rule.score = std::stoi(tmp); } catch (...) {} }
        tmp = extract(L"enabled");
        // enabled 缺省为 true; 显式 "false"/"0" 表示禁用
        if (!tmp.empty()) {
            rule.enabled = !(tmp == L"false" || tmp == L"0");
        }

        m_rules.push_back(rule);
        count++;
    }

    if (count == 0) return false;

    printf("[ZETA_HIPS] Parsed %d rules from %S\n", count, m_rulesPath.c_str());
    return true;
}

// P0-2: 标准通配匹配 — `*` 匹配任意字符(含路径分隔符 \), `?` 匹配单个字符, 大小写不敏感.
// 与驱动层 ProtectRules::WildcardMatch 语义一致(但不依赖 WDK API, 纯 std 实现).
static bool WildcardMatchW(const std::wstring& pattern, const std::wstring& str) {
    size_t p = 0, s = 0, starP = std::wstring::npos, starS = 0;
    while (s < str.size()) {
        if (p < pattern.size() &&
            (pattern[p] == L'?' ||
             towlower(pattern[p]) == towlower(str[s]))) {
            p++; s++;
        } else if (p < pattern.size() && pattern[p] == L'*') {
            starP = p++; starS = s;   // 记录 * 位置, 尝试 0 字符匹配
        } else if (starP != std::wstring::npos) {
            p = starP + 1; s = ++starS;  // 回溯: * 多吞一个字符
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == L'*') p++;
    return p == pattern.size();
}

HipsAction HipsEngine::matchRule(unsigned long code, const std::wstring& process,
    const std::wstring& target) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_lastMatchedScore = 0;

    for (const auto& w : m_whitelist) {
        if (process.find(w) != std::wstring::npos || target.find(w) != std::wstring::npos) {
            return HIPS_ALLOW;
        }
    }

    for (const auto& r : m_rules) {
        if (r.code != code) continue;
        if (!r.enabled) continue;  // UI 禁用的规则不参与匹配
        if (r.process_exact) {
            if (r.process == process) {
                m_lastMatchedScore = r.score;
                return r.action;
            }
        }
    }

    for (const auto& r : m_rules) {
        if (r.code != code) continue;
        if (!r.enabled) continue;  // UI 禁用的规则不参与匹配
        // process 匹配: 含通配符则用通配匹配, 否则保持子串匹配(向后兼容)
        if (!r.process.empty()) {
            bool hit = r.process.find(L'*') != std::wstring::npos ||
                       r.process.find(L'?') != std::wstring::npos
                ? WildcardMatchW(r.process, process)
                : process.find(r.process) != std::wstring::npos;
            if (hit) {
                m_lastMatchedScore = r.score;
                return r.action;
            }
        }
        // target 匹配: 同理
        if (!r.target.empty()) {
            bool hit = r.target.find(L'*') != std::wstring::npos ||
                       r.target.find(L'?') != std::wstring::npos
                ? WildcardMatchW(r.target, target)
                : target.find(r.target) != std::wstring::npos;
            if (hit) {
                m_lastMatchedScore = r.score;
                return r.action;
            }
        }
    }

    return HIPS_ASK;
}

int HipsEngine::lastMatchedScore() const {
    return m_lastMatchedScore;
}

void HipsEngine::addRule(unsigned long code, const std::wstring& process,
    const std::wstring& target, HipsAction action, int score, bool processExact) {
    std::lock_guard<std::mutex> lock(m_mutex);

    HipsRule rule;
    wchar_t idBuf[64];
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    swprintf_s(idBuf, L"rule_%llu", static_cast<unsigned long long>(now));
    rule.id = idBuf;
    rule.code = code;
    rule.process = process;
    rule.target = target;
    rule.action = action;
    rule.score = score;
    rule.timestamp = static_cast<unsigned long long>(time(nullptr));
    rule.process_exact = processExact;

    m_rules.push_back(rule);
    printf("[ZETA_HIPS] AddRule: id=%S code=%lu process=%S action=%d score=%d\n",
        rule.id.c_str(), code, process.c_str(), action, score);
}

bool HipsEngine::deleteRule(const std::wstring& ruleId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto it = m_rules.begin(); it != m_rules.end(); ++it) {
        if (it->id == ruleId) {
            m_rules.erase(it);
            printf("[ZETA_HIPS] DeleteRule: id=%S\n", ruleId.c_str());
            return true;
        }
    }
    return false;
}

void HipsEngine::clearRules() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_rules.clear();
    printf("[ZETA_HIPS] All rules cleared\n");
}

std::vector<HipsRule> HipsEngine::getRules() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_rules;
}

bool HipsEngine::isInWhitelist(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& w : m_whitelist) {
        if (path.find(w) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

void HipsEngine::addToWhitelist(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& w : m_whitelist) {
        if (w == path) return;
    }
    m_whitelist.push_back(path);

    std::wstring json = L"[";
    for (size_t i = 0; i < m_whitelist.size(); i++) {
        if (i > 0) json += L",";
        json += L"\"" + m_whitelist[i] + L"\"";
    }
    json += L"]";
    ConfigManager::instance().setString(L"white_list", json);
    ConfigManager::instance().save();

    printf("[ZETA_HIPS] AddWhitelist: path=%S\n", path.c_str());
}

void HipsEngine::removeFromWhitelist(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto it = m_whitelist.begin(); it != m_whitelist.end(); ++it) {
        if (*it == path) {
            m_whitelist.erase(it);
            break;
        }
    }

    std::wstring json = L"[";
    for (size_t i = 0; i < m_whitelist.size(); i++) {
        if (i > 0) json += L",";
        json += L"\"" + m_whitelist[i] + L"\"";
    }
    json += L"]";
    ConfigManager::instance().setString(L"white_list", json);
    ConfigManager::instance().save();

    printf("[ZETA_HIPS] RemoveWhitelist: path=%S\n", path.c_str());
}

std::vector<std::wstring> HipsEngine::getWhitelist() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_whitelist;
}

// ============================================================
// C DLL Exports for HIPS
// ============================================================
extern "C" {

__declspec(dllexport) int zeta_hips_load_rules() {
    return HipsEngine::instance().loadRules();
}

__declspec(dllexport) void zeta_hips_save_rules() {
    HipsEngine::instance().saveRules();
}

__declspec(dllexport) void zeta_hips_set_rules_path(const wchar_t* path) {
    if (path) {
        HipsEngine::instance().setRulesPath(path);
    }
}

__declspec(dllexport) int zeta_hips_match_rule(unsigned long code,
    const wchar_t* process, const wchar_t* target) {
    return static_cast<int>(HipsEngine::instance().matchRule(
        code,
        process ? process : L"",
        target ? target : L""));
}

__declspec(dllexport) int zeta_hips_match_rule_score(unsigned long code,
    const wchar_t* process, const wchar_t* target) {
    HipsEngine::instance().matchRule(
        code,
        process ? process : L"",
        target ? target : L"");
    return HipsEngine::instance().lastMatchedScore();
}

__declspec(dllexport) void zeta_hips_add_rule(unsigned long code,
    const wchar_t* process, const wchar_t* target, int action) {
    HipsEngine::instance().addRule(
        code,
        process ? process : L"",
        target ? target : L"",
        static_cast<HipsAction>(action),
        0);
}

__declspec(dllexport) void zeta_hips_add_rule_ex(unsigned long code,
    const wchar_t* process, const wchar_t* target, int action, int score) {
    HipsEngine::instance().addRule(
        code,
        process ? process : L"",
        target ? target : L"",
        static_cast<HipsAction>(action),
        score);
}

__declspec(dllexport) int zeta_hips_delete_rule(const wchar_t* ruleId) {
    return HipsEngine::instance().deleteRule(ruleId ? ruleId : L"") ? 1 : 0;
}

__declspec(dllexport) void zeta_hips_clear_rules() {
    HipsEngine::instance().clearRules();
}

__declspec(dllexport) int zeta_hips_is_whitelisted(const wchar_t* path) {
    return HipsEngine::instance().isInWhitelist(path ? path : L"") ? 1 : 0;
}

__declspec(dllexport) void zeta_hips_add_whitelist(const wchar_t* path) {
    HipsEngine::instance().addToWhitelist(path ? path : L"");
}

__declspec(dllexport) void zeta_hips_remove_whitelist(const wchar_t* path) {
    HipsEngine::instance().removeFromWhitelist(path ? path : L"");
}

} // extern "C"
