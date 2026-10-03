#define _WIN32_WINNT 0x0601
#define WINVER 0x0601
#include "zeta_engine.h"
#include <yara.h>
#include <yara/rules.h>   // yr_rules_foreach / YR_RULE 遍历 (建立"规则->置信档"表用)
#include <Windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <codecvt>
#include <shlwapi.h>
#include <fstream>
#include <sstream>
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")

// Stub Logger/WinHelpers to avoid zeta_core.dll compile-time linking
// (zeta_core.dll is loaded at runtime via LoadLibrary)
//
// 2026-10-03 接实: 原先四个方法都是空实现 —— 引擎侧【全部】日志(包括
//   "Rules dir: " / "N rule files from " / "Compiled OK" / "No rules compiled"
//   / "MEM-YARA hit ...") 全部进了黑洞, 导致"YARA 是否真的加载/执行过"这种
//   关键问题从外部完全无法观测, 只能靠猜。这正是本次排查里最费力的一环。
// 现在: 同时走 OutputDebugStringW(调试器可见) 与追加写 <exe目录>\zeta_engine.log
//   (UTF-8, 与 ZETA_CPP.log 同目录, 便于用普通编辑器查看)。
// 约束: 日志本身绝不能抛异常/影响扫描 —— 全程 try/catch 兜底。
struct Logger {
    static Logger& instance() { static Logger l; return l; }

    void info (const std::wstring& m, const std::wstring& a, const std::wstring& d) { write(L"INFO",  m, a, d); }
    void warn (const std::wstring& m, const std::wstring& a, const std::wstring& d) { write(L"WARN",  m, a, d); }
    void debug(const std::wstring& m, const std::wstring& a, const std::wstring& d) { write(L"DEBUG", m, a, d); }
    void stop() {}

private:
    std::mutex m_lk;

    static const std::wstring& logPath() {
        static std::wstring p;
        if (p.empty()) {
            wchar_t buf[MAX_PATH] = { 0 };
            DWORD n = GetModuleFileNameW(NULL, buf, MAX_PATH);   // 主程序(ZETA.exe)所在目录
            std::wstring dir(buf, n);
            size_t s = dir.find_last_of(L'\\');
            if (s != std::wstring::npos) dir.resize(s);
            p = dir + L"\\zeta_engine.log";
        }
        return p;
    }

    void write(const wchar_t* lvl, const std::wstring& mod,
               const std::wstring& act, const std::wstring& det) {
        try {
            SYSTEMTIME st;
            GetLocalTime(&st);
            wchar_t head[96];
            swprintf_s(head, _countof(head),
                L"[%04d-%02d-%02d %02d:%02d:%02d.%03d] %s | %s | %s | ",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                st.wSecond, st.wMilliseconds, lvl, mod.c_str(), act.c_str());
            std::wstring line = std::wstring(head) + det + L"\r\n";
            OutputDebugStringW(line.c_str());

            std::lock_guard<std::mutex> g(m_lk);
            FILE* f = _wfopen(logPath().c_str(), L"ab");
            if (f) {
                int need = WideCharToMultiByte(CP_UTF8, 0, line.c_str(), -1, nullptr, 0, nullptr, nullptr);
                if (need > 1) {
                    std::string u8((size_t)need - 1, '\0');
                    WideCharToMultiByte(CP_UTF8, 0, line.c_str(), -1, &u8[0], need, nullptr, nullptr);
                    fwrite(u8.data(), 1, u8.size(), f);
                }
                fclose(f);
            }
        } catch (...) {
            /* 日志失败绝不影响扫描 */
        }
    }
};
namespace WinHelpers {
    inline bool fileExists(const std::wstring& p) { return PathFileExistsW(p.c_str()) != 0; }
    inline bool pathIsDirectory(const std::wstring& p) {
        DWORD attr = GetFileAttributesW(p.c_str());
        return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY);
    }
}

// ============================================================
// Simple JSON Parser (for EDR rules)
// ============================================================
inline std::string trim(const std::string& s) {
    auto start = s.begin();
    while (start != s.end() && std::isspace(*start)) start++;
    auto end = s.end();
    do { end--; } while (std::distance(start, end) > 0 && std::isspace(*end));
    return std::string(start, end + 1);
}

inline std::string removeComments(std::string json) {
    size_t pos = 0;
    while ((pos = json.find("//", pos)) != std::string::npos) {
        size_t end = json.find("\n", pos);
        if (end == std::string::npos) end = json.size();
        json.erase(pos, end - pos);
    }
    return json;
}

inline std::vector<std::string> parseJsonArray(const std::string& json, const std::string& key) {
    std::vector<std::string> result;
    std::string cleaned = removeComments(json);
    size_t keyPos = cleaned.find("\"" + key + "\"");
    if (keyPos == std::string::npos) return result;
    size_t arrStart = cleaned.find("[", keyPos);
    if (arrStart == std::string::npos) return result;
    size_t arrEnd = cleaned.find("]", arrStart);
    if (arrEnd == std::string::npos) return result;
    
    std::string arrContent = cleaned.substr(arrStart + 1, arrEnd - arrStart - 1);
    size_t pos = 0;
    while (pos < arrContent.size()) {
        if (arrContent[pos] == '"') {
            size_t end = arrContent.find("\"", pos + 1);
            if (end != std::string::npos) {
                std::string val = arrContent.substr(pos + 1, end - pos - 1);
                if (!val.empty() && val[0] != '/') result.push_back(val);
                pos = end + 1;
            } else break;
        } else {
            pos++;
        }
    }
    return result;
}

inline int parseJsonInt(const std::string& json, const std::string& key, int def = 0) {
    std::string cleaned = removeComments(json);
    size_t keyPos = cleaned.find("\"" + key + "\"");
    if (keyPos == std::string::npos) return def;
    size_t colon = cleaned.find(":", keyPos);
    if (colon == std::string::npos) return def;
    size_t valStart = colon + 1;
    while (valStart < cleaned.size() && (cleaned[valStart] == ' ' || cleaned[valStart] == '\n')) valStart++;
    return std::stoi(cleaned.substr(valStart));
}

inline bool parseJsonBool(const std::string& json, const std::string& key, bool def = true) {
    std::string cleaned = removeComments(json);
    size_t keyPos = cleaned.find("\"" + key + "\"");
    if (keyPos == std::string::npos) return def;
    size_t colon = cleaned.find(":", keyPos);
    if (colon == std::string::npos) return def;
    size_t valStart = colon + 1;
    while (valStart < cleaned.size() && (cleaned[valStart] == ' ' || cleaned[valStart] == '\n')) valStart++;
    // P0 修复(2026-10-03): 原实现取【固定 5 个字符】再与 4 字符的 "true" 比较,
    // 于是只要值后面还有任何字符就必然不等:
    //     值后是 CR('\r', 本配置是 CRLF 换行) -> "true\r" != "true" -> false
    //     值后是逗号                           -> "true,"  != "true" -> false
    // 只有"该值恰好位于所传字符串的最末尾"(substr 被截成 4 字符)时才可能为 true。
    // 实测后果(用等价逻辑逐键复现): Rule_Scanning_Enabled 的三个开关【恒为 false】,
    // 其中 enable_yara=false 直接让 ScanEngine::scanFile() 跳过整段 YARA 扫描 ——
    // 这才是"ZETA 的 YARA 从未真正执行过"的最终根因, 与规则集/路径配置/崩溃均无关。
    // 修复: 按分隔符(逗号/右括号/换行/空白)取完整 token 再比较。
    size_t valEnd = valStart;
    while (valEnd < cleaned.size() &&
           cleaned[valEnd] != ',' && cleaned[valEnd] != '}' &&
           cleaned[valEnd] != ']' && cleaned[valEnd] != '\r' &&
           cleaned[valEnd] != '\n' && cleaned[valEnd] != ' ' &&
           cleaned[valEnd] != '\t') {
        ++valEnd;
    }
    std::string val = cleaned.substr(valStart, valEnd - valStart);
    return (val == "true" || val == "TRUE");
}

inline size_t findMatchingBrace(const std::string& json, size_t startPos) {
    if (startPos >= json.size() || json[startPos] != '{') return std::string::npos;
    int depth = 1;
    for (size_t i = startPos + 1; i < json.size(); i++) {
        if (json[i] == '{') depth++;
        else if (json[i] == '}') depth--;
        if (depth == 0) return i;
    }
    return std::string::npos;
}

// ============================================================
// EDR Rule Manager Implementation
// ============================================================
bool EdrRuleManager::loadFromConfig(const std::wstring& configPath) {
    std::ifstream file(configPath, std::ios::binary);
    if (!file) return false;
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string json = buffer.str();
    
    auto loadWStrings = [&](const std::string& key) -> std::vector<std::wstring> {
        std::vector<std::wstring> result;
        auto strings = parseJsonArray(json, key);
        for (const auto& s : strings) {
            try {
                result.push_back(std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(s));
            } catch (...) {
                result.push_back(std::wstring(s.begin(), s.end()));
            }
        }
        return result;
    };
    
    suspiciousApis = parseJsonArray(json, "Rule_Pe_SuspiciousApis");
    highRiskApis = parseJsonArray(json, "Rule_Pe_HighRiskApis");
    suspiciousSections = parseJsonArray(json, "Rule_Pe_SuspiciousSections");
    trustedPublishers = parseJsonArray(json, "Rule_Signature_TrustedPublishers");
    requiredExtensions = parseJsonArray(json, "Rule_Signature_RequiredExtensions");
    yaraPaths = loadWStrings("Rule_Yara_Paths");
    
    size_t scoringPos = json.find("\"Rule_Scoring\"");
    if (scoringPos != std::string::npos) {
        size_t scoringStart = json.find("{", scoringPos);
        size_t scoringEnd = findMatchingBrace(json, scoringStart);
        if (scoringStart != std::string::npos && scoringEnd != std::string::npos) {
            std::string scoringJson = json.substr(scoringStart, scoringEnd - scoringStart + 1);
            scoring.suspiciousApi = parseJsonInt(scoringJson, "suspicious_api_score", 15);
            scoring.highRiskApi = parseJsonInt(scoringJson, "high_risk_api_score", 30);
            scoring.suspiciousSection = parseJsonInt(scoringJson, "suspicious_section_score", 30);
            scoring.rwxSection = parseJsonInt(scoringJson, "rwx_section_score", 20);
            scoring.highEntropy = parseJsonInt(scoringJson, "high_entropy_score", 25);
            scoring.noEntryPoint = parseJsonInt(scoringJson, "no_entry_point_score", 10);
            scoring.unsignedScore = parseJsonInt(scoringJson, "unsigned_score", 20);
            scoring.yaraMatch = parseJsonInt(scoringJson, "yara_match_score", 100);
            scoring.threatThreshold = parseJsonInt(scoringJson, "threat_threshold", 50);
            scoring.highThreatThreshold = parseJsonInt(scoringJson, "high_threat_threshold", 70);
        }
    }
    
    size_t enabledPos = json.find("\"Rule_Scanning_Enabled\"");
    if (enabledPos != std::string::npos) {
        size_t enabledStart = json.find("{", enabledPos);
        size_t enabledEnd = findMatchingBrace(json, enabledStart);
        if (enabledStart != std::string::npos && enabledEnd != std::string::npos) {
            std::string enabledJson = json.substr(enabledStart, enabledEnd - enabledStart + 1);
            enabled.enableYara = parseJsonBool(enabledJson, "enable_yara", true);
            enabled.enablePeHeuristics = parseJsonBool(enabledJson, "enable_pe_heuristics", true);
            enabled.enableSignatureCheck = parseJsonBool(enabledJson, "enable_signature_check", true);
        }
    }
    
    Logger::instance().info(L"EDR", L"LoadConfig",
        L"SuspiciousApis=" + std::to_wstring(suspiciousApis.size()) +
        L" HighRiskApis=" + std::to_wstring(highRiskApis.size()) +
        L" Sections=" + std::to_wstring(suspiciousSections.size()) +
        L" YARA=" + std::to_wstring(enabled.enableYara) +
        L" PE=" + std::to_wstring(enabled.enablePeHeuristics) +
        L" Sig=" + std::to_wstring(enabled.enableSignatureCheck));
    
    return true;
}

EdrRuleManager& EdrRuleManager::instance() {
    static EdrRuleManager inst;
    return inst;
}

// ============================================================
// SignScanner
// ============================================================
SignScanner::SignScanner()
    : m_wintrust(nullptr), m_loaded(false), m_coreDll(nullptr), m_trustVerify(nullptr) {
    m_wintrust = LoadLibraryW(L"wintrust.dll");
    if (m_wintrust) m_loaded = true;

    // P1 收敛: 加载 zeta_core 的 TrustProvider (统一签名验证入口)
    // zeta_core.dll 与 zeta_engine.dll 同目录, LoadLibrary 按 exe 目录搜索即可命中。
    m_coreDll = LoadLibraryW(L"ZETA_Core.dll");
    if (m_coreDll) {
        m_trustVerify = (int (*)(const wchar_t*))GetProcAddress(m_coreDll, "zeta_core_trust_verify");
    }
}

SignScanner::~SignScanner() {
    if (m_coreDll) FreeLibrary(m_coreDll);
    if (m_wintrust) FreeLibrary(m_wintrust);
}

bool SignScanner::verify(const std::wstring& filePath) {
    // 1) 优先走 TrustProvider (zeta_core, 统一签名验证 + 缓存)
    if (m_trustVerify) {
        int verdict = m_trustVerify(filePath.c_str());
        // 2=TRUST_SIGNED, 3=TRUST_CATALOG (与 zeta_core trust_provider.h 一致)
        return (verdict == 2 || verdict == 3);
    }

    // 2) 回退: 本地嵌入签名验证 (zeta_core 不可用时)
    if (!m_loaded) return false;

    WINTRUST_FILE_INFO fileInfo = {0};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();
    fileInfo.hFile = nullptr;
    fileInfo.pgKnownSubject = nullptr;

    WINTRUST_DATA wintrustData = {0};
    wintrustData.cbStruct = sizeof(WINTRUST_DATA);
    wintrustData.dwUnionChoice = WTD_CHOICE_FILE;
    wintrustData.pFile = &fileInfo;
    wintrustData.dwUIChoice = WTD_UI_NONE;
    wintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    wintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    wintrustData.dwProvFlags = WTD_REVOCATION_CHECK_NONE;
    wintrustData.dwUIContext = WTD_UICONTEXT_EXECUTE;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &policyGuid, &wintrustData);

    wintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGuid, &wintrustData);

    return status == ERROR_SUCCESS;
}

std::wstring SignScanner::getPublisher(const std::wstring& filePath) {
    if (!m_loaded) return L"";

    HCERTSTORE hStore = nullptr;
    HCRYPTMSG hMsg = nullptr;
    DWORD encoding = 0, contentType = 0, formatType = 0;

    BOOL ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE, filePath.c_str(),
        CERT_QUERY_CONTENT_FLAG_ALL, CERT_QUERY_FORMAT_FLAG_ALL, 0,
        &encoding, &contentType, &formatType, &hStore, &hMsg, nullptr);

    if (!ok) return L"";

    std::wstring publisher;
    PCCERT_CONTEXT pCertCtx = nullptr;
    while ((pCertCtx = CertEnumCertificatesInStore(hStore, pCertCtx)) != nullptr) {
        wchar_t nameBuf[512];
        if (CertGetNameStringW(pCertCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0, nullptr, nameBuf, 512)) {
            publisher = nameBuf;
            break;
        }
    }
    if (pCertCtx) CertFreeCertificateContext(pCertCtx);
    if (hMsg) CryptMsgClose(hMsg);
    if (hStore) CertCloseStore(hStore, 0);
    return publisher;
}

// ============================================================
// YaraScanner (real libyara integration)
// ============================================================
struct YaraMatchContext {
    std::wstring matchedRule;
    std::wstring matchedString;
    bool isHigh;
    // 2026-10-04 新增(评分策略): 收集本次扫描命中的【全部】规则名。
    // 旧实现只保留最后一次回调写入的名字, 再加上 SCAN_FLAGS_FAST_MODE 会在
    // 首个命中处提前结束扫描, 于是"命中 1 条"与"命中 10 条"在上层看来完全一样,
    // 分级评分/交叉表决根本无法实现。
    std::vector<std::wstring> allRules;
};

static int yara_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    (void)context;
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        YaraMatchContext* ctx = (YaraMatchContext*)user_data;
        if (rule && ctx) {
            // P0-崩溃修复: C 回调内禁止异常逃逸 (会穿过 C 边界导致 UB)。
            // from_bytes 遇到无效 UTF-8 规则标识符会抛异常, 这里捕获降级。
            std::wstring id;
            if (rule->identifier) {
                try {
                    id = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(rule->identifier);
                } catch (...) {
                    id.clear();
                }
            }
            if (!id.empty()) {
                if (ctx->matchedRule.empty()) ctx->matchedRule = id;   // 保持"首条"语义
                // 去重 + 上限: 规则数量固定(约 1.7 万), 命中数不可能失控;
                // 上限只是防御性措施, 防止异常规则集把证据串撑爆。
                if (ctx->allRules.size() < 64) {
                    bool bDup = false;
                    for (size_t i = 0; i < ctx->allRules.size(); ++i) {
                        if (ctx->allRules[i] == id) { bDup = true; break; }
                    }
                    if (!bDup) ctx->allRules.push_back(id);
                }
            } else {
                ctx->isHigh = true;
            }
            ctx->isHigh = true; // matched rule = threat
        }
        return CALLBACK_CONTINUE;
    }
    return CALLBACK_CONTINUE;
}

YaraScanner::YaraScanner() : m_rules(nullptr) {}

YaraScanner::~YaraScanner() {
    if (m_rules) yr_rules_destroy(m_rules);
    m_rules = nullptr;
}

// 2026-10-03 新增: 在 yr_finalize() 之前显式释放规则。
// 见 ~ScanEngine() 处的说明 —— 成员析构晚于析构体, 会导致
// yr_rules_destroy 跑在 yr_finalize 之后(顺序颠倒的 UAF)。
// 本函数幂等, 之后 ~YaraScanner() 再跑一次也是空操作。
void YaraScanner::destroyRules() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_rules) {
        yr_rules_destroy(m_rules);
        m_rules = nullptr;
    }
}

// 编译诊断回调 (2026-10-03 新增): 让"某条规则为何编译失败"从此可见。
// 签名必须与 yara/compiler.h 的 YR_COMPILER_CALLBACK_FUNC 完全一致(六参数),
// 少写一个在 C++ 里会报 overloaded-function、在 C 里则只会让实参错位。
static void YrCompileDiagnostic_(int errLevel, const char* fname, int lineno,
                                 const YR_RULE* rule, const char* msg, void* user) {
    (void)user;
    (void)rule;
    if (errLevel != YARA_ERROR_LEVEL_ERROR) return;
    try {
        std::string sf = fname ? std::string(fname) : std::string();
        std::string sm = msg ? std::string(msg) : std::string();
        std::wstring af(sf.begin(), sf.end());
        std::wstring am(sm.begin(), sm.end());
        Logger::instance().warn(L"Yara", L"CompileError",
            af + L":" + std::to_wstring(lineno) + L": " + am);
    } catch (...) {
    }
}

// ============================================================
// 规则置信档 (2026-10-04 新增, 评分策略的前提)
//
// 背景: 旧评分把"扫描器返回 3"一刀切成 100 分 —— 而 3 的含义只是"有命中",
// 哪怕命中的是 `IsPE64`(只要是 64 位 PE)、`with_urls`(程序里有 URL)这类
// 能力型规则, 也会立刻越过告警阈值 85。反过来, 若只给 1~3 分则真检测也永不告警。
// 正确解法是让"证据"与"权重"分离:
//   · 引擎本文件: 如实统计【命中了几条、分别属于哪一档】;
//   · 行为引擎(behavior_engine.h 的 YaraScoreConfig): 施加权重并锁死不变式。
//
// 分档依据是【规则所在文件】, 因为"这条规则是能力型还是检测型"是规则集的属性,
// 不是单条规则的属性 —— 例如 crypto_signatures.yar 里全是密码学常量表
// (任何用了 OpenSSL/Chromium/Qt 的正常软件都会命中), 而 signature-base 的
// mal_/apt_/crime_ 前缀文件是策展过的家族签名。
// 分档表依据 = 误报审计实测(4.3GB 干净语料) + 规则集来源, 见
// Plugins\Rules\YARA\_disabled-by-audit\README.md
// ============================================================

// 从规则文件文本里提取规则名(UTF-8, 规则标识符必为 ASCII)。
// 只认"行首(允许前导空白 + private/global 前缀) 且标识符之后紧跟 : 或 {"的形态,
// 以免把注释或字符串里的 "rule xxx" 当成定义。
// 注意: 抽出的名字只是【候选】, 最终会与 libyara 编译出的真实规则名求交集(见
// compileRules), 因此即使这里多抽了几个名字也不会污染分档表。
static void ExtractRuleNamesUtf8_(const std::string& s, std::vector<std::string>& out) {
    size_t i = 0;
    const size_t n = s.size();
    while (i < n) {
        size_t lineEnd = s.find('\n', i);
        if (lineEnd == std::string::npos) lineEnd = n;

        size_t j = i;
        while (j < lineEnd && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r')) ++j;

        // 跳过注释行
        const bool bComment = (j + 1 < lineEnd) && (s[j] == '/' && (s[j + 1] == '/' || s[j + 1] == '*'));
        if (!bComment) {
            size_t k = j;
            for (int pref = 0; pref < 2; ++pref) {
                static const char* kPref[] = { "private", "global" };
                const std::string prefStr(kPref[pref]);
                const size_t len = prefStr.size();
                if (k + len + 1 <= lineEnd && s.compare(k, len, prefStr) == 0 &&
                    (s[k + len] == ' ' || s[k + len] == '\t')) {
                    k += len;
                    while (k < lineEnd && (s[k] == ' ' || s[k] == '\t')) ++k;
                } else {
                    break;
                }
            }
            if (k + 5 <= lineEnd && s.compare(k, 4, "rule") == 0 &&
                (s[k + 4] == ' ' || s[k + 4] == '\t')) {
                k += 4;
                while (k < lineEnd && (s[k] == ' ' || s[k] == '\t')) ++k;
                size_t idStart = k;
                // 显式判断标识符字符, 避免引入 <cctype>(本项目对头文件依赖很敏感)
                while (k < lineEnd &&
                       ((s[k] >= 'A' && s[k] <= 'Z') || (s[k] >= 'a' && s[k] <= 'z') ||
                        (s[k] >= '0' && s[k] <= '9') || s[k] == '_')) ++k;
                if (k > idStart) {
                    // 标识符之后必须是分隔符: 允许空白(可能是 `rule X : tag {`)。
                    // 要求本行后续出现 ':' 或 '{' —— 这是规则声明的强特征。
                    if (s.find(':', k) < lineEnd || s.find('{', k) < lineEnd) {
                        out.push_back(s.substr(idStart, k - idStart));
                    }
                }
            }
        }
        i = lineEnd + 1;
    }
}

RuleTier YaraScanner::tierFromRulePath(const std::wstring& fullPath) {
    std::wstring p = fullPath;
    for (auto& c : p) c = (wchar_t)towlower(c);

    // ── 弱档: 误报审计实测证明的"能力型/库型"规则目录 ──
    // 这些目录里的规则描述的是"程序具有某种能力"(是 PE、含 URL、含 DES 常量表、
    // 被打包器加壳、用了 Qt/MSVC/Delphi), 而不是"这是恶意软件"。
    static const wchar_t* kWeakDirs[] = {
        L"\\capabilities\\",      // win_registry / keylogger / screenshot / network_* ...
        L"\\crypto\\",            // MD5_Constants / DES_sbox / Chacha_256_constant ...
        L"\\antidebug_antivm\\",  // Qemu_Detection / antivm_vmware / anti_dbg ...
        L"\\packers\\",           // peid.yar(7600+ 条) / packer.yar / 编译器指纹
        L"\\utils\\",             // suspicious_strings / base64 / url / domain / ip
    };
    for (size_t i = 0; i < sizeof(kWeakDirs) / sizeof(kWeakDirs[0]); ++i) {
        if (p.find(kWeakDirs[i]) != std::wstring::npos) return RuleTier::Weak;
    }

    // ── 强档: 产品自带规则 + signature-base 里策展过的家族签名 ──
    if (p.find(L"\\20-drl1.1-signature-base\\") != std::wstring::npos) {
        size_t s = p.find_last_of(L"\\/");
        std::wstring base = (s == std::wstring::npos) ? p : p.substr(s + 1);
        static const wchar_t* kStrongPrefix[] = {
            L"mal_",     // mal_win_akira_apr25 / mal_crime_unknown ...
            L"apt_",     // apt_apt29 / apt_fin7 ...
            L"crime_",   // crime_maze_ransomware ...
            L"rat_",
            L"spy_",
            L"expl_",    // exploit_* 也多为策展的漏洞利用特征
        };
        for (size_t i = 0; i < sizeof(kStrongPrefix) / sizeof(kStrongPrefix[0]); ++i) {
            if (base.rfind(kStrongPrefix[i], 0) == 0) return RuleTier::Strong;
        }
        return RuleTier::Normal;
    }

    // 产品自带规则直接位于 YARA 根目录(不在 \community\ 下): 这是本项目自己策展的
    // 检测逻辑, 单条命中即应告警。(其中被误报审计证明是误报源的部分已停用。)
    if (p.find(L"\\community\\") == std::wstring::npos) return RuleTier::Strong;

    return RuleTier::Normal;
}

RuleTier YaraScanner::tierOfRule(const std::wstring& ruleName) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_ruleTier.find(ruleName);
    if (it == m_ruleTier.end()) return RuleTier::Normal;   // 未收录一律按普通规则
    return (it->second == (int)RuleTier::Weak) ? RuleTier::Weak
         : (it->second == (int)RuleTier::Strong) ? RuleTier::Strong
         : RuleTier::Normal;
}

bool YaraScanner::compileRules() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Free old rules if any
    if (m_rules) {
        yr_rules_destroy(m_rules);
        m_rules = nullptr;
    }
    
    if (m_ruleFiles.empty()) {
        Logger::instance().warn(L"Yara", L"Compile", L"no rule files collected");
        return false;
    }

    // 2026-10-03 修复: 改为【逐文件容错】。
    // 原先语义是"任一文件出错即整集作废": 只要有一条规则编译失败(例如声明了却从未
    // 引用的字符串, 或用了本工程未编入的模块 hash/dotnet), 就不调用
    // yr_compiler_get_rules(), m_rules 保持 NULL —— 于是【整个 YARA 检测静默失效】,
    // 而唯一线索只有一句 "No rules compiled"(且该 Logger 当时还是空桩)。
    // 本项目已因此长期带病运行, 且"一条坏规则废掉整套规则"是屡次酿成静默故障的
    // 根本放大器。
    // 现在: 先用一个 compiler 试编; 若发现坏文件, 记录原因后排除它们整体重来,
    // 直到干净为止 —— 仍能从好文件里拿到可用规则集, 坏文件与原因都进日志。
    std::vector<std::wstring> aBad;
    const int nMaxPass = 8;
    for (int nPass = 1; nPass <= nMaxPass; ++nPass) {
        YR_COMPILER* compiler = nullptr;
        if (yr_compiler_create(&compiler) != ERROR_SUCCESS) return false;
        yr_compiler_set_callback(compiler, YrCompileDiagnostic_, nullptr);

        std::vector<std::wstring> aNewBad;
        int nAdded = 0;
        // 2026-10-04: 本轮各文件抽出的 (规则名, 档位) 候选。成功编译后与 libyara
        // 的真实规则名求交集, 才写入 m_ruleTier —— 见本函数末尾。
        std::vector<std::pair<std::wstring, int> > aTierCand;
        for (const auto& ruleFile : m_ruleFiles) {
            bool bSkip = false;
            for (const auto& b : aBad) {
                if (_wcsicmp(b.c_str(), ruleFile.c_str()) == 0) { bSkip = true; break; }
            }
            if (bSkip) continue;

            // P0-崩溃修复: 路径编码转换异常时跳过该规则文件而非崩溃
            std::string narrowFile;
            try {
                narrowFile = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(ruleFile);
            } catch (...) {
                aNewBad.push_back(ruleFile);
                continue;
            }
            // P0 修复(2026-10-03): 必须用 _wfopen。
            // 原先用 fopen(narrowFile)，而 narrowFile 是 UTF-8 字节；Windows 的 fopen
            // 按 ANSI 代码页解释路径，因此当规则目录含非 ASCII 字符时(如 E:\远控\...)
            // 【每一个规则文件都打不开】→ ok=false → 不调用 yr_compiler_get_rules()
            // → m_rules 恒为 NULL → YARA 从未真正参与扫描。
            FILE* f = _wfopen(ruleFile.c_str(), L"rb");
            if (!f) {
                Logger::instance().warn(L"Yara", L"Compile", L"cannot open " + ruleFile);
                aNewBad.push_back(ruleFile);
                continue;
            }

            // 2026-10-04: 顺带读一遍文本, 抽出该文件里的规则名候选并绑定档位。
            // 只为建立分档表, 不参与编译; 读完 fseek 回起点交回 libyara。
            {
                const int nTier = (int)tierFromRulePath(ruleFile);
                std::string text;
                char chunk[65536];
                size_t nGot = 0;
                while ((nGot = fread(chunk, 1, sizeof(chunk), f)) > 0) text.append(chunk, nGot);
                fseek(f, 0, SEEK_SET);
                if (!text.empty()) {
                    std::vector<std::string> names;
                    ExtractRuleNamesUtf8_(text, names);
                    for (size_t t = 0; t < names.size(); ++t) {
                        aTierCand.push_back(std::make_pair(
                            std::wstring(names[t].begin(), names[t].end()), nTier));
                    }
                }
            }

            int errors = yr_compiler_add_file(compiler, f, nullptr, narrowFile.c_str());
            fclose(f);
            ++nAdded;
            if (errors > 0) aNewBad.push_back(ruleFile);
        }

        if (aNewBad.empty()) {
            if (yr_compiler_get_rules(compiler, &m_rules) != ERROR_SUCCESS) m_rules = nullptr;
            yr_compiler_destroy(compiler);

            // 2026-10-04: 建立"规则名 -> 置信档"表。
            // 以 libyara 编译出的【真实】规则名为准(权威), 只在其中查找抽出的档位候选,
            // 因此文本解析多抽/抽错名字都不会污染分档表。同名取【更高】档位
            // (偏保守: 宁可多告警也不静默降级 —— 但档位只影响权重, 不再有 +100 越阈)。
            m_ruleTier.clear();
            int nWeak = 0, nNorm = 0, nStrong = 0;
            if (m_rules) {
                std::unordered_map<std::wstring, int> cand;
                for (size_t i = 0; i < aTierCand.size(); ++i) {
                    const std::wstring& nm = aTierCand[i].first;
                    const int v = aTierCand[i].second;
                    auto it = cand.find(nm);
                    if (it == cand.end() || v > it->second) cand[nm] = v;
                }
                YR_RULE* pRule = nullptr;
                yr_rules_foreach(m_rules, pRule) {
                    if (!pRule || !pRule->identifier) continue;
                    std::wstring nm;
                    try {
                        nm = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(pRule->identifier);
                    } catch (...) {
                        continue;
                    }
                    int v = (int)RuleTier::Normal;
                    auto it = cand.find(nm);
                    if (it != cand.end()) v = it->second;
                    m_ruleTier[nm] = v;
                    if (v == (int)RuleTier::Weak) ++nWeak;
                    else if (v == (int)RuleTier::Strong) ++nStrong;
                    else ++nNorm;
                }
            }

            Logger::instance().info(L"Yara", L"Compile",
                std::to_wstring(nAdded) + L" file(s) added, rules=" +
                (m_rules ? L"OK" : L"NULL") +
                (aBad.empty() ? L"" : (L", " + std::to_wstring(aBad.size()) + L" bad file(s) excluded")));
            Logger::instance().info(L"Yara", L"RuleTier",
                L"weak=" + std::to_wstring(nWeak) + L" normal=" + std::to_wstring(nNorm) +
                L" strong=" + std::to_wstring(nStrong) +
                L" | 评分不变式: 弱档累计<WARN, 单条普通<ALERT, 单条强>=ALERT");
            return m_rules != nullptr;
        }

        // 有坏文件: 必须换新 compiler 重来(旧 compiler 的错误状态会残留)
        yr_compiler_destroy(compiler);
        for (const auto& b : aNewBad) aBad.push_back(b);
    }

    Logger::instance().warn(L"Yara", L"Compile",
        L"gave up after " + std::to_wstring(nMaxPass) + L" passes, bad file(s)=" +
        std::to_wstring(aBad.size()));
    return false;
}

bool YaraScanner::loadPath(const std::wstring& path) {
    // 2026-10-03 修复: 原先直接 collectRuleFiles(path, m_ruleFiles) ——
    //   ① 不清空, 于是每次调用都往同一个 vector 上【累积追加】:
    //      yaraPaths 里配了 *.yar 和 *.yara 两条(或 create 被反复调用)时,
    //      同一文件会被 add_file 两次 → 重复规则名 → 整个规则集编译失败;
    //   ② 全程不持锁, 与另一线程的 scan/scanMem 并发改同一容器。
    // 现在: 先在锁内收集到局部 vector, 去重后一次性替换 m_ruleFiles, 再释放锁。
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<std::wstring> found;
        collectRuleFiles(path, found);
        m_ruleFiles.clear();
        for (size_t i = 0; i < found.size(); ++i) {
            bool bDup = false;
            for (size_t j = 0; j < m_ruleFiles.size(); ++j) {
                if (_wcsicmp(m_ruleFiles[j].c_str(), found[i].c_str()) == 0) { bDup = true; break; }
            }
            if (!bDup) m_ruleFiles.push_back(found[i]);
        }
    }

    Logger::instance().info(L"Yara", L"LoadPath",
        std::to_wstring(m_ruleFiles.size()) + L" rule files from " + path);
    
    // Compile once, cache for all scans
    bool compiled = compileRules();
    Logger::instance().info(L"Yara", L"Compile",
        compiled ? L"OK" : L"No rules compiled");
    return true;
}

void YaraScanner::collectRuleFiles(const std::wstring& dir, std::vector<std::wstring>& out) {
    std::wstring search = dir + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(search.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring full = dir + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            collectRuleFiles(full, out);
        } else {
            const wchar_t* ext = wcsrchr(fd.cFileName, L'.');
            if (ext && (_wcsicmp(ext, L".yar") == 0 || _wcsicmp(ext, L".yara") == 0)) {
                out.push_back(full);
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

bool YaraScanner::scan(const std::wstring& filePath,
    std::wstring& outRule, std::wstring& outLabel, bool& outIsHigh,
    std::vector<std::wstring>* outAllRules) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_rules) return false;

    // P0-崩溃修复: wstring_convert::to_bytes 在遇到无效 UTF-16 序列/畸形路径
    // (如含 \??\ 前缀或命令行拼接的混合字符串) 时会抛 std::range_error 异常。
    // 此前无 try/catch, 异常在 worker 线程逃逸 → std::terminate → __fastfail(7)
    // → ZETA.exe 在 ucrtbase.dll c0000409 崩溃 (WER 记录 6+ 次)。
    // 修复: 捕获转换异常, 绝不崩溃。但"无法编码"不能静默返回 false (会被上层
    // 当成"干净"→ 恶意软件可用畸形路径逃逸)。此处返回特殊标记: 调用方通过
    // outRule="__PATH_ENCODE_ERROR__" 得知扫描未完成, 按"可疑/无法验证"处理。
    std::string narrowPath;
    try {
        narrowPath = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(filePath);
    } catch (...) {
        outRule = L"__PATH_ENCODE_ERROR__";
        outLabel.clear();
        outIsHigh = false;
        return true;  // 返回 true 但带错误标记, 上层据此判"无法验证"而非"干净"
    }
    if (narrowPath.empty()) {
        outRule = L"__PATH_ENCODE_ERROR__";
        outLabel.clear();
        outIsHigh = false;
        return true;
    }

    YaraMatchContext ctx;
    ctx.isHigh = false;

    // P0 修复(2026-10-03): 不再用 yr_rules_scan_file。
    // libyara 在 Windows 上按 ANSI 代码页打开文件, 传 UTF-8 路径时, 对含非 ASCII
    // 字符的路径恒返回 ERROR_COULD_NOT_OPEN_FILE(3)(本机实测 rc=3, 见
    // yara_validate 的 --scan 对照)。后果是【中文路径下的文件一律不被扫描且被当成
    // 干净】—— 既是检测盲区, 也是可被攻击者利用的绕过面(把载荷放到中文路径即可)。
    // 改为自己用 _wfopen 读入内存, 再走 yr_rules_scan_mem。
    (void)narrowPath;
    int rc = ERROR_SUCCESS;
    bool matched = false;
    {
        FILE* pF = _wfopen(filePath.c_str(), L"rb");
        if (!pF) {
            // 打不开不能静默放行: 按"无法验证"上报, 由上层判可疑
            outRule = L"__PATH_OPEN_ERROR__";
            outLabel.clear();
            outIsHigh = false;
            return true;
        }
        fseek(pF, 0, SEEK_END);
        long nLen = ftell(pF);
        fseek(pF, 0, SEEK_SET);
        if (nLen > 0) {
            std::vector<BYTE> buf((size_t)nLen);
            size_t nRead = fread(buf.data(), 1, (size_t)nLen, pF);
            fclose(pF);
            if (nRead > 0) {
                // 2026-10-04 评分策略修复: 不再无条件使用 SCAN_FLAGS_FAST_MODE。
                // libyara 的 FAST_MODE 语义是"一旦有规则命中就停止扫描", 于是回调
                // 只会被调用一次 —— 上层永远看不到"还有几条同时命中"。分级评分
                // (弱/普通/强 × 条数交叉表决) 必须以完整命中集为前提, 故改为全量扫描。
                // 代价: 单文件扫描时间由 ~首命中提前返回 变为全量(实测 1.7 万规则
                // 扫 450KB 约 145ms)。AutoScan 仅在进程创建时触发, 可接受。
                // 例外: 超大文件(>64MB)仍用 FAST_MODE 以免单次扫描过久, 此时
                // 退化为"只有一条证据", 评分层按单条普通命中处理(不会告警)。
                const bool bHugeFile = (nRead > (64u << 20));
                const int nFlags = bHugeFile ? SCAN_FLAGS_FAST_MODE : 0;
                rc = yr_rules_scan_mem(m_rules, buf.data(), (unsigned long)nRead,
                    nFlags, yara_callback, &ctx, 0);
                matched = (rc == ERROR_SUCCESS && !ctx.matchedRule.empty());
            }
        } else {
            fclose(pF);
        }
    }

    if (matched) {
        outRule = ctx.matchedRule;
        outLabel = ctx.matchedString;
        outIsHigh = ctx.isHigh;
        if (outAllRules) *outAllRules = ctx.allRules;
    }
    return matched;
}

bool YaraScanner::scanMem(const BYTE* data, size_t size,
    std::wstring& outRule, std::wstring& outLabel, bool& outIsHigh,
    std::vector<std::wstring>* outAllRules) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_rules || !data || size == 0) return false;

    YaraMatchContext ctx;
    ctx.isHigh = false;

    // 内存扫描保留 FAST_MODE: 调用方(scanProcess)按 64MB 上限逐区扫描,
    // 全量跑完一个进程的可执行页代价过高。此处每条内存区最多提供 1 条证据,
    // 由 scanProcess 跨区累积 —— 见该函数处对"多区累积"的说明。
    int rc = yr_rules_scan_mem(m_rules, data, (unsigned long)size,
        SCAN_FLAGS_FAST_MODE, yara_callback, &ctx, 0);

    bool matched = (rc == ERROR_SUCCESS && !ctx.matchedRule.empty());
    if (matched) {
        outRule = ctx.matchedRule;
        outLabel = ctx.matchedString;
        outIsHigh = ctx.isHigh;
        if (outAllRules) *outAllRules = ctx.allRules;
    }
    return matched;
}

// ============================================================
// PeScanner
// ============================================================
PeScanner::PeScanner() {
    reloadRules();
}

void PeScanner::reloadRules() {
    auto& mgr = EdrRuleManager::instance();
    m_suspiciousApis = mgr.suspiciousApis;
    m_highRiskApis = mgr.highRiskApis;
    m_suspiciousSections = mgr.suspiciousSections;
}

int PeScanner::scan(const std::wstring& filePath, bool enhancedMode) {
    std::wstring dummy;
    return scan(filePath, enhancedMode, dummy);
}

int PeScanner::scan(const std::wstring& filePath, bool enhancedMode, std::wstring& outDetails) {
    outDetails.clear();

    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);
    if (fileSize.QuadPart > 100 * 1024 * 1024) {
        CloseHandle(hFile);
        return 0;
    }

    std::vector<unsigned char> data(fileSize.QuadPart);
    DWORD bytesRead = 0;
    ReadFile(hFile, data.data(), static_cast<DWORD>(data.size()), &bytesRead, nullptr);
    CloseHandle(hFile);

    if (bytesRead < 2 || data[0] != 'M' || data[1] != 'Z') return 0;

    auto& scoring = EdrRuleManager::instance().scoring;
    int score = 0;
    score += analyzeImports(data, scoring, outDetails);
    score += analyzeSections(data, scoring, outDetails);
    score += analyzeEntropy(data, scoring, outDetails);
    score += analyzeEntryPoint(data, scoring, outDetails);

    return score;
}

std::wstring PeScanner::getDetails() {
    return L"";
}

int PeScanner::analyzeImports(const std::vector<unsigned char>& data, const EdrScoring& scoring, std::wstring& outDetails) {
    if (data.size() < 0x3C + 4) return 0;
    unsigned long peOffset = *reinterpret_cast<const unsigned long*>(&data[0x3C]);
    if (peOffset + 4 >= data.size()) return 0;
    if (data[peOffset] != 'P' || data[peOffset+1] != 'E') return 0;

    int score = 0;
    unsigned char* ncData = const_cast<unsigned char*>(data.data());
    IMAGE_NT_HEADERS64* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(ncData + peOffset);
    
    if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC && 
        ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return 0;

    DWORD importDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD importDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    if (importDirRVA == 0 || importDirSize == 0) return 0;

    for (DWORD i = 0; i < importDirSize; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        DWORD descOffset = importDirRVA + i;
        if (descOffset + sizeof(IMAGE_IMPORT_DESCRIPTOR) > data.size()) break;
        
        IMAGE_IMPORT_DESCRIPTOR* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(ncData + descOffset);
        if (desc->OriginalFirstThunk == 0 && desc->FirstThunk == 0) break;

        DWORD thunkRVA = desc->OriginalFirstThunk != 0 ? desc->OriginalFirstThunk : desc->FirstThunk;
        if (thunkRVA == 0) continue;

        for (DWORD j = 0; ; j += sizeof(IMAGE_THUNK_DATA64)) {
            DWORD thunkOffset = thunkRVA + j;
            if (thunkOffset + sizeof(IMAGE_THUNK_DATA64) > data.size()) break;
            
            IMAGE_THUNK_DATA64* thunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(ncData + thunkOffset);
            if (thunk->u1.Function == 0) break;

            if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                DWORD hintNameRVA = thunk->u1.AddressOfData;
                if (hintNameRVA + 2 > data.size()) continue;
                
                WORD* hint = reinterpret_cast<WORD*>(ncData + hintNameRVA);
                DWORD nameRVA = hintNameRVA + sizeof(WORD);
                if (nameRVA >= data.size()) continue;
                
                char* apiName = reinterpret_cast<char*>(ncData + nameRVA);
                if (apiName[0] == '\0') continue;

                std::string apiNameStr(apiName);
                bool found = false;

                for (const auto& suspApi : m_suspiciousApis) {
                    if (apiNameStr.find(suspApi) != std::string::npos) {
                        score += scoring.suspiciousApi;
                        outDetails += L" SuspiciousAPI:" + std::wstring(apiNameStr.begin(), apiNameStr.end());
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    for (const auto& highApi : m_highRiskApis) {
                        if (apiNameStr.find(highApi) != std::string::npos) {
                            score += scoring.highRiskApi;
                            outDetails += L" HighRiskAPI:" + std::wstring(apiNameStr.begin(), apiNameStr.end());
                            break;
                        }
                    }
                }
            }
        }
    }

    return score;
}

int PeScanner::analyzeSections(const std::vector<unsigned char>& data, const EdrScoring& scoring, std::wstring& outDetails) {
    if (data.size() < 0x3C + 4) return 0;
    unsigned long peOffset = *reinterpret_cast<const unsigned long*>(&data[0x3C]);
    if (peOffset + sizeof(IMAGE_NT_HEADERS64) >= data.size()) return 0;

    int score = 0;
    unsigned char* ncData = const_cast<unsigned char*>(data.data());
    IMAGE_NT_HEADERS64* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(ncData + peOffset);
    WORD numSections = ntHeaders->FileHeader.NumberOfSections;
    DWORD sectionOffset = peOffset + sizeof(IMAGE_NT_HEADERS64);

    for (WORD i = 0; i < numSections; i++) {
        if (sectionOffset + sizeof(IMAGE_SECTION_HEADER) > data.size()) break;
        IMAGE_SECTION_HEADER* section = reinterpret_cast<IMAGE_SECTION_HEADER*>(ncData + sectionOffset);
        char name[9] = {0};
        memcpy(name, section->Name, 8);
        // P0-崩溃修复: PE 节名是原始字节, 不一定是合法 UTF-8。
        // from_bytes 对非法 UTF-8 序列会抛 std::range_error → __fastfail 崩溃。
        // 这是 bun.exe (打包型 exe) 扫描时的崩溃点。捕获异常, 用原始字节兜底。
        std::wstring sectionName;
        try {
            sectionName = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(name);
        } catch (...) {
            sectionName.assign(name, name + 8);
            for (auto& c : sectionName) {
                if (c > 0x7F) c = L'?';
            }
        }

        for (const auto& susp : m_suspiciousSections) {
            std::wstring suspW(susp.begin(), susp.end());
            if (sectionName.find(suspW) != std::wstring::npos) {
                score += scoring.suspiciousSection;
                outDetails += L" Packed:" + sectionName;
            }
        }
        if (section->Characteristics & IMAGE_SCN_MEM_WRITE && section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            score += scoring.rwxSection;
            outDetails += L" RWX:" + sectionName;
        }
        sectionOffset += sizeof(IMAGE_SECTION_HEADER);
    }
    return score;
}

int PeScanner::analyzeEntropy(const std::vector<unsigned char>& data, const EdrScoring& scoring, std::wstring& outDetails) {
    if (data.size() < 0x1000) return 0;
    int score = 0;
    size_t entropySize = min(data.size(), (size_t)65536);
    int byteCounts[256] = {0};
    for (size_t i = 0; i < entropySize; i++) byteCounts[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (byteCounts[i] > 0) {
            double p = static_cast<double>(byteCounts[i]) / entropySize;
            entropy -= p * log2(p);
        }
    }
    if (entropy > 7.0) { score += scoring.highEntropy; outDetails += L" HighEntropy:" + std::to_wstring(entropy); }
    else if (entropy > 6.5) { score += 10; }
    return score;
}

int PeScanner::analyzeEntryPoint(const std::vector<unsigned char>& data, const EdrScoring& scoring, std::wstring& outDetails) {
    if (data.size() < 0x3C + 4) return 0;
    unsigned long peOffset = *reinterpret_cast<const unsigned long*>(&data[0x3C]);
    if (peOffset + sizeof(IMAGE_NT_HEADERS64) >= data.size()) return 0;
    int score = 0;
    unsigned char* ncData = const_cast<unsigned char*>(data.data());
    IMAGE_NT_HEADERS64* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(ncData + peOffset);
    if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 0;
    unsigned long ep = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    if (ep == 0) { score += scoring.noEntryPoint; outDetails += L" NoEP"; }
    return score;
}

// ============================================================
// ScanEngine
// ============================================================
ScanEngine& ScanEngine::instance() {
    static ScanEngine inst;
    return inst;
}

ScanEngine::ScanEngine() : m_scanning(false), m_progress(0), m_inited(false) {
    // Initialize YARA library
    yr_initialize();
}

ScanEngine::~ScanEngine() {
    stopScan();
    // 2026-10-03 修复(顺序颠倒的 UAF): yr_finalize() 会拆掉 libyara 的全局状态,
    // 而 m_yaraScanner 是【成员】, 它的析构在析构体【之后】才跑 —— 于是
    // ~YaraScanner() 里的 yr_rules_destroy(m_rules) 会发生在 yr_finalize() 之后。
    // 这里在 finalize 之前显式释放规则, 保证顺序正确。
    m_yaraScanner.destroyRules();
    // Finalize YARA library
    yr_finalize();
}

bool ScanEngine::init(const std::wstring& rulesDir) {
    // 2026-10-03 修复(根因): 幂等。
    // 崩溃链: main.cpp 的 AutoScan 每次扫描都调 zeta_engine_create(),
    // 而它无条件调本函数 → loadPath()(无锁, 且向 m_ruleFiles 累积追加)
    // → compileRules()(销毁并重建 m_rules)。与 Monitor 线程的 scanMem 并发
    // 时即在另一线程正在使用的对象上做销毁 → use-after-free
    // (实测崩在 ZETA_Engine.dll+0x7486, std::wstring 的 SSO 容量检查)。
    // 规则只需在 zeta_engine_init() 里加载一次。
    if (m_inited.load()) {
        return true;
    }
    {
        std::lock_guard<std::mutex> guard(m_mutex);   // 与并发 init 串行化
        if (m_inited.load()) return true;
        m_inited.store(true);
    }

    Logger::instance().info(L"Engine", L"Init", L"Rules dir: " + rulesDir);
    
    std::wstring edrConfigPath = rulesDir + L"\\Rules_EDR.json";
    if (EdrRuleManager::instance().loadFromConfig(edrConfigPath)) {
        Logger::instance().info(L"Engine", L"Init", L"EDR rules loaded from config");
        m_peScanner.reloadRules();
    } else {
        Logger::instance().warn(L"Engine", L"Init", L"EDR config not found, using defaults");
    }
    
    auto& ruleMgr = EdrRuleManager::instance();
    if (!ruleMgr.yaraPaths.empty()) {
        for (const auto& yaraPath : ruleMgr.yaraPaths) {
            std::wstring fullPath = rulesDir + L"\\" + yaraPath;
            size_t starPos = fullPath.find(L'*');
            if (starPos != std::wstring::npos) {
                std::wstring dir = fullPath.substr(0, starPos);
                if (dir.back() == L'\\') dir.pop_back();
                if (WinHelpers::pathIsDirectory(dir)) {
                    m_yaraScanner.loadPath(dir);
                }
            } else {
                if (WinHelpers::pathIsDirectory(fullPath)) {
                    m_yaraScanner.loadPath(fullPath);
                }
            }
        }
    } else {
        if (WinHelpers::pathIsDirectory(rulesDir)) {
            m_yaraScanner.loadPath(rulesDir);
        }
    }
    
    // 2026-10-03 修复: 规则集刚加载完, 必须作废此前的扫描缓存。
    // scanFile() 有按路径的 m_cache, 命中即直接返回旧结论(见 scanFile 开头);
    // 而"先前判为干净"很可能是在【规则还没加载】(m_rules==NULL, scan 立即 return false)
    // 的情况下得出的 —— 缓存不失效 = 这些文件永久不再复检, 也等于规则更新永不生效。
    // 原先的 m_cache.clear() 在 clearResults() 里(被调用与否取决于 UI), 与规则加载无关。
    m_cache.clear();

    Logger::instance().info(L"Engine", L"Init", L"Scan engine initialized");
    return true;
}

void ScanEngine::clearResults() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_results.clear();
    m_cache.clear();
}

void ScanEngine::startScan(const std::vector<std::wstring>& targets) {
    if (m_scanning) return;
    m_scanning = true;
    m_progress = 0;

    m_scanThread = std::thread([this, targets]() {
        Logger::instance().info(L"Engine", L"StartScan", L"Targets: " + std::to_wstring(targets.size()));

        std::vector<std::wstring> allFiles;
        for (const auto& target : targets) {
            if (WinHelpers::fileExists(target)) {
                allFiles.push_back(target);
            } else if (WinHelpers::pathIsDirectory(target)) {
                std::vector<std::wstring> stack;
                stack.push_back(target);
                while (!stack.empty() && m_scanning) {
                    std::wstring dir = stack.back();
                    stack.pop_back();
                    std::wstring search = dir + L"\\*";
                    WIN32_FIND_DATAW fd;
                    HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
                    if (hFind != INVALID_HANDLE_VALUE) {
                        do {
                            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                            std::wstring fullPath = dir + L"\\" + fd.cFileName;
                            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                                stack.push_back(fullPath);
                            } else {
                                allFiles.push_back(fullPath);
                            }
                        } while (FindNextFileW(hFind, &fd) && m_scanning);
                        FindClose(hFind);
                    }
                }
            }
        }

        Logger::instance().info(L"Engine", L"StartScan", L"Total files: " + std::to_wstring(allFiles.size()));

        int total = static_cast<int>(allFiles.size());
        for (int i = 0; i < total && m_scanning; i++) {
            m_progress = (i * 100) / max(total, 1);
            if (m_progressCb) m_progressCb(m_progress, allFiles[i]);

            ScanResult result = scanFile(allFiles[i]);
            if (!result.type.empty()) {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_results.push_back(result);
                if (m_resultCb) m_resultCb(result);
            }
        }

        m_progress = 100;
        m_scanning = false;
        Logger::instance().info(L"Engine", L"ScanComplete", L"Scanned " + std::to_wstring(total) + L" files");
    });
}

void ScanEngine::stopScan() {
    m_scanning = false;
    if (m_scanThread.joinable()) {
        m_scanThread.join();
    }
}

bool ScanEngine::isWhitelisted(const std::wstring& path) {
    std::wstring lower = path;
    for (auto& c : lower) c = towlower(c);
    if (lower.find(L"\\windows\\system32\\") != std::wstring::npos) return true;
    if (lower.find(L"\\windows\\syswow64\\") != std::wstring::npos) return true;
    if (lower.find(L"\\windows\\winsxs\\") != std::wstring::npos) return true;
    if (lower.find(L"\\program files\\") != std::wstring::npos) return m_signScanner.verify(path);
    if (lower.find(L"\\program files (x86)") != std::wstring::npos) return m_signScanner.verify(path);
    return false;
}

ScanResult ScanEngine::scanFile(const std::wstring& filePath, bool enhancedMode) {
    ScanResult result;
    result.path = filePath;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_cache.find(filePath);
        if (it != m_cache.end()) return it->second;
    }

    std::wstring ext = filePath.substr(filePath.find_last_of(L'.') + 1);
    for (auto& c : ext) c = towlower(c);

    if (isWhitelisted(filePath)) return result;

    auto& enabled = EdrRuleManager::instance().enabled;
    auto& scoring = EdrRuleManager::instance().scoring;

    // 1. YARA scan
    if (enabled.enableYara) {
        std::wstring ruleName, label;
        bool isHigh = false;
        std::vector<std::wstring> allRules;
        if (m_yaraScanner.scan(filePath, ruleName, label, isHigh, &allRules)) {
            // P0-逃逸修复: 路径编码异常 (恶意畸形路径) 绝不可当作"干净"。
            // 恶意软件用畸形路径会让扫描抛异常, 若静默返回 false 即绕过扫描。
            // 此处将 __PATH_ENCODE_ERROR__ 降级为"Suspicious/unreadable"结果,
            // 让调用方 (onNewProcessCreated → reportScanScore) 走评分处置链路。
            if (ruleName == L"__PATH_ENCODE_ERROR__") {
                result.type = L"unreadable";
                result.status = L"Suspicious";
                result.detail = L"Invalid path encoding (scan skipped)";
                result.isHigh = false;
                result.disposition = ScanResult::NONE;
                std::lock_guard<std::mutex> lock(m_mutex);
                if (m_cache.size() < MAX_CACHE) m_cache[filePath] = result;
                return result;
            }

            // 2026-10-04 评分策略: 把证据如实统计出来, 交给行为引擎施加权重。
            // 旧实现 detail 只放一条规则名, 且 isHigh 只要命中就为 true —— 上层
            // 因此无法区分"命中 1 条弱规则"与"命中 5 条含强签名", 只能一律 +100。
            int nWeak = 0, nNormal = 0, nStrong = 0;
            for (size_t i = 0; i < allRules.size(); ++i) {
                switch (m_yaraScanner.tierOfRule(allRules[i])) {
                    case RuleTier::Weak:   ++nWeak;   break;
                    case RuleTier::Strong: ++nStrong; break;
                    default:               ++nNormal; break;
                }
            }
            if (allRules.empty()) ++nNormal;   // 兜底: 有命中却拿不到名字, 按 1 条普通处理

            std::wstring csv;
            for (size_t i = 0; i < allRules.size(); ++i) {
                if (i) csv += L";";
                csv += allRules[i];
            }
            result.type = L"yara";
            // isHigh 语义收紧为"存在强档(高置信)命中"。原先"有命中即高危"正是
            // 误报链的起点: 弱规则命中也会被判 Threat 并进入隔离处置。
            result.isHigh = (nStrong > 0);
            result.status = result.isHigh ? L"Threat" : L"Suspicious";
            result.detail = L"Hits=" + std::to_wstring(nWeak + nNormal + nStrong) +
                            L" Weak=" + std::to_wstring(nWeak) +
                            L" Normal=" + std::to_wstring(nNormal) +
                            L" Strong=" + std::to_wstring(nStrong) +
                            (csv.empty() ? L"" : (L" | " + csv));
            // 威胁级 → 标记隔离处置（由调用方统一执行 remediate）
            result.disposition = result.isHigh ? ScanResult::QUARANTINE : ScanResult::NONE;
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_cache.size() < MAX_CACHE) m_cache[filePath] = result;
            return result;
        }
    }

    // 2. PE scan (heuristics)
    if (enabled.enablePeHeuristics) {
        std::wstring peDetails;
        int peScore = m_peScanner.scan(filePath, enhancedMode, peDetails);
        if (peScore >= scoring.threatThreshold) {
            result.type = L"pe";
            result.status = L"Threat";
            result.detail = L"PE heuristic: " + std::to_wstring(peScore) + peDetails;
            result.isHigh = peScore > scoring.highThreatThreshold;
            // 威胁级 → 标记隔离处置
            result.disposition = ScanResult::QUARANTINE;
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_cache.size() < MAX_CACHE) m_cache[filePath] = result;
            return result;
        }
    }

    // 3. Signature check
    if (enabled.enableSignatureCheck) {
        if (!m_signScanner.verify(filePath)) {
            auto& reqExts = EdrRuleManager::instance().requiredExtensions;
            bool requiresSign = false;
            std::string extStr;
            try {
                extStr = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(ext);
            } catch (...) {
                extStr.assign(ext.begin(), ext.end());
            }
            for (const auto& re : reqExts) {
                if (extStr == re) {
                    requiresSign = true;
                    break;
                }
            }
            if (requiresSign || ext == L"exe" || ext == L"dll" || ext == L"scr" || ext == L"sys") {
                result.type = L"signature";
                result.status = L"Suspicious";
                result.detail = L"Unsigned";
                result.isHigh = false;
                std::lock_guard<std::mutex> lock(m_mutex);
                if (m_cache.size() < MAX_CACHE) m_cache[filePath] = result;
                return result;
            }
        }
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_cache.size() < MAX_CACHE) m_cache[filePath] = result;
    return result;
}

ScanResult ScanEngine::scanProcess(unsigned long pid) {
    ScanResult result;
    result.path = L"pid:" + std::to_wstring(pid);

    auto& enabled = EdrRuleManager::instance().enabled;
    if (!enabled.enableYara) return result;

    // 依赖 ZETA.exe 已注入的 SeDebugPrivilege（PPL + DKOM 注入），
    // 才能 OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION) 打开任意进程。
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        Logger::instance().warn(L"Engine", L"MemScan",
            L"OpenProcess failed pid=" + std::to_wstring(pid) +
            L" (err=" + std::to_wstring(GetLastError()) + L")");
        return result;
    }

    // 遍历 VAD：仅扫描可执行且映像/映射内存区（MEM_IMAGE / MEM_MAPPED 且 PAGE_EXECUTE*）
    MEMORY_BASIC_INFORMATION mbi = {0};
    BYTE* addr = nullptr;
    BOOL found = FALSE;

    // 2026-10-04 评分策略: 跨内存区累积全部命中证据。
    // 原先"首个命中即 break" —— 于是一次内存扫描最多只给出 1 条证据, 无法与
    // 文件扫描的条数证据合流。改为继续扫到收满 4 条(足够判定强/普通/弱交叉)或
    // 区遍历结束为止; 4 条的上限用于避免命中后把整个地址空间再跑一遍。
    std::vector<std::wstring> aMemRules;

    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if ((mbi.State & MEM_COMMIT) &&
            (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) &&
            (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                            PAGE_EXECUTE_WRITECOPY))) {

            SIZE_T regionSize = mbi.RegionSize;
            // 单区过大（如少数特大映射）限制扫描上限，避免单次分配过多
            if (regionSize > 64 * 1024 * 1024) regionSize = 64 * 1024 * 1024;

            std::vector<BYTE> buf(regionSize);
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hProc, mbi.BaseAddress, buf.data(), regionSize, &bytesRead) &&
                bytesRead > 0) {
                std::wstring rule, label;
                bool isHigh = false;
                std::vector<std::wstring> aHitRules;
                if (m_yaraScanner.scanMem(buf.data(), bytesRead, rule, label, isHigh, &aHitRules)) {
                    found = TRUE;
                    std::vector<std::wstring> src = aHitRules;
                    if (src.empty()) src.push_back(rule);
                    for (size_t i = 0; i < src.size(); ++i) {
                        bool bDup = false;
                        for (size_t j = 0; j < aMemRules.size(); ++j) {
                            if (aMemRules[j] == src[i]) { bDup = true; break; }
                        }
                        if (!bDup && aMemRules.size() < 64) aMemRules.push_back(src[i]);
                    }
                    if (aMemRules.size() >= 4) break;   // 证据已足够, 不再跑完整地址空间
                }
            }
        }

        // 移动到下一个区域
        BYTE* next = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;  // 防回绕
        addr = next;
    }

    CloseHandle(hProc);

    if (found) {
        int nWeak = 0, nNormal = 0, nStrong = 0;
        for (size_t i = 0; i < aMemRules.size(); ++i) {
            switch (m_yaraScanner.tierOfRule(aMemRules[i])) {
                case RuleTier::Weak:   ++nWeak;   break;
                case RuleTier::Strong: ++nStrong; break;
                default:               ++nNormal; break;
            }
        }
        if (aMemRules.empty()) ++nNormal;
        std::wstring csv;
        for (size_t i = 0; i < aMemRules.size(); ++i) {
            if (i) csv += L";";
            csv += aMemRules[i];
        }
        result.type = L"mem-yara";
        result.isHigh = (nStrong > 0);
        result.status = result.isHigh ? L"Threat" : L"Suspicious";
        result.detail = L"pid=" + std::to_wstring(pid) +
                        L" Hits=" + std::to_wstring(nWeak + nNormal + nStrong) +
                        L" Weak=" + std::to_wstring(nWeak) +
                        L" Normal=" + std::to_wstring(nNormal) +
                        L" Strong=" + std::to_wstring(nStrong) +
                        (csv.empty() ? L"" : (L" | " + csv));
        result.disposition = result.isHigh ? ScanResult::QUARANTINE : ScanResult::NONE;

        Logger::instance().info(L"Engine", L"MemScan",
            L"MEM-YARA hit pid=" + std::to_wstring(pid) + L" " + result.detail);
    }
    return result;
}

// ============================================================
// DLL Exports
// ============================================================
static std::wstring g_rulesDir;

extern "C" {

// P0-崩溃修复(根治): C++ 异常绝不能穿过 extern "C" DLL 导出边界。
// scanFile/scanProcess 内部 (PE 解析/YARA/签名验证) 任何异常 (bad_alloc,
// range_error, invalid_argument, out_of_range) 若逃逸到这里, 会在没有
// catch 的情况下触发 std::terminate → abort → __fastfail(FAST_FAIL_FATAL_APP_EXIT)
// → ZETA.exe 在 ucrtbase.dll c0000409 崩溃 (WER 记录 6+ 次, 均在 bun.exe
// 进程创建 → onNewProcessCreated → scan_file 时触发)。
// 修复: 每个导出函数用 try/catch(...) 兜底, 异常时返回错误码而非崩溃。

__declspec(dllexport) int zeta_engine_init(const wchar_t* rulesDir) {
    try {
        g_rulesDir = rulesDir ? rulesDir : L"C:\\ProgramData\\ZETA\\Rules";
        return ScanEngine::instance().init(g_rulesDir) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

__declspec(dllexport) void* zeta_engine_create() {
    try {
        // 2026-10-03 修复(崩溃根因): 这里原先调 ScanEngine::instance().init(g_rulesDir)。
        // main.cpp 的 AutoScan 对【每一个文件】都调一次本函数, 于是每次扫描都会
        // 重跑 加载配置 → loadPath() → compileRules()(销毁并重建全部规则)。
        // 与 Monitor 线程的 scanMem 并发时, 就是在另一线程正在使用的对象上做销毁
        // → use-after-free(实测崩在 ZETA_Engine.dll+0x7486)。
        // 规则改由 zeta_engine_init() 在启动时加载一次; init() 内部也已加幂等保护。
        return &ScanEngine::instance();
    } catch (...) {
        return nullptr;
    }
}

__declspec(dllexport) void zeta_engine_destroy(void* engine) {
    (void)engine;
}

__declspec(dllexport) int zeta_engine_wrapper_scan(void* engine, const wchar_t* path,
    wchar_t* resultBuffer, int bufferSize) {
    (void)engine;
    if (!path || !resultBuffer || bufferSize <= 0) return -1;
    try {
        ScanResult result = ScanEngine::instance().scanFile(path);
        if (result.type.empty()) {
            wcsncpy_s(resultBuffer, bufferSize, L"Clean", _TRUNCATE);
            return 0;
        }
        std::wstring out = result.type + L":" + result.status + L":" + result.detail;
        wcsncpy_s(resultBuffer, bufferSize, out.c_str(), _TRUNCATE);
        return result.isHigh ? 3 : 1;
    } catch (...) {
        // P0-逃逸修复: 扫描异常绝不可当作"干净"。恶意畸形路径会让扫描抛异常,
        // 若静默返回 -1 (main.cpp 只打日志不评分) 即逃逸。
        // 此处返回 1 (可疑) + 明确错误串, 使 onNewProcessCreated 走 reportScanScore
        // 评分链路 (即使分数不高也会被记录/审计, 而非静默放行)。
        if (resultBuffer && bufferSize > 0) {
            wcsncpy_s(resultBuffer, bufferSize, L"ScanError:unreadable", _TRUNCATE);
        }
        return 1;  // 可疑, 交由行为引擎评分处置
    }
}

__declspec(dllexport) int zeta_engine_check_signature(const wchar_t* path) {
    if (!path) return 0;
    try {
        return SignScanner().verify(path) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

__declspec(dllexport) int zeta_engine_scan_process(unsigned long pid,
    wchar_t* outType, int typeSize, wchar_t* outStatus, int statusSize,
    wchar_t* outDetail, int detailSize) {
    try {
        ScanResult result = ScanEngine::instance().scanProcess(pid);
        if (result.type.empty()) return 0;
        if (outType && typeSize > 0)
            wcsncpy_s(outType, typeSize, result.type.c_str(), _TRUNCATE);
        if (outStatus && statusSize > 0)
            wcsncpy_s(outStatus, statusSize, result.status.c_str(), _TRUNCATE);
        if (outDetail && detailSize > 0)
            wcsncpy_s(outDetail, detailSize, result.detail.c_str(), _TRUNCATE);
        return result.isHigh ? 3 : 1;
    } catch (...) {
        return -1;
    }
}

}
