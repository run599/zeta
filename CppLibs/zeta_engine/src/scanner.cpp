#define _WIN32_WINNT 0x0601
#define WINVER 0x0601
#include "zeta_engine.h"
#include <yara.h>
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
struct Logger {
    static Logger& instance() { static Logger l; return l; }
    void info(const std::wstring&, const std::wstring&, const std::wstring&) {}
    void warn(const std::wstring&, const std::wstring&, const std::wstring&) {}
    void debug(const std::wstring&, const std::wstring&, const std::wstring&) {}
    void stop() {}
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
    std::string val = cleaned.substr(valStart, 5);
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
            result.push_back(std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(s));
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
SignScanner::SignScanner() : m_wintrust(nullptr), m_loaded(false) {
    m_wintrust = LoadLibraryW(L"wintrust.dll");
    if (m_wintrust) m_loaded = true;
}

SignScanner::~SignScanner() {
    if (m_wintrust) FreeLibrary(m_wintrust);
}

bool SignScanner::verify(const std::wstring& filePath) {
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
};

static int yara_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    (void)context;
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        YaraMatchContext* ctx = (YaraMatchContext*)user_data;
        if (rule && ctx) {
            ctx->matchedRule = rule->identifier ? std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(rule->identifier) : L"";
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

bool YaraScanner::compileRules() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Free old rules if any
    if (m_rules) {
        yr_rules_destroy(m_rules);
        m_rules = nullptr;
    }
    
    if (m_ruleFiles.empty()) return false;
    
    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) return false;
    
    bool ok = true;
    for (const auto& ruleFile : m_ruleFiles) {
        std::string narrowFile = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(ruleFile);
        FILE* f = fopen(narrowFile.c_str(), "rb");
        if (!f) { ok = false; continue; }
        int errors = yr_compiler_add_file(compiler, f, nullptr, narrowFile.c_str());
        fclose(f);
        if (errors > 0) ok = false;
    }
    
    if (ok) {
        yr_compiler_get_rules(compiler, &m_rules);
    }
    yr_compiler_destroy(compiler);
    
    return m_rules != nullptr;
}

bool YaraScanner::loadPath(const std::wstring& path) {
    // Collect .yar files
    collectRuleFiles(path, m_ruleFiles);
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
    std::wstring& outRule, std::wstring& outLabel, bool& outIsHigh) {
    if (!m_rules) return false;

    // Map std::wstring paths to std::string for YARA
    std::string narrowPath = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(filePath);
    
    // Scan with cached compiled rules
    YaraMatchContext ctx;
    ctx.isHigh = false;

    int rc = yr_rules_scan_file(m_rules, narrowPath.c_str(), SCAN_FLAGS_FAST_MODE,
        yara_callback, &ctx, 0);

    bool matched = (rc == ERROR_SUCCESS && !ctx.matchedRule.empty());

    if (matched) {
        outRule = ctx.matchedRule;
        outLabel = ctx.matchedString;
        outIsHigh = ctx.isHigh;
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
    m_suspiciousApis.clear();
    m_highRiskApis.clear();
    m_suspiciousSections.clear();
    
    for (const auto& api : mgr.suspiciousApis) {
        m_suspiciousApis.push_back(std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(api));
    }
    for (const auto& api : mgr.highRiskApis) {
        m_highRiskApis.push_back(std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(api));
    }
    for (const auto& sec : mgr.suspiciousSections) {
        m_suspiciousSections.push_back(std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(sec));
    }
}

int PeScanner::scan(const std::wstring& filePath, bool enhancedMode) {
    m_details.clear();

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
    score += analyzeImports(data, scoring);
    score += analyzeSections(data, scoring);
    score += analyzeEntropy(data, scoring);
    score += analyzeEntryPoint(data, scoring);

    return score;
}

std::wstring PeScanner::getDetails() {
    return m_details;
}

int PeScanner::analyzeImports(const std::vector<unsigned char>& data, const EdrScoring& scoring) {
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
                    std::string suspStr(suspApi.begin(), suspApi.end());
                    if (apiNameStr.find(suspStr) != std::string::npos) {
                        score += scoring.suspiciousApi;
                        m_details += L" SuspiciousAPI:" + std::wstring(apiNameStr.begin(), apiNameStr.end());
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    for (const auto& highApi : m_highRiskApis) {
                        std::string highStr(highApi.begin(), highApi.end());
                        if (apiNameStr.find(highStr) != std::string::npos) {
                            score += scoring.highRiskApi;
                            m_details += L" HighRiskAPI:" + std::wstring(apiNameStr.begin(), apiNameStr.end());
                            break;
                        }
                    }
                }
            }
        }
    }

    return score;
}

int PeScanner::analyzeSections(const std::vector<unsigned char>& data, const EdrScoring& scoring) {
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
        std::wstring sectionName = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(name);

        for (const auto& susp : m_suspiciousSections) {
            if (sectionName.find(susp) != std::wstring::npos) {
                score += scoring.suspiciousSection;
                m_details += L" Packed:" + sectionName;
            }
        }
        if (section->Characteristics & IMAGE_SCN_MEM_WRITE && section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            score += scoring.rwxSection;
            m_details += L" RWX:" + sectionName;
        }
        sectionOffset += sizeof(IMAGE_SECTION_HEADER);
    }
    return score;
}

int PeScanner::analyzeEntropy(const std::vector<unsigned char>& data, const EdrScoring& scoring) {
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
    if (entropy > 7.0) { score += scoring.highEntropy; m_details += L" HighEntropy:" + std::to_wstring(entropy); }
    else if (entropy > 6.5) { score += 10; }
    return score;
}

int PeScanner::analyzeEntryPoint(const std::vector<unsigned char>& data, const EdrScoring& scoring) {
    if (data.size() < 0x3C + 4) return 0;
    unsigned long peOffset = *reinterpret_cast<const unsigned long*>(&data[0x3C]);
    if (peOffset + sizeof(IMAGE_NT_HEADERS64) >= data.size()) return 0;
    int score = 0;
    unsigned char* ncData = const_cast<unsigned char*>(data.data());
    IMAGE_NT_HEADERS64* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(ncData + peOffset);
    if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 0;
    unsigned long ep = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    if (ep == 0) { score += scoring.noEntryPoint; m_details += L" NoEP"; }
    return score;
}

// ============================================================
// ScanEngine
// ============================================================
ScanEngine& ScanEngine::instance() {
    static ScanEngine inst;
    return inst;
}

ScanEngine::ScanEngine() : m_scanning(false), m_progress(0) {
    // Initialize YARA library
    yr_initialize();
}

ScanEngine::~ScanEngine() {
    stopScan();
    // Finalize YARA library
    yr_finalize();
}

bool ScanEngine::init(const std::wstring& rulesDir) {
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
        if (m_yaraScanner.scan(filePath, ruleName, label, isHigh)) {
            result.type = L"yara";
            result.status = isHigh ? L"Threat" : L"Suspicious";
            result.detail = ruleName;
            result.isHigh = isHigh;
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_cache.size() < MAX_CACHE) m_cache[filePath] = result;
            return result;
        }
    }

    // 2. PE scan (heuristics)
    if (enabled.enablePeHeuristics) {
        int peScore = m_peScanner.scan(filePath, enhancedMode);
        if (peScore >= scoring.threatThreshold) {
            result.type = L"pe";
            result.status = L"Threat";
            result.detail = L"PE heuristic: " + std::to_wstring(peScore);
            result.isHigh = peScore > scoring.highThreatThreshold;
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
            std::string extStr(ext.begin(), ext.end());
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

// ============================================================
// DLL Exports
// ============================================================
static std::wstring g_rulesDir;

extern "C" {

__declspec(dllexport) int zeta_engine_init(const wchar_t* rulesDir) {
    g_rulesDir = rulesDir ? rulesDir : L"C:\\ProgramData\\ZETA\\Rules";
    return ScanEngine::instance().init(g_rulesDir) ? 1 : 0;
}

__declspec(dllexport) void* zeta_engine_create() {
    ScanEngine::instance().init(g_rulesDir);
    return &ScanEngine::instance();
}

__declspec(dllexport) void zeta_engine_destroy(void* engine) {
    (void)engine;
}

__declspec(dllexport) int zeta_engine_wrapper_scan(void* engine, const wchar_t* path,
    wchar_t* resultBuffer, int bufferSize) {
    (void)engine;
    if (!path || !resultBuffer || bufferSize <= 0) return -1;
    ScanResult result = ScanEngine::instance().scanFile(path);
    if (result.type.empty()) {
        wcsncpy_s(resultBuffer, bufferSize, L"Clean", _TRUNCATE);
        return 0;
    }
    std::wstring out = result.type + L":" + result.status + L":" + result.detail;
    wcsncpy_s(resultBuffer, bufferSize, out.c_str(), _TRUNCATE);
    return result.isHigh ? 3 : 1;
}

__declspec(dllexport) int zeta_engine_check_signature(const wchar_t* path) {
    if (!path) return 0;
    return SignScanner().verify(path) ? 1 : 0;
}

}
