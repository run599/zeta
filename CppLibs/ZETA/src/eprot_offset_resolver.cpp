// ============================================================
// eprot_offset_resolver.cpp — 通用内核结构偏移解析器
//
// 自研轻量 PDB 解析器 (MSF + TPI), 从本地 PDB 精确解析内核结构
// 字段偏移, 覆盖全部硬编码的内核结构偏移:
//   _EPROCESS.Protection / _EPROCESS.Peb
//   _KTHREAD.TrapFrame / _KTRAP_FRAME.Rip
//   _PEB.Ldr / _LDR_DATA_TABLE_ENTRY.*
//   _KLDR_DATA_TABLE_ENTRY.Flags / .SignatureLevel
//
// 绕开 dbghelp (其加载内核镜像符号存在兼容问题)。全程本地文件读取,
// 零联网。解析成功下发给驱动替换硬编码宏, 失败回退硬编码 (双保险)。
// ============================================================

#include "eprot_offset_resolver.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

namespace {

constexpr LONG kOffsetMin = 0x100;    // EPROCESS.Protection 位于结构中后段
constexpr LONG kOffsetMax = 0x1000;   // 不可能超过一页

const wchar_t* kRegPath = L"Software\\ZETA";
const wchar_t* kRegValue = L"EprocessProtectionOffset";

// ================= 注册表缓存 (Protection 兼容) =================
LONG ReadCachedOffset() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRegPath, 0, KEY_READ, &key)
            != ERROR_SUCCESS) return 0;
    DWORD val = 0, size = sizeof(val);
    LONG r = RegQueryValueExW(key, kRegValue, nullptr, nullptr,
                              (LPBYTE)&val, &size);
    RegCloseKey(key);
    return (r == ERROR_SUCCESS && val >= (DWORD)kOffsetMin &&
            val <= (DWORD)kOffsetMax) ? (LONG)val : 0;
}

void WriteCachedOffset(LONG offset) {
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kRegPath, 0, nullptr, 0,
                        KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS) return;
    DWORD val = (DWORD)offset;
    RegSetValueExW(key, kRegValue, 0, REG_DWORD, (LPBYTE)&val, sizeof(val));
    RegCloseKey(key);
}

// ================= MSF 容器 =================
struct Msf {
    const BYTE* base = nullptr;
    size_t size = 0;
    DWORD blockSize = 0;
    std::vector<BYTE> dirData;
    DWORD numStreams = 0;
    std::vector<DWORD> streamSizes;
    std::vector<DWORD> pageList;
};

static bool MsfInit(Msf& m, const BYTE* base, size_t size) {
    m.base = base; m.size = size;
    if (size < 0x38) return false;
    if (memcmp(base, "Microsoft C/C++ MSF 7.00", 24) != 0) return false;
    m.blockSize = *(const DWORD*)(base + 0x20);
    if (m.blockSize < 0x200 || m.blockSize > 0x10000 || (m.blockSize & (m.blockSize - 1))) return false;
    DWORD numDirBytes = *(const DWORD*)(base + 0x2C);
    DWORD blockMapAddr = *(const DWORD*)(base + 0x34);
    DWORD numDirBlocks = (numDirBytes + m.blockSize - 1) / m.blockSize;
    if ((size_t)blockMapAddr * m.blockSize + (size_t)numDirBlocks * 4 > size) return false;
    const BYTE* mapPage = base + (size_t)blockMapAddr * m.blockSize;
    std::vector<DWORD> dirPages(numDirBlocks);
    memcpy(dirPages.data(), mapPage, (size_t)numDirBlocks * 4);
    m.dirData.resize(numDirBytes);
    size_t got = 0;
    for (DWORD i = 0; i < numDirBlocks && got < numDirBytes; i++) {
        if ((size_t)dirPages[i] * m.blockSize + m.blockSize > size) return false;
        size_t take = (std::min)((size_t)m.blockSize, numDirBytes - got);
        memcpy(m.dirData.data() + got, base + (size_t)dirPages[i] * m.blockSize, take);
        got += take;
    }
    if (m.dirData.size() < 4) return false;
    m.numStreams = *(const DWORD*)m.dirData.data();
    if (m.dirData.size() < 4 + (size_t)4 * m.numStreams) return false;
    for (DWORD i = 0; i < m.numStreams; i++)
        m.streamSizes.push_back(*(const DWORD*)(m.dirData.data() + 4 + (size_t)4 * i));
    size_t totalPages = 0;
    for (DWORD i = 0; i < m.numStreams; i++)
        totalPages += (m.streamSizes[i] + m.blockSize - 1) / m.blockSize;
    if (m.dirData.size() < 4 + (size_t)4 * m.numStreams + (size_t)4 * totalPages) return false;
    for (size_t i = 0; i < totalPages; i++)
        m.pageList.push_back(*(const DWORD*)(m.dirData.data() + 4 + (size_t)4 * m.numStreams + (size_t)4 * i));
    return true;
}

static bool MsfReadStream(const Msf& m, DWORD idx, std::vector<BYTE>& out) {
    if (idx >= m.numStreams) return false;
    DWORD sz = m.streamSizes[idx];
    DWORD npages = (sz + m.blockSize - 1) / m.blockSize;
    DWORD pageStart = 0;
    for (DWORD i = 0; i < idx; i++) pageStart += (m.streamSizes[i] + m.blockSize - 1) / m.blockSize;
    if ((size_t)pageStart + npages > m.pageList.size()) return false;
    out.resize(sz);
    size_t got = 0;
    for (DWORD i = 0; i < npages && got < sz; i++) {
        DWORD page = m.pageList[pageStart + i];
        if ((size_t)page * m.blockSize + m.blockSize > m.size) return false;
        size_t take = (std::min)((size_t)m.blockSize, (size_t)sz - got);
        memcpy(out.data() + got, m.base + (size_t)page * m.blockSize, take);
        got += take;
    }
    return true;
}

// ================= TPI 解析 =================
static const BYTE* ReadName(const BYTE* p, const BYTE* end, std::string& out) {
    out.clear();
    while (p < end && *p) { out.push_back((char)*p); p++; }
    return (p < end) ? p + 1 : p;
}

// 在 LF_FIELDLIST 中定位字段偏移
// 用 "field\0" 定位候选 (成员 name 后接 \0), 验证前导是 LF_MEMBER leaf
// + offset 合理性, 避免 "Peb" 误中 "UserPeb" 这类子串 (读取完整名二次确认)
static bool FindFieldOffset(const BYTE* fp, size_t flen, const BYTE* fEnd,
                            const char* fieldName, LONG& out) {
    if (flen < 12) return false;
    std::string whole((const char*)fp, flen);
    std::string needle = std::string(fieldName) + '\0';
    size_t pos = 0;
    while ((pos = whole.find(needle, pos)) != std::string::npos) {
        if (pos >= 10) {
            const BYTE* namePtr = fp + pos;  // "field\0" 的 field 起始
            // 此格式成员: leaf(2) attr(2) index(4)[LF_MEMBER] offset(2) name
            // LF_MEMBER_ST 无 index: leaf(2) attr(2) offset(2) name
            USHORT l1 = *(const USHORT*)(namePtr - 10);
            USHORT l2 = *(const USHORT*)(namePtr - 6);
            if (l1 == 0x150D || l1 == 0x150E || l2 == 0x150D || l2 == 0x150E) {
                // 读取完整成员名, 二次确认 (排除子串误匹配)
                std::string gotName;
                ReadName(namePtr, fEnd, gotName);
                if (gotName != fieldName) { pos += 1; continue; }
                LONG off = (LONG)*(const USHORT*)(namePtr - 2);
                if (off >= 0 && off <= kOffsetMax) {  // 偏移合理性
                    out = off;
                    return true;
                }
            }
        }
        pos += 1;
    }
    return false;
}

// 目标字段定义
struct FieldTarget {
    const char* structName;   // "_EPROCESS"
    const char* fieldName;    // "Protection"
    LONG* outOffset;          // 输出
};

// 解析整个 PDB, 填充所有目标偏移 (失败的保持 0)
static void ParsePdbForTargets(const std::vector<BYTE>& pdbData,
                               FieldTarget* targets, int targetCount) {
    for (int i = 0; i < targetCount; i++) *targets[i].outOffset = 0;

    Msf m;
    if (!MsfInit(m, pdbData.data(), pdbData.size())) return;
    std::vector<BYTE> tpi;
    if (!MsfReadStream(m, 2, tpi)) return;
    if (tpi.size() < 0x24) return;

    DWORD headerSize = *(const DWORD*)(tpi.data() + 4);
    DWORD recBytes   = *(const DWORD*)(tpi.data() + 0x10);
    DWORD begin      = *(const DWORD*)(tpi.data() + 8);
    if (headerSize > tpi.size()) return;

    const BYTE* records = tpi.data() + headerSize;
    const BYTE* recEnd  = records + recBytes;
    if (recEnd > tpi.data() + tpi.size()) recEnd = tpi.data() + tpi.size();

    // 线性扫描类型记录 (记录区连续; 记录与 TypeIndex 一一对应)
    std::vector<const BYTE*> recs;
    const BYTE* p = records;
    while (p + 4 <= recEnd) {
        USHORT len  = *(const USHORT*)p;
        USHORT leaf = *(const USHORT*)(p + 2);
        if (len < 2 || p + 2 + (size_t)len > recEnd) break;
        const BYTE* payload = p + 4;
        size_t payloadLen = (size_t)len - 2;
        recs.push_back(p);

        if (leaf == 0x1505 || leaf == 0x1508) {  // LF_STRUCTURE / LF_UNION
            if (payloadLen >= 8) {
                std::string name;
                ReadName(payload + 18, payload + payloadLen, name);
                for (int i = 0; i < targetCount; i++) {
                    if (*targets[i].outOffset != 0) continue;   // 已解析
                    if (name != targets[i].structName) continue;
                    DWORD fieldlist = *(const DWORD*)(payload + 4);
                    if (fieldlist < begin || fieldlist - begin >= recs.size()) continue;
                    const BYTE* flRec = recs[fieldlist - begin];
                    USHORT flLen  = *(const USHORT*)flRec;
                    USHORT flLeaf = *(const USHORT*)(flRec + 2);
                    if (flLeaf != 0x1203) continue;  // LF_FIELDLIST
                    const BYTE* fp = flRec + 4;
                    size_t flen = (size_t)flLen - 2;
                    const BYTE* fEnd = fp + flen;
                    if (fEnd > recEnd) fEnd = recEnd;
                    LONG off = 0;
                    if (FindFieldOffset(fp, (size_t)(fEnd - fp), fEnd,
                                        targets[i].fieldName, off))
                        *targets[i].outOffset = off;
                }
            }
        }
        p += 2 + len;
    }
}

// ================= PE CodeView 提取 =================
static bool ReadFileBytes(const wchar_t* path, std::vector<BYTE>& out) {
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz;
    GetFileSizeEx(hFile, &sz);
    if (sz.QuadPart <= 0) { CloseHandle(hFile); return false; }
    out.resize((size_t)sz.QuadPart);
    DWORD rd = 0;
    BOOL ok = ReadFile(hFile, out.data(), (DWORD)out.size(), &rd, NULL);
    CloseHandle(hFile);
    return ok && rd == out.size();
}

static bool ExtractKernelCodeView(std::wstring& pdbName, GUID& guid, DWORD& age) {
    wchar_t sysRoot[MAX_PATH] = {0};
    GetWindowsDirectoryW(sysRoot, MAX_PATH);
    std::vector<BYTE> pe;
    if (!ReadFileBytes((std::wstring(sysRoot) + L"\\System32\\ntoskrnl.exe").c_str(), pe))
        return false;
    if (pe.size() < 0x1000) return false;

    DWORD e_lfanew = *(const DWORD*)(pe.data() + 0x3C);
    if (e_lfanew + 0x20 > pe.size()) return false;
    if (*(const DWORD*)(pe.data() + e_lfanew) != 0x00004550) return false;
    WORD optSize  = *(const WORD*)(pe.data() + e_lfanew + 20);
    WORD optMagic = *(const WORD*)(pe.data() + e_lfanew + 24);
    if (optMagic != 0x20B || optSize < 0x70) return false;

    DWORD ddRVA  = *(const DWORD*)(pe.data() + e_lfanew + 24 + 112 + 6 * 8);
    DWORD ddSize = *(const DWORD*)(pe.data() + e_lfanew + 24 + 112 + 6 * 8 + 4);
    if (ddRVA == 0 || ddSize == 0) return false;

    WORD numSections = *(const WORD*)(pe.data() + e_lfanew + 6);
    const BYTE* secTable = pe.data() + e_lfanew + 24 + optSize;
    auto RvaToOffset = [&](DWORD rva) -> DWORD {
        for (WORD i = 0; i < numSections; i++) {
            const BYTE* sec = secTable + (size_t)i * 40;
            DWORD va  = *(const DWORD*)(sec + 12);
            DWORD vs  = *(const DWORD*)(sec + 8);
            DWORD raw = *(const DWORD*)(sec + 20);
            if (rva >= va && rva < va + vs && raw != 0)
                return raw + (rva - va);
        }
        return 0;
    };

    DWORD debugOff = RvaToOffset(ddRVA);
    if (debugOff == 0 || debugOff + ddSize > pe.size()) return false;
    DWORD nEntries = ddSize / 28;
    for (DWORD i = 0; i < nEntries; i++) {
        const BYTE* ent = pe.data() + debugOff + (size_t)i * 28;
        DWORD type = *(const DWORD*)(ent + 12);
        DWORD raw  = *(const DWORD*)(ent + 24);
        if (type == 2 && raw != 0 && raw + 24 <= pe.size()) {
            const BYTE* cv = pe.data() + raw;
            if (*(const DWORD*)cv == 0x53445352) {  // "RSDS"
                memcpy(&guid, cv + 4, sizeof(GUID));
                age = *(const DWORD*)(cv + 20);
                const char* name = (const char*)(cv + 24);
                int wlen = MultiByteToWideChar(CP_ACP, 0, name, -1, nullptr, 0);
                if (wlen > 1) {
                    pdbName.resize(wlen - 1);
                    MultiByteToWideChar(CP_ACP, 0, name, -1, &pdbName[0], wlen);
                    return true;
                }
            }
        }
    }
    return false;
}

// ================= 符号目录 + 路径 =================
static std::wstring GetSymbolDirectory() {
    wchar_t buf[8192] = {0};
    if (!GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", buf, 8192)) return L"";
    std::wstring all(buf);
    size_t start = 0;
    while (start <= all.size()) {
        size_t sep = all.find(L';', start);
        std::wstring item = all.substr(start, sep == std::wstring::npos
                                          ? all.size() - start : sep - start);
        size_t b = item.find_first_not_of(L" \t");
        size_t e = item.find_last_not_of(L" \t");
        if (b != std::wstring::npos) item = item.substr(b, e - b + 1);
        if (!item.empty() && item.find(L"srv") != 0 && item.find(L"http") != 0 &&
            item.find(L"\\\\") != 0 && item.find(L"https") != 0)
            return item;
        if (sep == std::wstring::npos) break;
        start = sep + 1;
    }
    return L"";
}

static std::string GuidToHex(const GUID& g) {
    char buf[64];
    sprintf_s(buf, "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
              g.Data1, g.Data2, g.Data3,
              g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
              g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return buf;
}

// 定位当前机器内核 PDB 文件路径
static bool GetKernelPdbPath(std::wstring& pdbPath) {
    std::wstring symbolDir = GetSymbolDirectory();
    if (symbolDir.empty()) return false;
    std::wstring pdbNameW;
    GUID guid{};
    DWORD age = 0;
    if (!ExtractKernelCodeView(pdbNameW, guid, age) || pdbNameW.empty()) return false;
    char ageHex[16];
    sprintf_s(ageHex, "%X", age);
    std::string hexGuid = GuidToHex(guid);
    std::wstring hexGuidW(hexGuid.begin(), hexGuid.end());
    std::wstring ageHexW(ageHex, ageHex + strlen(ageHex));
    pdbPath = symbolDir + L"\\" + pdbNameW + L"\\" +
        hexGuidW + ageHexW + L"\\" + pdbNameW;
    return true;
}

} // namespace

// ============================================================
// ResolveKernelOffsets — 解析全部内核结构偏移
// ============================================================
extern "C" __declspec(dllexport) int ResolveKernelOffsets(KernelOffsets* out) {
    if (!out) return 0;
    *out = KernelOffsets{};

    std::wstring pdbPath;
    if (!GetKernelPdbPath(pdbPath)) return 0;
    std::vector<BYTE> pdbData;
    if (!ReadFileBytes(pdbPath.c_str(), pdbData)) return 0;

    FieldTarget targets[] = {
        { "_EPROCESS",               "Protection",       &out->EprocessProtection },
        { "_EPROCESS",               "Peb",              &out->EprocessPeb },
        { "_KTHREAD",                "TrapFrame",        &out->KthreadTrapFrame },
        { "_KTRAP_FRAME",            "Rip",              &out->KtrapFrameRip },
        { "_PEB",                    "Ldr",              &out->PebLdr },
        { "_LDR_DATA_TABLE_ENTRY",   "InMemoryOrderLinks", &out->LdrInMemoryLinks },
        { "_LDR_DATA_TABLE_ENTRY",   "DllBase",          &out->LdrDllBase },
        { "_LDR_DATA_TABLE_ENTRY",   "SizeOfImage",      &out->LdrSizeOfImage },
        { "_LDR_DATA_TABLE_ENTRY",   "BaseDllName",      &out->LdrBaseDllName },
        { "_KLDR_DATA_TABLE_ENTRY",  "Flags",            &out->KldrFlags },
        { "_KLDR_DATA_TABLE_ENTRY",  "SignatureLevel",   &out->KldrSignatureLevel },
    };
    int nTargets = sizeof(targets) / sizeof(targets[0]);
    ParsePdbForTargets(pdbData, targets, nTargets);

    // 合理性校验 + 统计 (0=未解析; 偏移范围 0x1~0x1000, 小偏移如 Rip=0x78 也有效)
    int n = 0;
    LONG* p = &out->EprocessProtection;
    for (int i = 0; i < nTargets; i++) {
        if (p[i] > 0 && p[i] <= kOffsetMax) n++;
        else p[i] = 0;
    }
    return n;
}

// ============================================================
// ResolveEprocessProtectionOffset — 兼容入口 (仅 Protection)
// ============================================================
extern "C" __declspec(dllexport) LONG ResolveEprocessProtectionOffset() {
    LONG cached = ReadCachedOffset();
    if (cached != 0) return cached;

    KernelOffsets ko;
    if (ResolveKernelOffsets(&ko) > 0 && ko.EprocessProtection) {
        WriteCachedOffset(ko.EprocessProtection);
        return ko.EprocessProtection;
    }
    return 0;
}
