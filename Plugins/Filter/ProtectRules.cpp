#include "DriverCommon.h"

// Forward declarations for platform API functions not declared in standard headers
extern "C" {
    HANDLE PsGetProcessInheritedFromUniqueProcessId(PEPROCESS Process);
    UCHAR* PsGetProcessImageFileName(PEPROCESS Process);
}

constexpr auto TRUST_CACHE_SIZE = 1024;
constexpr auto TRUST_CACHE_TTL_SEC = 300;

typedef struct _TRUST_CACHE_ENTRY {
 PEPROCESS Process;
 LARGE_INTEGER ProcessCreateTime;
 ULONG TrustLevel;  // 0=NONE, 1=SIGNED, 2=SYSTEM
 LARGE_INTEGER CacheTime;
} TRUST_CACHE_ENTRY, * PTRUST_CACHE_ENTRY;

static TRUST_CACHE_ENTRY TrustCache[TRUST_CACHE_SIZE];
static KSPIN_LOCK TrustCacheLock;
static BOOLEAN g_CacheInitialized = FALSE;

// M1-5: 勒索挂起超时兜底 — 表/锁在此定义 (InitializeRulesEngine 需先引用)
static RANSOM_SUSPEND_ENTRY g_RansomSuspendTrack[RANSOM_SUSPEND_TRACK_MAX];
static KSPIN_LOCK g_RansomSuspendLock;
static VOID RansomExp_RegisterSuspend(ULONG Pid);
static VOID RansomExp_UnregisterSuspend(ULONG Pid);

static ERESOURCE Lock_Registry;
static ERESOURCE Lock_Process;
static ERESOURCE Lock_File;
static PRULE_NODE g_RegistryBlockList = NULL;
static PRULE_NODE g_RegistryTrustedList = NULL;
static PRULE_NODE g_ProcessTrustedPaths = NULL;
static PRULE_NODE g_ProcessExploitable = NULL;
static PRULE_NODE g_FileProtectedPaths = NULL;
static PRULE_NODE g_FileExceptionPaths = NULL;
static PRULE_NODE g_FileRansomExts = NULL;
static PRULE_NODE g_DocBackupExtList = NULL;   // Rule_File_DocBackup_Extensions (Rules_FileProtect.json)

PREFIX_HASH_TABLE g_FilePrefixHashes = {0};
PREFIX_HASH_TABLE g_RegistryPrefixHashes = {0};
PREFIX_HASH_TABLE g_ProcessPrefixHashes = {0};

const PCWSTR Helper_NaturallyCompressedExtensions[] = {
 L".zip", L".7z", L".rar", L".tar", L".gz",
 L".jpg", L".jpeg", L".png", L".webp", L".gif",
 L".mp3", L".wav", L".aac", L".ogg", L".flac",
 L".mp4", L".avi", L".mov", L".wmv", L".mkv",
 L".docx", L".xlsx", L".pptx", L".pdf", L".wps",
 L".apk", L".jar", L".class", L".db", L".sqlite",
 L".txt", L".json", L".xml", L".ini", L".cfg",
 L".conf", L".log", L".csv", L".html", L".htm",
 L".css", L".js", L".ts", L".py", L".java",
 L".cpp", L".c", L".h", L".hpp", L".cs",
 L".vb", L".php", L".rb", L".go", L".rs",
 L".md", L".rtf", L".yaml", L".yml", L".toml",
 L".lua", L".sh", L".bat", L".cmd", L".ps1",
 L".vbs", L".jsx", L".tsx", L".vue", L".svelte",
 L".less", L".scss", L".sass", L".styl", L".svg"
};

static VOID FreeList(PRULE_NODE* Head) {
	PRULE_NODE Current = *Head;
	while (Current) {
		PRULE_NODE Next = Current->Next;
		if (Current->Pattern.Buffer) ZetaFree(Current->Pattern.Buffer);
		ZetaFree(Current);
		Current = Next;
	}
	*Head = NULL;
}

static ULONG CountRules(PRULE_NODE Head) {
	ULONG Count = 0;
	while (Head) {
		Count++;
		Head = Head->Next;
	}
	return Count;
}

static VOID AddRule(PRULE_NODE* Head, PUNICODE_STRING RuleStr) {
 if (!RuleStr || !RuleStr->Buffer) return;

 PRULE_NODE Check = *Head;
 while (Check) {
 if (RtlEqualUnicodeString(&Check->Pattern, RuleStr, TRUE)) {
 return;
 }
 Check = Check->Next;
 }

 PRULE_NODE Node = (PRULE_NODE)ZetaAllocate(sizeof(RULE_NODE));
 if (!Node) return;

 SIZE_T Size = RuleStr->Length + sizeof(WCHAR);
 Node->Pattern.Buffer = (PWCHAR)ZetaAllocate(Size);
 if (!Node->Pattern.Buffer) {
 ZetaFree(Node);
 return;
 }

 RtlCopyMemory(Node->Pattern.Buffer, RuleStr->Buffer, RuleStr->Length);
 Node->Pattern.Buffer[RuleStr->Length / sizeof(WCHAR)] = L'\0';
 Node->Pattern.Length = RuleStr->Length;
 Node->Pattern.MaximumLength = (USHORT)Size;

 Node->Next = *Head;
 *Head = Node;
}

static BOOLEAN HasSuffix(PCUNICODE_STRING String, PCWSTR Suffix) {
 if (!String || !String->Buffer || !Suffix) return FALSE;

 SIZE_T StringLenChars = String->Length / sizeof(WCHAR);
 SIZE_T SuffixLenChars = 0;

 while (Suffix[SuffixLenChars] != L'\0') {
 SuffixLenChars++;
 }

 if (StringLenChars < SuffixLenChars) return FALSE;

 PCWSTR Ptr = String->Buffer + (StringLenChars - SuffixLenChars);

 for (SIZE_T i = 0; i < SuffixLenChars; i++) {
 if (RtlDowncaseUnicodeChar(Ptr[i]) != RtlDowncaseUnicodeChar(Suffix[i])) {
 return FALSE;
 }
 }
 return TRUE;
}

BOOLEAN WildcardMatch(PCWSTR Pattern, PCWSTR String, USHORT StringLengthBytes) {
 if (Pattern == NULL || String == NULL) return FALSE;

 USHORT StringLenChars = StringLengthBytes / sizeof(WCHAR);
 PCWSTR mp = NULL;
 PCWSTR cp = NULL;
 PCWSTR StringEnd = String + StringLenChars;

 while (String < StringEnd) {
 if (*Pattern == L'*') {
 mp = ++Pattern;
 cp = String + 1;
 }
 else if (*Pattern == L'?' || (RtlDowncaseUnicodeChar(*Pattern) == RtlDowncaseUnicodeChar(*String))) {
 Pattern++;
 String++;
 }
 else if (mp != NULL) {
 Pattern = mp;
 String = cp++;
 }
 else {
 return FALSE;
 }
 }
 while (*Pattern == L'*') {
 Pattern++;
 }

 return (*Pattern == L'\0') ? TRUE : FALSE;
}

// ── Prefix hash pre-filter ──────────────────────────────────────────
static ULONG FnvHashW(PCWSTR Str, USHORT Len) {
    ULONG h = 2166136261UL;
    for (USHORT i = 0; i < Len; i++) {
        h ^= (ULONG)RtlDowncaseUnicodeChar(Str[i]);
        h *= 16777619UL;
    }
    return h;
}

static ULONG ExtractFirstComponentHash(PCWSTR Pattern) {
    if (!Pattern) return 0;
    PCWSTR p = Pattern;
    while (*p == L'*' || *p == L'?' || *p == L'\\') p++;
    if (*p == L'\0') return 0;
    PCWSTR s = p;
    while (*p && *p != L'\\') p++;
    USHORT len = (USHORT)(p - s);
    return len ? FnvHashW(s, len) : 0;
}

static VOID RebuildPrefixHashes(PRULE_NODE List, PPREFIX_HASH_TABLE Tbl) {
    Tbl->Count = 0;
    for (PRULE_NODE N = List; N && Tbl->Count < MAX_PREFIX_HASHES; N = N->Next) {
        if (N->Pattern.Buffer && N->Pattern.Length > 0) {
            ULONG h = ExtractFirstComponentHash(N->Pattern.Buffer);
            if (h) {
                Tbl->Entries[Tbl->Count].Hash = h;
                Tbl->Entries[Tbl->Count].HasLeadingWildcard =
                    (N->Pattern.Buffer[0] == L'*' && N->Pattern.Buffer[1] == L'\\');
                Tbl->Count++;
            }
        }
    }
}

static BOOLEAN PrefixHashMatch(PCWSTR Str, USHORT Len, PPREFIX_HASH_TABLE Tbl) {
    if (!Tbl->Count) return TRUE;
    PCWSTR p = Str;
    if (*p == L'\\') p++;
    if (p[0] && p[1] == L':') p += 2;
    if (*p == L'\\') p++;
    // 检查多个路径组件以兼容 NT 设备路径格式
    // 驱动返回的进程路径是 \Device\HarddiskVolume3\Program Files\... 格式
    // 第一个组件是 "Device" 而非真实目录名，需要跳过 NT 前缀组件
    for (int comp = 0; comp < 4; comp++) {
        PCWSTR s = p;
        while (*p && *p != L'\\') p++;
        USHORT clen = (USHORT)(p - s);
        if (!clen) return TRUE;
        ULONG ih = FnvHashW(s, clen);
        for (ULONG i = 0; i < Tbl->Count; i++)
            if (Tbl->Entries[i].Hash == ih) return TRUE;
        if (*p != L'\\') break;
        p++; // 跳过反斜杠进入下一组件
    }
    return FALSE;
}

static ULONG ProcessJsonUnescape(PWCHAR Buffer, ULONG LengthChars) {
 if (!Buffer || LengthChars == 0) return 0;

 ULONG WriteIdx = 0;
 ULONG ReadIdx = 0;

 while (ReadIdx < LengthChars) {
 if (Buffer[ReadIdx] == L'\\' && (ReadIdx + 1 < LengthChars)) {
 WCHAR NextChar = Buffer[ReadIdx + 1];
 if (NextChar == L'\\' || NextChar == L'"' || NextChar == L'/') {
 Buffer[WriteIdx++] = NextChar;
 ReadIdx += 2;
 }
 else if (NextChar == L'n') { Buffer[WriteIdx++] = L'\n'; ReadIdx += 2; }
 else if (NextChar == L'r') { Buffer[WriteIdx++] = L'\r'; ReadIdx += 2; }
 else if (NextChar == L't') { Buffer[WriteIdx++] = L'\t'; ReadIdx += 2; }
 else {
 Buffer[WriteIdx++] = Buffer[ReadIdx++];
 }
 }
 else {
 Buffer[WriteIdx++] = Buffer[ReadIdx++];
 }
 }

 Buffer[WriteIdx] = L'\0';
 return WriteIdx * sizeof(WCHAR);
}

static VOID SkipWhitespace(PCHAR* Ptr, PCHAR End) {
 while (*Ptr < End) {
 char c = **Ptr;
 if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
 (*Ptr)++;
 }
 else {
 break;
 }
 }
}

static VOID ParseAndLoadRules(PCHAR JsonContent, ULONG ContentLength, PCSTR KeyName, PRULE_NODE* ListHead, BOOLEAN SafeOnly) {
 if (!JsonContent || !KeyName || !ListHead) return;

 PCHAR Ptr = JsonContent;
 PCHAR End = JsonContent + ContentLength;
 SIZE_T KeyLen = 0;
 while (KeyName[KeyLen] != '\0') KeyLen++;

 while (Ptr < End) {
 if (*Ptr == '"') {
 if ((SIZE_T)(End - Ptr) > KeyLen && RtlCompareMemory(Ptr + 1, KeyName, KeyLen) == KeyLen) {
 if (*(Ptr + 1 + KeyLen) == '"') {
 Ptr += 1 + KeyLen + 1;

 SkipWhitespace(&Ptr, End);
 if (Ptr >= End || *Ptr != ':') continue;
 Ptr++;

 SkipWhitespace(&Ptr, End);
 if (Ptr >= End || *Ptr != '[') continue;
 Ptr++;

 while (Ptr < End) {
 SkipWhitespace(&Ptr, End);
 if (Ptr >= End || *Ptr == ']') {
 if (Ptr < End) Ptr++;
 return;
 }

 if (*Ptr == '"') {
 PCHAR StartQuote = ++Ptr;
 BOOLEAN Escaped = FALSE;

 while (Ptr < End) {
 if (*Ptr == '"' && Escaped == FALSE) break;
 if (*Ptr == '\\') {
 Escaped = (Escaped == FALSE) ? TRUE : FALSE;
 }
 else {
 Escaped = FALSE;
 }
 Ptr++;
 }

 if (Ptr < End && *Ptr == '"') {
 ULONG UTF8Len = (ULONG)(Ptr - StartQuote);
 if (UTF8Len > 0) {
 ULONG WideSize = 0;
 RtlUTF8ToUnicodeN(NULL, 0, &WideSize, StartQuote, UTF8Len);

 if (WideSize > 0) {
 PWCHAR WideBuffer = (PWCHAR)ZetaAllocate(WideSize + sizeof(WCHAR));
 if (WideBuffer) {
 ULONG ResultSize = 0;
 RtlUTF8ToUnicodeN(WideBuffer, WideSize, &ResultSize, StartQuote, UTF8Len);
 ULONG FinalSize = ProcessJsonUnescape(WideBuffer, ResultSize / sizeof(WCHAR));

 UNICODE_STRING Us;
 Us.Buffer = WideBuffer;
 Us.Length = (USHORT)FinalSize;
 Us.MaximumLength = (USHORT)(WideSize + sizeof(WCHAR));

 AddRule(ListHead, &Us);
 // Mark safe-only rule (only applies to safe file extensions)
 if (SafeOnly && *ListHead) {
  (*ListHead)->OnlySafeTypes = TRUE;
 }
 ZetaFree(WideBuffer);
 }
 }
 }
 Ptr++;
 }
 }
 else {
 Ptr++;
 }
 }
 return;
 }
 }
 }
 Ptr++;
 }
}

// M1-4: 规则文件结构完整性校验 (替换原恒假死代码)
//
// 目标: 防止规则文件被损坏/截断/清空成空壳后"静默加载空规则"——
//      驱动认为规则已加载, 实际拦截全空 (攻击者/故障导致规则失效不可见)。
//
// 校验内容 (轻量扫描, 不引入 JSON 解析器):
//   1. 基础结构: 字符串引号闭合、{ } 配平、顶层为 '{' 起始的对象。
//   2. RequireRuleKeys=TRUE (系统规则): 文件中必须出现 "Rule_xxx" 键
//      (防被清空成 "{}" 或空壳; 用户规则 RequireRuleKeys=FALSE 允许清空)。
//
// 返回 TRUE=通过 / FALSE=损坏或空壳。
static BOOLEAN VerifyRulesFileIntegrity(PCHAR FileBuffer, ULONG FileLength, BOOLEAN RequireRuleKeys) {
    if (!FileBuffer || FileLength == 0) return FALSE;

    // 去首尾空白
    PCHAR p = FileBuffer;
    PCHAR end = FileBuffer + FileLength;
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    while (end > p && (*(end - 1) == ' ' || *(end - 1) == '\t' ||
                       *(end - 1) == '\n' || *(end - 1) == '\r')) end--;
    if (end - p < 2) return FALSE;               // 空文件
    if (*p != '{') return FALSE;                 // 顶层必须是对象

    LONG depthBrace = 0;
    BOOLEAN inString = FALSE;
    BOOLEAN sawRuleKey = FALSE;
    static const char rulePrefix[] = "Rule_";
    const SIZE_T prefixLen = sizeof(rulePrefix) - 1;

    for (PCHAR c = p; c < end; c++) {
        char ch = *c;

        if (inString) {
            if (ch == '\\') { if (c + 1 < end) c++; continue; }  // 转义: 跳过下一字节
            if (ch == '"') inString = FALSE;
            continue;
        }

        if (ch == '"') {
            inString = TRUE;
            // 判断字符串值是否以 Rule_ 开头 (键名形如 "Rule_Registry_BlockList")
            if ((SIZE_T)(end - c) > prefixLen + 1 &&
                RtlCompareMemory(c + 1, rulePrefix, prefixLen) == prefixLen) {
                sawRuleKey = TRUE;
            }
            continue;
        }
        if (ch == '{') { depthBrace++; continue; }
        if (ch == '}') {
            depthBrace--;
            if (depthBrace < 0) return FALSE;    // 多余的 '}' → 截断/错乱
            continue;
        }
    }

    if (inString) return FALSE;                  // 字符串引号未闭合
    if (depthBrace != 0) return FALSE;           // 大括号未配平
    if (RequireRuleKeys && !sawRuleKey) return FALSE;
    return TRUE;
}

VOID InitializeRulesEngine() {
 ExInitializeResourceLite(&Lock_Registry);
 ExInitializeResourceLite(&Lock_Process);
 ExInitializeResourceLite(&Lock_File);
 KeInitializeSpinLock(&TrustCacheLock);
 RtlZeroMemory(TrustCache, sizeof(TrustCache));
 g_CacheInitialized = TRUE;

 // M1-5: 勒索挂起超时跟踪表初始化
 KeInitializeSpinLock(&g_RansomSuspendLock);
 RtlZeroMemory(g_RansomSuspendTrack, sizeof(g_RansomSuspendTrack));
}

VOID UninitializeRulesEngine() {
 // 在 DriverUnload 时先 ObDereferenceObject 所有缓存的 EPROCESS
	// 再释放 ERESOURCE，避免 refcount 泄漏
	if (g_CacheInitialized) {
		KIRQL OldIrql;
		KeAcquireSpinLock(&TrustCacheLock, &OldIrql);
		for (ULONG i = 0; i < TRUST_CACHE_SIZE; i++) {
			if (TrustCache[i].Process) {
				ObDereferenceObject(TrustCache[i].Process);
				TrustCache[i].Process = NULL;
			}
		}
		KeReleaseSpinLock(&TrustCacheLock, OldIrql);
	}

	ExDeleteResourceLite(&Lock_Registry);
 ExDeleteResourceLite(&Lock_Process);
 ExDeleteResourceLite(&Lock_File);
 g_CacheInitialized = FALSE;
}

static VOID RemoveRule(PRULE_NODE* Head, PUNICODE_STRING RuleStr) {
 if (!RuleStr || !RuleStr->Buffer) return;
 PRULE_NODE Current = *Head;
 PRULE_NODE Previous = NULL;

 while (Current) {
 if (RtlEqualUnicodeString(&Current->Pattern, RuleStr, TRUE)) {
 PRULE_NODE ToDelete = Current;

 if (Previous) {
 Previous->Next = Current->Next;
 }
 else {
 *Head = Current->Next;
 }

 Current = Current->Next;

 if (ToDelete->Pattern.Buffer) ZetaFree(ToDelete->Pattern.Buffer);
 ZetaFree(ToDelete);
 }
 else {
 Previous = Current;
 Current = Current->Next;
 }
 }
}

VOID AddDynamicWhitelist(PUNICODE_STRING RuleStr) {
 KeEnterCriticalRegion();
 ExAcquireResourceExclusiveLite(&Lock_Process, TRUE);
 AddRule(&g_ProcessTrustedPaths, RuleStr);
 ExReleaseResourceLite(&Lock_Process);
 ExAcquireResourceExclusiveLite(&Lock_File, TRUE);
 AddRule(&g_FileExceptionPaths, RuleStr);
 ExReleaseResourceLite(&Lock_File);

 KIRQL OldIrql;
 KeAcquireSpinLock(&TrustCacheLock, &OldIrql);
 RtlZeroMemory(TrustCache, sizeof(TrustCache));
 KeReleaseSpinLock(&TrustCacheLock, OldIrql);

 KeLeaveCriticalRegion();
}

VOID RemoveDynamicWhitelist(PUNICODE_STRING RuleStr) {
 KeEnterCriticalRegion();
 ExAcquireResourceExclusiveLite(&Lock_Process, TRUE);
 RemoveRule(&g_ProcessTrustedPaths, RuleStr);
 ExReleaseResourceLite(&Lock_Process);
 ExAcquireResourceExclusiveLite(&Lock_File, TRUE);
 RemoveRule(&g_FileExceptionPaths, RuleStr);
 ExReleaseResourceLite(&Lock_File);

 KIRQL OldIrql;
 KeAcquireSpinLock(&TrustCacheLock, &OldIrql);
 RtlZeroMemory(TrustCache, sizeof(TrustCache));
 KeReleaseSpinLock(&TrustCacheLock, OldIrql);

 KeLeaveCriticalRegion();
}

// Load rules from a single JSON file and merge into existing lists
// FileName is relative to BaseDir (e.g. L"\\Rules\\Rules_User.json")
static NTSTATUS ParseSingleRulesFile(PWCHAR BaseDir, SIZE_T BufferSize, PCWSTR FileName) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE FileHandle = NULL;
    IO_STATUS_BLOCK IoStatus = { 0 };
    OBJECT_ATTRIBUTES oa = { 0 };
    UNICODE_STRING FinalPath = { 0 };

    // Save BaseDir in case we need to restore
    SIZE_T BaseLen = wcslen(BaseDir);
    RtlStringCbCatW(BaseDir, BufferSize, FileName);

    // Ensure NT device path prefix
    if (wcsncmp(BaseDir, L"\\??\\", 4) != 0 &&
        wcsncmp(BaseDir, L"\\SystemRoot", 11) != 0 &&
        wcsncmp(BaseDir, L"\\DosDevices\\", 12) != 0) {
        // If prefix missing, prepend (unlikely but safe)
        DbgPrint("ZETA: ParseSingleRulesFile - prepending \\??\\ to path\n");
    }

    RtlInitUnicodeString(&FinalPath, BaseDir);

    DbgPrint("ZETA: ParseSingleRulesFile - opening: %wZ\n", &FinalPath);

    InitializeObjectAttributes(&oa, &FinalPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateFile(&FileHandle, GENERIC_READ | SYNCHRONIZE, &oa, &IoStatus, NULL,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                          FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(status)) {
        DbgPrint("ZETA: ParseSingleRulesFile - open failed (0x%08X) for %wZ\n", status, &FinalPath);
        // Restore BaseDir
        BaseDir[BaseLen] = L'\0';
        return status;
    }

    FILE_STANDARD_INFORMATION FileInfo = { 0 };
    status = ZwQueryInformationFile(FileHandle, &IoStatus, &FileInfo, sizeof(FileInfo), FileStandardInformation);

    if (NT_SUCCESS(status) && FileInfo.EndOfFile.LowPart > 0) {
        DbgPrint("ZETA: ParseSingleRulesFile - file size: %lu bytes for %s\n", FileInfo.EndOfFile.LowPart, FileName);
        PVOID FileBuffer = ZetaAllocate(FileInfo.EndOfFile.LowPart + 1);
        if (FileBuffer) {
            status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatus, FileBuffer,
                                FileInfo.EndOfFile.LowPart, NULL, NULL);
            if (NT_SUCCESS(status)) {
                ((PCHAR)FileBuffer)[FileInfo.EndOfFile.LowPart] = '\0';

                // M1-4: 规则文件结构完整性校验。系统规则 (Rules_Driver_P1.json)
                // 必须包含 Rule_ 键 (防被清空/损坏成空壳后静默加载空规则);
                // 用户规则 (Rules_User.json) 只做结构配平校验 (允许用户清空自定义规则)。
                BOOLEAN isSystemRules = (FileName != nullptr) &&
                    (wcsstr(FileName, L"Rules_Driver_P1.json") != nullptr);
                if (!VerifyRulesFileIntegrity((PCHAR)FileBuffer,
                                              FileInfo.EndOfFile.LowPart,
                                              isSystemRules)) {
                    DbgPrint("ZETA: ParseSingleRulesFile - INTEGRITY FAILED for %s "
                             "(empty/corrupt/cleared), refusing load\n", FileName);
                    DriverLog(0,
                        isSystemRules
                            ? L"规则完整性校验失败: 系统规则文件缺失或损坏, 已拒绝加载"
                            : L"规则完整性校验失败: 用户规则文件结构异常, 已拒绝加载");
                    status = STATUS_ACCESS_DENIED;
                } else {
                    KeEnterCriticalRegion();
                    ExAcquireResourceExclusiveLite(&Lock_Registry, TRUE);
                    ParseAndLoadRules((PCHAR)FileBuffer, FileInfo.EndOfFile.LowPart, "Rule_Registry_BlockList", &g_RegistryBlockList, FALSE);
                    ParseAndLoadRules((PCHAR)FileBuffer, FileInfo.EndOfFile.LowPart, "Rule_Registry_TrustedList", &g_RegistryTrustedList, FALSE);
                    ExReleaseResourceLite(&Lock_Registry);
                    ExAcquireResourceExclusiveLite(&Lock_Process, TRUE);
                    ParseAndLoadRules((PCHAR)FileBuffer, FileInfo.EndOfFile.LowPart, "Rule_Process_TrustedPaths", &g_ProcessTrustedPaths, FALSE);
                    ParseAndLoadRules((PCHAR)FileBuffer, FileInfo.EndOfFile.LowPart, "Rule_Process_ExploitableBlacklist", &g_ProcessExploitable, FALSE);
                    ExReleaseResourceLite(&Lock_Process);
                    ExAcquireResourceExclusiveLite(&Lock_File, TRUE);
                    ParseAndLoadRules((PCHAR)FileBuffer, FileInfo.EndOfFile.LowPart, "Rule_File_ProtectedPaths", &g_FileProtectedPaths, FALSE);
                    ParseAndLoadRules((PCHAR)FileBuffer, FileInfo.EndOfFile.LowPart, "Rule_File_ExceptionPaths", &g_FileExceptionPaths, FALSE);
                    ParseAndLoadRules((PCHAR)FileBuffer, FileInfo.EndOfFile.LowPart, "Rule_File_ExceptionPaths_Safe", &g_FileExceptionPaths, TRUE);
                    ParseAndLoadRules((PCHAR)FileBuffer, FileInfo.EndOfFile.LowPart, "Rule_File_RansomwareExtensions", &g_FileRansomExts, FALSE);
                    ParseAndLoadRules((PCHAR)FileBuffer, FileInfo.EndOfFile.LowPart, "Rule_File_DocBackup_Extensions", &g_DocBackupExtList, FALSE);
                    ExReleaseResourceLite(&Lock_File);
                    KeLeaveCriticalRegion();

                    DbgPrint("ZETA: ParseSingleRulesFile - rules loaded from %s\n", FileName);
                    status = STATUS_SUCCESS;
                }
            }
            ZetaFree(FileBuffer);
        }
    }
    ZwClose(FileHandle);

    // Restore BaseDir for subsequent calls
    BaseDir[BaseLen] = L'\0';
    return status;
}

NTSTATUS LoadRulesFromDisk(PUNICODE_STRING RegistryPath) {
 NTSTATUS status = STATUS_SUCCESS;
 HANDLE RegHandle = NULL;
 PKEY_VALUE_PARTIAL_INFORMATION Info = NULL;
 ULONG ResultLength = 0;
 PWCHAR PathBuffer = NULL;
 SIZE_T PathBufferSize = 0;
 UNICODE_STRING ImagePathName;

 RtlInitUnicodeString(&ImagePathName, L"ImagePath");

 OBJECT_ATTRIBUTES RegOa = { 0 };
 InitializeObjectAttributes(&RegOa, RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
 status = ZwOpenKey(&RegHandle, KEY_READ, &RegOa);
 if (!NT_SUCCESS(status)) return status;

 status = ZwQueryValueKey(RegHandle, &ImagePathName, KeyValuePartialInformation, NULL, 0, &ResultLength);
 if (status != STATUS_BUFFER_TOO_SMALL) {
 ZwClose(RegHandle);
 return status;
 }

 Info = (PKEY_VALUE_PARTIAL_INFORMATION)ZetaAllocate(ResultLength);
 if (!Info) {
 ZwClose(RegHandle);
 return STATUS_INSUFFICIENT_RESOURCES;
 }

 status = ZwQueryValueKey(RegHandle, &ImagePathName, KeyValuePartialInformation, Info, ResultLength, &ResultLength);
 ZwClose(RegHandle);
 if (!NT_SUCCESS(status)) {
 ZetaFree(Info);
 return status;
 }

 if (Info->Type == REG_EXPAND_SZ || Info->Type == REG_SZ) {
 PathBufferSize = Info->DataLength + 1024;
 PathBuffer = (PWCHAR)ZetaAllocate(PathBufferSize);
 if (PathBuffer) {
 RtlZeroMemory(PathBuffer, PathBufferSize);
 if (Info->DataLength > 0) {
 RtlCopyMemory(PathBuffer, Info->Data, Info->DataLength);
 }

 PWCHAR LastSlash = NULL;
 PWCHAR Current = PathBuffer;
 while (*Current) {
 if (*Current == L'\\') LastSlash = Current;
 Current++;
 }

 if (LastSlash) {
 *LastSlash = L'\0';

 // Strip \Filter suffix to get the base installation directory
 SIZE_T CurrentPathLen = wcslen(PathBuffer);
 const WCHAR FilterSuffix[] = L"\\Filter";
 SIZE_T FilterLen = (sizeof(FilterSuffix) / sizeof(WCHAR)) - 1;

 if (CurrentPathLen >= FilterLen) {
 PWCHAR SuffixStart = PathBuffer + CurrentPathLen - FilterLen;
 BOOLEAN Match = TRUE;
 for (SIZE_T i = 0; i < FilterLen; i++) {
 if (RtlDowncaseUnicodeChar(SuffixStart[i]) != RtlDowncaseUnicodeChar(FilterSuffix[i])) {
 Match = FALSE;
 break;
 }
 }
 if (Match) {
 *SuffixStart = L'\0';
 }
 }

 // Ensure NT device path prefix
 if (wcsncmp(PathBuffer, L"\\??\\", 4) != 0 &&
 wcsncmp(PathBuffer, L"\\SystemRoot", 11) != 0 &&
 wcsncmp(PathBuffer, L"\\DosDevices\\", 12) != 0) {

 PWCHAR TmpBuffer = (PWCHAR)ZetaAllocate(PathBufferSize + 16);
 if (TmpBuffer) {
 RtlStringCbCopyW(TmpBuffer, PathBufferSize + 16, L"\\??\\");
 RtlStringCbCatW(TmpBuffer, PathBufferSize + 16, PathBuffer);
 ZetaFree(PathBuffer);
 PathBuffer = TmpBuffer;
 PathBufferSize += 16;
 }
 }

 BOOLEAN systemRulesLoaded = FALSE;
 BOOLEAN userRulesLoaded = FALSE;

 g_DriverState.SystemRulesStatus = STATUS_UNSUCCESSFUL;
 g_DriverState.UserRulesStatus = STATUS_UNSUCCESSFUL;

 // 1. Load system rules (app must include this file)
 DbgPrint("ZETA: LoadRulesFromDisk - loading system rules (Rules_Driver_P1.json)\n");
 status = ParseSingleRulesFile(PathBuffer, PathBufferSize, L"\\Rules\\Rules_Driver_P1.json");
 g_DriverState.SystemRulesStatus = status;
 if (!NT_SUCCESS(status)) {
 DbgPrint("ZETA: LoadRulesFromDisk - Rules_Driver_P1.json FAILED (0x%08X), continuing\n", status);
 } else {
 systemRulesLoaded = TRUE;
 DbgPrint("ZETA: LoadRulesFromDisk - Rules_Driver_P1.json loaded OK\n");
 }

 // 2. Load user custom rules (optional - user can create/edit this file)
 DbgPrint("ZETA: LoadRulesFromDisk - loading user rules (Rules_User.json)\n");
 NTSTATUS userStatus = ParseSingleRulesFile(PathBuffer, PathBufferSize, L"\\Rules\\Rules_User.json");
 g_DriverState.UserRulesStatus = userStatus;

 // 3. Load file-protection rules (可选) — 文档写前备份扩展名等单独成文件
 //    文件缺失时 g_DocBackupExtList 保持空 → 文档备份回退驱动内置默认表。
 NTSTATUS fileProtectStatus = ParseSingleRulesFile(PathBuffer, PathBufferSize, L"\\Rules\\Rules_FileProtect.json");
 if (!NT_SUCCESS(fileProtectStatus)) {
  DbgPrint("ZETA: LoadRulesFromDisk - Rules_FileProtect.json FAILED (0x%08lX), doc-backup uses builtin defaults\n", fileProtectStatus);
 }

 if (!NT_SUCCESS(userStatus)) {
 DbgPrint("ZETA: LoadRulesFromDisk - Rules_User.json FAILED (0x%08X), skipping\n", userStatus);
 } else {
 userRulesLoaded = TRUE;
 g_DriverState.UserRulesLoaded = TRUE;
 DbgPrint("ZETA: LoadRulesFromDisk - Rules_User.json loaded OK and merged\n");
	}

	// Rebuild prefix hash tables for fast matching
	RebuildPrefixHashes(g_RegistryBlockList, &g_RegistryPrefixHashes);
	RebuildPrefixHashes(g_FileProtectedPaths, &g_FilePrefixHashes);
	// For process, combine both exploitable and trusted path hashes
	RebuildPrefixHashes(g_ProcessExploitable, &g_ProcessPrefixHashes);
	{
		PRULE_NODE pNode = g_ProcessTrustedPaths;
		while (pNode && g_ProcessPrefixHashes.Count < MAX_PREFIX_HASHES) {
			if (pNode->Pattern.Buffer && pNode->Pattern.Length > 0) {
				ULONG hash = ExtractFirstComponentHash(pNode->Pattern.Buffer);
				if (hash != 0) {
					g_ProcessPrefixHashes.Entries[g_ProcessPrefixHashes.Count].Hash = hash;
					g_ProcessPrefixHashes.Entries[g_ProcessPrefixHashes.Count].HasLeadingWildcard =
						(pNode->Pattern.Buffer[0] == L'*' && pNode->Pattern.Buffer[1] == L'\\');
					g_ProcessPrefixHashes.Count++;
				}
			}
			pNode = pNode->Next;
		}
	}

	// Also add IsSignedImageLocation hardcoded path components for prefix pre-filter
	{
		PCWSTR signedLocPatterns[] = {
			L"*\\Windows\\*",
			L"*\\Program Files\\*",
			L"*\\Program Files (x86)\\*",
			L"*\\Common Files\\*",
			L"*\\ProgramData\\*",
		};
		for (int i = 0; i < (int)(sizeof(signedLocPatterns) / sizeof(signedLocPatterns[0])) && g_ProcessPrefixHashes.Count < MAX_PREFIX_HASHES; i++) {
			ULONG hash = ExtractFirstComponentHash(signedLocPatterns[i]);
			if (hash != 0) {
				BOOLEAN found = FALSE;
				for (ULONG j = 0; j < g_ProcessPrefixHashes.Count; j++) {
					if (g_ProcessPrefixHashes.Entries[j].Hash == hash) {
						found = TRUE;
						break;
					}
				}
				if (!found) {
					g_ProcessPrefixHashes.Entries[g_ProcessPrefixHashes.Count].Hash = hash;
					g_ProcessPrefixHashes.Entries[g_ProcessPrefixHashes.Count].HasLeadingWildcard = TRUE;
					g_ProcessPrefixHashes.Count++;
				}
			}
		}
	}

	// Print final rule counts
	DbgPrint("ZETA: LoadRulesFromDisk - final rule counts: RegistryBlockList=%lu, RegistryTrustedList=%lu, "
 "ProcessTrustedPaths=%lu, ProcessExploitable=%lu, FileProtectedPaths=%lu, "
 "FileExceptionPaths=%lu, FileRansomExts=%lu\n",
 CountRules(g_RegistryBlockList), CountRules(g_RegistryTrustedList),
 CountRules(g_ProcessTrustedPaths), CountRules(g_ProcessExploitable),
 CountRules(g_FileProtectedPaths), CountRules(g_FileExceptionPaths),
 CountRules(g_FileRansomExts));

 // Store counts in global state
 g_DriverState.RegistryBlockCount = CountRules(g_RegistryBlockList);
 g_DriverState.RegistryTrustedCount = CountRules(g_RegistryTrustedList);
 g_DriverState.ProcessTrustedCount = CountRules(g_ProcessTrustedPaths);
 g_DriverState.ProcessExploitCount = CountRules(g_ProcessExploitable);
 g_DriverState.FileProtectedCount = CountRules(g_FileProtectedPaths);
 g_DriverState.FileExceptionCount = CountRules(g_FileExceptionPaths);
 g_DriverState.FileRansomCount = CountRules(g_FileRansomExts);

 // Count safe-only exception paths
 ULONG safeCount = 0;
 PRULE_NODE tmpNode = g_FileExceptionPaths;
 while (tmpNode) {
  if (tmpNode->OnlySafeTypes) safeCount++;
  tmpNode = tmpNode->Next;
 }
 g_DriverState.FileSafeExceptionCount = safeCount;

 // Set RulesLoaded flag - TRUE only if at least one rule file was loaded successfully
 g_DriverState.RulesLoaded = (systemRulesLoaded || userRulesLoaded);

 // WARNING: If no rules loaded, protection is effectively disabled
 if (!g_DriverState.RulesLoaded) {
 DbgPrint("ZETA: WARNING - NO RULES LOADED! Protection is effectively DISABLED.\n");
 DbgPrint("ZETA: Ensure Rules_Driver_P1.json exists in the Rules directory.\n");
 }
 }
 }
 }
 ZetaFree(Info);

 if (PathBuffer) ZetaFree(PathBuffer);
 DbgPrint("ZETA: LoadRulesFromDisk - complete, status=0x%08lX\n", status);
 return status;
}

VOID UnloadRules() {
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&Lock_Registry, TRUE);
	FreeList(&g_RegistryBlockList);
	FreeList(&g_RegistryTrustedList);
	ExReleaseResourceLite(&Lock_Registry);
	ExAcquireResourceExclusiveLite(&Lock_Process, TRUE);
	FreeList(&g_ProcessTrustedPaths);
	FreeList(&g_ProcessExploitable);
	ExReleaseResourceLite(&Lock_Process);
	ExAcquireResourceExclusiveLite(&Lock_File, TRUE);
	FreeList(&g_FileProtectedPaths);
	FreeList(&g_FileExceptionPaths);
	FreeList(&g_FileRansomExts);
	FreeList(&g_DocBackupExtList);
	ExReleaseResourceLite(&Lock_File);
	KeLeaveCriticalRegion();

	// Zero out prefix hash tables
	g_FilePrefixHashes.Count = 0;
	g_RegistryPrefixHashes.Count = 0;
	g_ProcessPrefixHashes.Count = 0;
}

NTSTATUS GetProcessImageName(HANDLE ProcessId, PUNICODE_STRING* ImageName) {
 if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
 return STATUS_UNSUCCESSFUL;
 }

 NTSTATUS status;
 PEPROCESS Process = NULL;

 *ImageName = NULL;
 status = PsLookupProcessByProcessId(ProcessId, &Process);
 if (!NT_SUCCESS(status)) return status;

 status = SeLocateProcessImageName(Process, ImageName);
 ObDereferenceObject(Process);

 return status;
}

static BOOLEAN IsFileDigitallySigned(PUNICODE_STRING ImagePath) {
 if (!ImagePath || !ImagePath->Buffer || ImagePath->Length == 0) return FALSE;

 HANDLE fileHandle = NULL;
 OBJECT_ATTRIBUTES oa;
 IO_STATUS_BLOCK iosb;
 NTSTATUS status;
 IMAGE_DOS_HEADER dosHeader = {0};
 LARGE_INTEGER byteOffset = { 0, 0 };
 IMAGE_NT_HEADERS ntHeaders = {0};

 InitializeObjectAttributes(&oa, ImagePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

 status = ZwCreateFile(&fileHandle, GENERIC_READ, &oa, &iosb, NULL,
  FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
  FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
 if (!NT_SUCCESS(status)) return FALSE;

 status = ZwReadFile(fileHandle, NULL, NULL, NULL, &iosb, &dosHeader, sizeof(dosHeader), &byteOffset, NULL);
 if (!NT_SUCCESS(status) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
 ZwClose(fileHandle);
 return FALSE;
 }

 byteOffset.QuadPart = dosHeader.e_lfanew;
 RtlZeroMemory(&iosb, sizeof(iosb));
 status = ZwReadFile(fileHandle, NULL, NULL, NULL, &iosb, &ntHeaders, sizeof(ntHeaders), &byteOffset, NULL);
 ZwClose(fileHandle);

 if (!NT_SUCCESS(status) || ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
  return FALSE;
 }

 ULONG certSize = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
 ULONG certAddr = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;

 if (certSize > 0 && certAddr > 0) {
  return TRUE;
 }

 return FALSE;
}

// Check if a process is a known Windows system executable that should NEVER be
// flagged as ransomware, regardless of file write behavior.
// This prevents false-positive kills of legitimate processes like msiexec.exe.
static BOOLEAN IsKnownWindowsSystemProcess(PCWSTR ImagePath, USHORT Length) {
    if (!ImagePath || Length == 0) return FALSE;

    // Extract basename from path (find last backslash)
    PCWSTR baseName = ImagePath;
    for (USHORT i = 0; i < Length / sizeof(WCHAR); i++) {
        if (ImagePath[i] == L'\\') baseName = &ImagePath[i + 1];
    }

    // Compare base name against known Windows executables
    // These are all signed Microsoft binaries that perform legitimate file I/O
    PCWSTR knownNames[] = {
        L"msiexec.exe",      // Windows Installer
        L"svchost.exe",      // Service Host
        L"services.exe",     // Service Control Manager
        L"lsass.exe",        // Local Security Authority
        L"csrss.exe",        // Client/Server Runtime
        L"smss.exe",         // Session Manager
        L"wininit.exe",      // Windows Init
        L"winlogon.exe",     // Windows Logon
        L"dllhost.exe",      // DLL Host
        L"rundll32.exe",     // Run DLL
        L"regsvr32.exe",     // Register Server
        L"msbuild.exe",      // MSBuild
        L"devenv.exe",       // Visual Studio
        L"cmd.exe",          // Command Prompt
        L"powershell.exe",   // PowerShell
        L"pwsh.exe",         // PowerShell Core
        L"conhost.exe",      // Console Host
        L"notepad.exe",      // Notepad
        L"explorer.exe",     // Explorer
        L"taskhostw.exe",    // Task Host
        L"SearchFilterHost.exe", // Windows Search
        L"SearchIndexer.exe",    // Windows Search
        L"SearchProtocolHost.exe", // Windows Search
        L"TiWorker.exe",     // Windows Update
        L"TrustedInstaller.exe", // Windows Modules
        L"DismHost.exe",     // DISM
        L"MoFUsbHost.exe",   // Windows Update
        L"WmiPrvSE.exe",     // WMI Provider
        L"RuntimeBroker.exe", // Runtime Broker
        L"backgroundTaskHost.exe", // Background Tasks
        L"WWAHost.exe",      // Windows Web Apps
        L"SystemSettings.exe", // System Settings
        L"compmgmt.exe",     // Computer Management
        L"mmc.exe",          // Microsoft Management Console
        L"mshta.exe",        // HTML Application Host
        L"control.exe",      // Control Panel
        L"fontdrvhost.exe",  // Font Driver Host
        L"sihost.exe",       // Shell Infrastructure
        L"ctfmon.exe",       // CTF Loader
        L"ShellExperienceHost.exe", // Shell Experience
        L"ApplicationFrameHost.exe", // App Frame
        L"GameInputSvc.exe", // Game Input
    };

    for (int i = 0; i < (int)(sizeof(knownNames) / sizeof(knownNames[0])); i++) {
        // Case-insensitive comparison of base name
        PCWSTR k = knownNames[i];
        PCWSTR b = baseName;
        BOOLEAN match = TRUE;
        while (*k && *b) {
            WCHAR kl = *k >= L'A' && *k <= L'Z' ? *k + 32 : *k;
            WCHAR bl = *b >= L'A' && *b <= L'Z' ? *b + 32 : *b;
            if (kl != bl) { match = FALSE; break; }
            k++; b++;
        }
        if (match && *k == L'\0') return TRUE;
    }

    return FALSE;
}

static BOOLEAN IsWindowsSystemApp(PCWSTR Buffer, USHORT Length) {
 if (WildcardMatch(L"*\\Windows\\SystemApps\\*", Buffer, Length)) return TRUE;
 if (WildcardMatch(L"*\\Windows\\ImmersiveControlPanel\\*", Buffer, Length)) return TRUE;
 if (WildcardMatch(L"*\\Windows\\explorer.exe", Buffer, Length)) return TRUE;
 return FALSE;
}

// Check if a process image path is from a trusted (signed) location
// Processes from these directories are typically digitally signed
static BOOLEAN IsSignedImageLocation(PCWSTR Buffer, USHORT Length) {
 if (!Buffer || Length == 0) return FALSE;

 // Windows system directories
 if (WildcardMatch(L"*\\Windows\\System32\\*", Buffer, Length)) return TRUE;
 if (WildcardMatch(L"*\\Windows\\SysWOW64\\*", Buffer, Length)) return TRUE;
 if (WildcardMatch(L"*\\Windows\\WinSxS\\*", Buffer, Length)) return TRUE;
 if (WildcardMatch(L"*\\Windows\\Microsoft.NET\\*", Buffer, Length)) return TRUE;
 if (WildcardMatch(L"*\\Windows\\*", Buffer, Length)) return TRUE;

 // Program Files / Common Files
 if (WildcardMatch(L"*\\Program Files\\*", Buffer, Length)) return TRUE;
 if (WildcardMatch(L"*\\Program Files (x86)\\*", Buffer, Length)) return TRUE;
 if (WildcardMatch(L"*\\Common Files\\*", Buffer, Length)) return TRUE;

 // Windows Defender (ProgramData on newer Windows)
 if (WildcardMatch(L"*\\ProgramData\\Microsoft\\Windows Defender\\*", Buffer, Length)) return TRUE;

 return FALSE;
}

// Three-tier Trust Level
TRUST_LEVEL GetProcessTrustLevel(HANDLE ProcessId) {
 DbgPrint("ZETA: GetProcessTrustLevel - PID %lu\n", (ULONG)(ULONG_PTR)ProcessId);
 // TRUST_SYSTEM: ZETA itself, PID=4
 if ((ULONG)(ULONG_PTR)ProcessId == GlobalData.ZetaPid) return TRUST_LEVEL_SYSTEM;
 if (ProcessId == (HANDLE)4) return TRUST_LEVEL_SYSTEM;

 PEPROCESS Process = NULL;
 if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) {
 return TRUST_LEVEL_NONE;
 }

 LARGE_INTEGER createTime;
 createTime.QuadPart = PsGetProcessCreateTimeQuadPart(Process);

 // Check trust window first (fastest path)
 // Now matches by process image PATH, not PID — so all processes sharing
 // the same executable (e.g., Electron child processes) are covered.
 PUNICODE_STRING imageName = NULL;
 if (NT_SUCCESS(SeLocateProcessImageName(Process, &imageName)) && imageName && imageName->Buffer) {
  BOOLEAN inWindow = IsInTrustWindow(imageName->Buffer);
  ExFreePool(imageName);
  if (inWindow) {
   ObDereferenceObject(Process);
   return TRUST_LEVEL_SIGNED;
  }
 }

 // Check trust cache
 if (g_CacheInitialized) {
 KIRQL OldIrql;
 KeAcquireSpinLock(&TrustCacheLock, &OldIrql);
 ULONG Hash = ((ULONG)((ULONG_PTR)ProcessId * 2654435761u)) >> 22;

 if (TrustCache[Hash].Process == Process && TrustCache[Hash].ProcessCreateTime.QuadPart == createTime.QuadPart) {
 LARGE_INTEGER Now;
 KeQuerySystemTime(&Now);
 if ((Now.QuadPart - TrustCache[Hash].CacheTime.QuadPart) < (TRUST_CACHE_TTL_SEC * 10000000LL)) {
 ULONG cachedLevel = TrustCache[Hash].TrustLevel;
 KeReleaseSpinLock(&TrustCacheLock, OldIrql);
 ObDereferenceObject(Process);
 return (TRUST_LEVEL)cachedLevel;
 }
 }
 KeReleaseSpinLock(&TrustCacheLock, OldIrql);
 }

 if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
  ObDereferenceObject(Process);
  return TRUST_LEVEL_NONE;
 }

 PUNICODE_STRING imageFileName = NULL;
 NTSTATUS status = GetProcessImageName(ProcessId, &imageFileName);
 TRUST_LEVEL result = TRUST_LEVEL_NONE;

 if (NT_SUCCESS(status) && imageFileName && imageFileName->Buffer) {
  // CA-signed → TRUST_SIGNED
  if (IsFileDigitallySigned(imageFileName)) {
   result = TRUST_LEVEL_SIGNED;
   DbgPrint("ZETA: GetProcessTrustLevel - PID %lu: CA-signed → SIGNED\n", (ULONG)(ULONG_PTR)ProcessId);
   if (imageFileName) ExFreePool(imageFileName);
   ObDereferenceObject(Process);
   return TRUST_LEVEL_SIGNED;
  }
 }

 // Quick pre-filter: no prefix match → TRUST_NONE
 if (NT_SUCCESS(status) && imageFileName && imageFileName->Buffer) {
  if (!PrefixHashMatch(imageFileName->Buffer, imageFileName->Length / sizeof(WCHAR), &g_ProcessPrefixHashes)) {
   if (imageFileName) ExFreePool(imageFileName);
   ObDereferenceObject(Process);
   return TRUST_LEVEL_NONE;
  }
 }

 KeEnterCriticalRegion();
 ExAcquireResourceSharedLite(&Lock_Process, TRUE);

 if (NT_SUCCESS(status) && imageFileName && imageFileName->Buffer) {
  // Exploitable blacklist → TRUST_NONE (most suspicious)
  PRULE_NODE Node = g_ProcessExploitable;
  while (Node) {
   if (WildcardMatch(Node->Pattern.Buffer, imageFileName->Buffer, imageFileName->Length)) {
    result = TRUST_LEVEL_NONE;
    goto update_cache;
   }
   Node = Node->Next;
  }

  // Windows system app → TRUST_SYSTEM
  if (IsWindowsSystemApp(imageFileName->Buffer, imageFileName->Length)) {
   result = TRUST_LEVEL_SYSTEM;
   goto update_cache;
  }

  // Signed image location → TRUST_SIGNED
  if (IsSignedImageLocation(imageFileName->Buffer, (USHORT)(imageFileName->Length / sizeof(WCHAR)))) {
   result = TRUST_LEVEL_SIGNED;
   goto update_cache;
  }

  // Known Windows system process (basename fallback) → TRUST_SIGNED
  // Handles cases where SeLocateProcessImageName returns device paths
  // like \Device\HarddiskVolume3\Windows\System32\msiexec.exe
  if (IsKnownWindowsSystemProcess(imageFileName->Buffer, (USHORT)(imageFileName->Length / sizeof(WCHAR)))) {
   result = TRUST_LEVEL_SIGNED;
   goto update_cache;
  }

  // User-configured trusted paths → TRUST_SIGNED
  Node = g_ProcessTrustedPaths;
  while (Node) {
   if (WildcardMatch(Node->Pattern.Buffer, imageFileName->Buffer, imageFileName->Length)) {
    result = TRUST_LEVEL_SIGNED;
    goto update_cache;
   }
   Node = Node->Next;
  }
 }

update_cache:
 if (g_CacheInitialized) {
 KIRQL OldIrql;
 KeAcquireSpinLock(&TrustCacheLock, &OldIrql);
 ULONG Hash = ((ULONG)((ULONG_PTR)ProcessId * 2654435761u)) >> 22;
 // 释放旧的 EPROCESS 引用（如果槽位被占用）
 if (TrustCache[Hash].Process) {
  ObDereferenceObject(TrustCache[Hash].Process);
 }
 TrustCache[Hash].Process = Process;
 ObReferenceObject(Process);  // 为 Cache 加引用，确保 EPROCESS 不被释放
 TrustCache[Hash].ProcessCreateTime = createTime;
 KeQuerySystemTime(&TrustCache[Hash].CacheTime);
 TrustCache[Hash].TrustLevel = (ULONG)result;
 KeReleaseSpinLock(&TrustCacheLock, OldIrql);
 }

 ExReleaseResourceLite(&Lock_Process);
 KeLeaveCriticalRegion();

 DbgPrint("ZETA: GetProcessTrustLevel - PID %lu level=%d\n",
  (ULONG)(ULONG_PTR)ProcessId, result);

 if (imageFileName) ExFreePool(imageFileName);
 ObDereferenceObject(Process);
 return result;
}

// Legacy wrapper: returns TRUE for SYSTEM or SIGNED
BOOLEAN IsProcessTrusted(HANDLE ProcessId) {
 return GetProcessTrustLevel(ProcessId) >= TRUST_LEVEL_SIGNED;
}

// Trust Window (dynamic: after HIPS allow, 30 min no re-pend)

VOID InitializeTrustWindow() {
 InitializeListHead(&g_TrustWindowList);
 KeInitializeSpinLock(&g_TrustWindowLock);
 DbgPrint("ZETA: TrustWindow initialized\n");
}

BOOLEAN IsInTrustWindow(PCWSTR ProcessPath) {
 KIRQL oldIrql;
 KeAcquireSpinLock(&g_TrustWindowLock, &oldIrql);

 LARGE_INTEGER now;
 KeQuerySystemTime(&now);

 BOOLEAN found = FALSE;
 for (PLIST_ENTRY entry = g_TrustWindowList.Flink;
   entry != &g_TrustWindowList; entry = entry->Flink) {
  PTRUST_WINDOW_ENTRY cur = CONTAINING_RECORD(entry, TRUST_WINDOW_ENTRY, ListEntry);
  // Case-insensitive path comparison
  UNICODE_STRING curPath, searchPath;
  RtlInitUnicodeString(&curPath, cur->ProcessPath);
  RtlInitUnicodeString(&searchPath, ProcessPath);
  if (RtlEqualUnicodeString(&curPath, &searchPath, TRUE)) {
   if (now.QuadPart < cur->ExpiryTime.QuadPart) {
    found = TRUE;  // still in window
   } else {
    // Expired — remove
    RemoveEntryList(&cur->ListEntry);
    ZetaFree(cur);
   }
   break;
  }
 }

 KeReleaseSpinLock(&g_TrustWindowLock, oldIrql);
 return found;
}

// ── Get full NT device path from a PID (PASSIVE_LEVEL only) ──
BOOLEAN GetProcessPathFromPid(ULONG ProcessId, PWCHAR OutPath, ULONG OutChars) {
 if (!OutPath || OutChars == 0) return FALSE;

 PEPROCESS Process = NULL;
 if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &Process))) {
  return FALSE;
 }

 PUNICODE_STRING imageName = NULL;
 BOOLEAN result = FALSE;
 if (NT_SUCCESS(SeLocateProcessImageName(Process, &imageName)) && imageName && imageName->Buffer) {
  ULONG copyChars = (imageName->Length / sizeof(WCHAR)) < (OutChars - 1)
   ? (imageName->Length / sizeof(WCHAR)) : (OutChars - 1);
  RtlCopyMemory(OutPath, imageName->Buffer, copyChars * sizeof(WCHAR));
  OutPath[copyChars] = L'\0';
  result = TRUE;
  ExFreePool(imageName);
 }

 ObDereferenceObject(Process);
 return result;
}

VOID AddToTrustWindow(PCWSTR ProcessPath) {
 KIRQL oldIrql;
 KeAcquireSpinLock(&g_TrustWindowLock, &oldIrql);

 // Remove existing entry for this path (to refresh timer)
 UNICODE_STRING searchPath;
 RtlInitUnicodeString(&searchPath, ProcessPath);
 for (PLIST_ENTRY entry = g_TrustWindowList.Flink;
   entry != &g_TrustWindowList; entry = entry->Flink) {
  PTRUST_WINDOW_ENTRY cur = CONTAINING_RECORD(entry, TRUST_WINDOW_ENTRY, ListEntry);
  UNICODE_STRING curPath;
  RtlInitUnicodeString(&curPath, cur->ProcessPath);
  if (RtlEqualUnicodeString(&curPath, &searchPath, TRUE)) {
   RemoveEntryList(&cur->ListEntry);
   ZetaFree(cur);
   break;
  }
 }

 // Count entries, trim oldest if at limit
 ULONG count = 0;
 PLIST_ENTRY oldest = NULL;
 for (PLIST_ENTRY entry = g_TrustWindowList.Flink;
   entry != &g_TrustWindowList; entry = entry->Flink) {
  count++;
  if (!oldest) oldest = entry;
 }
 if (count >= MAX_TRUST_WINDOW && oldest) {
  PTRUST_WINDOW_ENTRY old = CONTAINING_RECORD(oldest, TRUST_WINDOW_ENTRY, ListEntry);
  RemoveEntryList(&old->ListEntry);
  ZetaFree(old);
 }

 // Add new entry
 PTRUST_WINDOW_ENTRY newEntry = (PTRUST_WINDOW_ENTRY)ZetaAllocate(sizeof(TRUST_WINDOW_ENTRY));
 if (newEntry) {
  ULONG copyChars = (ULONG)wcslen(ProcessPath);
  if (copyChars >= TRUST_WINDOW_PATH_LEN) copyChars = TRUST_WINDOW_PATH_LEN - 1;
  RtlCopyMemory(newEntry->ProcessPath, ProcessPath, copyChars * sizeof(WCHAR));
  newEntry->ProcessPath[copyChars] = L'\0';
  KeQuerySystemTime(&newEntry->ExpiryTime);
  newEntry->ExpiryTime.QuadPart += (LONGLONG)TRUST_WINDOW_SEC * 10000000LL;
  InsertTailList(&g_TrustWindowList, &newEntry->ListEntry);
 }

 KeReleaseSpinLock(&g_TrustWindowLock, oldIrql);
 DbgPrint("ZETA: AddToTrustWindow - %ws added for %ds\n", ProcessPath, TRUST_WINDOW_SEC);
}

VOID RemoveFromTrustWindow(PCWSTR ProcessPath) {
 KIRQL oldIrql;
 KeAcquireSpinLock(&g_TrustWindowLock, &oldIrql);

 UNICODE_STRING searchPath;
 RtlInitUnicodeString(&searchPath, ProcessPath);
 for (PLIST_ENTRY entry = g_TrustWindowList.Flink;
   entry != &g_TrustWindowList; entry = entry->Flink) {
  PTRUST_WINDOW_ENTRY cur = CONTAINING_RECORD(entry, TRUST_WINDOW_ENTRY, ListEntry);
  UNICODE_STRING curPath;
  RtlInitUnicodeString(&curPath, cur->ProcessPath);
  if (RtlEqualUnicodeString(&curPath, &searchPath, TRUE)) {
   RemoveEntryList(&cur->ListEntry);
   ZetaFree(cur);
   break;
  }
 }

 KeReleaseSpinLock(&g_TrustWindowLock, oldIrql);
}

VOID CleanupTrustWindow() {
 KIRQL oldIrql;
 KeAcquireSpinLock(&g_TrustWindowLock, &oldIrql);

 while (!IsListEmpty(&g_TrustWindowList)) {
  PLIST_ENTRY entry = RemoveHeadList(&g_TrustWindowList);
  PTRUST_WINDOW_ENTRY cur = CONTAINING_RECORD(entry, TRUST_WINDOW_ENTRY, ListEntry);
  ZetaFree(cur);
 }

 KeReleaseSpinLock(&g_TrustWindowLock, oldIrql);
 DbgPrint("ZETA: TrustWindow cleaned up\n");
}

BOOLEAN IsTargetProtected(HANDLE ProcessId) {
 // check if it is our own process
 if ((ULONG)(ULONG_PTR)ProcessId == GlobalData.ZetaPid) return TRUE;

 // ?????????????????????????
 if (KeGetCurrentIrql() != PASSIVE_LEVEL) return FALSE;

 PUNICODE_STRING imageFileName = NULL;
 NTSTATUS status = GetProcessImageName(ProcessId, &imageFileName);
 if (!NT_SUCCESS(status) || !imageFileName || !imageFileName->Buffer) {
 return FALSE;
 }

 BOOLEAN isProtected = FALSE;

 KeEnterCriticalRegion();
 ExAcquireResourceSharedLite(&Lock_File, TRUE);

 // ????????????????
 PRULE_NODE Node = g_FileProtectedPaths;
 while (Node) {
 if (WildcardMatch(Node->Pattern.Buffer, imageFileName->Buffer, imageFileName->Length)) {
 isProtected = TRUE;
 break;
 }
 Node = Node->Next;
 }

 ExReleaseResourceLite(&Lock_File);
 KeLeaveCriticalRegion();

 if (imageFileName) ExFreePool(imageFileName);
 return isProtected;
}

BOOLEAN CheckRegistryRule(PCUNICODE_STRING KeyName) {
	if (!KeyName || !KeyName->Buffer) return FALSE;
	if (KeyName->Length < 4 * sizeof(WCHAR)) return FALSE;

	if (WildcardMatch(L"*{645FF040-5081-101B-9F08-00AA002F954E}\\DefaultIcon", KeyName->Buffer, KeyName->Length)) {
		return FALSE;
	}

	// Quick prefix hash pre-filter (no lock needed)
	if (!PrefixHashMatch(KeyName->Buffer, KeyName->Length / sizeof(WCHAR), &g_RegistryPrefixHashes)) {
		return FALSE;
	}

	KeEnterCriticalRegion();
 ExAcquireResourceSharedLite(&Lock_Registry, TRUE);

 PRULE_NODE AllowNode = g_RegistryTrustedList;
 while (AllowNode) {
 if (WildcardMatch(AllowNode->Pattern.Buffer, KeyName->Buffer, KeyName->Length)) {
 ExReleaseResourceLite(&Lock_Registry);
 KeLeaveCriticalRegion();
 return FALSE;
 }
 AllowNode = AllowNode->Next;
 }

 PRULE_NODE Node = g_RegistryBlockList;
	BOOLEAN Match = FALSE;
	while (Node) {
		if (WildcardMatch(Node->Pattern.Buffer, KeyName->Buffer, KeyName->Length)) {
			Match = TRUE;
			DbgPrint("ZETA: CheckRegistryRule - MATCH found for key: %wZ\n", KeyName);
			break;
		}
		Node = Node->Next;
	}
	ExReleaseResourceLite(&Lock_Registry);
	KeLeaveCriticalRegion();
	return Match;
}

BOOLEAN CheckFileExtensionRule(PCUNICODE_STRING FileName) {
 if (!FileName || !FileName->Buffer) return FALSE;

 KeEnterCriticalRegion();
 ExAcquireResourceSharedLite(&Lock_File, TRUE);

 PRULE_NODE ExNode = g_FileExceptionPaths;
 while (ExNode) {
 if (WildcardMatch(ExNode->Pattern.Buffer, FileName->Buffer, FileName->Length)) {
 ExReleaseResourceLite(&Lock_File);
 KeLeaveCriticalRegion();
 return FALSE;
 }
 ExNode = ExNode->Next;
 }

 PRULE_NODE Node = g_FileRansomExts;
	BOOLEAN Match = FALSE;
	while (Node) {
		if (HasSuffix(FileName, Node->Pattern.Buffer)) {
			Match = TRUE;
			DbgPrint("ZETA: CheckFileExtensionRule - MATCH found for file: %wZ\n", FileName);
			break;
		}
		Node = Node->Next;
	}
	ExReleaseResourceLite(&Lock_File);
	KeLeaveCriticalRegion();
	return Match;
}

// Safe file extensions that should pass through safe-only exception paths
// These are non-executable data/config/text files that legitimate apps write
// 安全类型白名单（文档 / 配置 / 缓存）。用 RTL_NUMBER_OF 在编译期取字符数（含结尾 NUL 故 -1），
// 不依赖任何运行时字符串 API。
typedef struct _SAFE_EXT { PCWSTR Text; USHORT Chars; } SAFE_EXT;

static const SAFE_EXT g_SafeExts[] = {
 { L".txt",   RTL_NUMBER_OF(L".txt")   - 1 },
 { L".json",  RTL_NUMBER_OF(L".json")  - 1 },
 { L".xml",   RTL_NUMBER_OF(L".xml")   - 1 },
 { L".log",   RTL_NUMBER_OF(L".log")   - 1 },
 { L".md",    RTL_NUMBER_OF(L".md")    - 1 },
 { L".csv",   RTL_NUMBER_OF(L".csv")   - 1 },
 { L".cfg",   RTL_NUMBER_OF(L".cfg")   - 1 },
 { L".ini",   RTL_NUMBER_OF(L".ini")   - 1 },
 { L".conf",  RTL_NUMBER_OF(L".conf")  - 1 },
 { L".cnf",   RTL_NUMBER_OF(L".cnf")   - 1 },
 { L".yaml",  RTL_NUMBER_OF(L".yaml")  - 1 },
 { L".yml",   RTL_NUMBER_OF(L".yml")   - 1 },
 { L".toml",  RTL_NUMBER_OF(L".toml")  - 1 },
 { L".tmp",   RTL_NUMBER_OF(L".tmp")   - 1 },
 { L".temp",  RTL_NUMBER_OF(L".temp")  - 1 },
 { L".dat",   RTL_NUMBER_OF(L".dat")   - 1 },
 { L".cache", RTL_NUMBER_OF(L".cache") - 1 },
};

// =============================================================================
// IsSafeFileExtension — 判定扩展名是否属于"文档 / 配置 / 缓存"类安全类型
//
// ⚠ 2026-09-30 修复两个真实缺陷（由 _test-bin/RuleLint.py 的 safe_ext_audit 实测暴露）:
//
//   缺陷1 — 比较长度传错 ⇒ 退化成前缀匹配:
//     原代码 `RtlCompareMemory(dot, L".txt", 4) == 4` 是**按字节**比较, 而 L".txt"
//     实际占 8 字节, 传 4 相当于只比较了扩展名的前 2 个字符。实测后果:
//       .dat  只比 ".d" ⇒ 把 **.dll** 判成安全   (DLL 侧加载)
//       .log  只比 ".l" ⇒ 把 **.lnk** 判成安全   (快捷方式持久化)
//       .md   只比 ".m" ⇒ 把 **.msi/.mp4** 判成安全 (安装包)
//       .json 只比 ".js"⇒ 把 **.jar** 判成安全
//       .csv/.cfg/.conf/.cnf/.cache 只比 ".c" ⇒ 把 **.cpl** 判成安全
//       .xml  只比 ".x" ⇒ 把 **.xls** 判成安全
//     而 Rule_File_ExceptionPaths_Safe（含 "*\AppData\*"）是按本函数放行的 ⇒
//     **AppData 等目录对 DLL 侧加载 / 快捷方式持久化 / MSI / CPL 变成不受保护区**。
//
//   缺陷2 — 大小写:
//     注释写 case-insensitive, 但 RtlCompareMemory 是逐字节**大小写敏感** ⇒
//     ".TXT" 不被判为安全而 ".txt" 是; 行为随大小写漂移, 不可预测。
//
//   修复原则: 取**完整**扩展名(最后一个 '.' 到文件名末端), 做**等长 + 大小写不敏感**比较,
//     只认"整段相等", 不再有任何前缀语义。这样 .txtx / .datx 也不会误命中。
//
// ⚠ 行为变化提醒: 修复后 .lnk/.dll/.js/.msi/.cpl/.xls 不再被 ExceptionPaths_Safe 放行,
//   它们会重新受到保护规则的约束 ⇒ **可能出现新的拦截(原本被误放行)**。
//   若线上发现 AppData/Startup 下的正常写入被拦, 应当**把该扩展名显式加进白名单**,
//   而不是回退到前缀匹配。
// =============================================================================
static BOOLEAN IsSafeFileExtension(PCUNICODE_STRING FileName) {
 PWCHAR buf;
 ULONG  len, i, extChars;
 PWCHAR dot = NULL;
 UNICODE_STRING ext;

 if (!FileName || !FileName->Buffer || FileName->Length < 2) return FALSE;

 buf = FileName->Buffer;
 len = FileName->Length / sizeof(WCHAR);

 // 从末尾向前, 在"文件名部分"(最后一个 \\ 或 / 之后)内找最后一个 '.'
 for (i = len; i > 0; i--) {
  WCHAR c = buf[i - 1];
  if (c == L'\\' || c == L'/') break;   // 已越过文件名部分, 说明没有扩展名
  if (c == L'.') { dot = &buf[i - 1]; break; }
 }
 if (!dot) return FALSE;
 if (dot == buf) return FALSE;           // 整个路径就是一个 ".xxx"
 // 形如 ".txt" 的隐藏文件(无主名): 前一个字符是分隔符 ⇒ 不视为"安全类型"
 if (*(dot - 1) == L'\\' || *(dot - 1) == L'/') return FALSE;

 extChars = len - (ULONG)(dot - buf);
 if (extChars == 0 || extChars > 16) return FALSE;   // 扩展名不可能很长

 ext.Buffer = dot;
 ext.Length = (USHORT)(extChars * sizeof(WCHAR));
 ext.MaximumLength = ext.Length;

 for (i = 0; i < RTL_NUMBER_OF(g_SafeExts); i++) {
  UNICODE_STRING s;
  if (g_SafeExts[i].Chars != extChars) continue;     // **等长** —— 杜绝前缀匹配
  s.Buffer = (PWCH)g_SafeExts[i].Text;
  s.Length = (USHORT)(g_SafeExts[i].Chars * sizeof(WCHAR));
  s.MaximumLength = s.Length;
  if (RtlEqualUnicodeString(&ext, &s, TRUE)) return TRUE;   // TRUE = 大小写不敏感
 }

 return FALSE;
}

BOOLEAN CheckProtectedPathRule(PCUNICODE_STRING FileName) {
 if (!FileName || !FileName->Buffer) return FALSE;

 if (WildcardMatch(L"*\\Windows\\System32\\config\\systemprofile*", FileName->Buffer, FileName->Length)) {
  return FALSE;
 }

 // Quick prefix hash pre-filter (no lock needed)
 if (!PrefixHashMatch(FileName->Buffer, FileName->Length / sizeof(WCHAR), &g_FilePrefixHashes)) {
  return FALSE;
 }

 KeEnterCriticalRegion();
 ExAcquireResourceSharedLite(&Lock_File, TRUE);

 PRULE_NODE ExNode = g_FileExceptionPaths;
 while (ExNode) {
  if (WildcardMatch(ExNode->Pattern.Buffer, FileName->Buffer, FileName->Length)) {
   // If this is a safe-only exception, check file extension
   if (ExNode->OnlySafeTypes) {
    // Get file extension and check if it's in the safe list
    // Only txt, json, xml, log, cfg, ini, yaml, tmp, dat, md, csv are safe
    if (!IsSafeFileExtension(FileName)) {
     // Not a safe file type - don't apply exception, continue checking
     ExNode = ExNode->Next;
     continue;
    }
   }
   // Exception applies (either unconditional, or safe-only and file is safe)
   ExReleaseResourceLite(&Lock_File);
   KeLeaveCriticalRegion();
   return FALSE;
  }
  ExNode = ExNode->Next;
 }

 PRULE_NODE Node = g_FileProtectedPaths;
 BOOLEAN Match = FALSE;
 while (Node) {
  if (WildcardMatch(Node->Pattern.Buffer, FileName->Buffer, FileName->Length)) {
   Match = TRUE;
   DbgPrint("ZETA: CheckProtectedPathRule - MATCH found for file: %wZ\n", FileName);
   break;
  }
  Node = Node->Next;
 }
 ExReleaseResourceLite(&Lock_File);
 KeLeaveCriticalRegion();
 return Match;
}



NTSTATUS SendMessageToUser(ULONG Code, ULONG Pid, PWCHAR Path, USHORT PathSize) {
    return SendMessageToUserWithContext(Code, Pid, Path, PathSize, NULL);
}

NTSTATUS SendMessageToUserWithContext(ULONG Code, ULONG Pid, PWCHAR Path, USHORT PathSize,
    PZETA_IRP_CONTEXT Context) {
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_UNSUCCESSFUL;

    if (!ExAcquireRundownProtection(&GlobalData.PortRundown)) {
        return STATUS_PORT_DISCONNECTED;
    }

    NTSTATUS status = STATUS_PORT_DISCONNECTED;

    if (GlobalData.ClientPort) {
        // 始终发送 ZETA_MESSAGE + ZETA_IRP_CONTEXT (固定大小，简化接收)
        ULONG msgSize = sizeof(ZETA_MESSAGE) + sizeof(ZETA_IRP_CONTEXT);

        PCHAR rawMsg = (PCHAR)ZetaAllocate(msgSize);
        if (rawMsg) {
            RtlZeroMemory(rawMsg, msgSize);
            PZETA_MESSAGE msg = (PZETA_MESSAGE)rawMsg;
            msg->MessageCode = Code;
            msg->ProcessId = Pid;

            if (Path && PathSize > 0) {
                size_t MaxSize = sizeof(msg->Path) - sizeof(WCHAR);
                size_t BytesToCopy = PathSize > MaxSize ? MaxSize : PathSize;

                __try {
                    RtlCopyMemory(msg->Path, Path, BytesToCopy);
                    msg->Path[BytesToCopy / sizeof(WCHAR)] = L'\0';
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    ZetaFree(rawMsg);
                    ExReleaseRundownProtection(&GlobalData.PortRundown);
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            // 追加 IRP 语义上下文 (8 bytes)，零填充当无上下文时
            PZETA_IRP_CONTEXT ctx = (PZETA_IRP_CONTEXT)(rawMsg + sizeof(ZETA_MESSAGE));
            if (Context) {
                RtlCopyMemory(ctx, Context, sizeof(ZETA_IRP_CONTEXT));
            }

            LARGE_INTEGER timeout;
            if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
                timeout.QuadPart = -(5 * 10000);
            }
            else {
                timeout.QuadPart = 0;
            }

            status = FltSendMessage(GlobalData.FilterHandle, &GlobalData.ClientPort,
                rawMsg, msgSize, NULL, NULL, &timeout);

            ZetaFree(rawMsg);
        }
        else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    ExReleaseRundownProtection(&GlobalData.PortRundown);
    return status;
}

// ============================================================================
// Lineage Tracker - Experimental Process Bloodline Detection
// Tracks process parent-child relationships via PsSetCreateProcessNotifyRoutineEx
// Detects when script interpreters (PowerShell, CMD, etc.) spawn PE file releases
// ============================================================================

// ── Learning Mode (user-controlled, no auto-disable timer) ────────
BOOLEAN g_LearningModeActive = FALSE;  // Start OFF, user enables manually from UI

VOID LearningMode_SetEnabled(BOOLEAN Enabled) {
    if (Enabled) {
        g_LearningModeActive = TRUE;
        DbgPrint("ZETA: Learning mode manually enabled\n");
    } else {
        g_LearningModeActive = FALSE;
        DbgPrint("ZETA: Learning mode manually disabled\n");
        // Save whitelist so learned processes persist across reboots
        LearningWhitelist_Save();
    }
}

// ── Learning Whitelist ──────────────────────────────────────────────
// Stores process image basenames that were observed during learning mode.
// After learning mode is off, these processes are auto-allowed,
// eliminating repeat false positives. Persists across reboots via registry.

static WCHAR g_LearnedNames[LEARNING_WHITELIST_MAX][LEARNING_WHITELIST_NAME_LEN];
static LONG g_LearnedCount = 0;
static KSPIN_LOCK g_LearnedLock;

static BOOLEAN LearningWhitelist_GetProcessImageName(HANDLE ProcessId, WCHAR* OutBuf, USHORT OutLen) {
    if (!OutBuf || OutLen == 0) return FALSE;
    RtlZeroMemory(OutBuf, OutLen * sizeof(WCHAR));

    PEPROCESS Process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) return FALSE;

    // PsGetProcessImageFileName returns PCSTR (ANSI basename like "notepad.exe")
    PCSTR ansiName = (PCSTR)PsGetProcessImageFileName(Process);
    if (ansiName && ansiName[0] != '\0') {
        // Convert ANSI to Unicode (simple ASCII-compatible conversion)
        SIZE_T copyLen = 0;
        while (ansiName[copyLen] && copyLen < (SIZE_T)(OutLen - 1)) {
            OutBuf[copyLen] = (WCHAR)(UCHAR)ansiName[copyLen];
            copyLen++;
        }
        OutBuf[copyLen] = L'\0';
        ObDereferenceObject(Process);
        return TRUE;
    }

    ObDereferenceObject(Process);
    return FALSE;
}

VOID LearningWhitelist_Init() {
    g_LearnedCount = 0;
    RtlZeroMemory(g_LearnedNames, sizeof(g_LearnedNames));
    KeInitializeSpinLock(&g_LearnedLock);

    // Load persisted whitelist from registry
    UNICODE_STRING keyPath;
    RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ZETA_Drv\\Parameters");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &keyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hKey = NULL;
    NTSTATUS status = ZwOpenKey(&hKey, KEY_READ, &oa);
    if (NT_SUCCESS(status)) {
        UNICODE_STRING valName;
        RtlInitUnicodeString(&valName, L"LearnedProcesses");
        // Read value size first
        ULONG bufSize = 0;
        status = ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, NULL, 0, &bufSize);
        if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL) {
            PKEY_VALUE_PARTIAL_INFORMATION kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(POOL_FLAG_PAGED, bufSize, 'WrnL');
            if (kvpi) {
                status = ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, kvpi, bufSize, &bufSize);
                if (NT_SUCCESS(status) && kvpi->Type == REG_MULTI_SZ && kvpi->DataLength > 0) {
                    WCHAR* data = (WCHAR*)kvpi->Data;
                    ULONG dataEnd = kvpi->DataLength / sizeof(WCHAR);
                    ULONG i = 0;
                    while (i < dataEnd && g_LearnedCount < LEARNING_WHITELIST_MAX) {
                        // Find next string (MULTI_SZ is double-null terminated)
                        WCHAR* entry = &data[i];
                        SIZE_T entryLen = 0;
                        while (i < dataEnd && data[i] != L'\0') { entryLen++; i++; }
                        i++; // skip null
                        if (entryLen > 0 && entryLen < LEARNING_WHITELIST_NAME_LEN) {
                            RtlCopyMemory(g_LearnedNames[g_LearnedCount], entry, entryLen * sizeof(WCHAR));
                            g_LearnedNames[g_LearnedCount][entryLen] = L'\0';
                            g_LearnedCount++;
                        }
                    }
                    DbgPrint("ZETA: Loaded %d learned processes from registry\n", g_LearnedCount);
                }
                ExFreePoolWithTag(kvpi, 'WrnL');
            }
        }
        ZwClose(hKey);
    }
}

VOID LearningWhitelist_Save() {
    if (g_LearnedCount == 0) return;

    UNICODE_STRING keyPath;
    RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ZETA_Drv\\Parameters");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &keyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hKey = NULL;
    NTSTATUS status = ZwCreateKey(&hKey, KEY_SET_VALUE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status)) {
        status = ZwOpenKey(&hKey, KEY_SET_VALUE, &oa);
    }
    if (NT_SUCCESS(status)) {
        // Build MULTI_SZ: all strings null-separated, double-null terminated
        ULONG totalSize = 0;
        for (LONG i = 0; i < g_LearnedCount; i++) {
            totalSize += (ULONG)((wcslen(g_LearnedNames[i]) + 1) * sizeof(WCHAR));
        }
        totalSize += sizeof(WCHAR); // final null terminator

        WCHAR* multiSz = (WCHAR*)ExAllocatePool2(POOL_FLAG_PAGED, totalSize, 'WrnL');
        if (multiSz) {
            RtlZeroMemory(multiSz, totalSize);
            ULONG offset = 0;
            for (LONG i = 0; i < g_LearnedCount; i++) {
                SIZE_T len = wcslen(g_LearnedNames[i]);
                RtlCopyMemory((PUCHAR)multiSz + offset, g_LearnedNames[i], len * sizeof(WCHAR));
                offset += (ULONG)((len + 1) * sizeof(WCHAR));
            }
            UNICODE_STRING valName;
            RtlInitUnicodeString(&valName, L"LearnedProcesses");
            ZwSetValueKey(hKey, &valName, 0, REG_MULTI_SZ, multiSz, totalSize);
            DbgPrint("ZETA: Saved %d learned processes to registry\n", g_LearnedCount);
            ExFreePoolWithTag(multiSz, 'WrnL');
        }
        ZwClose(hKey);
    }
}

VOID LearningWhitelist_LearnProcess(HANDLE ProcessId) {
    WCHAR name[LEARNING_WHITELIST_NAME_LEN];
    if (!LearningWhitelist_GetProcessImageName(ProcessId, name, LEARNING_WHITELIST_NAME_LEN)) return;

    KIRQL OldIrql;
    KeAcquireSpinLock(&g_LearnedLock, &OldIrql);

    // Check if already present (case-insensitive)
    for (LONG i = 0; i < g_LearnedCount; i++) {
        BOOLEAN match = TRUE;
        for (LONG j = 0; j < LEARNING_WHITELIST_NAME_LEN; j++) {
            WCHAR a = g_LearnedNames[i][j];
            WCHAR b = name[j];
            if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);  // tolower
            if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);
            if (a != b) { match = FALSE; break; }
            if (a == L'\0') break;
        }
        if (match) {
            KeReleaseSpinLock(&g_LearnedLock, OldIrql);
            return; // already learned
        }
    }
    // Add to whitelist
    if (g_LearnedCount < LEARNING_WHITELIST_MAX) {
        wcscpy_s(g_LearnedNames[g_LearnedCount], LEARNING_WHITELIST_NAME_LEN, name);
        g_LearnedCount++;
        DbgPrint("ZETA: Learned process: %ws (total=%d)\n", name, g_LearnedCount);
    }

    KeReleaseSpinLock(&g_LearnedLock, OldIrql);
}

BOOLEAN LearningWhitelist_IsProcessAllowed(HANDLE ProcessId) {
    WCHAR name[LEARNING_WHITELIST_NAME_LEN];
    if (!LearningWhitelist_GetProcessImageName(ProcessId, name, LEARNING_WHITELIST_NAME_LEN)) return FALSE;

    KIRQL OldIrql;
    KeAcquireSpinLock(&g_LearnedLock, &OldIrql);

    for (LONG i = 0; i < g_LearnedCount; i++) {
        BOOLEAN match = TRUE;
        for (LONG j = 0; j < LEARNING_WHITELIST_NAME_LEN; j++) {
            WCHAR a = g_LearnedNames[i][j];
            WCHAR b = name[j];
            if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);
            if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);
            if (a != b) { match = FALSE; break; }
            if (a == L'\0') break;
        }
        if (match) {
            KeReleaseSpinLock(&g_LearnedLock, OldIrql);
            return TRUE;
        }
    }

    KeReleaseSpinLock(&g_LearnedLock, OldIrql);
    return FALSE;
}

LINEAGE_NODE g_LineageTable[LINEAGE_TABLE_SIZE] = {0};
KSPIN_LOCK g_LineageLock;
BOOLEAN g_LineageTrackerEnabled = FALSE;

static LINEAGE_THROTTLE g_LineageThrottle[LINEAGE_THROTTLE_SIZE] = {0};
static PVOID g_LineageNotifyHandle = NULL;
static ULONG g_LineageNextSlot = 0;

static BOOLEAN LineageTracker_IsSuspiciousScript(PCUNICODE_STRING ImageName) {
    if (!ImageName || !ImageName->Buffer) return FALSE;

    // Extract just the filename from the full path
    WCHAR FileName[LINEAGE_SCRIPT_NAME_LEN];
    RtlZeroMemory(FileName, sizeof(FileName));

    // Find the last backslash
    SIZE_T len = ImageName->Length / sizeof(WCHAR);
    PCWSTR baseName = ImageName->Buffer;
    for (SIZE_T i = len; i > 0; i--) {
        if (ImageName->Buffer[i - 1] == L'\\') {
            baseName = ImageName->Buffer + i;
            break;
        }
    }

    // Copy filename (lowercase) into FileName buffer
    SIZE_T nameLen = 0;
    PCWSTR src = baseName;
    while (*src && nameLen < LINEAGE_SCRIPT_NAME_LEN - 1) {
        FileName[nameLen++] = RtlDowncaseUnicodeChar(*src);
        src++;
    }
    FileName[nameLen] = L'\0';

    // Compare against known script interpreter names
    for (int i = 0; g_ScriptInterpreterNames[i] != NULL; i++) {
        PCWSTR expected = g_ScriptInterpreterNames[i];
        SIZE_T expectedLen = 0;
        while (expected[expectedLen]) expectedLen++;

        if (nameLen == expectedLen) {
            BOOLEAN match = TRUE;
            for (SIZE_T j = 0; j < expectedLen; j++) {
                if (FileName[j] != RtlDowncaseUnicodeChar(expected[j])) {
                    match = FALSE;
                    break;
                }
            }
            if (match) return TRUE;
        }
    }
    return FALSE;
}

static ULONG LineageTracker_FindSlot(HANDLE ProcessId) {
    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;
    ULONG HashSlot = (pid * 2654435761u) % LINEAGE_TABLE_SIZE;

    // Linear probe starting from hash slot
    for (ULONG i = 0; i < LINEAGE_TABLE_SIZE; i++) {
        ULONG idx = (HashSlot + i) % LINEAGE_TABLE_SIZE;
        if (g_LineageTable[idx].InUse &&
            g_LineageTable[idx].ProcessId == pid) {
            return idx;
        }
        if (!g_LineageTable[idx].InUse) {
            return idx;
        }
    }
    // Fallback: LRU - replace oldest entry
    ULONG oldest = 0;
    for (ULONG i = 1; i < LINEAGE_TABLE_SIZE; i++) {
        if (g_LineageTable[i].CreateTime.QuadPart < g_LineageTable[oldest].CreateTime.QuadPart) {
            oldest = i;
        }
    }
    return oldest;
}

VOID LineageTracker_OnProcessCreate(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create) {
    UNREFERENCED_PARAMETER(ParentId);

    if (!g_LineageTrackerEnabled) return;
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return;

    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;

    // Process termination: simple table clear (quick operation, safe under spinlock)
    if (!Create) {
        KIRQL OldIrql;
        KeAcquireSpinLock(&g_LineageLock, &OldIrql);
        for (ULONG i = 0; i < LINEAGE_TABLE_SIZE; i++) {
            if (g_LineageTable[i].InUse && g_LineageTable[i].ProcessId == pid) {
                g_LineageTable[i].InUse = FALSE;
                RtlZeroMemory(g_LineageTable[i].ImageName, sizeof(g_LineageTable[i].ImageName));
                break;
            }
        }
        KeReleaseSpinLock(&g_LineageLock, OldIrql);

        // Trigger file rollback for terminated untrusted processes
        Rollback_Execute(pid);

        return;
    }

    // ✅ Step 1: Get image name and parent PID BEFORE acquiring spinlock (PASSIVE_LEVEL only)
    PUNICODE_STRING imageName = NULL;
    NTSTATUS status = GetProcessImageName(ProcessId, &imageName);

    ULONG parentPid = 0;
    PEPROCESS process = NULL;
    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) {
        parentPid = (ULONG)(ULONG_PTR)PsGetProcessInheritedFromUniqueProcessId(process);
        ObDereferenceObject(process);
    }

    BOOLEAN isSuspicious = FALSE;
    if (NT_SUCCESS(status) && imageName) {
        isSuspicious = LineageTracker_IsSuspiciousScript(imageName);
    }

    // ✅ Step 2: Only hold spinlock for the fast table write
    KIRQL OldIrql;
    KeAcquireSpinLock(&g_LineageLock, &OldIrql);
    ULONG slot = LineageTracker_FindSlot(ProcessId);
    PLINEAGE_NODE node = &g_LineageTable[slot];
    node->ProcessId = pid;
    node->ParentProcessId = parentPid;
    node->InUse = TRUE;
    node->IsSuspiciousScript = isSuspicious;
    KeQuerySystemTime(&node->CreateTime);

    // Copy filename (lowercase) into node
    RtlZeroMemory(node->ImageName, sizeof(node->ImageName));
    if (NT_SUCCESS(status) && imageName && imageName->Buffer) {
        PCWSTR baseName = imageName->Buffer;
        SIZE_T len = imageName->Length / sizeof(WCHAR);
        for (SIZE_T i = len; i > 0; i--) {
            if (imageName->Buffer[i - 1] == L'\\') {
                baseName = imageName->Buffer + i;
                break;
            }
        }
        SIZE_T copyLen = 0;
        while (baseName[copyLen] && copyLen < LINEAGE_SCRIPT_NAME_LEN - 1) {
            node->ImageName[copyLen] = (WCHAR)RtlDowncaseUnicodeChar(baseName[copyLen]);
            copyLen++;
        }
        node->ImageName[copyLen] = L'\0';
    }
    KeReleaseSpinLock(&g_LineageLock, OldIrql);

    if (imageName) ExFreePool(imageName);

    DbgPrint("ZETA: LineageTracker - Process created PID=%lu Parent=%lu Image=%ls Script=%s\n",
        pid, parentPid, node->ImageName, isSuspicious ? "YES" : "NO");
}

static BOOLEAN LineageTracker_CheckThrottle(ULONG ProcessId) {
    KIRQL OldIrql;
    KeAcquireSpinLock(&g_LineageLock, &OldIrql);

    LARGE_INTEGER Now;
    KeQuerySystemTime(&Now);
    LONGLONG ThrottleTicks = (LONGLONG)LINEAGE_THROTTLE_MS * 10000LL;

    // Find existing throttle entry or reuse oldest
    ULONG slot = (ULONG)-1;
    ULONG oldestSlot = 0;
    LONGLONG oldestTime = Now.QuadPart;

    for (ULONG i = 0; i < LINEAGE_THROTTLE_SIZE; i++) {
        if (g_LineageThrottle[i].ProcessId == ProcessId) {
            slot = i;
            break;
        }
        if (g_LineageThrottle[i].LastAlertTime.QuadPart < oldestTime) {
            oldestTime = g_LineageThrottle[i].LastAlertTime.QuadPart;
            oldestSlot = i;
        }
    }

    if (slot == (ULONG)-1) {
        slot = oldestSlot;
        g_LineageThrottle[slot].ProcessId = ProcessId;
        g_LineageThrottle[slot].LastAlertTime = Now;
        KeReleaseSpinLock(&g_LineageLock, OldIrql);
        return TRUE; // No previous alert, allow
    }

    LONGLONG elapsed = Now.QuadPart - g_LineageThrottle[slot].LastAlertTime.QuadPart;
    if (elapsed < ThrottleTicks) {
        KeReleaseSpinLock(&g_LineageLock, OldIrql);
        return FALSE; // Throttled
    }

    g_LineageThrottle[slot].LastAlertTime = Now;
    KeReleaseSpinLock(&g_LineageLock, OldIrql);
    return TRUE;
}

static ULONG LineageTracker_FindParentPid(ULONG ProcessId) {
    KIRQL OldIrql;
    KeAcquireSpinLock(&g_LineageLock, &OldIrql);

    ULONG slot = LineageTracker_FindSlot((HANDLE)(ULONG_PTR)ProcessId);
    ULONG parent = 0;
    if (g_LineageTable[slot].InUse && g_LineageTable[slot].ProcessId == ProcessId) {
        parent = g_LineageTable[slot].ParentProcessId;
    }
    KeReleaseSpinLock(&g_LineageLock, OldIrql);
    return parent;
}

// ── P0: 查询进程的脚本解释器链深度 ──────────────────────────
// 返回 0 = 普通进程, 1 = 直接是脚本解释器, 2+ = 多级脚本嵌套
// 用于填充 IRP 上下文的 ScriptDepth 字段
UCHAR GetScriptDepthForProcess(HANDLE ProcessId) {
    if (!g_LineageTrackerEnabled) return 0;
    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;
    if (pid == 0 || pid == 4) return 0;

    UCHAR depth = 0;
    KIRQL OldIrql;
    KeAcquireSpinLock(&g_LineageLock, &OldIrql);

    for (ULONG d = 0; d < LINEAGE_MAX_DEPTH; d++) {
        ULONG slot = LineageTracker_FindSlot((HANDLE)(ULONG_PTR)pid);
        if (!g_LineageTable[slot].InUse ||
            g_LineageTable[slot].ProcessId != pid)
            break;

        if (g_LineageTable[slot].IsSuspiciousScript)
            depth++;

        pid = g_LineageTable[slot].ParentProcessId;
        if (pid == 0 || pid == 4) break;
    }

    KeReleaseSpinLock(&g_LineageLock, OldIrql);
    return depth;
}

// ── P0: 填充 IRP 上下文的 ScriptDepth 和脚本标志 ────────────
// 一次锁获取批量完成，避免重复自旋
VOID FillScriptInfo(PZETA_IRP_CONTEXT ctx) {
    if (!g_LineageTrackerEnabled) return;
    ULONG pidVal = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (pidVal == 0 || pidVal == 4) return;

    UCHAR depth = 0;
    ULONG currentPid = pidVal;

    KIRQL OldIrql;
    KeAcquireSpinLock(&g_LineageLock, &OldIrql);

    for (ULONG d = 0; d < LINEAGE_MAX_DEPTH; d++) {
        ULONG slot = LineageTracker_FindSlot((HANDLE)(ULONG_PTR)currentPid);
        if (!g_LineageTable[slot].InUse ||
            g_LineageTable[slot].ProcessId != currentPid)
            break;

        if (g_LineageTable[slot].IsSuspiciousScript) {
            depth++;
            if (currentPid == pidVal)
                ctx->Flags |= CTX_FLAG_SCRIPT_HOST;
        }

        currentPid = g_LineageTable[slot].ParentProcessId;
        if (currentPid == 0 || currentPid == 4) break;
    }

    if (depth > 0)
        ctx->Flags |= CTX_FLAG_HAS_SCRIPT_ANC;
    ctx->ScriptDepth = depth;

    KeReleaseSpinLock(&g_LineageLock, OldIrql);
}

VOID LineageTracker_OnFileRelease(ULONG ProcessId, PUNICODE_STRING FilePath) {
    if (!g_LineageTrackerEnabled) return;
    if (!FilePath || !FilePath->Buffer) return;
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return;

    // Check throttle first
    if (!LineageTracker_CheckThrottle(ProcessId)) {
        return;
    }

    // Backtrack the ancestry chain (up to 16 levels)
    ULONG currentPid = ProcessId;
    ULONG suspects[LINEAGE_MAX_DEPTH];
    ULONG suspectCount = 0;

    for (ULONG depth = 0; depth < LINEAGE_MAX_DEPTH; depth++) {
        KIRQL OldIrql;
        KeAcquireSpinLock(&g_LineageLock, &OldIrql);

        ULONG slot = LineageTracker_FindSlot((HANDLE)(ULONG_PTR)currentPid);
        BOOLEAN found = FALSE;
        BOOLEAN isScript = FALSE;
        ULONG parentPid = 0;

        if (g_LineageTable[slot].InUse && g_LineageTable[slot].ProcessId == currentPid) {
            found = TRUE;
            isScript = g_LineageTable[slot].IsSuspiciousScript;
            parentPid = g_LineageTable[slot].ParentProcessId;
        }

        KeReleaseSpinLock(&g_LineageLock, OldIrql);

        if (!found) break;

        if (isScript) {
            suspects[suspectCount++] = currentPid;
            // Found a script interpreter ancestor, but keep going up to find the root
            currentPid = parentPid;
            if (suspectCount >= LINEAGE_MAX_DEPTH) break;
        } else {
            currentPid = parentPid;
        }

        if (currentPid == 0 || currentPid == 4) break; // Idle/System
    }

    // If we found any script interpreter in the ancestry, alert
    if (suspectCount > 0) {
        if (g_LearningModeActive) {
            DbgPrint("ZETA: LineageTracker - ALERT suppressed (learning mode) PID=%lu script ancestors=%lu\n",
                ProcessId, suspectCount);
            // Learn the releasing process so it won't trigger again
            LearningWhitelist_LearnProcess((HANDLE)(ULONG_PTR)ProcessId);
            return;
        }
        // Check learning whitelist before alerting
        if (LearningWhitelist_IsProcessAllowed((HANDLE)(ULONG_PTR)ProcessId)) {
            DbgPrint("ZETA: LineageTracker - PID=%lu is whitelisted (learned)\n", ProcessId);
            return;
        }
        DbgPrint("ZETA: LineageTracker - ALERT! PID=%lu released file through %lu script ancestors: %wZ\n",
            ProcessId, suspectCount, FilePath);

        // Build alert message: format "PID|FILEPATH"
        WCHAR alertBuf[MAX_PATH_LEN];
        ULONG written = 0;

        // Format as "RELEASEPID|FILEPATH" so user-mode can aggregate
        WCHAR pidStr[16];
        RtlStringCbPrintfW(pidStr, sizeof(pidStr), L"%lu|", ProcessId);
        SIZE_T pidLen = wcslen(pidStr);

        RtlCopyMemory(alertBuf, pidStr, pidLen * sizeof(WCHAR));
        written = (ULONG)pidLen;

        // Append file path
        SIZE_T pathCopyLen = FilePath->Length / sizeof(WCHAR);
        if (pathCopyLen > MAX_PATH_LEN - written - 1) {
            pathCopyLen = MAX_PATH_LEN - written - 1;
        }
        if (pathCopyLen > 0) {
            RtlCopyMemory(alertBuf + written, FilePath->Buffer, pathCopyLen * sizeof(WCHAR));
            written += (ULONG)pathCopyLen;
        }
        alertBuf[written] = L'\0';

        // Also format a human-readable message
        WCHAR msgBuf[MAX_PATH_LEN];
        RtlStringCbPrintfW(msgBuf, sizeof(msgBuf),
            L"Lineage Alert: PID=%lu script ancestors=%lu file=%wZ",
            ProcessId, suspectCount, FilePath);

        SendMessageToUser(ZETA_MSG_LINEAGE_ALERT, ProcessId, alertBuf, (written + 1) * sizeof(WCHAR));
        DriverLog(ProcessId, L"LineageTracker: ALERT - Script ancestry detected (%lu levels)", suspectCount);
    }
}

NTSTATUS LineageTracker_SetEnabled(BOOLEAN Enabled) {
    g_LineageTrackerEnabled = Enabled;
    g_DriverState.LineageTrackerOK = Enabled;
    if (Enabled) {
        DbgPrint("ZETA: LineageTracker ENABLED\n");
    } else {
        DbgPrint("ZETA: LineageTracker DISABLED\n");
    }
    return STATUS_SUCCESS;
}

// ============================================================================
// First-Write Header Integrity Check
// 
// 原理：
//   勒索软件为了速度使用 XOR/流加密，加密后的文件头 4 字节必然是乱码，
//   不可能匹配任何已知文件格式的魔数 (ZIP = PK\x03\x04, PDF = %PDF, ...)。
// 
//   检测流程：
//   1. 未信任进程首次对文档文件做 offset=0 写入时，检查写缓冲区前 4 字节
//   2. 如果匹配已知魔数 → 标记进程为 "已验证，不是勒索"，后续写入放行
//   3. 如果不匹配任何已知魔数 → 挂起进程 → 终止进程 → 报告告警
// 
//   性能：只检查每个进程的第一次 offset=0 写入，O(1) 开销
// ============================================================================

static RANSOM_FIRSTWRITE_TRACKER g_RansomFirstWriteTrackers[RANSOM_EXP_FIRSTWRITE_MAX];
static KSPIN_LOCK g_RansomFirstWriteLock;

// Work item for async process suspension and termination
typedef struct _RANSOM_TERMINATE_WORK {
    WORK_QUEUE_ITEM WorkItem;
    PEPROCESS Process;
    HANDLE Pid;
    ULONG PidValue;
    WCHAR FilePath[MAX_PATH_LEN];
} RANSOM_TERMINATE_WORK, *PRANSOM_TERMINATE_WORK;

static VOID RansomExp_TerminateWorker(PVOID Parameter) {
    PRANSOM_TERMINATE_WORK work = (PRANSOM_TERMINATE_WORK)Parameter;

    // Track this work item for unload synchronization
    InterlockedIncrement(&g_WorkItemTracker.PendingCount);

    if (g_IsUnloading) {
        ObDereferenceObject(work->Process);
        ZetaFree(work);
        InterlockedDecrement(&g_WorkItemTracker.PendingCount);
        return;
    }

    // SAFETY GUARD: Never terminate ZETA's own process
    if (work->PidValue == GlobalData.ZetaPid) {
        DbgPrint("ZETA: RansomExp-FirstWrite: SAFETY GUARD - refusing to terminate ZETA PID=%lu\n",
            work->PidValue);
        DriverLog(work->PidValue,
            L"RansomExp-FirstWrite: SAFETY GUARD triggered - ZETA process cannot self-terminate");
        ObDereferenceObject(work->Process);
        ZetaFree(work);
        InterlockedDecrement(&g_WorkItemTracker.PendingCount);
        return;
    }

    // LOG: record the suspension target before acting
    DbgPrint("ZETA: RansomExp-FirstWrite: Suspending PID=%lu (file=%ws)\n",
        work->PidValue, work->FilePath);
    DriverLog(work->PidValue,
        L"RansomExp-FirstWrite: About to suspend process (ransomware), file=%ws", work->FilePath);

    // P1-2: 使用 PsSuspendProcess 替代 ZwTerminateProcess
    // 原方案直接终止进程 (伪装崩溃)，但会丢失现场，无法让用户决策
    // 新方案:
    //   1. 挂起进程 (冻结所有线程，停止进一步破坏)
    //   2. 发送告警到用户态 (UI 弹窗: 阻止/允许)
    //   3. 标记回滚 (释放的 PE 文件待清理)
    //   4. 不主动终止，由用户态决策 (UI 调用 TerminateProcess 或 PsResumeProcess)

    // Step 1: Suspend the process (freeze all threads)
    NTSTATUS suspendStatus = PsSuspendProcess(work->Process);
    if (!NT_SUCCESS(suspendStatus)) {
        DbgPrint("ZETA: RansomExp-FirstWrite: PsSuspendProcess FAILED (0x%08X) for PID=%lu\n",
            suspendStatus, work->PidValue);
        DriverLog(work->PidValue,
            L"RansomExp-FirstWrite: Suspend FAILED (0x%lX), ransomware may continue", suspendStatus);
        ObDereferenceObject(work->Process);
        ZetaFree(work);
        if (InterlockedDecrement(&g_WorkItemTracker.PendingCount) == 0) {
            KeSetEvent(&g_WorkItemTracker.CompletionEvent, 0, FALSE);
        }
        return;
    }

    DbgPrint("ZETA: RansomExp-FirstWrite: SUSPENDED PID=%lu (ransomware, file=%ws)\n",
        work->PidValue, work->FilePath);
    DriverLog(work->PidValue,
        L"RansomExp-FirstWrite: SUSPENDED - ransomware detected, awaiting user decision, file=%ws", work->FilePath);

    // M1-5: 登记挂起进程到超时跟踪表 (UI 失联时由超时线程兜底, 避免永久冻结)
    RansomExp_RegisterSuspend(work->PidValue);

    // Step 2: Send alert to user-mode (UI will show HIPS popup)
    // ZETA_MSG_RANSOM_HEADER_ALERT (7002) - 用户态收到后弹窗询问用户
    SendMessageToUser(ZETA_MSG_RANSOM_HEADER_ALERT,
        work->PidValue, work->FilePath, (USHORT)(wcslen(work->FilePath) * sizeof(WCHAR)));

    // Step 3: Mark for rollback (so PE files released by this PID can be cleaned up on exit)
    Rollback_MarkTerminated(work->PidValue);

    // Step 4: NOT terminating - process stays suspended
    // User-mode decides:
    //   - Block (kill): user-mode calls TerminateProcess API on the PID
    //   - Allow (resume): user-mode sends ZETA_CMD_ALLOW_OP (4) with PID
    //     (driver will resume the process via PsResumeProcess)
    //   - Timeout: process stays suspended (safer than auto-killing)

    ObDereferenceObject(work->Process);
    ZetaFree(work);

    // Decrement counter; if zero, signal completion event
    if (InterlockedDecrement(&g_WorkItemTracker.PendingCount) == 0) {
        KeSetEvent(&g_WorkItemTracker.CompletionEvent, 0, FALSE);
    }
}

BOOLEAN RansomExp_CheckFirstWrite(PFLT_CALLBACK_DATA Data,
    PUNICODE_STRING FileName, HANDLE Pid, PEPROCESS Process,
    PVOID WriteBuffer, ULONG WriteLength)
{
    UNREFERENCED_PARAMETER(Data);

    // Guard: not enabled, learning mode, or wrong IRQL
    if (!g_RansomExperimentalEnabled) return FALSE;
    if (g_LearningModeActive) return FALSE;
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FALSE;
    if (!FileName || !FileName->Buffer) return FALSE;
    if (WriteLength < 4 || !WriteBuffer) return FALSE;

    // ── Trust-level gate: never flag signed/system processes ──
    // GetProcessTrustLevel now includes IsKnownWindowsSystemProcess fallback
    // to prevent false-positive kills of msiexec.exe, svchost.exe, etc.
    if (Pid && GetProcessTrustLevel(Pid) >= TRUST_LEVEL_SIGNED) {
        return FALSE;
    }

    // Only check writes at offset 0 (beginning of file)
    LARGE_INTEGER writeOffset = Data->Iopb->Parameters.Write.ByteOffset;
    if (writeOffset.QuadPart != 0) return FALSE;

    // Only check user directory document files
    if (!WildcardMatch(L"*\\Users\\*", FileName->Buffer, FileName->Length)) {
        return FALSE;
    }

    // Skip noisy / system / temp paths
    if (WildcardMatch(L"*\\AppData\\Local\\Temp\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\Windows\\Temp\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\Windows\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\Program Files\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\Program Files (x86)\\*", FileName->Buffer, FileName->Length)) {
        return FALSE;
    }

    // Skip known compressed extensions (zip, rar, 7z, gif, jpg, png, mp3, mp4, ...)
    for (int i = 0; i < sizeof(Helper_NaturallyCompressedExtensions) /
        sizeof(Helper_NaturallyCompressedExtensions[0]); i++) {
        if (HasSuffix(FileName, Helper_NaturallyCompressedExtensions[i])) {
            return FALSE;
        }
    }

    // ── Check first-write tracker for this process ──
    LARGE_INTEGER Now;
    KeQuerySystemTime(&Now);
    LARGE_INTEGER createTime;
    createTime.QuadPart = PsGetProcessCreateTimeQuadPart(Process);

    KIRQL OldIrql;
    KeAcquireSpinLock(&g_RansomFirstWriteLock, &OldIrql);

    // Find existing tracker or empty slot
    PRANSOM_FIRSTWRITE_TRACKER Tracker = NULL;
    int freeSlot = -1;

    for (int i = 0; i < RANSOM_EXP_FIRSTWRITE_MAX; i++) {
        PRANSOM_FIRSTWRITE_TRACKER T = &g_RansomFirstWriteTrackers[i];

        if (T->Process == Process &&
            T->ProcessCreateTime.QuadPart == createTime.QuadPart) {
            Tracker = T;
            break;
        }

        if (freeSlot < 0 && T->Process == NULL) {
            freeSlot = i;
        }
    }

    // If this is the first time we see this process
    if (!Tracker) {
        // No slot → process already tracked (maxed out, skip)
        if (freeSlot < 0) {
            KeReleaseSpinLock(&g_RansomFirstWriteLock, OldIrql);
            return FALSE;
        }

        // First write from this process → check header
        Tracker = &g_RansomFirstWriteTrackers[freeSlot];
        // 释放旧槽位的 EPROCESS 引用（过期条目）
        if (Tracker->Process) {
            ObDereferenceObject(Tracker->Process);
        }
        Tracker->Process = Process;
        ObReferenceObject(Process);  // 为追踪器加引用，避免 UAF
        Tracker->ProcessCreateTime = createTime;

        // Check the write buffer's first 4 bytes against known magic numbers
        PUCHAR Buf = (PUCHAR)WriteBuffer;
        BOOLEAN IsKnown = RansomExp_IsKnownMagic(Buf, WriteLength);

        if (IsKnown) {
            // Header matches a known format → NOT ransomware
            Tracker->Investigated = TRUE;
            Tracker->Terminating = FALSE;
            KeReleaseSpinLock(&g_RansomFirstWriteLock, OldIrql);
            return FALSE;  // Allow the write
        } else {
            // Header does NOT match any known format → this is ransomware!
            Tracker->Investigated = FALSE;
            Tracker->Terminating = TRUE;
            KeReleaseSpinLock(&g_RansomFirstWriteLock, OldIrql);

            // Schedule async termination: suspend → terminate
            PRANSOM_TERMINATE_WORK work = (PRANSOM_TERMINATE_WORK)
                ZetaAllocate(sizeof(RANSOM_TERMINATE_WORK));
            if (work) {
                RtlZeroMemory(work, sizeof(RANSOM_TERMINATE_WORK));
                ExInitializeWorkItem(&work->WorkItem, RansomExp_TerminateWorker, work);
                work->Process = Process;
                work->Pid = Pid;
                work->PidValue = (ULONG)(ULONG_PTR)Pid;
                ULONG copyLen = FileName->Length;
                if (copyLen > sizeof(work->FilePath) - sizeof(WCHAR)) {
                    copyLen = sizeof(work->FilePath) - sizeof(WCHAR);
                }
                RtlCopyMemory(work->FilePath, FileName->Buffer, copyLen);
                work->FilePath[copyLen / sizeof(WCHAR)] = L'\0';

                ObReferenceObject(Process);  // Kept alive for the work item
                ExQueueWorkItem(&work->WorkItem, DelayedWorkQueue);

                DbgPrint("ZETA: RansomExp-FirstWrite: Ransomware DETECTED at first write! "
                    "PID=%lu, File=%wZ\n", (ULONG)(ULONG_PTR)Pid, FileName);
                SendMessageToUser(ZETA_MSG_RANSOM_FIRST_WRITE, (ULONG)(ULONG_PTR)Pid, FileName->Buffer, FileName->Length);
            }

            return TRUE;  // BLOCK this first write
        }
    } else {
        // Process already in tracker
        if (Tracker->Investigated) {
            KeReleaseSpinLock(&g_RansomFirstWriteLock, OldIrql);
            return FALSE;  // Already verified clean
        }

        if (Tracker->Terminating) {
            KeReleaseSpinLock(&g_RansomFirstWriteLock, OldIrql);
            return TRUE;   // Termination in progress, block this write too
        }

        KeReleaseSpinLock(&g_RansomFirstWriteLock, OldIrql);
        return FALSE;
    }
}

VOID RansomExp_ResetFirstWriteTrackers() {
    KIRQL OldIrql;
    KeAcquireSpinLock(&g_RansomFirstWriteLock, &OldIrql);
    // 先释放所有 EPROCESS 引用，再清零
    for (int i = 0; i < RANSOM_EXP_FIRSTWRITE_MAX; i++) {
        if (g_RansomFirstWriteTrackers[i].Process) {
            ObDereferenceObject(g_RansomFirstWriteTrackers[i].Process);
            g_RansomFirstWriteTrackers[i].Process = NULL;
        }
    }
    RtlZeroMemory(g_RansomFirstWriteTrackers, sizeof(g_RansomFirstWriteTrackers));
    KeReleaseSpinLock(&g_RansomFirstWriteLock, OldIrql);
    DbgPrint("ZETA: RansomExp-FirstWrite: Trackers reset\n");
}

// ============================================================================
// Experimental Ransomware Detection - Enhanced Module
// Behavioral: high-entropy writes + frequency tracking (3s window, weight 2)
// Header check: first 32 bytes against known magic numbers
// ============================================================================

BOOLEAN g_RansomExperimentalEnabled = FALSE;

// ── Module Switches (P1-1: 运行时模块开关) ──────────────────────
// 默认全部启用 (向后兼容)；网络保护默认禁用 (由独立 NetFilter 驱动处理)
BOOLEAN g_ProcessProtectEnabled  = TRUE;   // 进程保护 (ObRegisterCallbacks/DKOM)
BOOLEAN g_SuspendEnabled          = TRUE;   // HIPS 挂起待决操作
BOOLEAN g_FileProtectEnabled      = TRUE;   // 文件保护 (PreCreate/PreWrite/PreSetInfo)
BOOLEAN g_SystemProtectEnabled    = TRUE;   // 系统保护 (System32/SAM/SYSTEM 等)
BOOLEAN g_DriverProtectEnabled    = TRUE;   // 驱动保护 (反驱动作恶)
BOOLEAN g_NetworkProtectEnabled   = FALSE;  // 网络保护 (由 ZETA_NetFilter.sys 独立处理)
BOOLEAN g_RansomRedirectEnabled   = FALSE;  // P1-状态机: 勒索写重定向 (写隔离副本, 原文件保留)
BOOLEAN g_DocBackupEnabled        = FALSE;  // P0: 文档写前备份 (暴力方案)
BOOLEAN g_UnloadAuthorized        = FALSE;  // 防卸载授权 (ZETA_CMD_AUTHORIZE_UNLOAD=27)

#define RANSOM_EXP_TRACKER_MAX 64
typedef struct _RANSOM_EXP_TRACKER {
    PEPROCESS Process;
    LARGE_INTEGER ProcessCreateTime;
    ULONG ActivityCount;
    LARGE_INTEGER LastActivityTime;
} RANSOM_EXP_TRACKER, * PRANSOM_EXP_TRACKER;

static RANSOM_EXP_TRACKER g_RansomExpTrackers[RANSOM_EXP_TRACKER_MAX];

BOOLEAN RansomExp_IsKnownMagic(PUCHAR Header, ULONG HeaderLen) {
    if (!Header || HeaderLen < 4) return FALSE;

    for (int i = 0; i < RANSOM_HEADER_NUM_MAGICS; i++) {
        if (g_KnownMagicNumbers[i][0] == 0x00 &&
            g_KnownMagicNumbers[i][1] == 0x00 &&
            g_KnownMagicNumbers[i][2] == 0x00 &&
            g_KnownMagicNumbers[i][3] == 0x00) {
            break; // Skip terminator
        }

        BOOLEAN match = TRUE;
        for (int j = 0; j < 4; j++) {
            if (Header[j] != g_KnownMagicNumbers[i][j]) {
                match = FALSE;
                break;
            }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

static BOOLEAN RansomExp_IsPEFile(PUCHAR Header, ULONG HeaderLen) {
    if (!Header || HeaderLen < 4) return FALSE;
    // PE files start with MZ (0x4D, 0x5A)
    return (Header[0] == 0x4D && Header[1] == 0x5A);
}

static BOOLEAN RansomExp_CheckHighEntropy(PUCHAR Buffer, ULONG Length) {
    if (!Buffer || Length < 64) return FALSE;

    ULONG ScanLen = (Length > 1024) ? 1024 : Length;
    USHORT Histogram[256] = {0};

    __try {
        for (ULONG i = 0; i < ScanLen; i++) {
            Histogram[Buffer[i]]++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    USHORT MaxFreq = 0;
    for (int i = 0; i < 256; i++) {
        if (Histogram[i] > MaxFreq) MaxFreq = Histogram[i];
    }

    ULONG ExpectedAvg = ScanLen / 256;
    return (MaxFreq < (ExpectedAvg + 10)); // Same threshold as existing IsHighEntropy
}

BOOLEAN RansomExp_CheckWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                              PUNICODE_STRING FileName, PVOID WriteBuffer, ULONG WriteLength) {
    UNREFERENCED_PARAMETER(FltObjects);

    if (!g_RansomExperimentalEnabled) return FALSE;
    if (g_LearningModeActive) return FALSE;   // skip all during learning mode
    if (!FileName || !FileName->Buffer) return FALSE;
    if (Data->RequestorMode == KernelMode) return FALSE;
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FALSE;

    // ── Trust-level gate: skip signed/system processes ──
    {
        HANDLE curPid = PsGetCurrentProcessId();
        if (GetProcessTrustLevel(curPid) >= TRUST_LEVEL_SIGNED) {
            return FALSE;
        }
    }

    // Only check user directories
    if (!WildcardMatch(L"*\\Users\\*", FileName->Buffer, FileName->Length)) {
        return FALSE;
    }

    // Skip noisy paths
    if (WildcardMatch(L"*\\AppData\\Local\\Temp\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\Windows\\Temp\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\Windows\\Prefetch\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\Program Files\\*", FileName->Buffer, FileName->Length) ||
        WildcardMatch(L"*\\Program Files (x86)\\*", FileName->Buffer, FileName->Length)) {
        return FALSE;
    }

    // Skip known compressed extensions
    BOOLEAN isCompressed = FALSE;
    for (int i = 0; i < sizeof(Helper_NaturallyCompressedExtensions) / sizeof(Helper_NaturallyCompressedExtensions[0]); i++) {
        SIZE_T extLen = 0;
        while (Helper_NaturallyCompressedExtensions[i][extLen]) extLen++;
        if (HasSuffix(FileName, Helper_NaturallyCompressedExtensions[i])) {
            isCompressed = TRUE;
            break;
        }
    }
    if (isCompressed) return FALSE;

    // Skip writes that are too small
    if (WriteLength < 64) return FALSE;

    // Step 1: Check entropy of write buffer
    BOOLEAN isHighEntropy = FALSE;
    if (WriteBuffer && WriteLength > 0) {
        isHighEntropy = RansomExp_CheckHighEntropy((PUCHAR)WriteBuffer, WriteLength);
    }

    if (!isHighEntropy) return FALSE;

    // Step 2: Track activity per process (3-second window, threshold 5, weight 2)
    HANDLE Pid = PsGetCurrentProcessId();
    PEPROCESS Process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(Pid, &Process))) {
        return FALSE;
    }

    LARGE_INTEGER Now;
    KeQuerySystemTime(&Now);
    LARGE_INTEGER createTime;
    createTime.QuadPart = PsGetProcessCreateTimeQuadPart(Process);
    BOOLEAN Result = FALSE;

    KIRQL OldIrql;
    KeAcquireSpinLock(&GlobalData.TrackerMutex, &OldIrql);

    PRANSOM_EXP_TRACKER Tracker = NULL;
    PRANSOM_EXP_TRACKER LruSlot = &g_RansomExpTrackers[0];

    for (int i = 0; i < RANSOM_EXP_TRACKER_MAX; i++) {
        PRANSOM_EXP_TRACKER Current = &g_RansomExpTrackers[i];

        if (Current->LastActivityTime.QuadPart < LruSlot->LastActivityTime.QuadPart) {
            LruSlot = Current;
        }

        if (Current->Process == Process && Current->ProcessCreateTime.QuadPart == createTime.QuadPart) {
            Tracker = Current;
            break;
        }
    }

    if (!Tracker) {
        // Find expired or empty slot (LRU)
        for (int i = 0; i < RANSOM_EXP_TRACKER_MAX; i++) {
            PRANSOM_EXP_TRACKER Current = &g_RansomExpTrackers[i];
            BOOLEAN isExpired = FALSE;
            if (Current->Process != NULL) {
                LARGE_INTEGER Diff;
                Diff.QuadPart = Now.QuadPart - Current->LastActivityTime.QuadPart;
                if (Diff.QuadPart > (RANSOM_EXP_TIME_WINDOW_MS * 10000LL)) {
                    isExpired = TRUE;
                }
            }
            if (Current->Process == NULL || isExpired) {
                Tracker = Current;
                break;
            }
        }
        if (!Tracker) Tracker = LruSlot;

        // 释放旧槽位的 EPROCESS 引用（过期/LRU 条目）
        if (Tracker->Process) {
            ObDereferenceObject(Tracker->Process);
        }
        Tracker->Process = Process;
        ObReferenceObject(Process);  // 为追踪器加引用
        Tracker->ProcessCreateTime = createTime;
        Tracker->ActivityCount = 0;
        Tracker->LastActivityTime = Now;
    } else {
        LARGE_INTEGER Diff;
        Diff.QuadPart = Now.QuadPart - Tracker->LastActivityTime.QuadPart;
        if (Diff.QuadPart > (RANSOM_EXP_TIME_WINDOW_MS * 10000LL)) {
            Tracker->ActivityCount = 0;
        }
        Tracker->LastActivityTime = Now;
    }

    Tracker->ActivityCount += RANSOM_EXP_WEIGHT;

    if (Tracker->ActivityCount >= RANSOM_EXP_COUNT_THRESHOLD) {
        Result = TRUE;
        DbgPrint("ZETA: RansomExp - RANSOMWARE activity detected! PID=%lu, File=%wZ, Count=%lu\n",
            (ULONG)(ULONG_PTR)Pid, FileName, Tracker->ActivityCount);
    }

    KeReleaseSpinLock(&GlobalData.TrackerMutex, OldIrql);
    ObDereferenceObject(Process);

    if (Result) {
        DriverLog((ULONG)(ULONG_PTR)Pid, L"RansomExp: Behavioral ransomware detected (count=%lu)", Tracker->ActivityCount);
    }

    return Result;
}

NTSTATUS RansomExp_SetEnabled(BOOLEAN Enabled) {
    g_RansomExperimentalEnabled = Enabled;
    g_DriverState.RansomExperimentalOK = Enabled;

    if (Enabled) {
        // 先释放所有行为追踪器的 EPROCESS 引用，再清零
        for (int i = 0; i < RANSOM_EXP_TRACKER_MAX; i++) {
            if (g_RansomExpTrackers[i].Process) {
                ObDereferenceObject(g_RansomExpTrackers[i].Process);
                g_RansomExpTrackers[i].Process = NULL;
            }
        }
        RtlZeroMemory(g_RansomExpTrackers, sizeof(g_RansomExpTrackers));
        // ResetFirstWriteTrackers 内部已经处理了 EPROCESS 引用释放
        RansomExp_ResetFirstWriteTrackers();
        DbgPrint("ZETA: RansomExperimental ENABLED (behavioral + first-write header check)\n");
    } else {
        DbgPrint("ZETA: RansomExperimental DISABLED\n");
    }
    return STATUS_SUCCESS;
}

// ============================================================================
// M1-5: 勒索挂起超时兜底 — 实现 (表/锁在文件顶部定义)
// 被 PsSuspendProcess 挂起的进程等待用户态 ALLOW/DENY 决策。
// 若 UI 失联/客户端崩溃, 进程会永久冻结 → 登记到本表, 由 1s 超时线程扫描,
// 超时执行默认策略 (默认 Kill, fail-closed 符合勒索高置信语义)。
// ============================================================================
static VOID RansomExp_RegisterSuspend(ULONG Pid) {
    if (Pid == 0 || Pid == 4) return;
    KIRQL irql;
    KeAcquireSpinLock(&g_RansomSuspendLock, &irql);
    for (ULONG i = 0; i < RANSOM_SUSPEND_TRACK_MAX; i++) {
        if (g_RansomSuspendTrack[i].InUse && g_RansomSuspendTrack[i].Pid == Pid) {
            // 已在表内 (重复命中) → 更新时间戳即可
            KeQuerySystemTime(&g_RansomSuspendTrack[i].SuspendTime);
            KeReleaseSpinLock(&g_RansomSuspendLock, irql);
            return;
        }
    }
    for (ULONG i = 0; i < RANSOM_SUSPEND_TRACK_MAX; i++) {
        if (!g_RansomSuspendTrack[i].InUse) {
            g_RansomSuspendTrack[i].InUse = TRUE;
            g_RansomSuspendTrack[i].Pid = Pid;
            KeQuerySystemTime(&g_RansomSuspendTrack[i].SuspendTime);
            KeReleaseSpinLock(&g_RansomSuspendLock, irql);
            return;
        }
    }
    KeReleaseSpinLock(&g_RansomSuspendLock, irql);
    // 表满: 无法跟踪 → 保守立即按超时默认处理
    ZETA_WARN("RansomSuspend: track table full, applying default policy for PID=%lu\n", Pid);
    if (RANSOM_SUSPEND_TIMEOUT_KILL) {
        KillSuspendedProcess(Pid);
    } else {
        ResumeSuspendedProcess(Pid);
    }
}

static VOID RansomExp_UnregisterSuspend(ULONG Pid) {
    KIRQL irql;
    KeAcquireSpinLock(&g_RansomSuspendLock, &irql);
    for (ULONG i = 0; i < RANSOM_SUSPEND_TRACK_MAX; i++) {
        if (g_RansomSuspendTrack[i].InUse && g_RansomSuspendTrack[i].Pid == Pid) {
            g_RansomSuspendTrack[i].InUse = FALSE;
            g_RansomSuspendTrack[i].Pid = 0;
            KeReleaseSpinLock(&g_RansomSuspendLock, irql);
            return;
        }
    }
    KeReleaseSpinLock(&g_RansomSuspendLock, irql);
}

VOID RansomExp_CheckSuspendTimeouts() {
    KIRQL irql;
    KeAcquireSpinLock(&g_RansomSuspendLock, &irql);
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    ULONG timeoutPids[RANSOM_SUSPEND_TRACK_MAX];
    ULONG n = 0;
    LONGLONG timeout100ns = (LONGLONG)RANSOM_SUSPEND_TIMEOUT_MS * 10000LL;
    for (ULONG i = 0; i < RANSOM_SUSPEND_TRACK_MAX; i++) {
        if (g_RansomSuspendTrack[i].InUse &&
            (now.QuadPart - g_RansomSuspendTrack[i].SuspendTime.QuadPart) >= timeout100ns) {
            timeoutPids[n++] = g_RansomSuspendTrack[i].Pid;
            g_RansomSuspendTrack[i].InUse = FALSE;
            g_RansomSuspendTrack[i].Pid = 0;
        }
    }
    KeReleaseSpinLock(&g_RansomSuspendLock, irql);

    // 释放锁后执行默认策略 (Kill/Resume 需 PASSIVE_LEVEL)
    for (ULONG i = 0; i < n; i++) {
        ZETA_WARN("RansomSuspend: PID=%lu decision TIMEOUT (%lu ms), applying default policy (%ls)\n",
            timeoutPids[i], (ULONG)RANSOM_SUSPEND_TIMEOUT_MS,
            RANSOM_SUSPEND_TIMEOUT_KILL ? L"KILL" : L"RESUME");
        DriverLog(timeoutPids[i],
            RANSOM_SUSPEND_TIMEOUT_KILL
                ? L"RansomSuspend: 用户决策超时, 默认终止挂起进程"
                : L"RansomSuspend: 用户决策超时, 默认恢复进程(放行)");
        if (RANSOM_SUSPEND_TIMEOUT_KILL) {
            KillSuspendedProcess(timeoutPids[i]);
        } else {
            ResumeSuspendedProcess(timeoutPids[i]);
        }
    }
}

VOID RansomExp_CleanupSuspendTrack() {
    KIRQL irql;
    KeAcquireSpinLock(&g_RansomSuspendLock, &irql);
    ULONG pendingPids[RANSOM_SUSPEND_TRACK_MAX];
    ULONG n = 0;
    for (ULONG i = 0; i < RANSOM_SUSPEND_TRACK_MAX; i++) {
        if (g_RansomSuspendTrack[i].InUse) {
            pendingPids[n++] = g_RansomSuspendTrack[i].Pid;
            g_RansomSuspendTrack[i].InUse = FALSE;
            g_RansomSuspendTrack[i].Pid = 0;
        }
    }
    KeReleaseSpinLock(&g_RansomSuspendLock, irql);

    // 卸载时驱动即将消失: 挂起进程不能再等用户态 → 执行默认策略
    for (ULONG i = 0; i < n; i++) {
        ZETA_WARN("RansomSuspend: unload cleanup, applying default policy for PID=%lu\n", pendingPids[i]);
        DriverLog(pendingPids[i], L"RansomSuspend: 驱动卸载, 清理挂起进程");
        if (RANSOM_SUSPEND_TIMEOUT_KILL) {
            KillSuspendedProcess(pendingPids[i]);
        } else {
            ResumeSuspendedProcess(pendingPids[i]);
        }
    }
}

// ============================================================================
// P1-2: 勒索软件挂起后用户态决策辅助函数
// ============================================================================

// ResumeSuspendedProcess - 恢复被 PsSuspendProcess 挂起的进程
// 用户态收到 ZETA_MSG_RANSOM_HEADER_ALERT 后，若用户选择"允许"，
// 发送 ZETA_CMD_ALLOW_OP(4) 命令，driver 调用此函数恢复进程
NTSTATUS ResumeSuspendedProcess(ULONG ProcessId) {
    if (ProcessId == 0 || ProcessId == 4) return STATUS_INVALID_PARAMETER;

    PEPROCESS Process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &Process);
    if (!NT_SUCCESS(status) || !Process) {
        ZETA_WARN("ResumeSuspendedProcess: PsLookupProcessByProcessId FAILED (0x%08X) for PID=%lu\n",
            status, ProcessId);
        return status;
    }

    // Safety: never resume ZETA's own process
    if (ProcessId == GlobalData.ZetaPid) {
        ZETA_WARN("ResumeSuspendedProcess: refusing to resume ZETA PID=%lu\n", ProcessId);
        ObDereferenceObject(Process);
        return STATUS_ACCESS_DENIED;
    }

    status = PsResumeProcess(Process);
    if (NT_SUCCESS(status)) {
        ZETA_INFO("ResumeSuspendedProcess: PID=%lu resumed (user allowed)\n", ProcessId);
        DriverLog(ProcessId, L"RansomExp: Process RESUMED by user decision");
        // M1-5: 用户已决策 → 从超时跟踪表移除
        RansomExp_UnregisterSuspend(ProcessId);
    } else {
        ZETA_WARN("ResumeSuspendedProcess: PsResumeProcess FAILED (0x%08X) for PID=%lu\n",
            status, ProcessId);
    }

    ObDereferenceObject(Process);
    return status;
}

// KillSuspendedProcess - 终止被挂起的勒索进程
// 用户态收到 ZETA_MSG_RANSOM_HEADER_ALERT 后，若用户选择"阻止"，
// 发送 ZETA_CMD_DENY_OP(5) 命令，driver 调用此函数终止进程
NTSTATUS KillSuspendedProcess(ULONG ProcessId) {
    if (ProcessId == 0 || ProcessId == 4) return STATUS_INVALID_PARAMETER;

    // Safety: never kill ZETA's own process
    if (ProcessId == GlobalData.ZetaPid) {
        ZETA_WARN("KillSuspendedProcess: refusing to kill ZETA PID=%lu\n", ProcessId);
        return STATUS_ACCESS_DENIED;
    }

    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    CLIENT_ID cid;
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)ProcessId;
    cid.UniqueThread = NULL;

    NTSTATUS status = ZwOpenProcess(&hProcess,
        PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION,
        &oa, &cid);

    if (!NT_SUCCESS(status)) {
        ZETA_WARN("KillSuspendedProcess: ZwOpenProcess FAILED (0x%08X) for PID=%lu\n",
            status, ProcessId);
        return status;
    }

    // Terminate with ACCESS_VIOLATION (0xC0000005) to look like a crash
    status = ZwTerminateProcess(hProcess, STATUS_ACCESS_VIOLATION);
    ZwClose(hProcess);

    if (NT_SUCCESS(status)) {
        ZETA_INFO("KillSuspendedProcess: PID=%lu TERMINATED (user blocked)\n", ProcessId);
        DriverLog(ProcessId, L"RansomExp: Process TERMINATED by user decision");
        // M1-5: 用户已决策 → 从超时跟踪表移除
        RansomExp_UnregisterSuspend(ProcessId);
    } else {
        ZETA_WARN("KillSuspendedProcess: ZwTerminateProcess FAILED (0x%08X) for PID=%lu\n",
            status, ProcessId);
    }

    return status;
}

// ============================================================================
// P1-状态机/勒索重定向: 把勒索写入数据写到隔离目录副本 (原文件保留)
//
// 原理: 勒索写命中时, 不覆盖原文件, 而是把本次写入的数据写到
//       \SystemRoot\ZETA_Quarantine\ 下的副本文件。勒索软件"以为"写成功
//       (IRP 完成返回成功), 实际原文件完好, 后续可 SystemRepair 恢复。
//
// 返回: STATUS_SUCCESS 表示重定向成功 (调用方完成 IRP 返回成功)
//       非 SUCCESS 表示重定向失败 (调用方应按原逻辑处理)
// ============================================================================

// ── P0-1/P0-2: 备份区(勒索恢复)完整性 ─────────────────────────
BOOLEAN ZetaVault_IsPath(PUNICODE_STRING FileName) {
    if (!FileName || !FileName->Buffer) return FALSE;
    return WildcardMatch(L"*\\ZETA_DocBackup\\*", FileName->Buffer, FileName->Length) ||
           WildcardMatch(L"*\\ZETA_DocBackup", FileName->Buffer, FileName->Length) ||
           WildcardMatch(L"*\\ZETA_Quarantine\\*", FileName->Buffer, FileName->Length) ||
           WildcardMatch(L"*\\ZETA_Quarantine", FileName->Buffer, FileName->Length);
}

BOOLEAN ZetaVault_IsAllowedWriter(HANDLE Pid) {
    ULONG pid = (ULONG)(ULONG_PTR)Pid;
    if (pid == 4) return TRUE;                                        // SYSTEM
    if (GlobalData.ZetaPid != 0 && pid == GlobalData.ZetaPid) return TRUE; // ZETA.exe (UI 恢复/删除)
    return FALSE;
}

// 在 <VaultDir>\.ZETA_index 追加一行(UTF-16LE): <副本全路径>\t<pid>\t<原文件全路径>
NTSTATUS ZetaVault_AppendIndex(PCWSTR VaultDir, PUNICODE_STRING DestFile,
                               PUNICODE_STRING SrcPath, ULONG Pid) {
    if (!VaultDir || !DestFile || !DestFile->Buffer ||
        !SrcPath || !SrcPath->Buffer) {
        return STATUS_INVALID_PARAMETER;
    }
    ULONG destChars = DestFile->Length / sizeof(WCHAR);
    ULONG srcChars = SrcPath->Length / sizeof(WCHAR);
    if (srcChars > 4096) srcChars = 4096;   // 超长路径截断, 防池/栈溢出

    SIZE_T need = (SIZE_T)destChars + srcChars + 32;
    PWCHAR line = (PWCHAR)ZetaAllocate((ULONG)(need * sizeof(WCHAR)));
    if (!line) return STATUS_INSUFFICIENT_RESOURCES;
    SIZE_T p = 0;
    RtlCopyMemory(&line[p], DestFile->Buffer, destChars * sizeof(WCHAR));
    p += destChars;
    line[p++] = L'\t';
    WCHAR pidBuf[16];
    if (!NT_SUCCESS(RtlStringCbPrintfW(pidBuf, sizeof(pidBuf), L"%lu", Pid))) {
        ExFreePoolWithTag(line, ZETA_POOL_TAG);
        return STATUS_UNSUCCESSFUL;
    }
    RtlCopyMemory(&line[p], pidBuf, (wcslen(pidBuf) + 1) * sizeof(WCHAR));
    p += wcslen(pidBuf);
    p--;   // 去掉 NUL (已留位), 下面接 \t
    line[p++] = L'\t';
    RtlCopyMemory(&line[p], SrcPath->Buffer, srcChars * sizeof(WCHAR));
    p += srcChars;
    line[p++] = L'\r';
    line[p++] = L'\n';
    // UTF-8 规范化输出: 元数据统一 UTF-8 (UI / zeta_meta 读取时兼容旧 UTF-16LE)
    ULONG wideChars = (ULONG)p;
    ULONG utf8Cap = wideChars * 3 + 16;
    PCHAR utf8Buf = (PCHAR)ZetaAllocate(utf8Cap);
    if (!utf8Buf) {
        ExFreePoolWithTag(line, ZETA_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ULONG utf8Len = 0;
    NTSTATUS status = RtlUnicodeToUTF8N(utf8Buf, utf8Cap, &utf8Len,
                                        line, wideChars * sizeof(WCHAR));
    ExFreePoolWithTag(line, ZETA_POOL_TAG);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(utf8Buf, ZETA_POOL_TAG);
        return status;
    }

    WCHAR indexPath[320];
    status = RtlStringCbPrintfW(indexPath, sizeof(indexPath),
        L"%ls\\.ZETA_index", VaultDir);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(utf8Buf, ZETA_POOL_TAG);
        return status;
    }
    UNICODE_STRING idxUs;
    RtlInitUnicodeString(&idxUs, indexPath);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &idxUs, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE hIdx = NULL;
    IO_STATUS_BLOCK iosb;
    status = ZwCreateFile(&hIdx, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(utf8Buf, ZETA_POOL_TAG);
        return status;
    }
    status = ZwWriteFile(hIdx, NULL, NULL, NULL, &iosb, utf8Buf, utf8Len, NULL, NULL);
    ZwClose(hIdx);
    ExFreePoolWithTag(utf8Buf, ZETA_POOL_TAG);
    return status;
}

NTSTATUS RansomExp_RedirectWrite(PUNICODE_STRING FileName, ULONG Pid,
                                 PVOID WriteBuffer, ULONG WriteLength) {
    if (!FileName || !FileName->Buffer || WriteLength == 0 || !WriteBuffer) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return STATUS_UNSUCCESSFUL;

    // 构造隔离路径: \SystemRoot\ZETA_Quarantine\ransom_<pid>_<tick>_<文件名>
    WCHAR quarantineDir[] = L"\\SystemRoot\\ZETA_Quarantine\\";
    WCHAR destPath[512];
    LARGE_INTEGER tickCount;
    KeQueryTickCount(&tickCount);
    RtlStringCbPrintfW(destPath, sizeof(destPath), L"%lsransom_%lu_%llu_",
        quarantineDir, Pid, (ULONGLONG)tickCount.QuadPart);

    // 追加原文件名 (去掉路径前缀, 只取最后一段)
    PCWSTR src = FileName->Buffer;
    ULONG srcLen = FileName->Length / sizeof(WCHAR);
    // 取最后一个反斜杠之后的部分
    ULONG nameStart = 0;
    for (ULONG i = srcLen; i > 0; i--) {
        if (src[i-1] == L'\\') { nameStart = i; break; }
    }
    // 防溢出
    size_t destLen = wcslen(destPath);
    size_t remain = (sizeof(destPath) / sizeof(WCHAR)) - destLen - 1;
    ULONG copyLen = (srcLen - nameStart < remain) ? (srcLen - nameStart) : (ULONG)remain;
    if (copyLen > 0) {
        RtlCopyMemory(destPath + destLen, src + nameStart, copyLen * sizeof(WCHAR));
        destPath[destLen + copyLen] = L'\0';
    }

    UNICODE_STRING destUs;
    RtlInitUnicodeString(&destUs, destPath);

    // 打开/创建隔离副本 (始终新建, 追加写入模式)
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &destUs, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status = ZwCreateFile(&hFile,
        GENERIC_WRITE | SYNCHRONIZE,
        &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ, FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status)) {
        ZETA_WARN("RansomExp_RedirectWrite: ZwCreateFile FAILED (0x%08X) %wZ\n", status, &destUs);
        return status;
    }

    // 写入副本数据
    status = ZwWriteFile(hFile, NULL, NULL, NULL, &iosb,
        WriteBuffer, WriteLength, NULL, NULL);
    ZwClose(hFile);

    if (NT_SUCCESS(status)) {
        ZETA_INFO("RansomExp_RedirectWrite: PID=%lu write redirected to %wZ (len=%lu)\n",
            Pid, &destUs, WriteLength);
        // P0-2: 记录恢复索引, 供 UI "勒索恢复"页按原路径定位
        ZetaVault_AppendIndex(L"\\SystemRoot\\ZETA_Quarantine", &destUs, FileName, Pid);
        return STATUS_SUCCESS;
    }
    ZETA_WARN("RansomExp_RedirectWrite: ZwWriteFile FAILED (0x%08X)\n", status);
    return status;
}

// ============================================================================
// P0: 文档写前备份 (暴力方案)
// 思路: 不判断"是不是勒索" —— 命中受保护扩展名的覆盖写/替换, 一律先把
//       原文件完整复制到备份区。宁可错杀不可放过: 误判代价仅多一份副本,
//       漏判风险为零。EXE/DLL/系统文件不备份(勒索它们无损失)。
// ============================================================================

// ── 受保护扩展名: 用户文档 / 图片 / 常用数据文件 (大小写不敏感) ──
static const WCHAR* g_DocBackupExts[] = {
    L"doc", L"docx", L"xls", L"xlsx", L"ppt", L"pptx",
    L"pdf", L"txt", L"rtf", L"md", L"odt", L"csv",
    L"jpg", L"jpeg", L"png", L"gif", L"bmp", L"tiff", L"webp", L"heic",
    L"psd", L"ai",
    L"db", L"sqlite",
    NULL
};

// 忽略大小写扩展名匹配 (内核无 wcsicmp, 手写; 表项均为小写)
static BOOLEAN DocBackup_ExtMatch(const WCHAR* a, const WCHAR* b) {
    ULONG i = 0;
    while (a[i] != L'\0' && b[i] != L'\0') {
        WCHAR ca = a[i], cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca = (WCHAR)(ca + 32);
        if (cb >= L'A' && cb <= L'Z') cb = (WCHAR)(cb + 32);
        if (ca != cb) return FALSE;
        i++;
    }
    return (a[i] == L'\0' && b[i] == L'\0');
}

static BOOLEAN DocBackup_IsWatchedExtension(PUNICODE_STRING FileName) {
    if (!FileName || !FileName->Buffer || FileName->Length < 4) return FALSE;

    // 定位最后一个 '.' 之后的后缀
    ULONG nChars = FileName->Length / sizeof(WCHAR);
    PWCHAR buf = FileName->Buffer;
    ULONG dot = 0;
    for (ULONG i = nChars; i > 0; i--) {
        if (buf[i - 1] == L'.') { dot = i; break; }   // dot 指向 '.' 之后
    }
    if (dot == 0) return FALSE;                       // 无扩展名

    ULONG extLen = nChars - dot;
    if (extLen == 0 || extLen > 8) return FALSE;

    // 转小写并终止
    WCHAR ext[12];
    if (extLen >= (sizeof(ext) / sizeof(WCHAR))) return FALSE;
    for (ULONG i = 0; i < extLen; i++) {
        WCHAR c = buf[dot + i];
        ext[i] = (c >= L'A' && c <= L'Z') ? (WCHAR)(c + 32) : c;
    }
    ext[extLen] = L'\0';

    // P0-规则化: 优先查 Rules_FileProtect.json 的 Rule_File_DocBackup_Extensions
    // (条目为 ".docx" 样式); 文件未加载(g_DocBackupExtList 空)时回退内置默认表。
    if (g_DocBackupExtList) {
        BOOLEAN hit = FALSE;
        KeEnterCriticalRegion();
        ExAcquireResourceSharedLite(&Lock_File, TRUE);
        PRULE_NODE node = g_DocBackupExtList;
        while (node) {
            if (node->Pattern.Buffer && node->Pattern.Buffer[0] == L'.') {
                PCWSTR pat = node->Pattern.Buffer + 1;   // 跳过 '.'
                ULONG i = 0;
                BOOLEAN eq = TRUE;
                while (pat[i] && ext[i]) {
                    WCHAR a = pat[i], b = ext[i];
                    if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);
                    if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);
                    if (a != b) { eq = FALSE; break; }
                    i++;
                }
                if (eq && !pat[i] && !ext[i]) { hit = TRUE; break; }
            }
            node = node->Next;
        }
        ExReleaseResourceLite(&Lock_File);
        KeLeaveCriticalRegion();
        return hit;
    }

    for (int i = 0; g_DocBackupExts[i]; i++) {
        if (DocBackup_ExtMatch(ext, g_DocBackupExts[i])) return TRUE;
    }
    return FALSE;
}

// ── 排除目录: 临时/缓存/系统目录不备份 (无价值且高频) ──
static BOOLEAN DocBackup_IsExcludedLocation(PUNICODE_STRING FileName) {
    if (!FileName || !FileName->Buffer) return FALSE;
    // 备份区自身 / Windows / Program Files / 临时目录 / 浏览器缓存
    if (WildcardMatch(L"*\\ZETA_DocBackup\\*", FileName->Buffer, FileName->Length)) return TRUE;
    if (WildcardMatch(L"*\\ZETA_Quarantine\\*", FileName->Buffer, FileName->Length)) return TRUE;
    if (WildcardMatch(L"*\\Windows\\*", FileName->Buffer, FileName->Length)) return TRUE;
    if (WildcardMatch(L"*\\Program Files*\\*", FileName->Buffer, FileName->Length)) return TRUE;
    if (WildcardMatch(L"*\\Temp\\*", FileName->Buffer, FileName->Length)) return TRUE;
    if (WildcardMatch(L"*\\AppData\\Local\\Temp\\*", FileName->Buffer, FileName->Length)) return TRUE;
    return FALSE;
}

// ── per-FileObject 去重: 同一句柄会话只备份一次 (后续分块写不再重复全量复制) ──
#define DOC_BACKUP_HANDLE_MAX 128
static PFILE_OBJECT g_DocBackupHandles[DOC_BACKUP_HANDLE_MAX];
static ULONG g_DocBackupHandleCount = 0;
static KSPIN_LOCK g_DocBackupHandleLock = {0};

static BOOLEAN DocBackup_MarkFileObject(PFILE_OBJECT FileObject) {
    if (!FileObject) return FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DocBackupHandleLock, &oldIrql);
    for (ULONG i = 0; i < g_DocBackupHandleCount; i++) {
        if (g_DocBackupHandles[i] == FileObject) {
            KeReleaseSpinLock(&g_DocBackupHandleLock, oldIrql);
            return FALSE;   // 已备份过
        }
    }
    // 表满则整体重置 (已关闭句柄自然不再命中, 可接受偶尔重复备份)
    if (g_DocBackupHandleCount >= DOC_BACKUP_HANDLE_MAX) {
        RtlZeroMemory(g_DocBackupHandles, sizeof(g_DocBackupHandles));
        g_DocBackupHandleCount = 0;
    }
    g_DocBackupHandles[g_DocBackupHandleCount++] = FileObject;
    KeReleaseSpinLock(&g_DocBackupHandleLock, oldIrql);
    return TRUE;            // 首次, 需备份
}

BOOLEAN DocBackup_IsEnabled(void) {
    return g_DocBackupEnabled;
}

NTSTATUS DocBackup_SetEnabled(BOOLEAN Enabled) {
    g_DocBackupEnabled = Enabled;
    // 关闭时清理去重表, 下次开启重新开始记录
    if (!Enabled) {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_DocBackupHandleLock, &oldIrql);
        RtlZeroMemory(g_DocBackupHandles, sizeof(g_DocBackupHandles));
        g_DocBackupHandleCount = 0;
        KeReleaseSpinLock(&g_DocBackupHandleLock, oldIrql);
    }
    ZETA_INFO("DocBackup enabled=%u\n", g_DocBackupEnabled);
    return STATUS_SUCCESS;
}

// 把 FileName 指向的源文件完整复制到 \SystemRoot\ZETA_DocBackup\<pid>_<tick>_<原名>
// 调用方必须 PASSIVE_LEVEL
static NTSTATUS DocBackup_CopyFileToVault(PUNICODE_STRING FileName, ULONG Pid) {
    if (!FileName || !FileName->Buffer || FileName->Length == 0) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return STATUS_UNSUCCESSFUL;

    OBJECT_ATTRIBUTES srcOa;
    IO_STATUS_BLOCK iosb;
    HANDLE hSrc = NULL;
    NTSTATUS status;

    // 1) 打开源 (只读, 允许共享读写删除 — 别挡正常写入)
    InitializeObjectAttributes(&srcOa, FileName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenFile(&hSrc, GENERIC_READ | SYNCHRONIZE, &srcOa, &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) return status;

    // 2) 查文件大小
    FILE_STANDARD_INFORMATION stdInfo;
    status = ZwQueryInformationFile(hSrc, &iosb, &stdInfo, sizeof(stdInfo),
        FileStandardInformation);
    if (!NT_SUCCESS(status)) { ZwClose(hSrc); return status; }
    if (stdInfo.EndOfFile.QuadPart <= 0) { ZwClose(hSrc); return status; }
    if (stdInfo.EndOfFile.QuadPart > (LONGLONG)(64 * 1024 * 1024)) {
        // >64MB 大文件跳过 (文档/图片几乎不可能; 避免复制卡顿), 留待 v2 块级 COW
        ZwClose(hSrc);
        return STATUS_SUCCESS;
    }

    // 3) 目标路径: \SystemRoot\ZETA_DocBackup\doc_<pid>_<tick>_<原名>
    WCHAR backupDir[] = L"\\SystemRoot\\ZETA_DocBackup\\";
    WCHAR destPath[512];
    LARGE_INTEGER tick;
    KeQueryTickCount(&tick);
    RtlStringCbPrintfW(destPath, sizeof(destPath), L"%lsdoc_%lu_%llu_",
        backupDir, Pid, (ULONGLONG)tick.QuadPart);

    // 追加原名最后一段
    PCWSTR src = FileName->Buffer;
    ULONG srcLen = FileName->Length / sizeof(WCHAR);
    ULONG nameStart = 0;
    for (ULONG i = srcLen; i > 0; i--) {
        if (src[i-1] == L'\\') { nameStart = i; break; }
    }
    size_t destLen = wcslen(destPath);
    size_t remain = (sizeof(destPath) / sizeof(WCHAR)) - destLen - 1;
    ULONG copyLen = (srcLen - nameStart < remain) ? (srcLen - nameStart) : (ULONG)remain;
    if (copyLen > 0) {
        RtlCopyMemory(destPath + destLen, src + nameStart, copyLen * sizeof(WCHAR));
        destPath[destLen + copyLen] = L'\0';
    }

    UNICODE_STRING destUs;
    RtlInitUnicodeString(&destUs, destPath);
    OBJECT_ATTRIBUTES destOa;
    InitializeObjectAttributes(&destOa, &destUs,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    // 目录不存在则先创建 (ZETA_Quarantine 目录由重定向路径预建; 此处独立创建)
    {
        // 建目录: 打开父路径不存在会失败, 因此先尝试创建目录 (失败可忽略: 若已存在或不可创建, 后续 ZwCreateFile 会报错)
        UNICODE_STRING dirUs;
        RtlInitUnicodeString(&dirUs, L"\\SystemRoot\\ZETA_DocBackup");
        OBJECT_ATTRIBUTES dirOa;
        InitializeObjectAttributes(&dirOa, &dirUs, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        HANDLE hDir = NULL;
        status = ZwCreateFile(&hDir, GENERIC_WRITE | SYNCHRONIZE, &dirOa, &iosb, NULL,
            FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN_IF, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (NT_SUCCESS(status)) ZwClose(hDir);
    }

    // 4) 写入副本
    HANDLE hDest = NULL;
    status = ZwCreateFile(&hDest, GENERIC_WRITE | SYNCHRONIZE, &destOa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
        FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status)) { ZwClose(hSrc); return status; }

    // 5) 分块复制
    const ULONG block = 64 * 1024;
    PUCHAR buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, block, ZETA_POOL_TAG);
    if (!buffer) { ZwClose(hDest); ZwClose(hSrc); return STATUS_INSUFFICIENT_RESOURCES; }

    LARGE_INTEGER byteOffset;
    byteOffset.QuadPart = 0;
    ULONGLONG remaining = (ULONGLONG)stdInfo.EndOfFile.QuadPart;
    while (remaining > 0) {
        ULONG want = (remaining > block) ? block : (ULONG)remaining;
        ULONG bytesRead = 0;
        status = ZwReadFile(hSrc, NULL, NULL, NULL, &iosb, buffer, want, &byteOffset, NULL);
        if (!NT_SUCCESS(status) || iosb.Information == 0) break;
        bytesRead = (ULONG)iosb.Information;
        status = ZwWriteFile(hDest, NULL, NULL, NULL, &iosb, buffer, bytesRead, &byteOffset, NULL);
        if (!NT_SUCCESS(status)) break;
        byteOffset.QuadPart += bytesRead;
        remaining -= bytesRead;
    }

    ExFreePoolWithTag(buffer, ZETA_POOL_TAG);
    ZwClose(hDest);
    ZwClose(hSrc);

    if (NT_SUCCESS(status) || remaining == 0) {
        ZETA_INFO("DocBackup: PID=%lu backed up %wZ -> %wZ\n", Pid, FileName, &destUs);
        // P0-2: 记录恢复索引, 供 UI "勒索恢复"页按原路径定位
        ZetaVault_AppendIndex(L"\\SystemRoot\\ZETA_DocBackup", &destUs, FileName, Pid);
        return STATUS_SUCCESS;
    }
    return status;
}

// PreWrite 入口: 命中受保护扩展名 + 非可信目录 + 同句柄首次 → 复制旧文件
BOOLEAN DocBackup_OnPreWrite(PUNICODE_STRING FileName, ULONG Pid, PFILE_OBJECT FileObject) {
    if (!g_DocBackupEnabled) return FALSE;
    if (!FileName || !FileName->Buffer) return FALSE;
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FALSE;
    if (!DocBackup_IsWatchedExtension(FileName)) return FALSE;
    if (DocBackup_IsExcludedLocation(FileName)) return FALSE;
    if (!DocBackup_MarkFileObject(FileObject)) return FALSE;   // 同句柄已备份过

    NTSTATUS status = DocBackup_CopyFileToVault(FileName, Pid);
    return NT_SUCCESS(status);
}

// PreSetInfo rename 入口: 目标文件替换 (ReplaceIfExists) 且命中受保护扩展名 → 备份目标
BOOLEAN DocBackup_OnRenameReplace(PUNICODE_STRING FileName, PVOID InfoBuffer,
    ULONG InfoBufferLength, ULONG Pid) {
    if (!g_DocBackupEnabled) return FALSE;
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FALSE;

    BOOLEAN backedUp = FALSE;
    __try {
        // 兼容 FileRenameInformation (ReplaceIfExists) 与 FileRenameInformationEx (Flags)
        // v1: 统一按标准布局解析 (ReplaceIfExists 位于首字节; Ex 的 Flags 低位同义)
        if (!InfoBuffer || InfoBufferLength < (ULONG)FIELD_OFFSET(ZETA_FILE_RENAME_INFO, FileName[0])) return FALSE;

        ZETA_FILE_RENAME_INFO* ri = (ZETA_FILE_RENAME_INFO*)InfoBuffer;
        BOOLEAN replace = ri->ReplaceIfExists;
        ULONG nameBytes = ri->FileNameLength;
        if (!replace || nameBytes == 0) return FALSE;
        if ((ULONG)FIELD_OFFSET(ZETA_FILE_RENAME_INFO, FileName[0]) + nameBytes > InfoBufferLength) return FALSE;
        if (nameBytes > 8 * 1024) return FALSE;

        // 目标名 (可能是完整路径或相对名)。完整路径则直接用; 相对名由调用方带源目录拼接。
        // 此处 v1 支持: 目标名以盘符/UNC 开头(完整) → 直接判断; 相对名 → 认为同目录,
        // 用当前被 rename 的源路径所在目录拼接已在调用方完成(FileName 已是完整路径时)。
        // 判断依据: 只对受保护扩展名备份, 与被替换目标是否受保护一致。
        UNICODE_STRING targetName;
        targetName.Buffer = ri->FileName;
        targetName.Length = (USHORT)nameBytes;
        targetName.MaximumLength = (USHORT)nameBytes;

        // 用源路径判断扩展名与排除 (rename 目标扩展名一般与源语义接近; 被覆盖文件是关键)
        if (!DocBackup_IsWatchedExtension(&targetName)) return FALSE;
        if (DocBackup_IsExcludedLocation(FileName)) return FALSE;

        // 目标完整路径 = 源目录 + 目标名 (若目标是相对路径)
        // 简化: 直接备份"被覆盖的目标文件"—— 需要目标完整路径。
        // 若目标名为完整路径(含盘符或\\开头)直接用, 否则用源所在目录拼接。
        BOOLEAN targetIsFull = (targetName.Length >= 2 * sizeof(WCHAR)) &&
            (ri->FileName[0] == L'\\' ||
             (ri->FileName[1] == L':' && ri->FileName[0] != L'\0'));

        WCHAR fullTarget[520];
        UNICODE_STRING fullUs;
        RtlInitEmptyUnicodeString(&fullUs, fullTarget, (USHORT)sizeof(fullTarget));
        if (targetIsFull) {
            RtlCopyUnicodeString(&fullUs, &targetName);
        } else if (FileName && FileName->Buffer && FileName->Length > 0) {
            // 取源路径目录部分 (最后一个 '\' 之前) + '\' + 目标名
            ULONG srcLen = FileName->Length / sizeof(WCHAR);
            ULONG nameStart = 0;
            for (ULONG i = srcLen; i > 0; i--) {
                if (FileName->Buffer[i-1] == L'\\') { nameStart = i; break; }
            }
            if (nameStart == 0) return FALSE;   // 无目录信息
            // 复制目录部分(含尾'\') + 目标名
            SIZE_T dirBytes = nameStart * sizeof(WCHAR);
            SIZE_T totalBytes = dirBytes + nameBytes;
            if (totalBytes + sizeof(WCHAR) > sizeof(fullTarget)) return FALSE;
            RtlCopyMemory(fullTarget, FileName->Buffer, dirBytes);
            RtlCopyMemory(fullTarget + nameStart, ri->FileName, nameBytes);
            fullTarget[nameStart + nameBytes / sizeof(WCHAR)] = L'\0';
            RtlInitUnicodeString(&fullUs, fullTarget);
        } else {
            return FALSE;
        }

        // 备份被覆盖的目标文件
        if (fullUs.Buffer && fullUs.Length > 0) {
            NTSTATUS st = DocBackup_CopyFileToVault(&fullUs, Pid);
            backedUp = NT_SUCCESS(st);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        backedUp = FALSE;
    }
    return backedUp;
}

// ============================================================================
// IRP Audit Mode — Ring Buffer + FillAuditExt
// ============================================================================

ULONG g_AuditMode = AUDIT_MODE_OFF;
PAUDIT_RING_BUFFER g_AuditRing = NULL;

NTSTATUS InitializeAuditRing() {
    if (g_AuditRing) return STATUS_SUCCESS;
    g_AuditRing = (PAUDIT_RING_BUFFER)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(AUDIT_RING_BUFFER), 'zAUD');
    if (!g_AuditRing) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_AuditRing, sizeof(AUDIT_RING_BUFFER));
    DbgPrint("ZETA: Audit ring buffer allocated (%zu bytes, %d entries)\n",
        sizeof(AUDIT_RING_BUFFER), AUDIT_RING_SIZE);
    return STATUS_SUCCESS;
}

VOID UninitializeAuditRing() {
    if (g_AuditRing) {
        ExFreePool(g_AuditRing);
        g_AuditRing = NULL;
    }
}

VOID AuditRing_WriteEntry(ULONG Code, ULONG Pid, PWCHAR Path, USHORT PathLen,
    PZETA_IRP_CONTEXT Ictx, PZETA_IRP_AUDIT_EXT Ext)
{
    if (!g_AuditRing || g_AuditMode == AUDIT_MODE_OFF) return;

    LONG head = g_AuditRing->Head;
    LONG next = (head + 1) & AUDIT_RING_MASK;
    // If ring is full, advance tail (drop oldest entry)
    if (next == g_AuditRing->Tail) {
        g_AuditRing->Tail = (g_AuditRing->Tail + 1) & AUDIT_RING_MASK;
    }

    PAUDIT_RING_ENTRY e = &g_AuditRing->Entries[head];
    e->Timestamp = KeQuerySystemTime(NULL);
    e->ProcessId = Pid;
    e->MessageCode = Code;
    if (Ictx) e->Ictx = *Ictx;
    if (Ext) {
        e->Ext = *Ext;
    } else {
        RtlZeroMemory(&e->Ext, sizeof(ZETA_IRP_AUDIT_EXT));
        e->Ext.Size = sizeof(ZETA_IRP_AUDIT_EXT);
    }
    // Copy path (truncate if needed)
    USHORT copyLen = PathLen;
    USHORT maxLen = sizeof(e->Path) - sizeof(WCHAR);
    if (copyLen > maxLen) copyLen = maxLen;
    if (Path && copyLen > 0) {
        RtlCopyMemory(e->Path, Path, copyLen);
        e->Path[copyLen / sizeof(WCHAR)] = L'\0';
    } else {
        e->Path[0] = L'\0';
    }

    // Memory barrier before publishing
    InterlockedExchange(&g_AuditRing->Head, next);
}

VOID FillAuditExt_PreCreate(PFLT_CALLBACK_DATA Data, PZETA_IRP_AUDIT_EXT Ext) {
    RtlZeroMemory(Ext, sizeof(ZETA_IRP_AUDIT_EXT));
    Ext->Size = sizeof(ZETA_IRP_AUDIT_EXT);
    Ext->IrpMajor = IRP_MJ_CREATE;
    if (Data->Iopb->Parameters.Create.SecurityContext) {
        Ext->DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }
    Ext->CreateOptions = Data->Iopb->Parameters.Create.Options;
    Ext->ShareAccess = Data->Iopb->Parameters.Create.ShareAccess;
}

VOID FillAuditExt_PreWrite(PFLT_CALLBACK_DATA Data, PZETA_IRP_AUDIT_EXT Ext) {
    RtlZeroMemory(Ext, sizeof(ZETA_IRP_AUDIT_EXT));
    Ext->Size = sizeof(ZETA_IRP_AUDIT_EXT);
    Ext->IrpMajor = IRP_MJ_WRITE;
    Ext->WriteLength = Data->Iopb->Parameters.Write.Length;
    Ext->ByteOffset = Data->Iopb->Parameters.Write.ByteOffset.QuadPart;

    // Sample first 32 bytes of write buffer (audit mode only)
    if (g_AuditMode >= AUDIT_MODE_SAMPLING) {
        PVOID buf = NULL;
        PMDL mdl = Data->Iopb->Parameters.Write.MdlAddress;
        if (mdl) {
            buf = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
        } else {
            buf = Data->Iopb->Parameters.Write.WriteBuffer;
        }
        if (buf) {
            USHORT sampleLen = (Ext->WriteLength > 32) ? 32 : (USHORT)Ext->WriteLength;
            __try {
                RtlCopyMemory(Ext->WriteSample, buf, sampleLen);
                Ext->WriteSampleLen = sampleLen;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Ext->WriteSampleLen = 0;
            }
        }
    }
}

VOID FillAuditExt_PreSetInfo(PFLT_CALLBACK_DATA Data, PZETA_IRP_AUDIT_EXT Ext) {
    RtlZeroMemory(Ext, sizeof(ZETA_IRP_AUDIT_EXT));
    Ext->Size = sizeof(ZETA_IRP_AUDIT_EXT);
    Ext->IrpMajor = IRP_MJ_SET_INFORMATION;
    Ext->FileClass = (USHORT)Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
}

