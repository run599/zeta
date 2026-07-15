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

static BOOLEAN VerifyRulesFileIntegrity(PCHAR FileBuffer, ULONG FileLength) {
 if (!FileBuffer || FileLength == 0) return FALSE;
 UCHAR checksum[16] = {0};
 for (ULONG i = 0; i < FileLength; i++) checksum[(i % 16)] ^= FileBuffer[i];
 UCHAR expected[16] = {0};
 for (ULONG i = 0; i < 16; i++) expected[i] = checksum[i] ^ 0x5A;
 return RtlEqualMemory(checksum, expected, sizeof(checksum));
}

VOID InitializeRulesEngine() {
 ExInitializeResourceLite(&Lock_Registry);
 ExInitializeResourceLite(&Lock_Process);
 ExInitializeResourceLite(&Lock_File);
 KeInitializeSpinLock(&TrustCacheLock);
 RtlZeroMemory(TrustCache, sizeof(TrustCache));
 g_CacheInitialized = TRUE;
}

VOID UninitializeRulesEngine() {
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
                ExReleaseResourceLite(&Lock_File);
                KeLeaveCriticalRegion();

                DbgPrint("ZETA: ParseSingleRulesFile - rules loaded from %s\n", FileName);
                status = STATUS_SUCCESS;
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
 TrustCache[Hash].Process = Process;
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
static BOOLEAN IsSafeFileExtension(PCUNICODE_STRING FileName) {
 if (!FileName || !FileName->Buffer || FileName->Length < 2) return FALSE;

 // Find the last '.' in the file name to get the extension
 PWCHAR buf = FileName->Buffer;
 ULONG len = FileName->Length / sizeof(WCHAR);
 PWCHAR dot = NULL;
 for (ULONG i = len - 1; i > 0; i--) {
  if (buf[i] == L'.') {
   dot = &buf[i];
   break;
  }
  if (buf[i] == L'\\' || buf[i] == L'/') break;  // no dot in filename
 }
 if (!dot) return FALSE;

 // Compare extension against safe list (case-insensitive)
 if (RtlCompareMemory(dot, L".txt", 4) == 4) return TRUE;
 if (RtlCompareMemory(dot, L".json", 5) == 5) return TRUE;
 if (RtlCompareMemory(dot, L".xml", 4) == 4) return TRUE;
 if (RtlCompareMemory(dot, L".log", 4) == 4) return TRUE;
 if (RtlCompareMemory(dot, L".md", 3) == 3) return TRUE;
 if (RtlCompareMemory(dot, L".csv", 4) == 4) return TRUE;

 // Config files
 if (RtlCompareMemory(dot, L".cfg", 4) == 4) return TRUE;
 if (RtlCompareMemory(dot, L".ini", 4) == 4) return TRUE;
 if (RtlCompareMemory(dot, L".conf", 5) == 5) return TRUE;
 if (RtlCompareMemory(dot, L".cnf", 4) == 4) return TRUE;

 // YAML/TOML
 if (RtlCompareMemory(dot, L".yaml", 5) == 5) return TRUE;
 if (RtlCompareMemory(dot, L".yml", 4) == 4) return TRUE;
 if (RtlCompareMemory(dot, L".toml", 5) == 5) return TRUE;

 // Temp/cache
 if (RtlCompareMemory(dot, L".tmp", 4) == 4) return TRUE;
 if (RtlCompareMemory(dot, L".temp", 5) == 5) return TRUE;
 if (RtlCompareMemory(dot, L".dat", 4) == 4) return TRUE;
 if (RtlCompareMemory(dot, L".cache", 6) == 6) return TRUE;

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
 if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_UNSUCCESSFUL;

 if (!ExAcquireRundownProtection(&GlobalData.PortRundown)) {
 return STATUS_PORT_DISCONNECTED;
 }

 NTSTATUS status = STATUS_PORT_DISCONNECTED;

 if (GlobalData.ClientPort) {
 PZETA_MESSAGE msg = (PZETA_MESSAGE)ZetaAllocate(sizeof(ZETA_MESSAGE));
 if (msg) {
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
 ZetaFree(msg);
 ExReleaseRundownProtection(&GlobalData.PortRundown);
 return STATUS_ACCESS_VIOLATION;
 }
 }

 LARGE_INTEGER timeout;
 if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
 timeout.QuadPart = -(5 * 10000);
 }
 else {
 timeout.QuadPart = 0;
 }

 status = FltSendMessage(GlobalData.FilterHandle, &GlobalData.ClientPort, msg, sizeof(ZETA_MESSAGE), NULL, NULL, &timeout);

 ZetaFree(msg);
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

VOID InitializeLearningMode() {
    g_LearningModeActive = FALSE;  // Start with learning mode OFF (user enables manually)
    DbgPrint("ZETA: Learning mode initialized (user-controlled via UI)\n");
}
VOID UninitializeLearningMode() {
    g_LearningModeActive = FALSE;
    DbgPrint("ZETA: Learning mode uninitialized\n");
}

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
//   不可能匹配任何已知文件格式的魔数（ZIP = PK\x03\x04, PDF = %PDF, ...）。
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

    // LOG: record the termination target before acting
    DbgPrint("ZETA: RansomExp-FirstWrite: Terminating PID=%lu (file=%ws)\n",
        work->PidValue, work->FilePath);
    DriverLog(work->PidValue,
        L"RansomExp-FirstWrite: About to suspend/terminate process, file=%ws", work->FilePath);

    // Step 1: Suspend the process (freeze all threads)
    PsSuspendProcess(work->Process);

    DbgPrint("ZETA: RansomExp-FirstWrite: SUSPENDED PID=%lu (header mismatch, file=%ws)\n",
        work->PidValue, work->FilePath);
    DriverLog(work->PidValue,
        L"RansomExp-FirstWrite: SUSPENDED - ransomware header mismatch, file=%ws", work->FilePath);

    // Step 2: Wait briefly for the write buffer to drain (100ms)
    LARGE_INTEGER delay;
    delay.QuadPart = -100 * 10000LL;  // 100ms
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    // Step 3: Terminate the process
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    CLIENT_ID cid;
    cid.UniqueProcess = work->Pid;
    cid.UniqueThread = NULL;

    NTSTATUS status = ZwOpenProcess(&hProcess,
        PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION,
        &oa, &cid);

    if (NT_SUCCESS(status)) {
        // Terminate with ACCESS_VIOLATION (0xC0000005) to look like a crash
        ZwTerminateProcess(hProcess, STATUS_ACCESS_VIOLATION);
        ZwClose(hProcess);

        DbgPrint("ZETA: RansomExp-FirstWrite: TERMINATED PID=%lu (ransomware)\n",
            work->PidValue);
        DriverLog(work->PidValue,
            L"RansomExp-FirstWrite: TERMINATED - ransomware detected and killed");
    } else {
        DbgPrint("ZETA: RansomExp-FirstWrite: FAILED to open PID=%lu for termination (status=%08X)\n",
            work->PidValue, status);
    }

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
        Tracker->Process = Process;
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
                SendMessageToUser(5002, (ULONG)(ULONG_PTR)Pid, FileName->Buffer, FileName->Length);
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

        Tracker->Process = Process;
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

    // Reset all trackers when enabling
    if (Enabled) {
        RtlZeroMemory(g_RansomExpTrackers, sizeof(g_RansomExpTrackers));
        RtlZeroMemory(g_RansomFirstWriteTrackers, sizeof(g_RansomFirstWriteTrackers));
        DbgPrint("ZETA: RansomExperimental ENABLED (behavioral + first-write header check)\n");
    } else {
        DbgPrint("ZETA: RansomExperimental DISABLED\n");
    }
    return STATUS_SUCCESS;
}

