#pragma once
#include <fltKernel.h>
#include <ntddk.h> 
#include <ntdddisk.h> 
#include <ntddscsi.h> 
#include <ntstrsafe.h>
#include <ntimage.h>

constexpr auto ZETA_PORT_NAME = L"\\ZETA_Output_Pipe";
constexpr auto MAX_PATH_LEN = 1024;
constexpr auto ZETA_POOL_TAG = 'ATEZ';

// ============================================================
// Driver log levels (dynamic control)
// ============================================================
#define ZETA_LOG_ERROR    1   // Always printed
#define ZETA_LOG_WARN     2   // Warning level
#define ZETA_LOG_INFO     3   // Informational
#define ZETA_LOG_DEBUG    4   // Debug (verbose)
#define ZETA_LOG_VERBOSE  5   // Very verbose (production: disabled)

// Global log level (default: INFO, can be changed via registry or user command)
extern ULONG g_DriverLogLevel;
extern BOOLEAN g_IsUnloading;

// Log macros (conditionally print based on level)
#define ZETA_LOG(level, fmt, ...) \
    do { \
        if (g_DriverLogLevel >= level) { \
            DbgPrint("ZETA: " fmt, ##__VA_ARGS__); \
        } \
    } while(0)

// Convenience macros
#define ZETA_ERROR(fmt, ...)  ZETA_LOG(ZETA_LOG_ERROR, "[ERR] " fmt, ##__VA_ARGS__)
#define ZETA_WARN(fmt, ...)   ZETA_LOG(ZETA_LOG_WARN,  "[WARN] " fmt, ##__VA_ARGS__)
#define ZETA_INFO(fmt, ...)   ZETA_LOG(ZETA_LOG_INFO,  "[INFO] " fmt, ##__VA_ARGS__)
#define ZETA_DEBUG(fmt, ...)  ZETA_LOG(ZETA_LOG_DEBUG, "[DBG] " fmt, ##__VA_ARGS__)
#define ZETA_VERBOSE(fmt, ...) ZETA_LOG(ZETA_LOG_VERBOSE, "[VBS] " fmt, ##__VA_ARGS__)

// Production build: use KdPrint (only in _DEBUG)
#ifdef _DEBUG
#define ZETA_DBG(fmt, ...) DbgPrint("ZETA: " fmt, ##__VA_ARGS__)
#else
#define ZETA_DBG(fmt, ...) ((void)0)
#endif

// ============================================================

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE (0x0001)
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD (0x0002)
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION (0x0008)
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ (0x0010)
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE (0x0020)
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE (0x0040)
#endif
#ifndef PROCESS_CREATE_PROCESS
#define PROCESS_CREATE_PROCESS (0x0080)
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION (0x0200)
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION (0x0400)
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME (0x0800)
#endif
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
#endif
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA (0x0100)
#endif
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE (0x0001)
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME (0x0002)
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT (0x0010)
#endif
#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION (0x0020)
#endif
#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN (0x0080)
#endif
#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED 0x0000000000000040UI64
#endif

#ifndef FSCTL_MANAGE_BYPASS_IO
#define FSCTL_MANAGE_BYPASS_IO CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 188, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef enum _FS_BPIO_OPERATIONS {
 FS_BPIO_OP_ENABLE = 1,
 FS_BPIO_OP_DISABLE = 2,
 FS_BPIO_OP_QUERY = 3,
 FS_BPIO_OP_VOLUME_STACK_PAUSE = 4,
 FS_BPIO_OP_VOLUME_STACK_RESUME = 5,
 FS_BPIO_OP_STREAM_PAUSE = 6,
 FS_BPIO_OP_STREAM_RESUME = 7,
 FS_BPIO_OP_GET_INFO = 8
} FS_BPIO_OPERATIONS;

typedef struct _FS_BPIO_INPUT {
 FS_BPIO_OPERATIONS Operation;
 ULONG InFlags;
 ULONGLONG Reserved1;
 ULONGLONG Reserved2;
} FS_BPIO_INPUT, * PFS_BPIO_INPUT;

typedef struct _FS_BPIO_OUTPUT {
 FS_BPIO_OPERATIONS Operation;
 ULONG OutFlags;
 ULONGLONG Reserved1;
 ULONGLONG Reserved2;
 NTSTATUS Status;
} FS_BPIO_OUTPUT, * PFS_BPIO_OUTPUT;

#endif

#define ZETA_MSG_SILVERFOX_DETECTED    6001
#define ZETA_MSG_SILVERFOX_SIGNATURE   6002

// Lineage Tracker message codes (experimental feature)
#define ZETA_MSG_LINEAGE_ALERT         7001
#define ZETA_MSG_LINEAGE_FALLBACK      7004  // kernel lineage unavailable, switch to user-mode ETW

// Experimental Ransomware message codes
#define ZETA_MSG_RANSOM_HEADER_ALERT   7002
#define ZETA_MSG_RANSOM_EXPERIMENTAL   7003

// New ZETA_CMD codes for experimental feature toggles
#define ZETA_CMD_SET_LINEAGE_TRACKER   6   // user -> kernel: enable/disable lineage tracker
#define ZETA_CMD_SET_RANSOM_EXPERIMENTAL 7  // user -> kernel: enable/disable experimental ransomware
#define ZETA_CMD_SET_PROCESS_PROTECT   8   // user -> kernel: enable/disable process protection
#define ZETA_CMD_SET_SUSPEND_ENABLE    9   // user -> kernel: enable/disable suspend pending
#define ZETA_CMD_SET_FILE_PROTECT      10  // user -> kernel: enable/disable file protection
#define ZETA_CMD_SET_SYSTEM_PROTECT    11  // user -> kernel: enable/disable system protection
#define ZETA_CMD_SET_DRIVER_PROTECT    12  // user -> kernel: enable/disable driver protection
#define ZETA_CMD_SET_NETWORK_PROTECT   13  // user -> kernel: enable/disable network protection
#define ZETA_CMD_SET_LEARNING_MODE    14  // user -> kernel: enable/disable learning mode
#define ZETA_CMD_RELOAD_RULES      15  // user -> kernel: reload rules from disk

// Lineage Tracker: Process bloodline table (experimental)
#define LINEAGE_TABLE_SIZE      512
#define LINEAGE_MAX_DEPTH       16
#define LINEAGE_THROTTLE_MS     2000    // 2-second throttle per PID
#define LINEAGE_SCRIPT_NAME_LEN 32

// Script interpreter list for lineage tracking
// Only actual script hosts — NOT system hosts that are children of every process
static const PCWSTR g_ScriptInterpreterNames[] = {
    L"powershell.exe",
    L"pwsh.exe",
    L"cmd.exe",
    L"cscript.exe",
    L"wscript.exe",
    L"mshta.exe",
    L"wmic.exe",
    L"msiexec.exe",
    NULL
};

// ── Learning Whitelist ──────────────────────────────────────────
// During learning mode, process image names that trigger checks are
// recorded. After learning, these are auto-allowed — eliminating 
// false positives permanently across reboots via registry persistence.
#define LEARNING_WHITELIST_MAX   64
#define LEARNING_WHITELIST_NAME_LEN  64   // max chars for process image basename
extern BOOLEAN g_LearningModeActive;
VOID LearningWhitelist_Init();
VOID LearningWhitelist_Save();
BOOLEAN LearningWhitelist_IsProcessAllowed(HANDLE ProcessId);
VOID LearningWhitelist_LearnProcess(HANDLE ProcessId);

typedef struct _LINEAGE_NODE {
    ULONG       ProcessId;
    ULONG       ParentProcessId;
    WCHAR       ImageName[LINEAGE_SCRIPT_NAME_LEN];  // e.g. "powershell.exe"
    BOOLEAN     InUse;
    BOOLEAN     IsSuspiciousScript;  // is this process a known script interpreter?
    LARGE_INTEGER CreateTime;
} LINEAGE_NODE, * PLINEAGE_NODE;

extern LINEAGE_NODE g_LineageTable[LINEAGE_TABLE_SIZE];
extern KSPIN_LOCK g_LineageLock;
extern BOOLEAN g_LineageTrackerEnabled;
extern BOOLEAN g_ProcessNotifyExActive;

// Throttle entry: track last alert time per PID
#define LINEAGE_THROTTLE_SIZE 64
typedef struct _LINEAGE_THROTTLE {
    ULONG ProcessId;
    LARGE_INTEGER LastAlertTime;
} LINEAGE_THROTTLE, * PLINEAGE_THROTTLE;

// Experimental ransomware detection: file header magic numbers
#define RANSOM_HEADER_NUM_MAGICS 16
static const UCHAR g_KnownMagicNumbers[RANSOM_HEADER_NUM_MAGICS][4] = {
    {0x50, 0x4B, 0x03, 0x04},  // ZIP
    {0x52, 0x61, 0x72, 0x21},  // RAR
    {0x37, 0x7A, 0xBC, 0xAF},  // 7z
    {0x25, 0x50, 0x44, 0x46},  // PDF
    {0x89, 0x50, 0x4E, 0x47},  // PNG
    {0xFF, 0xD8, 0xFF, 0xE0},  // JPEG
    {0x4D, 0x5A, 0x90, 0x00},  // PE (MZ)
    {0xD0, 0xCF, 0x11, 0xE0},  // OLE/Compound
    {0x49, 0x44, 0x33, 0x03},  // MP3 ID3v2
    {0x66, 0x74, 0x79, 0x70},  // MP4/QuickTime (ftyp)
    {0x52, 0x49, 0x46, 0x46},  // AVI/WAV (RIFF)
    {0x47, 0x49, 0x46, 0x38},  // GIF
    {0x42, 0x4D, 0x00, 0x00},  // BMP
    {0x1F, 0x8B, 0x08, 0x00},  // GZIP
    {0x7B, 0x5C, 0x72, 0x74},  // RTF
    {0x00, 0x00, 0x00, 0x00}   // Terminator
};

extern BOOLEAN g_RansomExperimentalEnabled;

// First-write header integrity check (ransomware detection at offset 0)
#define RANSOM_EXP_FIRSTWRITE_MAX 64
typedef struct _RANSOM_FIRSTWRITE_TRACKER {
    PEPROCESS Process;
    LARGE_INTEGER ProcessCreateTime;
    BOOLEAN Investigated;   // TRUE: first write was checked, process is clean
    BOOLEAN Terminating;    // TRUE: process is being terminated (ransomware)
} RANSOM_FIRSTWRITE_TRACKER;
typedef RANSOM_FIRSTWRITE_TRACKER* PRANSOM_FIRSTWRITE_TRACKER;

// Three-tier Trust System
// TRUST_SYSTEM: Windows system / ZETA -> skip ALL checks
// TRUST_SIGNED: CA-signed / trusted paths -> monitor-only (EDR), no blocking
// TRUST_NONE:   Self-signed / unsigned -> full HIPS + EDR
typedef enum {
    TRUST_LEVEL_NONE   = 0,
    TRUST_LEVEL_SIGNED = 1,
    TRUST_LEVEL_SYSTEM = 2
} TRUST_LEVEL;

#define TRUST_WINDOW_SEC (30 * 60)       // 30 minutes
#define MAX_TRUST_WINDOW 128
#define TRUST_WINDOW_PATH_LEN 260        // Max process path length (WCHARs)

typedef struct _TRUST_WINDOW_ENTRY {
    LIST_ENTRY ListEntry;
    LARGE_INTEGER ExpiryTime;
    WCHAR ProcessPath[TRUST_WINDOW_PATH_LEN];  // Full NT device path, not PID
} TRUST_WINDOW_ENTRY, * PTRUST_WINDOW_ENTRY;

extern LIST_ENTRY g_TrustWindowList;
extern KSPIN_LOCK g_TrustWindowLock;

TRUST_LEVEL GetProcessTrustLevel(HANDLE ProcessId);
BOOLEAN IsProcessTrusted(HANDLE ProcessId);
VOID InitializeTrustWindow();
BOOLEAN IsInTrustWindow(PCWSTR ProcessPath);
VOID AddToTrustWindow(PCWSTR ProcessPath);
BOOLEAN GetProcessPathFromPid(ULONG ProcessId, PWCHAR OutPath, ULONG OutChars);
VOID RemoveFromTrustWindow(PCWSTR ProcessPath);
VOID CleanupTrustWindow();

BOOLEAN RansomExp_CheckFirstWrite(PFLT_CALLBACK_DATA Data,
    PUNICODE_STRING FileName, HANDLE Pid, PEPROCESS Process,
    PVOID WriteBuffer, ULONG WriteLength);
VOID RansomExp_ResetFirstWriteTrackers();

// Experimental ransomware tracker (enhanced with new parameters)
#define RANSOM_EXP_TIME_WINDOW_MS  3000   // 3-second window
#define RANSOM_EXP_COUNT_THRESHOLD 5
#define RANSOM_EXP_WEIGHT          2
#define RANSOM_EXP_HEADER_READ_BYTES 32

typedef struct _ZETA_MESSAGE {
    ULONG MessageCode;
    ULONG ProcessId;
    WCHAR Path[MAX_PATH_LEN];
} ZETA_MESSAGE, * PZETA_MESSAGE;

#define SILVERFOX_TIME_WINDOW_MS 10000
#define SILVERFOX_MAX_RELEASES 32

// Silver Fox detection: track PE file release patterns per process
// Tier 1 (driver): path-based fast detection (AppData/Temp vs System32/ProgramFiles)
// Tier 2 (user-mode): signature consistency check (Real Silver Fox Killer)
typedef struct _SILVERFOX_ENTRY {
    ULONG Flags;           // 1=SuspiciousPath, 2=NormalPath
    WCHAR Path[MAX_PATH_LEN];
} SILVERFOX_ENTRY, * PSILVERFOX_ENTRY;

typedef struct _SILVERFOX_TRACKER {
    ULONG ProcessId;
    LARGE_INTEGER StartTime;
    LONG EntryCount;
    LONG Alerted;
    SILVERFOX_ENTRY Entries[SILVERFOX_MAX_RELEASES];
} SILVERFOX_TRACKER, * PSILVERFOX_TRACKER;

extern KSPIN_LOCK g_SilverFoxLock;
extern SILVERFOX_TRACKER g_SilverFoxTrackers[64];

#define ZETA_CMD_ADD_WHITELIST 1
#define ZETA_CMD_REMOVE_WHITELIST 2
#define ZETA_CMD_GET_INITLOG 3
#define ZETA_CMD_ALLOW_OP 4   // user → kernel: allow pending operation for PID
#define ZETA_CMD_DENY_OP 5    // user → kernel: deny pending operation for PID
#define ZETA_CMD_ROLLBACK_MARK 8  // user → kernel: mark PID for rollback

// Pending operation: tracks a minifilter callback awaiting user-mode decision
typedef struct _PENDING_OP {
    LIST_ENTRY ListEntry;
    PFLT_CALLBACK_DATA CallbackData;
    PCFLT_RELATED_OBJECTS FltObjects;
    ULONG ProcessId;
    ULONG MessageCode;        // original block code (2001, 5001, etc.)
    LARGE_INTEGER StartTime;  // for timeout
    WCHAR TargetPath[MAX_PATH_LEN];
} PENDING_OP, * PPENDING_OP;

extern LIST_ENTRY g_PendingOps;
extern KSPIN_LOCK g_PendingOpsLock;

NTSTATUS PendOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, ULONG ProcessId, ULONG MessageCode, PWCHAR TargetPath, ULONG TargetPathBytes);
NTSTATUS CompletePendingOperation(ULONG ProcessId, BOOLEAN Allow);
NTSTATUS QueueCompletePendingOperation(ULONG ProcessId, BOOLEAN Allow);
VOID CleanupAllPendingOperations();
VOID InitializePendingOps();
VOID CheckPendingTimeouts();
VOID StartTimeoutChecker();
VOID StopTimeoutChecker();

typedef struct _ZETA_USER_MESSAGE {
 ULONG Command;
 WCHAR Path[MAX_PATH_LEN];
} ZETA_USER_MESSAGE, * PZETA_USER_MESSAGE;

typedef struct _DRIVER_DATA {
 PDRIVER_OBJECT DriverObject;
 PFLT_FILTER FilterHandle;
 PFLT_PORT ServerPort;
 PFLT_PORT ClientPort;
 PEPROCESS UserProcess;
 ULONG ZetaPid;
 LARGE_INTEGER Cookie;
 KSPIN_LOCK PortMutex;
    KSPIN_LOCK TrackerMutex;
    EX_RUNDOWN_REF PortRundown;
} DRIVER_DATA, * PDRIVER_DATA;

// ============================================================================
// Work item tracker: synchronize async work items during driver unload
// ============================================================================
typedef struct _WORK_ITEM_TRACKER {
    LONG PendingCount;       // number of queued work items still running
    KEVENT CompletionEvent;  // signaled when PendingCount reaches 0
} WORK_ITEM_TRACKER;
extern WORK_ITEM_TRACKER g_WorkItemTracker;

typedef struct _RULE_NODE {
 struct _RULE_NODE* Next;
 UNICODE_STRING Pattern;
 BOOLEAN OnlySafeTypes;   // TRUE: only match safe file extensions (txt, json, xml, etc.)
} RULE_NODE, * PRULE_NODE;

#define MAX_PREFIX_HASHES 256

typedef struct _PREFIX_HASH_ENTRY {
    ULONG Hash;
    BOOLEAN HasLeadingWildcard;
} PREFIX_HASH_ENTRY, * PPREFIX_HASH_ENTRY;

typedef struct _PREFIX_HASH_TABLE {
    PREFIX_HASH_ENTRY Entries[MAX_PREFIX_HASHES];
    ULONG Count;
} PREFIX_HASH_TABLE, * PPREFIX_HASH_TABLE;

extern DRIVER_DATA GlobalData;

// DriverEntry initialization state (visible to all modules for logging)
typedef struct _DRIVER_STATE {
    BOOLEAN RulesEngineOK;
    BOOLEAN RulesLoaded;
    BOOLEAN UserRulesLoaded;   // Rules_User.json loaded & merged
    BOOLEAN FilterRegistered;
    BOOLEAN PortCreated;
    BOOLEAN ProcessProtectionOK;
    NTSTATUS ProcessProtectionStatus;  // exact NTSTATUS from ObRegisterCallbacks
    BOOLEAN RegistryProtectionOK;
    BOOLEAN ImageNotifyOK;
    BOOLEAN FilterStarted;
    BOOLEAN AnyFailure;
    BOOLEAN LineageTrackerOK;
    BOOLEAN ProcessNotifyExOK;       // PsSetCreateProcessNotifyRoutineEx registered
    NTSTATUS ProcessNotifyExStatus;  // exact NTSTATUS from PsSetCreateProcessNotifyRoutineEx
    BOOLEAN RansomExperimentalOK;
    ULONG RegistryBlockCount;
    ULONG RegistryTrustedCount;
    ULONG ProcessTrustedCount;
    ULONG ProcessExploitCount;
    ULONG FileProtectedCount;
    ULONG FileExceptionCount;
    ULONG FileSafeExceptionCount;
    ULONG FileRansomCount;
    
    NTSTATUS SystemRulesStatus;    // Rules_Driver_P1.json load status
    NTSTATUS UserRulesStatus;      // Rules_User.json load status
} DRIVER_STATE, * PDRIVER_STATE;

extern DRIVER_STATE g_DriverState;

extern PREFIX_HASH_TABLE g_FilePrefixHashes;
extern PREFIX_HASH_TABLE g_RegistryPrefixHashes;
extern PREFIX_HASH_TABLE g_ProcessPrefixHashes;

FLT_PREOP_CALLBACK_STATUS ProtectFile_PreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectFile_PreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectFile_PreSetInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectFile_FileSystemControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectFile_SetSecurity(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectBoot_PreDeviceControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

extern "C" {
    HANDLE PsGetProcessInheritedFromUniqueProcessId(PEPROCESS Process);
    UCHAR* PsGetProcessImageFileName(PEPROCESS Process);
    NTSTATUS PsSuspendProcess(PEPROCESS Process);
}

NTSTATUS InitializeProcessProtection();
VOID UninitializeProcessProtection();
NTSTATUS InitializeRegistryProtection(PDRIVER_OBJECT DriverObject);
VOID UninitializeRegistryProtection();

NTSTATUS LoadRulesFromDisk(PUNICODE_STRING RegistryPath);
VOID UnloadRules();

VOID InitializeRulesEngine();
VOID UninitializeRulesEngine();

VOID AddDynamicWhitelist(PUNICODE_STRING RuleStr);
VOID RemoveDynamicWhitelist(PUNICODE_STRING RuleStr);

VOID ImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);

NTSTATUS GetProcessImageName(HANDLE ProcessId, PUNICODE_STRING* ImageName);

BOOLEAN IsProcessTrusted(HANDLE ProcessId);
BOOLEAN IsTargetProtected(HANDLE ProcessId);
BOOLEAN WildcardMatch(PCWSTR Pattern, PCWSTR String, USHORT StringLengthBytes);

BOOLEAN CheckRegistryRule(PCUNICODE_STRING KeyName);
BOOLEAN CheckFileExtensionRule(PCUNICODE_STRING FileName);
BOOLEAN CheckProtectedPathRule(PCUNICODE_STRING FileName);
// ── Learning Mode (3.7) ──────────────────────────────────────────
#define ZETA_LEARNING_DURATION_MS  300000  // 5 minutes in milliseconds
extern BOOLEAN g_LearningModeActive;
VOID InitializeLearningMode();
VOID UninitializeLearningMode();
VOID LearningMode_SetEnabled(BOOLEAN Enabled);
// ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

// Lineage Tracker: experimental process bloodline tracking
VOID LineageTracker_Initialize();
VOID LineageTracker_Uninitialize();
VOID LineageTracker_OnProcessCreate(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create);
VOID LineageTracker_OnFileRelease(ULONG ProcessId, PUNICODE_STRING FilePath);
NTSTATUS LineageTracker_SetEnabled(BOOLEAN Enabled);

// ── Simple File Rollback ──────────────────────────────────────────────
// Records PE files created by untrusted processes.
// When the process exits, all recorded files are deleted.
#define ROLLBACK_MAX_FILES   32   // Max files tracked per PID
#define ROLLBACK_MAX_PIDS    32   // Max simultaneous tracked PIDs

typedef struct _ROLLBACK_ENTRY {
    WCHAR Path[MAX_PATH_LEN];
} ROLLBACK_ENTRY;

typedef struct _ROLLBACK_TRACKER {
    LONG  ProcessId;            // -1 = slot free
    ROLLBACK_ENTRY Files[ROLLBACK_MAX_FILES];
    LONG  FileCount;
    LARGE_INTEGER StartTime;
    BOOLEAN WasHipsTerminated;  // TRUE = process was terminated by HIPS
} ROLLBACK_TRACKER;

VOID Rollback_RecordFile(ULONG ProcessId, PUNICODE_STRING FilePath);
VOID Rollback_MarkTerminated(ULONG ProcessId);
VOID Rollback_Execute(ULONG ProcessId);

extern KSPIN_LOCK g_RollbackLock;
extern ROLLBACK_TRACKER g_RollbackTrackers[ROLLBACK_MAX_PIDS];
// ── ── ── ── ── ── ── ── ── ── ──

// Experimental ransomware detection
BOOLEAN RansomExp_CheckWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PUNICODE_STRING FileName, PVOID WriteBuffer, ULONG WriteLength);
BOOLEAN RansomExp_IsKnownMagic(PUCHAR Header, ULONG HeaderLen);
NTSTATUS RansomExp_SetEnabled(BOOLEAN Enabled);

NTSTATUS SendMessageToUser(ULONG Code, ULONG Pid, PWCHAR Path, USHORT PathSize);

// Process creation/exit events via PsSetCreateProcessNotifyRoutineEx
#define ZETA_MSG_PROCESS_CREATE     7006  // process created (path=ImagePath\nCmdLine\nPPID)
#define ZETA_MSG_PROCESS_EXIT       7007  // process exited

// Log message code - sent to user-mode for logging
#define ZETA_MSG_LOG 7000
#define ZETA_MSG_LEARNING_LOG 7005  // learning mode activity log

// DriverLog: send a log message to user-mode via SendMessageToUser
// Uses a static buffer; only call from PASSIVE_LEVEL
FORCEINLINE VOID DriverLog(ULONG Pid, PCWSTR Format, ...) {
    WCHAR Buffer[MAX_PATH_LEN];
    va_list Args;
    va_start(Args, Format);
    RtlStringCbVPrintfW(Buffer, sizeof(Buffer), Format, Args);
    va_end(Args);

    ULONG Len = (ULONG)wcslen(Buffer);
    if (Len > 0) {
        ULONG Bytes = (Len < (MAX_PATH_LEN - 1) ? Len : (MAX_PATH_LEN - 1)) * sizeof(WCHAR);
        SendMessageToUser(ZETA_MSG_LOG, Pid, Buffer, Bytes);
    }
}

FORCEINLINE PVOID ZetaAllocate(SIZE_T Size) {
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, ZETA_POOL_TAG);
}

FORCEINLINE VOID ZetaFree(PVOID Ptr) {
    if (Ptr) ExFreePoolWithTag(Ptr, ZETA_POOL_TAG);
}


