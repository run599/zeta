#pragma once
#include <fltKernel.h>
#include <ntddk.h> 
#include <ntdddisk.h> 
#include <ntddscsi.h> 
#include <ntstrsafe.h>
#include <ntimage.h>

// 本地定义文件操作结构体 — 避免 WDK 版本间 ntifs.h 包含差异
typedef struct _ZETA_FILE_RENAME_INFO {
    BOOLEAN ReplaceIfExists;
    BOOLEAN Reserved;
    BOOLEAN Reserved1;
    BOOLEAN Reserved2;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} ZETA_FILE_RENAME_INFO;

typedef struct _ZETA_FILE_DISPOSITION_INFO {
    BOOLEAN DeleteFile;
} ZETA_FILE_DISPOSITION_INFO;

typedef struct _ZETA_FILE_DISPOSITION_INFO_EX {
    ULONG Flags;
} ZETA_FILE_DISPOSITION_INFO_EX;

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

// APC 注入拦截 (NtQueueApcThread hook)
#define ZETA_MSG_APC_INJECT            6010  // Path="SourcePid|TargetPid"

// P0-注入拦截: 远程线程/内存写入前置拦截 (SSDT hook)
#define ZETA_MSG_THREAD_CREATE_INJECT  6015  // NtCreateThreadEx 跨进程远程线程 (Path="SourcePid|TargetPid|Routine")
#define ZETA_MSG_WRITE_MEM_INJECT      6016  // NtWriteVirtualMemory 跨进程写入 (Path="SourcePid|TargetPid|Bytes")

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
#define ZETA_CMD_SET_AUDIT_MODE    16  // user -> kernel: enable/disable audit mode
#define ZETA_CMD_QUERY_AUDIT_LOG   17  // user -> kernel: query audit ring buffer entries
#define ZETA_CMD_SET_APC_HOOK      19  // user -> kernel: enable NtQueueApcThread hook (Path="ApcSysno,ValidateSysno")
#define ZETA_CMD_SET_UNLOAD_GUARD  20  // user -> kernel: enable NtUnloadDriver guard (Path="UnloadSysno,ValidateSysno")
#define ZETA_CMD_SET_RANSOM_REDIRECT 21 // user -> kernel: enable/disable ransomware write redirect (Path="0/1")
#define ZETA_CMD_SET_INJECT_HOOK     22 // user -> kernel: enable NtCreateThreadEx+NtWriteVirtualMemory hooks (Path="CreateThreadSysno,WriteMemSysno,ValidateSysno")

// ============================================================================
// IRP Audit Mode — Extended context for forensic-level analysis
// ============================================================================

// Audit mode levels
#define AUDIT_MODE_OFF       0   // Normal: only ZETA_IRP_CONTEXT (8 bytes)
#define AUDIT_MODE_ON        1   // Audit: ZETA_IRP_CONTEXT + ZETA_IRP_AUDIT_EXT
#define AUDIT_MODE_SAMPLING  2   // Audit + write buffer sampling (first 32 bytes)

// Ring buffer for audit records (kernel -> user shared memory)
#define AUDIT_RING_SIZE      4096  // must be power of 2
#define AUDIT_RING_MASK      (AUDIT_RING_SIZE - 1)

#pragma pack(push, 1)
typedef struct _ZETA_IRP_AUDIT_EXT {
    USHORT  Size;           // total bytes of this struct (for variable-length)
    USHORT  IrpMajor;       // IRP_MJ_* or registry major
    ULONG   DesiredAccess;  // PreCreate: full ACCESS_MASK
    ULONG   CreateOptions;  // PreCreate: full CreateOptions
    ULONG   ShareAccess;    // PreCreate: ShareAccess
    ULONG   WriteLength;    // PreWrite: write length
    ULONGLONG ByteOffset;   // PreWrite: byte offset (full 64-bit)
    USHORT  FileClass;      // PreSetInfo: FileInformationClass
    USHORT  RegValueType;   // Registry: REG_SZ/DWORD/BINARY
    WCHAR   ValueName[64];  // Registry: value name (e.g. "internat.exe")
    UCHAR   WriteSample[32]; // PreWrite: first 32 bytes of write buffer
    USHORT  WriteSampleLen;  // actual bytes copied into WriteSample
} ZETA_IRP_AUDIT_EXT, *PZETA_IRP_AUDIT_EXT;
#pragma pack(pop)

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
extern BOOLEAN g_ThreadNotifyActive;  // PsSetCreateThreadNotifyRoutine registered

// ScriptDepth: 查询指定进程的脚本解释器链深度（LineageTracker 表）
// 返回值 0=普通进程, 1=脚本解释器直接, 2+=多级脚本嵌套
UCHAR GetScriptDepthForProcess(HANDLE ProcessId);

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
extern BOOLEAN g_RansomRedirectEnabled;   // P1-状态机: 勒索写重定向开关

// ── Module Switches (P1-1: 运行时模块开关) ──────────────────────
// 通过 ZETA_CMD_SET_* 命令在运行时启用/禁用各保护模块
// 默认全部启用 (向后兼容)；网络保护默认禁用 (由独立 NetFilter 驱动处理)
extern BOOLEAN g_ProcessProtectEnabled;   // ZETA_CMD_SET_PROCESS_PROTECT (8)
extern BOOLEAN g_SuspendEnabled;         // ZETA_CMD_SET_SUSPEND_ENABLE  (9) - 挂起待决操作
extern BOOLEAN g_FileProtectEnabled;      // ZETA_CMD_SET_FILE_PROTECT    (10)
extern BOOLEAN g_SystemProtectEnabled;    // ZETA_CMD_SET_SYSTEM_PROTECT  (11)
extern BOOLEAN g_DriverProtectEnabled;    // ZETA_CMD_SET_DRIVER_PROTECT  (12)
extern BOOLEAN g_NetworkProtectEnabled;   // ZETA_CMD_SET_NETWORK_PROTECT (13)

// P0-1: watchdog 三合一校验需要的全局状态（跨文件引用）
extern PVOID g_ObRegistrationHandle;        // ProtectProcess.cpp: ObRegisterCallbacks 注册句柄（非 NULL 表示句柄保护已注册）
BOOLEAN ApcHook_IsTableIntact();            // ApcHook.cpp: 校验 APC SSDT 表项仍指向本驱动 handler
VOID    ApcHook_RestoreTableEntry();        // ApcHook.cpp: 重打 APC SSDT 表项 (watchdog 恢复用)
NTSTATUS InitializeProcessProtection();     // ProtectProcess.cpp: 重新注册 Ob 句柄保护回调 (watchdog 恢复用)
// P0-2: 拦截 ZETA_Drv 自卸载 (UnloadGuard)
NTSTATUS UnloadGuard_Enable(ULONG UnloadSyscall, ULONG ValidateSyscall);
VOID    UnloadGuard_Disable();
BOOLEAN UnloadGuard_IsActive();
BOOLEAN UnloadGuard_IsTableIntact();        // watchdog 三合一校验用
VOID    UnloadGuard_RestoreTableEntry();    // watchdog 恢复表项用

// P0-注入拦截: NtCreateThreadEx (远程线程) + NtWriteVirtualMemory (跨进程写入)
NTSTATUS InjectHook_Enable(ULONG CreateThreadSyscall, ULONG WriteMemSyscall, ULONG ValidateSyscall);
VOID    InjectHook_Disable();
BOOLEAN InjectHook_IsActive();
VOID    InjectHook_Init();
VOID    InjectHook_CheckTimeouts();

// SSDT 定位/重定向框架 (ApcHook.cpp 提供, 跨模块共用)
NTSTATUS GetNtoskrnlBase(PVOID* OutBase, ULONG* OutSize);
ULONG_PTR FindKiServiceTable(PVOID Base, ULONG Size, ULONG ValidateSyscall);
NTSTATUS PatchSsdtEntry(ULONG_PTR Table, ULONG Index, ULONG_PTR Handler,
    ULONG_PTR* OutOriginal);

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
#define ZETA_CMD_ROLLBACK_MARK 18  // user → kernel: mark PID for rollback (P0-1: 8→18 避免与 SET_PROCESS_PROTECT 冲突)

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

// ── APC Hook (NtQueueApcThread 拦截) ──
NTSTATUS ApcHook_Enable(ULONG ApcSyscall, ULONG ValidateSyscall);
VOID ApcHook_Disable();
BOOLEAN ApcHook_IsActive();
VOID ApcHook_Init();
VOID ApcHook_CheckTimeouts();
VOID CompletePendingApc(ULONG SourcePid, BOOLEAN Allow);

NTSTATUS PendOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, ULONG ProcessId, ULONG MessageCode, PWCHAR TargetPath, ULONG TargetPathBytes);
NTSTATUS CompletePendingOperation(ULONG ProcessId, BOOLEAN Allow);
NTSTATUS QueueCompletePendingOperation(ULONG ProcessId, BOOLEAN Allow);
VOID CompleteAllPendingOperations();  // 先 FltCompletePendedPreOperation 再释放
VOID CleanupAllPendingOperations();
VOID InitializePendingOps();
VOID CheckPendingTimeouts();
VOID StartTimeoutChecker();
VOID StopTimeoutChecker();

typedef struct _ZETA_USER_MESSAGE {
 ULONG Command;
 WCHAR Path[MAX_PATH_LEN];
} ZETA_USER_MESSAGE, * PZETA_USER_MESSAGE;

// Max network instances to track
#define ZETA_MAX_NET_INSTANCES 8

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

// P0-自伤免疫 (self-write marker):
// ZETA 自身所有的内核自修改动作 (DKOM 写 EPROCESS/KLDR 字段、SSDT 表项重定向)
// 在执行前必须置位此标志、完成后清除。未来任何"内核完整性监控"逻辑
// (检测 PPL 字段/KLDR/SSDT 是否被外部篡改) 看到此标志为 TRUE 时, 必须判定
// "这是 ZETA 自己在改 → 放行", 绝不能把 ZETA 的自保动作误报为恶意篡改。
extern volatile BOOLEAN g_SelfDkomInProgress;

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
FLT_PREOP_CALLBACK_STATUS ProtectFile_PreSectionSync(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS ProtectBoot_PreDeviceControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

// ── Network device protection ──
// Network monitoring is handled by ZETA_NetFilter.sys (separate WDM driver)
#define ZETA_MSG_NET_SOCKET_CREATE  8001
#define ZETA_MSG_NET_SOCKET_SEND    8002
#define ZETA_MSG_NET_SOCKET_CONNECT 8003

extern "C" {
    HANDLE PsGetProcessInheritedFromUniqueProcessId(PEPROCESS Process);
    UCHAR* PsGetProcessImageFileName(PEPROCESS Process);
    NTSTATUS PsSuspendProcess(PEPROCESS Process);
    NTSTATUS PsResumeProcess(PEPROCESS Process);  // P1-2: 用于勒索软件挂起后用户态决策恢复
}

NTSTATUS InitializeProcessProtection();
VOID UninitializeProcessProtection();

// ── DKOM PPL 自保 (邪门歪道版) ──────────
// 直接写 EPROCESS.Protection 字段，绕过签名检查
// 效果: 将 ZETA.exe 提升为 PPL，免 ObRegisterCallbacks
NTSTATUS InitializeDkomProcessProtection();
VOID UninitializeDkomProcessProtection();

// DkomSetDriverSignatureFlags -- DKOM 修改驱动镜像 KLDR_DATA_TABLE_ENTRY.Flags
// 将 Flags |= 0x20 (ProcessStaticImport bit)，使 ObRegisterCallbacks 验证通过。
// 原理: MmVerifyCallbackFunctionCheckFlags 检查 DriverSection->Flags & 0x20
NTSTATUS DkomSetDriverSignatureFlags();

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

// ── Self-registration detection for Run keys ──────────────────────
// If a signed process writes a Run value whose name matches the process
// filename (e.g. internat.exe writes Run\internat.exe), it is a normal
// self-registration and should not be blocked.
// Returns TRUE when the write appears to be a legitimate self-registration.
static __forceinline BOOLEAN IsRunKeySelfRegistration(HANDLE Pid, PCWSTR FullPath) {
    if (!FullPath) return FALSE;
    // Must be a Run/RunOnce key with a value name
    USHORT pathLen = (USHORT)(wcslen(FullPath) * sizeof(WCHAR));
    if (!WildcardMatch(L"*\\CurrentVersion\\Run\\*", FullPath, pathLen) &&
        !WildcardMatch(L"*\\CurrentVersion\\RunOnce\\*", FullPath, pathLen))
        return FALSE;

    // Extract value name (last component after \)
    PCWSTR lastSlash = FullPath;
    PCWSTR p = FullPath;
    while (*p) { if (*p == L'\\') lastSlash = p + 1; p++; }
    USHORT valueLen = (USHORT)((p - lastSlash) * sizeof(WCHAR));
    if (valueLen < 4 * sizeof(WCHAR)) return FALSE; // too short to be exe

    // Get process image path
    PUNICODE_STRING imageFileName = NULL;
    if (!NT_SUCCESS(GetProcessImageName(Pid, &imageFileName)))
        return FALSE;
    if (!imageFileName || !imageFileName->Buffer || imageFileName->Length == 0) {
        if (imageFileName) ExFreePool(imageFileName);
        return FALSE;
    }

    // Extract filename from image path
    PCWSTR imgLastSlash = imageFileName->Buffer;
    PCWSTR imgP = imageFileName->Buffer;
    USHORT imgLenW = imageFileName->Length / sizeof(WCHAR);
    for (USHORT i = 0; i < imgLenW; i++) {
        if (imgP[i] == L'\\') imgLastSlash = imgP + i + 1;
    }
    USHORT imgNameLen = (USHORT)((imgP + imgLenW - imgLastSlash) * sizeof(WCHAR));

    ExFreePool(imageFileName);

    // Compare: process filename == registry value name
    if (imgNameLen != valueLen) return FALSE;
    for (USHORT i = 0; i < imgNameLen / sizeof(WCHAR); i++) {
        if (RtlDowncaseUnicodeChar(imgLastSlash[i]) != RtlDowncaseUnicodeChar(lastSlash[i]))
            return FALSE;
    }
    return TRUE;
}
// ── Learning Mode (3.7) ──────────────────────────────────────────
#define ZETA_LEARNING_DURATION_MS  300000  // 5 minutes in milliseconds
extern BOOLEAN g_LearningModeActive;
VOID LearningMode_SetEnabled(BOOLEAN Enabled);
// ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ──

// Lineage Tracker: experimental process bloodline tracking
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
// P1-状态机: 勒索写重定向 (写隔离副本, 原文件保留)
NTSTATUS RansomExp_RedirectWrite(PUNICODE_STRING FileName, ULONG Pid,
    PVOID WriteBuffer, ULONG WriteLength);

// P1-2: 勒索软件挂起后用户态决策辅助函数
// ResumeSuspendedProcess - 恢复被 PsSuspendProcess 挂起的进程 (用户态选择"允许")
NTSTATUS ResumeSuspendedProcess(ULONG ProcessId);
// KillSuspendedProcess - 终止被挂起的勒索进程 (用户态选择"阻止")
NTSTATUS KillSuspendedProcess(ULONG ProcessId);

NTSTATUS SendMessageToUser(ULONG Code, ULONG Pid, PWCHAR Path, USHORT PathSize);

// ============================================================================
// IRP Semantic Context — 内核在 IRP 检查点提取的语义标签
// 与 zeta_driver.h 中的 ZETA_IRP_CONTEXT 保持一致 (8 bytes)
// ============================================================================
// IRP Semantic Context — 内核在 IRP 检查点提取的语义标签
// ============================================================================

// IrpOperationType
#define IRP_OP_FILE_CREATE     0
#define IRP_OP_FILE_WRITE      1
#define IRP_OP_FILE_RENAME     2
#define IRP_OP_FILE_DELETE     3
#define IRP_OP_FILE_SETINFO    4
#define IRP_OP_REG_CREATEKEY   10
#define IRP_OP_REG_SETVALUE    11
#define IRP_OP_REG_DELETEKEY   12
#define IRP_OP_REG_RENAMEKEY   13
#define IRP_OP_DISK_WRITE      20
#define IRP_OP_DISK_IOCTL      21
#define IRP_OP_PROCESS_CREATE  30
#define IRP_OP_PROCESS_EXIT    31
#define IRP_OP_IMAGE_LOAD      32

// FileSemanticFlags
#define FILE_SEM_NONE            0x0000
#define FILE_SEM_IS_PE           0x0001
#define FILE_SEM_IS_SCRIPT       0x0002
#define FILE_SEM_IS_DOCUMENT     0x0004
#define FILE_SEM_OFFSET_ZERO     0x0008
#define FILE_SEM_LARGE_WRITE     0x0010
#define FILE_SEM_HIDDEN_ATTR     0x0020
#define FILE_SEM_SYSTEM_ATTR     0x0040
#define FILE_SEM_DELETE_OP       0x0080
#define FILE_SEM_EXCLUSIVE       0x0100
#define FILE_SEM_OVERWRITE       0x0200
#define FILE_SEM_NONCACHED       0x0400
#define FILE_SEM_PAGING_IO       0x0800
#define FILE_SEM_TEMP_PATH       0x1000
#define FILE_SEM_APPDATA_PATH    0x2000
#define FILE_SEM_SYSTEM_PATH     0x4000
#define FILE_SEM_PUBLIC_PATH     0x8000

// Context Flags (byte 7 of ZETA_IRP_CONTEXT) — 跨操作类型通用标志
#define CTX_FLAG_REPLACE_IF_EXISTS  0x01  // 重命名时 ReplaceIfExists=TRUE（替代同路径已有文件）
#define CTX_FLAG_DISPOSITION_EX     0x02  // SetInfo: FileDispositionInformationEx（Windows 10+）
#define CTX_FLAG_DISPOSITION_DELETE 0x04  // SetInfo: DeleteFile=TRUE（硬删除，不可恢复）
#define CTX_FLAG_HAS_TRANSACTION    0x08  // 操作在 TxF 事务内（可疑，如 office 暂存文件机制）
#define CTX_FLAG_SCRIPT_HOST       0x10  // 当前进程是脚本解释器（powershell/cmd/wscript等）
#define CTX_FLAG_HAS_SCRIPT_ANC    0x20  // 当前进程有脚本解释器祖先（父/祖父进程是脚本）

// RegSemanticFlags
#define REG_SEM_NONE             0x0000
#define REG_SEM_RUN_KEY          0x0001
#define REG_SEM_SERVICE_KEY      0x0002
#define REG_SEM_IFEO_KEY         0x0004
#define REG_SEM_UAC_KEY          0x0008
#define REG_SEM_DEFENDER_KEY     0x0010
#define REG_SEM_FIREWALL_KEY     0x0020
#define REG_SEM_APPINIT_KEY      0x0040
#define REG_SEM_BCD_KEY          0x0080
#define REG_SEM_VALUE_DELETE     0x0100

// ProcessTrustLevel
#define TRUST_UNKNOWN       0
#define TRUST_NONE          1
#define TRUST_UNSIGNED      2
#define TRUST_SIGNED        3
#define TRUST_MS_SIGNED     4
#define TRUST_SYSTEM        5
#define TRUST_ZETA          6

// 8-byte IRP 语义上下文 (与 zeta_driver.h 中的 ZETA_IRP_CONTEXT 一致)
#pragma pack(push, 1)
typedef struct _ZETA_IRP_CONTEXT {
    UCHAR OperationType;
    UCHAR TrustLevel;
    USHORT FileFlags;
    USHORT RegFlags;
    UCHAR ScriptDepth;
    UCHAR Flags;
} ZETA_IRP_CONTEXT, *PZETA_IRP_CONTEXT;
#pragma pack(pop)

// 批量填充 IRP 上下文的 ScriptDepth 和 CTX_FLAG_SCRIPT_HOST/ANC 标志
VOID FillScriptInfo(PZETA_IRP_CONTEXT ctx);

// Audit ring buffer entry (fixed-size record)
#define AUDIT_ENTRY_MAX_PATH 520
#pragma pack(push, 1)
typedef struct _AUDIT_RING_ENTRY {
    LONGLONG Timestamp;
    ULONG    ProcessId;
    ULONG    MessageCode;
    ZETA_IRP_CONTEXT Ictx;
    ZETA_IRP_AUDIT_EXT Ext;
    WCHAR    Path[AUDIT_ENTRY_MAX_PATH / sizeof(WCHAR)];
} AUDIT_RING_ENTRY, *PAUDIT_RING_ENTRY;
#pragma pack(pop)

// Audit ring buffer (lock-free single-producer single-consumer)
typedef struct _AUDIT_RING_BUFFER {
    volatile LONG Head;
    volatile LONG Tail;
    AUDIT_RING_ENTRY Entries[AUDIT_RING_SIZE];
} AUDIT_RING_BUFFER, *PAUDIT_RING_BUFFER;

// Audit mode globals
extern ULONG g_AuditMode;
extern PAUDIT_RING_BUFFER g_AuditRing;

// Audit ring buffer API
NTSTATUS InitializeAuditRing();
VOID UninitializeAuditRing();
VOID AuditRing_WriteEntry(ULONG Code, ULONG Pid, PWCHAR Path, USHORT PathLen,
    PZETA_IRP_CONTEXT Ictx, PZETA_IRP_AUDIT_EXT Ext);

// Fill audit extension from IRP callback data (called at check points)
VOID FillAuditExt_PreCreate(PFLT_CALLBACK_DATA Data, PZETA_IRP_AUDIT_EXT Ext);
VOID FillAuditExt_PreWrite(PFLT_CALLBACK_DATA Data, PZETA_IRP_AUDIT_EXT Ext);
VOID FillAuditExt_PreSetInfo(PFLT_CALLBACK_DATA Data, PZETA_IRP_AUDIT_EXT Ext);

NTSTATUS SendMessageToUserWithContext(ULONG Code, ULONG Pid, PWCHAR Path, USHORT PathSize,
    PZETA_IRP_CONTEXT Context);

// ============================================================================
// 内核侧语义提取辅助函数
// ============================================================================

// Map driver TRUST_LEVEL enum to IRP context TRUST_* defines
static __forceinline UCHAR MapTrustLevelToIrpCtx(TRUST_LEVEL level) {
    switch (level) {
        case TRUST_LEVEL_SYSTEM:  return TRUST_SYSTEM;   // 2 → 5
        case TRUST_LEVEL_SIGNED: return TRUST_SIGNED;    // 1 → 3
        default:                 return TRUST_NONE;      // 0 → 1
    }
}

static __forceinline VOID ExtractFileSemantics_PreCreate(
    PFLT_CALLBACK_DATA Data, PUNICODE_STRING FileName,
    PZETA_IRP_CONTEXT ctx)
{
    RtlZeroMemory(ctx, sizeof(ZETA_IRP_CONTEXT));
    ctx->OperationType = IRP_OP_FILE_CREATE;
    // Populate real trust level so user-mode scoring can apply MS signature discount
    ctx->TrustLevel = MapTrustLevelToIrpCtx(
        GetProcessTrustLevel(PsGetCurrentProcessId()));

    ACCESS_MASK access = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    ULONG options = Data->Iopb->Parameters.Create.Options;
    ULONG share = Data->Iopb->Parameters.Create.ShareAccess;
    ULONG attrs = Data->Iopb->Parameters.Create.FileAttributes;
    ULONG disposition = (options >> 24) & 0xFF;

    if (FileName && FileName->Buffer && FileName->Length > 0) {
        SIZE_T nameLen = FileName->Length / sizeof(WCHAR);
        WCHAR* buf = FileName->Buffer;
        if (nameLen > 4) {
            WCHAR e0 = buf[nameLen-4] | 0x20, e1 = buf[nameLen-3] | 0x20;
            WCHAR e2 = buf[nameLen-2] | 0x20, e3 = buf[nameLen-1] | 0x20;
            if ((e0==L'.'&&e1==L'e'&&e2==L'x'&&e3==L'e')||(e0==L'.'&&e1==L'd'&&e2==L'l'&&e3==L'l')||
                (e0==L'.'&&e1==L's'&&e2==L'y'&&e3==L's')||(e0==L'.'&&e1==L's'&&e2==L'c'&&e3==L'r')||
                (e0==L'.'&&e1==L'b'&&e2==L'a'&&e3==L't')||(e0==L'.'&&e1==L'c'&&e2==L'm'&&e3==L'd'))
                ctx->FileFlags |= FILE_SEM_IS_PE;
            if ((e0==L'.'&&e1==L'p'&&e2==L's'&&e3==L'1')||(e0==L'.'&&e1==L'v'&&e2==L'b'&&e3==L's')||
                (e0==L'.'&&e1==L'h'&&e2==L't'&&e3==L'a')||(e0==L'.'&&e1==L'c'&&e2==L'h'&&e3==L'm'))
                ctx->FileFlags |= FILE_SEM_IS_SCRIPT;
        }
        if (WildcardMatch(L"*\\Temp\\*", FileName->Buffer, FileName->Length))
            ctx->FileFlags |= FILE_SEM_TEMP_PATH;
        if (WildcardMatch(L"*\\AppData\\*", FileName->Buffer, FileName->Length))
            ctx->FileFlags |= FILE_SEM_APPDATA_PATH;
        if (WildcardMatch(L"*\\Windows\\System32\\*", FileName->Buffer, FileName->Length) ||
            WildcardMatch(L"*\\Windows\\SysWOW64\\*", FileName->Buffer, FileName->Length))
            ctx->FileFlags |= FILE_SEM_SYSTEM_PATH;
        if (WildcardMatch(L"*\\Users\\Public\\*", FileName->Buffer, FileName->Length))
            ctx->FileFlags |= FILE_SEM_PUBLIC_PATH;
    }

    if (access & DELETE) ctx->FileFlags |= FILE_SEM_DELETE_OP;
    if (share == 0) ctx->FileFlags |= FILE_SEM_EXCLUSIVE;
    if (disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF)
        ctx->FileFlags |= FILE_SEM_OVERWRITE;
    if (attrs & FILE_ATTRIBUTE_HIDDEN) ctx->FileFlags |= FILE_SEM_HIDDEN_ATTR;
    if (attrs & FILE_ATTRIBUTE_SYSTEM) ctx->FileFlags |= FILE_SEM_SYSTEM_ATTR;

    // ScriptDepth + 脚本标志
    FillScriptInfo(ctx);
}

static __forceinline VOID ExtractFileSemantics_PreWrite(
    PFLT_CALLBACK_DATA Data, PUNICODE_STRING FileName,
    PZETA_IRP_CONTEXT ctx)
{
    RtlZeroMemory(ctx, sizeof(ZETA_IRP_CONTEXT));
    ctx->OperationType = IRP_OP_FILE_WRITE;
    // Populate real trust level so user-mode scoring can apply MS signature discount
    ctx->TrustLevel = MapTrustLevelToIrpCtx(
        GetProcessTrustLevel(PsGetCurrentProcessId()));

    if (Data->Iopb->Parameters.Write.ByteOffset.QuadPart == 0) ctx->FileFlags |= FILE_SEM_OFFSET_ZERO;
    if (Data->Iopb->Parameters.Write.Length > 65536) ctx->FileFlags |= FILE_SEM_LARGE_WRITE;
    if (Data->Iopb->IrpFlags & (IRP_PAGING_IO|IRP_SYNCHRONOUS_PAGING_IO)) ctx->FileFlags |= FILE_SEM_PAGING_IO;

    if (FileName && FileName->Buffer && FileName->Length > 0) {
        if (WildcardMatch(L"*\\Temp\\*", FileName->Buffer, FileName->Length))
            ctx->FileFlags |= FILE_SEM_TEMP_PATH;
        if (WildcardMatch(L"*\\AppData\\*", FileName->Buffer, FileName->Length))
            ctx->FileFlags |= FILE_SEM_APPDATA_PATH;
        SIZE_T nLen = FileName->Length / sizeof(WCHAR);
        if (nLen > 4) {
            WCHAR* b = FileName->Buffer;
            WCHAR e0=b[nLen-4]|0x20, e1=b[nLen-3]|0x20, e2=b[nLen-2]|0x20, e3=b[nLen-1]|0x20;
            if ((e0==L'.'&&e1==L'e'&&e2==L'x'&&e3==L'e')||(e0==L'.'&&e1==L'd'&&e2==L'l'&&e3==L'l')||
                (e0==L'.'&&e1==L's'&&e2==L'y'&&e3==L's'))
                ctx->FileFlags |= FILE_SEM_IS_PE;
        }
    }

    // ScriptDepth + 脚本标志
    FillScriptInfo(ctx);
}

// ── PreSetInfo (文件重命名/删除) 语义提取 ─────────────────────────
// 注意：不标记 __forceinline — 函数体较大，由编译器自行决定
static __inline VOID ExtractFileSemantics_PreSetInfo(
    PFLT_CALLBACK_DATA Data, PUNICODE_STRING FileName,
    PZETA_IRP_CONTEXT ctx)
{
    RtlZeroMemory(ctx, sizeof(ZETA_IRP_CONTEXT));
    ctx->TrustLevel = MapTrustLevelToIrpCtx(
        GetProcessTrustLevel(PsGetCurrentProcessId()));

    FILE_INFORMATION_CLASS fc = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    if (fc == FileDispositionInformation || fc == FileDispositionInformationEx) {
        ctx->OperationType = IRP_OP_FILE_DELETE;
        ctx->FileFlags |= FILE_SEM_DELETE_OP;

        if (fc == FileDispositionInformationEx) {
            ctx->Flags |= CTX_FLAG_DISPOSITION_EX;
            __try {
                ZETA_FILE_DISPOSITION_INFO_EX* di = (ZETA_FILE_DISPOSITION_INFO_EX*)
                    Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
                if (di && Data->Iopb->Parameters.SetFileInformation.Length >= (ULONG)sizeof(ULONG)) {
                    if (di->Flags & 0x00000001) ctx->Flags |= CTX_FLAG_DISPOSITION_DELETE;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        } else {
            __try {
                ZETA_FILE_DISPOSITION_INFO* di = (ZETA_FILE_DISPOSITION_INFO*)
                    Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
                if (di && Data->Iopb->Parameters.SetFileInformation.Length >= (ULONG)sizeof(BOOLEAN)) {
                    if (di->DeleteFile) ctx->Flags |= CTX_FLAG_DISPOSITION_DELETE;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    } else {
        // FileRenameInformation / FileRenameInformationEx
        ctx->OperationType = IRP_OP_FILE_RENAME;

        __try {
            ZETA_FILE_RENAME_INFO* ri = (ZETA_FILE_RENAME_INFO*)
                Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            if (ri && Data->Iopb->Parameters.SetFileInformation.Length >=
                      (ULONG)FIELD_OFFSET(ZETA_FILE_RENAME_INFO, FileName[0])) {
                if (ri->ReplaceIfExists) ctx->Flags |= CTX_FLAG_REPLACE_IF_EXISTS;

                ULONG nameBytes = ri->FileNameLength;
                ULONG renameInfoHdrOffset = (ULONG)FIELD_OFFSET(ZETA_FILE_RENAME_INFO, FileName[0]);
                if (nameBytes > 8u && nameBytes < 1024u &&
                    (renameInfoHdrOffset + nameBytes)
                        <= Data->Iopb->Parameters.SetFileInformation.Length) {
                    WCHAR* targetName = ri->FileName;
                    ULONG nameChars = nameBytes / sizeof(WCHAR);
                    if (nameChars > 4) {
                        WCHAR e0 = targetName[nameChars-4] | 0x20;
                        WCHAR e1 = targetName[nameChars-3] | 0x20;
                        WCHAR e2 = targetName[nameChars-2] | 0x20;
                        WCHAR e3 = targetName[nameChars-1] | 0x20;
                        if ((e0==L'.'&&e1==L'e'&&e2==L'x'&&e3==L'e')||
                            (e0==L'.'&&e1==L'd'&&e2==L'l'&&e3==L'l')||
                            (e0==L'.'&&e1==L's'&&e2==L'y'&&e3==L's'))
                            ctx->FileFlags |= FILE_SEM_IS_PE;
                        if ((e0==L'.'&&e1==L'p'&&e2==L's'&&e3==L'1')||
                            (e0==L'.'&&e1==L'v'&&e2==L'b'&&e3==L's')||
                            (e0==L'.'&&e1==L'h'&&e2==L't'&&e3==L'a'))
                            ctx->FileFlags |= FILE_SEM_IS_SCRIPT;
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    // 路径分类标志（与 PreCreate 相同）
    if (FileName && FileName->Buffer && FileName->Length > 0) {
        if (WildcardMatch(L"*\\Temp\\*", FileName->Buffer, FileName->Length))
            ctx->FileFlags |= FILE_SEM_TEMP_PATH;
        if (WildcardMatch(L"*\\AppData\\*", FileName->Buffer, FileName->Length))
            ctx->FileFlags |= FILE_SEM_APPDATA_PATH;
        if (WildcardMatch(L"*\\Windows\\System32\\*", FileName->Buffer, FileName->Length) ||
            WildcardMatch(L"*\\Windows\\SysWOW64\\*", FileName->Buffer, FileName->Length))
            ctx->FileFlags |= FILE_SEM_SYSTEM_PATH;
        if (WildcardMatch(L"*\\Users\\Public\\*", FileName->Buffer, FileName->Length))
            ctx->FileFlags |= FILE_SEM_PUBLIC_PATH;
        SIZE_T nLen = FileName->Length / sizeof(WCHAR);
        if (nLen > 4) {
            WCHAR* b = FileName->Buffer;
            WCHAR e0=b[nLen-4]|0x20, e1=b[nLen-3]|0x20, e2=b[nLen-2]|0x20, e3=b[nLen-1]|0x20;
            if ((e0==L'.'&&e1==L'e'&&e2==L'x'&&e3==L'e')||(e0==L'.'&&e1==L'd'&&e2==L'l'&&e3==L'l')||
                (e0==L'.'&&e1==L's'&&e2==L'y'&&e3==L's'))
                ctx->FileFlags |= FILE_SEM_IS_PE;
        }
    }

    // ScriptDepth + 脚本标志
    FillScriptInfo(ctx);
}

// Process creation/exit events via PsSetCreateProcessNotifyRoutineEx
#define ZETA_MSG_PROCESS_CREATE     7006  // process created (path=ImagePath\nCmdLine\nPPID)
#define ZETA_MSG_PROCESS_EXIT       7007  // process exited
#define ZETA_MSG_THREAD_CREATE      7008  // thread created (PID,TID)
#define ZETA_MSG_THREAD_EXIT        7009  // thread exited (PID,TID)
// P1-状态机: 驱动加载事件 (.sys image load) - 供状态机规则 (BYOVD) 关联判定
#define ZETA_MSG_IMAGE_LOAD         7010  // driver loaded (PID, ImagePath=.sys)

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


