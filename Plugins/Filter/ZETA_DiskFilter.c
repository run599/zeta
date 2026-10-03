/*++
Module Name:
    ZETA_DiskFilter.c

Description:
    Standalone WDM disk class filter driver (NOT a minifilter).

    Intercepts IRP_MJ_WRITE / IRP_MJ_DEVICE_CONTROL / IRP_MJ_INTERNAL_DEVICE_CONTROL
    on \Device\HarddiskX\DR0 and blocks destructive raw-disk operations issued by
    untrusted processes:
      - writes intersecting the MBR / GPT primary header / partition table zone
      - writes intersecting the GPT backup zone at the end of the disk
      - partition-table rewrite IOCTLs (SET/DELETE DRIVE LAYOUT, CREATE_DISK, FORMAT_TRACKS)
      - SCSI / ATA pass-through carrying destructive CDB opcodes (WRITE, FORMAT UNIT,
        SANITIZE, WRITE SAME, UNMAP, SECURITY PROTOCOL OUT)

    Reports every intercepted event to user mode through a named control device so
    the UI can display a real protection state instead of guessing from the service
    start result.

    Control device : \Device\ZETA_DiskMon  ->  \??\ZETA_DiskMon
    IOCTL contract : see the IOCTL_DISK_* block below (shared with main.cpp).

    Purpose: rainbow-cat-style MBR / GPT wiper protection with observable state.
--*/

#include <ntifs.h>
#include <ntstatus.h>
#include <ntstrsafe.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <wdmsec.h>

/* ================================================================
   Debug logging
   ================================================================ */
#ifdef DBG
    #define DPF(_x_) DbgPrint _x_
#else
    #define DPF(_x_)
#endif

/* ================================================================
   Protocol contract (must stay in sync with CppLibs/ZETA/src/main.cpp)
   ================================================================ */
#define ZETA_MSG_DISK_WRITE        4001  /* 磁盘底层写拦截 */

#define DISKFILTER_TAG      'kSD#'
#define DISK_RING_SIZE      256
#define DISK_EVENT_MAX      512
#define DISK_MAX_DISKS      32

/* 保护区间: 磁盘起始 1MB (MBR + GPT 主头 + 分区表) 与末尾 1MB (GPT 备份) */
#define DISK_HEAD_ZONE      (1024ULL * 1024ULL)
#define DISK_TAIL_ZONE      (1024ULL * 1024ULL)

#define CTRL_NAME   L"\\Device\\ZETA_DiskMon"
#define CTRL_LINK   L"\\??\\ZETA_DiskMon"

/* 运行模式 */
#define DISK_MODE_BLOCK     0   /* 拦截 (默认) */
#define DISK_MODE_MONITOR   1   /* 仅监控并上报 */

/* ── 事件 Flags 语义 (DISK_EVENT.Flags) ────────────────────────────────
   驱动与用户态(main.cpp 的 DiskEvent 镜像)必须一致。 */
#define DISK_FLAG_OBSERVED      0   /* 命中但放行 (监控模式) */
#define DISK_FLAG_BLOCKED       1   /* 已拦截: IRP 以 STATUS_ACCESS_DENIED 完成 */
#define DISK_FLAG_TRUSTED_PASS  2   /* 可信磁盘工具豁免放行 —— 仍然上报, 保证可审计 */

/* ================================================================
   Event ring (驱动 -> 用户态)
   ================================================================ */
typedef struct _DISK_EVENT {
    LONGLONG  Ts;        /* 系统时间 (100ns) */
    ULONG     Pid;
    ULONG     Code;      /* ZETA_MSG_DISK_WRITE */
    ULONG     DiskNumber;
    ULONG     Flags;     /* DISK_FLAG_*: 0=仅记录 1=已拦截 2=可信放行 */
    ULONGLONG Offset;    /* 命中的字节偏移 */
    ULONG     Length;    /* 写入长度 */
    USHORT    Len;       /* Data 有效字节数 */
    UCHAR     Data[DISK_EVENT_MAX];   /* 保留: 进程映像名 / CDB 原始字节 */
} DISK_EVENT, *PDISK_EVENT;

typedef struct _DISK_RING {
    volatile LONG Head, Tail;
    DISK_EVENT    E[DISK_RING_SIZE];
} DISK_RING, *PDISK_RING;

/* ================================================================
   统计 (供 UI 显示真实防护状态)
   ================================================================ */
typedef struct _DISK_STATS {
    ULONG     Enabled;        /* 1 = 防护开启 */
    ULONG     Mode;           /* DISK_MODE_* */
    ULONG     DiskCount;      /* 当前挂接的物理磁盘数 */
    ULONG     BlockedCount;   /* 累计拦截次数 */
    ULONG     ObservedCount;  /* 累计仅记录次数 */
    ULONG     LastPid;
    ULONG     LastDiskNumber;
    ULONG     TrustedCount;   /* 可信工具豁免放行次数 (原 Reserved 字段, 布局不变) */
    ULONGLONG LastOffset;
    ULONGLONG LastTime;       /* 系统时间 (100ns) */
} DISK_STATS, *PDISK_STATS;

/* ================================================================
   IOCTL 契约
   ================================================================ */
#define IOCTL_DISK_GET_EVENT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_OUT_DIRECT, FILE_READ_DATA)
#define IOCTL_DISK_GET_STATS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_DISK_SET_ENABLED \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_DISK_SET_MODE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_DISK_REFRESH \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_DISK_RESET_STATS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, FILE_WRITE_DATA)

/* ================================================================
   Per-disk filter device extension
   ================================================================ */
typedef struct _FILTER_EXT {
    ULONG           Signature;
    PDEVICE_OBJECT  Self;
    PDEVICE_OBJECT  LowerDevice;
    PFILE_OBJECT    TargetFile;     /* 持有引用: 防止 lower device 悬空 */
    ULONG           DiskNumber;
    ULONGLONG       DiskLength;
    BOOLEAN         Attached;
    LIST_ENTRY      Link;
} FILTER_EXT, *PFILTER_EXT;

/* ================================================================
   Globals
   ================================================================ */
static PDRIVER_OBJECT   g_DriverObject   = NULL;
static PDEVICE_OBJECT   g_Ctrl           = NULL;   /* 控制设备 (有名) */
static UNICODE_STRING   g_Link;
static BOOLEAN          g_LinkOk         = FALSE;
static BOOLEAN          g_Unload         = FALSE;
static volatile PDISK_RING g_Ring        = NULL;

static LIST_ENTRY       g_DiskList;
static KSPIN_LOCK       g_ListLock;
static KSPIN_LOCK       g_RingLock;
static IO_REMOVE_LOCK   g_RemoveLock;

static volatile LONG    g_Enabled        = 1;      /* 防护开关 */
static volatile LONG    g_Mode           = DISK_MODE_BLOCK;
static volatile LONG    g_DiskCount      = 0;
static volatile LONG    g_BlockedCount   = 0;
static volatile LONG    g_ObservedCount  = 0;
static volatile LONG    g_TrustedCount   = 0;   /* 可信工具豁免放行次数 */
static volatile LONG    g_LastPid        = 0;
static volatile LONG    g_LastDiskNumber = 0;
static volatile LONG64  g_LastOffset     = 0;
static volatile LONG64  g_LastTime       = 0;

/* ================================================================
   Forward declarations
   ================================================================ */
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     DriverUnload;
DRIVER_DISPATCH   DispatchPassThrough;
DRIVER_DISPATCH   DispatchCreateClose;
DRIVER_DISPATCH   DispatchWrite;
DRIVER_DISPATCH   DispatchDeviceControl;
DRIVER_DISPATCH   DispatchInternalDeviceControl;
DRIVER_DISPATCH   DispatchPower;
DRIVER_DISPATCH   DispatchPnp;
DRIVER_DISPATCH   DispatchAny;

static NTSTATUS AttachToDisk(ULONG DiskNumber);
static VOID     DetachDisk(PFILTER_EXT ext, BOOLEAN WaitForIrps);
static VOID     DetachAllDisks(VOID);
static ULONG    EnumerateDisks(VOID);
static VOID     RemoveExtFromList(PFILTER_EXT ext);
static VOID     ReportEvent(ULONG DiskNumber, ULONG Flags, ULONGLONG Offset,
                            ULONG Length, PCSTR Reason);

/* ================================================================
   Trust check

   旧的路径白名单 (FsRtlIsNameInExpression 精确匹配 \Windows\ 之类) 从不生效:
   真实映像名形如 \Device\HarddiskVolume3\Windows\System32\x.exe, 永远匹配不上。
   改为按令牌判定, 与磁盘擦写的真实威胁模型一致:
     1) 进程令牌完整性级别 >= High  (管理员 / 提权进程)
     2) 进程令牌持有 SeBackupPrivilege (备份/镜像工具)
   ================================================================ */
#ifndef SECURITY_MANDATORY_HIGH_RID
    #define SECURITY_MANDATORY_HIGH_RID   0x3000
#endif
#ifndef SECURITY_MANDATORY_SYSTEM_RID
    #define SECURITY_MANDATORY_SYSTEM_RID 0x4000
#endif

/* ================================================================
   可信磁盘工具判定（2026-09 收窄）
   ----------------------------------------------------------------
   历史问题（上机实测确认）：原判定把"令牌完整性 >= High"直接当作可信 ——
   等价于放行任何提权进程。而打开 \\.\PhysicalDriveN 本身就必须有管理员权限，
   于是"有能力造成破坏的进程"恰好全被豁免：拦截路径对真正的威胁（提权后的
   勒索 / 引导型木马）完全失效。更糟的是豁免发生在事件上报之前，不留痕迹。

   现收窄为两条【同时】成立才算可信：
     ① 映像是 \Windows\System32\ 或 \Windows\SysWOW64\ 的【直接子项】
        （子目录不算 —— 例如 System32\WindowsPowerShell\...\powershell.exe 不在内）
     ② 基本文件名命中内置的磁盘工具白名单
   不再接受"仅持有 SeBackupPrivilege"作为豁免理由（管理员可自行启用该特权，
   因此它不是有效鉴别依据）。
   也不再查询令牌完整性级别 —— 见 IsTrustedDiskTool 内的详细说明：
   那次查询的分配/释放路径本身就是 2026-09-29 蓝屏的成因，且对本判据冗余。

   注: 被判定可信的调用仍然上报事件（DISK_FLAG_TRUSTED_PASS），保证可审计。
   ================================================================ */

/* 磁盘工具白名单：只覆盖"合法且必须直接操作裸盘 / 分区表"的系统工具。
   第三方镜像 / 克隆工具如需豁免，请连同其安装目录一并评估后再加入本表。 */
static const WCHAR* const g_TrustedDiskTools[] = {
    L"diskpart.exe",    /* 分区命令行工具 */
    L"vds.exe",         /* 虚拟磁盘服务 */
    L"vdsldr.exe",
    L"svchost.exe",     /* VDS / VSS 的服务宿主 (磁盘管理 MMC 经此下发) */
    L"mmc.exe",         /* 磁盘管理控制台 */
    L"vssvc.exe",       /* 卷影复制服务 */
    L"diskshadow.exe",
    L"wbengine.exe",    /* Windows 备份引擎 */
    L"wbadmin.exe",
    L"sdclt.exe",
    L"bootsect.exe",    /* 引导扇区修复 */
    L"bcdboot.exe",
    L"bcdedit.exe",
    L"dism.exe",
    L"chkdsk.exe",
};

/* 在 s(lenBytes 字节) 中大小写不敏感查找字面量 lit; 命中返回其【之后】的字符下标, 否则 -1 */
static LONG IndexAfterLiteral(PCWSTR s, USHORT lenBytes, PCWSTR lit)
{
    ULONG nChars = (ULONG)(lenBytes / sizeof(WCHAR));
    ULONG litLen = 0, i, j;

    while (lit[litLen]) litLen++;
    if (nChars < litLen) return -1;

    for (i = 0; i + litLen <= nChars; i++) {
        for (j = 0; j < litLen; j++) {
            WCHAR a = s[i + j], b = lit[j];
            if (a >= L'a' && a <= L'z') a = (WCHAR)(a - 32);
            if (b >= L'a' && b <= L'z') b = (WCHAR)(b - 32);
            if (a != b) break;
        }
        if (j == litLen) return (LONG)(i + litLen);
    }
    return -1;
}

/* 基本文件名是否在磁盘工具白名单内 */
static BOOLEAN IsTrustedToolName(PCUNICODE_STRING base)
{
    ULONG i;
    for (i = 0; i < RTL_NUMBER_OF(g_TrustedDiskTools); i++) {
        UNICODE_STRING want;
        ULONG n = 0;
        while (g_TrustedDiskTools[i][n]) n++;
        want.Buffer        = (PWCH)g_TrustedDiskTools[i];
        want.Length        = (USHORT)(n * sizeof(WCHAR));
        want.MaximumLength = want.Length;
        if (RtlEqualUnicodeString((PUNICODE_STRING)base, &want, TRUE)) return TRUE;
    }
    return FALSE;
}

static PUNICODE_STRING GetCurrentImageName(VOID);   /* 定义见下 */

static BOOLEAN IsTrustedDiskTool(VOID)
{
    PUNICODE_STRING img = NULL;
    BOOLEAN ok = FALSE;

    /* Idle / System: 内核自身的写不应被拦 */
    if ((ULONG_PTR)PsGetCurrentProcessId() <= 4) return TRUE;

    /* 映像名查询要求 PASSIVE_LEVEL; 更高 IRQL 无法可靠判定, 保守判为不可信 */
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FALSE;

    /*
      只依据【映像位置 + 白名单文件名】判定, 不再查询令牌完整性级别。

      为什么不查(2026-09-29 实测教训):
        原先的 SeQueryInformationToken(TokenIntegrityLevel) 需要在 __try 内分配
        TOKEN_MANDATORY_LABEL、在 __except 之后释放该指针、并读取非 volatile 的
        局部变量 label —— 这条路径自驱动写出来起【从未被执行过】(旧设计下提权
        进程会在 ShouldBlock 更早处被豁免, 而该函数又从未被触发), 一旦首次真正
        拦到一次危险 IOCTL, 立刻 0x3B(0xC0000005) 蓝屏:
          AV 于 nt!ExFreeHeapPool+0xad ← nt!ExFreePool ← ZETA_DiskFilter+0x22f4
          (即 `if (label) ExFreePool(label);` 一行)
        对一个"防护"驱动来说, 在拦截路径上引入这种未验证的分配/释放是不划算的。

      为什么不影响安全性:
        打开 \\.\PhysicalDriveN 本身就需要管理员权限, 因此"有能力造成破坏的进程"
        必然是高完整性进程 —— 用完整性级别做判据等于没有过滤。真正有效的收敛是
        本函数保留的两条: 映像必须【直接位于】System32/SysWOW64, 且文件名命中
        白名单。这两条比"任意提权进程"严格得多。
    */
    img = GetCurrentImageName();
    if (img && img->Buffer && img->Length >= sizeof(WCHAR)) {
        ULONG nChars = (ULONG)(img->Length / sizeof(WCHAR));
        LONG  after  = IndexAfterLiteral(img->Buffer, img->Length, L"\\Windows\\System32\\");
        if (after < 0)
            after = IndexAfterLiteral(img->Buffer, img->Length, L"\\Windows\\SysWOW64\\");
        if (after >= 0 && (ULONG)after < nChars) {
            UNICODE_STRING base;
            BOOLEAN hasSlash = FALSE;
            ULONG k;
            base.Buffer        = img->Buffer + after;
            base.Length        = (USHORT)((nChars - (ULONG)after) * sizeof(WCHAR));
            base.MaximumLength = base.Length;
            /* 直接子项判定: 剩余串中不得再出现反斜杠 */
            for (k = 0; k < (ULONG)(base.Length / sizeof(WCHAR)); k++) {
                if (base.Buffer[k] == L'\\') { hasSlash = TRUE; break; }
            }
            if (!hasSlash && IsTrustedToolName(&base)) ok = TRUE;
        }
    }
    if (img) ExFreePool(img);

    return ok;
}

/* 取当前进程映像名 (不含路径的设备部分), 用于事件上报; 调用方负责 ExFreePool */
static PUNICODE_STRING GetCurrentImageName(VOID)
{
    PUNICODE_STRING name = NULL;
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return NULL;
    if (!NT_SUCCESS(SeLocateProcessImageName(PsGetCurrentProcess(), &name)))
        return NULL;
    if (name && (!name->Buffer || name->Length == 0)) {
        ExFreePool(name);
        return NULL;
    }
    return name;
}

/* ================================================================
   Event ring helpers
   ================================================================ */
static VOID RingPush(DISK_EVENT *src)
{
    PDISK_RING ring = g_Ring;
    KIRQL irql;
    LONG head, next;

    if (!ring || g_Unload) return;

    KeAcquireSpinLock(&g_RingLock, &irql);
    head = ring->Head;
    next = (head + 1) & (DISK_RING_SIZE - 1);
    if (next == ring->Tail)
        ring->Tail = (ring->Tail + 1) & (DISK_RING_SIZE - 1);  /* 覆盖最旧 */
    ring->E[head] = *src;
    MemoryBarrier();
    ring->Head = next;
    KeReleaseSpinLock(&g_RingLock, irql);
}

/* 在 dst 缓冲区尾部追加一个 UNICODE_STRING, 返回新的字节长度 (不含终止 0) */
static USHORT TryAppendUnicode(PUCHAR dst, USHORT capacity, USHORT used, PCUNICODE_STRING src)
{
    USHORT room;

    if (!src || !src->Buffer || src->Length == 0) return used;
    /* 预留 2 字节给终止符 */
    if (used + 2 >= capacity) return used;
    room = (USHORT)(capacity - 2 - used);
    if (src->Length <= room) {
        RtlCopyMemory(dst + used, src->Buffer, src->Length);
        used = (USHORT)(used + src->Length);
    } else {
        /* 截断: 按 2 字节字符边界向下取整 */
        USHORT copy = (USHORT)(room & ~1u);
        if (copy == 0) return used;
        RtlCopyMemory(dst + used, src->Buffer, copy);
        used = (USHORT)(used + copy);
    }
    /* 始终保证 NUL 结尾 */
    *(PWCH)(dst + used) = L'\0';
    return used;
}

/* 组装并投递一条事件 */
static VOID ReportEvent(ULONG DiskNumber, ULONG Flags, ULONGLONG Offset,
                        ULONG Length, PCSTR Reason)
{
    DISK_EVENT ev;
    UNICODE_STRING reason = {0};
    ANSI_STRING ansi;
    PUNICODE_STRING img = NULL;
    USHORT used = 0;

    RtlZeroMemory(&ev, sizeof(ev));
    KeQuerySystemTime((PLARGE_INTEGER)&ev.Ts);
    ev.Pid        = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    ev.Code       = ZETA_MSG_DISK_WRITE;
    ev.DiskNumber = DiskNumber;
    ev.Flags      = Flags;
    ev.Offset     = Offset;
    ev.Length     = Length;

    /*
      Data 布局: UTF-16LE "<进程映像名> | <原因>" (以 NUL 结尾, Len 为字节数)

      IRQL 约束(重要): 本段需要分配内存 —— GetCurrentImageName 内部走
      SeLocateProcessImageName, RtlAnsiStringToUnicodeString 走分页池。
      而 ReportEvent 会被 DispatchWrite / DispatchInternalDeviceControl 调用,
      这两条路径可能运行在 DISPATCH_LEVEL(存储栈下发的内部 IOCTL) ——
      在 DISPATCH_LEVEL 分配分页池会直接 bugcheck。故只在 PASSIVE_LEVEL 组装
      字符串; 更高 IRQL 下仅上报数值字段, 确保拦截路径本身绝不出错。
    */
    if (KeGetCurrentIrql() <= PASSIVE_LEVEL) {
        img = GetCurrentImageName();
        used = TryAppendUnicode(ev.Data, DISK_EVENT_MAX, used, img);
        if (used > 0) {
            static const WCHAR kSep[] = L" | ";
            UNICODE_STRING sep;
            sep.Buffer = (PWCH)kSep;
            sep.Length = (USHORT)(sizeof(kSep) - sizeof(WCHAR));
            sep.MaximumLength = sep.Length;
            used = TryAppendUnicode(ev.Data, DISK_EVENT_MAX, used, &sep);
        }
        if (img) { ExFreePool(img); img = NULL; }

        RtlInitAnsiString(&ansi, Reason);
        if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&reason, &ansi, TRUE))) {
            used = TryAppendUnicode(ev.Data, DISK_EVENT_MAX, used, &reason);
            RtlFreeUnicodeString(&reason);
        }
    }
    ev.Len = used;

    /*
      统计: 每次上报都累计, 便于 UI 显示真实拦截/监控计数。
      Flags 决定归属 —— 不能再写成"Flags 非 0 即拦截": DISK_FLAG_TRUSTED_PASS(2)
      表示放行, 若按旧逻辑会计入 BlockedCount 造成拦截数虚高。
      LastOffset 只在非 0 时更新 (offset==0 是正常的 MBR 命中值, 用 LastTime 区分)。
    */
    if (Flags == DISK_FLAG_BLOCKED)           InterlockedIncrement(&g_BlockedCount);
    else if (Flags == DISK_FLAG_TRUSTED_PASS) InterlockedIncrement(&g_TrustedCount);
    else                                      InterlockedIncrement(&g_ObservedCount);
    InterlockedExchange((PLONG)&g_LastPid, (LONG)ev.Pid);
    InterlockedExchange((PLONG)&g_LastDiskNumber, (LONG)DiskNumber);
    InterlockedExchange64((PLONG64)&g_LastOffset, (LONG64)Offset);
    InterlockedExchange64((PLONG64)&g_LastTime, (LONG64)ev.Ts);

    RingPush(&ev);
}

/* ================================================================
   受保护区判定

   旧实现只判 offset 恰好等于 0 或 -1, 导致:
     - 写入区间跨过 LBA0 (offset>0 但覆盖 MBR) 放行
     - GPT 主头 (LBA1) / GPT 备份 (盘尾) / 分区表扇区 全部放行
   现改为「写入区间与受保护区相交」判定, 并用 FileObject->CurrentByteOffset
   正确解析 FILE_USE_FILE_POINTER_POSITION, 避免顺序写 raw disk 被误判。
   ================================================================ */
static BOOLEAN RangeIntersects(ULONGLONG start, ULONG length, ULONGLONG zoneStart, ULONGLONG zoneEnd)
{
    ULONGLONG end;

    if (length == 0) return FALSE;
    if (zoneEnd <= zoneStart) return FALSE;

    end = start + (ULONGLONG)length;        /* 64 位回绕: 溢出视为溢出, 下面单独处理 */
    if (end < start) return TRUE;           /* 回绕 => 覆盖极大区间, 视为危险 */

    return (start < zoneEnd) && (end > zoneStart);
}

/* 返回 TRUE 表示命中受保护区 */
static BOOLEAN IsProtectedDiskRange(ULONGLONG offset, ULONG length, ULONGLONG diskLength)
{
    /* 起始 1MB: MBR + GPT 主头 + 分区表 */
    if (RangeIntersects(offset, length, 0, DISK_HEAD_ZONE)) return TRUE;

    /* 末尾 1MB: GPT 备份头 + 备份分区表 */
    if (diskLength > DISK_HEAD_ZONE) {
        if (RangeIntersects(offset, length, diskLength - DISK_TAIL_ZONE, diskLength))
            return TRUE;
    }
    return FALSE;
}

/* ================================================================
   SCSI / ATA CDB 解析: 只拦「会改盘」的命令, 放行 SMART/IDENTIFY 等只读查询
   ================================================================ */
static BOOLEAN AtaCommandWrites(UCHAR op)
{
    switch (op) {
    case 0x30: case 0x31: case 0x32: case 0x33:   /* WRITE SECTOR(S) */
    case 0x34: case 0x35: case 0x36: case 0x37:   /* WRITE SECTOR(S) EXT */
    case 0x38: case 0x39: case 0x3A: case 0x3B:   /* WRITE DMA */
    case 0x3C: case 0x3D: case 0x3E: case 0x3F:   /* WRITE VERIFY / MULTIPLE */
    case 0x40:                                    /* READ VERIFY SECTORS */
    case 0x5D:                                    /* TRUSTED RECEIVE */
    case 0x91:                                    /* INITIALIZE DEVICE PARAMETERS */
    case 0x92: case 0x93:                         /* DOWNLOAD MICROCODE (DMA) */
    case 0x9F:                                    /* CFA WRITE / hibernate */
    case 0xF0:                                    /* SECURITY SET PASSWORD */
    case 0xF1: case 0xF2: case 0xF3: case 0xF4:   /* SECURITY ERASE/DISABLE/FREEZE */
    case 0xF5: case 0xF6:                         /* SECURITY FREEZE / DISABLE */
        return TRUE;
    default:
        /* 只读命令 (IDENTIFY 0xEC, SMART 0xB0, READ 0x20/0x24/0x25...) 一律放行 */
        return FALSE;
    }
}

/*
   解析 CDB。返回 TRUE 表示该命令具有破坏性 (需按信任度决定放行/拦截)。
   outDesc 写入可读的原因串 (调用方提供 >= 32 字节)。
*/
static BOOLEAN CdbIsDestructive(const UCHAR *cdb, ULONG cdbLen, PCSTR *outDesc)
{
    UCHAR op;

    if (!cdb || cdbLen == 0) return FALSE;
    op = cdb[0];

    switch (op) {
    case 0x04: {  /* FORMAT UNIT (也用于 SCSI low-level format) */
        *outDesc = "SCSI FORMAT UNIT";
        return TRUE;
    }
    case 0x0A:    /* WRITE(6) */
    case 0x0C:    /* WRITE(12) */
    case 0x2A:    /* WRITE(10) */
    case 0x8A:    /* WRITE(16) */
    case 0xAA: {  /* WRITE(12) 长格式 */
        *outDesc = "SCSI WRITE";
        return TRUE;
    }
    case 0x41: {  /* WRITE SAME(10/16): 常用于整盘填充/擦写 */
        *outDesc = "SCSI WRITE SAME";
        return TRUE;
    }
    case 0x42: {  /* UNMAP: 批量丢弃数据 (TRIM, 恶意可覆盖分区表) */
        *outDesc = "SCSI UNMAP";
        return TRUE;
    }
    case 0x48: {  /* SANITIZE: 整盘擦除 (SSD secure erase) */
        *outDesc = "SCSI SANITIZE";
        return TRUE;
    }
    case 0xB5: {  /* SECURITY PROTOCOL OUT: secure erase / TCG 擦除 */
        *outDesc = "SCSI SECURITY PROTOCOL OUT";
        return TRUE;
    }
    case 0xA1:    /* ATA PASS-THROUGH(12): 命令在 CDB[2] */
    case 0x85: {  /* ATA PASS-THROUGH(16): 命令在 CDB[2] */
        UCHAR ata;
        if (cdbLen < 3) return FALSE;
        ata = cdb[2];
        if (AtaCommandWrites(ata)) {
            *outDesc = "ATA PASS-THROUGH (write)";
            return TRUE;
        }
        return FALSE;
    }
    default:
        return FALSE;
    }
}

/* 从 METHOD_BUFFERED 输入取 pass-through 结构并判定 */
static BOOLEAN PassThroughIsDestructive(PIRP Irp, ULONG ioctl, PCSTR *outDesc)
{
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.InputBufferLength;

    if (!buf) return FALSE;

    if (ioctl == IOCTL_SCSI_PASS_THROUGH_DIRECT) {
        PSCSI_PASS_THROUGH_DIRECT p = (PSCSI_PASS_THROUGH_DIRECT)buf;
        if (inLen < sizeof(SCSI_PASS_THROUGH_DIRECT)) return FALSE;
        return CdbIsDestructive(p->Cdb, sizeof(p->Cdb), outDesc);
    }
    if (ioctl == IOCTL_SCSI_PASS_THROUGH) {
        PSCSI_PASS_THROUGH p = (PSCSI_PASS_THROUGH)buf;
        if (inLen < sizeof(SCSI_PASS_THROUGH)) return FALSE;
        return CdbIsDestructive(p->Cdb, sizeof(p->Cdb), outDesc);
    }
    /*
       ATA_PASS_THROUGH(_DIRECT) 没有 CDB 字段: ATA 命令寄存器位于
       CurrentTaskFile[6] (Features/SectorCount/SectorNumber/CylLow/CylHigh/
       DriveHead/Command/Reserved)。
    */
    if (ioctl == IOCTL_ATA_PASS_THROUGH_DIRECT) {
        PATA_PASS_THROUGH_DIRECT p = (PATA_PASS_THROUGH_DIRECT)buf;
        if (inLen < sizeof(ATA_PASS_THROUGH_DIRECT)) return FALSE;
        if (AtaCommandWrites(p->CurrentTaskFile[6])) {
            *outDesc = "ATA PASS-THROUGH DIRECT (write)";
            return TRUE;
        }
        return FALSE;
    }
    if (ioctl == IOCTL_ATA_PASS_THROUGH) {
        PATA_PASS_THROUGH_EX p = (PATA_PASS_THROUGH_EX)buf;
        if (inLen < sizeof(ATA_PASS_THROUGH_EX)) return FALSE;
        if (AtaCommandWrites(p->CurrentTaskFile[6])) {
            *outDesc = "ATA PASS-THROUGH (write)";
            return TRUE;
        }
        return FALSE;
    }
    return FALSE;
}

/* ================================================================
   通用: 判定一次操作是否应被拦截, 需要时上报事件
   返回 TRUE 表示已拦截 (调用方需以 STATUS_ACCESS_DENIED 完成 IRP)
   ================================================================ */
static BOOLEAN ShouldBlock(PDEVICE_OBJECT DeviceObject, ULONGLONG offset,
                           ULONG length, PCSTR reason)
{
    PFILTER_EXT ext = (PFILTER_EXT)DeviceObject->DeviceExtension;
    ULONG diskNo = (ext && ext->Signature == DISKFILTER_TAG) ? ext->DiskNumber : 0;
    ULONG mode   = (ULONG)InterlockedCompareExchange((PLONG)&g_Mode, 0, 0);
    ULONG enabled= (ULONG)InterlockedCompareExchange((PLONG)&g_Enabled, 0, 0);
    BOOLEAN trusted;

    if (!enabled) return FALSE;                 /* 防护已关闭: 不属于防护事件, 不记录 */

    /*
      可信判定不再"静默放行": 先算出结论, 之后无论放行还是拦截都上报事件。
      修复前 IsTrustedProcess() 命中即 return FALSE, 而且发生在 ReportEvent 之前,
      导致提权进程的裸盘写在【监控模式下也完全不留痕】—— 属于审计盲区。
    */
    trusted = IsTrustedDiskTool();

    if (mode == DISK_MODE_MONITOR) {
        /* 监控模式: 一律只记录, 用不同 Flags 区分"可信豁免"与"本应拦截的命中" */
        ReportEvent(diskNo, trusted ? DISK_FLAG_TRUSTED_PASS : DISK_FLAG_OBSERVED,
                    offset, length, reason);
        return FALSE;
    }

    if (trusted) {
        /* 白名单磁盘工具: 放行, 但留痕 (DISK_FLAG_TRUSTED_PASS) 供审计 */
        ReportEvent(diskNo, DISK_FLAG_TRUSTED_PASS, offset, length, reason);
        return FALSE;
    }

    ReportEvent(diskNo, DISK_FLAG_BLOCKED, offset, length, reason);
    return TRUE;
}

/* 以 STATUS_ACCESS_DENIED 完成 IRP */
static NTSTATUS DenyIrp(PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_ACCESS_DENIED;
}

/* ================================================================
   DispatchCreateClose — 转发到下层磁盘设备
   ================================================================ */
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFILTER_EXT ext = (PFILTER_EXT)DeviceObject->DeviceExtension;
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDevice, Irp);
}

/* ================================================================
   DispatchPassThrough — 无检查转发
   ================================================================ */
NTSTATUS DispatchPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFILTER_EXT ext = (PFILTER_EXT)DeviceObject->DeviceExtension;
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDevice, Irp);
}

/* ================================================================
   DispatchWrite — 拦截受保护区写入
   ================================================================ */
NTSTATUS DispatchWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFILTER_EXT ext = (PFILTER_EXT)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    LONGLONG offset = irpSp->Parameters.Write.ByteOffset.QuadPart;
    ULONG length = irpSp->Parameters.Write.Length;

    if (g_Unload || !ext || !ext->Attached || !ext->LowerDevice)
        return DenyIrp(Irp);

    /* 解析 FILE_USE_FILE_POINTER_POSITION: 顺序写 raw disk 常见, 需取真实偏移 */
    if (offset == FILE_USE_FILE_POINTER_POSITION || offset == (LONGLONG)-1) {
        if (irpSp->FileObject)
            offset = irpSp->FileObject->CurrentByteOffset.QuadPart;
        else
            offset = FILE_USE_FILE_POINTER_POSITION;
    }

    DPF(("ZETA_DiskFilter: Write Disk%lu offset=0x%llx len=%lu\n",
         ext->DiskNumber, offset, length));

    /* 无法确定偏移 (仍为 -1): 只上报不拦截, 避免误杀顺序写工具 */
    if (offset != FILE_USE_FILE_POINTER_POSITION && length > 0 &&
        IsProtectedDiskRange((ULONGLONG)offset, length, ext->DiskLength)) {
        if (ShouldBlock(DeviceObject, (ULONGLONG)offset, length, "disk protected zone write"))
            return DenyIrp(Irp);
    } else if (offset == FILE_USE_FILE_POINTER_POSITION && length > 0) {
        /* 仅观测 */
        ReportEvent(ext->DiskNumber, 0, 0, length, "raw disk sequential write (observed)");
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDevice, Irp);
}

/* ================================================================
   危险 IOCTL 清单 (分区表改写 / 格式化)
   ================================================================ */
static BOOLEAN IsDestructiveLayoutIoctl(ULONG code, PCSTR *outDesc)
{
    switch (code) {
    case IOCTL_DISK_SET_DRIVE_LAYOUT_EX:
        *outDesc = "IOCTL_DISK_SET_DRIVE_LAYOUT_EX"; return TRUE;
    case IOCTL_DISK_SET_DRIVE_LAYOUT:
        *outDesc = "IOCTL_DISK_SET_DRIVE_LAYOUT"; return TRUE;
    case IOCTL_DISK_DELETE_DRIVE_LAYOUT:
        *outDesc = "IOCTL_DISK_DELETE_DRIVE_LAYOUT"; return TRUE;
    case IOCTL_DISK_CREATE_DISK:
        *outDesc = "IOCTL_DISK_CREATE_DISK"; return TRUE;
    case IOCTL_DISK_FORMAT_TRACKS:
        *outDesc = "IOCTL_DISK_FORMAT_TRACKS"; return TRUE;
    case IOCTL_DISK_FORMAT_TRACKS_EX:
        *outDesc = "IOCTL_DISK_FORMAT_TRACKS_EX"; return TRUE;
    default:
        return FALSE;
    }
}

/* 设备控制通用检查; 返回 TRUE 表示已拦截 */
static BOOLEAN CheckDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    PCSTR desc = NULL;

    if (IsDestructiveLayoutIoctl(code, &desc))
        return ShouldBlock(DeviceObject, 0, 0, desc);

    switch (code) {
    case IOCTL_SCSI_PASS_THROUGH:
    case IOCTL_SCSI_PASS_THROUGH_DIRECT:
    case IOCTL_ATA_PASS_THROUGH:
    case IOCTL_ATA_PASS_THROUGH_DIRECT:
        if (PassThroughIsDestructive(Irp, code, &desc))
            return ShouldBlock(DeviceObject, 0, 0, desc);
        break;
    default:
        break;
    }
    return FALSE;
}

/* ================================================================
   DispatchDeviceControl — 用户态下发的 IOCTL
   ================================================================ */
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFILTER_EXT ext = (PFILTER_EXT)DeviceObject->DeviceExtension;

    if (g_Unload || !ext || !ext->Attached || !ext->LowerDevice)
        return DenyIrp(Irp);

    if (CheckDeviceControl(DeviceObject, Irp))
        return DenyIrp(Irp);

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDevice, Irp);
}

/* ================================================================
   DispatchInternalDeviceControl — 内核组件直通 (旧实现完全未挂载)
   ================================================================ */
NTSTATUS DispatchInternalDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFILTER_EXT ext = (PFILTER_EXT)DeviceObject->DeviceExtension;

    if (g_Unload || !ext || !ext->Attached || !ext->LowerDevice)
        return DenyIrp(Irp);

    if (CheckDeviceControl(DeviceObject, Irp))
        return DenyIrp(Irp);

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDevice, Irp);
}

/* ================================================================
   DispatchPower — 必须用 PoCallDriver
   ================================================================ */
NTSTATUS DispatchPower(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFILTER_EXT ext = (PFILTER_EXT)DeviceObject->DeviceExtension;
    if (!ext || !ext->LowerDevice) return DenyIrp(Irp);
    IoSkipCurrentIrpStackLocation(Irp);
    return PoCallDriver(ext->LowerDevice, Irp);
}

/* ================================================================
   DispatchCreateClose (磁盘过滤器侧) + PnP

   旧实现未处理 IRP_MJ_PNP: 磁盘热插拔/卸载时既不移除自己的过滤器设备,
   也不 detach, 留下悬空的 LowerDevice 指针 -> 0xCE / 蓝屏。
   ================================================================ */
static VOID RemoveExtFromList(PFILTER_EXT ext)
{
    KIRQL irql;
    if (!ext) return;
    KeAcquireSpinLock(&g_ListLock, &irql);
    if (ext->Attached) {
        ext->Attached = FALSE;
        RemoveEntryList(&ext->Link);
        InitializeListHead(&ext->Link);
        InterlockedDecrement(&g_DiskCount);
    }
    KeReleaseSpinLock(&g_ListLock, irql);
}

NTSTATUS DispatchPnp(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFILTER_EXT ext = (PFILTER_EXT)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    PDEVICE_OBJECT lower = (ext && ext->LowerDevice) ? ext->LowerDevice : NULL;
    NTSTATUS status;

    if (!lower) return DenyIrp(Irp);

    switch (irpSp->MinorFunction) {
    case IRP_MN_REMOVE_DEVICE:
        RemoveExtFromList(ext);
        /* 先摘除过滤层, 再把 IRP 交下去, 最后删除自己的设备对象 */
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(lower, Irp);
        IoDetachDevice(lower);
        if (ext && ext->TargetFile) {
            ObDereferenceObject(ext->TargetFile);
            ext->TargetFile = NULL;
        }
        IoDeleteDevice(DeviceObject);
        return status;

    case IRP_MN_SURPRISE_REMOVAL:
        RemoveExtFromList(ext);
        if (ext) ext->Attached = FALSE;   /* 不再接收新 IRP */
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(lower, Irp);

    default:
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(lower, Irp);
    }
}

/* ================================================================
   磁盘长度查询 (同步下发 IOCTL_DISK_GET_LENGTH_INFO)
   用于判定末尾 1MB 的 GPT 备份区, 旧实现完全不知道盘有多大。
   ================================================================ */
static ULONGLONG QueryDiskLength(PDEVICE_OBJECT targetDev, PFILE_OBJECT fileObj)
{
    KEVENT ev;
    IO_STATUS_BLOCK iosb;
    PIRP irp;
    PIO_STACK_LOCATION next;
    GET_LENGTH_INFORMATION len;
    ULONGLONG result = 0;

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return 0;
    if (!targetDev || !fileObj) return 0;

    RtlZeroMemory(&len, sizeof(len));
    KeInitializeEvent(&ev, NotificationEvent, FALSE);

    irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_LENGTH_INFO,
                                        targetDev, NULL, 0,
                                        &len, sizeof(len), FALSE, &ev, &iosb);
    if (!irp) return 0;

    next = IoGetNextIrpStackLocation(irp);
    next->FileObject = fileObj;

    if (IoCallDriver(targetDev, irp) == STATUS_PENDING)
        KeWaitForSingleObject(&ev, Executive, KernelMode, FALSE, NULL);

    if (NT_SUCCESS(iosb.Status) && len.Length.QuadPart > 0)
        result = (ULONGLONG)len.Length.QuadPart;

    return result;
}

/* ================================================================
   列表辅助
   ================================================================ */
static BOOLEAN IsDiskAlreadyAttached(ULONG DiskNumber)
{
    PLIST_ENTRY e;
    KIRQL irql;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_ListLock, &irql);
    for (e = g_DiskList.Flink; e != &g_DiskList; e = e->Flink) {
        PFILTER_EXT x = CONTAINING_RECORD(e, FILTER_EXT, Link);
        if (x->DiskNumber == DiskNumber && x->Attached) { found = TRUE; break; }
    }
    KeReleaseSpinLock(&g_ListLock, irql);
    return found;
}

/* ================================================================
   AttachToDisk — 创建并挂接过滤器设备

   与旧实现的区别:
     - 保留 IoGetDeviceObjectPointer 得到的 fileObj 引用 (旧实现立刻
       ObDereferenceObject, 导致 LowerDevice 成悬空指针)
     - 继承下层 Flags/AlignmentRequirement, 不再硬编码 DO_DIRECT_IO
     - 查询磁盘真实长度, 用于末尾 GPT 备份区判定
   ================================================================ */
static NTSTATUS AttachToDisk(ULONG DiskNumber)
{
    WCHAR path[64];
    UNICODE_STRING name;
    PFILE_OBJECT fileObj = NULL;
    PDEVICE_OBJECT targetDev = NULL;
    PDEVICE_OBJECT filterDev = NULL;
    PFILTER_EXT ext;
    NTSTATUS status;
    KIRQL irql;

    if (g_Unload) return STATUS_DELETE_PENDING;
    if (IsDiskAlreadyAttached(DiskNumber)) return STATUS_SUCCESS;

    RtlStringCbPrintfW(path, sizeof(path), L"\\Device\\Harddisk%lu\\DR0", DiskNumber);
    RtlInitUnicodeString(&name, path);
    status = IoGetDeviceObjectPointer(&name, FILE_READ_ATTRIBUTES, &fileObj, &targetDev);
    if (!NT_SUCCESS(status)) {
        RtlStringCbPrintfW(path, sizeof(path), L"\\Device\\Harddisk%lu\\Partition0", DiskNumber);
        RtlInitUnicodeString(&name, path);
        status = IoGetDeviceObjectPointer(&name, FILE_READ_ATTRIBUTES, &fileObj, &targetDev);
        if (!NT_SUCCESS(status)) return status;
    }

    status = IoCreateDevice(g_DriverObject, sizeof(FILTER_EXT), NULL,
                            targetDev->DeviceType, 0, FALSE, &filterDev);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(fileObj);
        return status;
    }

    ext = (PFILTER_EXT)filterDev->DeviceExtension;
    RtlZeroMemory(ext, sizeof(FILTER_EXT));
    ext->Signature  = DISKFILTER_TAG;
    ext->Self       = filterDev;
    ext->DiskNumber = DiskNumber;
    ext->TargetFile = fileObj;                          /* 持有引用 */
    ext->DiskLength = QueryDiskLength(targetDev, fileObj);
    InitializeListHead(&ext->Link);

    /* 继承下层设备的 I/O 特性 */
    filterDev->Flags = targetDev->Flags & (DO_DIRECT_IO | DO_BUFFERED_IO);
    filterDev->AlignmentRequirement = targetDev->AlignmentRequirement;
    filterDev->Characteristics = targetDev->Characteristics;

    ext->LowerDevice = IoAttachDeviceToDeviceStack(filterDev, targetDev);
    if (!ext->LowerDevice) {
        ext->TargetFile = NULL;
        IoDeleteDevice(filterDev);
        ObDereferenceObject(fileObj);
        return STATUS_UNSUCCESSFUL;
    }

    filterDev->Flags &= ~DO_DEVICE_INITIALIZING;
    ext->Attached = TRUE;

    KeAcquireSpinLock(&g_ListLock, &irql);
    InsertTailList(&g_DiskList, &ext->Link);
    InterlockedIncrement(&g_DiskCount);
    KeReleaseSpinLock(&g_ListLock, irql);

    DPF(("ZETA_DiskFilter: ATTACHED Harddisk%lu len=%llu\n", DiskNumber, ext->DiskLength));
    return STATUS_SUCCESS;
}

/* ================================================================
   卸载时的设备回收: 先摘栈, 待 IRP 排空后再删除设备对象
   ================================================================ */
static PDEVICE_OBJECT g_DyingDevices[DISK_MAX_DISKS];
static ULONG          g_DyingCount = 0;

static VOID DetachAllDisks(VOID)
{
    PLIST_ENTRY e;
    PFILTER_EXT ext;
    KIRQL irql;

    KeAcquireSpinLock(&g_ListLock, &irql);
    while (!IsListEmpty(&g_DiskList)) {
        e = RemoveHeadList(&g_DiskList);
        ext = CONTAINING_RECORD(e, FILTER_EXT, Link);
        ext->Attached = FALSE;
        InitializeListHead(&ext->Link);

        /* 先摘除设备栈: 新 IRP 不再路由到本过滤器 */
        if (ext->LowerDevice) {
            IoDetachDevice(ext->LowerDevice);
            ext->LowerDevice = NULL;
        }
        if (ext->TargetFile) {
            ObDereferenceObject(ext->TargetFile);
            ext->TargetFile = NULL;
        }
        if (g_DyingCount < DISK_MAX_DISKS && ext->Self)
            g_DyingDevices[g_DyingCount++] = ext->Self;
    }
    InterlockedExchange(&g_DiskCount, 0);
    InitializeListHead(&g_DiskList);
    KeReleaseSpinLock(&g_ListLock, irql);
}

/* IRP 排空后才可安全删除设备对象 */
static VOID DeleteDyingDevices(VOID)
{
    ULONG i;
    for (i = 0; i < g_DyingCount; i++) {
        if (g_DyingDevices[i]) {
            IoDeleteDevice(g_DyingDevices[i]);
            g_DyingDevices[i] = NULL;
        }
    }
    g_DyingCount = 0;
}

/* ================================================================
   EnumerateDisks — 逐个尝试, 失败不中断

   旧实现遇到第一个空洞就 break, 导致后面的磁盘全部不设防。
   ================================================================ */
static ULONG EnumerateDisks(VOID)
{
    ULONG i, ok = 0;

    for (i = 0; i < DISK_MAX_DISKS; i++) {
        if (NT_SUCCESS(AttachToDisk(i))) ok++;
    }
    return ok;
}

/* ================================================================
   DispatchControl — 控制设备 (\Device\ZETA_DiskMon) 的 IOCTL 接口
   ================================================================ */
static NTSTATUS DispatchControl(PDEVICE_OBJECT Dev, PIRP Irp)
{
    PIO_STACK_LOCATION s;
    UCHAR mj;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    UNREFERENCED_PARAMETER(Dev);

    if (g_Unload || !NT_SUCCESS(IoAcquireRemoveLock(&g_RemoveLock, Irp))) {
        Irp->IoStatus.Status = STATUS_DELETE_PENDING;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_DELETE_PENDING;
    }

    s = IoGetCurrentIrpStackLocation(Irp);
    mj = s->MajorFunction;

    if (mj == IRP_MJ_CREATE || mj == IRP_MJ_CLOSE) {
        status = STATUS_SUCCESS;
        goto done;
    }

    if (mj == IRP_MJ_DEVICE_CONTROL) {
        ULONG code   = s->Parameters.DeviceIoControl.IoControlCode;
        ULONG inLen  = s->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outLen = s->Parameters.DeviceIoControl.OutputBufferLength;

        switch (code) {

        case IOCTL_DISK_GET_EVENT: {
            PVOID ob = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
            PDISK_RING ring = g_Ring;
            if (ob && ring && outLen >= sizeof(DISK_EVENT)) {
                KIRQL x;
                KeAcquireSpinLock(&g_RingLock, &x);
                if (ring->Head != ring->Tail) {
                    LONG t = ring->Tail;
                    RtlCopyMemory(ob, &ring->E[t], sizeof(DISK_EVENT));
                    ring->Tail = (t + 1) & (DISK_RING_SIZE - 1);
                    Irp->IoStatus.Information = sizeof(DISK_EVENT);
                    status = STATUS_SUCCESS;
                } else {
                    status = STATUS_NO_MORE_ENTRIES;
                }
                KeReleaseSpinLock(&g_RingLock, x);
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        }

        case IOCTL_DISK_GET_STATS: {
            if (Irp->AssociatedIrp.SystemBuffer && outLen >= sizeof(DISK_STATS)) {
                PDISK_STATS st = (PDISK_STATS)Irp->AssociatedIrp.SystemBuffer;
                RtlZeroMemory(st, sizeof(DISK_STATS));
                st->Enabled        = (ULONG)InterlockedCompareExchange((PLONG)&g_Enabled, 0, 0);
                st->Mode           = (ULONG)InterlockedCompareExchange((PLONG)&g_Mode, 0, 0);
                st->DiskCount      = (ULONG)InterlockedCompareExchange((PLONG)&g_DiskCount, 0, 0);
                st->BlockedCount   = (ULONG)InterlockedCompareExchange((PLONG)&g_BlockedCount, 0, 0);
                st->ObservedCount  = (ULONG)InterlockedCompareExchange((PLONG)&g_ObservedCount, 0, 0);
        st->TrustedCount   = (ULONG)InterlockedCompareExchange((PLONG)&g_TrustedCount, 0, 0);
                st->LastPid        = (ULONG)InterlockedCompareExchange((PLONG)&g_LastPid, 0, 0);
                st->LastDiskNumber = (ULONG)InterlockedCompareExchange((PLONG)&g_LastDiskNumber, 0, 0);
                st->LastOffset     = (ULONGLONG)InterlockedCompareExchange64((PLONG64)&g_LastOffset, 0, 0);
                st->LastTime       = (ULONGLONG)InterlockedCompareExchange64((PLONG64)&g_LastTime, 0, 0);
                Irp->IoStatus.Information = sizeof(DISK_STATS);
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        }

        case IOCTL_DISK_SET_ENABLED: {
            if (Irp->AssociatedIrp.SystemBuffer && inLen >= sizeof(ULONG)) {
                ULONG v = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
                InterlockedExchange(&g_Enabled, v ? 1 : 0);
                Irp->IoStatus.Information = sizeof(ULONG);
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        }

        case IOCTL_DISK_SET_MODE: {
            if (Irp->AssociatedIrp.SystemBuffer && inLen >= sizeof(ULONG)) {
                ULONG v = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
                InterlockedExchange(&g_Mode, v ? DISK_MODE_MONITOR : DISK_MODE_BLOCK);
                Irp->IoStatus.Information = sizeof(ULONG);
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        }

        case IOCTL_DISK_REFRESH:
            EnumerateDisks();
            status = STATUS_SUCCESS;
            break;

        case IOCTL_DISK_RESET_STATS:
            InterlockedExchange(&g_BlockedCount, 0);
            InterlockedExchange(&g_ObservedCount, 0);
            InterlockedExchange(&g_TrustedCount, 0);
            status = STATUS_SUCCESS;
            break;

        default:
            break;
        }
    }

done:
    Irp->IoStatus.Status = status;
    IoReleaseRemoveLock(&g_RemoveLock, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ================================================================
   DispatchAny — 统一入口 (控制设备与磁盘过滤器设备共用)
   ================================================================ */
NTSTATUS DispatchAny(PDEVICE_OBJECT Dev, PIRP Irp)
{
    PIO_STACK_LOCATION s;

    if (Dev == g_Ctrl) return DispatchControl(Dev, Irp);

    s = IoGetCurrentIrpStackLocation(Irp);
    switch (s->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:                   return DispatchCreateClose(Dev, Irp);
    case IRP_MJ_WRITE:                   return DispatchWrite(Dev, Irp);
    case IRP_MJ_DEVICE_CONTROL:          return DispatchDeviceControl(Dev, Irp);
    case IRP_MJ_INTERNAL_DEVICE_CONTROL: return DispatchInternalDeviceControl(Dev, Irp);
    case IRP_MJ_PNP:                     return DispatchPnp(Dev, Irp);
    case IRP_MJ_POWER:                   return DispatchPower(Dev, Irp);
    default:                             return DispatchPassThrough(Dev, Irp);
    }
}

/* ================================================================
   DriverUnload
   ================================================================ */
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("ZETA_DiskFilter: DriverUnload\n");

    g_Unload = TRUE;

    /* 1) 摘除所有磁盘过滤层 (不再接收新 IRP) */
    DetachAllDisks();

    /* 2) 等所有在途 IRP 完成 */
    IoReleaseRemoveLockAndWait(&g_RemoveLock, (PVOID)(ULONG_PTR)DISKFILTER_TAG);

    /* 3) 删除控制设备与符号链接 */
    if (g_LinkOk) {
        IoDeleteSymbolicLink(&g_Link);
        g_LinkOk = FALSE;
    }
    if (g_Ctrl) {
        IoDeleteDevice(g_Ctrl);
        g_Ctrl = NULL;
    }

    /* 4) 现在可以安全删除磁盘过滤设备对象 */
    DeleteDyingDevices();

    /* 5) 释放事件环形缓冲 */
    if (g_Ring) {
        ExFreePoolWithTag((PVOID)g_Ring, DISKFILTER_TAG);
        g_Ring = NULL;
    }
}

/* ================================================================
   DriverEntry
   ================================================================ */
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING ctrlName;
    ULONG i;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("ZETA_DiskFilter: DriverEntry\n");

    g_DriverObject = DriverObject;

    InitializeListHead(&g_DiskList);
    KeInitializeSpinLock(&g_ListLock);
    KeInitializeSpinLock(&g_RingLock);
    IoInitializeRemoveLock(&g_RemoveLock, DISKFILTER_TAG, 0, 0);
    g_Unload = FALSE;
    g_DyingCount = 0;
    g_Ctrl = NULL;
    g_LinkOk = FALSE;

    g_Ring = (PDISK_RING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(DISK_RING), DISKFILTER_TAG);
    if (!g_Ring) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_Ring, sizeof(DISK_RING));

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = DispatchAny;
    DriverObject->DriverUnload = DriverUnload;

    /* 控制设备: 仅 SYSTEM / Administrators 可打开, 防止低权限进程关掉磁盘防护 */
    RtlInitUnicodeString(&ctrlName, CTRL_NAME);
    status = IoCreateDeviceSecure(DriverObject, 0, &ctrlName,
                                  FILE_DEVICE_UNKNOWN, 0, FALSE,
                                  &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
                                  NULL, &g_Ctrl);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ZETA_DiskFilter: IoCreateDeviceSecure failed 0x%08X\n", status);
        ExFreePoolWithTag((PVOID)g_Ring, DISKFILTER_TAG);
        g_Ring = NULL;
        return status;
    }

    RtlInitUnicodeString(&g_Link, CTRL_LINK);
    status = IoCreateSymbolicLink(&g_Link, &ctrlName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ZETA_DiskFilter: IoCreateSymbolicLink failed 0x%08X\n", status);
        IoDeleteDevice(g_Ctrl);
        g_Ctrl = NULL;
        ExFreePoolWithTag((PVOID)g_Ring, DISKFILTER_TAG);
        g_Ring = NULL;
        return status;
    }
    g_LinkOk = TRUE;

    /* 枚举已存在的物理磁盘; 单个失败不中断 (空洞磁盘不影响后续磁盘) */
    i = EnumerateDisks();
    DbgPrint("ZETA_DiskFilter: attached %lu disk(s)\n", i);

    return STATUS_SUCCESS;
}
