// =============================================================================
// ProtectProcessDkom.cpp -- EPROCESS Protection Field DKOM
//
// Unorthodox self-protection: Bypass CI signing checks by directly writing
// the EPROCESS Protection field to promote ZETA.exe to PPL level.
//
// Principle:
//   EPROCESS has a PS_PROTECTION byte near its end. Setting it through
//   NtSetInformationProcess(ProcessProtectionInfo) triggers CI signing checks.
//   But writing it directly from kernel mode bypasses ALL signing checks.
//
//   PPL level = (Signer << 3) | Type
//   Type=2(ProtectedLight), Signer=1(Antimalware) -> 0x0A
//
// Effect:
//   - OpenProcess(PROCESS_TERMINATE) returns ACCESS_DENIED
//   - PROCESS_VM_WRITE / PROCESS_CREATE_THREAD blocked
//   - ProcessHacker/Task Manager cannot kill ZETA.exe
//
// Compatibility:
//   - Win10 2004~22H2:  offset 0x87A
//   - Win11 21H2~24H2:  offset 0x8DA/0x8F2
//   Auto-detected via RtlGetVersion. 100% effective without HVCI.
// =============================================================================

#include "DriverCommon.h"

// ZwAdjustPrivilegesToken is not auto-declared in all WDK configs
extern "C" NTSTATUS NTAPI ZwAdjustPrivilegesToken(
    _In_ HANDLE TokenHandle,
    _In_ BOOLEAN DisableAllPrivileges,
    _In_opt_ PTOKEN_PRIVILEGES NewState,
    _In_ ULONG BufferLength,
    _Out_opt_ PTOKEN_PRIVILEGES PreviousState,
    _Out_opt_ PULONG ReturnLength
);

// =============================================================================
// PS_PROTECTION (undocumented, from ntifs.h)
// =============================================================================
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type  : 3;  // 0=None, 1=Protected, 2=ProtectedLight(PPL)
            UCHAR Signer: 5;  // 0=Authenticode, 1=Antimalware, 5=Windows, 6=Tcb
        };
    };
} PS_PROTECTION;

// PPL level constants
// PPL Antimalware = Type=2, Signer=1
#define PPL_ANTIMALWARE     ((UCHAR)((1 << 3) | 2))   // 0x0A
// PPL Windows = Type=2, Signer=5
#define PPL_WINDOWS         ((UCHAR)((5 << 3) | 2))   // 0x2A
// PPL Tcb = Type=2, Signer=6
#define PPL_TCB             ((UCHAR)((6 << 3) | 2))   // 0x32

// EPROCESS Protection field offsets (by Windows version)
#define EPROT_OFFSET_WIN10_2004   0x87A   // Win10 20H1~22H2 (19041~19045)
#define EPROT_OFFSET_WIN11        0x8DA   // Win11 21H2+ (22000+)
#define EPROT_OFFSET_WIN11_24H2   0x8F2   // Win11 24H2 (26100)
#define EPROT_OFFSET_UNKNOWN      0x87A   // fallback

// Watchdog globals
static HANDLE            g_DkomWatchdogThread = NULL;
static KEVENT            g_DkomWatchdogStopEvent;
static volatile BOOLEAN  g_DkomWatchdogRunning = FALSE;
static volatile BOOLEAN  g_DkomProtectionActive = FALSE;

// 用户态 PDB 解析下发的偏移覆盖 (0 = 未设置, 回退硬编码表)。
// 通过 ZETA_CMD_SET_PROTECTION_OFFSET 由 ZETA.exe 启动时下发。
static volatile ULONG    g_ProtectionOffsetOverride = 0;

// =============================================================================
// P0-自保护功能探针 (2026-10-02)
//
// 【为什么不用"查回调项字段"的写法】—— 2026-10-02 对抗分析结论(样本 E:\远控\cs)：
//   · 主流"摘 Ob 回调"实现(RemoveObCallbacks) 不注销注册句柄、不破坏链表结构,
//     只把每个回调项的 +0x10 / +0x14 两个 DWORD 清零;
//   · 于是 g_ObRegistrationHandle 仍非 NULL, 任何"查句柄是否为空"的存在性判据
//     都会判定为正常 —— 而保护实际已死(这正是本文件原第 ④ 项判据的缺陷);
//   · 而且只要判据依赖结构偏移, 对手换个偏移即可绕过(该样本自己就因为硬编码
//     Win10 22H2 偏移而不可移植)。
//   ⇒ 改用【功能探针】: 主动发起一次必然经过该回调的操作, 看回调是否仍被调用。
//     不依赖任何偏移, 对下列手法表现【完全一致】:
//       清零回调项字段 / ObUnRegisterCallbacks / 替换函数指针 / 改 Operations 位
//     —— 全部表现为"探针不命中"。
//
// 【防误报设计 —— 2026-10-02 二次改造: 由"首次不命中即停用"改为"交叉表决"】
//
//   ⚠ 已被证伪的旧设计(不要改回去): 旧实现是"UNKNOWN 状态首次不命中 →
//     立即标 UNSUPPORTED 并永不告警"。它的致命面是: 攻击者只要在 watchdog
//     第一次探测【之前】把回调摘掉, 探针的首次观测就是"未命中", 于是被判成
//     "本机不适用"而【整个开机周期静默停用】—— 最该报警的那一击反而变成永不
//     报警。实测样本 E:\远控\cs 的时序恰好来得及: 它 LoadHPDriver 成功后立刻
//     RemoveObCallbacks(), 而 watchdog 周期是 5 秒。
//
//   现在的规则(交叉表决): "本机不适用"是关于【ZETA 自身机制】的断言, 必须有
//   独立旁证才允许下 —— 单条探针的未命中不足以支撑它。判 UNSUPPORTED 需同时满足:
//     ① 该机制在启动时【没有】注册成功   (注册状态=真值, ProbeMechanismRegistered)
//     ② 另外两条探针【没有】任何一条曾命中过 (框架级旁证, ProbePeersValidated)
//     ③ 已走过 PROBE_RETIRE_GRACE_ROUNDS 轮观察窗(给同伴探针留出校验时间)
//   只要任一条件不成立, 未命中就按【已被外部禁用】处理, 走连续失败计数并上报。
//   判定停用时还会额外发一条"没有任何探针校验通过"的全局告警, 让"全盲"这个
//   状态本身可见, 而不是静默变成"一切正常"。
//
//   时序前提(已核实, 不依赖猜测): watchdog 不在 DriverEntry 里启动, 而是在
//   InitializeDkomProcessProtection() 里 —— 该函数按注释"必须等 ZETA.exe 连上
//   由 PortConnect 调用", 即远晚于 DriverEntry 中的 ObRegisterCallbacks /
//   FltStartFiltering / CmRegisterCallbackEx。所以首轮探针运行时三个注册标志
//   早已落定, 不存在"注册动作还没做完"导致的假阴性。
// =============================================================================

volatile LONG g_ObProbeArmed             = 0;
volatile LONG g_ObProbeHits              = 0;
volatile LONG g_FileProbeArmed           = 0;
volatile LONG g_FileProbeHits            = 0;
volatile LONG g_RegProbeArmed            = 0;
volatile LONG g_RegProbeHits             = 0;
volatile LONG g_SelfIntegrityTotalFails  = 0;
volatile LONG g_KernelTamperSuspectCount = 0;
volatile LONG g_RogueDriverCount         = 0;

#define PROBE_HEALTH_UNKNOWN      0
#define PROBE_HEALTH_OK           1
#define PROBE_HEALTH_UNSUPPORTED  2

typedef struct _PROBE_STATE {
    volatile LONG Health;
    volatile LONG ConsecFails;
    // 2026-10-02 交叉表决新增:
    volatile LONG EverValidated;    // 本探针是否曾命中过 (作为同伴旁证的来源)
    volatile LONG FirstMissRound;   // 首次未命中所处的 watchdog 轮次 (0=尚未发生)
} PROBE_STATE;

typedef struct _PROBE_RESULT {
    ULONG Probed;
    ULONG Hits;
} PROBE_RESULT;

static PROBE_STATE g_ObProbeState   = { PROBE_HEALTH_UNKNOWN, 0, 0, 0 };
static PROBE_STATE g_FileProbeState = { PROBE_HEALTH_UNKNOWN, 0, 0, 0 };
static PROBE_STATE g_RegProbeState  = { PROBE_HEALTH_UNKNOWN, 0, 0, 0 };

// 三条探针的汇总表 —— 交叉表决要跨探针互相看"谁曾命中过" (见 ProbePeersValidated)。
// 用 sizeof 推长度, 不依赖 RTL_NUMBER_OF / ARRAYSIZE 这类宏可用性。
static PROBE_STATE* g_AllProbeStates[] = {
    &g_ObProbeState, &g_FileProbeState, &g_RegProbeState
};

// watchdog 周期计数器: 每个周期 +1 一次, 供"观察窗"判定用。
static volatile LONG g_ProbeRound = 0;

// 曾校验通过(至少命中一次)的探针条数。判停用时若仍为 0, 说明"全盲"。
static volatile LONG g_ProbeEverValidated = 0;

// "没有任何探针校验通过"这条全局告警只发一次 (用 CAS 保证)。
static volatile LONG g_AllProbesUnvalidatedAlerted = 0;

// 观察窗与上报阈值
#define PROBE_FAIL_THRESHOLD        3   // 连续未命中轮数 → 上报 (与改造前一致, 不提高灵敏度)
#define PROBE_RETIRE_GRACE_ROUNDS   6   // 允许判 UNSUPPORTED 前的最短观察轮数 (≈30s @5s/轮)

// 消息缓冲必须是非 const 静态数组: SendMessageToUser 形参是 PWCHAR(非 const),
// 直接传字面量编不过 (同类注释见 ProtectProcess.cpp g_KhMsgProc)。
static WCHAR g_MsgObIntegrity[]   = L"自保护失效: Ob 句柄保护回调已被外部禁用 (疑似 BYOVD 摘除保护)";
static WCHAR g_MsgFileIntegrity[] = L"自保护失效: 文件过滤回调已被外部禁用 (执法点失守)";
static WCHAR g_MsgRegIntegrity[]  = L"自保护失效: 注册表保护回调已被外部禁用";

// ── 探针日志字面量 + 组件标签 (2026-10-02) ──
// 为什么探针结果必须走用户态通道:
//   DbgPrint 只进内核调试器(DbgView/WinDbg), 不进 ZETA_CPP.log —— 只靠 DbgPrint
//   等于运维侧看不见探针是死是活, 这个功能就白做了。
//
// ⚠ 刻意不做任何格式化: 直接 SendMessageToUser(ZETA_MSG_LOG, ...) 送固定字面量。
//   原因: DriverLog 内部是 RtlStringCbVPrintfW, 它对 %s/%S 的宽窄约定与 DbgPrint
//   不一致, 传错会打乱码甚至越界读。本仓库既有调用点也都只用 %u/%X 数值 —— 沿用。
#define PROBE_TAG_OB    1
#define PROBE_TAG_FILE  2
#define PROBE_TAG_REG   3
#define PROBE_TAG_GLOBAL 4   // 非单探针的全局告警 (如"三条全废、一条都没校验通过")

static WCHAR g_LogObOk[]     = L"[SelfIntegrity] OB 句柄回调探针 —— 校验通过(回调在线)";
static WCHAR g_LogObSkip[]   = L"[SelfIntegrity] OB 句柄回调探针 —— 本机制不适用, 已停用(不会误报)";
static WCHAR g_LogObFail[]   = L"[SelfIntegrity] OB 句柄回调探针 —— 未命中! 回调疑似已被外部禁用";
static WCHAR g_LogFileOk[]   = L"[SelfIntegrity] 文件过滤回调探针 —— 校验通过(回调在线)";
static WCHAR g_LogFileSkip[] = L"[SelfIntegrity] 文件过滤回调探针 —— 本机制不适用, 已停用(不会误报)";
static WCHAR g_LogFileFail[] = L"[SelfIntegrity] 文件过滤回调探针 —— 未命中! 执法点疑似已被禁用";
static WCHAR g_LogRegOk[]    = L"[SelfIntegrity] 注册表回调探针 —— 校验通过(回调在线)";
static WCHAR g_LogRegSkip[]  = L"[SelfIntegrity] 注册表回调探针 —— 本机制不适用, 已停用(不会误报)";
static WCHAR g_LogRegFail[]  = L"[SelfIntegrity] 注册表回调探针 —— 未命中! 回调疑似已被外部禁用";
// 全局告警: 三条探针全被停用且没有任何一条曾校验通过 —— 自保护状态不可知。
// 这条的存在意义就是让"全盲"可见, 而不是像改造前那样静默停用。
static WCHAR g_LogGlobalUnvalidated[] =
    L"[SelfIntegrity] ⚠警告: 没有任何探针校验通过 —— 全部探针已停用, 自保护状态不可知";

// Kind: 0=校验通过  1=不适用(停用)  2=未命中
static VOID LogProbeEvent(ULONG Tag, ULONG Kind) {
    PWCHAR msg = NULL;
    if (Tag == PROBE_TAG_OB) {
        msg = (Kind == 0) ? g_LogObOk : (Kind == 1) ? g_LogObSkip : g_LogObFail;
    } else if (Tag == PROBE_TAG_FILE) {
        msg = (Kind == 0) ? g_LogFileOk : (Kind == 1) ? g_LogFileSkip : g_LogFileFail;
    } else if (Tag == PROBE_TAG_REG) {
        msg = (Kind == 0) ? g_LogRegOk : (Kind == 1) ? g_LogRegSkip : g_LogRegFail;
    } else if (Tag == PROBE_TAG_GLOBAL) {
        msg = g_LogGlobalUnvalidated;   // 只有告警一种形态
    }
    if (msg && KeGetCurrentIrql() == PASSIVE_LEVEL) {
        SendMessageToUser(ZETA_MSG_LOG, GlobalData.ZetaPid, msg,
                          (USHORT)((wcslen(msg) + 1) * sizeof(WCHAR)));
    }
}

// WDK 未声明 (ApcHook.cpp 里的声明在 ZETA_ENABLE_SSDT=0 时整文件空编, 不可复用)
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

// RTL_PROCESS_MODULES 布局 (与 ApcHook.cpp 的 ZETA_SYS_MODULE_* 同构, 名字不同以免冲突)
typedef struct _ZETA_MODULE_ENTRY {
    PVOID  Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} ZETA_MODULE_ENTRY, *PZETA_MODULE_ENTRY;

typedef struct _ZETA_MODULE_INFO {
    ULONG Count;
    ULONG Unused;
    ZETA_MODULE_ENTRY Module[1];
} ZETA_MODULE_INFO, *PZETA_MODULE_INFO;

// =============================================================================
// 反制: 探针失效时做内核模块表比对, 定位"刚被加载的可疑驱动"
//
// 依据: 摘 Ob 回调/关过滤器都必须先在目标机上跑起一个持有任意内核写的驱动 ——
//       它必然出现在 SystemModuleInformation 里; 而攻击时间窗只有几秒到几十秒,
//       所以"模块表尾部(最近加载)项"是高置信度候选。
// 职责边界: 驱动只负责【定位 + 上报候选路径】, 签名/路径判定与隔离由用户态
//       (已有 remediateProcess 闭环) 完成 —— 驱动里不做签名校验。
// =============================================================================
static volatile ULONG g_LastModuleCount = 0;

#define ZETA_TAMPER_REPORT_MAX 4

static VOID RetaliateOnModuleDiff(void) {
    ULONG size = 0;
    NTSTATUS st = ZwQuerySystemInformation(11 /* SystemModuleInformation */, NULL, 0, &size);
    if (size == 0 || size > 16 * 1024 * 1024) {
        DbgPrint("ZETA: SelfIntegrity: module query size invalid (%lu)\n", size);
        return;
    }

    PZETA_MODULE_INFO info = (PZETA_MODULE_INFO)ZetaAllocate(size);
    if (!info) {
        DbgPrint("ZETA: SelfIntegrity: module snapshot alloc FAILED (%lu bytes)\n", size);
        return;
    }

    st = ZwQuerySystemInformation(11, info, size, &size);
    if (!NT_SUCCESS(st) || info->Count == 0) {
        DbgPrint("ZETA: SelfIntegrity: module query FAILED (0x%08X)\n", st);
        ZetaFree(info);
        return;
    }

    InterlockedIncrement(&g_KernelTamperSuspectCount);
    g_DriverState.KernelTamperSuspectCount =
        (ULONG)InterlockedCompareExchange(&g_KernelTamperSuspectCount, 0, 0);

    ULONG prev = (ULONG)InterlockedCompareExchange((volatile LONG*)&g_LastModuleCount, 0, 0);
    DbgPrint("ZETA: SelfIntegrity: module count prev=%lu now=%lu\n", prev, info->Count);

    // 无论有无基线, 都对【最近加载的若干项】上报候选 —— 本函数只在探针连续 3 轮
    // 失效(已是强证据)时被调用, 尾部新项是最可能的攻击载体。
    ULONG report = (prev != 0 && info->Count > prev) ? (info->Count - prev) : 1;
    if (report == 0) report = 1;
    if (report > ZETA_TAMPER_REPORT_MAX) report = ZETA_TAMPER_REPORT_MAX;

    for (ULONG k = 0; k < report; k++) {
        ULONG idx = info->Count - 1 - k;
        PZETA_MODULE_ENTRY m = &info->Module[idx];

        // FullPathName 从 0 开始就是完整路径(含 \SystemRoot\...), 用它给用户态判签名
        WCHAR widePath[260];
        ULONG i = 0;
        for (; i < 255; i++) {
            UCHAR c = m->FullPathName[i];
            widePath[i] = (WCHAR)c;
            if (c == 0) break;
        }
        widePath[255] = L'\0';

        DbgPrint("ZETA: SelfIntegrity: candidate module #%lu: %s (ImageBase=%p size=%lu)\n",
                 idx, m->FullPathName, m->ImageBase, m->ImageSize);

        if (KeGetCurrentIrql() == PASSIVE_LEVEL && widePath[0] != L'\0') {
            SendMessageToUser(ZETA_MSG_ROGUE_DRIVER_LOADED, GlobalData.ZetaPid,
                              widePath,
                              (USHORT)((wcslen(widePath) + 1) * sizeof(WCHAR)));
        }
    }
    InterlockedIncrement(&g_RogueDriverCount);

    g_LastModuleCount = info->Count;
    ZetaFree(info);
}

// =============================================================================
// ReportSelfIntegrityFailure -- 探针判定某组件已被外部禁用
// =============================================================================
VOID ReportSelfIntegrityFailure(PWCHAR Msg, PCSTR AnsiName, ULONG Probed, ULONG Hits) {
    DbgPrint("ZETA: SelfIntegrity: *** %s DISABLED *** (probe=%lu hits=%lu)\n",
             AnsiName, Probed, Hits);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return;   // 上报通道要求 <= PASSIVE

    SendMessageToUser(ZETA_MSG_SELF_INTEGRITY_FAIL, GlobalData.ZetaPid,
                      Msg, (USHORT)((wcslen(Msg) + 1) * sizeof(WCHAR)));

    RetaliateOnModuleDiff();
}

// =============================================================================
// 交叉表决的两个独立旁证源 (2026-10-02)
//
// CheckProbe 单靠自己【无法】区分"探针不适用"与"探针被攻击禁用了" —— 两者表现
// 完全一样(都是未命中)。所以引入两个独立旁证源做表决, 详见文件头"防误报设计"。
// =============================================================================

// 旁证 A: 该机制在启动时是否注册成功 (真值)
static BOOLEAN ProbeMechanismRegistered(ULONG Tag) {
    switch (Tag) {
    case PROBE_TAG_OB:
        // ⚠ 刻意不用 g_DriverState.ProcessProtectionOK —— 该字段在
        //   InitializeDkomProcessProtection() 里被复用成"PPL DKOM 成功"的语义
        //   (本文件 :890 置 TRUE / :931 置 FALSE), 与 Ob 回调是否注册不是一回事。
        //   Ob 注册状态的唯一可靠信号是注册句柄本身:
        //   ObRegisterCallbacks 成功 → 非 NULL; ObUnRegisterCallbacks 之后 → NULL。
        return (g_ObRegistrationHandle != NULL);

    case PROBE_TAG_FILE:
        // FilterStarted 只在 FltStartFiltering 成功后才置 TRUE (DriverEntry.cpp:1266)
        return (g_DriverState.FilterStarted != FALSE);

    case PROBE_TAG_REG:
        // RegistryProtectionOK 在 CmRegisterCallbackEx 成功后置 TRUE (DriverEntry.cpp:1356)
        return (g_DriverState.RegistryProtectionOK != FALSE);

    default:
        return FALSE;
    }
}

// 旁证 B: 另外两条探针里有没有任何一条曾命中过
static BOOLEAN ProbePeersValidated(const PROBE_STATE* Self) {
    for (ULONG i = 0; i < sizeof(g_AllProbeStates) / sizeof(g_AllProbeStates[0]); i++) {
        if (g_AllProbeStates[i] == Self) continue;
        if (InterlockedCompareExchange(&g_AllProbeStates[i]->EverValidated, 0, 0) != 0) {
            return TRUE;
        }
    }
    return FALSE;
}

// 全盲可见化: 一条都没校验通过就全被停用 —— 这个状态本身就异常, 必须留痕。
// 刻意【不】调 ReportSelfIntegrityFailure(): 那会连带触发 RetaliateOnModuleDiff()
// 去隔离模块, 而"机制未注册"更可能是本机安装/签名环境问题(例如测试签名等级不够
// 导致 ObRegisterCallbacks 被拒), 不是攻击, 不该反制。
static VOID ProbeAlertIfNothingValidated(VOID) {
    if (InterlockedCompareExchange(&g_ProbeEverValidated, 0, 0) != 0) return;
    if (InterlockedCompareExchange(&g_AllProbesUnvalidatedAlerted, 1, 0) != 0) return;
    DbgPrint("ZETA: SelfIntegrity: *** NO PROBE EVER VALIDATED *** "
             "all probes retired - protection state UNKNOWN\n");
    LogProbeEvent(PROBE_TAG_GLOBAL, 2);
}

// =============================================================================
// CheckProbe -- 探针健康状态机 (交叉表决版, 2026-10-02)
// =============================================================================
static VOID CheckProbe(PROBE_STATE* State, PCSTR AnsiName, PWCHAR Msg,
                       ULONG Tag, PROBE_RESULT r) {
    // ── 命中 → 回调仍在工作 ──
    if (r.Hits > r.Probed) {
        // 首次命中才计入"曾校验通过的探针数"(作为同伴旁证的来源)
        if (InterlockedCompareExchange(&State->EverValidated, 1, 0) == 0) {
            InterlockedIncrement(&g_ProbeEverValidated);
        }
        if (InterlockedCompareExchange(&State->Health, PROBE_HEALTH_OK,
                                       PROBE_HEALTH_UNKNOWN) == PROBE_HEALTH_UNKNOWN) {
            DbgPrint("ZETA: SelfIntegrity: %s probe VALIDATED\n", AnsiName);
            LogProbeEvent(Tag, 0);      // 用户态可见: 校验通过(仅首次报一次)
        }
        InterlockedExchange(&State->ConsecFails, 0);
        InterlockedExchange(&State->FirstMissRound, 0);
        return;
    }

    LONG health = InterlockedCompareExchange(&State->Health, 0, 0);
    if (health == PROBE_HEALTH_UNSUPPORTED) return;    // 已停用, 不再重复判定

    // ── 未命中 ──
    if (health == PROBE_HEALTH_UNKNOWN) {
        BOOLEAN registered = ProbeMechanismRegistered(Tag);
        BOOLEAN peerOk     = ProbePeersValidated(State);

        if (!registered && !peerOk) {
            // 两个旁证源都给不出"本机制本该工作"的证据 → 还不能下结论, 先走观察窗,
            // 等同伴探针校验通过(它们可能比本探针晚几轮才跑出结果)。
            LONG round = InterlockedCompareExchange(&g_ProbeRound, 0, 0);
            LONG first = InterlockedCompareExchange(&State->FirstMissRound, 0, 0);
            if (first == 0) {
                InterlockedCompareExchange(&State->FirstMissRound, round, 0);
                first = InterlockedCompareExchange(&State->FirstMissRound, 0, 0);
            }
            if (round - first < PROBE_RETIRE_GRACE_ROUNDS) {
                return;                 // 观察窗内: 既不告警也不停用
            }

            InterlockedExchange(&State->Health, PROBE_HEALTH_UNSUPPORTED);
            DbgPrint("ZETA: SelfIntegrity: %s probe UNSUPPORTED "
                     "(mechanism not registered, no peer validated) - disabled\n", AnsiName);
            LogProbeEvent(Tag, 1);          // 用户态可见: 该探针已停用(运维需要知道)
            ProbeAlertIfNothingValidated(); // 若三条全废 → 额外一条全局告警
            return;
        }

        // 有旁证 ⇒ 未命中不可能是"机制不适用", 直接按【已被外部禁用】处理,
        // 纳入下面的连续失败计数 —— 上报阈值与恢复路径保持原样, 不提高灵敏度。
        InterlockedExchange(&State->Health, PROBE_HEALTH_OK);
        DbgPrint("ZETA: SelfIntegrity: %s probe FIRST-MISS with corroboration "
                 "(registered=%u peerValidated=%u) -> treated as DISABLED\n",
                 AnsiName, (ULONG)registered, (ULONG)peerOk);
        health = PROBE_HEALTH_OK;
    }

    LONG fails = InterlockedIncrement(&State->ConsecFails);
    InterlockedIncrement(&g_SelfIntegrityTotalFails);
    g_DriverState.SelfIntegrityFailCount  = (ULONG)fails;
    g_DriverState.SelfIntegrityTotalFails =
        (ULONG)InterlockedCompareExchange(&g_SelfIntegrityTotalFails, 0, 0);

    DbgPrint("ZETA: SelfIntegrity: %s probe MISSED (consec=%ld)\n", AnsiName, fails);

    // 仅首次未命中 + 达到上报阈值时写用户态日志, 避免每 5 秒刷屏
    if (fails == 1) LogProbeEvent(Tag, 2);

    if (fails >= PROBE_FAIL_THRESHOLD) {
        ReportSelfIntegrityFailure(Msg, AnsiName, r.Probed, r.Hits);
        InterlockedExchange(&State->ConsecFails, 0);      // 上报后归零, 避免每轮刷屏
        g_DriverState.SelfIntegrityFailCount = 0;
    }
}

// =============================================================================
// 探针 ①: Ob 句柄保护回调
//
// 发起一次必然经过 PreOpenProcess 的句柄打开。内核态 ZwOpenProcess 同样触发 Ob
// 回调(走 KernelHandle=TRUE 分支), 而探针计数被放在两个回调的最前面, 所以一定
// 被计入。目标选 System(PID 4): 恒定存在、只读查询、无副作用。
// =============================================================================
static PROBE_RESULT ProbeObCallbacks(void) {
    PROBE_RESULT r;
    r.Probed = (ULONG)InterlockedCompareExchange(&g_ObProbeHits, 0, 0);

    HANDLE h = NULL;
    CLIENT_ID cid;
    cid.UniqueProcess = (HANDLE)4;
    cid.UniqueThread  = NULL;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    InterlockedExchange(&g_ObProbeArmed, 1);
    ZwOpenProcess(&h, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid);
    InterlockedExchange(&g_ObProbeArmed, 0);

    // 不看返回值: 即便打开失败(权限/状态), PreOperation 回调也已执行过。
    if (h) ZwClose(h);

    r.Hits = (ULONG)InterlockedCompareExchange(&g_ObProbeHits, 0, 0);
    return r;
}

// =============================================================================
// 探针 ②: 文件过滤(minifilter)回调
//
// 读方式打开一个恒定存在的系统文件 → 必然经过 ProtectFile_PreCreate。
// 只读、无写、无副作用。请求者模式为 KernelMode, 但探针计数在 PreCreate 最前面。
// =============================================================================
static PROBE_RESULT ProbeMinifilter(void) {
    PROBE_RESULT r;
    r.Probed = (ULONG)InterlockedCompareExchange(&g_FileProbeHits, 0, 0);

    UNICODE_STRING path;
    RtlInitUnicodeString(&path, L"\\SystemRoot\\system32\\ntoskrnl.exe");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;

    InterlockedExchange(&g_FileProbeArmed, 1);
    ZwOpenFile(&h, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb,
               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
               FILE_SYNCHRONOUS_IO_NONALERT);
    InterlockedExchange(&g_FileProbeArmed, 0);

    if (h) ZwClose(h);

    r.Hits = (ULONG)InterlockedCompareExchange(&g_FileProbeHits, 0, 0);
    return r;
}

// =============================================================================
// 探针 ③: 注册表回调
//
// 打开一个恒定存在的键 → 触发 RegistryCallback (RegNtPreOpenKey)。
// 纯打开、不写值, 零副作用(比写一个探针值干净)。
// 注: 若本机实测 RegNtPreOpenKey 不被派发, 首次校验会把它标为 UNSUPPORTED
//     并自动停用 —— 不会误报。
// =============================================================================
static PROBE_RESULT ProbeRegistryCallback(void) {
    PROBE_RESULT r;
    r.Probed = (ULONG)InterlockedCompareExchange(&g_RegProbeHits, 0, 0);

    UNICODE_STRING path;
    RtlInitUnicodeString(&path, L"\\Registry\\Machine\\SOFTWARE");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE hKey = NULL;

    InterlockedExchange(&g_RegProbeArmed, 1);
    ZwOpenKey(&hKey, KEY_READ, &oa);
    InterlockedExchange(&g_RegProbeArmed, 0);

    if (hKey) ZwClose(hKey);

    r.Hits = (ULONG)InterlockedCompareExchange(&g_RegProbeHits, 0, 0);
    return r;
}

// =============================================================================
// DkomSetProtectionOffset -- 接收用户态 PDB 解析的 Protection 字段偏移
//
// 优先级: PDB 解析(精确) > 硬编码表(按 build 分支)。
// 用户态用 dbghelp 从 ntoskrnl PDB 解析 _EPROCESS.Protection 偏移下发,
// 覆盖本驱动的硬编码猜测, 支持任意新 build。
// =============================================================================
NTSTATUS DkomSetProtectionOffset(ULONG Offset) {
    // 偏移合理性: 必须是 EPROCESS 中后段 (< 一页), 防止传错值导致越界写
    if (Offset < 0x100 || Offset > 0x1000) {
        DbgPrint("ZETA: DkomPPL: protection offset 0x%X out of range, rejected\n", Offset);
        return STATUS_INVALID_PARAMETER;
    }
    g_ProtectionOffsetOverride = Offset;
    DbgPrint("ZETA: DkomPPL: protection offset override = 0x%X (PDB resolved)\n", Offset);
    return STATUS_SUCCESS;
}

// =============================================================================
// DetectProtectionOffset -- choose offset by Windows build number
// (PDB 解析覆盖优先, 硬编码表兜底)
// =============================================================================
static ULONG DetectProtectionOffset() {
    ULONG ov = g_ProtectionOffsetOverride;
    if (ov != 0) return ov;  // 用户态 PDB 解析的精确偏移优先

    RTL_OSVERSIONINFOW ver = { sizeof(ver) };
    NTSTATUS status = RtlGetVersion(&ver);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ZETA: DkomPPL: RtlGetVersion failed (0x%08X)\n", status);
        return EPROT_OFFSET_UNKNOWN;
    }

    ULONG build = ver.dwBuildNumber;

    // Win11 24H2 (26100+)
    if (build >= 26100) return EPROT_OFFSET_WIN11_24H2;
    // Win11 21H2~23H2 (22000+)
    if (build >= 22000) return EPROT_OFFSET_WIN11;
    // Win10 2004~22H2 (19041+)
    if (build >= 19041) return EPROT_OFFSET_WIN10_2004;

    // Older/unknown builds
    DbgPrint("ZETA: DkomPPL: untested build %lu, trying offset 0x%X\n",
             build, EPROT_OFFSET_UNKNOWN);
    return EPROT_OFFSET_UNKNOWN;
}

// =============================================================================
// DkomSetProcessProtection -- core DKOM write
//
// Directly write the EPROCESS.Protection field, bypassing CI entirely.
// Protected by __try/__except against invalid offsets.
// =============================================================================
NTSTATUS DkomSetProcessProtection(PEPROCESS Process, UCHAR ProtectionLevel) {
    if (!Process) {
        DbgPrint("ZETA: DkomPPL: Process is NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    // P0-自伤免疫: ZETA 自己写 EPROCESS.Protection 字段, 置位标记,
    // 使监控逻辑识别为自保动作, 不当作外部 DKOM 篡改告警。
    g_SelfDkomInProgress = TRUE;

    ULONG protOffset = DetectProtectionOffset();

    __try {
        PUCHAR field = (PUCHAR)Process + protOffset;
        UCHAR oldValue = *field;

        if (oldValue == ProtectionLevel) {
            DbgPrint("ZETA: DkomPPL: already set at 0x%02X\n", ProtectionLevel);
            g_SelfDkomInProgress = FALSE;
            return STATUS_ALREADY_COMPLETE;
        }

        // If already has a different protection, don't overwrite
        if (oldValue != 0 && oldValue != ProtectionLevel) {
            PS_PROTECTION oldProt;
            oldProt.Level = oldValue;
            DbgPrint("ZETA: DkomPPL: already protected Type=%u Signer=%u (0x%02X), skip\n",
                     oldProt.Type, oldProt.Signer, oldValue);
            g_SelfDkomInProgress = FALSE;
            return STATUS_ALREADY_COMPLETE;
        }

        // DKOM write! Bypasses all CI checks.
        *field = ProtectionLevel;
        MemoryBarrier();

        // Verify
        UCHAR verifyValue = *field;
        if (verifyValue == ProtectionLevel) {
            PS_PROTECTION prot;
            prot.Level = ProtectionLevel;
            DbgPrint("ZETA: DkomPPL: PPL SET EPROCESS+0x%X "
                     "(Type=%u Signer=%u Level=0x%02X)\n",
                     protOffset, prot.Type, prot.Signer, ProtectionLevel);
            g_SelfDkomInProgress = FALSE;
            return STATUS_SUCCESS;
        } else {
            DbgPrint("ZETA: DkomPPL: write verify FAILED "
                     "(expected 0x%02X got 0x%02X)\n",
                     ProtectionLevel, verifyValue);
            g_SelfDkomInProgress = FALSE;
            return STATUS_UNSUCCESSFUL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("ZETA: DkomPPL: exception at EPROCESS+0x%X\n", protOffset);
        g_SelfDkomInProgress = FALSE;
        return STATUS_ACCESS_VIOLATION;
    }
}

// =============================================================================
// DkomQueryProtection -- read current protection level (no write)
// =============================================================================
NTSTATUS DkomQueryProtection(PEPROCESS Process, PUCHAR OutLevel,
                             PUCHAR OutType, PUCHAR OutSigner) {
    if (!Process || !OutLevel) return STATUS_INVALID_PARAMETER;

    ULONG protOffset = DetectProtectionOffset();

    __try {
        PS_PROTECTION prot;
        prot.Level = *(PUCHAR)((PUCHAR)Process + protOffset);

        *OutLevel = prot.Level;
        if (OutType)  *OutType = prot.Type;
        if (OutSigner) *OutSigner = prot.Signer;

        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }
}

// P0-3: DkomVerifyTokenPrivileges 前向声明（实现在文件末尾，watchdog 提前引用）
NTSTATUS DkomVerifyTokenPrivileges();

// =============================================================================
// DkomWatchdogThreadProc -- periodic PPL level verification
//
// On HVCI/Secure Kernel systems, the Protection field may get reset.
// This thread checks every 5 seconds and re-DKOM if needed.
// =============================================================================
static VOID DkomWatchdogThreadProc(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);
    LARGE_INTEGER interval;
    interval.QuadPart = -50000000LL; // 5 seconds

    DbgPrint("ZETA: DkomPPL: watchdog thread started\n");

    while (g_DkomWatchdogRunning) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -50000000LL;
        NTSTATUS waitStatus = KeWaitForSingleObject(
            &g_DkomWatchdogStopEvent,
            Executive, KernelMode, FALSE, &timeout);

        if (!g_DkomWatchdogRunning) break;
        if (waitStatus == STATUS_WAIT_0) break;  // stop event

        // 卸载守卫: 驱动卸载期间禁止任何恢复动作 (防恢复 SSDT hook / 重注册 OB 回调导致 0xCE)
        if (g_IsUnloading) break;

        // P0-1: watchdog 多合一校验
        // 进程保护开关关闭时不重写 PPL (允许系统正常管理 ZETA.exe)。
        // 但当开关开启时，除了 PPL 字段，还要校验其他防线的完整性：
        //   ② 驱动 DriverSection 仍存在 (驱动未被卸载)
        //   ③ APC SSDT 表项仍指向本驱动 handler (APC 钩子未被还原; SSDT 退役后不参与)
        //   ④ Ob 句柄保护回调【功能探针】仍命中 (2026-10-02 由"句柄非空"改造而来)
        //   ⑦ 文件过滤(minifilter)回调【功能探针】仍命中 (2026-10-02 新增)
        //   ⑧ 注册表保护回调【功能探针】仍命中 (2026-10-02 新增)
        // 任一异常即对应的恢复动作并上报。
        if (g_DkomProtectionActive && GlobalData.UserProcess && g_ProcessProtectEnabled) {
            // ── ① PPL 字段 ──
            UCHAR currentLevel = 0;
            UCHAR currentType = 0;
            UCHAR currentSigner = 0;
            NTSTATUS qs = DkomQueryProtection(GlobalData.UserProcess,
                                               &currentLevel,
                                               &currentType,
                                               &currentSigner);

            if (NT_SUCCESS(qs)) {
                if (currentLevel != PPL_ANTIMALWARE) {
                    DbgPrint("ZETA: DkomPPL: level RESET "
                             "(was 0x%02X, now 0x%02X). Re-DKOM...\n",
                             PPL_ANTIMALWARE, currentLevel);

                    NTSTATUS setSt = DkomSetProcessProtection(
                        GlobalData.UserProcess, PPL_ANTIMALWARE);

                    if (NT_SUCCESS(setSt) || setSt == STATUS_ALREADY_COMPLETE) {
                        DbgPrint("ZETA: DkomPPL: re-protection OK\n");
                    } else {
                        DbgPrint("ZETA: DkomPPL: re-protection FAILED (0x%08X)\n", setSt);
                    }
                }
            }

            // ── ② 驱动 DriverSection 存在性 ──
            // DriverSection 在 DriverEntry 后由内核填充；若驱动对象仍在但
            // DriverSection 被清零，说明 KLDR 条目被破坏，需重建 Flags。
            if (GlobalData.DriverObject && GlobalData.DriverObject->DriverSection == NULL) {
                DbgPrint("ZETA: DkomPPL: DriverSection MISSING. Re-DKOM sig flags...\n");
                NTSTATUS dsSt = DkomSetDriverSignatureFlags();
                if (NT_SUCCESS(dsSt)) {
                    DbgPrint("ZETA: DkomPPL: DriverSection rebuild OK\n");
                } else {
                    DbgPrint("ZETA: DkomPPL: DriverSection rebuild FAILED (0x%08X)\n", dsSt);
                }
            }

#if ZETA_ENABLE_SSDT
            // ── ③ APC SSDT 表项完整性 ──
            if (!ApcHook_IsTableIntact()) {
                DbgPrint("ZETA: DkomPPL: APC SSDT tampered. Re-applying handler...\n");
                // 重新定位并打表项 (ApcHook_Enable 幂等，会重设表项)
                // 系统调用号在 DriverEntry 已确定，这里用已缓存的索引重打。
                // 注意: 若系统调用号未知则跳过 (无法安全重定向)。
                // 通过重新启用恢复 (若已禁用则启用，若已激活则重设表项)。
                // ApcHook_Enable 内部已处理"已激活"幂等，这里直接调用以重设表项。
                // 但 ApcHook_Enable 需要系统调用号参数，watchdog 不持有。
                // 改用内部重打: 直接复用 g_KiServiceTable 与 g_ApcSyscallIndex。
                // （见 ApcHook_RestoreTableEntry 由 ApcHook.cpp 提供）
                ApcHook_RestoreTableEntry();
            }
#endif

            // 本轮探针轮次号 (2026-10-02 交叉表决): 三条探针共用同一轮次,
            // 用于判定"未命中的观察窗是否已足够长"。每个 watchdog 周期只 +1 一次,
            // 必须放在三条探针之前。
            InterlockedIncrement(&g_ProbeRound);

            // ── ④ Ob 句柄保护 ── (2026-10-02 改造: "句柄非空"存在性判据 → 功能探针)
            // 原判据只查 g_ObRegistrationHandle 是否为空。缺陷: 主流"摘 Ob 回调"实现
            // 只清零回调项字段、不注销句柄, 于是该判据判定为"正常"而保护实际已死
            // (详见本文件顶部"P0-自保护功能探针"说明)。
            if (g_ObRegistrationHandle == NULL) {
                // 句柄真的为空(被 ObUnRegisterCallbacks 注销 / 从未注册) → 走原恢复路径
                DbgPrint("ZETA: DkomPPL: Ob callback UNREGISTERED. Re-registering...\n");
                NTSTATUS obSt = InitializeProcessProtection();
                if (NT_SUCCESS(obSt)) {
                    DbgPrint("ZETA: DkomPPL: Ob callback re-registered OK\n");
                } else {
                    DbgPrint("ZETA: DkomPPL: Ob callback re-register FAILED (0x%08X)\n", obSt);
                }
            } else {
                // 句柄在, 但回调可能已被禁用 → 用功能探针判定
                PROBE_RESULT prOb = ProbeObCallbacks();
                CheckProbe(&g_ObProbeState, "ObCallback", g_MsgObIntegrity, PROBE_TAG_OB, prOb);
            }

            // ── ⑦ 文件过滤(minifilter)回调完整性 —— 2026-10-02 新增 ──
            // 这是 ZETA 唯一的强制执法点(所有文件 I/O 都经过它, 直接 syscall 也绕不过),
            // 此前完全没有完整性校验。
            {
                PROBE_RESULT prFile = ProbeMinifilter();
                CheckProbe(&g_FileProbeState, "Minifilter", g_MsgFileIntegrity, PROBE_TAG_FILE, prFile);
            }

            // ── ⑧ 注册表保护回调完整性 —— 2026-10-02 新增 ──
            {
                PROBE_RESULT prReg = ProbeRegistryCallback();
                CheckProbe(&g_RegProbeState, "RegistryCallback", g_MsgRegIntegrity, PROBE_TAG_REG, prReg);
            }

#if ZETA_ENABLE_SSDT
            // ── ⑤ UnloadGuard SSDT 表项完整性 ──
            if (UnloadGuard_IsActive() && !UnloadGuard_IsTableIntact()) {
                DbgPrint("ZETA: DkomPPL: UnloadGuard SSDT tampered. Re-applying...\n");
                UnloadGuard_RestoreTableEntry();
            }
#endif

            // ── ⑥ 令牌特权复查与重注入 ──
            NTSTATUS tknSt = DkomVerifyTokenPrivileges();
            if (!NT_SUCCESS(tknSt)) {
                DbgPrint("ZETA: DkomPPL: token privilege verify FAILED (0x%08X)\n", tknSt);
            }
        }
    }

    DbgPrint("ZETA: DkomPPL: watchdog thread exiting\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// =============================================================================
// DkomStartWatchdog -- create watchdog thread
// =============================================================================
NTSTATUS DkomStartWatchdog() {
    if (g_DkomWatchdogRunning) {
        return STATUS_ALREADY_COMPLETE;
    }

    KeInitializeEvent(&g_DkomWatchdogStopEvent, NotificationEvent, FALSE);
    g_DkomWatchdogRunning = TRUE;

    NTSTATUS status = PsCreateSystemThread(
        &g_DkomWatchdogThread,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        DkomWatchdogThreadProc,
        NULL);

    if (!NT_SUCCESS(status)) {
        DbgPrint("ZETA: DkomPPL: watchdog create FAILED (0x%08X)\n", status);
        g_DkomWatchdogRunning = FALSE;
        return status;
    }

    DbgPrint("ZETA: DkomPPL: watchdog thread created\n");
    return STATUS_SUCCESS;
}

// =============================================================================
// DkomStopWatchdog -- stop watchdog thread
// =============================================================================
VOID DkomStopWatchdog() {
    if (!g_DkomWatchdogRunning) return;

    g_DkomWatchdogRunning = FALSE;
    KeSetEvent(&g_DkomWatchdogStopEvent, 0, FALSE);

    if (g_DkomWatchdogThread) {
        PVOID threadObj = NULL;
        NTSTATUS status = ObReferenceObjectByHandle(
            g_DkomWatchdogThread, SYNCHRONIZE, *PsThreadType,
            KernelMode, &threadObj, NULL);

        if (NT_SUCCESS(status)) {
            KeWaitForSingleObject(threadObj, Executive, KernelMode, FALSE, NULL);
            ObDereferenceObject(threadObj);
        }

        ZwClose(g_DkomWatchdogThread);
        g_DkomWatchdogThread = NULL;
    }

    DbgPrint("ZETA: DkomPPL: watchdog thread stopped\n");
}

// =============================================================================
// DkomInjectTokenPrivileges -- inject SeTcbPrivilege into ZETA.exe token
//
// Gives ZETA.exe: SeTcbPrivilege, SeDebugPrivilege, SeTakeOwnershipPrivilege
// After this, ZETA.exe can OpenProcess(PROCESS_ALL_ACCESS) on ANY process
// including PPL-protected ones, and can manage other processes' PPL levels.
//
// Works because ZwAdjustPrivilegesToken from KernelMode bypasses the
// SeIncreaseQuotaPrivilege check (PreviousMode == KernelMode -> always pass).
// =============================================================================
NTSTATUS DkomInjectTokenPrivileges() {
    // P0-自伤免疫: ZETA 自己修改自身令牌特权, 置位标记 (虽非 EPROCESS/KLDR 字段,
    // 但令牌校验也是完整性监控的一环, 统一标记避免未来监控误报)。
    g_SelfDkomInProgress = TRUE;

    HANDLE procHandle = NULL;
    HANDLE tokenHandle = NULL;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;

    // 1. Open ZETA.exe process handle (from kernel mode -> no access check)
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)GlobalData.ZetaPid;
    cid.UniqueThread = NULL;

    NTSTATUS status = ZwOpenProcess(&procHandle, PROCESS_QUERY_INFORMATION,
                                     &oa, &cid);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ZETA: DkomTkn: ZwOpenProcess FAILED (0x%08X)\n", status);
        g_SelfDkomInProgress = FALSE;
        return status;
    }

    // 2. Open ZETA.exe's primary token
    status = ZwOpenProcessTokenEx(procHandle,
                                   TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                   OBJ_KERNEL_HANDLE, &tokenHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ZETA: DkomTkn: ZwOpenProcessTokenEx FAILED (0x%08X)\n", status);
        ZwClose(procHandle);
        g_SelfDkomInProgress = FALSE;
        return status;
    }

    // 3. Prepare privilege list
    // Privilege LUIDs are stable across all Windows versions:
    //   SeTcbPrivilege            = 7
    //   SeDebugPrivilege          = 20
    //   SeTakeOwnershipPrivilege  = 9
    //   SeLoadDriverPrivilege     = 10
    //   SeIncreaseQuotaPrivilege  = 5
    UCHAR privilegeCount = 5;
    // FIX(0x139): TOKEN_PRIVILEGES 内嵌数组只有 1 个 LUID_AND_ATTRIBUTES,
    // 直接写 5 个特权会越界 48 字节、破坏栈 cookie -> __report_gsfailure 0x139。
    // 改为分配足够大的局部缓冲, 以 PTOKEN_PRIVILEGES 访问。
    UCHAR tpBuf[sizeof(TOKEN_PRIVILEGES) + 4 * sizeof(LUID_AND_ATTRIBUTES)];
    RtlZeroMemory(tpBuf, sizeof(tpBuf));
    PTOKEN_PRIVILEGES tp = (PTOKEN_PRIVILEGES)tpBuf;
    tp->PrivilegeCount = privilegeCount;

    // SeIncreaseQuotaPrivilege (5) - needed to modify token privileges
    tp->Privileges[0].Luid.LowPart = 5;
    tp->Privileges[0].Luid.HighPart = 0;
    tp->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // SeTcbPrivilege (7) - act as part of OS, manage PPL protection
    tp->Privileges[1].Luid.LowPart = 7;
    tp->Privileges[1].Luid.HighPart = 0;
    tp->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;

    // SeTakeOwnershipPrivilege (9) - take ownership of objects
    tp->Privileges[2].Luid.LowPart = 9;
    tp->Privileges[2].Luid.HighPart = 0;
    tp->Privileges[2].Attributes = SE_PRIVILEGE_ENABLED;

    // SeLoadDriverPrivilege (10) - load/unload drivers
    tp->Privileges[3].Luid.LowPart = 10;
    tp->Privileges[3].Luid.HighPart = 0;
    tp->Privileges[3].Attributes = SE_PRIVILEGE_ENABLED;

    // SeDebugPrivilege (20) - debug any process
    tp->Privileges[4].Luid.LowPart = 20;
    tp->Privileges[4].Luid.HighPart = 0;
    tp->Privileges[4].Attributes = SE_PRIVILEGE_ENABLED;

    // 4. Enable privileges
    // From kernel mode, SeSinglePrivilegeCheck with PreviousMode=KernelMode
    // always passes, bypassing the SeIncreaseQuotaPrivilege requirement.
    status = ZwAdjustPrivilegesToken(tokenHandle, FALSE, tp, (ULONG)sizeof(tpBuf), NULL, NULL);

    if (NT_SUCCESS(status)) {
        DbgPrint("ZETA: DkomTkn: privileges injected "
                 "(Tcb+Debug+TakeOwnership+LoadDrv+IncQuota)\n");
    } else {
        // ZwAdjustPrivilegesToken returned the actual status
        DbgPrint("ZETA: DkomTkn: ZwAdjustPrivilegesToken FAILED (0x%08X)\n",
                 status);
    }

    ZwClose(tokenHandle);
    ZwClose(procHandle);
    g_SelfDkomInProgress = FALSE;
    return status;
}

// =============================================================================
// InitializeDkomProcessProtection -- external entry point
//
// Must be called after ZETA.exe connects (GlobalData.UserProcess != NULL).
// Called from PortConnect.
// =============================================================================
NTSTATUS InitializeDkomProcessProtection() {
    if (!GlobalData.UserProcess) {
        DbgPrint("ZETA: DkomPPL: UserProcess is NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    // 1. DKOM write Protection field -> PPL
    NTSTATUS status = DkomSetProcessProtection(
        GlobalData.UserProcess, PPL_ANTIMALWARE);

    if (NT_SUCCESS(status) || status == STATUS_ALREADY_COMPLETE) {
        g_DkomProtectionActive = TRUE;
        g_DriverState.ProcessProtectionOK = TRUE;
        g_DriverState.ProcessProtectionStatus = status;

        // 2. Start watchdog
        NTSTATUS wdSt = DkomStartWatchdog();
        if (!NT_SUCCESS(wdSt)) {
            DbgPrint("ZETA: DkomPPL: watchdog FAILED (0x%08X)\n", wdSt);
        }

        // 3. Inject SeTcbPrivilege + SeDebugPrivilege into ZETA.exe token
        // This lets ZETA.exe manage other processes and their PPL protection.
        NTSTATUS tknSt = DkomInjectTokenPrivileges();
        if (NT_SUCCESS(tknSt)) {
            DbgPrint("ZETA: DkomPPL: token privileges injected\n");
            DriverLog(GlobalData.ZetaPid,
                      L"PPL-DKOM: SeTcb+SeDebug+SeTakeOwnership "
                      L"injected - ZETA can now open any process");
        } else {
            DbgPrint("ZETA: DkomPPL: token injection FAILED (0x%08X)\n", tknSt);
            DriverLog(GlobalData.ZetaPid,
                      L"PPL-DKOM: token injection FAILED (0x%08lX)",
                      tknSt);
        }

        // 4. Log final level
        UCHAR level = 0, type = 0, signer = 0;
        if (NT_SUCCESS(DkomQueryProtection(GlobalData.UserProcess,
                                           &level, &type, &signer))) {
            DriverLog(GlobalData.ZetaPid,
                      L"PPL-DKOM: Type=%u Signer=%u Level=0x%02X - "
                      L"ZETA.exe is now protected",
                      type, signer, level);
        }

        DbgPrint("ZETA: DkomPPL: protection ACTIVE (PPL=0x%02X)\n",
                 PPL_ANTIMALWARE);
        return STATUS_SUCCESS;
    }

    // DKOM failed
    DbgPrint("ZETA: DkomPPL: DkomSetProcessProtection FAILED (0x%08X)\n", status);
    g_DriverState.ProcessProtectionOK = FALSE;
    g_DriverState.ProcessProtectionStatus = status;
    return status;
}

// =============================================================================
// UninitializeDkomProcessProtection -- cleanup on driver unload
// =============================================================================
VOID UninitializeDkomProcessProtection() {
    DkomStopWatchdog();
    g_DkomProtectionActive = FALSE;

    // We do NOT clear the Protection field --
    // it persists until ZETA.exe exits naturally.
    DbgPrint("ZETA: DkomPPL: uninitialized (PPL stays until process exits)\n");
}

// =============================================================================
// KLDR_DATA_TABLE_ENTRY (undocumented, from ntoskrnl.exe)
// Windows 11 25H2 结构 (sizeof = 0xA0):
//   偏移 0x00: InLoadOrderLinks (LIST_ENTRY, 16 bytes)
//   偏移 0x10: ExceptionTable (PVOID, 8 bytes)
//   偏移 0x18: ExceptionTableSize (ULONG, 4 bytes)
//   偏移 0x1C: GpValue (PVOID, 8 bytes) -- 注意对齐后偏移 0x20
//   偏移 0x28: NonPagedDebugInfo (PVOID, 8 bytes)
//   偏移 0x30: DllBase (PVOID, 8 bytes)
//   偏移 0x38: EntryPoint (PVOID, 8 bytes)
//   偏移 0x40: SizeOfImage (ULONG, 4 bytes)
//   偏移 0x48: FullDllName (UNICODE_STRING, 16 bytes)
//   偏移 0x58: BaseDllName (UNICODE_STRING, 16 bytes)
//   偏移 0x68: Flags (ULONG, 4 bytes) <-- ObRegisterCallbacks 检查此字段
//   偏移 0x6E: SignatureLevel union (USHORT, 4 bits + 3 bits + ...)
//
// MmVerifyCallbackFunctionCheckFlags 检查:
//   DriverSection->Flags & 0x20 (bit 5 = ProcessStaticImport)
//
// 关键偏移常量
#define KLDR_FLAGS_OFFSET         0x68  // Flags 字段偏移
#define KLDR_SIGNATURE_OFFSET     0x6E  // SignatureLevel 偏移
#define KLDR_CALLBACK_CHECK_FLAG  0x20  // ObRegisterCallbacks 检查的标志位

// =============================================================================
// DkomSetDriverSignatureFlags -- DKOM 设置驱动镜像 Flags |= 0x20
//
// 原理:
//   ObRegisterCallbacks 调用 MmVerifyCallbackFunctionCheckFlags(callback, 0x20)
//   MmVerifyCallbackFunctionCheckFlags 内部:
//     v6 = MiLookupDataTableEntry(callback_addr, 0)
//     if (v6 && (*(_DWORD *)(v6 + 0x68) & 0x20) != 0) return 1
//
//   只需找到 ZETA_Drv.sys 的 KLDR_DATA_TABLE_ENTRY，设置 Flags |= 0x20
//
// 返回: STATUS_SUCCESS 如果成功设置
// =============================================================================
NTSTATUS DkomSetDriverSignatureFlags() {
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    // P0-自伤免疫: ZETA 自己改 KLDR_DATA_TABLE_ENTRY 的 Flags/SignatureLevel,
    // 置位标记, 使监控逻辑识别为自保动作, 不当作外部 KLDR 篡改告警。
    g_SelfDkomInProgress = TRUE;

    // 获取当前驱动对象 (从全局变量中获取，DriverEntry 传入)
    PDRIVER_OBJECT driverObject = GlobalData.DriverObject;
    if (!driverObject) {
        DbgPrint("ZETA: DkomDriverSig: DriverObject is NULL\n");
        g_SelfDkomInProgress = FALSE;
        return STATUS_INVALID_PARAMETER;
    }

    // DriverSection 指向 KLDR_DATA_TABLE_ENTRY
    PVOID driverSection = driverObject->DriverSection;
    if (!driverSection) {
        DbgPrint("ZETA: DkomDriverSig: DriverSection is NULL\n");
        g_SelfDkomInProgress = FALSE;
        return STATUS_INVALID_PARAMETER;
    }

    // 计算 Flags 字段地址: DriverSection + Flags 偏移 (PDB 解析优先, 硬编码兜底)
    ULONG kldrFlagsOff = g_OffKldrFlags ? g_OffKldrFlags : KLDR_FLAGS_OFFSET;
    PULONG flagsPtr = (PULONG)((PUCHAR)driverSection + kldrFlagsOff);

    // 保存原始 Flags 用于日志
    ULONG originalFlags = *flagsPtr;

    // 设置 bit 5 (0x20) - ProcessStaticImport
    // 这是 ObRegisterCallbacks 验证的唯一标志位
    *flagsPtr |= KLDR_CALLBACK_CHECK_FLAG;

    // 验证写入
    if (*flagsPtr & KLDR_CALLBACK_CHECK_FLAG) {
        DbgPrint("ZETA: DkomDriverSig: Flags 0x%08X -> 0x%08X (bit5 SET)\n",
                 originalFlags, *flagsPtr);
        status = STATUS_SUCCESS;
    } else {
        DbgPrint("ZETA: DkomDriverSig: Flags write FAILED! 0x%08X\n",
                 *flagsPtr);
        status = STATUS_UNSUCCESSFUL;
    }

    // 额外: 设置 SignatureLevel (PDB 解析优先, 硬编码兜底)
    // 在某些 Windows 版本中，KLDR_DATA_TABLE_ENTRY + 0x6E 包含 SignatureLevel
    // 这可以进一步绕过其他签名检查
    ULONG kldrSigOff = g_OffKldrSignatureLevel ? g_OffKldrSignatureLevel : KLDR_SIGNATURE_OFFSET;
    PUCHAR sigLevelPtr = (PUCHAR)driverSection + kldrSigOff;
    UCHAR originalSigLevel = *sigLevelPtr;
    if (originalSigLevel == 0) {
        // 设置为 ANTIMALWARE (2) 或 MICROSOFT (6)
        *sigLevelPtr = 0x02;  // SIGNING_LEVEL_ANTIMALWARE
        DbgPrint("ZETA: DkomDriverSig: SignatureLevel 0x%02X -> 0x02\n",
                 originalSigLevel);
    }

    g_SelfDkomInProgress = FALSE;
    return status;
}

// =============================================================================
// DkomVerifyTokenPrivileges -- P0-3: watchdog 令牌特权复查
//
// 复查 ZETA.exe 令牌上的 5 个关键特权 (SeTcb/SeDebug/SeTakeOwnership/
// SeLoadDriver/SeIncreaseQuota) 是否仍 ENABLED。任一缺失则重新调用
// DkomInjectTokenPrivileges 重注入（该函数幂等）。
// 避免每周期无条件 ZwAdjustPrivilegesToken，减少内核调用开销。
// =============================================================================
NTSTATUS DkomVerifyTokenPrivileges() {
    if (!GlobalData.UserProcess) return STATUS_INVALID_PARAMETER;

    // 关键特权 LUID (跨 Windows 版本稳定)
    static const ULONG kCriticalPrivs[] = { 5, 7, 9, 10, 20 }; // IncQuota/Tcb/TakeOwnership/LoadDriver/Debug
    static const ULONG kCriticalCount = sizeof(kCriticalPrivs) / sizeof(kCriticalPrivs[0]);

    HANDLE procHandle = NULL;
    HANDLE tokenHandle = NULL;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)GlobalData.ZetaPid;
    cid.UniqueThread = NULL;

    NTSTATUS status = ZwOpenProcess(&procHandle, PROCESS_QUERY_INFORMATION, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        DbgPrint("ZETA: DkomTkn: Verify ZwOpenProcess FAILED (0x%08X)\n", status);
        return status;
    }

    status = ZwOpenProcessTokenEx(procHandle, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                                 OBJ_KERNEL_HANDLE, &tokenHandle);
    if (!NT_SUCCESS(status)) {
        ZwClose(procHandle);
        DbgPrint("ZETA: DkomTkn: Verify ZwOpenProcessTokenEx FAILED (0x%08X)\n", status);
        return status;
    }

    // 查询当前特权集
    UCHAR buf[sizeof(TOKEN_PRIVILEGES) + 64 * sizeof(LUID_AND_ATTRIBUTES)];
    ULONG retLen = 0;
    status = ZwQueryInformationToken(tokenHandle, TokenPrivileges, buf, sizeof(buf), &retLen);
    if (!NT_SUCCESS(status)) {
        ZwClose(tokenHandle);
        ZwClose(procHandle);
        DbgPrint("ZETA: DkomTkn: Verify ZwQueryInformationToken FAILED (0x%08X)\n", status);
        return status;
    }

    PTOKEN_PRIVILEGES tp = (PTOKEN_PRIVILEGES)buf;
    BOOLEAN allPresent = TRUE;
    for (ULONG i = 0; i < kCriticalCount; i++) {
        BOOLEAN found = FALSE;
        for (ULONG j = 0; j < tp->PrivilegeCount; j++) {
            if (tp->Privileges[j].Luid.LowPart == kCriticalPrivs[i] &&
                (tp->Privileges[j].Attributes & SE_PRIVILEGE_ENABLED)) {
                found = TRUE;
                break;
            }
        }
        if (!found) { allPresent = FALSE; break; }
    }

    ZwClose(tokenHandle);
    ZwClose(procHandle);

    if (allPresent) {
        return STATUS_SUCCESS;  // 全部在位，无需重注
    }

    // 缺失 → 重注入
    DbgPrint("ZETA: DkomTkn: privileges missing, re-injecting...\n");
    return DkomInjectTokenPrivileges();
}
