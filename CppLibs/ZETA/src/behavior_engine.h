#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <cstdint>
#include <queue>
#include <condition_variable>
#include <thread>
#include <atomic>

// ============================================================
// ProcessBehaviorEngine — User-mode behavior risk scoring
//
// Architecture: Producer-Consumer
//   Producer: onDriverMessage (message thread) → ingest() → enqueue
//   Consumer: worker thread → dequeue → score → evaluate → notify
//
// ingest() is O(1) lock-and-push. All heavy work (WinVerifyTrust,
// process lookup, scoring, notification) runs on the worker thread.
// This prevents the driver message thread from ever blocking.
// ============================================================

// ── 事件类 (用于"类内分数上限") ─────────────────────────────────────────────
//
// 【修复背景 2026-10-03】评分器是"衰减累加器": 每个事件先衰减再加分
// (processEvent Step4), 半衰期 120s。稳态解 S_eq = s / (1 - 2^(-T/H))。
// 以驱动对线程创建的限速 T=1s、H=120s 计算, 系数 = 173.6
//   ⇒ 单事件分值只要 ≥ 0.5, 持续约 2 分钟就必然越过 ALERT_THRESHOLD(85)。
//
// 实测证据: 某进程每次【普通线程创建】落到 `return cfi.injectorUnverified`
// 拿 5 分, 稳态可达 868 分; 日志逐条吻合 ((int)(43*0.99424)+5=47, +5=51...),
// 约 17 个事件(17 秒)就越阈弹框, 归零后必然复弹 → 无限弹框。
//
// 两项修复:
//   ① 基数型事件退出评分 (见 behavior_engine.cpp 的 THREAD_CREATE 分支);
//   ② 每类累计贡献设上限, 且上限必须 < ALERT_THRESHOLD, 使得
//      【单一类别的重复行为永远无法独自触发告警】—— 告警必须来自多类组合证据。
enum ScoreCategory {
    CAT_NONE = 0,
    CAT_FILE,
    CAT_REG,
    CAT_RANSOM,
    CAT_INJECT,
    CAT_MISC,      // SilverFox/血统 + 上下文加成 + 序列加成 (跨事件组合证据)
    CAT_HONEY,     // 蜜罐触碰及后续加成: 决定性证据且天然稀有 → 刻意【不设上限】
    CAT_COUNT
};

struct ProcessProfile {
    unsigned long pid = 0;
    unsigned long parentPid = 0;
    long long startTimeMs = 0;
    std::wstring processPath;   // [FIX] 进程完整路径 (用于系统路径检测)

    // ── 基础计数器 ──
    int peReleases = 0;
    int suspiciousDllLoads = 0;
    int fileWriteBursts = 0;
    int diskWriteCount = 0;
    bool hasScriptAncestor = false;
    bool hitHoneypot = false;
    bool wroteToRunKey = false;
    bool hasMixedPublishers = false;
    bool hasUnsignedPE = false;
    bool userApproved = false;

    // ── 上下文感知状态 ──
    unsigned char trustLevel = 0;     // 最近一次事件的进程信任级别
    int untrustedPeCount = 0;         // 无签名进程释放的 PE 数
    int offsetZeroWriteCount = 0;     // offset=0 写入次数 (勒索特征)
    int tempPathPeCount = 0;          // 从 Temp 路径释放的 PE 数
    int scriptChainDepth = 0;         // 最大脚本链深度
    int sensitiveRegWriteCount = 0;   // 敏感注册表写入次数
    int exclusiveWriteCount = 0;      // 独占写入次数
    int honeyFileTouchCount = 0;      // 蜜罐文件触碰次数
    int threadCreateCount = 0;        // 线程创建事件计数
    int remoteThreadCount = 0;        // 远程线程注入事件计数 (驱动标记 ,R)
    int driverLoadCount = 0;          // 驱动加载事件计数 (7010, 供状态机 BYOVD 判定)
    int sameEventRepeatCount = 0;     // 同类型事件连续重复次数
    unsigned long lastEventCode = 0;  // 上次事件码 (用于重复检测)
    long long lastRepeatEventMs = 0;  // 上次重复事件时间
    long long firstEventMs = 0;       // 首次事件时间 (用于速率计算)
    int totalEvents = 0;              // 总事件数

    // ── 行为序列追踪 (新增) ──
    // 记录最近 N 个事件的 (code, path前缀) 用于序列匹配
    static constexpr int SEQ_WINDOW = 16;
    static constexpr int PATH_TAIL_LEN = 20;  // path 尾部快照长度 (M1-2: 窗口内 endswith 匹配)
    struct SeqEntry {
        unsigned long code;
        unsigned short fileFlags;
        unsigned short regFlags;
        unsigned char trustLevel;
        long long timeMs = 0;                 // M1-2: 事件发生时间戳 (window_ms 窗口匹配)
        wchar_t pathTail[PATH_TAIL_LEN];      // M1-2: 路径尾部(小写快照), endswith 判定用
    };
    SeqEntry recentSequence[SEQ_WINDOW] = {};
    int seqHead = 0;  // 环形缓冲区写指针
    int seqCount = 0; // 已填充的事件数

    // ── 状态机窗口命中抑制 (M1-2) ──
    // ruleId -> 最近命中时刻 (毫秒)。带 window_ms 的规则命中后, 窗口期内不重复处置。
    std::unordered_map<std::wstring, long long> smRuleHitMs;

    // Scoring
    int score = 0;
    // P2-6: 二维评分分量
    //   confidence: 证据强度 (0.0~1.0)，来自签名/已知规则/血缘等硬证据
    //   severity:   动作危害 (0.0~1.0)，来自进程注入/文件落地/注册表等危害动作
    // 判定 = confidence * severity >= 阈值，避免"高分低危"(合法安装器)误报
    double confidence = 0.0;
    double severity = 0.0;
    std::vector<std::wstring> reasons;
    std::vector<std::wstring> artifacts;
    long long lastUpdateMs = 0;

    // ── 事件类累计贡献 (受 CategoryCaps 约束; 与 score 同步衰减) ──
    // 作用: 把"次数"从判据里拿掉。任一类别吃满上限后, 同类事件继续发生也不再加分,
    // 于是判据退化为"该类行为【是否发生过】", 而不是"发生了多少次"。
    int catScore[CAT_COUNT] = {};
};

// IRP 语义标签 (内核提取，8 bytes)
// 与 zeta_driver.h 中的 ZETA_IRP_CONTEXT 保持一致
struct IrpSemantic {
    unsigned char opType;        // IrpOperationType
    unsigned char trustLevel;    // ProcessTrustLevel
    unsigned short fileFlags;    // FileSemanticFlags 位组合
    unsigned short regFlags;     // RegSemanticFlags 位组合
    unsigned char scriptDepth;   // 脚本调用深度
    unsigned char flags;         // ContextFlags (byte 7)

    // 操作类型检测
    bool isFileCreate()  const { return opType == 0; }
    bool isFileWrite()   const { return opType == 1; }
    bool isFileRename()  const { return opType == 2; }
    bool isFileDelete()  const { return opType == 3; }
    bool isRegOp()       const { return opType >= 10 && opType <= 13; }

    // ContextFlags (byte 7)
    bool replaceIfExists()    const { return (flags & 0x01) != 0; }
    bool dispositionEx()      const { return (flags & 0x02) != 0; }
    bool dispositionDelete()  const { return (flags & 0x04) != 0; }
    bool hasTransaction()     const { return (flags & 0x08) != 0; }
    bool isScriptHost()        const { return (flags & 0x10) != 0; }
    bool hasScriptAncestor()   const { return (flags & 0x20) != 0; }

    // 文件语义标志便捷查询
    bool isPeFile()    const { return (fileFlags & 0x0001) != 0; }
    bool isScript()    const { return (fileFlags & 0x0002) != 0; }
    bool isDocument()  const { return (fileFlags & 0x0004) != 0; }
    bool offsetZero()  const { return (fileFlags & 0x0008) != 0; }
    bool largeWrite()  const { return (fileFlags & 0x0010) != 0; }
    bool hiddenFile()  const { return (fileFlags & 0x0020) != 0; }
    bool deleteOp()    const { return (fileFlags & 0x0080) != 0; }
    bool exclusive()   const { return (fileFlags & 0x0100) != 0; }
    bool overwrite()   const { return (fileFlags & 0x0200) != 0; }
    bool isTempPath()  const { return (fileFlags & 0x1000) != 0; }
    bool isAppData()   const { return (fileFlags & 0x2000) != 0; }
    bool isSystem()    const { return (fileFlags & 0x4000) != 0; }
    bool isPublic()    const { return (fileFlags & 0x8000) != 0; }

    // 注册表语义标志便捷查询
    bool isRunKey()    const { return (regFlags & 0x0001) != 0; }
    bool isService()   const { return (regFlags & 0x0002) != 0; }
    bool isIfeo()      const { return (regFlags & 0x0004) != 0; }
    bool isUacBypass() const { return (regFlags & 0x0008) != 0; }
    bool isDefender()  const { return (regFlags & 0x0010) != 0; }

    bool isTrusted() const {
        return trustLevel >= 3;  // SIGNED, MS_SIGNED, SYSTEM, ZETA
    }
    bool isUntrusted() const {
        return trustLevel <= 1;  // UNKNOWN, NONE
    }
};

// ============================================================
// 第4层上下文评分配置 (Rules_Context.json)
// 覆盖 scoreWithContext / processEvent ctxBonus / detectBehaviorSequence
// 中的全部硬编码权值。字段缺省时回退到代码默认值(与硬编码行为一致)。
// ============================================================
struct ContextScoreConfig {
    // processEvent Step2 上下文加成 (ctxBonus)
    struct CtxBonus {
        int untrustedPeFirst = 10;        // 无签名进程首次释放 PE
        int untrustedPeMany = 20;         // 无签名进程多次释放 PE
        int untrustedPeManyCount = 3;     // "多次"阈值
        int offsetZeroDoc = 25;           // offset=0 写文档 (勒索覆写)
        int tempPe = 15;                  // Temp 路径释放 PE
        int tempPeCount = 2;              // Temp PE 触发阈值
        int scriptHostPe = 15;            // 脚本宿主释放 PE
        int scriptAncestorPe = 10;        // 脚本祖先释放 PE
        int scriptChainDepth3 = 20;       // 脚本链深度>=3
        int sensitiveReg = 15;            // 敏感注册表 (IFEO/UAC/Defender)
        int exclusivePe = 10;             // 独占写 PE
        int trustedReductionDiv = 2;      // 签名进程减权 = scoreAdd / div
    } ctxBonus;

    // scoreWithContext: FILE_PROTECT 分路
    struct FileScore {
        int writeBase = 10;               // 普通文件写
        int peBase = 20;                  // PE 释放基础分
        int peRepeat3 = 10;               // PE 释放重复>=3
        int peRepeat6 = 20;               // PE 释放重复>=6
        int renameBase = 5;               // 重命名基础分
        int renamePe = 10;                // 重命名为 PE
        int renameOverwrite = 3;          // 重命名覆盖已有
        int renameRepeat3 = 5;
        int renameRepeat6 = 10;
        int deleteBase = 3;               // 删除基础分
        int deleteDispEx = 2;             // 高级删除
        int deleteDispDelete = 1;         // 硬删除
        int deletePe = 5;                 // 删除 PE
        int deleteRepeat5 = 3;
        int deleteRepeat10 = 5;
        int honeyTouchFollowUp = 80;      // 蜜罐触碰后任一文件事件
    } file;

    // scoreWithContext: REG_PROTECT 分路
    struct RegScore {
        int base = 10;
        int repeat3 = 8;
        int repeat6 = 15;
        int service = 30;                 // 服务键写入
        int runkeyUntrusted = 25;         // Run 键 (不可信进程)
        int runkeyTrusted = 5;            // Run 键 (可信进程/系统路径)
    } reg;

    // scoreWithContext: 勒索信号
    struct RansomScore {
        int firstWrite = 30;              // 首写信号
        int entropyBase = 25;             // 高熵写基础分
        int entropyBurstScale = 3;        // 每轮递增
        int entropyBurstCap = 10;         // 递增上限
        int entropyRepeat3 = 15;
        int entropyRepeat8 = 30;
        int honeyTouch = 30;              // 蜜罐触碰单次
    } ransom;

    // scoreWithContext: 注入/镂空信号
    struct InjectScore {
        int threadCreateBase = 5;         // 线程创建基础分
        int remoteThread = 15;            // 远程线程注入
        int remoteThread3 = 15;           // >=3 次
        int remoteThread10 = 20;          // >=10 次
        int threadCount5 = 8;
        int threadCount10 = 12;
        int threadCount20 = 15;
        int lowTrustThread3 = 10;         // 低信任进程大量线程
        int injectorTrustedRemote = 5;    // 签名注入者的远程线程
        int injectorUnverified = 5;       // 注入者已退出
        int codeInject1 = 5;
        int codeInject2 = 10;
        int codeInject3 = 15;
        int apcUntrusted = 40;            // 无签名 APC 注入
        int apcUnverified = 10;
        int createThreadInject = 25;      // 6015 跨进程远程线程
        int writeMemInject = 30;          // 6016 跨进程写内存
        int unmapView = 40;               // 6017 跨进程解映射
        int writeMemPe = 30;              // 6018 写 MZ 头
        int writeMemShellcode = 50;       // 6019 写 shellcode
        int syscallSpoof = 30;            // 6020 间接 syscall
    } inject;

    // scoreWithContext: 其他强信号
    struct MiscScore {
        int silverfoxSignature = 60;
        int silverfoxReleases = 50;
        int lineageNonPe = 5;
        int lineagePublic = 25;           // 脚本链释放到 Public
        int lineageRoaming = 20;          // 脚本链释放到 Roaming
        int lineageSystem = 5;            // 脚本链释放到系统目录
        int lineageDefault = 15;
    } misc;

    // detectBehaviorSequence 序列加分
    struct SequenceScore {
        int scriptRunkeyPe = 25;          // 模式1: 脚本+Run键+PE
        int scriptChainDepth3 = 15;       // 模式2: 脚本链>=3
        int unsignedSensitiveReg = 20;    // 模式3: 无签名+敏感注册表
        int sensitiveRegThreshold = 2;
        int highFreqPe = 20;              // 模式4: 高频 PE 释放
        int highFreqPeRate = 2;           // 每秒释放数阈值
        long long highFreqPeWindowMs = 10000;
        int scriptPeThread = 30;          // 模式5: 脚本+PE+线程
        int peThreadNoScript = 20;        // 模式5b: PE+线程(无脚本)
        int offsetZeroChain = 25;         // 模式6: offset0+频繁写
        int offsetZeroCount = 20;         // 模式6b: 大量 offset0
        int offsetZeroCountThreshold = 3;
        int runkeyPe = 25;                // 模式7: Run键+PE释放
        int peReleaseThreshold = 2;
        int hollowFull = 50;              // 模式8: 镂空三环节齐
        int hollowPartial = 20;           // 模式8b: 镂空过半
        int honeyTouchBonus = 60;         // 模式9: 蜜罐触碰
        int multiAttack4 = 35;            // 模式10: 4种高危操作
        int multiAttack3 = 15;            // 模式10b: 3种
        int scriptParentPe = 40;          // 模式11: 脚本宿主子进程释放 PE
    } sequence;

    // ── 事件类分数上限 (架构不变式, 刻意不放进 Rules_Context.json) ──
    // 为什么硬编码: 这些上限必须满足 "每类上限 < ALERT_THRESHOLD", 否则单类别的
    // 重复行为又能独自把分数推过阈值 —— 那正是本次要修掉的误报根因。
    // 做成可配置项 = 允许把不变式配错, 故用 static_assert 在编译期锁死
    // (见 ProcessBehaviorEngine 类体内 ALERT_THRESHOLD 之后的断言)。
    // 取值理由: 既要 < 85, 又要不小于该类中"单发决定性信号"的分值, 以免削弱真证据。
    //   FILE   30 —— 蜜罐后续加成走 CAT_HONEY, 故本类无需容纳 80 分单发信号
    //   REG    30 —— 服务键写入 30 恰好放得下
    //   RANSOM 50 —— 容纳 writeMemShellcode 级的强信号 (首写30/高熵25+递增)
    //   INJECT 50 —— 容纳 unmapView(40)/writeMemShellcode(50) 单发全额
    //   MISC   70 —— 容纳 SilverFox(60) 与序列/上下文组合加成
    //   HONEY   0 —— 0 表示不设限; 蜜罐触碰是决定性证据, 必须能单独触发告警
    struct CategoryCaps {
        static constexpr int FILE_CAP   = 30;
        static constexpr int REG_CAP    = 30;
        static constexpr int RANSOM_CAP = 50;
        static constexpr int INJECT_CAP = 50;
        static constexpr int MISC_CAP   = 70;
        static constexpr int HONEY_CAP  = 0;

        static constexpr int Of(int cat) {
            switch (cat) {
            case CAT_FILE:   return FILE_CAP;
            case CAT_REG:    return REG_CAP;
            case CAT_RANSOM: return RANSOM_CAP;
            case CAT_INJECT: return INJECT_CAP;
            case CAT_MISC:   return MISC_CAP;
            case CAT_HONEY:  return HONEY_CAP;
            default:         return 0;   // 0 = 不设限
            }
        }
    } caps;
};

// ============================================================
// YARA 扫描证据 → 分数 (2026-10-04 新增)
//
// 旧实现(behavior_engine.cpp 里的 P0-4 修补)把"扫描器返回 3"直接映射成 100 分:
//     if (score >= 3) score = 100; else if (score == 1) score = 50;
// 而 3 的真实含义只是"有规则命中"。于是任何一条能力型规则 ——
// IsPE64(只要是 64 位 PE) / with_urls(程序里有 URL) / Chacha_256_constant
// (含加密常量) / QtFrameWork(用了 Qt) —— 都会把进程直接推过 ALERT_THRESHOLD(85)。
// 实测证据: git.exe 命中 with_urls → +100 → 立即 BehaviorAlert;
// 十分钟内 git / bun / node / HYP.exe(原神启动器) / ZETA.exe 自身 全部告警。
// 反过来若只加 1~3 分(修 P0-4 之前那样), 真正的家族签名也永不告警 —— 两个极端
// 都是错的, 根因是把"证据"压成了一个 0/1/3 的标量。
//
// 现在按【证据强度加权】。引擎侧(zeta_engine)已如实上报"命中了几条第几档":
//   · 弱档 WEAK   能力型/库型规则。单条 10 分, 累计上限 30 ——
//                 **低于 WARN_THRESHOLD(40)**: 纯弱规则无论命中多少条, 连
//                 通知栏提醒都到不了, 更不可能弹交互框或自动处置。
//   · 普通档 NORMAL 单条 45 → 越过 WARN 但 **不到 ALERT**,
//                 即"单条普通规则不能独自告警"; 两条 90 → 告警。
//   · 强档 STRONG  策展的高置信家族签名(产品自带规则 + signature-base 的
//                 mal_/apt_/crime_/rat_/spy_/expl_)。单条 100 → 告警,
//                 **保留"单发决定性签名立即告警"的能力**。
//   ⇒ 告警只能来自"多档证据组合"或"高置信签名", 而不是"某条弱规则恰好
//     在某个正常软件上命中"。这就是交叉表决。
// ============================================================
// 编译期【默认值】(2026-10-06 起可由 Rules_EDR.json 的 Rule_Scoring 覆盖)。
// 保留 constexpr 的用途：① 运行时配置缺省时的兜底；② static_assert 继续锁死"默认行为"安全。
// 用户覆盖后由 YaraScoreRuntime::validate() 运行时校验并告警。
//
// 默认值为何调低(2026-10-06)：社区规则集"普通档"有 6689 条，其中大量是能力型
// (DebuggerCheck__* / antivm_vmware / CRC32_table)。旧默认 NORMAL_CAP=90 ⇒ 正常程序
// 凑够 3 条普通规则即越 ALERT(85) ⇒ 误报风暴。新默认让纯 YARA 证据无法独自越阈：
//   弱18 + 普通3 = min(18*5,15) + min(3*20,35) = 15 + 35 = 50（< ALERT 85）
struct YaraScoreConfig {
    static constexpr int WEAK_PER_HIT   = 5;
    static constexpr int WEAK_CAP       = 15;
    static constexpr int NORMAL_PER_HIT = 20;
    static constexpr int NORMAL_CAP     = 35;
    static constexpr int STRONG_PER_HIT = 100;
    // 非 YARA 的"结构证据"(未签名 / 扩展名风险 / 路径编码异常)单发分值。
    // 刻意低于 WARN_THRESHOLD: 本机实测 TextInputHost.exe / esbuild.exe /
    // idalib-mcp.exe 等正常程序都是未签名的, 若"未签名即提醒"就会变成新的噪声源
    // (旧实现把这类结果按 1→50 分处理, 已经在提醒)。它应当只作为"可与其它证据
    // 叠加的一分证据", 单独出现时不打扰用户。
    static constexpr int STRUCTURAL_SUSPICIOUS = 20;
};

// ── YARA 评分的【运行时生效值】(2026-10-06) ──────────────────────────────
// 由 ProcessBehaviorEngine::loadYaraScoreConfig(Rules_EDR.json) 从 Rule_Scoring 读取，
// 让用户无需改代码即可调权重。缺省或文件缺失时保持上面的 constexpr 默认值。
// 与 Rules_Context.json 的 ContextScoreConfig 是同一套做法(见 loadContextConfig)。
struct YaraScoreRuntime {
    int weakPerHit           = YaraScoreConfig::WEAK_PER_HIT;
    int weakCap              = YaraScoreConfig::WEAK_CAP;
    int normalPerHit         = YaraScoreConfig::NORMAL_PER_HIT;
    int normalCap            = YaraScoreConfig::NORMAL_CAP;
    int strongPerHit         = YaraScoreConfig::STRONG_PER_HIT;
    int structuralSuspicious = YaraScoreConfig::STRUCTURAL_SUSPICIOUS;

    // 运行时不变式校验(编译期只保证默认值；用户改坏时返回 false 并给出原因)。
    // 阈值由调用方传入 —— 它们原本是 ProcessBehaviorEngine 的 private 静态成员，
    // 自由函数取不到；传参既能复用同一套契约，也不必把它们提成全局。
    bool validate(int warnThreshold, int alertThreshold, std::wstring* err) const;
};

// ============================================================
// 状态机 HIPS 规则引擎 (P1-状态机)
// 两层 JSON 规则: Rules_Conditions.json(条件库) + Rules_Compose.json(组装规则)
// ============================================================

// 单一条件定义 (对应 Rules_Conditions.json 的 conditions[id])
struct StateMachineCondition {
    std::wstring id;
    std::wstring type;     // process_state / event / relation
    std::wstring field;    // ProcessProfile 字段 或 事件属性
    std::wstring op;       // eq/ne/gt/ge/lt/le/contains/startswith/endswith/exists
    std::wstring value;    // 比较值 (字符串形式, 数字在求值时转换)
    bool expect = true;    // 期望结果, false 表示取反
};

// 组装规则 (对应 Rules_Compose.json 的 rules[i])
struct StateMachineRule {
    std::wstring id;
    std::wstring name;
    int action = 0;        // 0放行 1阻止 2询问 3重定向 4放行+修复
    int score = 0;
    int priority = 10;     // 越小越优先, 豁免规则 priority=1
    std::wstring block_at; // file_write/reg_write/image_load/process_create/disk_write/net_connect/apc_inject
    std::wstring reversibility; // none/full/partial
    std::wstring redirect_to;   // action=3 时重定向目标
    std::vector<std::wstring> all_conds;  // AND 组合的条件 id
    std::vector<std::wstring> any_conds;  // OR 组合的条件 id
    long long window_ms = 0;  // 时间窗 (毫秒), 0=不检查
};

// 状态机判定结果
struct StateMachineVerdict {
    bool hit = false;
    const StateMachineRule* rule = nullptr;
};

// Lightweight event struct for the queue
struct BehaviorEvent {
    unsigned long code;
    unsigned long pid;
    std::wstring path;
    std::wstring detail;   // detailed description (e.g. "MixedSig: 2Sig+1Unsig")
    IrpSemantic ctx;       // 内核提取的语义标签 (8 bytes)
};

class ProcessBehaviorEngine {
public:
    using AlertCallback = void (*)(unsigned long pid, int score, const wchar_t* reasons,
                                   const std::vector<std::wstring>& artifacts);
    using WarnCallback  = void (*)(unsigned long pid, int score, const wchar_t* message,
                                   const std::vector<std::wstring>& artifacts);

    static ProcessBehaviorEngine& instance();

    // Start the worker thread (call once from init)
    void start();

    // Stop gracefully (call from shutdown)
    void stop();

    // Producer: enqueue event, return immediately. O(1) + brief lock.
    void ingest(unsigned long code, unsigned long pid, const std::wstring& path,
                const std::wstring& detail = L"");

    // Producer: enqueue event with IRP context (新接口)
    void ingestWithContext(unsigned long code, unsigned long pid,
                          const std::wstring& path, const IrpSemantic& ctx,
                          const std::wstring& detail = L"");

    // P0-自杀修复: 设置 ZETA.exe 自身 PID, 评分/告警/处置入口对自身绝对豁免
    void setSelfPid(unsigned long pid) { m_selfPid = pid; }
    bool isSelf(unsigned long pid) const { return m_selfPid != 0 && pid == m_selfPid; }

    // M2-3 补漏 (2026-10-05): "注入者是自身" 的豁免计数。
    // 7008 远程线程事件的 evt.pid 是【受害者】、注入者只在 path 里，所以入口的
    // isSelf(evt.pid) 拦不住我们自己的 TLS 截获注入器；该豁免在 7008 分支按注入者判定。
    // 暴露计数是为了让这条豁免**可被观测**（否则又是一处静默行为）。
    int getSelfInjectorExemptCount() const { return m_selfInjectorExempt.load(); }

    bool isEngineEnabled() const { return m_enabled; }
    void setEnabled(bool en) { m_enabled = en; }

    void setAlertCallback(AlertCallback cb);
    void setWarnCallback(WarnCallback cb);

    // Auto-block mode: when score >= 60, auto-kill without user prompt
    void setAutoBlock(bool en) { m_autoBlock = en; }
    bool isAutoBlock() const { return m_autoBlock; }

    // Whitelist: load learned process names from driver's registry
    void loadWhitelist(const std::wstring& regKey);
    bool isWhitelisted(unsigned long pid);

    // HIPS-EDR integration: record user decision
    void markUserAllowed(unsigned long pid);         // user clicked Allow → zero score
    void addPenaltyScore(unsigned long pid, int extraScore);  // user clicked Block → +extra

    // HIPS→EDR linkage: report a HIPS rule's score to the process's cumulative score
    // Called when a HIPS rule (with score>0) matches a DENY action.
    void reportHipsScore(unsigned long pid, int score, unsigned long code,
                         const std::wstring& path);

    // Scan→EDR linkage: report scan score from auto-scan
    // (保留: 供"畸形路径 / 扫描失败"这类保守上报使用, 语义是"直接给定分值")
    void reportScanScore(unsigned long pid, int score, const std::wstring& name, 
                         const std::wstring& path);

    // Scan→EDR linkage (推荐路径, 2026-10-04): 按【证据强度】计分。
    // scanCode 为引擎返回值(0=干净, 1=可疑, 3=高危); detail 为证据串。
    // 分派(不同扫描类型不能混为一谈 —— YARA 是"签名证据", 未签名/PE 是"结构证据"):
    //   · yara / mem-yara detail 含 "Weak=.. Normal=.. Strong=.." →
    //       计分 = min(WEAK_CAP, w*WEAK_PER_HIT) + min(NORMAL_CAP, n*NORMAL_PER_HIT)
    //              + s*STRONG_PER_HIT
    //       旧格式(只有一条规则名)时: scanCode>=3 视为 1 条强档, 否则 1 条普通档。
    //   · 其它类型(pe / signature / extension / unreadable):
    //       scanCode>=3 → STRONG_PER_HIT (PE 高危: 其分值本身已是多信号累积)
    //       scanCode==1 → STRUCTURAL_SUSPICIOUS (低于 WARN_THRESHOLD:
    //                     "未签名"只是结构注记, 不足以提醒, 更不能告警)
    void reportScanEvidence(unsigned long pid, int scanCode, const std::wstring& detail,
                            const std::wstring& name, const std::wstring& path);

    // ── 状态机 HIPS 规则引擎 (P1-状态机) ──
    void loadStateMachineRules(const std::wstring& conditionsPath,
                               const std::wstring& composePath);

    // ── 第4层上下文评分配置 (Rules_Context.json) ──
    // 加载后覆盖 scoreWithContext/ctxBonus/sequence 的默认权值。
    // 文件缺失或字段缺省时保持代码默认值 (行为不变)。
    void loadContextConfig(const std::wstring& path);
    // 2026-10-06: YARA 证据权重(Rules_EDR.json 的 Rule_Scoring)，与上面同一套解析风格。
    // warnOut 非空时写入"违反不变式"的说明(供调用方用 appLog 记录)；不打断运行。
    void loadYaraScoreConfig(const std::wstring& path, std::wstring* warnOut = nullptr);
    const ContextScoreConfig& contextConfig() const { return m_cfg; }
    // 状态机命中回调 (由 main.cpp 设置, 用于按 block_at 处置)
    // M1-2: 扩展透传 block_at / redirect_to / window_ms, 供处置侧区分拦截位置。
    using StateMachineCallback = void (*)(unsigned long pid, const wchar_t* ruleId,
                                          const wchar_t* ruleName, int action, int score,
                                          const wchar_t* blockAt, const wchar_t* redirectTo,
                                          long long windowMs);
    void setStateMachineCallback(StateMachineCallback cb) { m_smCallback = cb; }

private:
    ProcessBehaviorEngine() = default;
    ProcessBehaviorEngine(const ProcessBehaviorEngine&) = delete;

    // Worker thread main loop
    void workerLoop();

    // Consumer: process one event
    void processEvent(const BehaviorEvent& evt);

    // 上下文感知评分 (新增)
    int scoreWithContext(const BehaviorEvent& evt, ProcessProfile& p);
    int detectBehaviorSequence(ProcessProfile& p);
    bool isScriptChain(ProcessProfile& p);

    void evaluateAndAlert(unsigned long pid);
    int decayScore(int currentScore, long long elapsedMs);
    bool isProcessAlive(unsigned long pid);
    unsigned long lookupParentPid(unsigned long pid);
    void doMaintenance();
    void drainRemaining();

    // ── 状态机实现 (P1-状态机) ──
    void evaluateStateMachine(const BehaviorEvent& evt, ProcessProfile& p);
    bool evalCondition(const StateMachineCondition& c, const BehaviorEvent& evt, ProcessProfile& p);
    // M1-2: 在窗口历史内扫描某个 event 类条件是否已满足 (timeMs ∈ [nowMs-windowMs, nowMs])
    bool evalEventConditionInWindow(const StateMachineCondition& c, const ProcessProfile& p,
                                    long long nowMs, long long windowMs);
    bool evalRelationTrustedChain(ProcessProfile& p, int depth);
    void parseConditionsJson(const std::wstring& json);
    void parseRulesJson(const std::wstring& json);
    std::wstring extractJsonKey(const std::wstring& obj, const std::wstring& key);
    int extractJsonInt(const std::wstring& obj, const std::wstring& key, int def);

    // ── State ──
    std::unordered_map<unsigned long, ProcessProfile> m_profiles;
    std::mutex m_mutex;

    // ── Queue (producer-consumer) ──
    std::queue<BehaviorEvent> m_queue;
    std::mutex m_queueMutex;
    std::condition_variable m_queueCv;
    static constexpr size_t MAX_QUEUE_SIZE = 4096;

    // ── Worker thread ──
    std::thread m_worker;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_enabled{true};
    std::atomic<unsigned long> m_selfPid{0};  // P0-自杀修复: ZETA.exe 自身 PID
    // M2-3 补漏: "注入者是自身" 的豁免次数（诊断用，见 getSelfInjectorExemptCount）
    std::atomic<int> m_selfInjectorExempt{0};

    // ── Callbacks (called from worker thread) ──
    AlertCallback m_alertCallback = nullptr;
    WarnCallback  m_warnCallback = nullptr;

    // ── Auto-block mode ──
    std::atomic<bool> m_autoBlock{true};

    // ── Whitelist (learned process names from driver) ──
    std::vector<std::wstring> m_whitelist;
    std::mutex m_whitelistMutex;

    // ── 状态机规则 (P1-状态机) ──
    std::unordered_map<std::wstring, StateMachineCondition> m_smConditions;
    std::vector<StateMachineRule> m_smRules;
    std::mutex m_smMutex;
    StateMachineCallback m_smCallback = nullptr;

    // ── 第4层上下文评分配置 (Rules_Context.json) ──
    ContextScoreConfig m_cfg;
    YaraScoreRuntime   m_yaraScore;   // 2026-10-06: JSON 可调的 YARA 权重

    // ── Constants ──
    static constexpr int ALERT_THRESHOLD = 85;    // EDR 累计到 85分 → 弹窗 + 杀进程
    static constexpr int WARN_THRESHOLD = 40;     // 40分以上 → 通知栏提醒
    // ── 不变式: 每个【设限】的事件类上限必须小于告警阈值 ──
    // 否则"单一类别的重复行为"仍能独自触发告警, 本次修复的目标就落空了。
    // CAT_HONEY 刻意不设限 (0), 故不参与断言。
    static_assert(ContextScoreConfig::CategoryCaps::FILE_CAP   < ALERT_THRESHOLD,
                  "文件类上限必须 < ALERT_THRESHOLD: 否则单一类别可独自越阈 (本次误报根因)");
    static_assert(ContextScoreConfig::CategoryCaps::REG_CAP    < ALERT_THRESHOLD,
                  "注册表类上限必须 < ALERT_THRESHOLD");
    static_assert(ContextScoreConfig::CategoryCaps::RANSOM_CAP < ALERT_THRESHOLD,
                  "勒索类上限必须 < ALERT_THRESHOLD");
    static_assert(ContextScoreConfig::CategoryCaps::INJECT_CAP < ALERT_THRESHOLD,
                  "注入类上限必须 < ALERT_THRESHOLD");
    static_assert(ContextScoreConfig::CategoryCaps::MISC_CAP   < ALERT_THRESHOLD,
                  "组合证据类上限必须 < ALERT_THRESHOLD");
    // ── 不变式: YARA 证据评分的三条边界 (2026-10-04) ──
    // 这三条就是把"命中即告警"改成"按证据强度加权"的全部契约, 放在这里与
    // ALERT/WARN 阈值同一个编译单元, 避免权重与阈值被分开改动而悄悄失效。
    static_assert(YaraScoreConfig::WEAK_CAP < WARN_THRESHOLD,
                  "弱档累计上限必须 < WARN_THRESHOLD: 否则纯能力型规则又能独自触发提醒(误报根因)");
    static_assert(YaraScoreConfig::NORMAL_PER_HIT < ALERT_THRESHOLD,
                  "单条普通规则不得独自越过 ALERT_THRESHOLD: 否则等于回到'命中即告警'");
    // 2026-10-06 契约变更：原为 "NORMAL_CAP >= ALERT_THRESHOLD(两条普通规则应当能告警)"，
    // 但社区规则集的普通档含大量能力型规则(DebuggerCheck__*/antivm_* 等)，该契约
    // 使正常程序凑 3 条即越阈 ⇒ 改为"普通档单独不得越阈"，纯 YARA 证据只能与其它
    // 证据叠加才告警(用户仍可在 JSON 里调回，运行时 validate() 会提示)。
    static_assert(YaraScoreConfig::NORMAL_CAP < ALERT_THRESHOLD,
                  "普通档累计必须 < ALERT_THRESHOLD: 否则能力型普通规则组合命中正常程序即误报");
    static_assert(YaraScoreConfig::STRONG_PER_HIT >= ALERT_THRESHOLD,
                  "高置信签名必须单发即告警, 否则会漏掉真正的家族签名");
    static_assert(YaraScoreConfig::STRUCTURAL_SUSPICIOUS < WARN_THRESHOLD,
                  "结构证据(未签名等)单发不得触发提醒: 正常程序大量未签名, 否则又是噪声源");
    // P2-6: 二维判定阈值 (confidence * severity)
    static constexpr double ALERT_CONF_SEV = 0.45;  // 置信×危害 ≥ 0.45 → ALERT
    static constexpr double WARN_CONF_SEV = 0.18;   // ≥ 0.18 → WARN
    static constexpr int MAX_PROFILES = 512;
    static constexpr int DECAY_HALF_LIFE_SEC = 120;
    static constexpr double DECAY_LAMBDA = 0.693147 / DECAY_HALF_LIFE_SEC;

    // P2-6: 由 score 反推 severity 的辅助常量 (score∈[0,100] 映射到 [0,1])
    static double severityFromScore(int score) {
        double s = (double)score / 100.0;
        return s > 1.0 ? 1.0 : s;
    }
};
