# ZETA 扫描评分策略（2026-10-04 改造）

> 本文对应源码改动，若要把规则/评分一起提交到仓库，可把本文件放进 `docs/`。

## 一、改造前的缺陷（三层叠加，缺一层都不会炸）

| # | 位置 | 事实 | 后果 |
|---|---|---|---|
| 1 | `scanner.cpp` `SCAN_FLAGS_FAST_MODE` | libyara 里该标志的语义是**一旦有规则命中就停止扫描** | 回调最多被调用一次，引擎**从设计上**拿不到"命中了几条" |
| 2 | `scanner.cpp` `YaraMatchContext` | 只保留一条规则名（每次回调覆盖） | 命中 1 条与 10 条在上层完全一样 |
| 3 | `behavior_engine.cpp` `reportScanScore` | `if (score >= 3) score = 100;` | 扫描器返回的 `3` 含义只是"有命中"，却被当成 100 分的严重度 → **直接越过 `ALERT_THRESHOLD=85`** |

第 3 条其实是一次"矫枉过正"的补丁（注释原文：修之前 YARA 命中只加 1~3 分，永远无法告警）。
两个极端都错，根因是**把证据压成了一个 0/1/3 的标量**。

实测后果（改造前，10 分钟内）：`git.exe` 命中 `with_urls` → +100 → 立刻 `BehaviorAlert`；
`bun.exe`(`with_sqlite`)、`esbuild.exe`(`Chacha_256_constant`)、`node.exe`、`python.exe`、
`HYP.exe`(米哈游启动器, `QtFrameWork`)、**`ZETA.exe` 自身** 全部告警。

## 二、改造后的分层：证据 / 权重 分离

```
zeta_engine (证据)                          ZETA.exe / behavior_engine (权重)
────────────────────────────────────────    ────────────────────────────────────
全量扫描(去掉 FAST_MODE 早退)                 YaraScoreConfig
收集全部命中规则                              弱  10/条, 上限 30
按规则文件判定置信档                          普通 45/条, 上限 90
输出 "Hits=N Weak=w Normal=n Strong=s | …"    强  100/条
                                            结构 20 (未签名等)
```

**为什么权重不与证据同处**：三条不变式必须与 `ALERT_THRESHOLD/WARN_THRESHOLD` 在同一个
编译单元，用 `static_assert` 锁死，否则会被拆散后悄悄失效。

### 分值表

| 证据 | 分数 | 结果 |
|---|---|---|
| 1 条弱档 | 10 | 静默（记档案，不提醒不告警） |
| 3 条弱档 | 30 | 静默（上限 30 < WARN 40） |
| **1 条普通档** | **45** | **只提醒，不告警**（45 < ALERT 85） |
| 2 条普通档 | 90 | 告警 |
| **1 条强档** | **100** | **告警**（保留单发决定性签名） |
| 1 普通 + 1 弱 | 55 | 提醒 |

### 三条编译期不变式（`behavior_engine.h`）

```cpp
static_assert(WEAK_CAP            < WARN_THRESHOLD);   // 纯弱规则连提醒都到不了
static_assert(NORMAL_PER_HIT      < ALERT_THRESHOLD);  // 单条普通规则不能独自告警
static_assert(STRONG_PER_HIT     >= ALERT_THRESHOLD);  // 强签名单发即告警
static_assert(STRUCTURAL_SUSPICIOUS < WARN_THRESHOLD);// 未签名等结构证据不打扰
```

## 三、规则置信档怎么定（`scanner.cpp::tierFromRulePath`）

分档依据是**规则所在文件**，因为"这条规则是能力型还是检测型"是规则集的属性，不是单条规则的属性。

| 档 | 目录/前缀 | 理由 |
|---|---|---|
| 弱 | `capabilities\` `crypto\` `antidebug_antivm\` `packers\` `utils\` | 描述"程序具有某种能力"（是 PE、含 URL、含 DES 常量表、被加壳、用了 Qt），不描述"这是恶意软件"。依据是 4.3GB 干净语料误报审计实测 |
| 普通 | 其余社区规则 | 默认 |
| 强 | 产品自带规则（YARA 根目录，不在 `community\` 下）+ `20-DRL1.1-signature-base` 的 `mal_/apt_/crime_/rat_/spy_/expl_` 前缀 | 策展过的家族/APT 签名 |

启动时日志会打印分档统计：`Yara|RuleTier| weak=7709 normal=7866 strong=1742`。

**调参入口**：想让某类规则更容易/更难告警，改 `tierFromRulePath` 的目录表即可（改的是档位，
不是分值；分值受不变式约束，不能单独改）。

## 四、其它一并修掉的

1. **`AMSI` 命中** 原先传 60，被 `score>=3 → 100` 的映射放大成 100（数值与语义都是巧合）。
   现在该映射已删除，调用点显式传 100，语义明确："AMSI 检出脚本载荷 = 高置信单发信号"。
2. **`AutoScan` 日志级别** 原先凡有命中一律记 `ALERT` 级 —— 一条 10 分的弱档命中在日志里
   也写成 ALERT，会误导任何"数 ALERT 行"的统计。现在只有引擎判高危（存在强档命中）才记 ALERT。
3. **内存扫描**（`scanProcess`）原先"首个命中即 break"，同样丢证据；现在跨内存区累积到 4 条证据为止。
4. **结构证据与签名证据分离**：`signature:Suspicious:Unsigned` 这类结果若按 YARA 回退分支处理，
   每个未签名正常程序都会白拿 45 分并提醒（实测 `TextInputHost.exe`/`esbuild.exe`/`idalib-mcp.exe`）。
   现在单独走 20 分档，低于提醒线。

## 五、验证方法与实测结果

同一份探针文件（`yara_probe.exe` 内含唯一标记串），把匹配规则分别放进不同档位目录，
观察 `AutoScan` 证据串与行为引擎加分（脚本：`E:\MCP\yara-fetch\test-scoring-ab.ps1`）：

| 场景 | 证据串 | 行为引擎 | 预期 | 实测 |
|---|---|---|---|---|
| 弱档 ×1 | `Hits=1 Weak=1 Normal=0 Strong=0` | 无 WARN/ALERT | 静默 | ✅ 静默 |
| 普通档 ×1 | `Hits=1 Weak=0 Normal=1 Strong=0` | `WARN score=45` | 提醒不告警 | ✅ |
| 普通档 ×2 | `Hits=2 Normal=2` | `BehaviorAlert score=90` | 告警 | ✅ |
| 强档 ×1 | `Hits=1 Strong=1` | `BehaviorAlert score=100` | 告警 | ✅ |

端到端回归（改造后实机）：`git.exe` 扫描结论为**干净**（此前 `with_urls`×8→100 告警）；
`node/bun/python/esbuild/HYP` 均无行为告警；日志中 `BehaviorAlert` 实际为 0 条。

## 六、重建命令（本机约定）

```powershell
$msvc='C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207'
$sdkRoot='C:\Program Files (x86)\Windows Kits\10'; $sdk='10.0.26100.0'
$env:INCLUDE="$msvc\include;$sdkRoot\Include\$sdk\ucrt;$sdkRoot\Include\$sdk\um;$sdkRoot\Include\$sdk\shared;$sdkRoot\Include\$sdk\winrt"
$env:LIB="$msvc\lib\x64;$sdkRoot\Lib\$sdk\ucrt\x64;$sdkRoot\Lib\$sdk\um\x64"
$env:PATH="$msvc\bin\Hostx64\x64;$env:PATH"
cmake --build 'E:\远控\zeta\CppLibs\build' --target ZETA_Engine   # → ZETA_Engine.dll
cmake --build 'E:\远控\zeta\CppLibs\build' --target ZETA          # → ZETA.exe
```

要点：**不要用 `vcvars64.bat`**（其内部 `vswhere` 在本机会冻结）；重建前必须停掉 ZETA，
否则 DLL 被占用会 `LNK1104`。规则文件是运行时数据，改规则**不需要重编译**。

## 七、涉及文件

| 文件 | 改动 |
|---|---|
| `CppLibs\zeta_engine\include\zeta_engine.h` | `RuleTier` 枚举；`scan/scanMem` 增出参；`tierOfRule`；`m_ruleTier` |
| `CppLibs\zeta_engine\src\scanner.cpp` | 收集全部命中；去掉文件扫描的 FAST_MODE；`tierFromRulePath`/`ExtractRuleNamesUtf8_`/分档表；`scanFile`/`scanProcess` 输出证据串 |
| `CppLibs\ZETA\src\behavior_engine.h` | `YaraScoreConfig` + 四条 `static_assert` |
| `CppLibs\ZETA\src\behavior_engine.cpp` | `reportScanEvidence`（证据→权重）；`reportScanScore` 去掉 3→100 映射 |
| `CppLibs\ZETA\src\main.cpp` | YARA 命中改走证据式上报；AMSI 显式 100；日志级别按证据强度 |
