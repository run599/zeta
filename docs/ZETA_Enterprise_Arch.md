# ZETA 企业版架构设计与路线图（私有化）

> 版本：v0.1（草案）　日期：2026-09-05
> 前提：以本仓库单机版 ZETA Security（驱动 ZETA_Drv.sys / ZETA_NetFilter.sys / ZETA_DiskFilter.sys + 用户态 zeta_core/driver/engine/monitor/hips + ZETA.exe）为基线。
> 核心理念（用户明确定义）：**企业版与单机版功能差不了太多，核心增量只有两个闭环——控制台向下发 JSON 规则/策略、agent 向上收日志/事件。不做远程卸载安全软件/驱动的能力。**

---

## 1. 目标与非目标

### 1.1 目标
| 编号 | 能力 | 说明 |
|---|---|---|
| G1 | 集中下发规则/策略 | 控制台将 HIPS/EDR/状态机/驱动/信任/YARA 规则打包为**带版本与签名的 JSON 包**下发，Agent 原子应用并回执结果 |
| G2 | 集中收日志/事件 | Agent 将拦截事件、EDR 判定、告警、审计增量上报；支持离线缓冲补传 |
| G3 | Agent 服务化 | 无 UI 的 Windows 服务，用户注销/无桌面环境仍持续防护（先决条件） |
| G4 | 资产与心跳 | 控制台能看每台端点的在线状态、版本、防护状态 |
| G5 | Web 控制台 | 私有化单套交付，数据不出内网 |

### 1.2 明确不做（非目标）
- ❌ 控制台远程卸载 Agent / 卸载安全软件驱动（企业不会无故卸载内网安全软件；卸载驱动是高危操作，仅保留**人工运维维护窗口**，可复用驱动 cmd27 授权机制）
- ❌ 云端 SaaS / 多租户公网运营（本期私有化单租户；表结构预留 `tenant_id` 即可）
- ❌ 杀软竞品互斥策略、漏洞补丁管理、DLP 内容审计引擎重做（zeta_tlsint 仅作可选能力保留）
- ❌ 重构内核驱动拦截逻辑（现有 28 条命令 + 事件码体系已够用）

---

## 2. 现状关键事实（设计输入）

| 域 | 现状 | 对企业版的影响 |
|---|---|---|
| 规则 | `Plugins\Rules\*.json`（HIPS/EDR/Conditions/Compose/Context/User/Driver_P1/TrustRules）+ 各引擎硬编码默认 + YARA `*.yar` | 规则**散在多文件、多解析器、多入口加载**；下发需统一成"策略包 + 一个原子应用器 + 一个运行期重载入口" |
| 规则加载时机 | HIPS/EDR/状态机规则在 `doDriverInstallWork`（启动安装线程）内一次性加载；驱动规则重启驱动生效 | **缺口：缺少"运行期全量重载"入口**，企业下发后必须能即时生效（详见 §5.4） |
| 配置 | `C:\ProgramData\ZETA\Config.json` 扁平 KV（9 开关 + theme） | 配置 key 已是"key→驱动 cmd"标准三元组，便于映射为策略项 |
| 判定/日志 | Verdict JSONL(`C:\ProgramData\ZETA\Verdicts\*.verdict.jsonl`,10MB 滚动)；拦截日志 `ZETA_Intercepts.log`；驱动审计环形 `AUDIT_RING`(cmd17) | **verdict.jsonl 已结构化**(ver/ts/aid/pid/score/tags/v/artifacts)，是最佳上送源；无需发明新格式 |
| 命令通道 | 驱动端口命令 0–27（含 ReloadRules=15、AuthorizeUnload=27、Audit 16/17） | 下发规则应用后已有内核重载与审计读取接口 |
| 事件源 | 事件码 2/3/4/5/6/7/8k（文件/注册/磁盘/勒索/注入/血统进程/网络）+ `ZETA_IRP_CONTEXT` 语义标签 | 遥测字段齐备，需**节流与策略**决定"全量 vs 仅告警" |
| 管理面 | 纯本地单机（Config/Rules/logs 全本地），无任何网络代码 | Agent 需新增传输与收集模块；服务端全新 |

---

## 3. 总体架构

```
                 ┌─────────────────── 内网（私有化） ───────────────────┐
                 │                                                      │
  浏览器  ──HTTPS──►  Web 控制台（新增，独立技术栈）                      │
                 │   ├─ 策略管理 / 规则打包器 / 版本管理                 │
                 │   ├─ 告警台 / 资产台账 / 日志检索 / 报表              │
                 │   ├─ RBAC / 审计日志                                  │
                 │   └─ 存储: PostgreSQL(元数据) + ClickHouse/时序(事件)  │
                 │        ▲  REST API (JSON)  ▲  证书签发(CSR/注册)       │
                 └────────┼──────────────────┼───────────────────────────┘
                    上报(HTTPS long-poll/push)   下发(任务拉取)
                 ┌────────┴──────────────────┴───────────────────────────┐
                 │  Agent（Windows 服务，会话0，无UI）                    │
                 │  ┌──────────────────────────────────────────────────┐ │
                 │  │ 新增 zeta_agent（传输/收集/策略/心跳）            │ │
                 │  │  ├ Transport  mTLS(每端点证书)+心跳+任务拉取      │ │
                 │  │  ├ Collector  事件→Spool(磁盘队列)→补传          │ │
                 │  │  ├ PolicyApp 下载→验签→原子切换→重载→回执         │ │
                 │  │  └ Status     资产/版本/防护状态采集              │ │
                 │  └───────────────┬──────────────────────────────────┘ │
                 │                  │ 本地调用(引擎下沉后共用)            │
                 │  ┌───────────────▼──────────────────────────────────┐ │
                 │  │ 存量核心(自单机版下沉，无UI依赖)                   │ │
                 │  │ DriverComm/HipsEngine/BehaviorEngine/Verifier    │ │
                 │  │ Monitors/Verdict/TrustDecider/zeta_engine/YARA   │ │
                 │  └───────────────┬──────────────────────────────────┘ │
                 │                  │ 事件/命令                            │
                 │  ┌───────────────▼──────────────────────────────────┐ │
                 │  │ ZETA_Drv.sys / NetFilter / DiskFilter（不改逻辑）  │ │
                 │  └──────────────────────────────────────────────────┘ │
                 └───────────────────────────────────────────────────────┘
```

**单机版 UI（ZETA.exe）在拆分后仍是合法宿主**：企业也可在运维机上装 UI 版做单点排查；服务端可选地对 UI 版放行上报。

---

## 4. Agent 侧改造（对存量改动最大的部分）

### 4.1 宿主拆分（先决，M1）
现状 `ZETA.exe` = 引擎 + Qt 捆绑于一个交互进程。改造原则：**只拆宿主，不动引擎内部**。

- 新增共享库 `zeta_engine_host`（建议并入现有 zeta_core/zeta_driver 体系），承载现 main.cpp 中：
  - DriverEventProcessor / BehaviorEngine 生命周期与回调闭包
  - DriverComm 连接、monitor 启停、规则加载入口、verdict/隔离/处置
- 两个薄宿主：
  - `ZETA.exe`（GUI 版）：Qt UI 只做视图与本地运维，引擎逻辑改调 host 库 → **行为不变**
  - `ZETAAgent.exe`（服务）：服务入口 + zeta_agent 传输模块，**不加载 Qt、不创建窗口**
- 退出/卸载语义沿用单机版（复用 cmd27 人工授权），Agent 服务停止**不等于**卸载驱动（与本次 0xCE 修复后的语义一致：驱动残留回调必须清干净/或不卸驱动只断连）。

风险提示：main.cpp 为 ~4300 行单文件，回调闭包与全局多；拆分以"提取初始化/事件循环骨架"为主，**禁止顺带重构评分逻辑**，每步用回归清单验证。

### 4.2 新增 zeta_agent 模块
| 子件 | 职责 | 要点 |
|---|---|---|
| Transport | HTTPS 长轮询 + 推送通道 | 复用系统 Schannel/mTLS；连接失败指数退避 |
| Identity | 端点身份 | 首次运行生成 key→CSR→控制台签发证书；`agent.json` 存 `endpoint_id`/server/cert，ACL 防篡改 |
| Heartbeat | 心跳+资产 | 30s：endpoint_id/版本/驱动状态/规则版本/防护开关快照 |
| TaskLoop | 任务拉取 | 拉策略包/触发扫描/取审计/远程隔离等（**清单不含卸载类**） |
| Collector | 上送缓冲 | 内存批量→`C:\ProgramData\ZETA\Spool\` 磁盘队列→成功删除；断线重连补传 |
| PolicyApplier | 策略应用 | 见 §5 |

### 4.3 上送内容策略（两档可配置）
- **标准档**：verdict/告警（score≥阈值）全量；原始驱动事件只送威胁类（6001/6010/6016/5002–5004/4001 等）；统计聚合（拦截计数、进程事件计数）。
- **全量档（合规取证）**：所有事件码 + `ZETA_IRP_CONTEXT` + AUDIT_RING，限时开启。
避免每端点每秒数十条全量事件把控制台打爆——**先节流再上送**是设计红线。

---

## 5. 策略包（下发的 JSON）规范 —— 核心

### 5.1 策略包结构
```jsonc
{
  "schema_ver": 1,                    // 协议版本
  "policy_id": "p_sec_level_2",
  "version": "2026-09-05-001",
  "endpoint_group": "*",              // 分组名（后续扩展）
  "signed_by": "ZETA_MGMT_CA",
  "signature": "<Ed25519/证书签名>",    // Agent 先验签后应用
  "payload": {
    "switches": { "process_switch": 1, "ransom_redirect_switch": 1, "doc_backup_switch": 0 },
    "rules": {
      "Rules_Hips.json":   "<完整JSON文本>",
      "Rules_EDR.json":    "<完整JSON文本>",
      "Rules_Conditions.json": "<完整JSON文本>",
      "Rules_Compose.json":  "<完整JSON文本>",
      "Rules_Context.json":  "<完整JSON文本>",
      "Rules_User.json":    "<完整JSON文本>",
      "Rules_Driver_P1.json": "<完整JSON文本>",
      "TrustRules.json":    "<完整JSON文本>"
    },
    "yara": [ { "name": "ransom.yar", "content_b64": "..." } ],
    "edr_thresholds": { "alert_threshold": 85, "autokill_threshold": 130 }
  }
}
```
- 单个 payload 即覆盖全部规则面；**未包含的类别 = 保持本机现状**（增量语义，防止误清空）。
- 引擎阈值（alert/autokill）、状态机 action 阈值从硬编码/单机 JSON 提升为策略项（见现状表"阈值写死"缺口）。

### 5.2 下发链路
```
Console 发布策略包(验签/入库/版本递增)
   │
   ▼  REST: GET /v1/agents/{id}/task?since=ver
Agent TaskLoop 拉到 {type:"apply_policy", pkg_url}
   │  下载 → 验签 → schema 校验
   ▼  PolicyApplier
① 写临时目录 → ② 本地规则原子切换(备份旧版)
③ 运行期重载：HIPS/EDR/状态机/驱动 全量重载入口（新增，见 5.4）
④ 开关应用：ConfigManager(标记 managed) + 下发对应驱动 cmd(8-14/21/26)
   ▼
POST /v1/agents/{id}/ack  {policy_id, version, result:"ok"|"fail:原因", applied_at}
```
- 失败必须**回滚到上一个可用策略版本**（Agent 本地保留 last-good）。

### 5.3 与本地配置的优先级
`server 策略 > 本机 UI/管理员 > 出厂默认`；策略项写入时打 `managed:true`，本机 UI 对这些项只读提示"由企业策略管理"。MVP 阶段企业 Agent 无 UI，冲突面很小。

### 5.4 【缺口】运行期全量规则重载入口（必须新增）
现状：HIPS/EDR/状态机规则在启动安装线程加载；运行时只有 HIPS `reload` 与驱动 cmd15。
企业下发后要即时生效，需在 host 库新增一个幂等入口：
```
ReloadAllRules():
  HIPS        → zeta_hips_load_rules()            (已有)
  DriverRules → 驱动 cmd15 ReloadRules            (已有)
  EDR/状态机  → BehaviorEngine.loadEdrConfig()
                + loadContextConfig() + loadStateMachineRules()  (抽取为公开方法，当前在 doDriverInstallWork 内联)
```
同时要求**解析器健壮化**：现状 HIPS/EDR JSON 允许 `//` 注释、数组混排、手写解析——企业规则高频下发，坏规则=全网点事故，M0 必须先固化 schema 与校验（服务端打包器负责生成合法文件，Agent 负责 schema_ver 校验，双层保险）。

---

## 6. 日志/事件上送规范

### 6.1 统一事件信封（Agent→Console）
```jsonc
{
  "env_ver": 1,
  "tenant_id": "0",
  "endpoint_id": "uuid",          // Agent 证书签发时绑定
  "ts": "2026-09-05T04:20:11.000Z", // 事件发生时刻(时钟以端点为准,控制台校准)
  "seq": 12345,                   // 每端点自增，供去重/乱序检测
  "type": "verdict|alert|event|stat|audit",
  "payload": { /* 见 6.2 */ }
}
```
- Spool 落盘格式与信封一致 → 重传天然幂等（按 `endpoint_id+seq` 去重）。

### 6.2 各类 payload
| type | 数据源（复用现状） | payload 要点 |
|---|---|---|
| `verdict` | `VerdictWriter` 写的 JSONL | 原行字段即可（score/tags/artifacts/v），补 endpoint 上下文 |
| `alert` | BehaviorEngine alert/warn 回调 | pid/proc/score/reasons/artifacts |
| `event` | 驱动消息 + `ZETA_IRP_CONTEXT` | code(2001/3001/6001...)/pid/path/opType/trust/flags |
| `stat` | 拦截日志计数/引擎自检 | 周期聚合，低频 |
| `audit` | 驱动 cmd17 AUDIT_RING | 全量档开启时 |

### 6.3 节流与容量（估算参考）
- 标准档 ≈ 每端点 0.1–2 条/s（威胁类+verdict）→ 500 端点峰值 ~1k eps，ClickHouse 轻松承载。
- 全量档可达 50–500 条/s/端点（进程风暴），**只建议取证窗口开启**。
- 控制台侧做索引拆分 + 过期归档（建议 90 天热存 + 可导出）。

---

## 7. 安全与信任（简版）

| 面 | 方案 |
|---|---|
| 传输 | HTTPS + mTLS：每端点唯一证书，控制台 CA 签发；私有化可自建 CA |
| 身份 | CSR 注册：agent 首次连入 → 管理员审批或预置 token 自动注册 |
| 策略完整 | 策略包 Ed25519 签名 + schema_ver，Agent 验签验 schema 后才落盘 |
| 上报防伪 | 证书绑定 endpoint_id；seq 去重防重放 |
| 高危操作 | **任务白名单机制**：控制台可下发的能力集合固定（规则/扫描/隔离/审计/配置）；**不提供卸载/停止驱动/自我删除**。Agent 自身的"移除"仅允许本地 SYSTEM 运维窗口（复用 cmd27），远程永远不下发 |

---

## 8. 控制台（Web，服务端建议）

### 8.1 技术选型建议
| 层 | 建议 | 理由 |
|---|---|---|
| 服务端 | Go 1.2x + Gin/Echo（或 Node/TS） | 单二进制私有化部署友好；与 C++ 无耦合，仅协议对接 |
| 事件存储 | ClickHouse（或 Postgres 分区表起步） | 写入放大低、聚合快 |
| 元数据/RBAC | PostgreSQL | 事务、关系清晰 |
| 前端 | React + AntD（管理后台惯例） | 图表/表格/多标签天然适合告警台 |
| 部署 | 单机 docker-compose 起步，预留水平扩展 | 私有化单套 |

### 8.2 页面清单（M3 后逐项）
资产列表、策略管理（编辑器=规则打包器）、发布/回滚、告警台、端点详情（事件时间线）、日志检索、报表（阻断/感染/处置 SLA）、系统设置（RBAC/CA）。

### 8.3 REST API 草案（摘要）
```
POST /v1/register                 // CSR 注册
GET  /v1/agents/{id}/task         // 任务拉取(含策略包URL)
POST /v1/agents/{id}/events       // 批量上送(信封数组)
POST /v1/agents/{id}/ack          // 策略/任务回执
POST /v1/agents/{id}/action       // 远程动作: scan|isolate|release|get_audit|set_log_level (不含卸载)
GET/POST /v1/console/policies     // 控制台策略 CRUD+发布
GET  /v1/console/events|alerts|assets|stats
```

---

## 9. 与既有驱动的接口约束（踩坑沉淀）
- 规则下发后驱动重载用 cmd15；**不要**为"更新规则"卸载驱动（本次 0xCE 教训：卸载+OB 回调竞态曾蓝屏）。
- 开关 cmd 8–14/21/26 均为幂等下发，策略应用可直接复用。
- 驱动命令行 cmd27 仅本地人工运维使用，Agent/控制台代码路径不引用。
- YARA 更新走 zeta_engine `YaraScanner` 重载接口（需新增 release/reload 入口，见 M2）。

---

## 10. 路线图

| 阶段 | 内容 | 验收标准 | 风险 |
|---|---|---|---|
| **M0 协议/规范定稿** | 本文档细化：API 全量、信封 schema、策略包 schema、CA/注册流程、Spool 格式 | 控制台与 Agent 可据此独立开发；mock 打通 | 低 |
| **M1 宿主拆分 + Agent 服务化** | 引擎下沉 host 库；ZETAAgent 服务(无 UI)装驱动+连接+心跳；单机 GUI 回归 | GUI 版全功能回归通过；服务版能无界面跑起、心跳上送假数据 | **高**（最大重构） |
| **M2 策略闭环** | PolicyApplier + ReloadAllRules 运行期重载 + 策略 ack；控制台策略发布 | 改一条 HIPS/EDR 规则→50 台 1min 生效且回执 ok；坏包回滚 | 中（解析器固化） |
| **M3 日志上送 + 告警台/资产** | Collector/Spool/补传；verdict+alert 实时入台；资产在线状态 | 300 台标准档稳定上报；控制台时间线/告警可用 | 中 |
| **M4 响应与运营** | 远程 scan/isolation/get_audit；RBAC；报表；CA/升级（策略签名轮换） | 远程处置演示闭环；审计员独立可查 | 中 |

**最小可用(MVP)= M1+M2+M3 的前半**：一台控制台 + N 台服务 Agent，能"下发 JSON 规则并回执、收到日志告警"，即达成用户定义的企业版核心。

---

## 11. 建议立即开始的第一件事
M0 的**数据契约定稿**（策略包 schema + 事件信封 + API），因为它决定两端能否并行开发，也顺带暴露"运行期重载入口/解析器固化"两个必须先补的存量缺口。M1 宿主拆分可并行开工但需隔离风险。
