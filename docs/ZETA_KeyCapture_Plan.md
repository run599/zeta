# ZETA 勒索防护实现记录（当前采用方案）

> 状态：**驱动端已实现并编译通过**（Full/Lite 双配置）｜日期：2026-09-04
> 原则：本文档**只记录实际落地的方案**。评估过但**未采用**的见文末「历史评估」。

---

## 一、当前实现总览

| # | 已实现模块 | 说明 |
|---|---|---|
| 1 | **文档写前备份（DocBackup）** | P0 主力：受保护文档/图片被覆盖前自动留存旧版，不依赖"识别勒索" |
| 2 | **双版本架构（Full / Lite）** | `ZETA_ENABLE_SSDT` 宏统一控制；Lite 二进制不含 SSDT 代码 |
| 3 | **授权卸载防卸载** | `FilterUnload` 未授权即拒绝（官方机制，不依赖 SSDT） |
| 4 | **Lite 注入检测官方事件源** | 7008 + 远程线程 StartAddress 模块校验 |
| 5 | **TLS 明文截获（zeta_tlsint）** | 进程内 hook EncryptMessage/DecryptMessage 截 TLS 明文 → 共享 Ring → 中央判定（防恶意信息外传 / C2 / DLP） |

网络保护：NetFilter（内核 AFD connect + IP 黑名单）维持现状；**新增**用户态 TLS 明文截获层 `zeta_tlsint`（详见第六节）。WFP 迁移仍为历史评估项。

---

## 二、文档写前备份（DocBackup，P0 主力）

### 核心思想

```
不判断"是不是勒索" —— 一律备份受保护扩展名的旧版本
宁可错杀不可放过: 误判代价仅多一份副本, 漏判风险为零
```

### 双覆盖点（已实现）

| 场景 | 触发点 | 备份对象 |
|---|---|---|
| 直接覆盖写 | `IRP_MJ_WRITE` PreWrite | 被写的原文件 |
| rename 替换（Word/Office 保存） | `IRP_MJ_SET_INFORMATION`（`FileRenameInformation(Ex)` + ReplaceIfExists） | 被替换的目标文件 |

### 实现要点（驱动）

- 备份到 `\SystemRoot\ZETA_DocBackup\doc_<pid>_<tick>_<原名>`
- 整文件复制（`ZwOpenFile` + 分块 `ZwReadFile`/`ZwWriteFile`，64KB 块）
- **>64MB 文件跳过**（文档/图片几乎不可能；留待 v2 块级 COW）
- **per-FileObject 去重**：同句柄会话只备份一次（表满 128 自动重置）
- 受保护扩展名：`doc docx xls xlsx ppt pptx pdf txt rtf md odt csv` / `jpg jpeg png gif bmp tiff webp heic psd ai` / `db sqlite`
- 排除目录：Windows / Program Files / Temp / 备份区自身

### 命令与开关

- 开关命令：`ZETA_CMD_SET_DOC_BACKUP`(26)，`Path="0/1"`
- UI 防护页开关：`doc_backup_switch`
- 全局：`g_DocBackupEnabled`（默认 FALSE）

### 已知边界（v1）

- 备份区**无容量滚动清理**（需后续补：满 10GB 删最旧、同文件保留 2 版本）
- 去重表满自动重置可能偶发重复备份

---

## 三、双版本架构（Full / Lite）

### 目的

| | Full（SSDT 满血） | Lite（纯官方机制） |
|---|---|---|
| 受众 | 自己 / 高级用户（可开测试模式） | 普通用户（双击安装，过 HVCI/PatchGuard） |
| SSDT hook | 启用 | 二进制中不存在 |
| 战力 | 前置拦截 + 官方机制 | 官方机制（含 7008 注入检测） |

### 实现（`ZETA_ENABLE_SSDT` 宏，Full=1 / Lite=0）

- 驱动 `DriverCommon.h`：默认值 + 注释
- **`ApcHook.cpp` / `InjectHook.cpp` 文件级 `#if`**：Lite 整个文件空编 → .sys 无 SSDT 打表/定位代码
- `DriverEntry.cpp`：SSDT 命令处理（19/20/22/24）、DriverUnload 还原、PortDisconnect 还原、初始化 全部 `#if`
- `ProtectProcessDkom.cpp`：watchdog 对 APC/UnloadGuard 表项看护 `#if`
- `PendingOps.cpp`：超时线程 `ApcHook_CheckTimeouts()` `#if`
- 用户态 `main.cpp`：顶部宏 + 4 处 SSDT 命令发送点（cmd 19/20/22/24）`#if`

### 代码分发（2026-09-21 起：单一源码树 + 构建参数）

```
同一棵树 E:\远控\zeta
  用户态: cmake -S CppLibs -B build -G Ninja -DZETA_EDITION=full|lite
  驱动  : msbuild Plugins\Filter\ZETA_Driver.vcxproj /p:ZetaEnableSsdt=1|0
```

- 两版差异**只由构建参数决定**，源码唯一：宏由 CMake 的 `-DZETA_EDITION`（用户态）或驱动的 `$(ZetaEnableSsdt)` 属性（内核）注入，不再靠两棵树各自的硬编码 `#define`。
- 旧的两棵并列源码树（原 `ZETA-OpenSource` / `ZETA-Lite`）已于 2026-09-21 合并为单树；Lite 副本归档在 `archive/ZETA-Lite-merged-20260921/`，**不参与构建**，仅作历史对照。
- Lite 用户态已于同日完成**首次构建验证**（`-DZETA_EDITION=lite`，76/76 链接通过，error=0）。

---

## 四、授权卸载防卸载（官方机制）

### 目的

Lite 无 SSDT `UnloadGuard` 后，驱动仍需防被恶意 `sc stop` / `fltmc unload` 卸载。

### 实现

```
FilterUnload 回调（fltmgr 尊重返回值）开头：
  Flags == FLTFL_FILTER_UNLOAD_MANDATORY（系统强制卸载） → 放行
  否则 && !g_UnloadAuthorized → return STATUS_ACCESS_DENIED → fltmgr 拒绝卸载
```

- 授权命令：`ZETA_CMD_AUTHORIZE_UNLOAD`(27)，`Path="1"`（Full/Lite 通用）
- **卸载前必须先发 cmd 27 授权**，再 `sc stop` / `fltmc unload`

---

## 五、Lite 注入检测官方事件源（7008 + StartAddress）

### 背景

SSDT 移除后 6010/6015-6020 事件无来源。Lite 需重新"看见"注入。

### 实现（用户态 7008 处理）

```
收到 7008 且 Path 含 ",R"（远程线程）
  → OpenThread(THREAD_QUERY_LIMITED_INFORMATION, tid)
  → 动态加载 ntdll!NtQueryInformationThread
  → 查 ThreadQuerySetWin32StartAddress(9) 得线程入口
  → VirtualQuery: 入口 State==MEM_COMMIT && Type != MEM_IMAGE
  → = 线程入口不在合法模块 → 疑似 shellcode/手动映射注入 → WARN 告警
```

- Full/Lite 通用（Full 为前置拦截的后置纵深，Lite 为注入检测主源）
- 局限：从"前置拦截"降为"后置发现"（注入已发生才告警），但补回事件流

### 事件处理侧去误导

- main.cpp 中 SSDT 注入 UI case（6010/6015/6016）已用 `#if ZETA_ENABLE_SSDT` 包裹（Lite 剔除）
- behavior_engine 的 60xx 评分依赖统一 ingest 喂事件，Lite 无输入天然不触发（保留以支持 Full）

---

## 六、TLS 明文截获（zeta_tlsint.dll，网络外传检测层）

### 目的

网络驱动（NetFilter）只能看到 TLS 密文。`zeta_tlsint` 注入受监控进程后，在 **TLS 加解密发生点**截获明文，用于：

- 防恶意信息外传（DLP）：勒索样本/文档批量外传检测
- C2 通信内容检测：恶意域名/IP、beacon 特征
- 入站下发内容取证（DecryptMessage）

### Hook 点（已实现，实测通过）

```
secur32/sspicli!EncryptMessage  → 外发明文 (TLS 加密前)
secur32/sspicli!DecryptMessage  → 入站明文 (解密后)
```

- MinHook 实现；**手动 LoadLibrary + GetProcAddress 解析真实实现**（规避转发模块导致 `MH_CreateHookApi` 解析失败）
- 实测：HTTPS GET 截获 `GET / HTTP/1.1...`（外发）与 `HTTP/1.1 200 OK...`（入站）

### 注入即生效

- `DllMain(DLL_PROCESS_ATTACH)` → 后台线程自动 `ZetaTlsInt_Install()`（避开 DllMain 中 LoadLibrary 的 loader lock）
- 目标进程只需 `CreateRemoteThread(LoadLibraryW("zeta_tlsint.dll"))` 即完成 加载 + 安装

### 明文回传（共享 Ring）

- `\BaseNamedObjects\ZETA_TlsInt_Ring`（Session 级文件映射，128 槽 × 64KB）
- hook 写入：`seq 自增 → 取槽 → 填 pid/dir/len/data → InterlockedExchange 发布`
- `ZETA.exe` 打开同一 Ring 消费 → 中央规则扫描

### 接口（zeta_tlsint.h）

```
ZetaTlsInt_Install / Uninstall / RingOpen / RingMap / RingWrite
GetCaptureCount / GetLastError / GetLastMhStatus
```

### 状态与待办

- ✅ DLL hook + 自动安装 + Ring 回传（自测 3 条明文读回）
- ⏳ **ZETA.exe 注入器**：7006 进程创建回调 → 判定目标 → CreateRemoteThread 加载 DLL（排除系统关键进程 / 自身 / 已注入）
- ⏳ **中央判定**：Ring 消费线程 → C2 黑名单 / 外传大样本 / 敏感信息扫描 → 告警
- 依赖：`MinHook.x64.dll` 需与 DLL 同目录；Ring 为 Session 级（同用户共享）

---

## 历史评估（未采用）

| 方案 | 结论 |
|---|---|
| 密钥留存 Hook（Crypto Capture） | 搁置：复杂度高、覆盖有限；仅"文件已被加密且无备份"才有价值，P2 |
| WriteOffset 写入指纹 / 熵突变检测 | 未实现：误报源多，作为可选检测增强而非必需 |
| 块级 COW 留存 | 未实现：被文档写前备份（只看扩展名）简化替代，v2 大文件场景可选 |
| NetFilter AFD → WFP 迁移 | 未动：内核过滤层改造，P3 待评估（外传检测已由 zeta_tlsint 用户态明文层覆盖） |
| 自研虚拟化（仿 360 晶核） | 不可行：VT-x 被 Hyper-V/VBS 占用 + 签名/工程量门槛 |
