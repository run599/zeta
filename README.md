# ZETA Security

面向 Windows 10 22H2 (19045) 的**驱动级主动防御**安全软件（HIPS + EDR）。

ZETA 不是传统"特征库 + 用户态 hook"型杀软，而是通过 **minifilter 深度解析 IRP、SSDT hook 前置拦截、Ob 回调 + DKOM 进程自保、磁盘类过滤器封堵原始盘写入**，与恶意软件在内核层对抗。

```
┌─────────────────────────────────────────────────────┐
│  ZETA.exe (Qt 主程序 + 行为引擎)                     │
│  ├─ ZETA_Core.dll      日志 / 配置 / 签名验证         │
│  ├─ ZETA_Driver.dll    驱动通信 / HIPS 规则引擎       │
│  ├─ ZETA_Engine.dll    YARA / PE 启发 / 签名验证      │
│  ├─ ZETA_Monitor.dll   进程/文件/网络监控 + 血统追踪  │
│  ├─ ZETA_Hips.dll      SilverFox / 勒索 / 弹窗拦截    │
│  └─ zeta_ui.dll        Qt 界面                        │
└───────────────┬─────────────────────────────────────┘
                │ (事件码消息, 契约见 events.h)
┌───────────────▼─────────────────────────────────────┐
│  ZETA_Drv.sys       minifilter: IRP 深度解析 + 拦截   │
│  ZETA_DiskFilter.sys 磁盘类过滤: MBR/SCSI 直通封堵     │
│  ZETA_NetFilter.sys  网络过滤                          │
│  ├─ SSDT hook ×4     APC / 卸载 / 远程线程 / 内存写   │
│  ├─ ObRegisterCallbacks  进程/线程句柄保护             │
│  ├─ DKOM 进程保护   EPROCESS.Protection → PPL 0x0A    │
│  ├─ 内核回调上报   进程创建 / 线程创建 / 镜像加载       │
│  └─ watchdog 自愈   五重校验 + 自动恢复                │
└─────────────────────────────────────────────────────┘
```

## 核心特性

- **IRP 语义拦截（非 ETW 遥测）**：minifilter 在 `IRP_MJ_CREATE / WRITE / SET_INFORMATION / ACQUIRE_FOR_SECTION_SYNC / DEVICE_CONTROL` 检查点深度提取语义上下文（操作类型、信任级、脚本深度、血统标志、offset-0 检测），**Pre-op 可直接拒绝**。
- **SSDT hook 前置拦截**：`NtQueueApcThread`（APC）、`NtUnloadDriver`（自保）、`NtCreateThreadEx` / `NtWriteVirtualMemory`（注入）在 syscall 层直接拒绝。
- **进程自保**：DKOM 写 `EPROCESS.Protection` 升 PPL + Ob 回调拦句柄 + 令牌特权注入。
- **磁盘写入纵深防护**：minifilter 拦文件层 + **磁盘类过滤器拦 `\\.\PhysicalDriveX` 原始盘写**（offset 0 / -1 即 MBR 写直接拒绝），封堵 `IOCTL_DISK_SET_DRIVE_LAYOUT_EX` / `IOCTL_SCSI_PASS_THROUGH_DIRECT` 等危险 IOCTL。
- **BYOVD 源头防御**：不可信进程写任何 `.sys` 文件 → 自动拒绝。
- **统一信任判定（TrustDecider）**：系统进程名 / 系统目录精确前缀 / 有效签名三层判定收敛为单一入口，名单数据外置 `TrustRules.json` 可配置。
- **事件码契约（events.h）**：驱动 → 用户态所有消息码唯一定义源，各工程共用，杜绝裸数字。
- **watchdog 五重自愈**：PPL 字段 / DriverSection 标志 / SSDT 表项 / Ob 回调 / 令牌特权被篡改时自动恢复。
- **行为引擎**：评分 + 状态机 + YARA + PE 启发 + 血统追踪。
- **安全警告**：本项目含 SSDT hook、DKOM、驱动过滤等**内核对抗技术**，仅供安全研究与学习，请勿用于恶意用途。

## 目录结构

```
zeta/                       单源码树 —— Full / Lite 由构建参数切换, 非两棵并列代码树
├── CppLibs/
│   ├── zeta_core/      日志 / 配置 / 签名验证 (DLL)
│   ├── zeta_driver/    驱动通信 / HIPS 规则 (DLL)
│   ├── zeta_engine/    YARA / PE 启发 / 签名验证 (DLL)
│   ├── zeta_hips/      SilverFox / 勒索 / 弹窗拦截 (DLL)
│   ├── zeta_monitor/   进程/文件/网络监控 + 血统 (DLL)
│   ├── zeta_tlsint/    TLS 明文截获 (DLL, 依赖 third_party/MinHook)
│   └── ZETA/           主程序 ZETA.exe + TrustDecider (trust.h/trust.cpp)
├── Plugins/
│   ├── Filter/         ZETA_Drv.sys 驱动源码 + events.h (事件码契约)
│   │                   + ZETA_DiskFilter.sys (磁盘类过滤)
│   ├── NetFilter/      ZETA_NetFilter.sys 网络过滤
│   └── Rules/          HIPS 规则 (JSON) + TrustRules.json (信任名单)
│                       + YARA 规则 + 证书
├── QtUI_DLL/           Qt 界面 (zeta_ui.dll) —— 独立 CMake 工程, 必须先构建
├── third_party/        MinHook (BSD-2-Clause, zeta_tlsint 依赖, 已内置)
├── tools/              debugtool / symbols / update (Go) / zeta_meta (Go)
├── docs/              设计文档
└── archive/           历史归档 (含已合并的 ZETA-Lite 旧树)
```

## 构建

### 用户态 DLL + 主程序（CMake + MSVC 2022）

**构建顺序有依赖**：`QtUI_DLL` 是独立的 CMake 工程，必须先构建它产出 `zeta_ui.lib`，
`ZETA.exe` 才能链接成功。

```bat
:: 0. 前置
::    - Visual Studio 2022 (C++ 桌面开发)
::    - Qt 6.9.x (msvc2022_64)
::    - YARA: 解压 yara-master 到 CppLibs/yara-master (或用 -DYARA_DIR 指定)
::    - MinHook: 仓库已内置于 third_party/MinHook, 无需外部准备

:: 1. 先构建界面工程 -> zeta_ui.dll / zeta_ui.lib
cmake -S QtUI_DLL -B QtUI_DLL/build3 -G "Visual Studio 17 2022" -A x64 ^
      -DCMAKE_PREFIX_PATH=D:/qtr/6.9.3/msvc2022_64
cmake --build QtUI_DLL/build3 --config Release

:: 2. 再构建各模块 + 主程序 (默认输出到仓库根 = 运行目录)
cmake -S CppLibs -B CppLibs/build -G Ninja ^
      -DCMAKE_PREFIX_PATH=D:/qtr/6.9.3/msvc2022_64
cmake --build CppLibs/build
```

#### 可调参数（均有默认值，缺省＝历史行为）

| 参数 | 默认值 | 用途 |
|---|---|---|
| `ZETA_EDITION` | `full` | `full`=含 SSDT hook；`lite`=剔除 SSDT 路径（可过 HVCI/PatchGuard） |
| `ZETA_OUTPUT_DIR` | 仓库根 | DLL/EXE 输出目录。**隔离构建务必覆盖**，否则会覆盖正在使用的产物 |
| `ZETA_QT_DIR` | `D:/qtr/6.9.3/msvc2022_64` | Qt6 安装目录 |
| `ZETA_UI_LIB_DIR` | `QtUI_DLL/build3/Release` | `zeta_ui.lib` 位置（UI 构建到别处时覆盖） |
| `YARA_DIR` | `CppLibs/yara-master` | YARA 源码根；缺失即报错并说明原因 |
| `MINHOOK_DIR` | `third_party/MinHook` | MinHook 依赖根 |

```bat
:: 例: 构建 Lite 版到临时目录, 完全不影响正在使用的 Full 产物
CppLibs\run_cmake.bat lite E:/tmp/zeta-lite
```

### 内核驱动（VS 驱动工程 + WDK）

驱动同样是**单一工程、双版本**，由 MSBuild 属性切换：

```bat
msbuild Plugins\Filter\ZETA_Driver.vcxproj /p:Configuration=Release /p:Platform=x64 /p:ZetaEnableSsdt=1
::  ZetaEnableSsdt=1 (默认) = Full: APC / UnloadGuard / 注入拦截 / 间接 syscall 反制
::  ZetaEnableSsdt=0        = Lite: ApcHook/InjectHook 整文件空编, 19/20/22/24 号命令走 #else
```

驱动使用 WDK + VS 驱动工程（`Plugins/Filter/ZETA_Driver.sln` / `ZETA_DiskFilter.vcxproj`）。
构建时**请使用自己的 WHQL/EV 代码签名证书**（开源版不附带签名脚本与私钥）。
测试机请先启用测试签名：`bcdedit /set testsigning on`。

## 兼容性

- 目标系统：**Windows 10 22H2 (build 19045)**（DKOM 偏移、SSDT 索引针对此版本验证）
- 其他 Windows 10 版本（2004+）部分可用（`DetectProtectionOffset` 按 build 分支）
- 不支持 Windows 11（EPROCESS 偏移未适配）

## 免责声明

本项目仅供安全研究与学习交流。作者不对因使用本软件造成的任何直接或间接损失负责。
请勿将本项目用于任何违法用途。
