# ZETA Security

面向 Windows 10 22H2 (19045) 的**驱动级主动防御**安全软件（HIPS + EDR）。

ZETA 不是传统"特征库 + 用户态 hook"型杀软，而是通过 **minifilter 深度解析 IRP、SSDT hook 前置拦截、Ob 回调 + DKOM 进程自保、磁盘类过滤器封堵原始盘写入**，与恶意软件在内核层对抗。

```
┌─────────────────────────────────────────────────────┐
│  ZETA.exe (Qt 主程序 + 行为引擎)                     │
│  ├─ ZETA_Core.dll      日志 / 配置 / 公共工具         │
│  ├─ ZETA_Driver.dll    驱动通信 / HIPS 规则引擎       │
│  ├─ ZETA_Engine.dll    YARA / PE 启发 / 签名验证      │
│  ├─ ZETA_Monitor.dll   进程/文件/网络监控 + 血统追踪  │
│  ├─ ZETA_Hips.dll      SilverFox / 勒索 / 弹窗拦截    │
│  └─ zeta_ui.dll        Qt 界面                        │
└───────────────┬─────────────────────────────────────┘
                │ (通信)
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

- **IRP 语义拦截（非 ETW 遥测）**：minifilter 在 `IRP_MJ_CREATE / WRITE / SET_INFORMATION / ACQUIRE_FOR_SECTION_SYNC / DEVICE_CONTROL` 检查点深度提取语义上下文（操作类型、信任级、脚本深度、血统标志、offset-0 检测），**Pre-op 可直接拒绝**，不是事后观察。
- **SSDT hook 前置拦截**：`NtQueueApcThread`（APC）、`NtUnloadDriver`（自保）、`NtCreateThreadEx` / `NtWriteVirtualMemory`（注入）在 syscall 层直接拒绝，恶意代码**尚未注入即被拦**。
- **进程自保**：DKOM 写 `EPROCESS.Protection` 升 PPL（绕过 CI 签名检查）+ Ob 回调拦句柄 + 令牌特权注入（SeTcb/SeDebug），常规 `OpenProcess` 杀不掉 ZETA 进程。
- **磁盘写入纵深防护**：minifilter 拦文件层 + **磁盘类过滤器拦 `\\.\PhysicalDriveX` 原始盘写**（offset 0 / -1 即 MBR 写直接 `STATUS_ACCESS_DENIED`），并封堵 `IOCTL_DISK_SET_DRIVE_LAYOUT_EX` / `IOCTL_SCSI_PASS_THROUGH_DIRECT` 等危险 IOCTL——**彩虹猫这类直接写 MBR 的恶意软件被硬拦截**。
- **BYOVD 源头防御**：不可信进程写任何 `.sys` 文件 → 自动拒绝（`ZwLoadDriver` 加载驱动必须先落盘，弹药写不出来即失败）。
- **watchdog 五重自愈**：PPL 字段 / DriverSection 标志 / SSDT 表项 / Ob 回调 / 令牌特权被外部篡改时自动检测并恢复。
- **行为引擎**：评分 + 状态机 + YARA + PE 启发 + 血统追踪，短命进程（`<500ms`）也有驱动回调兜底上报。
- **安全警告**：本项目含 SSDT hook、DKOM、驱动过滤等**内核对抗技术**，仅供安全研究与学习，请勿用于恶意用途。

## 目录结构

```
ZETA-OpenSource/
├── CppLibs/
│   ├── zeta_core/      日志 / 配置 / 公共工具 (DLL)
│   ├── zeta_driver/    驱动通信 / HIPS 规则 (DLL)
│   ├── zeta_engine/    YARA / PE 启发 / 签名验证 (DLL)
│   ├── zeta_hips/      SilverFox / 勒索 / 弹窗拦截 (DLL)
│   ├── zeta_monitor/   进程/文件/网络监控 + 血统 (DLL)
│   └── ZETA/           主程序 ZETA.exe
├── Plugins/
│   ├── Filter/         ZETA_Drv.sys 驱动源码 (minifilter + SSDT + Ob + DKOM)
│   │                   + ZETA_DiskFilter.sys (磁盘类过滤)
│   ├── NetFilter/      ZETA_NetFilter.sys 网络过滤
│   └── Rules/          HIPS 规则 (JSON) + YARA 规则 + 证书
└── QtUI_DLL/           Qt 界面 (zeta_ui.dll)
```

## 构建

### 用户态 DLL + 主程序（CMake + MSVC 2022）

```bat
:: 1. 准备依赖
::    - Visual Studio 2022 (C++ 桌面开发)
::    - Qt 6.9.x (msvc2022_64)
::    - YARA: 将 yara-master 解压到 CppLibs/yara-master
::      (https://github.com/VirusTotal/yara/releases)

:: 2. 配置 + 构建
cd CppLibs
cmake -S . -B build -G Ninja -DCMAKE_PREFIX_PATH=C:/Qt/6.9.3/msvc2022_64
cmake --build build --config Release
```

> 提示：`zeta_engine` 需要 `CppLibs/yara-master`（通过 `-DYARA_DIR=<path>` 可指定其他位置）。
> `ZETA.exe` 主程序需要先构建 `zeta_ui`（QtUI_DLL）生成 `zeta_ui.lib`。

### 内核驱动（Visual Studio 驱动工程）

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
