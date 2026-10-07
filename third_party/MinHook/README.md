# MinHook (第三方依赖, 内置副本)

本目录是 `zeta_tlsint` 编译所需的最小依赖集, 于 2026-09-21 从仓库内
`ZeroShell-main/include` 与 `ZeroShell-main/lib` 抽出, 目的是让 `zeta_tlsint`
不再依赖无关项目 `ZeroShell-main/`（该目录已同步清理归档）。

## 来源与许可
- MinHook — x86/x64 API hooking library, 作者 Tsuda Kageyu
- 许可: BSD 2-Clause
- 上游: https://github.com/TsudaKageyu/minhook

## 内容
- `include/MinHook.h`          头文件（= 上游 master，仅 `char * WINAPI` 一处空格差异）
- `src/`                       **源码**（2026-10-05 新增）：`buffer.c` `hook.c` `trampoline.c`
                               与 `hde/hde64.c` `hde/hde32.c`（x86/x64 由各自的 `_M_X64` 守卫选择）
- `LICENSE.txt`                BSD 2-Clause 原文（随源码一并内置）
- `lib/MinHook.x64.lib`        x64 导入库（**已不再被链接**，仅保留作对照/回退）
- `lib/MinHook.x64.dll/.exp`   x64 运行时与导出表（**已不再需要**；旧构建曾依赖它）
- `lib/MinHook.x86.*`          x86 版本（当前构建未使用, 保留备用）

## 构建（2026-10-05 起：静态编译）
`CppLibs/zeta_tlsint/CMakeLists.txt` 通过 `MINHOOK_DIR` 缓存项定位本目录,
默认即此处; 换版本可用 `-DMINHOOK_DIR=<path>` 覆盖。

P1-1 起改为**把 `src/` 直接编进 `ZETA_TlsInt.dll`**，不再链接 `lib/MinHook.x64.lib`。
原因：链接导入库会让产物产生 `MinHook.x64.dll` 运行时依赖，注入场景下少投这一个文件
即 `LoadLibrary` 失败 `err=126`（且失败静默：DLL 没加载 ⇒ hook 没装 ⇒ 明文一条都截不到）。
实测对照（目录内均无 `MinHook.x64.dll`、PATH 只留系统目录）：

| 构建 | 自测结果 |
|---|---|
| 链接导入库（P1-1 前） | `LoadLibrary failed: 126`，退出码 1 |
| 静态编译（P1-1 后） | `capture count = 3` + 3 条明文样本，退出码 0 |

⇒ 现在只需投放 `ZETA_TlsInt.dll` 一个文件。
`include/MinHook.h` 与所编源码同源（上游 master），故 ABI/API 一致。
