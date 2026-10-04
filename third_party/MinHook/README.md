# MinHook (第三方依赖, 内置副本)

本目录是 `zeta_tlsint` 编译所需的最小依赖集, 于 2026-09-21 从仓库内
`ZeroShell-main/include` 与 `ZeroShell-main/lib` 抽出, 目的是让 `zeta_tlsint`
不再依赖无关项目 `ZeroShell-main/`（该目录已同步清理归档）。

## 来源与许可
- MinHook — x86/x64 API hooking library, 作者 Tsuda Kageyu
- 许可: BSD 2-Clause
- 上游: https://github.com/TsudaKageyu/minhook

## 内容
- `include/MinHook.h`          头文件
- `lib/MinHook.x64.lib`        x64 导入库（zeta_tlsint 实际链接的就是这个）
- `lib/MinHook.x64.dll/.exp`   x64 运行时与导出表
- `lib/MinHook.x86.*`          x86 版本（当前构建未使用, 保留备用）

## 构建
`CppLibs/zeta_tlsint/CMakeLists.txt` 通过 `MINHOOK_DIR` 缓存项定位本目录,
默认即此处; 换版本可用 `-DMINHOOK_DIR=<path>` 覆盖。
