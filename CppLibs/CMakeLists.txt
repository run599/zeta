cmake_minimum_required(VERSION 3.16)
project(ZETA_CPP VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows API minimum version - set BEFORE any headers
add_definitions(-D_WIN32_WINNT=0x0601)
add_definitions(-DWINVER=0x0601)

# Suppress deprecation warnings for codecvt
add_definitions(-D_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS)
add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)

# ── 版本(edition)参数：单一源码树同时支持 Full / Lite ─────────────────────
# 背景: 此前 Full / Lite 靠两棵并列源码树维护, Lite 是 Full 的早期快照,
#       结果 SSDT 宏从未在 Lite 工程里显式定义(兜底默认 1), 导致"Lite 版"
#       实际编入了完整 SSDT 代码且可被激活 —— 与设计相反。
# 现在: 版本只由构建参数决定, 源码唯一。
#   full (默认): 用户态不再下发 SSDT 相关命令 (19/20/22) —— 与驱动侧默认一致
#   lite        : 同上 (两版差异仅供未来扩展保留)
# ⚠ 2026-09-30: SSDT 已退役, full/lite 均置 ZETA_ENABLE_SSDT=0。
#   原因见 Plugins/Filter/DriverCommon.h: PatchGuard 校验 KiServiceTable
#   (0x109 定时炸弹) + 注入/APC 已被 Ob 回调在句柄层提前覆盖 + UnloadGuard 实测无效。
#   要重新启用请显式改回 1, 并同步改驱动的 ZetaEnableSsdt 默认值。
# 用法: cmake -S . -B build -DZETA_EDITION=lite
set(ZETA_EDITION "full" CACHE STRING "ZETA edition: full | lite")
set_property(CACHE ZETA_EDITION PROPERTY STRINGS "full" "lite")

if(ZETA_EDITION STREQUAL "lite")
    add_definitions(-DZETA_ENABLE_SSDT=0)
    message(STATUS "ZETA edition: LITE  (SSDT disabled)")
elseif(ZETA_EDITION STREQUAL "full")
    add_definitions(-DZETA_ENABLE_SSDT=0)
    message(STATUS "ZETA edition: FULL  (SSDT retired — user-mode 不下发 19/20/22)")
else()
    message(FATAL_ERROR "ZETA_EDITION 取值非法: '${ZETA_EDITION}' (只允许 full 或 lite)")
endif()

# ── 输出目录参数：单一源码树同时服务 Full / Lite，互不覆盖 ────────────────
# 背景: 此前 8 个子工程把产物目录硬编码为 "E:/远控/zeta"(=仓库根, 同时也是
#       运行时目录), 因此任何一次 Lite 用户态构建都会直接覆盖正在使用的
#       Full DLL —— 这是"Lite 用户态从未构建过"的直接原因, 也是合并前置条件。
# 默认值 = 历史行为, 既有 Full 构建结果与产物路径完全不变;
# 需要隔离时显式覆盖:
#   cmake -S . -B build-lite -G Ninja -DZETA_EDITION=lite -DZETA_OUTPUT_DIR=E:/tmp/zeta-lite
set(ZETA_OUTPUT_DIR "E:/远控/zeta" CACHE PATH
    "ZETA 用户态产物输出目录 (默认=仓库根/运行目录, 与历史行为一致)")

# ── Qt 根目录参数 ───────────────────────────────────────────────────────
# ZETA.exe 直接链接 Qt6 导入库, 需要显式 lib 目录; 默认=本机现值, 换机覆盖。
set(ZETA_QT_DIR "D:/qtr/6.9.3/msvc2022_64" CACHE PATH "Qt6 MSVC 安装目录")

add_subdirectory(zeta_core)
add_subdirectory(zeta_driver)
add_subdirectory(zeta_engine)
add_subdirectory(zeta_monitor)
add_subdirectory(zeta_hips)
add_subdirectory(zeta_tlsint)
add_subdirectory(ZETA)

message(STATUS "All ZETA C++ DLL targets configured")
message(STATUS "  - zeta_core.dll: Logging, Config, Common")
message(STATUS "  - zeta_driver.dll: Driver Comm, HIPS Rules")
message(STATUS "  - zeta_engine.dll: YARA, PE Scan, Sign Verify")
message(STATUS "  - zeta_monitor.dll: Process/File/Net Monitor, ETW, Lineage")
message(STATUS "  - zeta_hips.dll: SilverFox, Ransomware, Popup Block")
