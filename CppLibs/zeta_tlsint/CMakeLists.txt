cmake_minimum_required(VERSION 3.16)
# P1-1: 本目标现在含 C 源码 (MinHook: buffer.c/hook.c/trampoline.c/hde*.c),
# 必须在此声明 C —— 兄弟目录 zeta_engine 的 enable_language(C) 不会传播到本作用域,
# 否则 generate 阶段报 "Missing variable is: CMAKE_C_COMPILE_OBJECT"。
project(ZETA_TlsInt VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DZETA_TLSINT_EXPORTS)
add_definitions(-DSECURITY_WIN32)   # sspi.h 必需 (SEC_ENTRY/SECBUFFER_*)
add_definitions(-D_WIN32_WINNT=0x0601)
add_definitions(-DWINVER=0x0601)
add_definitions(-D_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS)
add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)

file(GLOB_RECURSE SOURCES src/*.cpp)

add_library(${PROJECT_NAME} SHARED ${SOURCES})

target_include_directories(${PROJECT_NAME}
    PUBLIC include
)

# MinHook (BSD-2-Clause, Tsuda Kageyu) — 第三方依赖已抽到仓库内 third_party/MinHook/,
# 不再依赖 ZeroShell-main/（该目录为无关项目, 已于 2026-09-21 清理归档）。
# 换版本用 -DMINHOOK_DIR=<path> 覆盖; 缺失时立刻失败并说清原因。
#
# P1-1 (2026-10-05): 由「链接 MinHook.x64.lib 导入库」改为「静态编译 MinHook 源码」。
# 原因: 链接导入库会让 ZETA_TlsInt.dll 产生 MinHook.x64.dll 运行时依赖, 注入场景下
# 少投这一个文件就 LoadLibrary 失败 (err=126, 实测从 build\zeta_tlsint\ 直接跑自测即复现),
# 而失败是静默的 (DLL 没加载 => hook 没装 => 明文一条都截不到)。静态编译后产物自包含,
# 只需投 ZETA_TlsInt.dll 一个文件。
# 源码取自上游 master (与仓库内 include/MinHook.h 逐字同源, 仅一处注释空格差异),
# 见 third_party/MinHook/README.md 与 LICENSE.txt。
if(NOT DEFINED MINHOOK_DIR OR MINHOOK_DIR STREQUAL "")
    set(MINHOOK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/MinHook" CACHE PATH "MinHook 依赖根目录" FORCE)
endif()
set(MINHOOK_SOURCES
    "${MINHOOK_DIR}/src/buffer.c"
    "${MINHOOK_DIR}/src/hook.c"
    "${MINHOOK_DIR}/src/trampoline.c"
    "${MINHOOK_DIR}/src/hde/hde64.c"
    "${MINHOOK_DIR}/src/hde/hde32.c")   # hde32/hde64 各自按 _M_X64 守卫, 非目标架构编译为空
foreach(_mh_src IN LISTS MINHOOK_SOURCES)
    if(NOT EXISTS "${_mh_src}")
        message(FATAL_ERROR "MinHook 源缺失: ${_mh_src} — 需 ${MINHOOK_DIR}/src 下含 buffer.c/hook.c/trampoline.c/hde/, 或用 -DMINHOOK_DIR=<path> 指定")
    endif()
endforeach()
if(NOT EXISTS "${MINHOOK_DIR}/include/MinHook.h")
    message(FATAL_ERROR "MinHook 头缺失: ${MINHOOK_DIR}/include/MinHook.h")
endif()
target_sources(${PROJECT_NAME} PRIVATE ${MINHOOK_SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE
    ${MINHOOK_DIR}/include
    ${MINHOOK_DIR}/src
    ${MINHOOK_DIR}/src/hde
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        secur32.lib
        advapi32.lib
)

# 自测: HTTPS 明文截获验证 (需网络访问 example.com)
add_executable(ZETA_TlsInt_SelfTest tests/tlsint_selftest.cpp)
target_include_directories(ZETA_TlsInt_SelfTest PRIVATE include)
target_link_libraries(ZETA_TlsInt_SelfTest PRIVATE ${PROJECT_NAME} winhttp.lib)

# ── M2-3: 产物落到 ZETA 运行目录，与其余 5 个用户态 DLL 一致 ─────────────────
# 注入器（zeta_tlsint_host）按"与 ZETA.exe 同目录"查找本 DLL。本工程此前**唯独**
# 没设输出目录，所以 E:\远控\zeta\ 下长期没有 ZETA_TlsInt.dll，注入器只会静默地
# "TLS 明文截获未启用" —— 编译全绿但功能为零。这里补齐，与 zeta_core/driver/engine/
# monitor/hips 的四条属性完全一致。
set_target_properties(${PROJECT_NAME} PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY_RELEASE "${ZETA_OUTPUT_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${ZETA_OUTPUT_DIR}"
    LIBRARY_OUTPUT_DIRECTORY_DEBUG "${ZETA_OUTPUT_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${ZETA_OUTPUT_DIR}"
)

# 自测 exe 用 LoadLibraryW(L"ZETA_TlsInt.dll") 按 **exe 所在目录** 找 DLL；
# DLL 既然搬去了运行目录，就往自测 exe 旁边也放一份，保证原地自测仍可用。
add_custom_command(TARGET ZETA_TlsInt_SelfTest POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:ZETA_TlsInt>" "$<TARGET_FILE_DIR:ZETA_TlsInt_SelfTest>"
    COMMENT "自测 exe 旁同步一份 ZETA_TlsInt.dll（自测按 exe 目录加载）"
)
