cmake_minimum_required(VERSION 3.16)
project(ZETA_TlsInt VERSION 2.0.0 LANGUAGES CXX)

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
if(NOT DEFINED MINHOOK_DIR OR MINHOOK_DIR STREQUAL "")
    set(MINHOOK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/MinHook" CACHE PATH "MinHook 依赖根目录" FORCE)
endif()
if(NOT EXISTS "${MINHOOK_DIR}/lib/MinHook.x64.lib")
    message(FATAL_ERROR "MinHook 未找到: ${MINHOOK_DIR} — 需含 include/MinHook.h 与 lib/MinHook.x64.lib, 或用 -DMINHOOK_DIR=<path> 指定")
endif()
target_include_directories(${PROJECT_NAME} PRIVATE ${MINHOOK_DIR}/include)
target_link_libraries(${PROJECT_NAME} PRIVATE ${MINHOOK_DIR}/lib/MinHook.x64.lib)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        secur32.lib
        advapi32.lib
)

# 自测: HTTPS 明文截获验证 (需网络访问 example.com)
add_executable(ZETA_TlsInt_SelfTest tests/tlsint_selftest.cpp)
target_include_directories(ZETA_TlsInt_SelfTest PRIVATE include)
target_link_libraries(ZETA_TlsInt_SelfTest PRIVATE ${PROJECT_NAME} winhttp.lib)
