cmake_minimum_required(VERSION 3.16)
project(ZETA_Engine VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DZETA_CORE_EXPORTS)
add_definitions(-D_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS)
add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
add_definitions(-D_CRT_SECURE_NO_WARNINGS)
add_definitions(-DUSE_WINDOWS_PROC)
add_definitions(-DBUCKETS_128)
add_definitions(-DCHECKSUM_1B)

# ── 源码字符集 (2026-10-03) ────────────────────────────────────────────
# 背景: 本工程的编译参数里【没有】任何字符集选项, MSVC 因此靠 UTF-8 BOM 判定源文件
#       编码。一旦有人用会丢 BOM 的编辑器改这些源文件(实测: 用工具重写 scanner.cpp
#       即丢失 BOM), 中文注释就会被按系统 ANSI 代码页(GBK)误解码 —— 某些 UTF-8
#       字节序列解出尾字节 0x5C(反斜杠), 变成续行 → 行号错位 + 大面积级联语法错误,
#       且报错位置与真实问题无关, 极难定位(本次排查中就撞了两次)。
# 选择: 用 /source-charset:utf-8 而不是 /utf-8 —— 前者只固定"源文件字节如何解码"
#       (正是去掉 BOM 承重所需), 不动执行字符集; 后者会把执行字符集也改成 UTF-8,
#       若本工程存在窄字符中文字面量并参与比较, 会静默改变运行时行为。
#       只改解码, 则任何窄字符字面量的落地编码与改动前完全一致 = 零行为变更。
add_compile_options(/source-charset:utf-8)

# ── YARA 依赖参数 ───────────────────────────────────────────────────────
# zeta_engine 内置 YARA (BSD-3) 用于规则匹配。默认取仓库内 CppLibs/yara-master;
# 换位置/换版本用 -DYARA_DIR=<path> 覆盖。缺失时立刻失败并说清原因,
# 不再让链接阶段抛出难以定位的错误。
if(NOT DEFINED YARA_DIR OR YARA_DIR STREQUAL "")
    set(YARA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../yara-master" CACHE PATH "YARA 源码根目录" FORCE)
endif()
if(NOT EXISTS "${YARA_DIR}/libyara/libyara.c")
    message(FATAL_ERROR "YARA 源码未找到: ${YARA_DIR} — 请解压 yara-master 到 CppLibs/yara-master 或用 -DYARA_DIR=<path> 指定")
endif()

# ZETA Engine source files
file(GLOB_RECURSE ZETA_SOURCES src/*.cpp)

# ── YARA source files ──────────────────────────────────────────
# Core YARA library (all .c files from libyara/ root)
file(GLOB YARA_CORE_SOURCES
    ${YARA_DIR}/libyara/ahocorasick.c
    ${YARA_DIR}/libyara/arena.c
    ${YARA_DIR}/libyara/atoms.c
    ${YARA_DIR}/libyara/base64.c
    ${YARA_DIR}/libyara/bitmask.c
    ${YARA_DIR}/libyara/compiler.c
    ${YARA_DIR}/libyara/exec.c
    ${YARA_DIR}/libyara/exefiles.c
    ${YARA_DIR}/libyara/filemap.c
    ${YARA_DIR}/libyara/grammar.c
    ${YARA_DIR}/libyara/hash.c
    ${YARA_DIR}/libyara/hex_grammar.c
    ${YARA_DIR}/libyara/hex_lexer.c
    ${YARA_DIR}/libyara/lexer.c
    ${YARA_DIR}/libyara/libyara.c
    ${YARA_DIR}/libyara/mem.c
    ${YARA_DIR}/libyara/modules.c
    ${YARA_DIR}/libyara/notebook.c
    ${YARA_DIR}/libyara/object.c
    ${YARA_DIR}/libyara/parser.c
    ${YARA_DIR}/libyara/proc.c
    ${YARA_DIR}/libyara/proc/windows.c
    ${YARA_DIR}/libyara/re.c
    ${YARA_DIR}/libyara/re_grammar.c
    ${YARA_DIR}/libyara/re_lexer.c
    ${YARA_DIR}/libyara/rules.c
    ${YARA_DIR}/libyara/scan.c
    ${YARA_DIR}/libyara/scanner.c
    ${YARA_DIR}/libyara/sizedstr.c
    ${YARA_DIR}/libyara/simple_str.c
    ${YARA_DIR}/libyara/stack.c
    ${YARA_DIR}/libyara/stopwatch.c
    ${YARA_DIR}/libyara/stream.c
    ${YARA_DIR}/libyara/strutils.c
    ${YARA_DIR}/libyara/threading.c
    ${YARA_DIR}/libyara/tlshc/tlsh_util.c
    ${YARA_DIR}/libyara/tlshc/tlsh_impl.c
    ${YARA_DIR}/libyara/tlshc/tlsh.c
)

# YARA modules (excluding pe, hash, cuckoo which need OpenSSL/Jansson)
set(YARA_MODULE_SOURCES
    ${YARA_DIR}/libyara/modules/console/console.c
    ${YARA_DIR}/libyara/modules/dex/dex.c
    ${YARA_DIR}/libyara/modules/elf/elf.c
    ${YARA_DIR}/libyara/modules/macho/macho.c
    ${YARA_DIR}/libyara/modules/math/math.c
    ${YARA_DIR}/libyara/modules/pe/pe.c
    ${YARA_DIR}/libyara/modules/pe/pe_utils.c
    ${YARA_DIR}/libyara/modules/string/string.c
    ${YARA_DIR}/libyara/modules/tests/tests.c
    ${YARA_DIR}/libyara/modules/time/time.c
)

add_library(${PROJECT_NAME} SHARED
    ${ZETA_SOURCES}
    ${YARA_CORE_SOURCES}
    ${YARA_MODULE_SOURCES}
)

target_include_directories(${PROJECT_NAME}
    PUBLIC include
    PRIVATE
        src
        include
        ${YARA_DIR}/libyara
        ${YARA_DIR}/libyara/include
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        wintrust.lib
        crypt32.lib
        shlwapi.lib
        version.lib
)

set_target_properties(${PROJECT_NAME} PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY_RELEASE "${ZETA_OUTPUT_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${ZETA_OUTPUT_DIR}"
    LIBRARY_OUTPUT_DIRECTORY_DEBUG "${ZETA_OUTPUT_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${ZETA_OUTPUT_DIR}"
)
