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

# ── YARA 依赖 ──────────────────────────────────────────────────
# zeta_engine 内置 YARA (BSD-3 许可) 用于规则匹配。
# 构建前需把 yara-master 放在 CppLibs/ 下 (与 zeta_engine 同级),
# 或通过 -DYARA_DIR=<path> 指定 yara 源码根目录。
if(NOT DEFINED YARA_DIR)
    set(YARA_DIR "${YARA_DIR}")
endif()
if(NOT EXISTS "${YARA_DIR}/libyara/libyara.c")
    message(FATAL_ERROR
        "YARA 源码未找到: ${YARA_DIR}\n"
        "请将 yara-master 解压到 CppLibs/yara-master (https://github.com/VirusTotal/yara/releases)\n"
        "或通过 -DYARA_DIR=<path> 指定路径。")
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
    LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
)
