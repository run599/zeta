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

# ZETA Engine source files
file(GLOB_RECURSE ZETA_SOURCES src/*.cpp)

# ── YARA source files ──────────────────────────────────────────
# Core YARA library (all .c files from libyara/ root)
file(GLOB YARA_CORE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/ahocorasick.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/arena.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/atoms.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/base64.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/bitmask.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/compiler.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/exec.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/exefiles.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/filemap.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/grammar.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/hash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/hex_grammar.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/hex_lexer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/lexer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/libyara.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/mem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/modules.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/notebook.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/object.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/parser.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/proc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/proc/windows.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/re.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/re_grammar.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/re_lexer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/rules.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/scan.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/scanner.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/sizedstr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/simple_str.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/stack.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/stopwatch.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/stream.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/strutils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/threading.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/tlshc/tlsh_util.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/tlshc/tlsh_impl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/tlshc/tlsh.c
)

# YARA modules (excluding pe, hash, cuckoo which need OpenSSL/Jansson)
set(YARA_MODULE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/modules/console/console.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/modules/dex/dex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/modules/elf/elf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/modules/macho/macho.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/modules/math/math.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/modules/pe/pe.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/modules/pe/pe_utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/modules/string/string.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/modules/tests/tests.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/modules/time/time.c
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
        ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara
        ${CMAKE_CURRENT_SOURCE_DIR}/../yara-master/libyara/include
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        wintrust.lib
        crypt32.lib
        shlwapi.lib
        version.lib
)

set_target_properties(${PROJECT_NAME} PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY_RELEASE "D:/ZETA"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "D:/ZETA"
    LIBRARY_OUTPUT_DIRECTORY_DEBUG "D:/ZETA"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "D:/ZETA"
)
