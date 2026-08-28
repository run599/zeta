cmake_minimum_required(VERSION 3.16)
project(ZETA_Hips VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DZETA_HIPS_EXPORTS)
add_definitions(-D_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS)
add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)

# Force UTF-8 source encoding to handle Chinese comments
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/source-charset:utf-8>")
# /EHa: enable SEH (access violation) to be caught by C++ try-catch
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/EHa>")

file(GLOB_RECURSE SOURCES src/*.cpp)

add_library(${PROJECT_NAME} SHARED ${SOURCES})

target_include_directories(${PROJECT_NAME}
    PUBLIC include
    PRIVATE src
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../zeta_core/include
)

target_link_directories(${PROJECT_NAME} PRIVATE ${CMAKE_BINARY_DIR}/bin)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        user32.lib
        advapi32.lib
        wintrust.lib
        crypt32.lib
        ws2_32.lib
        ZETA_Core
)

set_target_properties(${PROJECT_NAME} PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
)
