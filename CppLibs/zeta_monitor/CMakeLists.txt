cmake_minimum_required(VERSION 3.16)
project(ZETA_Monitor VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DZETA_MONITOR_EXPORTS)
add_definitions(-D_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS)
add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)

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
        advapi32.lib
        iphlpapi.lib
        ws2_32.lib
        shlwapi.lib
        user32.lib
        ole32.lib
        wbemuuid.lib
        secur32.lib
        tdh.lib
        ZETA_Core
)

set_target_properties(${PROJECT_NAME} PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
)
