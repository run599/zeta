cmake_minimum_required(VERSION 3.16)
project(ZETA VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Force MSVC to treat source files as UTF-8 (supports Chinese in string literals)
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
# /EHa: enable SEH (access violation) to be caught by C++ try-catch
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/EHa>")

add_definitions(-D_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS)
add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)

file(GLOB_RECURSE SOURCES src/*.cpp)

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME}
    PRIVATE src
    PRIVATE include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../zeta_core/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../zeta_engine/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../zeta_hips/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../zeta_monitor/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../zeta_driver/include
    PRIVATE D:/ZETA/QtUI_DLL/src
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        shlwapi.lib
        advapi32.lib
        user32.lib
        ZETA_Driver
)

# Include zeta_ui DLL import lib
target_link_directories(${PROJECT_NAME} PRIVATE
    D:/ZETA/QtUI_DLL/build/Release
    D:/qtr/6.9.3/msvc2022_64/lib
    ${CMAKE_CURRENT_SOURCE_DIR}/../zeta_driver/build/Release
)
target_link_libraries(${PROJECT_NAME} PRIVATE
    zeta_ui.lib
    Qt6Widgets.lib
    Qt6Gui.lib
    Qt6Core.lib
)

# Output directly to D:\ZETA
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "D:/ZETA"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "D:/ZETA"
)
