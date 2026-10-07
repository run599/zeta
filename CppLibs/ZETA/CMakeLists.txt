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
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../zeta_tlsint_host/include
    PRIVATE ${CMAKE_SOURCE_DIR}/../QtUI_DLL/src
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        shlwapi.lib
        advapi32.lib
        user32.lib
        wintrust.lib
        ZETA_Driver
        ZETA_TlsInt_Host
)

# zeta_ui 导入库：QtUI_DLL 是**独立的 CMake 工程**, 必须先构建它才能链接 ZETA.exe。
# 其产物目录用 -DZETA_UI_LIB_DIR=<dir> 覆盖; 默认＝历史路径 QtUI_DLL/build3/Release。
# 缺失时给出可照做的构建顺序提示, 而不是让链接阶段抛一句没人看得懂的错。
set(ZETA_UI_LIB_DIR "${CMAKE_SOURCE_DIR}/../QtUI_DLL/build3/Release" CACHE PATH "zeta_ui.lib 所在目录 (需先构建 QtUI_DLL)")
if(NOT EXISTS "${ZETA_UI_LIB_DIR}/zeta_ui.lib")
    message(WARNING
        "未找到 ${ZETA_UI_LIB_DIR}/zeta_ui.lib —— ZETA.exe 链接会失败。\n"
        "  请先构建界面工程, 再回来构建本工程:\n"
        "    cmake -S <repo>/QtUI_DLL -B <repo>/QtUI_DLL/build3 -G \"Visual Studio 17 2022\" -A x64\n"
        "    cmake --build <repo>/QtUI_DLL/build3 --config Release\n"
        "  或用 -DZETA_UI_LIB_DIR=<dir> 指定已有 zeta_ui.lib 的目录。")
endif()

target_link_directories(${PROJECT_NAME} PRIVATE
    ${ZETA_UI_LIB_DIR}
    ${ZETA_QT_DIR}/lib
)
target_link_libraries(${PROJECT_NAME} PRIVATE
    zeta_ui.lib
    Qt6Widgets.lib
    Qt6Gui.lib
    Qt6Core.lib
)

# Output directly to the runtime dir (= repo root by default; override via ZETA_OUTPUT_DIR)
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${ZETA_OUTPUT_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${ZETA_OUTPUT_DIR}"
)
