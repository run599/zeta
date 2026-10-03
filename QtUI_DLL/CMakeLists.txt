cmake_minimum_required(VERSION 3.16)
project(zeta_ui LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Qt6 paths: 默认=本机现值(历史行为不变); 换机器/换 Qt 版本用
#   -DCMAKE_PREFIX_PATH=<Qt安装目录>   覆盖
if(NOT CMAKE_PREFIX_PATH)
    set(CMAKE_PREFIX_PATH "D:/qtr/6.9.3/msvc2022_64")
endif()
set(QT_DIR "${CMAKE_PREFIX_PATH}")

# zeta_ui.dll 落点: 默认=仓库根/运行目录(历史行为不变);
# 隔离构建(如 Lite 验证) 时用 -DZETA_OUTPUT_DIR=<目录> 覆盖, 避免覆盖在用 DLL。
set(ZETA_OUTPUT_DIR "E:/远控/zeta" CACHE PATH "ZETA 产物输出目录 (zeta_ui.dll 落点)")

find_package(Qt6 REQUIRED COMPONENTS Widgets Core Gui)

set(SOURCES
    src/zeta_ui_export.cpp
    src/MainWindow.cpp
    src/Bridge.cpp
    src/NotificationDialog.cpp
    src/NavSidebar.cpp
)

set(HEADERS
    src/zeta_ui_export.h
    src/MainWindow.h
    src/Bridge.h
    src/NotificationDialog.h
    src/NavSidebar.h
)

add_library(zeta_ui SHARED ${SOURCES} ${HEADERS})

target_link_libraries(zeta_ui PRIVATE
    Qt6::Widgets
    Qt6::Core
    Qt6::Gui
    psapi.lib
    iphlpapi.lib
)

target_include_directories(zeta_ui PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Copy DLL to the runtime dir (= repo root by default; override via ZETA_OUTPUT_DIR)
add_custom_command(TARGET zeta_ui POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        "$<TARGET_FILE:zeta_ui>"
        "${ZETA_OUTPUT_DIR}/zeta_ui.dll"
)
