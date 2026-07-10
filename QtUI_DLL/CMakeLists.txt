cmake_minimum_required(VERSION 3.16)
project(zeta_ui LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Qt6 paths (MSVC 2022 build)
set(CMAKE_PREFIX_PATH "D:/qtr/6.9.3/msvc2022_64")
set(QT_DIR "D:/qtr/6.9.3/msvc2022_64")

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

# Copy DLL to ZETA root
add_custom_command(TARGET zeta_ui POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        "$<TARGET_FILE:zeta_ui>"
        "${CMAKE_SOURCE_DIR}/../zeta_ui.dll"
)
