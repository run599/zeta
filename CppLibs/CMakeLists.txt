cmake_minimum_required(VERSION 3.16)
project(ZETA_CPP VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows API minimum version - set BEFORE any headers
add_definitions(-D_WIN32_WINNT=0x0601)
add_definitions(-DWINVER=0x0601)

# Suppress deprecation warnings for codecvt
add_definitions(-D_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS)
add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)

add_subdirectory(zeta_core)
add_subdirectory(zeta_driver)
add_subdirectory(zeta_engine)
add_subdirectory(zeta_monitor)
add_subdirectory(zeta_hips)
add_subdirectory(ZETA)

message(STATUS "All ZETA C++ DLL targets configured")
message(STATUS "  - zeta_core.dll: Logging, Config, Common")
message(STATUS "  - zeta_driver.dll: Driver Comm, HIPS Rules")
message(STATUS "  - zeta_engine.dll: YARA, PE Scan, Sign Verify")
message(STATUS "  - zeta_monitor.dll: Process/File/Net Monitor, ETW, Lineage")
message(STATUS "  - zeta_hips.dll: SilverFox, Ransomware, Popup Block")
