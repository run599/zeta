cmake_minimum_required(VERSION 3.16)
project(ZETA_Core VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DZETA_CORE_EXPORTS)
add_definitions(-D_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS)
add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)

file(GLOB_RECURSE SOURCES src/*.cpp)

add_library(${PROJECT_NAME} SHARED ${SOURCES})

target_include_directories(${PROJECT_NAME}
    PUBLIC include
    PRIVATE src
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        advapi32.lib
        shell32.lib
        user32.lib
)

set_target_properties(${PROJECT_NAME} PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY_RELEASE "D:/ZETA"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "D:/ZETA"
    LIBRARY_OUTPUT_DIRECTORY_DEBUG "D:/ZETA"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "D:/ZETA"
)
