cmake_minimum_required(VERSION 3.16)
project(ZETA_TlsInt_Host VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 本模块的日志/告警文案含中文，显式 /utf-8，否则 MSVC 按代码页 936 解析会产生乱码
# （注意：这是**新模块**自身的设置，不是去动 zeta_tlsint 的编译选项）
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

# 静态库：注入器 + 环消费/判定。ZETA.exe 内嵌它；同时被自测 exe 链接。
add_library(ZETA_TlsInt_Host STATIC
    src/tlsint_host.cpp
    src/tlsint_inject.cpp
    src/tlsint_detect.cpp
)

target_include_directories(ZETA_TlsInt_Host
    PUBLIC  include
    PRIVATE src
    # 复用 Ring 的名字与结构体定义（单一事实来源；不链接该 DLL）
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../zeta_tlsint/include
)

target_link_libraries(ZETA_TlsInt_Host PRIVATE advapi32.lib)

# 自测：不需要 ZETA.exe、不加载任何内核驱动
add_executable(ZETA_TlsInt_HostTest tests/tlsint_host_test.cpp)
target_include_directories(ZETA_TlsInt_HostTest PRIVATE include)
target_link_libraries(ZETA_TlsInt_HostTest PRIVATE ZETA_TlsInt_Host winhttp.lib advapi32.lib)
