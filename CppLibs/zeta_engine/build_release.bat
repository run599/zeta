@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" > nul 2>&1
ninja -C "D:\ZETA\CppLibs\zeta_engine\build" -j8 2>&1
