@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" x64 > nul 2>&1
cmake -S D:\ZETA\CppLibs -B D:\ZETA\CppLibs\build -G Ninja 2>&1
exit /b %ERRORLEVEL%
