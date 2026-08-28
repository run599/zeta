@echo off
cd /d "%~dp0"
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 > nul 2>&1
cmake -S . -B build -G Ninja 2>&1
exit /b %ERRORLEVEL%
