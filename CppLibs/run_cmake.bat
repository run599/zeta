@echo off
rem ─────────────────────────────────────────────────────────────────────
rem 用法: run_cmake.bat [edition] [output_dir]
rem   edition   : full(默认) | lite         -> -DZETA_EDITION
rem   output_dir: 产物目录, 缺省即 CMake 默认值 E:/远控/zeta (仓库根/运行目录)
rem 例:
rem   run_cmake.bat                            Full 构建, 落仓库根(历史行为)
rem   run_cmake.bat lite E:/tmp/zeta-lite       Lite 构建, 落临时目录不覆盖在用产物
rem 说明: 路径全部相对本脚本定位, 换机器/换盘符无需改文件。
rem ─────────────────────────────────────────────────────────────────────
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 > nul 2>&1

set EDITION=%1
if "%EDITION%"=="" set EDITION=full

set EXTRA=
if not "%2"=="" set EXTRA=-DZETA_OUTPUT_DIR=%2

cmake -S "%~dp0." -B "%~dp0build" -G Ninja -DZETA_EDITION=%EDITION% %EXTRA% 2>&1
exit /b %ERRORLEVEL%
