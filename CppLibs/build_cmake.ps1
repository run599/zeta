$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$vcvars = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
cmd.exe /c ("`"$vcvars`" x64 > nul 2>&1 && cmake -S `"$scriptDir`" -B `"$scriptDir\build`" -G Ninja 2>&1")
