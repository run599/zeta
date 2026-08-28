# Activate VS 2022 x64 environment and build zeta_engine
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$vspath = "C:\Program Files\Microsoft Visual Studio\2022\Community"
$vcvars = "$vspath\VC\Auxiliary\Build\vcvars64.bat"
$tempFile = [System.IO.Path]::GetTempFileName()
try {
    # Run vcvars64.bat and capture the environment variables
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "cmd.exe"
    $psi.Arguments = "/c `"`"$vcvars`" > nul 2>&1 && set`""
    $psi.RedirectStandardOutput = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $output = $p.StandardOutput.ReadToEnd()
    $p.WaitForExit()

    # Apply environment variables
    $output -split "`r`n" | ForEach-Object {
        if ($_ -match '^(\w+)=(.*)$') {
            $key = $matches[1]
            $val = $matches[2]
            # Skip PATH - it can cause issues
            if ($key -ne "PATH" -and $key -ne "PROMPT") {
                Set-Item -Path "env:$key" -Value $val -ErrorAction SilentlyContinue
            }
        }
    }

    # Run the build
    cmake --build (Join-Path $scriptDir "build") --config Release 2>&1
}
finally {
    if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
}
