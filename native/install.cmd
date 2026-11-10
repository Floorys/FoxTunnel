@echo off
setlocal

set "PS_EXE="
if exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" (
    set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
) else (
    for %%I in (powershell.exe pwsh.exe) do (
        if not defined PS_EXE (
            where %%I >nul 2>nul && set "PS_EXE=%%I"
        )
    )
)

if not defined PS_EXE (
    echo ERROR: PowerShell ^(powershell.exe or pwsh.exe^) was not found.
    echo Install or enable Windows PowerShell and re-run native\install.cmd.
    exit /b 1
)

"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
exit /b %ERRORLEVEL%

