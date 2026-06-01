@echo off
:: ============================================================
::  DiagCollect Launcher
::  Elevates to admin and runs the PowerShell collector.
::  Double-click to run. Works on Windows 7+
:: ============================================================
setlocal

set "SCRIPT=%~dp0Collect-Diagnostics.ps1"

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% == 0 goto :run_elevated

echo Requesting administrator privileges...
powershell -Command "Start-Process cmd -ArgumentList '/c cd /d ""%~dp0"" && powershell -NoProfile -ExecutionPolicy Bypass -File ""%SCRIPT%""' -Verb RunAs -Wait"
goto :end

:run_elevated
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"

:end
pause
