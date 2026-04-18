@echo off
:: ─────────────────────────────────────────────────────────────
::  SecureX AI IDS/IPS — Live Network Launcher
::  Double-click this file to start the system as Administrator
:: ─────────────────────────────────────────────────────────────

:: Check if already running as Admin
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :run
) else (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:run
cd /d "%~dp0"
echo.
echo  ============================================================
echo   SecureX AI - Intrusion Detection ^& Prevention System
echo   Mode: LIVE Network Capture
echo  ============================================================
echo.
python main.py
pause
