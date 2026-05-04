@echo off
:: ─────────────────────────────────────────────────────────────
::  SecureX AI IDS/IPS — DEMO Mode Launcher (No Admin Needed)
::  Double-click this file to start with synthetic traffic
:: ─────────────────────────────────────────────────────────────
cd /d "%~dp0"
echo.
echo  ============================================================
echo   SecureX AI - Intrusion Detection ^& Prevention System
echo   Mode: DEMO (Synthetic Traffic)
echo  ============================================================
echo.
python main.py --demo
pause

