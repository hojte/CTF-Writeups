@echo off
:: ===============================
:: MassDriver Loader Script (Auto-Elevate)
:: ===============================

:: Check for administrative privileges
:: If not elevated, re-run via PowerShell with UAC prompt
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [*] Elevating privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb runAs"
    exit /b
)

:: Set full path to your driver (adjust this)
set SERVICE_NAME=MyDriver

:: Delete previous driver service if it exists
sc stop %SERVICE_NAME% >nul 2>&1
sc delete %SERVICE_NAME% >nul 2>&1


echo [+] Driver removed.
pause
