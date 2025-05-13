@echo off
setlocal

rem Path to WinDbg (adjust if needed)
set WINDBG="C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe"

rem Launch WinDbg for kernel debugging over named pipe
start "" %WINDBG% -k com:port=\\.\pipe\com_port1,pipe,reconnect,baud=115200
