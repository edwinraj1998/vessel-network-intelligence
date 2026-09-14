@echo off
setlocal
cd /d "%~dp0"
if not exist "%~dp0.venv\Scripts\python.exe" (
 echo Run Setup Offline.cmd first.
 pause
 exit /b 1
)
"%~dp0.venv\Scripts\python.exe" "%~dp0vessel_intelligence\preflight.py"
pause
