@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
 echo Run Setup Offline.cmd first.
 pause
 exit /b 1
)
".venv\Scripts\python.exe" "vessel_intelligence\legacy_dashboard.py"
pause
