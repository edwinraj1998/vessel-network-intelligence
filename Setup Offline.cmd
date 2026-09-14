@echo off
setlocal
cd /d "%~dp0"
set "PYTHON=py -3.12"
%PYTHON% -c "import sys; assert sys.version_info[:2]==(3,12)" >nul 2>&1
if not errorlevel 1 goto found
set "PYTHON=python"
%PYTHON% -c "import sys; assert sys.version_info[:2]==(3,12)" >nul 2>&1
if not errorlevel 1 goto found
echo Install the included Python 3.12 x64 installer first. Enable the launcher or PATH.
pause
exit /b 1
:found
%PYTHON% -c "import struct; assert struct.calcsize('P')==8, '64-bit Python required'"
if errorlevel 1 goto failed
%PYTHON% -m venv ".venv"
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m pip install --no-index --find-links="wheels" --only-binary=:all: --disable-pip-version-check -r requirements-offline.txt
if errorlevel 1 goto failed
".venv\Scripts\python.exe" "vessel_intelligence\preflight.py"
if errorlevel 1 goto failed
echo Setup complete. Run Start Dashboard.cmd.
pause
exit /b 0
:failed
echo Setup failed. Read the error above and the deployment guide.
pause
exit /b 1
