@echo off
setlocal
cd /d "%~dp0"
if errorlevel 1 goto fail
if not defined CYBERWATCH_PORT set "CYBERWATCH_PORT=8000"

if exist ".venv\Scripts\python.exe" goto install
py -3 -c "import sys; sys.exit(sys.version_info < (3, 11))" >nul 2>&1
if not errorlevel 1 (
    py -3 -m venv .venv
    if errorlevel 1 goto fail
    goto install
)
python -c "import sys; sys.exit(sys.version_info < (3, 11))" >nul 2>&1
if errorlevel 1 goto missing_python
python -m venv .venv
if errorlevel 1 goto fail

:install
".venv\Scripts\python.exe" -c "import sys; sys.exit(sys.version_info < (3, 11))"
if errorlevel 1 goto missing_python
".venv\Scripts\python.exe" -m pip install -e "."
if errorlevel 1 goto fail
".venv\Scripts\python.exe" -m scripts.generate_demo_data
if errorlevel 1 goto fail
echo.
echo CyberWatch dashboard: http://localhost:%CYBERWATCH_PORT%
echo Press Ctrl+C to stop the server.
start "" powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 2; Start-Process 'http://localhost:%CYBERWATCH_PORT%'"
".venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port "%CYBERWATCH_PORT%"
if errorlevel 1 goto fail
exit /b 0

:missing_python
echo Python 3.11 or newer is required. Install it from https://www.python.org/downloads/windows/
echo Enable the Python launcher or Add Python to PATH, then run this file again.
echo If .venv exists but is broken, rename it and run this file again.
pause
exit /b 1

:fail
echo.
echo CyberWatch could not start. Review the error above and try again.
pause
exit /b 1
