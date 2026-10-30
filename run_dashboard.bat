@echo off
REM ============================================================
REM  AI-Based Cyber Crime Observation Device — Launcher
REM  Double-click this file to start the SOC Dashboard.
REM ============================================================

echo.
echo  ============================================================
echo   AI-Based Cyber Crime Observation Device
echo   Starting SOC Dashboard...
echo  ============================================================
echo.

REM Try to use the .venv Python if it exists
IF EXIST "%~dp0.venv\Scripts\python.exe" (
    SET PYTHON="%~dp0.venv\Scripts\python.exe"
) ELSE (
    SET PYTHON=python
)

echo  Using Python: %PYTHON%
echo  Dashboard will open at: http://localhost:5000
echo.

%PYTHON% "%~dp0dashboard\server.py"

IF ERRORLEVEL 1 (
    echo.
    echo  ERROR: Dashboard failed to start.
    echo  Make sure you have installed dependencies:
    echo    pip install -r requirements.txt
    echo.
    pause
)
