@echo off
setlocal DisableDelayedExpansion

for %%I in ("%~dp0..\..\..\mcp-registry-runtime") do set "runtime=%%~fI"
set "instance=%runtime%\gateway"
set "python=%runtime%\registry-venv\Scripts\python.exe"

if not exist "%python%" (
    echo Python environment missing. Install the Windows dependencies first.
    echo Expected: "%python%"
    pause
    exit /b 1
)

"%python%" -B "%~dp0gateway.py" stop --instance "%instance%"
set "result=%ERRORLEVEL%"
if not "%result%"=="0" (
    echo Gateway stop failed with exit code %result%.
    echo Logs: "%instance%\logs"
    pause
)
exit /b %result%
