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

"%python%" -B "%~dp0setup_cas.py" --instance "%instance%"
set "result=%ERRORLEVEL%"
pause
exit /b %result%
