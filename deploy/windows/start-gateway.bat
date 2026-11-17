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

if not exist "%instance%\gateway.env" (
    echo Gateway configuration missing. Copy and fill in gateway.env.example first.
    echo Expected: "%instance%\gateway.env"
    pause
    exit /b 1
)

"%python%" -B "%~dp0gateway.py" start --runtime "%runtime%" --instance "%instance%"
set "result=%ERRORLEVEL%"
if not "%result%"=="0" (
    echo Gateway startup failed with exit code %result%.
    echo Logs: "%instance%\logs"
    pause
)
exit /b %result%
