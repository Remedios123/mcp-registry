@echo off
setlocal DisableDelayedExpansion

set "token=%~dp0.token"
if not exist "%token%" (
    echo Token file missing. Save your gateway administrator token next to this script as ".token".
    echo Expected: "%token%"
    pause
    exit /b 1
)

set "repo=D:\Project\mcp-registry"
if exist "%~dp0..\..\api\registry_management.py" (
    for %%I in ("%~dp0..\..") do set "repo=%%~fI"
)
for %%I in ("%repo%\..\mcp-registry-runtime\registry-venv\Scripts\python.exe") do set "python=%%~fI"

if not exist "%repo%\api\registry_management.py" (
    echo Registry CLI missing: "%repo%\api\registry_management.py"
    pause
    exit /b 1
)
if not exist "%python%" (
    echo Python environment missing: "%python%"
    pause
    exit /b 1
)

set "gateway=http://127.0.0.1:17860"
if not "%~1"=="" set "gateway=%~1"

pushd "%repo%" || (
    echo Cannot open "%repo%".
    pause
    exit /b 1
)
"%python%" -B api\registry_management.py --registry-url "%gateway%" --token-file "%token%" embeddings-reindex --all-missing
set "result=%ERRORLEVEL%"
if not "%result%"=="0" goto done
"%python%" -B api\registry_management.py --registry-url "%gateway%" --token-file "%token%" embeddings-missing
set "result=%ERRORLEVEL%"

:done
popd
pause
exit /b %result%
