@echo off
cd /d "%~dp0"

echo === AI Security Tool Arsenal - Setup ===
echo.

:: ── Go Installation ──
where go >nul 2>&1
if %ERRORLEVEL%==0 (
    echo [*] Go already installed.
    go version
) else (
    echo [*] Installing Go...
    set "GO_VERSION=1.23.6"
    set "GO_MSI=go%GO_VERSION%.windows-amd64.msi"
    set "GO_URL=https://go.dev/dl/%GO_MSI%"

    echo    Downloading %GO_MSI%...
    powershell -Command "Invoke-WebRequest -Uri '%GO_URL%' -OutFile '%TEMP%\%GO_MSI%'"

    echo    Installing (this may require admin privileges)...
    msiexec /i "%TEMP%\%GO_MSI%" /quiet /norestart
    del "%TEMP%\%GO_MSI%" 2>nul

    :: Refresh PATH
    set "PATH=C:\Program Files\Go\bin;%USERPROFILE%\go\bin;%PATH%"

    where go >nul 2>&1
    if %ERRORLEVEL%==0 (
        echo [OK] Go installed.
        go version
    ) else (
        echo [!] Go installation may require a terminal restart to update PATH.
    )
)
echo.

:: ── Python venv ──
if not exist ".venv" (
    echo [*] Creating Python virtual environment...
    python -m venv .venv
) else (
    echo [*] Virtual environment already exists.
)

echo [*] Installing Python dependencies...
call .venv\Scripts\activate.bat
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo.
echo === Setup complete! ===
echo.
echo Next steps:
echo   1. Activate the venv:  .venv\Scripts\activate.bat
echo   2. List tools:         python tool_manager.py list
echo   3. Install all tools:  python tool_manager.py install-all
echo   4. (Optional) Set ANTHROPIC_API_KEY for AI features
echo.
