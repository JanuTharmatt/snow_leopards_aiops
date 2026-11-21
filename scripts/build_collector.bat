@echo off
REM ================================================================
REM SNOW LEOPARDS — Autonomous AIOps Platform
REM Collector Executable Packaging Script (PyInstaller --onefile)
REM Produces standalone dist/collector.exe for clean Windows evaluation
REM ================================================================

echo [SNOW LEOPARDS] Packaging collector into single standalone executable...

cd /d "%~dp0.."

if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)

pip show pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo [SNOW LEOPARDS] Installing PyInstaller build dependency...
    pip install pyinstaller
)

echo [SNOW LEOPARDS] Building dist/collector.exe with PyInstaller...
pyinstaller --noconfirm ^
    --distpath dist ^
    --workpath build_pyi ^
    collector/collector_app.spec

if %errorlevel% equ 0 (
    echo ================================================================
    echo [SUCCESS] Standalone collector executable built successfully!
    echo Binary available at: dist\collector.exe
    echo Works on any clean Windows laptop without Python installed.
    echo ================================================================
) else (
    echo [ERROR] Build failed with error level %errorlevel%
    exit /b %errorlevel%
)
