@echo off
REM CryptVault - one-click Windows build script.
REM Produces ONE standalone file: dist\CryptVault.exe
REM Explicitly bundles PySide6's Qt plugins (a common cause of an .exe
REM that runs fine on the build PC but fails silently on another one).

cd /d "%~dp0"
echo ============================================
echo  CryptVault - Windows build
echo ============================================

where python >nul 2>nul
if errorlevel 1 (
    echo ERROR: Python was not found on PATH.
    echo Install it from https://www.python.org/downloads/
    echo and tick "Add python.exe to PATH" during setup.
    pause
    exit /b 1
)

if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

call venv\Scripts\activate.bat

echo Installing/updating dependencies...
python -m pip install --upgrade pip >nul
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: pip install failed. See the messages above.
    pause
    exit /b 1
)

echo Cleaning any previous build...
rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul
del /q CryptVault.spec 2>nul

echo Building CryptVault.exe (this can take a minute or two)...
REM --onefile        = a single .exe, nothing else to copy around
REM --windowed       = no console window behind the GUI
REM --collect-all    = force-bundle EVERYTHING these packages need (Qt
REM                    plugins, platform DLLs, OpenSSL bindings) instead
REM                    of relying on autodetection, which is what usually
REM                    causes "works here, not on that other PC".
REM --noupx          = skip UPX compression - some antivirus tools corrupt
REM                    or quarantine UPX-compressed executables, which can
REM                    look exactly like "the exe doesn't fully work"
REM --clean          = ignore any stale PyInstaller cache
pyinstaller --noconfirm --onefile --windowed --clean --noupx --name CryptVault ^
    --collect-all PySide6 ^
    --collect-all shiboken6 ^
    --collect-all cryptography ^
    main.py

if errorlevel 1 (
    echo ERROR: build failed. See the messages above.
    pause
    exit /b 1
)

echo.
echo ============================================
echo  Done! Your app is ONE FILE at:
echo    dist\CryptVault.exe
echo  Copy that single file to any other Windows PC
echo  and it runs with no Python installed there.
echo.
echo  If it still doesn't open on another PC, that PC
echo  is almost certainly missing the Microsoft Visual
echo  C++ Redistributable. Install it there from:
echo    https://aka.ms/vs/17/release/vc_redist.x64.exe
echo  (a one-time, free, standard Microsoft download -
echo  most Windows PCs already have it, some don't)
echo ============================================
pause
