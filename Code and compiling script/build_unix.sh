#!/usr/bin/env bash
# CryptVault - one-click build script for Linux and macOS.
# Produces ONE standalone binary under dist/.
# Explicitly bundles PySide6's Qt plugins (a common cause of a build that
# runs fine on the build machine but fails silently on another one).

set -e
cd "$(dirname "$0")"

echo "============================================"
echo " CryptVault - build ($(uname -s))"
echo "============================================"

PYTHON=python3
if ! command -v $PYTHON >/dev/null 2>&1; then
    echo "ERROR: python3 was not found."
    echo "  macOS:  install from https://python.org or 'brew install python'"
    echo "  Linux:  sudo apt install python3 python3-pip python3-venv  (Debian/Ubuntu)"
    exit 1
fi

if [ ! -d venv ]; then
    echo "Creating virtual environment..."
    $PYTHON -m venv venv
fi

source venv/bin/activate

echo "Installing/updating dependencies..."
pip install --upgrade pip >/dev/null
pip install -r requirements.txt

echo "Cleaning any previous build..."
rm -rf build dist CryptVault.spec

echo "Building CryptVault (this can take a minute or two)..."
# --onefile        = a single binary, nothing else to copy around
# --windowed       = no terminal window behind the GUI
# --collect-all    = force-bundle EVERYTHING these packages need (Qt
#                    plugins, platform libs, OpenSSL bindings) instead of
#                    relying on autodetection - this is what usually
#                    causes "works here, not on that other machine".
# --noupx          = skip UPX compression, which some antivirus/security
#                    tools mangle - can look exactly like a broken build
# --clean          = ignore any stale PyInstaller cache
pyinstaller --noconfirm --onefile --windowed --clean --noupx --name CryptVault \
    --collect-all PySide6 \
    --collect-all shiboken6 \
    --collect-all cryptography \
    main.py

echo ""
echo "============================================"
echo " Done! Your app is ONE FILE at: dist/CryptVault"
echo " (on macOS this may appear as dist/CryptVault.app)"
echo " Copy it to another machine of the SAME OS and"
echo " it runs standalone - no Python installed there."
echo "============================================"
