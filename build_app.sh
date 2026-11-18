#!/bin/bash
# MSAT macOS .app builder — RUN THIS ON THE MAC, not on Linux.
# Uses PyInstaller to bundle MSAT into a double-clickable MSAT.app.
set -e
cd "$(dirname "$0")"

if [ "$(uname -s)" != "Darwin" ]; then
    echo "ERROR: This script builds a macOS .app bundle and must be run on macOS."
    echo "You are on: $(uname -s)"
    echo "On your MacBook, run:  ./build_app.sh"
    exit 1
fi

if [ ! -d ".venv" ]; then
    echo "No virtual environment found. Run ./setup.sh first."
    exit 1
fi

echo "Installing PyInstaller into the venv..."
.venv/bin/pip install -q pyinstaller

echo "Building MSAT.app (this takes a minute)..."
.venv/bin/pyinstaller msat.spec --noconfirm

echo
echo "Done. The app bundle is at:"
echo "  dist/MSAT.app"
echo "Drag it to /Applications, then double-click to run."
echo "Note: the first launch may ask for permission (unsigned app)."
