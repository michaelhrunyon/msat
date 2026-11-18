#!/bin/bash
# MSAT setup — macOS (also works on Linux for testing).
# Creates a virtual environment, installs dependencies, verifies Tkinter.
set -e
cd "$(dirname "$0")"

echo "== MSAT setup =="

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 was not found. Install Python 3.11+ first"
    echo "(python.org installer or Homebrew: brew install python)."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "Python $PYTHON_VERSION detected."

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment (.venv)..."
    python3 -m venv .venv
else
    echo "Virtual environment already exists."
fi

echo "Installing dependencies..."
.venv/bin/pip install --upgrade pip -q
.venv/bin/pip install -r requirements.txt

echo "Verifying Tkinter..."
if ! .venv/bin/python -c "import tkinter; print('Tkinter OK:', tkinter.TkVersion)" 2>&1; then
    echo "ERROR: Tkinter is not available in this Python."
    echo "On macOS, use the python.org installer (which bundles Tcl/Tk)"
    echo "or Homebrew Python (brew install python python-tk)."
    exit 1
fi

echo
echo "Setup complete. Run the app with:"
echo "  ./run.sh"
echo
echo "To build a double-clickable macOS .app bundle instead, run:"
echo "  ./build_app.sh"
