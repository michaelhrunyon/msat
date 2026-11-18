#!/bin/bash
# MSAT launcher — activates the venv and runs the app.
set -e
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
    echo "No virtual environment found. Run ./setup.sh first."
    exit 1
fi

exec .venv/bin/python src/main.py
