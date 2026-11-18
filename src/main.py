"""MSAT — macOS Server Administration Tools. Entry point.

Run with:  python3 src/main.py        (from the project root)
       or: ./run.sh                   (activates the venv first)
"""

import os
import sys
import tkinter as tk

# Make the bundled ``msat`` package importable no matter where the
# entry point is launched from.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from msat.app import MSATApp  # noqa: E402
from msat.constants import APP_TITLE  # noqa: E402


def main():
    root = tk.Tk()
    root.title(APP_TITLE)
    MSATApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
