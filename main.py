"""
main.py – Application entry point.

Run from the password_manager/ directory:
    python main.py

This file only wires up sys.path and launches the GUI.
No crypto or business logic lives here.
"""

import os
import sys
from pathlib import Path

# Ensure Tcl/Tk libraries resolve cleanly in virtual environments on Windows
if sys.platform == "win32":
    tcl_dir = os.path.join(sys.base_prefix, "tcl", "tcl8.6")
    tk_dir = os.path.join(sys.base_prefix, "tcl", "tk8.6")
    if os.path.exists(tcl_dir) and "TCL_LIBRARY" not in os.environ:
        os.environ["TCL_LIBRARY"] = tcl_dir
    if os.path.exists(tk_dir) and "TK_LIBRARY" not in os.environ:
        os.environ["TK_LIBRARY"] = tk_dir

# Add the project root to sys.path so that 'core' and 'gui' packages resolve.
sys.path.insert(0, str(Path(__file__).parent))

from gui.app import App

if __name__ == "__main__":
    app = App()
    app.mainloop()
