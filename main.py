"""
Entry point for the Crypto Visualizer application.

Usage:
    python main.py

Checks that all required dependencies are importable before launching the GUI,
and handles Ctrl+C gracefully so the terminal is not left in a broken state.
"""

from __future__ import annotations

import sys


# ---------------------------------------------------------------------------
# Dependency check — gives a clear message instead of a raw ImportError
# ---------------------------------------------------------------------------

_REQUIRED = {
    "cryptography": "cryptography>=42.0",
    "customtkinter": "customtkinter>=5.2",
    "PIL":           "Pillow>=10.0",
    "matplotlib":    "matplotlib>=3.8",
    "numpy":         "numpy>=1.26",
}


def _check_dependencies() -> None:
    missing: list[str] = []
    for module, package in _REQUIRED.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(package)

    if missing:
        print("=" * 60)
        print("ERROR: Missing required packages.")
        print("Run the following command to install them:")
        print()
        print("    pip install -r requirements.txt")
        print()
        print("Missing packages:")
        for pkg in missing:
            print(f"  - {pkg}")
        print("=" * 60)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    _check_dependencies()

    from gui.main_window import MainWindow

    app = MainWindow()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        print("\nApplication interrupted. Exiting.")
        app.destroy()


if __name__ == "__main__":
    main()
