"""The application as a user launches it: a fresh interpreter, real imports."""

from __future__ import annotations

import json

import pytest

from tests.gui.helpers import require, run_app_script

_START = """
from gui.main_window import MainWindow

app = MainWindow()
app.update()
app.destroy()
"""

_UNEXPECTED_ERROR = """
from tkinter import messagebox
messagebox.showerror = lambda title, message: print(f"DIALOG {title}: {message}")
from gui.main_window import MainWindow

def broken_handler():
    raise RuntimeError("boom")

app = MainWindow()
app.after(0, broken_handler)  # escapes from a Tk callback, like a button handler
app.after(300, app.destroy)
app.mainloop()
"""

_SWITCH_TABS = """
import json
from gui.main_window import MainWindow
from tests.gui.helpers import find_button, pump

app = MainWindow()
pump(app)
shown = []
for name in ("Tamper Lab", "Key Exchange", "AES Modes"):
    find_button(app, name).invoke()  # a segment of the tab selector
    pump(app)
    tabs = {"AES Modes": app.aes_tab, "Key Exchange": app.key_tab,
            "Tamper Lab": app.tamper_tab}
    shown.append([n for n, tab in tabs.items() if tab.winfo_ismapped()])
print(json.dumps(shown))
app.destroy()
"""

_CLOSE_TIMEOUT_S = 10
_HUNG_EXIT_CODE = 3

_CLOSE_WINDOW = f"""
import os, threading
from gui.main_window import MainWindow

app = MainWindow()
# Armed only once the window exists, so a slow first import (matplotlib builds
# its font cache on a fresh install) never counts against the close timeout.
watchdog = threading.Timer({_CLOSE_TIMEOUT_S}, os._exit, args=({_HUNG_EXIT_CODE},))
watchdog.daemon = True
watchdog.start()
app.after(100, app.destroy)  # what the window's close button does
app.mainloop()
watchdog.cancel()
"""

_MIN_CONTRAST = 4.5  # WCAG 2 AA for normal text

# Fills every tab, so the text that only appears after using it is checked too.
_CONTRAST = """
import json
import sys
import darkdetect
darkdetect.theme = lambda: sys.argv[1]  # the OS theme, before the app reads it

import customtkinter as ctk
from gui.main_window import MainWindow
from tests.gui.helpers import (
    block_canvas, click_block, descendants, find_button, low_contrast_text, pump
)

app = MainWindow()
pump(app)
plaintext = next(w for w in descendants(app.aes_tab) if isinstance(w, ctk.CTkEntry))
plaintext.delete(0, "end")
plaintext.insert(0, "YELLOW SUBMARINE" * 2)  # repeated blocks: coloured squares
find_button(app.aes_tab, "Encrypt").invoke()
pump(app)
click_block(block_canvas(app.aes_tab), 1)
find_button(app.aes_tab, "Use Sample").invoke()
find_button(app.key_tab, "Run DH").invoke()
for _ in range(5):
    find_button(app.key_tab, "Next").invoke()
find_button(app.tamper_tab, "One wrong key").invoke()
find_button(app.tamper_tab, "Tamper").invoke()
pump(app, 300)
print(json.dumps([ctk.get_appearance_mode(), low_contrast_text(app, MINIMUM)]))
app.destroy()
"""


def test_the_app_starts() -> None:
    result = run_app_script(_START)

    assert result.returncode == 0, f"app failed to start:\n{result.stderr}"


def test_unexpected_errors_are_shown_and_logged() -> None:
    result = run_app_script(_UNEXPECTED_ERROR)

    require(result.returncode == 0, f"app crashed:\n{result.stderr}")
    assert "DIALOG Unexpected error: RuntimeError: boom" in result.stdout
    # The full traceback is logged. (Python < 3.13 omits source lines for -c
    # code, so match the frame, not the raise statement.)
    assert "Traceback (most recent call last)" in result.stderr
    assert "in broken_handler" in result.stderr
    assert "RuntimeError: boom" in result.stderr


def test_the_tab_selector_shows_one_tab_at_a_time() -> None:
    result = run_app_script(_SWITCH_TABS)

    require(result.returncode == 0, f"app crashed:\n{result.stderr}")
    shown = json.loads(result.stdout.strip().splitlines()[-1])
    assert shown == [["Tamper Lab"], ["Key Exchange"], ["AES Modes"]]


def test_closing_the_window_ends_the_process() -> None:
    result = run_app_script(_CLOSE_WINDOW)

    require(
        result.returncode in (0, _HUNG_EXIT_CODE),
        f"app crashed (exit {result.returncode}):\n{result.stderr}",
    )
    assert result.returncode == 0, (
        f"main loop still running {_CLOSE_TIMEOUT_S}s after the window closed"
    )


@pytest.mark.parametrize("os_theme", ["Light", "Dark"])
def test_the_app_follows_the_os_theme_with_readable_text(os_theme: str) -> None:
    script = _CONTRAST.replace("MINIMUM", str(_MIN_CONTRAST))

    result = run_app_script(script, os_theme)

    require(result.returncode == 0, f"app crashed:\n{result.stderr}")
    mode, offenders = json.loads(result.stdout.strip().splitlines()[-1])
    assert mode == os_theme
    assert offenders == [], f"text below {_MIN_CONTRAST}:1 contrast:\n" + "\n".join(
        offenders
    )
