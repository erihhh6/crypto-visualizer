"""The application as a user launches it: a fresh interpreter, real imports."""

from __future__ import annotations

import json
from typing import Any

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

# Uses every tab, so what only appears after using it is checked too.
_FILL_EVERY_TAB = """
import json
import customtkinter as ctk
from tests.gui.helpers import (
    block_canvas, click_block, clipped_controls, descendants, find_button,
    low_contrast_text, pump, shown_texts
)

def fill_every_tab(app):
    pump(app)
    entries = [w for w in descendants(app.aes_tab) if isinstance(w, ctk.CTkEntry)]
    entries[0].delete(0, "end")
    entries[0].insert(0, "YELLOW SUBMARINE" * 2)  # repeated blocks: coloured squares
    find_button(app.aes_tab, "Encrypt").invoke()
    pump(app)
    click_block(block_canvas(app.aes_tab), 1)
    find_button(app.aes_tab, "Use Sample").invoke()
    find_button(app.key_tab, "Run DH").invoke()
    for _ in range(5):
        find_button(app.key_tab, "Next").invoke()
    find_button(app.key_tab, "Show Comparison").invoke()
    find_button(app.tamper_tab, "One wrong key").invoke()
    find_button(app.tamper_tab, "Tamper").invoke()
    pump(app, 300)
"""

_CONTRAST = (
    """
import sys
import darkdetect
darkdetect.theme = lambda: sys.argv[1]  # the OS theme, before the app reads it
"""
    + _FILL_EVERY_TAB
    + """
from gui.main_window import MainWindow

app = MainWindow()
fill_every_tab(app)
print(json.dumps([ctk.get_appearance_mode(), low_contrast_text(app, MINIMUM)]))
app.destroy()
"""
)

# Each tab in the smallest window allowed; GCM draws the largest block diagram.
_AT_MINIMUM_SIZE = (
    _FILL_EVERY_TAB
    + """
from gui.main_window import MIN_SIZE, MainWindow

app = MainWindow()
app.geometry("{}x{}".format(*MIN_SIZE))
(mode_menu,) = [w for w in descendants(app.aes_tab) if isinstance(w, ctk.CTkOptionMenu)]
mode_menu.set("GCM")
fill_every_tab(app)
clipped, texts = {}, []
for name in ("AES Modes", "Key Exchange", "Tamper Lab"):
    find_button(app, name).invoke()
    pump(app, 300)
    clipped[name] = clipped_controls(app)
    texts += shown_texts(app)
print(json.dumps({"clipped": clipped, "texts": texts}))
app.destroy()
"""
)


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


@pytest.fixture(scope="module")
def at_minimum_size() -> dict[str, Any]:
    """What every tab shows, used, in the smallest window allowed."""
    result = run_app_script(_AT_MINIMUM_SIZE)
    require(result.returncode == 0, f"app crashed:\n{result.stderr}")
    shown: dict[str, Any] = json.loads(result.stdout.strip().splitlines()[-1])
    return shown


def test_every_control_fits_in_the_smallest_window(
    at_minimum_size: dict[str, Any],
) -> None:
    clipped = at_minimum_size["clipped"]

    assert clipped == {"AES Modes": [], "Key Exchange": [], "Tamper Lab": []}


def test_no_text_needs_an_emoji_font(at_minimum_size: dict[str, Any]) -> None:
    """
    Characters beyond U+FFFF, emoji among them, are drawn as empty boxes by
    Tk where no emoji font is installed, as on many Linux systems.
    """
    needs_emoji_font = [
        text
        for text in at_minimum_size["texts"]
        if any(ord(char) > 0xFFFF for char in text)
    ]

    assert needs_emoji_font == []
