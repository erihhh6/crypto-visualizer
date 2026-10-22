"""The application as a user launches it: a fresh interpreter, real imports."""

from __future__ import annotations

import json

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

# 2:1 is far below WCAG AA (4.5:1 for body text): this only catches text that
# is effectively invisible. Raise the bar once the app has a real light theme.
_MIN_CONTRAST = 2.0

_LIGHT_OS_CONTRAST = f"""
import json
import darkdetect
darkdetect.theme = lambda: "Light"  # an OS in light mode, before the app reads it

from gui.main_window import MainWindow
from tests.gui.helpers import find_button, low_contrast_labels, pump

app = MainWindow()
pump(app)
find_button(app, "Run DH").invoke()  # the step cards only exist once a run starts
pump(app)
print(json.dumps(low_contrast_labels(app, minimum={_MIN_CONTRAST})))
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


def test_text_stays_readable_on_a_light_mode_os() -> None:
    result = run_app_script(_LIGHT_OS_CONTRAST)

    require(result.returncode == 0, f"app crashed:\n{result.stderr}")
    offenders = json.loads(result.stdout.strip().splitlines()[-1])
    assert offenders == [], f"text below {_MIN_CONTRAST}:1 contrast:\n" + "\n".join(
        offenders
    )
