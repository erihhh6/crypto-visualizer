"""The application as a user launches it: a fresh interpreter, real imports."""

from __future__ import annotations

import json
import sys

import pytest

from tests.gui.helpers import require, run_app_script
from tests.markers import known_bug

_ON_LINUX = sys.platform.startswith("linux")

_START = """
from gui.main_window import MainWindow

app = MainWindow()
app.update()
app.destroy()
"""

# Tests that need a running app cannot say anything where it does not start.
_NEEDS_APP_START = pytest.mark.skipif(
    _ON_LINUX, reason="the app cannot start on Linux yet (test_the_app_starts)"
)

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


@known_bug(
    "the window icon is a Windows .ico file, which Tk on Linux rejects at start-up",
    when=_ON_LINUX,
)
def test_the_app_starts() -> None:
    result = run_app_script(_START)

    assert result.returncode == 0, f"app failed to start:\n{result.stderr}"


@_NEEDS_APP_START
@known_bug("closing the window leaves the process running (pyplot's hidden Tk root)")
def test_closing_the_window_ends_the_process() -> None:
    result = run_app_script(_CLOSE_WINDOW)

    require(
        result.returncode in (0, _HUNG_EXIT_CODE),
        f"app crashed (exit {result.returncode}):\n{result.stderr}",
    )
    assert result.returncode == 0, (
        f"main loop still running {_CLOSE_TIMEOUT_S}s after the window closed"
    )


@_NEEDS_APP_START
@known_bug("on a light-mode OS, text on the hard-coded dark cards is near-invisible")
def test_text_stays_readable_on_a_light_mode_os() -> None:
    result = run_app_script(_LIGHT_OS_CONTRAST)

    require(result.returncode == 0, f"app crashed:\n{result.stderr}")
    offenders = json.loads(result.stdout.strip().splitlines()[-1])
    assert offenders == [], f"text below {_MIN_CONTRAST}:1 contrast:\n" + "\n".join(
        offenders
    )
