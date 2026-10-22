"""
Fixtures for GUI tests.

They need a real display (CI provides one with xvfb), behave the same on any
OS theme, and turn the failures Tk would normally hide into test failures.
"""

from __future__ import annotations

import os
import tkinter as tk
import traceback
from collections.abc import Callable, Iterator
from tkinter import messagebox
from types import TracebackType
from typing import Any

import customtkinter as ctk
import pytest

from tests.gui.helpers import pump


@pytest.fixture(scope="session", autouse=True)
def display() -> None:
    """Skip GUI tests locally without a display, but never silently in CI."""
    try:
        probe = tk.Tk()
    except tk.TclError as exc:
        if os.environ.get("CI"):
            pytest.fail(f"GUI tests need a display in CI (run under xvfb): {exc}")
        pytest.skip(f"no display available: {exc}")
    probe.destroy()


@pytest.fixture(autouse=True)
def light_mode_os(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make CustomTkinter's "System" appearance resolve to light on every OS."""
    monkeypatch.setattr("darkdetect.theme", lambda: "Light")
    # CustomTkinter remembers the theme it saw at import, and only looks again
    # from a polling loop: on a dark-mode OS a test could start dark. Set light
    # outright, then hand the choice back to the (now light) "System" theme.
    ctk.set_appearance_mode("Light")
    ctk.set_appearance_mode("System")


@pytest.fixture(autouse=True)
def no_dialogs(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """
    Replace modal message boxes, which would block the test run forever,
    and fail any test that triggers one it did not ask for.
    """
    shown: list[str] = []

    def recorder(kind: str) -> Callable[..., str]:
        def show(title: str = "", message: str = "", **_: Any) -> str:
            shown.append(f"{kind}: {title}: {message}")
            return "ok"

        return show

    for kind in ("showinfo", "showwarning", "showerror"):
        monkeypatch.setattr(messagebox, kind, recorder(kind))
    yield shown
    if shown:
        pytest.fail("unexpected dialog(s):\n" + "\n".join(shown))


@pytest.fixture
def switch_appearance(root: Any) -> Iterator[Callable[[str], None]]:
    """Switch the app to "Light" or "Dark"; back to following the OS afterwards."""

    def switch(mode: str) -> None:
        ctk.set_appearance_mode(mode)
        pump(root)

    yield switch
    ctk.set_appearance_mode("System")


@pytest.fixture
def root() -> Iterator[Any]:
    """
    A visible CTk window.

    It must be mapped: Tk drops synthetic events aimed at hidden windows.
    Exceptions raised inside Tk callbacks are normally printed and swallowed;
    here they fail the test.
    """
    window = ctk.CTk()
    window.geometry("1100x700")
    errors: list[str] = []

    def report(
        exc_type: type[BaseException], exc: BaseException, tb: TracebackType | None
    ) -> None:
        errors.append("".join(traceback.format_exception(exc_type, exc, tb)))

    window.report_callback_exception = report
    pump(window)
    yield window
    window.destroy()
    if errors:
        pytest.fail("exception(s) in Tk callbacks:\n" + "\n".join(errors))
