"""The palette: colours that follow the light/dark appearance, and their contrast."""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from types import TracebackType
from typing import Any

import customtkinter as ctk
import pytest

from gui import palette
from gui.palette import PANEL, follow_appearance, resolve
from tests.gui.helpers import contrast_ratio


def test_resolve_picks_the_colour_of_the_current_mode(
    root: Any, switch_appearance: Callable[[str], None]
) -> None:
    switch_appearance("Dark")
    assert resolve(("#ffffff", "#000000")) == "#000000"
    switch_appearance("Light")
    assert resolve(("#ffffff", "#000000")) == "#ffffff"


def test_a_widget_is_restyled_now_and_on_every_switch(
    root: Any, switch_appearance: Callable[[str], None]
) -> None:
    box = tk.Text(root)

    def restyle() -> None:
        box.configure(background=resolve(PANEL))

    follow_appearance(box, restyle)
    assert box["background"] == PANEL[0]

    switch_appearance("Dark")
    assert box["background"] == PANEL[1]


def test_the_subscription_ends_with_the_widget(root: Any) -> None:
    before = len(ctk.AppearanceModeTracker.callback_list)
    box = tk.Text(root)
    follow_appearance(box, lambda: None)
    assert len(ctk.AppearanceModeTracker.callback_list) == before + 1

    box.destroy()

    assert len(ctk.AppearanceModeTracker.callback_list) == before


def test_a_failing_restyle_is_reported_not_swallowed(
    root: Any,
    switch_appearance: Callable[[str], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reported: list[BaseException] = []

    def record(
        _type: type[BaseException], exc: BaseException, _tb: TracebackType | None
    ) -> None:
        reported.append(exc)

    monkeypatch.setattr(root, "report_callback_exception", record)
    switches = 0

    def restyle() -> None:
        nonlocal switches
        switches += 1
        if switches > 1:  # the first call, at subscription, succeeds
            raise RuntimeError("cannot restyle")

    follow_appearance(tk.Text(root), restyle)
    switch_appearance("Dark")

    assert [str(exc) for exc in reported] == ["cannot restyle"]


@pytest.mark.parametrize("mode", [0, 1], ids=["light", "dark"])
@pytest.mark.parametrize(
    "ink",
    ["TEXT", "MUTED", "BLUE", "ORANGE", "GREEN", "PURPLE", "RED"],
)
def test_text_colours_meet_wcag_aa_on_every_background(
    root: Any, ink: str, mode: int
) -> None:
    for background in ("SURFACE", "PANEL", "CARD", "CURRENT_CARD"):
        fg = getattr(palette, ink)[mode]
        bg = getattr(palette, background)[mode]
        assert contrast_ratio(root, fg, bg) >= 4.5, f"{ink} on {background}"


@pytest.mark.parametrize(
    "fill",
    [
        "FILL_BLUE",
        "FILL_ORANGE",
        "FILL_GREEN",
        "FILL_PURPLE",
        "FILL_BRONZE",
        "FILL_RED",
        "FILL_SLATE",
        "BUTTON_PRIMARY",
        "BUTTON_SECONDARY",
        "BUTTON_QUIET",
    ],
)
def test_white_text_meets_wcag_aa_on_every_fill(root: Any, fill: str) -> None:
    assert contrast_ratio(root, "#FFFFFF", getattr(palette, fill)) >= 4.5
