"""
The app's colours, as (light, dark) pairs that follow the system theme.

CustomTkinter widgets take a pair directly and switch by themselves. Plain Tk
widgets, canvas items and matplotlib figures cannot: they ask resolve() for
the colour of the current mode, and follow_appearance() restyles them when
the mode switches.

Every colour that text is drawn in or on gives at least WCAG AA contrast
(4.5:1) in both modes; tests/gui/test_main_window.py checks the whole window.
"""

from __future__ import annotations

import sys
import tkinter as tk
from collections.abc import Callable
from typing import TypeAlias

import customtkinter as ctk

from modules.aes_modes import AesMode
from modules.key_exchange import Actor, Visibility

Colour: TypeAlias = tuple[str, str]  # (light mode, dark mode)

# Backgrounds
SURFACE: Colour = ("#F7F8FB", "#1E1E2E")  # drawing areas: block canvas, image, plot
PANEL: Colour = ("#E3E6EE", "#2A2A3E")  # read-only text and cards
CARD: Colour = ("#E6EAF2", "#1E2533")  # key-exchange step cards
CURRENT_CARD: Colour = ("#C9D8EE", "#2C3E50")  # the current step's card

# Text, and lines that are not text
TEXT: Colour = ("#1B1F27", "#E0E0E0")
MUTED: Colour = ("#4A505C", "#AEB3BE")  # hints, captions, row headers
LINE: Colour = ("#6B7280", "#8A8F9A")  # arrows, ⊕ nodes, plot axes

# Text colours that carry meaning, readable on every background above
BLUE: Colour = ("#1C5A91", "#8EBDEA")
ORANGE: Colour = ("#934411", "#F2A46E")
GREEN: Colour = ("#1A6331", "#7FD39A")
PURPLE: Colour = ("#663B8C", "#CBA8E5")
RED: Colour = ("#A32219", "#FF928A")

# Fills under white text: dark enough in both modes, so a single colour each.
FILL_BLUE = "#2B6CB0"
FILL_ORANGE = "#A9501A"
FILL_GREEN = "#2C7A45"
FILL_PURPLE = "#6A4AA3"
FILL_BRONZE = "#7A5F1E"
FILL_RED = "#B03A2E"
FILL_SLATE = "#3A3A50"
BUTTON_PRIMARY = "#1F6AA5"
BUTTON_SECONDARY = "#4A55A2"
BUTTON_QUIET = "#555555"

MODE_COLOURS: dict[AesMode, Colour] = {
    AesMode.ECB: ORANGE,
    AesMode.CBC: BLUE,
    AesMode.CTR: GREEN,
    AesMode.GCM: PURPLE,
}

# Key exchange: who acts (names, plotted points) and who may know a value.
ACTOR_COLOURS: dict[Actor, Colour] = {
    Actor.ALICE: BLUE,
    Actor.BOB: ORANGE,
    Actor.BOTH: GREEN,
    Actor.SYSTEM: PURPLE,
}
ACTOR_FILLS: dict[Actor, str] = {  # the step number badges
    Actor.ALICE: FILL_BLUE,
    Actor.BOB: FILL_ORANGE,
    Actor.BOTH: FILL_GREEN,
    Actor.SYSTEM: FILL_PURPLE,
}
VALUE_COLOURS: dict[Visibility, Colour] = {
    Visibility.PUBLIC: GREEN,
    Visibility.SHARED_SECRET: RED,
    Visibility.PRIVATE: MUTED,
}


def use_readable_theme() -> None:
    """
    Load CustomTkinter's blue theme, with its buttons made readable.

    The stock theme writes light grey text on mid-blue buttons (2.7:1 in light
    mode) and on grey unselected tabs (2.1:1). White on these darker fills
    reaches WCAG AA's 4.5:1. Call it before creating any widget.
    """
    ctk.set_default_color_theme("blue")
    theme = ctk.ThemeManager.theme
    white = ["#FFFFFF", "#FFFFFF"]
    blue, darker, darkest = [BUTTON_PRIMARY] * 2, ["#144870"] * 2, ["#0E3350"] * 2
    theme["CTkButton"].update(fg_color=blue, hover_color=darker, text_color=white)
    theme["CTkOptionMenu"].update(
        fg_color=blue,
        button_color=darker,
        button_hover_color=darkest,
        text_color=white,
    )
    theme["CTkSegmentedButton"].update(
        selected_color=blue,
        selected_hover_color=darker,
        unselected_color=["#5F6670", "gray29"],
        unselected_hover_color=["#4B515A", "gray35"],
        text_color=white,
    )


def resolve(colour: Colour) -> str:
    """The colour of the pair for the current appearance mode."""
    return colour[1] if ctk.get_appearance_mode() == "Dark" else colour[0]


def follow_appearance(widget: tk.Misc, restyle: Callable[[], None]) -> None:
    """
    Call *restyle* now, and again whenever the app switches light and dark.

    *widget* is the plain Tk widget being restyled; the subscription ends
    when it is destroyed.
    """

    def on_switch(_mode: str) -> None:
        # CustomTkinter swallows exceptions from these callbacks; report them
        # like an error in any other Tk callback instead.
        try:
            restyle()
        except Exception:
            widget.nametowidget(".").report_callback_exception(*sys.exc_info())

    restyle()
    ctk.AppearanceModeTracker.add(on_switch, widget)
    widget.bind(
        "<Destroy>", lambda _e: ctk.AppearanceModeTracker.remove(on_switch), add="+"
    )
