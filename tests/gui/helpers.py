"""Helpers for driving and inspecting the Tk GUI from tests."""

from __future__ import annotations

import subprocess
import sys
import time
import tkinter as tk
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import customtkinter as ctk
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def require(condition: bool, message: str) -> None:
    """
    Check a test precondition.

    Fails through pytest.fail rather than assert, so a broken precondition is
    never mistaken for the AssertionError that a known_bug test expects.
    """
    if not condition:
        pytest.fail(message)


def pump(widget: tk.Misc, ms: int = 150) -> None:
    """
    Process Tk events for *ms* milliseconds.

    A single update() is not enough: CustomTkinter applies appearance changes
    from a 30 ms timer, and layout settles over several idle passes.
    """
    deadline = time.monotonic() + ms / 1000
    while time.monotonic() < deadline:
        widget.update()
        time.sleep(0.005)


def descendants(widget: tk.Misc) -> Iterator[tk.Misc]:
    """
    Yield every Tk descendant of *widget*.

    Walks ``children`` instead of ``winfo_children()``, which CTkFrame
    overrides to hide whatever its ``_canvas`` attribute points to.
    """
    for child in list(widget.children.values()):
        yield child
        yield from descendants(child)


def item_type(canvas: tk.Canvas, item: int) -> str:
    """Canvas item type, e.g. "text" (typeshed wrongly declares int | None)."""
    return str(canvas.type(item))


def item_option(canvas: tk.Canvas, item: int, option: str) -> str:
    """A canvas item option as text (typeshed leaves itemcget unannotated)."""
    return str(canvas.itemcget(item, option))  # type: ignore[no-untyped-call]


def tooltip_windows(root: tk.Misc) -> list[tk.Toplevel]:
    return [w for w in descendants(root) if isinstance(w, tk.Toplevel)]


def visible_tooltips(root: tk.Misc) -> list[tk.Toplevel]:
    return [w for w in tooltip_windows(root) if w.winfo_ismapped()]


def visible_tooltip_text(root: tk.Misc) -> str:
    shown = visible_tooltips(root)
    require(len(shown) == 1, f"expected one visible tooltip, found {len(shown)}")
    labels = [w for w in descendants(shown[0]) if isinstance(w, tk.Label)]
    require(len(labels) == 1, "tooltip window has no single text label")
    return str(labels[0].cget("text"))


def label_text(label: Any) -> str:
    """The text a CTkLabel shows, whether set directly or through a variable."""
    # cget returns the variable's Tcl name (a Tcl_Obj, not a tk.Variable),
    # or "" when the label has no variable.
    variable = str(label.cget("textvariable"))
    if variable:
        return str(label.getvar(variable))
    return str(label.cget("text"))


def find_button(widget: tk.Misc, label: str) -> Any:
    """Return the one CTkButton under *widget* whose text contains *label*."""
    matches = [
        w
        for w in descendants(widget)
        if isinstance(w, ctk.CTkButton) and label in str(w.cget("text"))
    ]
    require(len(matches) == 1, f"expected one {label!r} button, found {len(matches)}")
    return matches[0]


def block_canvas(widget: tk.Misc) -> tk.Canvas:
    """Return the canvas that draws the AES blocks (the one labelled "Block 0")."""
    matches = [
        w
        for w in descendants(widget)
        if isinstance(w, tk.Canvas)
        and any(
            item_type(w, item) == "text" and item_option(w, item, "text") == "Block 0"
            for item in w.find_all()
        )
    ]
    require(len(matches) == 1, f"expected one block canvas, found {len(matches)}")
    return matches[0]


def block_center_x(canvas: tk.Canvas, index: int) -> int:
    """Horizontal centre of block *index*, read from its "Block N" caption."""
    captions = [
        item
        for item in canvas.find_all()
        if item_type(canvas, item) == "text"
        and item_option(canvas, item, "text") == f"Block {index}"
    ]
    require(len(captions) == 1, f"no caption for block {index}")
    return int(canvas.coords(captions[0])[0])


def plaintext_rect(canvas: tk.Canvas, index: int) -> int:
    """The top rectangle (plaintext) of block *index*."""
    x = block_center_x(canvas, index)
    rects = [
        item
        for item in canvas.find_overlapping(x, 0, x, canvas.winfo_height())
        if item_type(canvas, item) == "rectangle"
    ]
    require(bool(rects), f"no rectangles drawn for block {index}")
    return min(rects, key=lambda item: canvas.coords(item)[1])


def plaintext_center(canvas: tk.Canvas, index: int) -> tuple[int, int]:
    x0, y0, x1, y1 = canvas.coords(plaintext_rect(canvas, index))
    return int((x0 + x1) / 2), int((y0 + y1) / 2)


def click_block(canvas: tk.Canvas, index: int) -> None:
    x, y = plaintext_center(canvas, index)
    canvas.event_generate("<Button-1>", x=x, y=y)


def run_app_script(code: str, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    """
    Run *code* in a fresh interpreter from the repository root.

    Import-time behaviour (such as the appearance mode) only shows up
    the way a user sees it in a process that has not imported the app before.
    """
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


# ---------------------------------------------------------------------------
# Text contrast (WCAG 2.x definitions)
# ---------------------------------------------------------------------------


def _for_current_mode(color: Any) -> str:
    """CustomTkinter colours are a name or a (light, dark) pair."""
    if isinstance(color, tuple | list):
        return str(color[0 if ctk.get_appearance_mode() == "Light" else 1])
    return str(color)


def _background_of(widget: tk.Misc) -> str:
    """The colour actually painted behind *widget*: the nearest opaque ancestor."""
    current: tk.Misc | None = widget
    while current is not None:
        try:
            color = _for_current_mode(current.cget("fg_color"))
        except (tk.TclError, ValueError):  # plain Tk widget, no fg_color option
            color = str(current.cget("background"))
        if color != "transparent":
            return color
        current = current.master
    raise LookupError(f"no opaque background behind {widget}")


def _relative_luminance(widget: tk.Misc, color: str) -> float:
    def linear(channel_16bit: int) -> float:
        c = channel_16bit / 65535
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (linear(v) for v in widget.winfo_rgb(color))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(widget: tk.Misc, foreground: str, background: str) -> float:
    """WCAG contrast ratio, from 1:1 (invisible) to 21:1 (black on white)."""
    lighter, darker = sorted(
        (
            _relative_luminance(widget, foreground),
            _relative_luminance(widget, background),
        ),
        reverse=True,
    )
    return (lighter + 0.05) / (darker + 0.05)


def low_contrast_labels(window: tk.Misc, minimum: float) -> list[str]:
    """Describe every non-empty CTkLabel whose text contrast is below *minimum*."""
    offenders = []
    for label in descendants(window):
        if not isinstance(label, ctk.CTkLabel):
            continue
        text = label_text(label)
        if not text.strip():
            continue
        foreground = _for_current_mode(label.cget("text_color"))
        background = _background_of(label)
        ratio = contrast_ratio(label, foreground, background)
        if ratio < minimum:
            snippet = text.strip().splitlines()[0][:40]
            offenders.append(
                f"{ratio:.2f}:1  {foreground} on {background}  {snippet!r}"
            )
    return offenders
