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
    """The text a (CTk) label shows, whether set directly or through a variable."""
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


_CONTROLS = (
    ctk.CTkButton,
    ctk.CTkEntry,
    ctk.CTkLabel,
    ctk.CTkOptionMenu,
    ctk.CTkSegmentedButton,
)


def _ancestors(widget: tk.Misc) -> Iterator[tk.Misc]:
    while widget.master is not None:
        widget = widget.master
        yield widget


def _scrolls_into_view(widget: tk.Misc) -> bool:
    """Inside a scrollable frame, which may hold more than fits the window."""
    return any(isinstance(w, ctk.CTkScrollableFrame) for w in _ancestors(widget))


def _control_text(control: tk.Misc) -> str:
    """The text a CustomTkinter control draws in its inner Tk label, if any."""
    labels = [w for w in descendants(control) if isinstance(w, tk.Label)]
    return label_text(labels[0]) if labels else ""


def clipped_controls(window: tk.Misc) -> list[str]:
    """
    Describe every control on show in *window* that it cuts off or squeezes.

    A control is on show when its geometry manager would display it: then it
    must be mapped (pack unmaps what has no room left), get at least the size
    it asks for and, unless a scrollable frame can bring it into view, lie
    inside the window.
    """
    right = window.winfo_rootx() + window.winfo_width()
    bottom = window.winfo_rooty() + window.winfo_height()
    clipped = []
    for widget in descendants(window):
        if not isinstance(widget, _CONTROLS):
            continue
        if not (widget.winfo_manager() and widget.master.winfo_ismapped()):
            continue  # hidden on purpose, like the tabs not shown
        width, height = widget.winfo_width(), widget.winfo_height()
        problem = ""
        if not widget.winfo_ismapped():
            problem = "no room at all"
        elif width < widget.winfo_reqwidth() or height < widget.winfo_reqheight():
            problem = (
                f"squeezed to {width}x{height} "
                f"(asks {widget.winfo_reqwidth()}x{widget.winfo_reqheight()})"
            )
        elif not _scrolls_into_view(widget) and (
            widget.winfo_rootx() + width > right
            or widget.winfo_rooty() + height > bottom
        ):
            problem = "cut off by the window edge"
        if problem:
            text = _control_text(widget)
            clipped.append(f"{type(widget).__name__} {text!r}: {problem}")
    return clipped


def shown_texts(window: tk.Misc) -> list[str]:
    """
    Every text in *window*: in labels (buttons draw theirs in one), entries,
    text boxes and on canvases.
    """
    texts = []
    for widget in descendants(window):
        if isinstance(widget, tk.Label):
            texts.append(label_text(widget))
        elif isinstance(widget, tk.Entry):
            texts.append(widget.get())
        elif isinstance(widget, tk.Text):
            texts.append(widget.get("1.0", "end-1c"))
        elif isinstance(widget, tk.Canvas) and not isinstance(widget, ctk.CTkCanvas):
            texts.extend(
                item_option(widget, item, "text")
                for item in widget.find_all()
                if item_type(widget, item) == "text"
            )
    return [text for text in texts if text.strip()]


def run_app_script(
    code: str, *args: str, timeout: float = 120
) -> subprocess.CompletedProcess[str]:
    """
    Run *code* in a fresh interpreter from the repository root, with *args*.

    Import-time behaviour (such as the appearance mode) only shows up
    the way a user sees it in a process that has not imported the app before.
    """
    return subprocess.run(
        [sys.executable, "-c", code, *args],
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


def _canvas_background(canvas: tk.Canvas, item: int) -> str:
    """The fill of the topmost shape under a canvas item, else the canvas's."""
    x0, y0, x1, y1 = canvas.bbox(item)
    x, y = (x0 + x1) / 2, (y0 + y1) / 2
    below = canvas.find_overlapping(x, y, x, y)
    shapes = [
        i
        for i in below[: below.index(item)]
        if item_type(canvas, i) in ("rectangle", "oval")
        and item_option(canvas, i, "fill")
    ]
    return (
        item_option(canvas, shapes[-1], "fill") if shapes else str(canvas["background"])
    )


def _disabled_control(label: tk.Label) -> bool:
    """Text on a disabled control: WCAG sets it no contrast requirement."""
    try:
        return str(label.master.cget("state")) == "disabled"
    except (tk.TclError, ValueError, AttributeError):
        return False


def low_contrast_text(window: tk.Misc, minimum: float) -> list[str]:
    """
    Describe every piece of text in *window* below *minimum* contrast.

    It checks the colours actually drawn: every Tk label (CustomTkinter's
    labels and buttons draw their text in one), every text box and each of
    its tags, and every text on a canvas against the shape beneath it.
    """
    offenders: list[str] = []

    def check(widget: tk.Misc, what: str, foreground: str, background: str) -> None:
        ratio = contrast_ratio(widget, foreground, background)
        if ratio < minimum:
            snippet = what.strip().splitlines()[0][:40] if what.strip() else ""
            offenders.append(
                f"{ratio:.2f}:1  {foreground} on {background}  {snippet!r}"
            )

    for widget in descendants(window):
        if isinstance(widget, tk.Label):
            text = label_text(widget)
            if text.strip() and not _disabled_control(widget):
                check(widget, text, widget["foreground"], widget["background"])
        elif isinstance(widget, tk.Text):
            foreground, background = widget["foreground"], widget["background"]
            check(widget, widget.get("1.0", "end-1c"), foreground, background)
            for tag in widget.tag_names():
                if tag != "sel":
                    tag_fg = widget.tag_cget(tag, "foreground") or foreground
                    tag_bg = widget.tag_cget(tag, "background") or background
                    check(widget, f"text tagged {tag!r}", str(tag_fg), str(tag_bg))
        # CustomTkinter draws rounded corners with font glyphs on its own
        # canvases; those characters are shapes, not text.
        elif isinstance(widget, tk.Canvas) and not isinstance(widget, ctk.CTkCanvas):
            for item in widget.find_all():
                if item_type(widget, item) == "text":
                    text = item_option(widget, item, "text")
                    if text.strip():
                        fill = item_option(widget, item, "fill")
                        check(widget, text, fill, _canvas_background(widget, item))
    return offenders
