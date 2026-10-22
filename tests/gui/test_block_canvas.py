"""BlockCanvas: hover tooltips, click selection and theming."""

from __future__ import annotations

import os
import tkinter as tk
from typing import Any

import customtkinter as ctk
import pytest

from gui.aes_tab import BlockCanvas
from modules.aes_modes import encrypt_ecb
from tests.gui.helpers import (
    block_canvas,
    descendants,
    item_option,
    item_type,
    pump,
    require,
)
from tests.markers import known_bug


@pytest.fixture
def canvas(root: Any) -> tk.Canvas:
    """A BlockCanvas filling the window, showing three ECB blocks."""
    widget = BlockCanvas(root)
    widget.pack(fill="both", expand=True)
    _, blocks = encrypt_ecb(b"A" * 40, os.urandom(16))
    widget.draw(blocks)
    pump(root)
    return block_canvas(widget)


def _block_center_x(canvas: tk.Canvas, index: int) -> int:
    """Horizontal centre of block *index*, read from its "Block N" caption."""
    captions = [
        item
        for item in canvas.find_all()
        if item_type(canvas, item) == "text"
        and item_option(canvas, item, "text") == f"Block {index}"
    ]
    require(len(captions) == 1, f"no caption for block {index}")
    return int(canvas.coords(captions[0])[0])


def _plaintext_rect(canvas: tk.Canvas, index: int) -> int:
    """The top rectangle (plaintext) of block *index*."""
    x = _block_center_x(canvas, index)
    rects = [
        item
        for item in canvas.find_overlapping(x, 0, x, canvas.winfo_height())
        if item_type(canvas, item) == "rectangle"
    ]
    require(bool(rects), f"no rectangles drawn for block {index}")
    return min(rects, key=lambda item: canvas.coords(item)[1])


def _plaintext_center(canvas: tk.Canvas, index: int) -> tuple[int, int]:
    x0, y0, x1, y1 = canvas.coords(_plaintext_rect(canvas, index))
    return int((x0 + x1) / 2), int((y0 + y1) / 2)


def _tooltip_windows(root: Any) -> list[tk.Toplevel]:
    return [w for w in descendants(root) if isinstance(w, tk.Toplevel)]


@known_bug("deselecting a block clears its border instead of restoring it")
def test_deselected_block_gets_its_border_back(canvas: tk.Canvas) -> None:
    rect = _plaintext_rect(canvas, 0)

    def border() -> tuple[str, str]:
        return item_option(canvas, rect, "outline"), item_option(canvas, rect, "width")

    original = border()
    for index in (0, 1):  # select block 0, then move the selection to block 1
        x, y = _plaintext_center(canvas, index)
        canvas.event_generate("<Button-1>", x=x, y=y)

    assert border() == original


@known_bug("the tooltip opens a new window on every mouse move")
def test_hovering_one_block_reuses_a_single_tooltip_window(
    canvas: tk.Canvas, root: Any
) -> None:
    x, y = _plaintext_center(canvas, 0)
    seen: set[str] = set()
    for dx in range(-20, 21, 2):
        canvas.event_generate("<Motion>", x=x + dx, y=y)
        seen |= {str(w) for w in _tooltip_windows(root)}

    require(bool(seen), "hovering a block showed no tooltip at all")
    assert len(seen) == 1, f"{len(seen)} tooltip windows created for one block"


@known_bug("hovering empty space below a block still shows its tooltip")
def test_no_tooltip_over_empty_space_below_the_blocks(
    canvas: tk.Canvas, root: Any
) -> None:
    x, _ = _plaintext_center(canvas, 0)
    below = canvas.winfo_height() - 5
    lowest_drawn = canvas.bbox("all")[3]
    require(below > lowest_drawn + 20, "canvas too short to hover below the blocks")

    canvas.event_generate("<Motion>", x=x, y=below)
    pump(root, 50)

    assert not [w for w in _tooltip_windows(root) if w.winfo_ismapped()]


@known_bug(
    "a theme switch repaints the block canvas with the frame colour, because "
    "BlockCanvas overwrites CTkFrame's own _canvas attribute"
)
def test_theme_switch_keeps_the_block_canvas_background(
    canvas: tk.Canvas, root: Any
) -> None:
    original = canvas.cget("background")
    other_mode = "Dark" if ctk.get_appearance_mode() == "Light" else "Light"
    try:
        ctk.set_appearance_mode(other_mode)
        pump(root)
        assert canvas.cget("background") == original
    finally:
        ctk.set_appearance_mode("System")
