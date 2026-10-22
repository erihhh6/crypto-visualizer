"""BlockCanvas: hover tooltips, click selection and theming."""

from __future__ import annotations

import os
import tkinter as tk
from typing import Any

import customtkinter as ctk
import pytest

from gui.aes_tab import BlockCanvas
from modules.aes_modes import AesMode, encrypt
from tests.gui.helpers import (
    block_canvas,
    descendants,
    item_option,
    item_type,
    pump,
    require,
)


@pytest.fixture
def canvas(root: Any) -> tk.Canvas:
    """A BlockCanvas filling the window, showing three ECB blocks."""
    widget = BlockCanvas(root)
    widget.pack(fill="both", expand=True)
    widget.draw(encrypt(AesMode.ECB, b"A" * 40, os.urandom(16)))
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


def _border(canvas: tk.Canvas, index: int) -> tuple[str, str]:
    rect = _plaintext_rect(canvas, index)
    return item_option(canvas, rect, "outline"), item_option(canvas, rect, "width")


def _click(canvas: tk.Canvas, index: int) -> None:
    x, y = _plaintext_center(canvas, index)
    canvas.event_generate("<Button-1>", x=x, y=y)


def _tooltip_windows(root: Any) -> list[tk.Toplevel]:
    return [w for w in descendants(root) if isinstance(w, tk.Toplevel)]


def _visible_tooltip_text(root: Any) -> str:
    shown = [w for w in _tooltip_windows(root) if w.winfo_ismapped()]
    require(len(shown) == 1, f"expected one visible tooltip, found {len(shown)}")
    labels = [w for w in descendants(shown[0]) if isinstance(w, tk.Label)]
    require(len(labels) == 1, "tooltip window has no single text label")
    return str(labels[0].cget("text"))


@pytest.mark.parametrize(
    ("mode", "rows"),
    [(AesMode.ECB, 2), (AesMode.CBC, 3), (AesMode.CTR, 3), (AesMode.GCM, 3)],
)
def test_middle_row_only_where_aes_input_differs_from_plaintext(
    root: Any, mode: AesMode, rows: int
) -> None:
    """ECB feeds the plaintext itself through AES, so it has no middle row."""
    widget = BlockCanvas(root)
    widget.pack(fill="both", expand=True)
    widget.draw(encrypt(mode, b"A" * 40, os.urandom(16)))
    pump(root)
    surface = block_canvas(widget)
    x = _block_center_x(surface, 0)

    drawn = surface.find_overlapping(x, 0, x, surface.winfo_height())
    assert sum(item_type(surface, item) == "rectangle" for item in drawn) == rows


def test_deselected_block_gets_its_border_back(canvas: tk.Canvas) -> None:
    original = _border(canvas, 0)

    _click(canvas, 0)
    _click(canvas, 1)  # moves the selection away from block 0

    assert _border(canvas, 0) == original


def test_clicking_a_block_highlights_only_that_block(canvas: tk.Canvas) -> None:
    _click(canvas, 0)
    _click(canvas, 1)

    unselected = {_border(canvas, 0), _border(canvas, 2)}
    assert len(unselected) == 1, "unselected blocks should share one border"
    assert _border(canvas, 1) not in unselected


def test_tooltip_follows_the_pointer_to_the_next_block(
    canvas: tk.Canvas, root: Any
) -> None:
    for index in (0, 1):
        x, y = _plaintext_center(canvas, index)
        canvas.event_generate("<Motion>", x=x, y=y)
    pump(root, 50)

    assert _visible_tooltip_text(root).startswith("Block 1")


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
