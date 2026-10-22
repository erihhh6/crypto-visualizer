"""BlockCanvas: each mode's data flow, hover tooltips, selection and theming."""

from __future__ import annotations

import os
import tkinter as tk
from collections.abc import Callable
from typing import Any

import customtkinter as ctk
import pytest

from gui.block_canvas import MAX_DRAWN_BLOCKS, BlockCanvas
from modules.aes_modes import AesMode, EncryptionResult, encrypt
from tests.gui.helpers import (
    block_canvas,
    click_block,
    item_option,
    item_type,
    plaintext_center,
    plaintext_rect,
    pump,
    require,
    tooltip_windows,
    visible_tooltip_text,
    visible_tooltips,
)


@pytest.fixture
def canvas(root: Any) -> tk.Canvas:
    """A BlockCanvas filling the window, showing three ECB blocks."""
    widget = BlockCanvas(root)
    widget.pack(fill="both", expand=True)
    widget.draw(encrypt(AesMode.ECB, b"A" * 40, os.urandom(16)))
    pump(root)
    return block_canvas(widget)


def _border(canvas: tk.Canvas, index: int) -> tuple[str, str]:
    rect = plaintext_rect(canvas, index)
    return item_option(canvas, rect, "outline"), item_option(canvas, rect, "width")


# ---------------------------------------------------------------------------
# Data flow. Items are tagged with what they show ("block1", "counter", "xor",
# "box", "value", ...), so the tests can follow the arrows without pixels.
# ---------------------------------------------------------------------------

_ROW_TAGS = ("plaintext", "aes_input", "counter", "keystream", "ciphertext")
_STREAM_MODES = [AesMode.CTR, AesMode.GCM]


def _drawn(
    root: Any,
    mode: AesMode,
    plaintext: bytes = b"A" * 40,
    on_select: Callable[[str], None] | None = None,
) -> tuple[tk.Canvas, EncryptionResult]:
    """A fresh BlockCanvas showing *plaintext* encrypted in *mode*."""
    result = encrypt(mode, plaintext, os.urandom(16))
    widget = BlockCanvas(root, on_select=on_select)
    widget.pack(fill="both", expand=True)
    widget.draw(result)
    pump(root)
    return block_canvas(widget), result


def _shapes(canvas: tk.Canvas, tags: str, kind: str) -> list[int]:
    return [i for i in canvas.find_withtag(tags) if item_type(canvas, i) == kind]


def _rows_top_to_bottom(canvas: tk.Canvas, tags: str) -> list[str]:
    boxes = sorted(
        canvas.find_withtag(f"{tags}&&box"), key=lambda i: canvas.coords(i)[1]
    )
    return [next(t for t in canvas.gettags(i) if t in _ROW_TAGS) for i in boxes]


def _values_top_to_bottom(canvas: tk.Canvas, tags: str) -> list[str]:
    texts = sorted(
        canvas.find_withtag(f"{tags}&&value"), key=lambda i: canvas.coords(i)[1]
    )
    return [item_option(canvas, i, "text") for i in texts]


def _side_input_start(canvas: tk.Canvas, tags: str) -> tuple[float, float]:
    """Where the arrow entering the ⊕ of *tags* from the left starts."""
    (oval,) = _shapes(canvas, f"{tags}&&xor", "oval")
    left, top, _, bottom = canvas.coords(oval)
    starts = [
        (coords[0], coords[1])
        for coords in (canvas.coords(i) for i in _shapes(canvas, "all", "line"))
        if abs(coords[-2] - left) <= 1 and top <= coords[-1] <= bottom
    ]
    require(len(starts) == 1, f"expected one side input into {tags}, found {starts}")
    return starts[0]


def _inside(canvas: tk.Canvas, point: tuple[float, float], tags: str) -> bool:
    (item,) = canvas.find_withtag(tags)
    x0, y0, x1, y1 = canvas.bbox(item)
    return x0 <= point[0] <= x1 and y0 <= point[1] <= y1


@pytest.mark.parametrize(
    ("mode", "rows", "xors"),
    [
        (AesMode.ECB, ["plaintext", "ciphertext"], 0),
        (AesMode.CBC, ["plaintext", "aes_input", "ciphertext"], 1),
        (AesMode.CTR, ["plaintext", "counter", "keystream", "ciphertext"], 1),
        (AesMode.GCM, ["plaintext", "counter", "keystream", "ciphertext"], 1),
    ],
)
def test_every_block_follows_its_modes_data_flow(
    root: Any, mode: AesMode, rows: list[str], xors: int
) -> None:
    canvas, result = _drawn(root, mode)

    for blk in result.blocks:
        block = f"block{blk.index}"
        assert _rows_top_to_bottom(canvas, block) == rows
        assert len(_shapes(canvas, f"{block}&&aes", "rectangle")) == 1
        assert len(_shapes(canvas, f"{block}&&xor", "oval")) == xors


@pytest.mark.parametrize("mode", list(AesMode))
def test_every_box_shows_its_own_value(root: Any, mode: AesMode) -> None:
    canvas, result = _drawn(root, mode)

    for blk in result.blocks:
        expected = {
            "plaintext": blk.plaintext,
            "aes_input": blk.aes_input,
            "counter": blk.aes_input,
            "keystream": blk.keystream,
            "ciphertext": blk.ciphertext,
        }
        block = f"block{blk.index}"
        rows = _rows_top_to_bottom(canvas, block)
        texts = _values_top_to_bottom(canvas, block)
        for row, text in zip(rows, texts, strict=True):
            value = expected[row]
            assert value is not None, f"block {blk.index} has no {row}"
            # Long values are cut short at one end, marked with an ellipsis.
            full, shown = value.hex().upper(), text.strip("…")
            assert full.startswith(shown) or full.endswith(shown), (
                f"block {blk.index} {row}: {text!r} is not part of {full}"
            )


def test_cbc_xors_in_the_iv_then_each_previous_ciphertext(root: Any) -> None:
    canvas, result = _drawn(root, AesMode.CBC)

    sources = ["iv&&box"] + [
        f"block{blk.index}&&ciphertext&&box" for blk in result.blocks[:-1]
    ]
    for blk, source in zip(result.blocks, sources, strict=True):
        start = _side_input_start(canvas, f"block{blk.index}")
        assert _inside(canvas, start, source), f"block {blk.index}"


@pytest.mark.parametrize("mode", _STREAM_MODES)
def test_stream_modes_xor_the_plaintext_with_the_keystream(
    root: Any, mode: AesMode
) -> None:
    canvas, result = _drawn(root, mode)

    for blk in result.blocks:
        start = _side_input_start(canvas, f"block{blk.index}")
        assert _inside(canvas, start, f"block{blk.index}&&plaintext&&box")


@pytest.mark.parametrize("mode", _STREAM_MODES)
def test_counter_boxes_show_the_end_that_changes(root: Any, mode: AesMode) -> None:
    canvas, result = _drawn(root, mode)

    shown = [
        _values_top_to_bottom(canvas, f"block{b.index}&&counter")[0]
        for b in result.blocks
    ]
    assert len(set(shown)) == len(shown), f"counters look alike: {shown}"
    for blk, text in zip(result.blocks, shown, strict=True):
        assert blk.aes_input.hex().upper().endswith(text.lstrip("…"))


def test_gcm_tag_is_drawn_from_j0_and_ghash_of_the_ciphertext(root: Any) -> None:
    canvas, result = _drawn(root, AesMode.GCM)
    assert result.tag is not None

    last = result.blocks[-1].index
    start = _side_input_start(canvas, "tag")
    assert _inside(canvas, start, f"block{last}&&ciphertext&&box")
    j0, tag = _values_top_to_bottom(canvas, "tag")
    assert j0.endswith("00000001")  # data blocks count from 2
    assert tag.startswith(result.tag.hex().upper()[:16])


@pytest.mark.parametrize(("mode", "tags"), [(AesMode.CBC, "iv"), (AesMode.GCM, "tag")])
def test_clicking_the_iv_or_the_tag_shows_its_value(
    root: Any, mode: AesMode, tags: str
) -> None:
    selected: list[str] = []
    canvas, result = _drawn(root, mode, on_select=selected.append)
    value = result.iv if tags == "iv" else result.tag
    assert value is not None

    x0, y0, x1, y1 = canvas.bbox(f"{tags}&&box")
    canvas.event_generate(
        "<Button-1>",
        x=int((x0 + x1) / 2 - canvas.canvasx(0)),
        y=int((y0 + y1) / 2 - canvas.canvasy(0)),
    )

    require(len(selected) == 1, f"expected one selection, got {selected}")
    assert value.hex().upper() in selected[0]


def test_long_messages_draw_only_the_first_blocks(root: Any) -> None:
    canvas, result = _drawn(root, AesMode.CTR, b"x" * 16 * 40)
    require(len(result.blocks) == 40, "CTR should not pad")

    drawn = {
        tag
        for item in canvas.find_withtag("box")
        for tag in canvas.gettags(item)
        if tag.startswith("block")
    }
    assert drawn == {f"block{i}" for i in range(MAX_DRAWN_BLOCKS)}
    (note,) = canvas.find_withtag("overflow")
    assert f"{MAX_DRAWN_BLOCKS} of 40 blocks" in item_option(canvas, note, "text")


def test_redrawing_scrolls_back_to_the_first_block(root: Any) -> None:
    widget = BlockCanvas(root)
    widget.pack(fill="both", expand=True)
    long_message = encrypt(AesMode.CTR, b"x" * 16 * 40, os.urandom(16))
    widget.draw(long_message)
    pump(root)
    canvas = block_canvas(widget)
    canvas.xview_moveto(1.0)
    require(canvas.xview()[0] > 0, "the canvas did not scroll")

    widget.draw(long_message)

    assert canvas.xview()[0] == 0


def test_deselected_block_gets_its_border_back(canvas: tk.Canvas) -> None:
    original = _border(canvas, 0)

    click_block(canvas, 0)
    click_block(canvas, 1)  # moves the selection away from block 0

    assert _border(canvas, 0) == original


def test_clicking_a_block_highlights_only_that_block(canvas: tk.Canvas) -> None:
    click_block(canvas, 0)
    click_block(canvas, 1)

    unselected = {_border(canvas, 0), _border(canvas, 2)}
    assert len(unselected) == 1, "unselected blocks should share one border"
    assert _border(canvas, 1) not in unselected


def test_tooltip_follows_the_pointer_to_the_next_block(
    canvas: tk.Canvas, root: Any
) -> None:
    for index in (0, 1):
        x, y = plaintext_center(canvas, index)
        canvas.event_generate("<Motion>", x=x, y=y)
    pump(root, 50)

    assert visible_tooltip_text(root).startswith("Block 1")


def test_hovering_one_block_reuses_a_single_tooltip_window(
    canvas: tk.Canvas, root: Any
) -> None:
    x, y = plaintext_center(canvas, 0)
    seen: set[str] = set()
    for dx in range(-20, 21, 2):
        canvas.event_generate("<Motion>", x=x + dx, y=y)
        seen |= {str(w) for w in tooltip_windows(root)}

    require(bool(seen), "hovering a block showed no tooltip at all")
    assert len(seen) == 1, f"{len(seen)} tooltip windows created for one block"


def _below_the_blocks(canvas: tk.Canvas) -> int:
    """A y coordinate in the empty space under the drawn blocks."""
    below = canvas.winfo_height() - 5
    lowest_drawn = canvas.bbox("all")[3]
    require(below > lowest_drawn + 20, "canvas too short to hover below the blocks")
    return below


def test_tooltip_hides_over_empty_space_below_the_blocks(
    canvas: tk.Canvas, root: Any
) -> None:
    x, y = plaintext_center(canvas, 0)
    canvas.event_generate("<Motion>", x=x, y=y)
    pump(root, 50)
    require(bool(visible_tooltips(root)), "hovering a block showed no tooltip")

    canvas.event_generate("<Motion>", x=x, y=_below_the_blocks(canvas))
    pump(root, 50)

    assert not visible_tooltips(root)


def test_tooltip_comes_back_after_hiding(canvas: tk.Canvas, root: Any) -> None:
    x, y = plaintext_center(canvas, 0)
    for pointer_y in (y, _below_the_blocks(canvas), y):
        canvas.event_generate("<Motion>", x=x, y=pointer_y)
        pump(root, 50)

    assert visible_tooltip_text(root).startswith("Block 0")


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
