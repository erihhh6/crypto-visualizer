"""ModeComparison's block strips: colours for equal blocks, the cap, tooltips."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from gui.mode_comparison import (
    MAX_CHIPS,
    NEUTRAL,
    REPEAT_COLOURS,
    BlockStrip,
    strip_colours,
)
from gui.palette import PANEL
from tests.gui.helpers import item_option, pump, visible_tooltip_text

_A, _B, _C, _D = (bytes([n]) * 16 for n in range(4))


def _strip(root: Any, blocks: list[bytes]) -> BlockStrip:
    strip = BlockStrip(root, background=PANEL)
    strip.pack(padx=40, pady=40)
    strip.show(blocks)
    pump(root)
    return strip


def test_equal_blocks_share_a_colour_and_unique_ones_stay_neutral() -> None:
    first, second = REPEAT_COLOURS[:2]

    assert strip_colours([_A, _B, _A, _C, _C, _D]) == [
        first,
        NEUTRAL,
        first,
        second,
        second,
        NEUTRAL,
    ]


def test_squares_follow_the_theme(
    root: Any, switch_appearance: Callable[[str], None]
) -> None:
    strip = _strip(root, [_A, _A, _B])
    repeated = REPEAT_COLOURS[0]

    for mode, colour in (("Dark", 1), ("Light", 0)):
        switch_appearance(mode)
        fills = [item_option(strip, i, "fill") for i in strip.find_withtag("chip")]
        assert fills == [repeated[colour], repeated[colour], NEUTRAL[colour]]
        assert strip["background"] == PANEL[colour]


def test_a_long_message_draws_a_capped_strip_and_counts_the_rest(root: Any) -> None:
    strip = _strip(root, [_A] * (MAX_CHIPS + 7))

    assert len(strip.find_withtag("chip")) == MAX_CHIPS
    (more,) = strip.find_withtag("more")
    assert item_option(strip, more, "text") == "+7"


def test_hovering_a_square_shows_its_block(root: Any) -> None:
    strip = _strip(root, [_A, _B, _C])
    x0, y0, x1, y1 = strip.coords(strip.find_withtag("chip")[1])

    strip.event_generate("<Motion>", x=int((x0 + x1) / 2), y=int((y0 + y1) / 2))
    pump(root, 50)

    assert visible_tooltip_text(root) == f"Block 1: {_B.hex().upper()}"
