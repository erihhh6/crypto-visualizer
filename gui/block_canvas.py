"""
Block visualization: how each AES mode turns plaintext blocks into ciphertext.

BlockCanvas draws one column per block, following the mode's data flow as
NIST draws it (SP 800-38A; SP 800-38D for GCM):

  ECB       P → AES → C
  CBC       P ⊕ (the IV, then the previous C) → AES → C
  CTR, GCM  counter → AES → keystream;  P ⊕ keystream → C
  GCM tag   J0 → AES → ⊕ GHASH(all of C) → tag

BlockPanel puts it under a title and shows the clicked item's details below it.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable, Sequence
from dataclasses import dataclass

import customtkinter as ctk

from gui.palette import (
    FILL_BLUE,
    FILL_BRONZE,
    FILL_GREEN,
    FILL_ORANGE,
    FILL_PURPLE,
    FILL_RED,
    FILL_SLATE,
    LINE,
    MUTED,
    PANEL,
    SURFACE,
    TEXT,
    follow_appearance,
    resolve,
)
from gui.tooltip import Tooltip
from modules.aes_modes import (
    AesMode,
    Block,
    EncryptionResult,
    gcm_pre_counter_block,
)

# Value boxes carry white text, so their fills are the same in both modes:
# plaintext blue, IV/AES input/counters green, keystream purple, ciphertext
# orange, GCM tag bronze. Each border is a darker shade of its fill.
_BORDERS = {
    FILL_BLUE: "#1E4F82",
    FILL_GREEN: "#1E5A32",
    FILL_PURPLE: "#4D3578",
    FILL_ORANGE: "#7C3A12",
    FILL_BRONZE: "#5A4515",
}
COLOUR_SEL = FILL_RED  # the selected item's border

LANE_W = 84  # row headers (and the CBC IV) left of the first block
BLOCK_W = 130  # value box width
BOX_H = 24  # value box height
BAND_H = 30  # gap between rows, where the AES boxes and ⊕ nodes sit
BLOCK_GAP = 28  # gap between columns; side inputs are routed through it
TOP = 24  # room for the column captions
XOR_R = 8  # radius of a ⊕ node

# Drawing every block of a long message froze the window (half a second for
# 64 KB) and made a canvas hundreds of thousands of pixels wide.
MAX_DRAWN_BLOCKS = 32


def _hex(data: bytes) -> str:
    return data.hex().upper()


def _abbreviate(hex_text: str, limit: int = 16, *, keep_end: bool = False) -> str:
    """Shorten *hex_text* to *limit* characters plus an ellipsis to fit a box."""
    if len(hex_text) <= limit:
        return hex_text
    return "…" + hex_text[-limit:] if keep_end else hex_text[:limit] + "…"


@dataclass(frozen=True)
class _Row:
    """One kind of value box, drawn once per block in its own row."""

    tag: str  # canvas tag of the row's items, e.g. "counter"
    header: str  # shown in the lane on the left
    fill: str
    value: Callable[[Block], bytes]
    # Counters only change at the end: show the end, or every box looks alike.
    keep_end: bool = False


def _keystream(blk: Block) -> bytes:
    if blk.keystream is None:
        raise ValueError(f"block {blk.index} has no keystream")
    return blk.keystream


_PLAINTEXT = _Row("plaintext", "Plaintext", FILL_BLUE, lambda b: b.plaintext)
_AES_INPUT = _Row("aes_input", "AES input", FILL_GREEN, lambda b: b.aes_input)
_COUNTER = _Row("counter", "Counter", FILL_GREEN, lambda b: b.aes_input, keep_end=True)
_KEYSTREAM = _Row("keystream", "Keystream", FILL_PURPLE, _keystream)
_CIPHERTEXT = _Row("ciphertext", "Ciphertext", FILL_ORANGE, lambda b: b.ciphertext)

# Top to bottom. Plaintext is always on top and ciphertext at the bottom, so
# the modes are easy to compare.
_ROWS: dict[AesMode, tuple[_Row, ...]] = {
    AesMode.ECB: (_PLAINTEXT, _CIPHERTEXT),
    AesMode.CBC: (_PLAINTEXT, _AES_INPUT, _CIPHERTEXT),
    AesMode.CTR: (_PLAINTEXT, _COUNTER, _KEYSTREAM, _CIPHERTEXT),
    AesMode.GCM: (_PLAINTEXT, _COUNTER, _KEYSTREAM, _CIPHERTEXT),
}


def _formula(mode: AesMode, index: int) -> str:
    match mode:
        case AesMode.ECB:
            return f"C{index} = AES(P{index})"
        case AesMode.CBC:
            previous = "IV" if index == 0 else f"C{index - 1}"
            return f"C{index} = AES(P{index} ⊕ {previous})"
        case AesMode.CTR | AesMode.GCM:
            return f"C{index} = P{index} ⊕ AES(counter{index})"


def _column_x(column: int) -> int:
    """Left edge of a column: blocks first, then any note and the GCM tag."""
    return LANE_W + BLOCK_GAP + column * (BLOCK_W + BLOCK_GAP)


def _row_top(row: int) -> int:
    return TOP + row * (BOX_H + BAND_H)


def _row_bottom(row: int) -> int:
    return _row_top(row) + BOX_H


def _row_middle(row: int) -> int:
    return _row_top(row) + BOX_H // 2


def _band_middle(row: int) -> int:
    """Vertical middle of the band below *row*."""
    return _row_bottom(row) + BAND_H // 2


@dataclass(frozen=True)
class _Item:
    """Something the user can hover and click: a block, the IV or the tag."""

    title: str  # e.g. "Block 1 — CBC"
    formula: str
    rows: list[tuple[str, str]]  # (label, full hex value)
    rects: list[int]  # its value boxes, outlined while selected
    bounds: tuple[int, int, int, int]  # the area it covers, for hit-testing

    def tooltip(self) -> str:
        rows = "\n".join(f"{label:<10}: {value}" for label, value in self.rows)
        return f"{self.title}\n{self.formula}\n{rows}"

    def details(self) -> str:
        rows = "\n".join(f"{label}:\n  {value}" for label, value in self.rows)
        return f"{self.title}\n{self.formula}\n{rows}"


class BlockCanvas(ctk.CTkFrame):
    """
    Canvas that draws each block's data flow, with hover tooltips.

    Clicking a block, the IV or the tag selects it and passes a description of
    it to *on_select*. Items carry tags naming what they show: "block2",
    "counter", "xor", "chain" (a ciphertext feeding the next CBC block), and so on.
    """

    def __init__(
        self,
        parent: tk.Widget,
        *,
        on_select: Callable[[str], None] | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(parent, **kwargs)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Not "_canvas": CTkFrame keeps its own background canvas under that
        # name, and overwriting it made every theme change repaint this one.
        self._surface = tk.Canvas(self, highlightthickness=0)
        self._surface.grid(row=0, column=0, sticky="nsew")

        # Many blocks make the diagram wide, and the four rows of CTR and GCM
        # are taller than the canvas gets in a small window.
        self._hscroll = ctk.CTkScrollbar(
            self, orientation="horizontal", command=self._surface.xview
        )
        self._hscroll.grid(row=1, column=0, sticky="ew")
        self._vscroll = ctk.CTkScrollbar(
            self, orientation="vertical", command=self._surface.yview
        )
        self._vscroll.grid(row=0, column=1, sticky="ns")
        self._surface.configure(
            xscrollcommand=self._hscroll.set, yscrollcommand=self._vscroll.set
        )

        self._tooltip = Tooltip(self._surface)
        self._on_select = on_select
        self._result: EncryptionResult | None = None
        self._items: list[_Item] = []
        # Each rectangle's own (outline, width), restored when it is deselected.
        self._normal_borders: dict[int, tuple[str, int]] = {}
        self._selected: _Item | None = None

        self._surface.bind("<Motion>", self._on_motion)
        self._surface.bind("<Leave>", lambda _e: self._tooltip.hide())
        self._surface.bind("<Button-1>", self._on_click)
        follow_appearance(self._surface, self._restyle)

    def _restyle(self) -> None:
        """Repaint in the current light/dark colours, keeping view and selection."""
        self._surface.configure(background=resolve(SURFACE))
        if self._result is None:
            return
        left, top = self._surface.xview()[0], self._surface.yview()[0]
        selected = self._selected.title if self._selected else None
        self.draw(self._result)
        self._surface.xview_moveto(left)
        self._surface.yview_moveto(top)
        for item in self._items:
            if item.title == selected:
                self._select(item)

    def draw(self, result: EncryptionResult) -> None:
        self._result = result
        self._surface.delete("all")
        self._surface.xview_moveto(0)
        self._surface.yview_moveto(0)
        self._items = []
        self._normal_borders = {}
        self._selected = None

        shown = result.blocks[:MAX_DRAWN_BLOCKS]
        if not shown:
            return
        rows = _ROWS[result.mode]

        for row_index, row in enumerate(rows):
            self._surface.create_text(
                LANE_W - 6,
                _row_middle(row_index),
                text=row.header,
                anchor="e",
                font=("Courier New", 8),
                fill=resolve(MUTED),
                tags=("header",),
            )
        for blk in shown:
            self._draw_block(result.mode, rows, blk)

        column = len(shown)
        if len(result.blocks) > len(shown):
            self._draw_overflow_note(column, len(shown), len(result.blocks))
            column += 1
        if result.mode is AesMode.CBC:
            self._draw_cbc_iv(result)
        if result.mode is AesMode.GCM:
            self._draw_gcm_tag(result, column, last_block=len(shown) - 1)

        _, _, right, bottom = self._surface.bbox("all")
        self._surface.configure(scrollregion=(0, 0, right + 20, bottom + 10))

    # ------------------------------------------------------------------
    # Drawing
    # ------------------------------------------------------------------

    def _draw_block(self, mode: AesMode, rows: Sequence[_Row], blk: Block) -> None:
        x0 = _column_x(blk.index)
        tags = (f"block{blk.index}",)
        self._caption(x0, f"Block {blk.index}", tags)
        rects = [
            self._box(
                x0,
                row_index,
                _abbreviate(_hex(row.value(blk)), keep_end=row.keep_end),
                row.fill,
                (*tags, row.tag),
            )
            for row_index, row in enumerate(rows)
        ]

        cx = x0 + BLOCK_W // 2
        match mode:
            case AesMode.ECB:
                self._aes_arrow(cx, _row_bottom(0), _row_top(1), tags)
            case AesMode.CBC:
                self._xor_between(cx, 0, tags)
                self._aes_arrow(cx, _row_bottom(1), _row_top(2), tags)
                if blk.index > 0:
                    # The previous ciphertext block, through the gap to the left.
                    gap = x0 - BLOCK_GAP // 2
                    self._arrow(
                        (x0 - BLOCK_GAP, _row_middle(2)),
                        (gap, _row_middle(2)),
                        (gap, _band_middle(0)),
                        (cx - XOR_R, _band_middle(0)),
                        tags=("chain",),
                    )
            case AesMode.CTR | AesMode.GCM:
                self._aes_arrow(cx, _row_bottom(1), _row_top(2), tags)
                self._xor_between(cx, 2, tags)
                # The plaintext never goes through AES: route it around the
                # counter and keystream into the ⊕.
                bypass = x0 - 10
                self._arrow(
                    (x0, _row_middle(0)),
                    (bypass, _row_middle(0)),
                    (bypass, _band_middle(2)),
                    (cx - XOR_R, _band_middle(2)),
                    tags=tags,
                )

        self._items.append(
            _Item(
                title=f"Block {blk.index} — {mode}",
                formula=_formula(mode, blk.index),
                rows=[(row.header, _hex(row.value(blk))) for row in rows],
                rects=rects,
                bounds=self._surface.bbox(tags[0]),
            )
        )

    def _draw_cbc_iv(self, result: EncryptionResult) -> None:
        """The IV, in the lane, feeding block 0's ⊕."""
        iv = result.iv
        if iv is None:
            raise ValueError("CBC result without an IV")
        tags = ("iv",)
        y = _band_middle(0)
        rect = self._rect(8, y - 10, LANE_W - 8, y + 10, FILL_GREEN, tags)
        self._surface.create_text(
            LANE_W // 2,
            y,
            text="IV",
            font=("Courier New", 9, "bold"),
            fill="white",
            tags=(*tags, "value"),
        )
        self._arrow(
            (LANE_W - 8, y),
            (_column_x(0) + BLOCK_W // 2 - XOR_R, y),
            tags=tags,
        )
        self._items.append(
            _Item(
                title=f"IV — {result.mode}",
                formula="C0 = AES(P0 ⊕ IV); a fresh random IV for every message",
                rows=[("IV", _hex(iv))],
                rects=[rect],
                bounds=self._surface.bbox(rect),
            )
        )

    def _draw_gcm_tag(
        self, result: EncryptionResult, column: int, last_block: int
    ) -> None:
        """J0 → AES → ⊕ GHASH(ciphertext) → tag, in a column after the blocks."""
        if result.iv is None or result.tag is None:
            raise ValueError("GCM result without an IV or a tag")
        j0 = gcm_pre_counter_block(result.iv)
        x0 = _column_x(column)
        cx = x0 + BLOCK_W // 2
        tags = ("tag",)
        self._caption(x0, "Tag", tags)
        j0_rect = self._box(
            x0, 1, _abbreviate(_hex(j0), keep_end=True), FILL_GREEN, tags
        )
        self._aes_arrow(cx, _row_bottom(1), _band_middle(2) - XOR_R, tags)
        self._xor_node(cx, _band_middle(2), tags)
        self._arrow((cx, _band_middle(2) + XOR_R), (cx, _row_top(3)), tags=tags)
        tag_rect = self._box(x0, 3, _abbreviate(_hex(result.tag)), FILL_BRONZE, tags)

        # GHASH covers every ciphertext block; the arrow leaves the last one.
        gap = x0 - BLOCK_GAP // 2
        self._arrow(
            (_column_x(last_block) + BLOCK_W, _row_middle(3)),
            (gap, _row_middle(3)),
            (gap, _band_middle(2)),
            (cx - XOR_R, _band_middle(2)),
            tags=("ghash",),
        )
        self._surface.create_text(
            (gap + cx - XOR_R) // 2,
            _band_middle(2) - 9,
            text="GHASH",
            font=("Courier New", 7),
            fill=resolve(MUTED),
            tags=("ghash",),
        )

        self._items.append(
            _Item(
                title=f"Tag — {result.mode}",
                formula="Tag = AES(J0) ⊕ GHASH(ciphertext); J0 = IV ‖ 00000001",
                rows=[("J0", _hex(j0)), ("Tag", _hex(result.tag))],
                rects=[j0_rect, tag_rect],
                bounds=self._surface.bbox(*tags),
            )
        )

    def _draw_overflow_note(self, column: int, shown: int, total: int) -> None:
        self._surface.create_text(
            _column_x(column) + BLOCK_W // 2,
            _row_middle(0),
            text=f"Showing the first\n{shown} of {total} blocks",
            justify="center",
            font=("Courier New", 8),
            fill=resolve(MUTED),
            tags=("overflow",),
        )

    # ------------------------------------------------------------------
    # Primitives
    # ------------------------------------------------------------------

    def _caption(self, x0: int, text: str, tags: tuple[str, ...]) -> None:
        self._surface.create_text(
            x0 + BLOCK_W // 2,
            TOP - 12,
            text=text,
            font=("Courier New", 8),
            fill=resolve(MUTED),
            tags=tags,
        )

    def _rect(
        self,
        x0: int,
        y0: int,
        x1: int,
        y1: int,
        fill: str,
        tags: tuple[str, ...],
    ) -> int:
        """Draw a value box and remember its normal border."""
        outline, width = _BORDERS[fill], 2
        rect = self._surface.create_rectangle(
            x0,
            y0,
            x1,
            y1,
            fill=fill,
            outline=outline,
            width=width,
            tags=(*tags, "box"),
        )
        self._normal_borders[rect] = (outline, width)
        return rect

    def _box(
        self,
        x0: int,
        row: int,
        text: str,
        fill: str,
        tags: tuple[str, ...],
    ) -> int:
        """A full-width value box in *row* of the column at *x0*."""
        rect = self._rect(x0, _row_top(row), x0 + BLOCK_W, _row_bottom(row), fill, tags)
        self._surface.create_text(
            x0 + BLOCK_W // 2,
            _row_middle(row),
            text=text,
            font=("Courier New", 9, "bold"),
            fill="white",
            tags=(*tags, "value"),
        )
        return rect

    def _arrow(self, *points: tuple[int, int], tags: tuple[str, ...]) -> None:
        self._surface.create_line(
            *points, fill=resolve(LINE), width=2, arrow=tk.LAST, tags=tags
        )

    def _aes_arrow(self, cx: int, y0: int, y1: int, tags: tuple[str, ...]) -> None:
        """An arrow down from *y0* to *y1* through an AES box in the band below y0."""
        self._arrow((cx, y0), (cx, y1), tags=tags)
        y = y0 + BAND_H // 2
        self._surface.create_rectangle(
            cx - 18,
            y - 8,
            cx + 18,
            y + 8,
            fill=FILL_SLATE,
            outline=resolve(LINE),
            tags=(*tags, "aes"),
        )
        self._surface.create_text(
            cx,
            y,
            text="AES",
            font=("Courier New", 7, "bold"),
            fill="white",
            tags=(*tags, "aes"),
        )

    def _xor_node(self, cx: int, cy: int, tags: tuple[str, ...]) -> None:
        r = XOR_R
        xor_tags = (*tags, "xor")
        self._surface.create_oval(
            cx - r,
            cy - r,
            cx + r,
            cy + r,
            fill=resolve(SURFACE),
            outline=resolve(LINE),
            width=2,
            tags=xor_tags,
        )
        for points in ((cx - r, cy, cx + r, cy), (cx, cy - r, cx, cy + r)):
            self._surface.create_line(
                *points, fill=resolve(LINE), width=2, tags=xor_tags
            )

    def _xor_between(self, cx: int, row: int, tags: tuple[str, ...]) -> None:
        """A ⊕ in the band below *row*, on the way down to the next row."""
        cy = _band_middle(row)
        self._arrow((cx, _row_bottom(row)), (cx, cy - XOR_R), tags=tags)
        self._xor_node(cx, cy, tags)
        self._arrow((cx, cy + XOR_R), (cx, _row_top(row + 1)), tags=tags)

    # ------------------------------------------------------------------
    # Interaction
    # ------------------------------------------------------------------

    def _item_at(self, x: float, y: float) -> _Item | None:
        """The item drawn at canvas point (x, y); None over empty space."""
        for item in self._items:
            x0, y0, x1, y1 = item.bounds
            if x0 <= x <= x1 and y0 <= y <= y1:
                return item
        return None

    def _item_under(self, event: tk.Event) -> _Item | None:
        """The item under the pointer, converting window to (scrolled) canvas space."""
        return self._item_at(
            self._surface.canvasx(event.x), self._surface.canvasy(event.y)
        )

    def _select(self, item: _Item) -> None:
        """Highlight *item*, giving the previous selection its border back."""
        if self._selected is not None:
            for rect in self._selected.rects:
                outline, width = self._normal_borders[rect]
                self._surface.itemconfigure(rect, outline=outline, width=width)
        for rect in item.rects:
            self._surface.itemconfigure(rect, outline=COLOUR_SEL, width=3)
        self._selected = item

    def _on_motion(self, event: tk.Event) -> None:
        item = self._item_under(event)
        if item is not None:
            self._tooltip.show(event.x, event.y, item.tooltip())
        else:
            self._tooltip.hide()

    def _on_click(self, event: tk.Event) -> None:
        item = self._item_under(event)
        if item is None:
            return
        self._select(item)
        if self._on_select is not None:
            self._on_select(item.details())


_DETAILS_PLACEHOLDER = "Click a block to see details…"


class BlockPanel(ctk.CTkFrame):
    """The block canvas under a title, with the clicked block's details below."""

    def __init__(self, parent: tk.Widget, **kwargs: object) -> None:
        super().__init__(parent, **kwargs)
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self,
            text="Block Visualization",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=8, pady=(6, 0))

        # Not "_canvas" either: see BlockCanvas.
        self._block_canvas = BlockCanvas(
            self, on_select=self._show_details, fg_color="transparent"
        )
        self._block_canvas.grid(row=1, column=0, sticky="nsew", padx=4, pady=4)

        # Details below the canvas: a fixed-height box of text that scrolls,
        # so every row of a block stays reachable.
        detail_frame = ctk.CTkFrame(self, height=115, fg_color=PANEL)
        detail_frame.grid(row=2, column=0, sticky="ew", padx=4, pady=(0, 4))
        detail_frame.grid_columnconfigure(0, weight=1)
        detail_frame.grid_rowconfigure(0, weight=1)
        detail_frame.grid_propagate(False)

        self._details = tk.Text(
            detail_frame,
            font=("Courier New", 10),
            relief="flat",
            bd=0,
            wrap="word",
            height=5,
            state="disabled",
            cursor="arrow",
        )
        self._details.grid(row=0, column=0, sticky="nsew", padx=6, pady=4)
        follow_appearance(self._details, self._restyle_details)
        self._show_details(_DETAILS_PLACEHOLDER)

    def _restyle_details(self) -> None:
        self._details.configure(background=resolve(PANEL), foreground=resolve(TEXT))

    def draw(self, result: EncryptionResult) -> None:
        self._block_canvas.draw(result)
        # Details of a block from the previous encryption would now be wrong.
        self._show_details(_DETAILS_PLACEHOLDER)

    def _show_details(self, text: str) -> None:
        """Replace the text of the read-only details box."""
        self._details.configure(state="normal")
        self._details.delete("1.0", "end")
        self._details.insert("1.0", text)
        self._details.configure(state="disabled")
