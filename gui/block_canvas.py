"""
Block visualization: every AES block as plaintext, AES input and ciphertext.

BlockCanvas draws the blocks and handles hovering and selection; BlockPanel
puts it under a title and shows the clicked block's details below it.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable

import customtkinter as ctk

from gui.palette import COLOUR_PANEL, COLOUR_SURFACE
from gui.tooltip import Tooltip
from modules.aes_modes import AesMode, Block, EncryptionResult

COLOUR_PT = "#5B9BD5"  # plaintext  → blue
COLOUR_CT = "#E07B39"  # ciphertext → orange
COLOUR_IV = "#5BAD72"  # IV / XOR   → green
COLOUR_SEL = "#C0392B"  # selected   → red outline
BLOCK_W = 130  # block rectangle width
BLOCK_H = 54  # block rectangle height
BLOCK_GAP = 14  # horizontal gap between blocks
ARROW_COLOR = "#888888"


def _abbreviate(hex_text: str, limit: int = 16) -> str:
    """Shorten *hex_text* to *limit* characters plus an ellipsis to fit a block."""
    return hex_text if len(hex_text) <= limit else hex_text[:limit] + "…"


def _hex(data: bytes) -> str:
    return data.hex().upper()


# The middle row shows what each mode feeds through AES. ECB has nothing extra
# to show: its AES input is the plaintext block itself.
_AES_INPUT_LABEL = {
    AesMode.CBC: "XOR Input",
    AesMode.CTR: "Counter",
    AesMode.GCM: "Counter",
}


class BlockCanvas(ctk.CTkFrame):
    """
    Canvas that draws AES blocks with arrows and hover tooltips.

    Clicking a block selects it and passes a description of it to *on_select*.
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
        self._surface = tk.Canvas(
            self,
            background=COLOUR_SURFACE,
            highlightthickness=0,
        )
        self._surface.grid(row=0, column=0, sticky="nsew")

        self._hscroll = ctk.CTkScrollbar(
            self, orientation="horizontal", command=self._surface.xview
        )
        self._hscroll.grid(row=1, column=0, sticky="ew")
        self._surface.configure(xscrollcommand=self._hscroll.set)

        self._tooltip = Tooltip(self._surface)
        self._on_select = on_select
        self._mode = AesMode.ECB
        self._blocks: tuple[Block, ...] = ()
        # Per block index: its rectangles, and the area it covers on the canvas.
        self._block_rects: dict[int, list[int]] = {}
        self._block_bounds: dict[int, tuple[int, int, int, int]] = {}
        # Each rectangle's own (outline, width), restored when it is deselected.
        self._normal_borders: dict[int, tuple[str, int]] = {}
        self._selected: int | None = None

        self._surface.bind("<Motion>", self._on_motion)
        self._surface.bind("<Leave>", lambda _e: self._tooltip.hide())
        self._surface.bind("<Button-1>", self._on_click)

    def draw(self, result: EncryptionResult) -> None:
        self._surface.delete("all")
        self._mode = result.mode
        self._blocks = result.blocks
        self._block_rects = {}
        self._block_bounds = {}
        self._normal_borders = {}
        self._selected = None

        if not self._blocks:
            return

        total_w = len(self._blocks) * (BLOCK_W + BLOCK_GAP) + BLOCK_GAP + 20
        canvas_h = BLOCK_H * 3 + 80

        self._surface.configure(scrollregion=(0, 0, total_w, canvas_h))

        for blk in self._blocks:
            x0 = BLOCK_GAP + blk.index * (BLOCK_W + BLOCK_GAP)
            self._draw_block(blk, x0)

    def _rect(self, x0: int, y0: int, fill: str, outline: str) -> int:
        """Draw one block-sized rectangle and remember its normal border."""
        width = 2
        rect = self._surface.create_rectangle(
            x0,
            y0,
            x0 + BLOCK_W,
            y0 + BLOCK_H,
            fill=fill,
            outline=outline,
            width=width,
        )
        self._normal_borders[rect] = (outline, width)
        return rect

    def _draw_block(self, blk: Block, x0: int) -> None:
        y_pt = 20
        y_iv = y_pt + BLOCK_H + 18
        y_ct = y_iv + BLOCK_H + 18

        r1 = self._rect(x0, y_pt, fill=COLOUR_PT, outline="#3A79B0")  # plaintext
        t1 = self._surface.create_text(
            x0 + BLOCK_W // 2,
            y_pt + 10,
            text="Plaintext",
            font=("Courier New", 8),
            fill="white",
        )
        t1b = self._surface.create_text(
            x0 + BLOCK_W // 2,
            y_pt + 28,
            text=_abbreviate(_hex(blk.plaintext)),
            font=("Courier New", 9, "bold"),
            fill="white",
        )

        # Middle row: what this mode passed through AES (none for ECB)
        middle_rects: list[int] = []
        middle_texts: list[int] = []
        aes_input_label = _AES_INPUT_LABEL.get(self._mode)
        if aes_input_label is not None:
            middle_rects.append(self._rect(x0, y_iv, fill=COLOUR_IV, outline="#3A8F58"))
            middle_texts.append(
                self._surface.create_text(
                    x0 + BLOCK_W // 2,
                    y_iv + 10,
                    text=aes_input_label,
                    font=("Courier New", 8),
                    fill="white",
                )
            )
            middle_texts.append(
                self._surface.create_text(
                    x0 + BLOCK_W // 2,
                    y_iv + 28,
                    text=_abbreviate(_hex(blk.aes_input)),
                    font=("Courier New", 9, "bold"),
                    fill="white",
                )
            )

        r3 = self._rect(x0, y_ct, fill=COLOUR_CT, outline="#B05A20")  # ciphertext
        t3 = self._surface.create_text(
            x0 + BLOCK_W // 2,
            y_ct + 10,
            text="Ciphertext",
            font=("Courier New", 8),
            fill="white",
        )
        t3b = self._surface.create_text(
            x0 + BLOCK_W // 2,
            y_ct + 28,
            text=_abbreviate(_hex(blk.ciphertext)),
            font=("Courier New", 9, "bold"),
            fill="white",
        )

        # Block index label
        idx_t = self._surface.create_text(
            x0 + BLOCK_W // 2,
            y_ct + BLOCK_H + 8,
            text=f"Block {blk.index}",
            font=("Courier New", 8),
            fill="#AAAAAA",
        )

        # CBC chaining arrow (only for CBC, between blocks)
        if self._mode is AesMode.CBC and blk.index > 0:
            self._surface.create_line(
                x0 - BLOCK_GAP,
                y_ct + BLOCK_H // 2,
                x0,
                y_ct + BLOCK_H // 2,
                fill=ARROW_COLOR,
                arrow=tk.LAST,
                width=2,
            )

        # Remember the block's rectangles (for selection) and the area its items
        # cover (for hit-testing; the CBC arrow sits between blocks, not in one).
        rects = [r1, *middle_rects, r3]
        items = [*rects, t1, t1b, *middle_texts, t3, t3b, idx_t]
        self._block_rects[blk.index] = rects
        self._block_bounds[blk.index] = self._surface.bbox(*items)

    def _block_at(self, x: float, y: float) -> int | None:
        """Index of the block drawn at canvas point (x, y); None over empty space."""
        for index, (x0, y0, x1, y1) in self._block_bounds.items():
            if x0 <= x <= x1 and y0 <= y <= y1:
                return index
        return None

    def _block_under(self, event: tk.Event) -> int | None:
        """The block under the pointer, converting window to (scrolled) canvas space."""
        return self._block_at(
            self._surface.canvasx(event.x), self._surface.canvasy(event.y)
        )

    def _select(self, index: int) -> None:
        """Highlight block *index*, giving the previous selection its border back."""
        if self._selected is not None:
            for rect in self._block_rects[self._selected]:
                outline, width = self._normal_borders[rect]
                self._surface.itemconfigure(rect, outline=outline, width=width)
        for rect in self._block_rects[index]:
            self._surface.itemconfigure(rect, outline=COLOUR_SEL, width=3)
        self._selected = index

    def _on_motion(self, event: tk.Event) -> None:
        idx = self._block_under(event)
        if idx is not None:
            blk = self._blocks[idx]
            rows = "\n".join(
                f"{label:<10}: {value}" for label, value in self._rows(blk)
            )
            self._tooltip.show(
                event.x, event.y, f"Block {blk.index}  [{self._mode}]\n{rows}"
            )
        else:
            self._tooltip.hide()

    def _on_click(self, event: tk.Event) -> None:
        idx = self._block_under(event)
        if idx is None:
            return

        self._select(idx)
        blk = self._blocks[idx]
        if self._on_select is not None:
            rows = "\n".join(f"{label}:\n  {value}" for label, value in self._rows(blk))
            self._on_select(f"Block {blk.index} — {self._mode}\n{rows}")

    def _rows(self, blk: Block) -> list[tuple[str, str]]:
        """(label, hex value) for each row of *blk*, top to bottom as drawn."""
        rows = [("Plaintext", _hex(blk.plaintext))]
        aes_input_label = _AES_INPUT_LABEL.get(self._mode)
        if aes_input_label is not None:
            rows.append((aes_input_label, _hex(blk.aes_input)))
        rows.append(("Ciphertext", _hex(blk.ciphertext)))
        return rows


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
        detail_frame = ctk.CTkFrame(self, height=115)
        detail_frame.grid(row=2, column=0, sticky="ew", padx=4, pady=(0, 4))
        detail_frame.grid_columnconfigure(0, weight=1)
        detail_frame.grid_rowconfigure(0, weight=1)
        detail_frame.grid_propagate(False)

        self._details = tk.Text(
            detail_frame,
            font=("Courier New", 10),
            background=COLOUR_PANEL,
            foreground="#E0E0E0",
            relief="flat",
            bd=0,
            wrap="word",
            height=5,
            state="disabled",
            cursor="arrow",
        )
        self._details.grid(row=0, column=0, sticky="nsew", padx=6, pady=4)
        self._show_details("Click a block to see details…")

    def draw(self, result: EncryptionResult) -> None:
        self._block_canvas.draw(result)

    def _show_details(self, text: str) -> None:
        """Replace the text of the read-only details box."""
        self._details.configure(state="normal")
        self._details.delete("1.0", "end")
        self._details.insert("1.0", text)
        self._details.configure(state="disabled")
