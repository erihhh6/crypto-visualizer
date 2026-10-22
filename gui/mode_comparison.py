"""
Mode comparison: one message, one key, all four AES modes side by side.

Every 16-byte block is a small square, and equal blocks share a colour. The
plaintext's pattern comes back in ECB's ciphertext and nowhere else: that is
ECB's leak. Each card also lists what is sent with the ciphertext (the IV or
initial counter, GCM's tag) and how long the ciphertext is.
"""

from __future__ import annotations

import tkinter as tk
from collections import Counter
from collections.abc import Iterable, Sequence

import customtkinter as ctk

from gui.palette import COLOUR_PANEL
from gui.tooltip import Tooltip
from modules.aes_modes import BLOCK_SIZE, AesMode, EncryptionResult

_MODE_COLOURS = {
    AesMode.ECB: "#E07B39",
    AesMode.CBC: "#5B9BD5",
    AesMode.CTR: "#5BAD72",
    AesMode.GCM: "#9B59B6",
}

NEUTRAL = "#4A4A60"  # a block that occurs only once
# One colour per group of equal blocks, in order of first appearance. More
# groups than colours reuse them; real messages rarely get that far.
REPEAT_COLOURS = ("#E74C3C", "#F1C40F", "#2ECC71", "#3498DB", "#E67E22", "#1ABC9C")

CHIP = 16  # square size
CHIP_GAP = 3
MAX_CHIPS = 10  # per strip; the rest are counted, not drawn


def strip_colours(blocks: Sequence[bytes]) -> list[str]:
    """One colour per block: equal blocks share a colour, unique ones are neutral."""
    counts = Counter(blocks)
    group_colour: dict[bytes, str] = {}
    colours = []
    for block in blocks:
        if counts[block] < 2:
            colours.append(NEUTRAL)
            continue
        if block not in group_colour:
            group_colour[block] = REPEAT_COLOURS[
                len(group_colour) % len(REPEAT_COLOURS)
            ]
        colours.append(group_colour[block])
    return colours


def _summary(result: EncryptionResult) -> str:
    """The ciphertext's length and the values sent along with it."""
    parts = [
        f"{len(result.ciphertext)} bytes" + (" (padded)" if result.mode.pads else "")
    ]
    if result.iv is None:
        parts.append("no IV")
    else:
        # PyCA's CTR "IV" is the whole initial counter block.
        name = "counter" if result.mode is AesMode.CTR else "IV"
        parts.append(f"{name} {result.iv.hex().upper()[:6]}…")
    if result.tag is not None:
        parts.append(f"tag {result.tag.hex().upper()[:6]}…")
    return " · ".join(parts)


class BlockStrip(tk.Canvas):
    """A row of squares, one per block; hovering one shows its bytes."""

    def __init__(self, parent: tk.Misc, background: str) -> None:
        super().__init__(
            parent, width=CHIP, height=CHIP, background=background, highlightthickness=0
        )
        self._blocks: Sequence[bytes] = ()
        self._tooltip = Tooltip(self)
        self.bind("<Motion>", self._on_motion)
        self.bind("<Leave>", lambda _e: self._tooltip.hide())

    def show(self, blocks: Sequence[bytes]) -> None:
        self.delete("all")
        self._blocks = blocks
        colours = strip_colours(blocks)[:MAX_CHIPS]
        for index, colour in enumerate(colours):
            x = index * (CHIP + CHIP_GAP)
            self.create_rectangle(
                x, 0, x + CHIP, CHIP, fill=colour, outline="", tags=("chip",)
            )
        width = len(colours) * (CHIP + CHIP_GAP)
        if len(blocks) > len(colours):
            self.create_text(
                width + 2,
                CHIP // 2,
                text=f"+{len(blocks) - len(colours)}",
                anchor="w",
                font=("Courier New", 8),
                fill="gray",
                tags=("more",),
            )
            width += 30
        self.configure(width=max(width, CHIP))  # fit the squares, no more

    def _on_motion(self, event: tk.Event) -> None:
        index, offset = divmod(event.x, CHIP + CHIP_GAP)
        if index < min(len(self._blocks), MAX_CHIPS) and offset < CHIP:
            text = f"Block {index}: {self._blocks[index].hex().upper()}"
            self._tooltip.show(event.x, event.y, text)
        else:
            self._tooltip.hide()


class ModeCard(ctk.CTkFrame):
    """One mode's ciphertext blocks, length, IV and tag."""

    def __init__(self, parent: tk.Widget, mode: AesMode, **kwargs: object) -> None:
        # The border is invisible (panel-coloured) until the card is selected.
        super().__init__(
            parent,
            fg_color=COLOUR_PANEL,
            border_width=2,
            border_color=COLOUR_PANEL,
            **kwargs,
        )
        self.mode = mode
        self.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            self,
            text=mode,
            font=ctk.CTkFont(family="Courier New", size=12, weight="bold"),
            text_color=_MODE_COLOURS[mode],
        ).grid(row=0, column=0, padx=(8, 4), pady=(6, 2), sticky="w")
        self._marker = ctk.CTkLabel(
            self, text="", font=("Courier New", 9), text_color="gray"
        )
        self._marker.grid(row=0, column=1, padx=8, pady=(6, 2), sticky="e")

        self._strip = BlockStrip(self, background=COLOUR_PANEL)
        self._strip.grid(row=1, column=0, columnspan=2, padx=8, sticky="w")

        self._info = ctk.CTkLabel(
            self, text="(no data)", font=("Courier New", 9), anchor="w"
        )
        self._info.grid(row=2, column=0, columnspan=2, padx=8, pady=(2, 6), sticky="w")

    def show(self, result: EncryptionResult, *, selected: bool) -> None:
        self._strip.show([blk.ciphertext for blk in result.blocks])
        self._info.configure(text=_summary(result))
        self._marker.configure(text="drawn above" if selected else "")
        self.configure(
            border_color=_MODE_COLOURS[self.mode] if selected else COLOUR_PANEL
        )


class ModeComparison(ctk.CTkFrame):
    """The plaintext's blocks, then one card per AES mode."""

    def __init__(self, parent: tk.Widget, **kwargs: object) -> None:
        super().__init__(parent, **kwargs)
        # "uniform": equal card widths, whatever the length of each card's text
        self.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="card")

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, columnspan=4, sticky="ew", padx=8, pady=(6, 2))
        ctk.CTkLabel(
            header,
            text="Mode Comparison — one message, one key, every mode",
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(side="left")
        plaintext = ctk.CTkFrame(header, fg_color=COLOUR_PANEL)
        plaintext.pack(side="left", padx=12)
        ctk.CTkLabel(
            plaintext, text="plaintext", font=("Courier New", 9), text_color="gray"
        ).pack(side="left", padx=(8, 4))
        self._plaintext_strip = BlockStrip(plaintext, background=COLOUR_PANEL)
        self._plaintext_strip.pack(side="left", padx=(0, 8), pady=4)
        ctk.CTkLabel(
            header,
            text="same colour = same 16-byte block",
            font=("Courier New", 9),
            text_color="gray",
        ).pack(side="left")

        self._cards: dict[AesMode, ModeCard] = {}
        for col, mode in enumerate(AesMode):
            card = ModeCard(self, mode)
            card.grid(row=1, column=col, padx=4, pady=(0, 6), sticky="nsew")
            self._cards[mode] = card

    def show(
        self,
        plaintext: bytes,
        results: Iterable[EncryptionResult],
        selected: AesMode,
    ) -> None:
        """Show *plaintext*'s blocks and each result on its mode's card."""
        self._plaintext_strip.show(
            [
                plaintext[i : i + BLOCK_SIZE]
                for i in range(0, len(plaintext), BLOCK_SIZE)
            ]
        )
        for result in results:
            self._cards[result.mode].show(result, selected=result.mode is selected)
