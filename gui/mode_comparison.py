"""Mode comparison: the same plaintext's ciphertext under every AES mode."""

from __future__ import annotations

import tkinter as tk
from collections.abc import Iterable

import customtkinter as ctk

from gui.palette import COLOUR_PANEL
from modules.aes_modes import AesMode, EncryptionResult


class ModeComparison(ctk.CTkFrame):
    """One card per AES mode, side by side, showing the ciphertext it produced."""

    def __init__(self, parent: tk.Widget, **kwargs: object) -> None:
        super().__init__(parent, **kwargs)
        self.grid_columnconfigure((0, 1, 2, 3), weight=1)

        ctk.CTkLabel(
            self,
            text="Mode Comparison — same plaintext, different modes:",
            font=ctk.CTkFont(size=12, weight="bold"),
        ).grid(row=0, column=0, columnspan=4, sticky="w", padx=8, pady=(6, 2))

        self._vars: dict[AesMode, tk.StringVar] = {}
        for col, mode in enumerate(AesMode):
            f = ctk.CTkFrame(self, fg_color=COLOUR_PANEL)
            f.grid(row=1, column=col, padx=4, pady=(0, 6), sticky="nsew")
            f.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(
                f,
                text=mode,
                font=ctk.CTkFont(family="Courier New", size=12, weight="bold"),
                text_color={
                    AesMode.ECB: "#E07B39",
                    AesMode.CBC: "#5B9BD5",
                    AesMode.CTR: "#5BAD72",
                    AesMode.GCM: "#9B59B6",
                }[mode],
            ).grid(row=0, column=0, padx=6, pady=(6, 2), sticky="w")

            var = tk.StringVar(value="(no data)")
            self._vars[mode] = var
            ctk.CTkLabel(
                f,
                textvariable=var,
                font=("Courier New", 9),
                justify="left",
                anchor="nw",
                wraplength=220,
            ).grid(row=1, column=0, padx=6, pady=(0, 6), sticky="w")

    def show(self, results: Iterable[EncryptionResult]) -> None:
        """Show each result's ciphertext on its mode's card."""
        for result in results:
            ct_hex = result.ciphertext.hex().upper()
            self._vars[result.mode].set(ct_hex[:64] + ("…" if len(ct_hex) > 64 else ""))
