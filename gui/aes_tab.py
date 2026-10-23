"""
AES Modes tab — encrypt and decrypt a message, and show how each mode works.

Layout (top-to-bottom, left-to-right):
  Row 0 : controls (input, key, mode, encrypt/decrypt buttons)
  Row 1 : block visualization (gui.block_canvas) | ECB image demo (gui.image_demo)
  Row 2 : comparison panel — all four modes side by side (gui.mode_comparison)
"""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import messagebox

import customtkinter as ctk

from gui.block_canvas import BlockPanel
from gui.image_demo import ImageDemo
from gui.mode_comparison import ModeComparison
from gui.palette import BUTTON_PRIMARY, BUTTON_SECONDARY
from modules.aes_modes import (
    AesMode,
    AuthenticationError,
    EncryptionResult,
    PaddingError,
    decrypt,
    encrypt,
    key_from_hex,
)


class AESTab(ctk.CTkFrame):
    """Full AES Modes tab widget."""

    def __init__(self, parent: tk.Widget, **kwargs: object) -> None:
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        # row 2 (comparison) is fixed height — no weight

        # The latest encryption: ciphertext, IV/tag and mode, kept for Decrypt.
        self._last_result: EncryptionResult | None = None

        self._build_controls()
        self._build_panels()

    # ------------------------------------------------------------------
    # UI builders
    # ------------------------------------------------------------------

    def _build_controls(self) -> None:
        # The inputs on top; the output and the actions below. In one row they
        # did not fit the window's minimum width, and Decrypt was cut off.
        ctrl = ctk.CTkFrame(self)
        ctrl.grid(row=0, column=0, sticky="ew", padx=6, pady=(6, 0))
        ctrl.grid_columnconfigure(1, weight=1)  # spare width goes to the text

        # Input text
        ctk.CTkLabel(ctrl, text="Plaintext:").grid(
            row=0, column=0, sticky="w", padx=(8, 2)
        )
        self._input_var = tk.StringVar(value="Hello, AES World! Crypto is fun.")
        self._input_entry = ctk.CTkEntry(
            ctrl,
            textvariable=self._input_var,
            font=("Courier New", 11),
            width=280,
        )
        self._input_entry.grid(row=0, column=1, padx=4, pady=6, sticky="ew")

        # Key field
        ctk.CTkLabel(ctrl, text="Key (hex):").grid(
            row=0, column=2, sticky="w", padx=(8, 2)
        )
        self._key_var = tk.StringVar()
        self._key_entry = ctk.CTkEntry(
            ctrl,
            textvariable=self._key_var,
            font=("Courier New", 11),
            width=200,
            placeholder_text="leave empty → random AES-128",
        )
        self._key_entry.grid(row=0, column=3, padx=(4, 8), pady=6, sticky="ew")

        # Enter in either input encrypts, like the Encrypt button.
        for entry in (self._input_entry, self._key_entry):
            for key in ("<Return>", "<KP_Enter>"):
                entry.bind(key, lambda _event: self._do_encrypt())

        # Decryption output: its own read-only field, so decrypting never
        # overwrites the plaintext the user typed.
        ctk.CTkLabel(ctrl, text="Decrypted:").grid(
            row=1, column=0, sticky="w", padx=(8, 2)
        )
        self._output_var = tk.StringVar()
        ctk.CTkEntry(
            ctrl,
            textvariable=self._output_var,
            font=("Courier New", 11),
            width=280,
            state="readonly",
        ).grid(row=1, column=1, padx=4, pady=(0, 6), sticky="ew")

        # Mode selector and buttons, under the key
        ctk.CTkLabel(ctrl, text="Mode:").grid(row=1, column=2, sticky="w", padx=(8, 2))
        actions = ctk.CTkFrame(ctrl, fg_color="transparent")
        actions.grid(row=1, column=3, sticky="w", padx=(4, 8), pady=(0, 6))

        self._mode_var = tk.StringVar(value=AesMode.ECB)
        self._mode_menu = ctk.CTkOptionMenu(
            actions,
            values=[mode.value for mode in AesMode],
            variable=self._mode_var,
            width=100,
        )
        self._mode_menu.pack(side="left")

        self._enc_btn = ctk.CTkButton(
            actions,
            text="Encrypt ▶",
            command=self._do_encrypt,
            width=110,
            fg_color=BUTTON_PRIMARY,
        )
        self._enc_btn.pack(side="left", padx=(8, 4))

        self._dec_btn = ctk.CTkButton(
            actions,
            text="◀ Decrypt",
            command=self._do_decrypt,
            width=110,
            fg_color=BUTTON_SECONDARY,
        )
        self._dec_btn.pack(side="left", padx=(4, 0))

    def _build_panels(self) -> None:
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=1, column=0, sticky="nsew", padx=6, pady=4)
        main.grid_columnconfigure(0, weight=3)
        main.grid_columnconfigure(1, weight=2)
        main.grid_rowconfigure(0, weight=1)

        self._block_panel = BlockPanel(main)
        self._block_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        ImageDemo(main).grid(row=0, column=1, sticky="nsew")

        self._comparison = ModeComparison(self)
        self._comparison.grid(row=2, column=0, sticky="ew", padx=6, pady=(0, 6))

    # ------------------------------------------------------------------
    # Crypto operations
    # ------------------------------------------------------------------

    def _encryption_key(self) -> bytes:
        """The key typed in the field, or a fresh AES-128 key written into it."""
        if not self._key_var.get().strip():
            key = os.urandom(16)
            self._key_var.set(key.hex())
            return key
        return key_from_hex(self._key_var.get())

    def _do_encrypt(self) -> None:
        plaintext = self._input_var.get().encode("utf-8")
        if not plaintext:
            messagebox.showwarning(
                "Input required", "Please enter some plaintext first."
            )
            return
        try:
            key = self._encryption_key()
        except ValueError as exc:
            messagebox.showerror("Invalid key", str(exc))
            return

        selected = AesMode(self._mode_var.get())
        self._last_result = encrypt(selected, plaintext, key)
        self._output_var.set("")  # an earlier decryption no longer applies
        self._block_panel.draw(self._last_result)
        # The selected mode's card must show the encryption drawn above, not a
        # second one with a different IV.
        results = [
            self._last_result if mode is selected else encrypt(mode, plaintext, key)
            for mode in AesMode
        ]
        self._comparison.show(plaintext, results, selected)

    def _do_decrypt(self) -> None:
        if self._last_result is None:
            messagebox.showinfo("Nothing to decrypt", "Encrypt something first.")
            return
        # Always read the key from the field so that editing it has real effect.
        if not self._key_var.get().strip():
            messagebox.showwarning(
                "Key required",
                "The key field is empty.\nEnter the hex key that was used to encrypt.",
            )
            return
        try:
            key = key_from_hex(self._key_var.get())
        except ValueError as exc:
            messagebox.showerror("Invalid key", str(exc))
            return

        try:
            plaintext = decrypt(self._last_result, key)
        except PaddingError as exc:
            # Show the garbled output so the user sees what the wrong key
            # actually produces: the educational point of the demo.
            self._output_var.set(exc.raw.decode("utf-8", errors="replace"))
            messagebox.showwarning(
                "Wrong key",
                "Padding check failed — the key is incorrect.\n\n"
                "The Decrypted field shows the garbled output\n"
                "so you can see what the wrong key produces.",
            )
            return
        except AuthenticationError:
            self._output_var.set("")
            messagebox.showerror(
                "Authentication failed (GCM)",
                "The authentication tag does not match.\n\n"
                "This means the key is wrong or the ciphertext was "
                "tampered with.\n"
                "GCM refuses to return any output at all — this is exactly\n"
                "why authenticated encryption is safer than ECB or CBC.",
            )
            return
        self._output_var.set(plaintext.decode("utf-8", errors="replace"))
