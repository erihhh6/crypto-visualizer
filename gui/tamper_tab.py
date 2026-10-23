"""
Tamper Lab tab — what each AES mode does with a wrong key or a forged edit.

Layout:
  Row 0 : the message (ASCII, so one character is one byte)
  Row 1 : decrypt with wrong keys: one, or many to measure how often it passes
  Row 2 : change the message without the key: replace some text by XORing
Each experiment shows one card per mode: the verdict, and what the receiver
got with the changed characters highlighted.
"""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import messagebox
from typing import NamedTuple

import customtkinter as ctk

from gui.layout import wrap_to_width
from gui.palette import (
    GREEN,
    MODE_COLOURS,
    MUTED,
    ORANGE,
    PANEL,
    RED,
    TEXT,
    Colour,
    follow_appearance,
    resolve,
)
from modules.aes_modes import AesMode, encrypt
from modules.tamper import (
    PADDING_FALSE_ACCEPT_RATE,
    Outcome,
    Verdict,
    count_accepted_wrong_keys,
    judge_edit,
    receive,
    replace_without_key,
    wrong_key,
)

WRONG_KEY_TRIALS = 20_000  # about 0.4 s for all four modes

_SAFE = GREEN  # the receiver noticed
_UNSAFE = RED  # wrong data accepted without a word
_DAMAGED = ORANGE  # garbage accepted, but not the attacker's text
_CHANGED: Colour = ("#F5B7B1", "#922B21")  # behind characters that differ

_WRONG_KEY_NOTES = {
    AesMode.ECB: "Only the padding check can notice; about 1 wrong key in 255 passes.",
    AesMode.CBC: "Only the padding check can notice; about 1 wrong key in 255 passes.",
    AesMode.CTR: "Nothing to check: every key 'works'.",
    AesMode.GCM: "The authentication tag rejects every wrong key.",
}
_EDIT_NOTES = {
    AesMode.ECB: "No XOR link from ciphertext to plaintext: it scrambles a block.",
    AesMode.CBC: "XORing the block before (or the IV) flips these bits, scrambling it.",
    AesMode.CTR: "Each ciphertext bit flips the matching plaintext bit, unchecked.",
    AesMode.GCM: "The tag covers every ciphertext bit: any change is rejected.",
}
_EDIT_VERDICTS = {
    Verdict.EXACT: ("Undetected: the edit landed exactly", _UNSAFE),
    Verdict.WITH_DAMAGE: ("Undetected: the edit landed, other bytes garbled", _UNSAFE),
    Verdict.GARBLED: ("Undetected: the message is garbled", _DAMAGED),
}
_TAKEAWAY = (
    "Encryption hides a message but does not protect it: only GCM, which "
    "authenticates the ciphertext, refuses both wrong keys and edits. "
    "A padding check is not an integrity check."
)


def _shown(byte: int) -> str:
    """One character per byte: printable ASCII as is, anything else as a dot."""
    return chr(byte) if 32 <= byte < 127 else "·"


class OutcomeCard(ctk.CTkFrame):
    """One mode's result: a verdict, what the receiver got, and why."""

    def __init__(self, parent: tk.Widget, mode: AesMode, **kwargs: object) -> None:
        super().__init__(parent, fg_color=PANEL, **kwargs)
        self.mode = mode
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self,
            text=mode,
            font=ctk.CTkFont(family="Courier New", size=12, weight="bold"),
            text_color=MODE_COLOURS[mode],
        ).grid(row=0, column=0, sticky="w", padx=8, pady=(6, 0))
        self._verdict = ctk.CTkLabel(
            self,
            text="",
            font=ctk.CTkFont(size=11, weight="bold"),
            justify="left",
            anchor="w",
            wraplength=230,
        )
        self._verdict.grid(row=1, column=0, sticky="w", padx=8)
        wrap_to_width(self._verdict, margin=16)

        self._received = tk.Text(
            self,
            height=2,
            wrap="char",
            font=("Courier New", 10),
            relief="flat",
            bd=0,
            state="disabled",
            cursor="arrow",
        )
        self._received.grid(row=2, column=0, sticky="ew", padx=8, pady=2)
        # Received bytes wrap anywhere; the dimmed summaries between words.
        self._received.tag_configure("dim", wrap="word")
        follow_appearance(self._received, self._restyle_received)

        self._note = ctk.CTkLabel(
            self,
            text="",
            font=("Courier New", 9),
            text_color=MUTED,
            justify="left",
            anchor="w",
            wraplength=230,
        )
        self._note.grid(row=3, column=0, sticky="w", padx=8, pady=(0, 6))
        wrap_to_width(self._note, margin=16)

    def _restyle_received(self) -> None:
        text = self._received
        text.configure(background=resolve(PANEL), foreground=resolve(TEXT))
        text.tag_configure("changed", background=resolve(_CHANGED))
        text.tag_configure("dim", foreground=resolve(MUTED))

    def show(
        self,
        verdict: str,
        colour: Colour,
        note: str,
        received: bytes | None = None,
        original: bytes = b"",
        summary: str = "",
    ) -> None:
        """
        Show a verdict. The text area shows *received*, with the bytes that
        differ from *original* highlighted, or else *summary*, dimmed.
        """
        self._verdict.configure(text=verdict, text_color=colour)
        self._note.configure(text=note)
        text = self._received
        text.configure(state="normal")
        text.delete("1.0", "end")
        if received is None:
            text.insert("end", summary, "dim")
        else:
            for i, byte in enumerate(received):
                changed = i >= len(original) or byte != original[i]
                text.insert("end", _shown(byte), "changed" if changed else ())
        text.configure(state="disabled")


class _Section(NamedTuple):
    header: ctk.CTkFrame  # title row, where the section's controls go
    cards: dict[AesMode, OutcomeCard]


class TamperTab(ctk.CTkFrame):
    """Wrong keys and forged edits, tried against all four modes."""

    def __init__(self, parent: tk.Widget, **kwargs: object) -> None:
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        # The lab is taller than the smallest window: there, it scrolls.
        self._body = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self._body.grid(row=0, column=0, sticky="nsew")
        self._body.grid_columnconfigure(0, weight=1)

        controls = ctk.CTkFrame(self._body)
        controls.grid(row=0, column=0, sticky="ew", padx=6, pady=(6, 4))
        controls.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(controls, text="Message:").grid(row=0, column=0, padx=(8, 4))
        self._message = tk.StringVar(value="Transfer from Alice to Bob: 100 EUR")
        ctk.CTkEntry(
            controls, textvariable=self._message, font=("Courier New", 11)
        ).grid(row=0, column=1, sticky="ew", padx=4, pady=6)
        ctk.CTkLabel(
            controls,
            text="Each run encrypts it under a fresh random AES-128 key.",
            font=("Courier New", 9),
            text_color=MUTED,
        ).grid(row=0, column=2, padx=(4, 8))

        wrong = self._section(
            1,
            "Decrypt with the wrong key",
            "What does the receiver get?",
        )
        ctk.CTkButton(
            wrong.header, text="One wrong key", width=120, command=self._try_one_key
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            wrong.header,
            text=f"{WRONG_KEY_TRIALS:,} wrong keys",
            width=140,
            command=self._try_many_keys,
        ).pack(side="left", padx=4)

        edit = self._section(
            2,
            "Change the message without the key",
            "The attacker knows where the text is, not the key.",
        )
        ctk.CTkLabel(edit.header, text="Replace").pack(side="left", padx=(8, 4))
        self._old = tk.StringVar(value="100")
        old_entry = ctk.CTkEntry(edit.header, textvariable=self._old, width=80)
        old_entry.pack(side="left")
        ctk.CTkLabel(edit.header, text="with").pack(side="left", padx=4)
        # Every character changes: ECB's garbage then matches the edit by
        # chance once in 16.7 million runs. With "900" (one changed byte) it
        # was once in 256, and ECB sometimes seemed to accept the edit.
        self._new = tk.StringVar(value="999")
        new_entry = ctk.CTkEntry(edit.header, textvariable=self._new, width=80)
        new_entry.pack(side="left")
        ctk.CTkButton(
            edit.header, text="Tamper ▶", width=100, command=self._tamper
        ).pack(side="left", padx=8)
        # Enter in either field makes the edit, like the Tamper button.
        for entry in (old_entry, new_entry):
            for key in ("<Return>", "<KP_Enter>"):
                entry.bind(key, lambda _event: self._tamper())

        self._wrong_key_cards = wrong.cards
        self._edit_cards = edit.cards

        takeaway = ctk.CTkLabel(
            self._body,
            text=_TAKEAWAY,
            font=ctk.CTkFont(size=12),
            justify="left",
            anchor="w",
            wraplength=900,
        )
        takeaway.grid(row=3, column=0, sticky="w", padx=14, pady=(8, 6))
        wrap_to_width(takeaway, margin=28)

    def _section(self, row: int, title: str, hint: str) -> _Section:
        frame = ctk.CTkFrame(self._body)
        frame.grid(row=row, column=0, sticky="ew", padx=6, pady=4)
        frame.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="card")

        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.grid(row=0, column=0, columnspan=4, sticky="ew", padx=8, pady=(6, 0))
        ctk.CTkLabel(header, text=title, font=ctk.CTkFont(size=13, weight="bold")).pack(
            side="left", padx=(0, 8)
        )
        # On a line of its own: beside the controls, it left the Tamper button
        # no room in a small window.
        ctk.CTkLabel(frame, text=hint, font=("Courier New", 9), text_color=MUTED).grid(
            row=1, column=0, columnspan=4, sticky="w", padx=8, pady=(0, 4)
        )

        cards = {}
        for col, mode in enumerate(AesMode):
            card = OutcomeCard(frame, mode)
            card.grid(row=2, column=col, sticky="nsew", padx=4, pady=(0, 6))
            cards[mode] = card
        return _Section(header, cards)

    # ------------------------------------------------------------------
    # Experiments
    # ------------------------------------------------------------------

    def _plaintext(self) -> bytes | None:
        """The message as bytes, or None (after explaining) if it cannot be used."""
        text = self._message.get()
        if not text:
            messagebox.showwarning("Message required", "Please enter a message first.")
            return None
        if not text.isascii():
            messagebox.showerror(
                "ASCII only",
                "The lab needs plain ASCII text, so that every character\n"
                "is one byte and the edits line up with the ciphertext.",
            )
            return None
        return text.encode("ascii")

    def _try_one_key(self) -> None:
        plaintext = self._plaintext()
        if plaintext is None:
            return
        key = os.urandom(16)
        for mode, card in self._wrong_key_cards.items():
            outcome = receive(encrypt(mode, plaintext, key), wrong_key(key))
            self._show_wrong_key(card, outcome, plaintext)

    @staticmethod
    def _show_wrong_key(card: OutcomeCard, outcome: Outcome, original: bytes) -> None:
        note = _WRONG_KEY_NOTES[card.mode]
        if outcome.accepted:
            verdict = "Undetected: garbage accepted"
            card.show(verdict, _UNSAFE, note, outcome.plaintext, original)
        else:
            card.show(
                f"Refused: {outcome.refusal}",
                _SAFE,
                note,
                summary="(nothing: decryption refused)",
            )

    def _try_many_keys(self) -> None:
        plaintext = self._plaintext()
        if plaintext is None:
            return
        key = os.urandom(16)
        expected = round(1 / PADDING_FALSE_ACCEPT_RATE)
        for mode, card in self._wrong_key_cards.items():
            accepted = count_accepted_wrong_keys(
                encrypt(mode, plaintext, key), key, WRONG_KEY_TRIALS
            )
            if accepted == WRONG_KEY_TRIALS:
                rate = "every wrong key"
            elif accepted:
                rate = f"1 in {WRONG_KEY_TRIALS / accepted:,.0f}"
            else:
                rate = "not one"
            if mode.pads:
                rate += f" (padding predicts 1 in {expected})"
            card.show(
                f"{accepted:,} of {WRONG_KEY_TRIALS:,} accepted",
                _UNSAFE if accepted else _SAFE,
                _WRONG_KEY_NOTES[mode],
                summary=rate,
            )

    def _tamper(self) -> None:
        plaintext = self._plaintext()
        if plaintext is None:
            return
        old, new = self._old.get(), self._new.get()
        if not (old.isascii() and new.isascii()):
            messagebox.showerror("ASCII only", "Use plain ASCII text for the edit.")
            return
        old_bytes, new_bytes = old.encode("ascii"), new.encode("ascii")
        key = os.urandom(16)
        for mode, card in self._edit_cards.items():
            try:
                forged = replace_without_key(
                    encrypt(mode, plaintext, key), plaintext, old_bytes, new_bytes
                )
            except ValueError as exc:
                messagebox.showerror(
                    "Cannot make this edit", str(exc).capitalize() + "."
                )
                return
            outcome = receive(forged, key)
            wanted = plaintext.replace(old_bytes, new_bytes, 1)
            verdict = judge_edit(outcome, plaintext, wanted)
            if verdict is Verdict.REFUSED:
                card.show(
                    f"Refused: {outcome.refusal}",
                    _SAFE,
                    _EDIT_NOTES[mode],
                    summary="(nothing: decryption refused)",
                )
            else:
                text, colour = _EDIT_VERDICTS[verdict]
                card.show(text, colour, _EDIT_NOTES[mode], outcome.plaintext, plaintext)
