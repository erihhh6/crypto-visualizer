"""TamperTab: wrong keys and forged edits against all four modes."""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from typing import Any, NamedTuple

import customtkinter as ctk
import pytest

from gui.palette import MUTED, PANEL, TEXT
from gui.tamper_tab import WRONG_KEY_TRIALS, OutcomeCard, TamperTab
from modules.aes_modes import AesMode
from tests.gui.helpers import descendants, find_button, label_text, pump, require


@pytest.fixture
def tab(root: Any) -> Any:
    widget = TamperTab(root)
    widget.pack(fill="both", expand=True)
    pump(root)
    return widget


class _Card(NamedTuple):
    verdict: str
    received: str
    highlighted: list[int]  # positions of the characters marked as changed


def _read(card: OutcomeCard) -> _Card:
    labels = [w for w in descendants(card) if isinstance(w, ctk.CTkLabel)]
    (text,) = [w for w in descendants(card) if isinstance(w, tk.Text)]
    received = text.get("1.0", "end-1c")
    highlighted = [
        i for i in range(len(received)) if "changed" in text.tag_names(f"1.0+{i}c")
    ]
    return _Card(label_text(labels[1]), received, highlighted)


def _cards(tab: Any) -> tuple[dict[AesMode, _Card], dict[AesMode, _Card]]:
    """The wrong-key cards and the edit cards (created in that order)."""
    cards = [w for w in descendants(tab) if isinstance(w, OutcomeCard)]
    require(len(cards) == 8, f"expected 8 outcome cards, found {len(cards)}")
    return (
        {card.mode: _read(card) for card in cards[:4]},
        {card.mode: _read(card) for card in cards[4:]},
    )


def _entries(tab: Any) -> list[Any]:
    """The message, the text to replace and its replacement."""
    return [w for w in descendants(tab) if isinstance(w, ctk.CTkEntry)]


def _type(entry: Any, text: str) -> None:
    entry.delete(0, "end")
    entry.insert(0, text)


def test_the_default_edit_meets_four_different_fates(tab: Any) -> None:
    find_button(tab, "Tamper").invoke()

    _, edits = _cards(tab)
    assert edits[AesMode.ECB].verdict == "Undetected: the message is garbled"
    assert edits[AesMode.CBC].verdict == (
        "Undetected: the edit landed, other bytes garbled"
    )
    assert edits[AesMode.CTR].verdict == "Undetected: the edit landed exactly"
    assert edits[AesMode.GCM].verdict == "Refused: authentication tag mismatch"


def test_only_the_changed_characters_are_highlighted(tab: Any) -> None:
    find_button(tab, "Tamper").invoke()

    _, edits = _cards(tab)
    ctr = edits[AesMode.CTR]
    assert ctr.received == "Transfer from Alice to Bob: 999 EUR"
    start = ctr.received.index("999")
    assert ctr.highlighted == [start, start + 1, start + 2]  # just "100" → "999"
    assert edits[AesMode.GCM].highlighted == []


def test_one_wrong_key(tab: Any) -> None:
    find_button(tab, "One wrong key").invoke()

    wrong_keys, _ = _cards(tab)
    assert wrong_keys[AesMode.CTR].verdict == "Undetected: garbage accepted"
    assert wrong_keys[AesMode.CTR].highlighted  # the garbage differs from the message
    assert wrong_keys[AesMode.GCM].verdict == "Refused: authentication tag mismatch"


def test_many_wrong_keys(tab: Any) -> None:
    find_button(tab, "wrong keys").invoke()

    wrong_keys, _ = _cards(tab)
    trials = f"{WRONG_KEY_TRIALS:,}"
    assert wrong_keys[AesMode.CTR].verdict == f"{trials} of {trials} accepted"
    assert wrong_keys[AesMode.CTR].received == "every wrong key"
    assert wrong_keys[AesMode.GCM].verdict == f"0 of {trials} accepted"
    assert wrong_keys[AesMode.GCM].received == "not one"
    assert "padding predicts 1 in 255" in wrong_keys[AesMode.ECB].received


def test_the_received_text_follows_the_theme(
    tab: Any, switch_appearance: Callable[[str], None]
) -> None:
    boxes = [w for w in descendants(tab) if isinstance(w, tk.Text)]
    require(len(boxes) == 8, f"expected 8 text boxes, found {len(boxes)}")

    for mode, colour in (("Dark", 1), ("Light", 0)):
        switch_appearance(mode)
        assert {(b["background"], b["foreground"]) for b in boxes} == {
            (PANEL[colour], TEXT[colour])
        }
        assert {b.tag_cget("dim", "foreground") for b in boxes} == {MUTED[colour]}


@pytest.mark.parametrize(
    ("message", "old", "new", "dialog"),
    [
        ("Transfer from Alice to Bob: 100 EUR", "100", "9000", "as long as"),
        ("Transfer from Alice to Bob: 100 EUR", "200", "900", "does not occur"),
        ("Grüße an Bob", "Bob", "Eve", "ASCII only"),
        ("", "100", "900", "Message required"),
    ],
)
def test_impossible_requests_are_explained(
    tab: Any,
    no_dialogs: list[str],
    message: str,
    old: str,
    new: str,
    dialog: str,
) -> None:
    for entry, text in zip(_entries(tab), (message, old, new), strict=True):
        _type(entry, text)

    find_button(tab, "Tamper").invoke()

    assert len(no_dialogs) == 1
    assert dialog in no_dialogs[0]
    no_dialogs.clear()  # the explanation was the expected outcome
