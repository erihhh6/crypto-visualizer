"""KeyExchangeTab: the narrated DH/ECDH steps and the key-size comparison."""

from __future__ import annotations

from typing import Any

import customtkinter as ctk
import pytest

from gui.key_exchange_tab import KeyExchangeTab, StepCard
from tests.gui.helpers import descendants, find_button, pump


@pytest.fixture
def tab(root: Any) -> Any:
    widget = KeyExchangeTab(root)
    widget.pack(fill="both", expand=True)
    pump(root)
    return widget


def _card_lines(tab: Any) -> list[list[str]]:
    """The text of each step card's labels, cards and labels in display order."""
    cards = [w for w in descendants(tab) if isinstance(w, StepCard)]
    return [
        [str(w.cget("text")) for w in descendants(card) if isinstance(w, ctk.CTkLabel)]
        for card in cards
    ]


def _value_lines(tab: Any) -> list[str]:
    """Every "symbol = value" line across all step cards."""
    return [
        line.strip()
        for lines in _card_lines(tab)
        for line in lines
        if " = " in line and "\n" not in line
    ]


@pytest.mark.parametrize("protocol", ["Run DH", "Run ECDH"])
def test_running_a_protocol_shows_six_step_cards(tab: Any, protocol: str) -> None:
    find_button(tab, protocol).invoke()
    pump(tab)

    assert len(_card_lines(tab)) == 6


def test_dh_shows_the_public_parameters_as_public(tab: Any) -> None:
    find_button(tab, "Run DH").invoke()

    first_card = _card_lines(tab)[0]
    assert any(line.startswith("🔓 p = FFFFFFFFFFFFFFFF") for line in first_card)
    assert "🔓 g = 2" in first_card


@pytest.mark.parametrize(
    ("protocol", "private_symbols"),
    [("Run DH", {"a", "b"}), ("Run ECDH", {"dA", "dB"})],
)
def test_private_keys_are_never_shown(
    tab: Any, protocol: str, private_symbols: set[str]
) -> None:
    find_button(tab, protocol).invoke()

    lines = _value_lines(tab)
    named = {line.split(" = ")[0].split()[-1]: line for line in lines}
    for symbol in private_symbols:
        assert named[symbol].endswith(f"{symbol} = [private]")
    assert all(
        "[private]" not in line for s, line in named.items() if s not in private_symbols
    )


def test_comparison_lists_three_security_levels(tab: Any) -> None:
    labels = {
        str(w.cget("text")) for w in descendants(tab) if isinstance(w, ctk.CTkLabel)
    }
    assert {"128-bit", "192-bit", "256-bit"} <= labels
