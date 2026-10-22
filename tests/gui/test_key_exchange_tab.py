"""KeyExchangeTab: the narrated steps, the protocol plot and the comparison."""

from __future__ import annotations

from typing import Any

import customtkinter as ctk
import pytest

from gui.exchange_plot import ExchangePlot
from gui.key_exchange_tab import KeyExchangeTab, StepCard
from modules.key_exchange import Point
from modules.toy_curve import TOY_CURVE, TOY_GENERATOR, TOY_ORDER
from tests.gui.helpers import descendants, find_button, label_text, pump, require


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


# ---------------------------------------------------------------------------
# The plot. Each highlighted point is a scatter with a gid: "G", "QA", "QB",
# "S"; "points" is the whole curve.
# ---------------------------------------------------------------------------


def _plot(tab: Any) -> ExchangePlot:
    (plot,) = [w for w in descendants(tab) if isinstance(w, ExchangePlot)]
    return plot


def _points(scatter: Any) -> list[Point]:
    """A scatter's points (matplotlib types its offsets loosely, as ArrayLike)."""
    return [(round(x), round(y)) for x, y in scatter.get_offsets().tolist()]


def _plotted(tab: Any) -> dict[str, list[Point]]:
    """The plotted points, by gid."""
    (axes,) = _plot(tab).figure.axes
    return {str(scatter.get_gid()): _points(scatter) for scatter in axes.collections}


def test_the_plot_shows_every_point_of_the_toy_curve(tab: Any) -> None:
    plotted = _plotted(tab)

    assert sorted(plotted["points"]) == sorted(TOY_CURVE.points())
    assert plotted["G"] == [TOY_GENERATOR]


def test_ecdh_steps_reveal_g_then_qa_then_qb_then_s(tab: Any) -> None:
    find_button(tab, "Run ECDH").invoke()
    shown = [set(_plotted(tab)) - {"points"}]
    for _ in range(5):
        find_button(tab, "Next").invoke()
        shown.append(set(_plotted(tab)) - {"points"})

    everything = {"G", "QA", "QB", "S"}
    assert shown == [
        {"G"},
        {"G", "QA"},
        {"G", "QA", "QB"},
        everything,  # step 4: Alice computes S
        everything,
        everything,
    ]


def test_the_plotted_exchange_is_real_ecdh(tab: Any) -> None:
    find_button(tab, "Run ECDH").invoke()
    for _ in range(3):
        find_button(tab, "Next").invoke()
    plotted = _plotted(tab)
    (qa,), (qb,), (s,) = plotted["QA"], plotted["QB"], plotted["S"]

    # On a curve this small, Alice's private key falls to trying every multiple.
    alice_private = next(
        k for k in range(1, TOY_ORDER) if TOY_CURVE.multiply(k, TOY_GENERATOR) == qa
    )
    assert s == TOY_CURVE.multiply(alice_private, qb)


def test_dh_shows_the_message_flow_instead_of_the_curve(tab: Any) -> None:
    find_button(tab, "Run ECDH").invoke()
    require("points" in _plotted(tab), "ECDH did not plot the curve")

    find_button(tab, "Run DH").invoke()
    find_button(tab, "Next").invoke()  # stepping through DH keeps its diagram

    assert _plotted(tab) == {}
    titles = [
        label_text(w) for w in descendants(_plot(tab)) if isinstance(w, ctk.CTkLabel)
    ]
    assert any("Diffie-Hellman" in title for title in titles)


def test_comparison_lists_three_security_levels(tab: Any) -> None:
    labels = {
        str(w.cget("text")) for w in descendants(tab) if isinstance(w, ctk.CTkLabel)
    }
    assert {"128-bit", "192-bit", "256-bit"} <= labels
