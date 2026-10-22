"""KeyExchangeTab: the narrated steps, the protocol plot and the comparison."""

from __future__ import annotations

import time
import tkinter as tk
from typing import Any

import customtkinter as ctk
import pytest

from gui.exchange_plot import ExchangePlot
from gui.key_exchange_tab import CURRENT_CARD_BG, KeyExchangeTab, StepCard
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


# ---------------------------------------------------------------------------
# Stepping through the story
# ---------------------------------------------------------------------------


def _cards(tab: Any) -> list[StepCard]:
    return [w for w in descendants(tab) if isinstance(w, StepCard)]


def _shown(tab: Any) -> list[int]:
    """The step numbers whose cards are on display."""
    pump(tab, 50)
    return [n for n, card in enumerate(_cards(tab), start=1) if card.winfo_ismapped()]


def _current(tab: Any) -> list[int]:
    """The step numbers whose cards are highlighted as current."""
    return [
        n
        for n, card in enumerate(_cards(tab), start=1)
        if card.cget("fg_color") == CURRENT_CARD_BG
    ]


def _press(tab: Any, key: str, widget: Any = None) -> None:
    """Send an arrow key, as Tk would to the widget with the keyboard focus."""
    target = widget or tab
    target.focus_force()
    pump(tab, 30)
    target.event_generate(key)


@pytest.mark.parametrize("protocol", ["Run DH", "Run ECDH"])
def test_a_run_starts_with_only_its_first_step(tab: Any, protocol: str) -> None:
    find_button(tab, protocol).invoke()

    assert len(_cards(tab)) == 6
    assert _shown(tab) == [1]
    assert _current(tab) == [1]


def test_next_reveals_one_step_at_a_time_and_prev_keeps_them(tab: Any) -> None:
    find_button(tab, "Run DH").invoke()
    for _ in range(3):
        find_button(tab, "Next").invoke()
    require(_shown(tab) == [1, 2, 3, 4], f"Next revealed {_shown(tab)}")

    find_button(tab, "Prev").invoke()

    assert _shown(tab) == [1, 2, 3, 4]  # step 4 stays readable
    assert _current(tab) == [3]


def test_moving_between_steps_keeps_the_same_cards(tab: Any) -> None:
    find_button(tab, "Run ECDH").invoke()
    before = _cards(tab)

    find_button(tab, "Next").invoke()
    find_button(tab, "Prev").invoke()

    assert all(a is b for a, b in zip(before, _cards(tab), strict=True))


def test_arrow_keys_step_through_the_story(tab: Any) -> None:
    find_button(tab, "Run DH").invoke()

    _press(tab, "<Right>")
    _press(tab, "<Right>")
    assert _current(tab) == [3]

    _press(tab, "<Left>")
    assert _current(tab) == [2]


def test_arrow_keys_in_a_text_field_only_move_its_cursor(tab: Any, root: Any) -> None:
    find_button(tab, "Run DH").invoke()
    entry = ctk.CTkEntry(root)
    entry.pack()
    (text_field,) = [w for w in descendants(entry) if isinstance(w, tk.Entry)]

    _press(tab, "<Right>", widget=text_field)

    assert _current(tab) == [1]


def test_arrow_keys_do_nothing_while_the_tab_is_hidden(tab: Any) -> None:
    find_button(tab, "Run DH").invoke()
    tab.pack_forget()  # as when another tab is selected

    _press(tab, "<Right>", widget=tab.winfo_toplevel())

    assert _current(tab) == [1]


@pytest.fixture
def fast_autoplay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("gui.key_exchange_tab.AUTOPLAY_MS", 10)


@pytest.mark.usefixtures("fast_autoplay")
def test_play_reveals_every_step_then_stops(tab: Any) -> None:
    find_button(tab, "Run ECDH").invoke()

    play = find_button(tab, "Play")

    play.invoke()
    # Wait for the end, not a fixed time: a slow CI runner once needed more.
    deadline = time.monotonic() + 10
    while play.cget("text") != "Play ▶":  # it stops by itself at the end
        require(time.monotonic() < deadline, "autoplay still running after 10 s")
        pump(tab, 20)

    assert _shown(tab) == [1, 2, 3, 4, 5, 6]
    assert _current(tab) == [6]


def test_pressing_prev_pauses_the_autoplay(
    tab: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("gui.key_exchange_tab.AUTOPLAY_MS", 100)
    find_button(tab, "Run DH").invoke()
    find_button(tab, "Next").invoke()  # Prev is disabled on step 1
    find_button(tab, "Play").invoke()
    require(find_button(tab, "Pause") is not None, "Play did not start")

    find_button(tab, "Prev").invoke()
    pump(tab, 400)

    assert _current(tab) == [1]
    assert _shown(tab) == [1, 2]
    assert find_button(tab, "Play").cget("text") == "Play ▶"


def test_pause_stops_the_autoplay(tab: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("gui.key_exchange_tab.AUTOPLAY_MS", 100)
    find_button(tab, "Run DH").invoke()
    find_button(tab, "Play").invoke()

    find_button(tab, "Pause").invoke()
    pump(tab, 400)

    assert _current(tab) == [1]
    assert find_button(tab, "Play").cget("text") == "Play ▶"


def test_play_at_the_end_tells_the_story_again(tab: Any) -> None:
    # At the normal pace, so no step plays while the test looks.
    find_button(tab, "Run DH").invoke()
    for _ in range(5):
        find_button(tab, "Next").invoke()

    find_button(tab, "Play").invoke()

    assert _shown(tab) == [1]  # back to the start before the first tick
    assert _current(tab) == [1]


def test_closing_the_tab_cancels_a_pending_autoplay_step(tab: Any) -> None:
    find_button(tab, "Run DH").invoke()
    pending_before = set(tab.tk.call("after", "info"))
    find_button(tab, "Play").invoke()
    autoplay = set(tab.tk.call("after", "info")) - pending_before
    require(len(autoplay) == 1, f"expected one new timer, found {autoplay}")

    tab.destroy()

    assert not autoplay & set(tab.tk.call("after", "info"))


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


@pytest.mark.parametrize(
    ("choice", "prime"),
    [
        (None, "3072-bit prime (RFC 3526 group 15)"),  # the default: like P-256
        ("2048-bit", "2048-bit prime (RFC 3526 group 14)"),
    ],
)
def test_the_dh_group_can_be_chosen(tab: Any, choice: str | None, prime: str) -> None:
    if choice is not None:
        (menu,) = [w for w in descendants(tab) if isinstance(w, ctk.CTkOptionMenu)]
        menu.set(choice)

    find_button(tab, "Run DH").invoke()

    first_card = "\n".join(_card_lines(tab)[0])
    assert prime in first_card
    title = _plot(tab).figure.axes[0].get_title()
    assert prime.split()[0] in title  # "3072-bit" or "2048-bit" in the diagram


@pytest.mark.parametrize("protocol", ["Run DH", "Run ECDH"])
def test_both_protocols_end_with_a_derived_aes_key(tab: Any, protocol: str) -> None:
    find_button(tab, protocol).invoke()

    last_card = _card_lines(tab)[-1]
    assert any("HKDF-SHA256" in line for line in last_card)
    (key_line,) = [line for line in last_card if " K = " in line]
    assert key_line.startswith("🔒")  # a shared secret: never sent


@pytest.mark.parametrize("protocol", ["Run DH", "Run ECDH"])
def test_stepping_brings_the_current_card_into_view(tab: Any, protocol: str) -> None:
    find_button(tab, protocol).invoke()
    pump(tab)
    for step in range(6):
        if step:
            find_button(tab, "Next").invoke()
            pump(tab, 100)
        cards = [w for w in descendants(tab) if isinstance(w, StepCard)]
        current, viewport = cards[step], cards[step].master.master
        require(isinstance(viewport, tk.Canvas), "the step list is not in a canvas")
        top, bottom = (
            viewport.winfo_rooty(),
            viewport.winfo_rooty() + viewport.winfo_height(),
        )

        assert top <= current.winfo_rooty(), f"step {step + 1} starts above the view"
        assert current.winfo_rooty() + current.winfo_height() <= bottom, (
            f"step {step + 1} ends below the view"
        )
        if viewport.yview()[1] < 1.0:  # the list could scroll further: it should
            # Tk scrolls in whole increments (30 px on Linux with CustomTkinter 6).
            slack = int(viewport.winfo_fpixels(viewport.cget("yscrollincrement")))
            assert current.winfo_rooty() - top <= max(slack, 1), (
                f"step {step + 1} is not at the top"
            )


def test_comparison_lists_three_security_levels(tab: Any) -> None:
    labels = {
        str(w.cget("text")) for w in descendants(tab) if isinstance(w, ctk.CTkLabel)
    }
    assert {"128-bit", "192-bit", "256-bit"} <= labels
