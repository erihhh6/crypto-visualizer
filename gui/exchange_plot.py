"""
The key-exchange plot: the DH message flow, or ECDH on a toy curve.

P-256 cannot be drawn, so the plot replays ECDH on a curve of the same shape
over a field of 97 elements (modules.toy_curve), where every point fits.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable

import customtkinter as ctk
from matplotlib.axes import Axes
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from matplotlib.patches import Rectangle

from gui.palette import (
    ACTOR_COLOURS,
    BLUE,
    FILL_BLUE,
    FILL_ORANGE,
    FILL_PURPLE,
    FILL_RED,
    GREEN,
    LINE,
    MUTED,
    RED,
    SURFACE,
    TEXT,
    Colour,
    follow_appearance,
    resolve,
)
from modules.key_exchange import Actor, DHGroup, Point
from modules.toy_curve import TOY_CURVE, TOY_GENERATOR, TOY_ORDER, ToyECDH

_POINT: Colour = ("#7D8394", "#6C7A93")  # the curve's points: 3:1 on SURFACE


class ExchangePlot(ctk.CTkFrame):
    """A titled matplotlib figure showing the protocol being run."""

    def __init__(self, parent: tk.Widget, **kwargs: object) -> None:
        super().__init__(parent, **kwargs)
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._title = ctk.CTkLabel(
            self, text="", font=ctk.CTkFont(size=13, weight="bold")
        )
        self._title.grid(row=0, column=0, sticky="w", padx=8, pady=(6, 0))

        # A bare Figure, not pyplot: pyplot attaches its figures to a hidden Tk
        # root of its own, which kept mainloop() running after the window closed.
        # A small size to ask for: the plot stretches to fill its column anyway,
        # and asking for 500 pixels starved the step list in a small window.
        self._figure = Figure(figsize=(3, 3))
        self._figure.subplots_adjust(left=0.1, right=0.97, top=0.92, bottom=0.27)
        self._ax = self._figure.add_subplot()
        self._footnote = self._figure.text(
            0.5, 0.02, "", ha="center", va="bottom", fontsize=7
        )
        # Not "_canvas": CTkFrame keeps its own background canvas under that name.
        self._mpl_canvas = FigureCanvasTkAgg(self._figure, master=self)
        self._mpl_canvas.get_tk_widget().grid(
            row=1, column=0, sticky="nsew", padx=4, pady=4
        )

        # Repaints the current view, in the current light/dark colours.
        self._redraw: Callable[[], None] = self._draw_curve
        follow_appearance(self._mpl_canvas.get_tk_widget(), lambda: self._redraw())

    @property
    def figure(self) -> Figure:
        return self._figure

    def show_curve(self, exchange: ToyECDH | None = None, revealed: int = 1) -> None:
        """
        Plot every point of the toy curve and highlight the exchange's points.

        *revealed* is how many of G, QA, QB and S to highlight, in that order,
        so the plot can follow the steps. Without an exchange only G exists.
        """
        self._redraw = lambda: self._draw_curve(exchange, revealed)
        self._redraw()

    def show_dh_flow(self, group: DHGroup) -> None:
        """Show what Alice and Bob send each other in classical DH."""
        self._redraw = lambda: self._draw_dh_flow(group)
        self._redraw()

    def _draw_curve(self, exchange: ToyECDH | None = None, revealed: int = 1) -> None:
        self._title.configure(text="ECDH on a toy curve: every point plotted")
        ax = self._clear()

        points = TOY_CURVE.points()
        ax.scatter(
            [x for x, _ in points],
            [y for _, y in points],
            s=10,
            color=resolve(_POINT),
            label=f"its {len(points)} points (and one at infinity)",
            gid="points",
            zorder=2,
        )
        # (point, name, legend text, marker fill, label colour)
        highlights: list[tuple[Point, str, str, str, Colour]] = [
            (
                TOY_GENERATOR,
                "G",
                "G, the generator",
                FILL_PURPLE,
                ACTOR_COLOURS[Actor.SYSTEM],
            )
        ]
        if exchange is not None:
            highlights += [
                (
                    exchange.alice_public,
                    "QA",
                    "QA = dA × G",
                    FILL_BLUE,
                    ACTOR_COLOURS[Actor.ALICE],
                ),
                (
                    exchange.bob_public,
                    "QB",
                    "QB = dB × G",
                    FILL_ORANGE,
                    ACTOR_COLOURS[Actor.BOB],
                ),
                (exchange.shared_point, "S", "S = dA × QB = dB × QA", FILL_RED, RED),
            ]
        for (x, y), name, description, fill, ink in highlights[:revealed]:
            ax.scatter(
                [x],
                [y],
                s=90,
                color=fill,
                edgecolors="white",
                linewidths=0.8,
                label=description,
                gid=name,
                zorder=4,
            )
            ax.annotate(
                name,
                (x, y),
                xytext=(6, 5),
                textcoords="offset points",
                color=resolve(ink),
                fontsize=9,
                fontweight="bold",
            )

        p = TOY_CURVE.p
        ax.set_title(
            f"y² = x³ − 3x + {TOY_CURVE.b}  (mod {p}), the shape of P-256",
            color=resolve(TEXT),
            fontsize=9,
        )
        ax.set_xlim(-3, p + 2)
        ax.set_ylim(-3, p + 2)
        ax.set_aspect("equal", adjustable="box")
        ax.legend(
            loc="upper center",
            bbox_to_anchor=(0.5, -0.08),
            ncol=2,
            fontsize=7,
            facecolor=resolve(SURFACE),
            edgecolor=resolve(LINE),
            labelcolor=resolve(MUTED),
        )
        self._footnote.set_text(
            f"With only {TOY_ORDER} points, anyone finds dA from QA by trying every "
            "multiple of G.\nP-256 has about 2²⁵⁶ points: the same search is hopeless."
        )
        self._mpl_canvas.draw()

    def _draw_dh_flow(self, group: DHGroup) -> None:
        self._title.configure(text="Diffie-Hellman: what crosses the wire")
        ax = self._clear()
        ax.set_xlim(0, 10)
        ax.set_ylim(0, 6)
        ax.set_axis_off()
        ax.set_title(
            f"DH Key Exchange — {group.bits}-bit MODP ({group.name})",
            color=resolve(TEXT),
            fontsize=9,
        )

        for x, name, fill in ((0.5, "Alice", FILL_BLUE), (7.5, "Bob", FILL_ORANGE)):
            ax.add_patch(Rectangle((x, 2), 2, 2, color=fill, zorder=2))
            ax.text(
                x + 1,
                3,
                name,
                ha="center",
                va="center",
                color="white",
                fontsize=11,
                fontweight="bold",
            )

        # A to Bob above, B to Alice below
        for y_arrow, y_text, start, end, text, colour in (
            (3.4, 3.6, 2.5, 7.5, "A = g^a mod p", resolve(GREEN)),
            (2.6, 2.3, 7.5, 2.5, "B = g^b mod p", resolve(BLUE)),
        ):
            ax.annotate(
                "",
                xy=(end, y_arrow),
                xytext=(start, y_arrow),
                arrowprops={"arrowstyle": "->", "color": colour, "lw": 2},
            )
            ax.text(5, y_text, text, ha="center", color=colour, fontsize=8)

        muted = resolve(MUTED)
        ax.text(1.5, 1.5, "s = B^a mod p", ha="center", color=muted, fontsize=7)
        ax.text(8.5, 1.5, "s = A^b mod p", ha="center", color=muted, fontsize=7)
        ax.text(
            5,
            0.7,
            "Both arrive at the same s, and HKDF turns it into the AES key K",
            ha="center",
            color=resolve(GREEN),
            fontsize=9,
        )
        self._footnote.set_text("Only A and B are sent; a, b and the secret never are.")
        self._mpl_canvas.draw()

    def _clear(self) -> Axes:
        """An empty plot area in the current light/dark colours."""
        background, line = resolve(SURFACE), resolve(LINE)
        self._figure.patch.set_facecolor(background)
        self._footnote.set_color(resolve(MUTED))
        ax = self._ax
        ax.clear()
        ax.set_axis_on()
        ax.set_aspect("auto")
        ax.set_facecolor(background)
        ax.tick_params(colors=line, labelsize=7)
        for spine in ax.spines.values():
            spine.set_edgecolor(line)
        return ax
