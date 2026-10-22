"""
Key Exchange tab — step-by-step DH/ECDH animator with a protocol plot.

Layout:
  Row 0 : control buttons  [DH] [group size] [ECDH] [Compare]
  Row 1 : step animator (left) | DH flow or toy-curve plot (gui.exchange_plot)
  Row 2 : DH vs ECDH comparison table
"""

from __future__ import annotations

import tkinter as tk

import customtkinter as ctk

from gui.exchange_plot import ExchangePlot
from gui.palette import ACTOR_COLOURS, VALUE_COLOURS
from modules.key_exchange import (
    EQUIVALENT_KEY_SIZES,
    MODP_2048,
    MODP_3072,
    RawValue,
    Step,
    Value,
    Visibility,
    dh_steps,
    ecdh_steps,
    run_dh,
    run_ecdh,
)
from modules.toy_curve import ToyECDH, run_toy_ecdh


def _shorten(hex_text: str, max_chars: int) -> str:
    """Keep the first and last characters of a long hex string."""
    if len(hex_text) <= max_chars:
        return hex_text
    half = max_chars // 2
    return hex_text[:half] + "…" + hex_text[-half:]


def _format(value: RawValue) -> str:
    match value:
        case str():
            return value
        case bytes():
            return _shorten(value.hex().upper(), 32)
        case int():
            return _shorten(format(value, "X"), 32)
        case (x, y):
            return f"({_shorten(format(x, 'X'), 16)}, {_shorten(format(y, 'X'), 16)})"


def _value_line(item: Value) -> str:
    """One line of a step card; private keys are never shown, even in a demo."""
    if item.visibility is Visibility.PRIVATE:
        return f"   {item.symbol} = [private]"
    icon = "🔓" if item.visibility is Visibility.PUBLIC else "🔒"
    return f"{icon} {item.symbol} = {_format(item.value)}"


CARD_BG = "#1E2533"
CURRENT_CARD_BG = "#2C3E50"
AUTOPLAY_MS = 1500  # time on each step when playing


class StepCard(ctk.CTkFrame):
    """A single step card in the step animator scroll frame."""

    def __init__(self, parent: tk.Widget, step: Step, **kwargs: object) -> None:
        super().__init__(parent, fg_color=CARD_BG, corner_radius=8, **kwargs)
        self.grid_columnconfigure(1, weight=1)

        actor_col = ACTOR_COLOURS[step.actor]

        # Step number badge
        badge = ctk.CTkLabel(
            self,
            text=f"{step.number}",
            font=ctk.CTkFont(family="Courier New", size=16, weight="bold"),
            fg_color=actor_col,
            text_color="white",
            corner_radius=20,
            width=36,
            height=36,
        )
        badge.grid(row=0, column=0, rowspan=3, padx=(10, 8), pady=10, sticky="n")

        # Actor label
        ctk.CTkLabel(
            self,
            text=step.actor,
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=actor_col,
        ).grid(row=0, column=1, sticky="w", padx=4, pady=(8, 0))

        # Description
        ctk.CTkLabel(
            self,
            text=step.description,
            font=("Courier New", 10),
            justify="left",
            anchor="nw",
            wraplength=300,
        ).grid(row=1, column=1, sticky="w", padx=4, pady=2)

        # The values this step produces, coloured by who may know them
        for row, item in enumerate(step.values, start=2):
            last = row == len(step.values) + 1
            ctk.CTkLabel(
                self,
                text=_value_line(item),
                font=("Courier New", 9),
                text_color=VALUE_COLOURS[item.visibility],
                justify="left",
                wraplength=300,
            ).grid(row=row, column=1, sticky="w", padx=4, pady=(0, 8 if last else 2))

    def set_current(self, current: bool) -> None:
        """Highlight the card while its step is the current one."""
        self.configure(fg_color=CURRENT_CARD_BG if current else CARD_BG)


class KeyExchangeTab(ctk.CTkFrame):
    """Key Exchange tab with step animator and protocol plot."""

    def __init__(self, parent: tk.Widget, **kwargs: object) -> None:
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._steps: tuple[Step, ...] = ()
        # One card per step, made once per run; cards after the furthest step
        # reached so far stay hidden, so the story unfolds one step at a time.
        self._cards: list[StepCard] = []
        self._current_step: int = 0
        self._furthest_step: int = 0
        self._mode: str = "DH"
        self._autoplay_job: str | None = None
        # The plotted stand-in for the P-256 exchange, made with each ECDH run.
        self._toy_exchange: ToyECDH | None = None

        self._build_controls()
        self._build_main_area()
        self._build_comparison_table()

        # ←/→ step through the exchange. Bound on the window, not this frame,
        # since a frame never has the keyboard focus; _on_arrow ignores keys
        # meant for other tabs or text fields.
        for key in ("<Left>", "<Right>"):
            self.winfo_toplevel().bind(key, self._on_arrow, add="+")

    # ------------------------------------------------------------------
    # UI builders
    # ------------------------------------------------------------------

    def _build_controls(self) -> None:
        ctrl = ctk.CTkFrame(self, fg_color="transparent")
        ctrl.grid(row=0, column=0, sticky="ew", padx=6, pady=(6, 2))

        self._dh_btn = ctk.CTkButton(
            ctrl,
            text="Run DH",
            command=self._run_dh,
            width=90,
            fg_color="#2E86AB",
        )
        self._dh_btn.pack(side="left", padx=(0, 4))

        # 3072-bit first: it matches P-256's 128-bit security.
        self._dh_groups = {f"{g.bits}-bit": g for g in (MODP_3072, MODP_2048)}
        self._dh_group_var = tk.StringVar(value=next(iter(self._dh_groups)))
        ctk.CTkOptionMenu(
            ctrl,
            values=list(self._dh_groups),
            variable=self._dh_group_var,
            width=100,
        ).pack(side="left", padx=(0, 12))

        self._ecdh_btn = ctk.CTkButton(
            ctrl,
            text="Run ECDH (P-256)",
            command=self._run_ecdh,
            width=160,
            fg_color="#5C6BC0",
        )
        self._ecdh_btn.pack(side="left", padx=(0, 8))

        self._cmp_btn = ctk.CTkButton(
            ctrl,
            text="Show Comparison ▼",
            command=self._show_comparison,
            width=160,
            fg_color="#555",
        )
        self._cmp_btn.pack(side="left")

        self._status_var = tk.StringVar(value="Choose a protocol above to begin.")
        ctk.CTkLabel(
            ctrl,
            textvariable=self._status_var,
            font=("Courier New", 10),
            text_color="gray",
        ).pack(side="left", padx=16)

    def _build_main_area(self) -> None:
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=1, column=0, sticky="nsew", padx=6, pady=4)
        main.grid_columnconfigure(0, weight=2)
        main.grid_columnconfigure(1, weight=3)
        main.grid_rowconfigure(0, weight=1)

        # -------- Left: step animator --------
        left = ctk.CTkFrame(main)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(left, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=8, pady=(6, 2))
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr,
            text="Step-by-Step Animator",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).grid(row=0, column=0, sticky="w")

        # Navigation buttons
        nav = ctk.CTkFrame(hdr, fg_color="transparent")
        nav.grid(row=0, column=1, sticky="e")

        self._play_btn = ctk.CTkButton(
            nav,
            text="Play ▶",
            command=self._toggle_autoplay,
            width=80,
            state="disabled",
            fg_color="#555",
        )
        self._play_btn.pack(side="left", padx=(2, 8))

        self._prev_btn = ctk.CTkButton(
            nav,
            text="← Prev",
            command=self._prev_step,
            width=80,
            state="disabled",
        )
        self._prev_btn.pack(side="left", padx=2)

        self._next_btn = ctk.CTkButton(
            nav,
            text="Next →",
            command=self._next_step,
            width=80,
            state="disabled",
        )
        self._next_btn.pack(side="left", padx=2)

        # Scrollable step list
        self._step_scroll = ctk.CTkScrollableFrame(left, fg_color="transparent")
        self._step_scroll.grid(row=1, column=0, sticky="nsew", padx=4, pady=(0, 4))
        self._step_scroll.grid_columnconfigure(0, weight=1)

        # -------- Right: protocol plot --------
        self._plot = ExchangePlot(main)
        self._plot.grid(row=0, column=1, sticky="nsew")

    def _build_comparison_table(self) -> None:
        comp = ctk.CTkFrame(self)
        comp.grid(row=2, column=0, sticky="ew", padx=6, pady=(0, 6))
        comp.grid_columnconfigure((1, 2, 3), weight=1)

        self._comp_frame = comp

        # Hidden until the user asks for it — the button toggles visibility
        comp.grid_remove()
        self._comp_visible = False

        headers = ["Security Level", "DH / RSA key size", "ECDH key size", "Size ratio"]
        for col, h in enumerate(headers):
            ctk.CTkLabel(
                comp,
                text=h,
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color="gray",
            ).grid(row=0, column=col, padx=12, pady=(6, 2), sticky="w")

        for row, level in enumerate(EQUIVALENT_KEY_SIZES, start=1):
            ratio = level.ffdh_bits // level.ecdh_bits
            ctk.CTkLabel(
                comp, text=f"{level.security_bits}-bit", font=("Courier New", 10)
            ).grid(row=row, column=0, padx=12, pady=2, sticky="w")
            ctk.CTkLabel(
                comp,
                text=f"{level.ffdh_bits:,} bits",
                font=("Courier New", 10),
                text_color="#E07B39",
            ).grid(row=row, column=1, padx=12, pady=2, sticky="w")
            ctk.CTkLabel(
                comp,
                text=f"{level.ecdh_bits} bits",
                font=("Courier New", 10),
                text_color="#5BAD72",
            ).grid(row=row, column=2, padx=12, pady=2, sticky="w")
            ctk.CTkLabel(
                comp,
                text=f"ECDH is ~{ratio}× smaller",
                font=("Courier New", 10),
                text_color="gray",
            ).grid(row=row, column=3, padx=12, pady=2, sticky="w")

    # ------------------------------------------------------------------
    # Protocol runners
    # ------------------------------------------------------------------

    def _run_dh(self) -> None:
        self._status_var.set("Running DH exchange…")
        self.update_idletasks()
        group = self._dh_groups[self._dh_group_var.get()]
        self._mode = "DH"
        self._start(dh_steps(run_dh(group)))
        self._plot.show_dh_flow(group)

    def _run_ecdh(self) -> None:
        self._status_var.set("Running ECDH exchange…")
        self.update_idletasks()
        self._toy_exchange = run_toy_ecdh()
        self._mode = "ECDH"
        self._start(ecdh_steps(run_ecdh()))  # also plots the toy exchange

    def _show_comparison(self) -> None:
        if self._comp_visible:
            self._comp_frame.grid_remove()
            self._comp_visible = False
            self._cmp_btn.configure(text="Show Comparison ▼")
        else:
            self._comp_frame.grid()
            self._comp_visible = True
            self._cmp_btn.configure(text="Hide Comparison ▲")

    # ------------------------------------------------------------------
    # Step rendering
    # ------------------------------------------------------------------

    def _start(self, steps: tuple[Step, ...]) -> None:
        """Show a new exchange: its cards are made once, then only step 1 shows."""
        self._stop_autoplay()
        for card in self._cards:
            card.destroy()
        self._steps = steps
        self._cards = [StepCard(self._step_scroll, step) for step in steps]
        self._rewind()
        self._play_btn.configure(state="normal")

    def _rewind(self) -> None:
        """Hide every card but the first and make step 1 current."""
        for row, card in enumerate(self._cards):
            card.grid(row=row, column=0, sticky="ew", padx=4, pady=4)
            card.set_current(False)
            if row:
                card.grid_remove()  # grid() later restores these options
        self._current_step = self._furthest_step = 0
        self._go_to(0)

    def _go_to(self, index: int) -> None:
        """Make step *index* current, revealing it and every step before it."""
        self._cards[self._current_step].set_current(False)
        for card in self._cards[self._furthest_step + 1 : index + 1]:
            card.grid()
        self._furthest_step = max(self._furthest_step, index)
        self._current_step = index
        self._cards[index].set_current(True)

        last = len(self._cards) - 1
        self._prev_btn.configure(state="normal" if index > 0 else "disabled")
        self._next_btn.configure(state="normal" if index < last else "disabled")
        self._status_var.set(
            f"{self._mode} exchange: step {index + 1} of {last + 1}. "
            "Next/Prev or ←/→, or Play."
        )
        self._scroll_to_current()
        self._update_plot_for_step()

    def _scroll_to_current(self) -> None:
        """Scroll the step list so that the current card starts at the top."""
        if not self._cards:
            return
        # A card may just have been shown: lay it out (which also updates the
        # scroll region) before measuring, or the view stops short.
        self.update_idletasks()
        # CustomTkinter offers no public access to the scrollable frame's canvas.
        canvas = self._step_scroll._parent_canvas
        top = self._cards[self._current_step].winfo_y()
        # Tk rounds the view to whole scroll increments (CustomTkinter uses 30
        # pixels on Linux): round down, so the card is never cut off at the top.
        increment = int(canvas.winfo_fpixels(canvas.cget("yscrollincrement")))
        if increment > 1:
            top -= top % increment
        canvas.yview_moveto(top / max(self._step_scroll.winfo_height(), 1))

    # ------------------------------------------------------------------
    # Navigation: buttons, arrow keys and autoplay
    # ------------------------------------------------------------------

    def _prev_step(self) -> None:
        self._stop_autoplay()  # the user takes over
        if self._current_step > 0:
            self._go_to(self._current_step - 1)

    def _next_step(self) -> None:
        self._stop_autoplay()
        if self._current_step < len(self._cards) - 1:
            self._go_to(self._current_step + 1)

    def _on_arrow(self, event: tk.Event) -> None:
        """←/→ step through the exchange, unless the keys are meant elsewhere."""
        if not self._cards or not (self.winfo_exists() and self.winfo_ismapped()):
            return  # no exchange yet, or another tab is showing
        if isinstance(event.widget, tk.Entry | tk.Text):
            return  # the user is moving a text cursor
        if event.keysym == "Left":
            self._prev_step()
        else:
            self._next_step()

    def _toggle_autoplay(self) -> None:
        if self._autoplay_job is not None:
            self._stop_autoplay()
            return
        if self._current_step == len(self._cards) - 1:
            self._rewind()  # at the end: play the story again from the start
        self._play_btn.configure(text="Pause")
        self._autoplay_job = self.after(AUTOPLAY_MS, self._autoplay_tick)

    def _autoplay_tick(self) -> None:
        self._go_to(self._current_step + 1)
        if self._current_step < len(self._cards) - 1:
            self._autoplay_job = self.after(AUTOPLAY_MS, self._autoplay_tick)
        else:
            self._autoplay_job = None
            self._play_btn.configure(text="Play ▶")

    def _stop_autoplay(self) -> None:
        if self._autoplay_job is not None:
            self.after_cancel(self._autoplay_job)
            self._autoplay_job = None
        self._play_btn.configure(text="Play ▶")

    def destroy(self) -> None:
        self._stop_autoplay()  # a pending step would run on destroyed widgets
        super().destroy()

    # ------------------------------------------------------------------
    # Plot
    # ------------------------------------------------------------------

    def _update_plot_for_step(self) -> None:
        """Highlight the toy exchange's points as the ECDH steps reach them."""
        if self._mode != "ECDH" or self._toy_exchange is None:
            return
        # Step 1 brings G, step 2 QA, step 3 QB, and steps 4 to 6 the shared S.
        revealed = min(self._current_step + 1, 4)
        self._plot.show_curve(self._toy_exchange, revealed=revealed)
