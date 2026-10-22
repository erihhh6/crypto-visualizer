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


class StepCard(ctk.CTkFrame):
    """A single step card in the step animator scroll frame."""

    def __init__(
        self,
        parent: tk.Widget,
        step: Step,
        highlighted: bool = False,
        **kwargs: object,
    ) -> None:
        bg = "#2C3E50" if highlighted else "#1E2533"
        super().__init__(parent, fg_color=bg, corner_radius=8, **kwargs)
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


class KeyExchangeTab(ctk.CTkFrame):
    """Key Exchange tab with step animator and protocol plot."""

    def __init__(self, parent: tk.Widget, **kwargs: object) -> None:
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._steps: tuple[Step, ...] = ()
        self._current_step: int = 0
        self._mode: str = "DH"
        # The plotted stand-in for the P-256 exchange, made with each ECDH run.
        self._toy_exchange: ToyECDH | None = None

        self._build_controls()
        self._build_main_area()
        self._build_comparison_table()

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
        self._steps = dh_steps(run_dh(group))
        self._current_step = 0
        self._mode = "DH"
        self._render_steps()
        self._plot.show_dh_flow(group)
        self._status_var.set(
            f"DH exchange: {len(self._steps)} steps. Use Next/Prev to navigate."
        )

    def _run_ecdh(self) -> None:
        self._status_var.set("Running ECDH exchange…")
        self.update_idletasks()
        self._steps = ecdh_steps(run_ecdh())
        self._toy_exchange = run_toy_ecdh()
        self._current_step = 0
        self._mode = "ECDH"
        self._render_steps()  # also plots the toy exchange
        self._status_var.set(
            f"ECDH exchange: {len(self._steps)} steps. Use Next/Prev to navigate."
        )

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

    def _render_steps(self) -> None:
        for w in self._step_scroll.winfo_children():
            w.destroy()

        for step in self._steps:
            highlighted = step.number - 1 == self._current_step
            card = StepCard(
                self._step_scroll,
                step,
                highlighted=highlighted,
            )
            card.grid(
                row=step.number - 1,
                column=0,
                sticky="ew",
                padx=4,
                pady=4,
            )

        self._prev_btn.configure(
            state="normal" if self._current_step > 0 else "disabled"
        )
        self._next_btn.configure(
            state="normal" if self._current_step < len(self._steps) - 1 else "disabled"
        )
        self._scroll_to_current()
        self._update_plot_for_step()

    def _scroll_to_current(self) -> None:
        """Scroll the step list so that the current card starts at the top."""
        cards = self._step_scroll.winfo_children()
        if not cards:
            return
        # The cards were just created: lay them out (which also updates the
        # scroll region) before measuring them, or the view stops short.
        self.update_idletasks()
        # CustomTkinter offers no public access to the scrollable frame's canvas.
        canvas = self._step_scroll._parent_canvas
        top = cards[self._current_step].winfo_y()
        # Tk rounds the view to whole scroll increments (CustomTkinter uses 30
        # pixels on Linux): round down, so the card is never cut off at the top.
        increment = int(canvas.winfo_fpixels(canvas.cget("yscrollincrement")))
        if increment > 1:
            top -= top % increment
        canvas.yview_moveto(top / max(self._step_scroll.winfo_height(), 1))

    def _prev_step(self) -> None:
        if self._current_step > 0:
            self._current_step -= 1
            self._render_steps()

    def _next_step(self) -> None:
        if self._current_step < len(self._steps) - 1:
            self._current_step += 1
            self._render_steps()

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
