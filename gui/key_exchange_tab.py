"""
Key Exchange tab — step-by-step DH/ECDH animator with matplotlib curve plot.

Layout:
  Row 0 : control buttons  [DH] [ECDH] [Compare]
  Row 1 : step animator (left) | elliptic curve plot (right)
  Row 2 : DH vs ECDH comparison table
"""

from __future__ import annotations

import tkinter as tk

import customtkinter as ctk
import matplotlib
import numpy as np

matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from modules.key_exchange import (
    DHStep,
    compare_dh_ecdh,
    run_dh_exchange,
    run_ecdh_exchange,
)

# ---------------------------------------------------------------------------
# Actor colours
# ---------------------------------------------------------------------------
ACTOR_COLOURS = {
    "Alice": "#5B9BD5",
    "Bob": "#E07B39",
    "Both": "#5BAD72",
    "System": "#9B59B6",
}
DEFAULT_ACTOR_COLOUR = "#888888"


class StepCard(ctk.CTkFrame):
    """A single step card in the step animator scroll frame."""

    def __init__(
        self,
        parent: tk.Widget,
        step: DHStep,
        highlighted: bool = False,
        **kwargs: object,
    ) -> None:
        bg = "#2C3E50" if highlighted else "#1E2533"
        super().__init__(parent, fg_color=bg, corner_radius=8, **kwargs)
        self.grid_columnconfigure(1, weight=1)

        actor_col = ACTOR_COLOURS.get(step.actor, DEFAULT_ACTOR_COLOUR)

        # Step number badge
        badge = ctk.CTkLabel(
            self,
            text=f"{step.step_number}",
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

        # Public / private values
        val_col = "#27AE60" if step.is_public else "#E74C3C"
        public_icon = "🔓" if step.is_public else "🔒"
        ctk.CTkLabel(
            self,
            text=f"{public_icon} {step.public_value}",
            font=("Courier New", 9),
            text_color=val_col,
            justify="left",
            wraplength=300,
        ).grid(row=2, column=1, sticky="w", padx=4, pady=(0, 4))

        ctk.CTkLabel(
            self,
            text=f"  {step.private_value}",
            font=("Courier New", 9),
            text_color="#AAA",
        ).grid(row=3, column=1, sticky="w", padx=4, pady=(0, 8))


class KeyExchangeTab(ctk.CTkFrame):
    """Key Exchange tab with step animator and embedded matplotlib curve."""

    def __init__(self, parent: tk.Widget, **kwargs: object) -> None:
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._steps: list[DHStep] = []
        self._current_step: int = 0
        self._mode: str = "DH"

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
            text="Run DH (2048-bit)",
            command=self._run_dh,
            width=160,
            fg_color="#2E86AB",
        )
        self._dh_btn.pack(side="left", padx=(0, 8))

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

        # -------- Right: matplotlib curve --------
        right = ctk.CTkFrame(main)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            right,
            text="Elliptic Curve Visualisation (P-256, simplified field)",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=8, pady=(6, 0))

        self._fig, self._ax = plt.subplots(figsize=(5, 4))
        self._fig.patch.set_facecolor("#1E2533")
        self._ax.set_facecolor("#1E2533")
        self._ax.tick_params(colors="gray")
        for spine in self._ax.spines.values():
            spine.set_edgecolor("gray")

        self._mpl_canvas = FigureCanvasTkAgg(self._fig, master=right)
        self._mpl_widget = self._mpl_canvas.get_tk_widget()
        self._mpl_widget.grid(row=1, column=0, sticky="nsew", padx=4, pady=4)

        self._draw_empty_curve()

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

        data = compare_dh_ecdh()
        row_map = {"128bit": 1, "192bit": 2, "256bit": 3}
        for level, row in row_map.items():
            vals = data[level]
            ratio = vals["dh_bits"] // vals["ecdh_bits"]
            ctk.CTkLabel(comp, text=level, font=("Courier New", 10)).grid(
                row=row, column=0, padx=12, pady=2, sticky="w"
            )
            ctk.CTkLabel(
                comp,
                text=f"{vals['dh_bits']:,} bits",
                font=("Courier New", 10),
                text_color="#E07B39",
            ).grid(row=row, column=1, padx=12, pady=2, sticky="w")
            ctk.CTkLabel(
                comp,
                text=f"{vals['ecdh_bits']} bits",
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
        self._steps = run_dh_exchange()
        self._current_step = 0
        self._mode = "DH"
        self._render_steps()
        self._draw_dh_diagram()
        self._status_var.set(
            f"DH exchange: {len(self._steps)} steps. Use Next/Prev to navigate."
        )

    def _run_ecdh(self) -> None:
        self._status_var.set("Running ECDH exchange…")
        self.update_idletasks()
        self._steps = run_ecdh_exchange()
        self._current_step = 0
        self._mode = "ECDH"
        self._render_steps()
        self._draw_ecdh_curve()
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
            highlighted = step.step_number - 1 == self._current_step
            card = StepCard(
                self._step_scroll,
                step,
                highlighted=highlighted,
            )
            card.grid(
                row=step.step_number - 1,
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
        """Attempt to scroll the step list so the current card is visible."""
        try:
            children = self._step_scroll.winfo_children()
            if children and self._current_step < len(children):
                total = len(children)
                fraction = self._current_step / max(total - 1, 1)
                self._step_scroll._parent_canvas.yview_moveto(fraction)
        except Exception:
            pass

    def _prev_step(self) -> None:
        if self._current_step > 0:
            self._current_step -= 1
            self._render_steps()

    def _next_step(self) -> None:
        if self._current_step < len(self._steps) - 1:
            self._current_step += 1
            self._render_steps()

    # ------------------------------------------------------------------
    # Matplotlib plots
    # ------------------------------------------------------------------

    def _draw_empty_curve(self) -> None:
        """Draw a placeholder elliptic curve y² = x³ - 3x + b on small field."""
        self._ax.clear()
        self._ax.set_facecolor("#1E2533")

        # Draw the curve y^2 = x^3 - x + 1 over reals for visual
        x = np.linspace(-2, 2.5, 400)
        y_sq = x**3 - x + 1
        mask = y_sq >= 0
        y_pos = np.sqrt(np.where(mask, y_sq, 0))
        y_neg = -y_pos

        self._ax.plot(
            x[mask],
            y_pos[mask],
            color="#5B9BD5",
            linewidth=1.5,
            label="y² = x³ − x + 1",
        )
        self._ax.plot(x[mask], y_neg[mask], color="#5B9BD5", linewidth=1.5)

        self._ax.set_xlim(-2.5, 3)
        self._ax.set_ylim(-3, 3)
        self._ax.axhline(0, color="gray", linewidth=0.5)
        self._ax.axvline(0, color="gray", linewidth=0.5)
        self._ax.set_title("Elliptic Curve (simplified)", color="white", fontsize=10)
        self._ax.tick_params(colors="gray", labelsize=7)
        for spine in self._ax.spines.values():
            spine.set_edgecolor("#444")
        self._ax.legend(fontsize=7, facecolor="#1E2533", labelcolor="gray")
        self._mpl_canvas.draw()

    def _draw_dh_diagram(self) -> None:
        """Show a simple Alice–Bob diagram for classical DH."""
        self._ax.clear()
        self._ax.set_facecolor("#1E2533")
        self._ax.set_xlim(0, 10)
        self._ax.set_ylim(0, 6)
        self._ax.axis("off")
        self._ax.set_title(
            "DH Key Exchange — 2048-bit MODP (RFC 3526)", color="white", fontsize=9
        )

        # Alice box
        self._ax.add_patch(plt.Rectangle((0.5, 2), 2, 2, color="#2E86AB", zorder=2))
        self._ax.text(
            1.5,
            3,
            "Alice",
            ha="center",
            va="center",
            color="white",
            fontsize=11,
            fontweight="bold",
        )

        # Bob box
        self._ax.add_patch(plt.Rectangle((7.5, 2), 2, 2, color="#E07B39", zorder=2))
        self._ax.text(
            8.5,
            3,
            "Bob",
            ha="center",
            va="center",
            color="white",
            fontsize=11,
            fontweight="bold",
        )

        # Arrows A→Bob
        self._ax.annotate(
            "",
            xy=(7.5, 3.4),
            xytext=(2.5, 3.4),
            arrowprops=dict(arrowstyle="->", color="#5BAD72", lw=2),
        )
        self._ax.text(5, 3.6, "A = g^a mod p", ha="center", color="#5BAD72", fontsize=8)

        # Arrows B→Alice
        self._ax.annotate(
            "",
            xy=(2.5, 2.6),
            xytext=(7.5, 2.6),
            arrowprops=dict(arrowstyle="->", color="#5B9BD5", lw=2),
        )
        self._ax.text(5, 2.3, "B = g^b mod p", ha="center", color="#5B9BD5", fontsize=8)

        # Shared secret labels
        self._ax.text(
            1.5, 1.5, "shared = B^a mod p", ha="center", color="gray", fontsize=7
        )
        self._ax.text(
            8.5, 1.5, "shared = A^b mod p", ha="center", color="gray", fontsize=7
        )

        self._ax.text(
            5,
            0.7,
            "Both arrive at the same shared secret!",
            ha="center",
            color="#5BAD72",
            fontsize=9,
        )

        self._mpl_canvas.draw()

    @staticmethod
    def _curve_y(x: float, positive: bool = True) -> float:
        """Return y on the curve y² = x³ − x + 1 for a given x (must have y² ≥ 0)."""
        y_sq = x**3 - x + 1
        y = float(np.sqrt(max(y_sq, 0.0)))
        return y if positive else -y

    def _draw_ecdh_curve(self, highlighted_step: int = 0) -> None:
        """Draw the elliptic curve with points that provably lie on y² = x³ − x + 1."""
        self._ax.clear()
        self._ax.set_facecolor("#1E2533")

        # Plot curve y² = x³ − x + 1 over reals
        x = np.linspace(-2, 2.5, 800)
        y_sq = x**3 - x + 1
        mask = y_sq >= 0
        y_pos = np.sqrt(np.where(mask, y_sq, 0.0))
        y_neg = -y_pos

        self._ax.plot(
            x[mask],
            y_pos[mask],
            color="#5B9BD5",
            linewidth=1.8,
            label="y² = x³ − x + 1",
        )
        self._ax.plot(x[mask], y_neg[mask], color="#5B9BD5", linewidth=1.8)

        # Points computed so they exactly satisfy the curve equation
        # G at x = -0.9  →  y² = (-0.9)³ + 0.9 + 1 = 1.171  →  y ≈ +1.082
        # QA at x = 1.3  →  y² = 2.197 − 1.3 + 1  = 1.897  →  y ≈ +1.378
        # QB at x = 2.0  →  y² = 8 − 2 + 1        = 7.000  →  y ≈ +2.646
        # S  at x = 0.5  →  y² = 0.125 − 0.5 + 1  = 0.625  →  y ≈ −0.791
        G = (-0.9, self._curve_y(-0.9, positive=True))
        QA = (1.3, self._curve_y(1.3, positive=True))
        QB = (2.0, self._curve_y(2.0, positive=True))
        S = (0.5, self._curve_y(0.5, positive=False))

        points_info = [
            (G, "G (generator)", "#5BAD72"),
            (QA, "QA (Alice pub)", "#5B9BD5"),
            (QB, "QB (Bob pub)", "#E07B39"),
            (S, "S (shared)", "#C0392B"),
        ]

        # Annotation offsets tuned per-point to avoid overlap with the curve line
        offsets = [(-0.6, 0.3), (0.25, 0.35), (0.2, 0.3), (0.25, -0.35)]

        step_to_show = min(highlighted_step, len(points_info) - 1)
        for i, ((pt, label, col), (dx, dy)) in enumerate(
            zip(points_info, offsets, strict=True)
        ):
            if i <= step_to_show:
                self._ax.scatter(
                    *pt, color=col, s=90, zorder=6, edgecolors="white", linewidths=0.6
                )
                self._ax.annotate(
                    label,
                    xy=pt,
                    xytext=(pt[0] + dx, pt[1] + dy),
                    color=col,
                    fontsize=8,
                    fontweight="bold",
                    arrowprops=dict(arrowstyle="-", color=col, lw=0.8),
                )

        self._ax.set_xlim(-2.5, 3.2)
        self._ax.set_ylim(-3.2, 3.5)
        self._ax.axhline(0, color="gray", linewidth=0.4)
        self._ax.axvline(0, color="gray", linewidth=0.4)
        self._ax.set_title(
            "ECDH — simplified curve y² = x³ − x + 1", color="white", fontsize=9
        )
        self._ax.tick_params(colors="gray", labelsize=7)
        for spine in self._ax.spines.values():
            spine.set_edgecolor("#444")
        self._ax.legend(
            fontsize=7, facecolor="#1E2533", labelcolor="gray", loc="upper left"
        )

        self._mpl_canvas.draw()

    def _update_plot_for_step(self) -> None:
        """Animate the curve plot by revealing points as steps progress."""
        if self._mode != "ECDH" or not self._steps:
            return
        # Map step index → how many points to show
        # Step 1: just G; Step 2: G+A; Step 3: G+A+B; Step 4+: all
        point_count = max(0, self._current_step)
        self._draw_ecdh_curve(highlighted_step=point_count)
