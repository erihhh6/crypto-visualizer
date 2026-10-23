"""Layout helpers shared by the tabs."""

from __future__ import annotations

import tkinter as tk

import customtkinter as ctk


def wrap_to_width(label: ctk.CTkLabel, margin: int = 0) -> None:
    """
    Wrap *label*'s text to its parent's width, less *margin*, as that changes.

    A fixed wraplength suits one window size only: in a narrower window the
    text is cut off, in a wider one it wraps for no reason.
    """

    def rewrap(event: tk.Event) -> None:
        # Configure events count physical pixels; wraplength is in the
        # unscaled units CustomTkinter multiplies by the display scaling.
        scaling = ctk.ScalingTracker.get_widget_scaling(label)
        label.configure(wraplength=max(1, round(event.width / scaling) - margin))

    label.master.bind("<Configure>", rewrap, add="+")
