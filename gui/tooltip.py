"""A tooltip that follows the pointer over a widget."""

from __future__ import annotations

import tkinter as tk


class Tooltip:
    """
    A borderless window that follows the pointer over a widget.

    The window is created once and then moved, re-texted, shown and hidden:
    building a fresh Toplevel on every <Motion> event made it flicker.
    """

    def __init__(self, owner: tk.Widget) -> None:
        self._owner = owner
        self._win: tk.Toplevel | None = None
        self._label: tk.Label | None = None

    def show(self, x: int, y: int, text: str) -> None:
        """Show *text* just below-right of widget coordinates (*x*, *y*)."""
        if self._win is None or self._label is None:
            self._win = tk.Toplevel(self._owner)
            self._win.wm_overrideredirect(True)
            self._label = tk.Label(
                self._win,
                font=("Courier New", 9),
                background="#FFFFE0",
                relief="solid",
                borderwidth=1,
                justify="left",
                padx=4,
                pady=2,
            )
            self._label.pack()
        if self._label.cget("text") != text:
            self._label.configure(text=text)
        rx = self._owner.winfo_rootx() + x + 15
        ry = self._owner.winfo_rooty() + y + 10
        self._win.wm_geometry(f"+{rx}+{ry}")
        self._win.deiconify()

    def hide(self) -> None:
        if self._win is not None:
            self._win.withdraw()
