"""
Main application window for the Crypto Visualizer.

Uses a custom tab system (CTkSegmentedButton + CTkFrame switcher) instead of
CTkTabview so that the tab selector buttons sit visually INSIDE the same
lighter-gray content box as the tab content — matching the expected look.
"""

from __future__ import annotations

import os
import sys
import traceback
from tkinter import messagebox
from types import TracebackType

import customtkinter as ctk
from PIL import Image, ImageTk

from gui.aes_tab import AESTab
from gui.key_exchange_tab import KeyExchangeTab
from gui.palette import MUTED, use_readable_theme
from gui.tamper_tab import TamperTab

_ICON_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "assets", "icon.ico"
)


# Follow the operating system's light or dark theme: every colour comes as a
# light/dark pair (gui.palette).
ctk.set_appearance_mode("System")
use_readable_theme()

MIN_SIZE = (900, 600)  # the smallest window in which every control still fits


class MainWindow(ctk.CTk):
    """Top-level application window."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Crypto Visualizer")
        self.geometry("1100x700")
        self.minsize(*MIN_SIZE)
        self.resizable(True, True)
        # Handlers show dialogs for problems the user can fix (a bad key, empty
        # input). Anything else escaping a button or event handler is a bug:
        # report it here, in one place, instead of in a console that may be
        # hidden, and without each handler needing a catch-all.
        self.report_callback_exception = self._report_unexpected_error
        self._set_window_icon()
        self._build_ui()

    def _report_unexpected_error(
        self,
        exc_type: type[BaseException],
        exc: BaseException,
        tb: TracebackType | None,
    ) -> None:
        traceback.print_exception(exc_type, exc, tb)
        messagebox.showerror("Unexpected error", f"{exc_type.__name__}: {exc}")

    def _set_window_icon(self) -> None:
        """Show the app icon using the mechanism each platform's Tk supports."""
        if not os.path.exists(_ICON_PATH):
            return
        if sys.platform == "win32":
            # Windows Tk reads .ico files natively, and CustomTkinter replaces
            # the icon with its own unless iconbitmap() has been called.
            self.iconbitmap(_ICON_PATH)
        else:
            # Tk on X11 rejects .ico files ('bitmap "…" not defined') and
            # crashes start-up, so hand it decoded pixels instead. Keep a
            # reference: Tk drops the image once Python garbage-collects it.
            self._icon_image = ImageTk.PhotoImage(Image.open(_ICON_PATH))
            self.iconphoto(True, self._icon_image)

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ── Header bar (outside the box) ──────────────────────────────────
        header = ctk.CTkFrame(self, fg_color="transparent", height=40)
        header.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 0))
        header.grid_columnconfigure(1, weight=1)
        header.grid_propagate(False)

        ctk.CTkLabel(
            header,
            text="Crypto Visualizer",
            font=ctk.CTkFont(family="Courier New", size=18, weight="bold"),
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            header,
            text="Interactive cryptography demonstrations",
            font=ctk.CTkFont(size=12),
            text_color=MUTED,
        ).grid(row=0, column=1, sticky="w", padx=12)

        # ── Main content box (the big lighter-gray frame) ─────────────────
        box = ctk.CTkFrame(self)
        box.grid(row=1, column=0, sticky="nsew", padx=10, pady=8)
        box.grid_columnconfigure(0, weight=1)
        box.grid_rowconfigure(1, weight=1)

        # Tab selector — lives INSIDE the gray box at the top
        names = ("AES Modes", "Key Exchange", "Tamper Lab")
        self._tab_selector = ctk.CTkSegmentedButton(
            box,
            values=list(names),
            command=self._switch_tab,
            font=ctk.CTkFont(size=12),
            width=390,
        )
        self._tab_selector.grid(row=0, column=0, padx=16, pady=(12, 8), sticky="w")

        # Content area — also inside the same gray box
        content = ctk.CTkFrame(box, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(0, weight=1)

        self.aes_tab = AESTab(content)
        self.key_tab = KeyExchangeTab(content)
        self.tamper_tab = TamperTab(content)
        tabs = (self.aes_tab, self.key_tab, self.tamper_tab)
        self._tabs: dict[str, ctk.CTkFrame] = dict(zip(names, tabs, strict=True))
        for tab in tabs:
            tab.grid(row=0, column=0, sticky="nsew")

        self._tab_selector.set(names[0])
        self._switch_tab(names[0])

    def _switch_tab(self, value: str) -> None:
        """Show the tab named *value* and hide the others."""
        for name, tab in self._tabs.items():
            if name == value:
                tab.grid()
            else:
                tab.grid_remove()
