"""
ECB image attack: encrypt an image's pixels and look at the result.

ECB turns equal 16-byte blocks into equal ciphertext, so areas of one colour
stay uniform and the picture's outlines survive; CBC turns it into noise.
"""

from __future__ import annotations

import os
import tkinter as tk
from dataclasses import dataclass
from tkinter import filedialog, messagebox

import customtkinter as ctk
from PIL import Image

from gui.palette import BUTTON_QUIET, MUTED, SURFACE
from modules.aes_modes import encrypt_pixels_cbc, encrypt_pixels_ecb

# Larger images are shrunk before they are encrypted: the pattern shows just
# as well, and loading even a 24-megapixel photo then stays well under 0.2 s.
MAX_ENCRYPTED_SIDE = 512
# Each view fits in a square this size (before HiDPI scaling), or a smaller one
# if the window leaves less room.
SHOWN_SIDE = 150

_SAMPLE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "assets", "sample.bmp"
)


def fit_within(size: tuple[int, int], side: int) -> tuple[int, int]:
    """The largest size with the same proportions that fits in a side×side square."""
    width, height = size
    scale = side / max(width, height)
    return max(1, round(width * scale)), max(1, round(height * scale))


@dataclass(frozen=True)
class EcbViews:
    """An image's pixels in the clear, encrypted with ECB, and with CBC."""

    original: Image.Image
    ecb: Image.Image
    cbc: Image.Image
    source_size: tuple[int, int]  # before any shrinking

    @property
    def shrunk(self) -> bool:
        return self.original.size != self.source_size


def encrypt_views(image: Image.Image, key: bytes) -> EcbViews:
    """
    Encrypt an image's raw RGB pixels with ECB and with CBC.

    Pillow's tobytes()/frombytes() give the same pixel layout whatever the
    file format, so the ciphertext can be shown as an image of the same size.
    A large image is first shrunk with nearest-neighbour sampling, which keeps
    areas of one colour exactly one colour; smoothing would blur them into
    gradients and hide the very repetition that ECB leaks.
    """
    rgb = image.convert("RGB")
    source_size = rgb.size
    if max(rgb.size) > MAX_ENCRYPTED_SIDE:
        smaller = fit_within(rgb.size, MAX_ENCRYPTED_SIDE)
        rgb = rgb.resize(smaller, Image.Resampling.NEAREST)
    pixels = rgb.tobytes()
    return EcbViews(
        original=rgb,
        ecb=Image.frombytes("RGB", rgb.size, encrypt_pixels_ecb(pixels, key)),
        cbc=Image.frombytes("RGB", rgb.size, encrypt_pixels_cbc(pixels, key)),
        source_size=source_size,
    )


class ImageDemo(ctk.CTkFrame):
    """Original, ECB-encrypted and CBC-encrypted views of an image, side by side."""

    def __init__(self, parent: tk.Widget, **kwargs: object) -> None:
        super().__init__(parent, **kwargs)
        self.grid_rowconfigure(2, weight=1)  # image area expands
        self.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=8, pady=(6, 0))
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr,
            text="Image ECB Attack Demo",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkButton(
            hdr,
            text="Open image…",
            command=self._open_image,
            width=100,
        ).grid(row=0, column=1, padx=(4, 0))

        ctk.CTkButton(
            hdr,
            text="Use Sample",
            command=lambda: self._show_ecb_demo(_SAMPLE),
            width=90,
            fg_color=BUTTON_QUIET,
        ).grid(row=0, column=2, padx=(4, 0))

        ctk.CTkLabel(
            self,
            text=(
                "ECB leaks structure; CBC/CTR/GCM all produce noise — only ECB vs "
                "CBC shown here.\nBest with flat colours: logos and drawings."
            ),
            font=("Courier New", 9),
            text_color=MUTED,
            justify="left",
        ).grid(row=1, column=0, sticky="w", padx=8, pady=(2, 0))

        # Image display area
        img_frame = ctk.CTkFrame(self, fg_color=SURFACE)
        img_frame.grid(row=2, column=0, sticky="nsew", padx=4, pady=4)
        img_frame.grid_columnconfigure((0, 1, 2), weight=1)
        img_frame.grid_rowconfigure(0, weight=1)

        self._views: EcbViews | None = None
        self._shown_size: tuple[int, int] | None = None
        self._img_labels: list[ctk.CTkLabel] = []
        captions = [
            "Original",
            "ECB — patterns visible",
            "CBC — secure",
        ]
        for col, cap in enumerate(captions):
            lbl = ctk.CTkLabel(img_frame, text="", image=None)
            lbl.grid(row=0, column=col, padx=4, pady=4, sticky="nsew")
            lbl.bind("<Configure>", lambda _event: self._fit_views(), add="+")
            self._img_labels.append(lbl)
            ctk.CTkLabel(
                img_frame,
                text=cap,
                font=("Courier New", 9),
                text_color=MUTED,
            ).grid(row=1, column=col, padx=4, pady=(0, 4))

        self._size_note = ctk.CTkLabel(
            img_frame, text="", font=("Courier New", 9), text_color=MUTED
        )
        self._size_note.grid(row=2, column=0, columnspan=3, pady=(0, 4))

    def _open_image(self) -> None:
        path = filedialog.askopenfilename(
            title="Open an image",
            filetypes=[
                ("Images", "*.png *.bmp *.gif *.jpg *.jpeg *.tif *.tiff"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self._show_ecb_demo(path)

    def _show_ecb_demo(self, path: str) -> None:
        """Show the original, ECB-encrypted and CBC-encrypted views of an image."""
        try:
            with Image.open(path) as image:
                views = encrypt_views(image, os.urandom(16))
        except (OSError, Image.DecompressionBombError) as exc:
            # OSError covers a missing file and one Pillow cannot read.
            messagebox.showerror("Cannot open image", f"{path}\n\n{exc}")
            return

        self._views, self._shown_size = views, None
        self._fit_views()

        width, height = views.original.size
        note = f"{width}×{height} pixels encrypted"
        if views.shrunk:
            source_width, source_height = views.source_size
            note += f" (shrunk from {source_width}×{source_height})"
        self._size_note.configure(text=note)

    def _fit_views(self) -> None:
        """Show the views as large as SHOWN_SIDE, or as their labels have room for."""
        if self._views is None:
            return
        room = min(
            min(lbl.winfo_width(), lbl.winfo_height()) for lbl in self._img_labels
        )
        side = SHOWN_SIDE
        if room > 1:  # laid out; a small window may leave less room than that
            scaling = ctk.ScalingTracker.get_widget_scaling(self)
            side = max(1, min(side, int(room / scaling)))
        size = fit_within(self._views.original.size, side)
        if size == self._shown_size:
            return  # a resize, but not one that changes the views
        self._shown_size = size
        views = (self._views.original, self._views.ecb, self._views.cbc)
        for label, view in zip(self._img_labels, views, strict=True):
            # CTkImage, unlike a Tk PhotoImage, scales with the display's DPI.
            label.configure(image=ctk.CTkImage(light_image=view, size=size))
