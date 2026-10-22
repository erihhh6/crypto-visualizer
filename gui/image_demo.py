"""
ECB image attack: encrypt an image's pixels and look at the result.

ECB turns equal 16-byte blocks into equal ciphertext, so areas of one colour
stay uniform and the picture's outlines survive; CBC turns it into noise.
"""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk
from PIL import Image, ImageTk

from gui.palette import COLOUR_SURFACE
from modules.aes_modes import encrypt_pixels_cbc, encrypt_pixels_ecb


class ImageDemo(ctk.CTkFrame):
    """Original, ECB-encrypted and CBC-encrypted views of a BMP, side by side."""

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
            text="Load BMP",
            command=self._load_image,
            width=90,
        ).grid(row=0, column=1, padx=(4, 0))

        ctk.CTkButton(
            hdr,
            text="Use Sample",
            command=self._use_sample_image,
            width=90,
            fg_color="#555",
        ).grid(row=0, column=2, padx=(4, 0))

        ctk.CTkLabel(
            self,
            text=(
                "ECB leaks structure; CBC/CTR/GCM all produce noise — "
                "only ECB vs CBC shown here."
            ),
            font=("Courier New", 9),
            text_color="gray",
            justify="left",
        ).grid(row=1, column=0, sticky="w", padx=8, pady=(2, 0))

        # Image display area
        img_frame = ctk.CTkFrame(self, fg_color=COLOUR_SURFACE)
        img_frame.grid(row=2, column=0, sticky="nsew", padx=4, pady=4)
        img_frame.grid_columnconfigure((0, 1, 2), weight=1)
        img_frame.grid_rowconfigure(0, weight=1)

        self._img_labels: list[ctk.CTkLabel] = []
        captions = [
            "Original",
            "ECB — patterns visible",
            "CBC — secure",
        ]
        for col, cap in enumerate(captions):
            lbl = ctk.CTkLabel(img_frame, text="", image=None)
            lbl.grid(row=0, column=col, padx=4, pady=4, sticky="nsew")
            self._img_labels.append(lbl)
            ctk.CTkLabel(
                img_frame,
                text=cap,
                font=("Courier New", 9),
                text_color="gray",
            ).grid(row=1, column=col, padx=4, pady=(0, 4))

        self._tk_images: list[ImageTk.PhotoImage] = []  # keep references alive

    def _load_image(self) -> None:
        path = filedialog.askopenfilename(
            title="Select a BMP image",
            filetypes=[("BMP Images", "*.bmp"), ("All files", "*.*")],
        )
        if path:
            self._show_ecb_demo(path)

    def _use_sample_image(self) -> None:
        sample = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "assets", "sample.bmp"
        )
        if os.path.exists(sample):
            self._show_ecb_demo(sample)
        else:
            messagebox.showerror("File not found", f"Sample image not found:\n{sample}")

    def _show_ecb_demo(self, path: str) -> None:
        """
        Display Original / ECB-encrypted / CBC-encrypted views of a BMP.

        Uses PIL tobytes() / frombytes() so this works for any BMP variant
        (24-bit, 32-bit, BGR, palette-indexed, top/bottom row order, etc.).
        The raw pixel bytes are always in PIL's normalized RGB format, so
        the encrypted result can be reconstructed without format guesswork.
        """
        try:
            key = os.urandom(16)

            # Normalize to RGB via PIL — works regardless of BMP subformat
            orig_img = Image.open(path).convert("RGB")
            raw_pixels = orig_img.tobytes()  # pure RGB, no BMP header complications

            # ECB: identical 16-byte blocks → identical ciphertext → patterns survive
            ecb_raw = encrypt_pixels_ecb(raw_pixels, key)
            ecb_img = Image.frombytes("RGB", orig_img.size, ecb_raw)

            # CBC: every block XOR'd with previous → looks like random noise
            cbc_raw = encrypt_pixels_cbc(raw_pixels, key)
            cbc_img = Image.frombytes("RGB", orig_img.size, cbc_raw)

            # Resize to fit the display panel (keep aspect ratio)
            target_w = 150
            target_h = int(orig_img.height * target_w / orig_img.width)
            lanczos = Image.Resampling.LANCZOS
            orig_r = orig_img.resize((target_w, target_h), lanczos)
            ecb_r = ecb_img.resize((target_w, target_h), lanczos)
            cbc_r = cbc_img.resize((target_w, target_h), lanczos)

            self._tk_images = [
                ImageTk.PhotoImage(orig_r),
                ImageTk.PhotoImage(ecb_r),
                ImageTk.PhotoImage(cbc_r),
            ]
            for i, lbl in enumerate(self._img_labels):
                lbl.configure(image=self._tk_images[i])

        except Exception as exc:
            messagebox.showerror("Image error", str(exc))
