"""
AES Modes tab — block visualization, pixel-diff ECB image attack, mode comparison.

Layout (top-to-bottom, left-to-right):
  Row 0 : controls (input, key, mode, encrypt/decrypt buttons)
  Row 1 : block canvas (left) | image ECB demo (right)
  Row 2 : comparison panel — all four modes side by side
"""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk
from PIL import Image, ImageTk

from modules.aes_modes import (
    AesMode,
    AuthenticationError,
    Block,
    EncryptionResult,
    PaddingError,
    decrypt,
    encrypt,
    encrypt_pixels_cbc,
    encrypt_pixels_ecb,
    key_from_hex,
)

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
COLOUR_PT = "#5B9BD5"  # plaintext  → blue
COLOUR_CT = "#E07B39"  # ciphertext → orange
COLOUR_IV = "#5BAD72"  # IV / XOR   → green
COLOUR_SEL = "#C0392B"  # selected   → red outline
COLOUR_BG = "#1E1E2E"
BLOCK_W = 130  # block rectangle width
BLOCK_H = 54  # block rectangle height
BLOCK_GAP = 14  # horizontal gap between blocks
ARROW_COLOR = "#888888"


def _abbreviate(hex_text: str, limit: int = 16) -> str:
    """Shorten *hex_text* to *limit* characters plus an ellipsis to fit a block."""
    return hex_text if len(hex_text) <= limit else hex_text[:limit] + "…"


def _hex(data: bytes) -> str:
    return data.hex().upper()


# The middle row shows what each mode feeds through AES. ECB has nothing extra
# to show: its AES input is the plaintext block itself.
_AES_INPUT_LABEL = {
    AesMode.CBC: "XOR Input",
    AesMode.CTR: "Counter",
    AesMode.GCM: "Counter",
}


class _Tooltip:
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


class BlockCanvas(ctk.CTkFrame):
    """Canvas that draws AES blocks with arrows and hover tooltips."""

    def __init__(self, parent: tk.Widget, **kwargs: object) -> None:
        super().__init__(parent, **kwargs)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Not "_canvas": CTkFrame keeps its own background canvas under that
        # name, and overwriting it made every theme change repaint this one.
        self._surface = tk.Canvas(
            self,
            background=COLOUR_BG,
            highlightthickness=0,
        )
        self._surface.grid(row=0, column=0, sticky="nsew")

        self._hscroll = ctk.CTkScrollbar(
            self, orientation="horizontal", command=self._surface.xview
        )
        self._hscroll.grid(row=1, column=0, sticky="ew")
        self._surface.configure(xscrollcommand=self._hscroll.set)

        self._tooltip = _Tooltip(self._surface)
        self._mode = AesMode.ECB
        self._blocks: tuple[Block, ...] = ()
        # Per block index: its rectangles, and the area it covers on the canvas.
        self._block_rects: dict[int, list[int]] = {}
        self._block_bounds: dict[int, tuple[int, int, int, int]] = {}
        # Each rectangle's own (outline, width), restored when it is deselected.
        self._normal_borders: dict[int, tuple[str, int]] = {}
        self._selected: int | None = None

        self._surface.bind("<Motion>", self._on_motion)
        self._surface.bind("<Leave>", lambda _e: self._tooltip.hide())
        self._surface.bind("<Button-1>", self._on_click)

        self._detail_var: tk.StringVar | None = None

    def set_detail_var(self, var: tk.StringVar) -> None:
        self._detail_var = var

    def draw(self, result: EncryptionResult) -> None:
        self._surface.delete("all")
        self._mode = result.mode
        self._blocks = result.blocks
        self._block_rects = {}
        self._block_bounds = {}
        self._normal_borders = {}
        self._selected = None

        if not self._blocks:
            return

        total_w = len(self._blocks) * (BLOCK_W + BLOCK_GAP) + BLOCK_GAP + 20
        canvas_h = BLOCK_H * 3 + 80

        self._surface.configure(scrollregion=(0, 0, total_w, canvas_h))

        for blk in self._blocks:
            x0 = BLOCK_GAP + blk.index * (BLOCK_W + BLOCK_GAP)
            self._draw_block(blk, x0)

    def _rect(self, x0: int, y0: int, fill: str, outline: str) -> int:
        """Draw one block-sized rectangle and remember its normal border."""
        width = 2
        rect = self._surface.create_rectangle(
            x0,
            y0,
            x0 + BLOCK_W,
            y0 + BLOCK_H,
            fill=fill,
            outline=outline,
            width=width,
        )
        self._normal_borders[rect] = (outline, width)
        return rect

    def _draw_block(self, blk: Block, x0: int) -> None:
        y_pt = 20
        y_iv = y_pt + BLOCK_H + 18
        y_ct = y_iv + BLOCK_H + 18

        r1 = self._rect(x0, y_pt, fill=COLOUR_PT, outline="#3A79B0")  # plaintext
        t1 = self._surface.create_text(
            x0 + BLOCK_W // 2,
            y_pt + 10,
            text="Plaintext",
            font=("Courier New", 8),
            fill="white",
        )
        t1b = self._surface.create_text(
            x0 + BLOCK_W // 2,
            y_pt + 28,
            text=_abbreviate(_hex(blk.plaintext)),
            font=("Courier New", 9, "bold"),
            fill="white",
        )

        # Middle row: what this mode passed through AES (none for ECB)
        middle_rects: list[int] = []
        middle_texts: list[int] = []
        aes_input_label = _AES_INPUT_LABEL.get(self._mode)
        if aes_input_label is not None:
            middle_rects.append(self._rect(x0, y_iv, fill=COLOUR_IV, outline="#3A8F58"))
            middle_texts.append(
                self._surface.create_text(
                    x0 + BLOCK_W // 2,
                    y_iv + 10,
                    text=aes_input_label,
                    font=("Courier New", 8),
                    fill="white",
                )
            )
            middle_texts.append(
                self._surface.create_text(
                    x0 + BLOCK_W // 2,
                    y_iv + 28,
                    text=_abbreviate(_hex(blk.aes_input)),
                    font=("Courier New", 9, "bold"),
                    fill="white",
                )
            )

        r3 = self._rect(x0, y_ct, fill=COLOUR_CT, outline="#B05A20")  # ciphertext
        t3 = self._surface.create_text(
            x0 + BLOCK_W // 2,
            y_ct + 10,
            text="Ciphertext",
            font=("Courier New", 8),
            fill="white",
        )
        t3b = self._surface.create_text(
            x0 + BLOCK_W // 2,
            y_ct + 28,
            text=_abbreviate(_hex(blk.ciphertext)),
            font=("Courier New", 9, "bold"),
            fill="white",
        )

        # Block index label
        idx_t = self._surface.create_text(
            x0 + BLOCK_W // 2,
            y_ct + BLOCK_H + 8,
            text=f"Block {blk.index}",
            font=("Courier New", 8),
            fill="#AAAAAA",
        )

        # CBC chaining arrow (only for CBC, between blocks)
        if self._mode is AesMode.CBC and blk.index > 0:
            self._surface.create_line(
                x0 - BLOCK_GAP,
                y_ct + BLOCK_H // 2,
                x0,
                y_ct + BLOCK_H // 2,
                fill=ARROW_COLOR,
                arrow=tk.LAST,
                width=2,
            )

        # Remember the block's rectangles (for selection) and the area its items
        # cover (for hit-testing; the CBC arrow sits between blocks, not in one).
        rects = [r1, *middle_rects, r3]
        items = [*rects, t1, t1b, *middle_texts, t3, t3b, idx_t]
        self._block_rects[blk.index] = rects
        self._block_bounds[blk.index] = self._surface.bbox(*items)

    def _block_at(self, x: float, y: float) -> int | None:
        """Index of the block drawn at canvas point (x, y); None over empty space."""
        for index, (x0, y0, x1, y1) in self._block_bounds.items():
            if x0 <= x <= x1 and y0 <= y <= y1:
                return index
        return None

    def _block_under(self, event: tk.Event) -> int | None:
        """The block under the pointer, converting window to (scrolled) canvas space."""
        return self._block_at(
            self._surface.canvasx(event.x), self._surface.canvasy(event.y)
        )

    def _select(self, index: int) -> None:
        """Highlight block *index*, giving the previous selection its border back."""
        if self._selected is not None:
            for rect in self._block_rects[self._selected]:
                outline, width = self._normal_borders[rect]
                self._surface.itemconfigure(rect, outline=outline, width=width)
        for rect in self._block_rects[index]:
            self._surface.itemconfigure(rect, outline=COLOUR_SEL, width=3)
        self._selected = index

    def _on_motion(self, event: tk.Event) -> None:
        idx = self._block_under(event)
        if idx is not None:
            blk = self._blocks[idx]
            rows = "\n".join(
                f"{label:<10}: {value}" for label, value in self._rows(blk)
            )
            self._tooltip.show(
                event.x, event.y, f"Block {blk.index}  [{self._mode}]\n{rows}"
            )
        else:
            self._tooltip.hide()

    def _on_click(self, event: tk.Event) -> None:
        idx = self._block_under(event)
        if idx is None:
            return

        self._select(idx)
        blk = self._blocks[idx]
        if self._detail_var:
            rows = "\n".join(f"{label}:\n  {value}" for label, value in self._rows(blk))
            self._detail_var.set(f"Block {blk.index} — {self._mode}\n{rows}")

    def _rows(self, blk: Block) -> list[tuple[str, str]]:
        """(label, hex value) for each row of *blk*, top to bottom as drawn."""
        rows = [("Plaintext", _hex(blk.plaintext))]
        aes_input_label = _AES_INPUT_LABEL.get(self._mode)
        if aes_input_label is not None:
            rows.append((aes_input_label, _hex(blk.aes_input)))
        rows.append(("Ciphertext", _hex(blk.ciphertext)))
        return rows


class AESTab(ctk.CTkFrame):
    """Full AES Modes tab widget."""

    def __init__(self, parent: tk.Widget, **kwargs: object) -> None:
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        # row 2 (comparison) is fixed height — no weight

        # The latest encryption: ciphertext, IV/tag and mode, kept for Decrypt.
        self._last_result: EncryptionResult | None = None

        self._build_controls()
        self._build_main_area()
        self._build_comparison()

    # ------------------------------------------------------------------
    # UI builders
    # ------------------------------------------------------------------

    def _build_controls(self) -> None:
        ctrl = ctk.CTkFrame(self)
        ctrl.grid(row=0, column=0, sticky="ew", padx=6, pady=(6, 0))
        for i in range(8):
            ctrl.grid_columnconfigure(i, weight=1 if i == 0 else 0)

        # Input text
        ctk.CTkLabel(ctrl, text="Plaintext:").grid(
            row=0, column=0, sticky="w", padx=(8, 2)
        )
        self._input_var = tk.StringVar(value="Hello, AES World! Crypto is fun.")
        self._input_entry = ctk.CTkEntry(
            ctrl,
            textvariable=self._input_var,
            font=("Courier New", 11),
            width=280,
        )
        self._input_entry.grid(row=0, column=1, padx=4, pady=6, sticky="ew")

        # Key field
        ctk.CTkLabel(ctrl, text="Key (hex):").grid(row=0, column=2, padx=(8, 2))
        self._key_var = tk.StringVar()
        self._key_entry = ctk.CTkEntry(
            ctrl,
            textvariable=self._key_var,
            font=("Courier New", 11),
            width=200,
            placeholder_text="leave empty → random AES-128",
        )
        self._key_entry.grid(row=0, column=3, padx=4, pady=6)

        # Mode selector
        ctk.CTkLabel(ctrl, text="Mode:").grid(row=0, column=4, padx=(8, 2))
        self._mode_var = tk.StringVar(value=AesMode.ECB)
        self._mode_menu = ctk.CTkOptionMenu(
            ctrl,
            values=[mode.value for mode in AesMode],
            variable=self._mode_var,
            width=100,
        )
        self._mode_menu.grid(row=0, column=5, padx=4, pady=6)

        # Buttons
        self._enc_btn = ctk.CTkButton(
            ctrl,
            text="Encrypt ▶",
            command=self._do_encrypt,
            width=110,
            fg_color="#2E86AB",
        )
        self._enc_btn.grid(row=0, column=6, padx=4, pady=6)

        self._dec_btn = ctk.CTkButton(
            ctrl,
            text="◀ Decrypt",
            command=self._do_decrypt,
            width=110,
            fg_color="#5C6BC0",
        )
        self._dec_btn.grid(row=0, column=7, padx=(4, 8), pady=6)

        # Decryption output: its own read-only field, so decrypting never
        # overwrites the plaintext the user typed.
        ctk.CTkLabel(ctrl, text="Decrypted:").grid(
            row=1, column=0, sticky="w", padx=(8, 2)
        )
        self._output_var = tk.StringVar()
        ctk.CTkEntry(
            ctrl,
            textvariable=self._output_var,
            font=("Courier New", 11),
            width=280,
            state="readonly",
        ).grid(row=1, column=1, padx=4, pady=(0, 6), sticky="ew")

    def _build_main_area(self) -> None:
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=1, column=0, sticky="nsew", padx=6, pady=4)
        main.grid_columnconfigure(0, weight=3)
        main.grid_columnconfigure(1, weight=2)
        main.grid_rowconfigure(0, weight=1)

        # -------- Left: block visualization --------
        left = ctk.CTkFrame(main)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            left,
            text="Block Visualization",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=8, pady=(6, 0))

        self._block_canvas = BlockCanvas(left, fg_color="transparent")
        self._block_canvas.grid(row=1, column=0, sticky="nsew", padx=4, pady=4)

        # Detail panel below canvas — scrollable text so IV is always visible
        detail_frame = ctk.CTkFrame(left, height=115)
        detail_frame.grid(row=2, column=0, sticky="ew", padx=4, pady=(0, 4))
        detail_frame.grid_columnconfigure(0, weight=1)
        detail_frame.grid_rowconfigure(0, weight=1)
        detail_frame.grid_propagate(False)

        self._detail_text = tk.Text(
            detail_frame,
            font=("Courier New", 10),
            background="#2A2A3E",
            foreground="#E0E0E0",
            relief="flat",
            bd=0,
            wrap="word",
            height=5,
            state="disabled",
            cursor="arrow",
        )
        self._detail_text.grid(row=0, column=0, sticky="nsew", padx=6, pady=4)

        self._detail_var = tk.StringVar(value="Click a block to see details…")
        self._block_canvas.set_detail_var(self._detail_var)
        # Keep a trace so the Text widget stays in sync with the StringVar.
        # A trace only fires on later writes, so show the placeholder now.
        self._detail_var.trace_add(
            "write",
            lambda *_: self._sync_detail_text(),
        )
        self._sync_detail_text()

        # -------- Right: Image ECB demo --------
        right = ctk.CTkFrame(main)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_rowconfigure(2, weight=1)  # image area expands
        right.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(right, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=8, pady=(6, 0))
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr,
            text="Image ECB Attack Demo",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).grid(row=0, column=0, sticky="w")

        self._load_img_btn = ctk.CTkButton(
            hdr,
            text="Load BMP",
            command=self._load_image,
            width=90,
        )
        self._load_img_btn.grid(row=0, column=1, padx=(4, 0))

        self._default_img_btn = ctk.CTkButton(
            hdr,
            text="Use Sample",
            command=self._use_sample_image,
            width=90,
            fg_color="#555",
        )
        self._default_img_btn.grid(row=0, column=2, padx=(4, 0))

        ctk.CTkLabel(
            right,
            text=(
                "ECB leaks structure; CBC/CTR/GCM all produce noise — "
                "only ECB vs CBC shown here."
            ),
            font=("Courier New", 9),
            text_color="gray",
            justify="left",
        ).grid(row=1, column=0, sticky="w", padx=8, pady=(2, 0))

        # Image display area
        self._img_frame = ctk.CTkFrame(right, fg_color=COLOUR_BG)
        self._img_frame.grid(row=2, column=0, sticky="nsew", padx=4, pady=4)
        self._img_frame.grid_columnconfigure((0, 1, 2), weight=1)
        self._img_frame.grid_rowconfigure(0, weight=1)

        self._img_labels: list[ctk.CTkLabel] = []
        self._img_captions: list[ctk.CTkLabel] = []
        captions = [
            "Original",
            "ECB — patterns visible",
            "CBC — secure",
        ]
        for col, cap in enumerate(captions):
            lbl = ctk.CTkLabel(self._img_frame, text="", image=None)
            lbl.grid(row=0, column=col, padx=4, pady=4, sticky="nsew")
            self._img_labels.append(lbl)
            cap_lbl = ctk.CTkLabel(
                self._img_frame,
                text=cap,
                font=("Courier New", 9),
                text_color="gray",
            )
            cap_lbl.grid(row=1, column=col, padx=4, pady=(0, 4))
            self._img_captions.append(cap_lbl)

        self._tk_images: list[ImageTk.PhotoImage] = []  # keep references alive

    def _build_comparison(self) -> None:
        comp = ctk.CTkFrame(self)
        comp.grid(row=2, column=0, sticky="ew", padx=6, pady=(0, 6))
        comp.grid_columnconfigure((0, 1, 2, 3), weight=1)

        ctk.CTkLabel(
            comp,
            text="Mode Comparison — same plaintext, different modes:",
            font=ctk.CTkFont(size=12, weight="bold"),
        ).grid(row=0, column=0, columnspan=4, sticky="w", padx=8, pady=(6, 2))

        self._comp_vars: dict[AesMode, tk.StringVar] = {}
        for col, mode in enumerate(AesMode):
            f = ctk.CTkFrame(comp, fg_color="#2A2A3E")
            f.grid(row=1, column=col, padx=4, pady=(0, 6), sticky="nsew")
            f.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(
                f,
                text=mode,
                font=ctk.CTkFont(family="Courier New", size=12, weight="bold"),
                text_color={
                    AesMode.ECB: "#E07B39",
                    AesMode.CBC: "#5B9BD5",
                    AesMode.CTR: "#5BAD72",
                    AesMode.GCM: "#9B59B6",
                }[mode],
            ).grid(row=0, column=0, padx=6, pady=(6, 2), sticky="w")

            var = tk.StringVar(value="(no data)")
            self._comp_vars[mode] = var
            ctk.CTkLabel(
                f,
                textvariable=var,
                font=("Courier New", 9),
                justify="left",
                anchor="nw",
                wraplength=220,
            ).grid(row=1, column=0, padx=6, pady=(0, 6), sticky="w")

    # ------------------------------------------------------------------
    # Crypto operations
    # ------------------------------------------------------------------

    def _encryption_key(self) -> bytes:
        """The key typed in the field, or a fresh AES-128 key written into it."""
        if not self._key_var.get().strip():
            key = os.urandom(16)
            self._key_var.set(key.hex())
            return key
        return key_from_hex(self._key_var.get())

    def _do_encrypt(self) -> None:
        plaintext = self._input_var.get().encode("utf-8")
        if not plaintext:
            messagebox.showwarning(
                "Input required", "Please enter some plaintext first."
            )
            return
        try:
            key = self._encryption_key()
        except ValueError as exc:
            messagebox.showerror("Invalid key", str(exc))
            return

        self._last_result = encrypt(AesMode(self._mode_var.get()), plaintext, key)
        self._output_var.set("")  # an earlier decryption no longer applies
        self._block_canvas.draw(self._last_result)
        self._update_comparison(plaintext, key)

    def _do_decrypt(self) -> None:
        if self._last_result is None:
            messagebox.showinfo("Nothing to decrypt", "Encrypt something first.")
            return
        # Always read the key from the field so that editing it has real effect.
        if not self._key_var.get().strip():
            messagebox.showwarning(
                "Key required",
                "The key field is empty.\nEnter the hex key that was used to encrypt.",
            )
            return
        try:
            key = key_from_hex(self._key_var.get())
        except ValueError as exc:
            messagebox.showerror("Invalid key", str(exc))
            return

        try:
            plaintext = decrypt(self._last_result, key)
        except PaddingError as exc:
            # Show the garbled output so the user sees what the wrong key
            # actually produces: the educational point of the demo.
            self._output_var.set(exc.raw.decode("utf-8", errors="replace"))
            messagebox.showwarning(
                "Wrong key",
                "Padding check failed — the key is incorrect.\n\n"
                "The Decrypted field shows the garbled output\n"
                "so you can see what the wrong key produces.",
            )
            return
        except AuthenticationError:
            self._output_var.set("")
            messagebox.showerror(
                "Authentication failed (GCM)",
                "The authentication tag does not match.\n\n"
                "This means the key is wrong or the ciphertext was "
                "tampered with.\n"
                "GCM refuses to return any output at all — this is exactly\n"
                "why authenticated encryption is safer than ECB or CBC.",
            )
            return
        self._output_var.set(plaintext.decode("utf-8", errors="replace"))

    def _update_comparison(self, plaintext: bytes, key: bytes) -> None:
        for mode, var in self._comp_vars.items():
            ct_hex = _hex(encrypt(mode, plaintext, key).ciphertext)
            var.set(ct_hex[:64] + ("…" if len(ct_hex) > 64 else ""))

    # ------------------------------------------------------------------
    # Image ECB demo
    # ------------------------------------------------------------------

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

    def _sync_detail_text(self) -> None:
        """Sync the read-only Text widget from the detail StringVar."""
        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0", "end")
        self._detail_text.insert("1.0", self._detail_var.get())
        self._detail_text.configure(state="disabled")

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
