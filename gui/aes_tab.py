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
from typing import Optional

import customtkinter as ctk
from PIL import Image, ImageTk

from modules.aes_modes import (
    BlockInfo,
    encrypt_ecb,
    encrypt_cbc,
    encrypt_ctr,
    encrypt_gcm,
    decrypt_ecb,
    decrypt_cbc,
    decrypt_ctr,
    decrypt_gcm,
    encrypt_pixels_ecb,
    encrypt_pixels_cbc,
)


# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
COLOUR_PT   = "#5B9BD5"   # plaintext  → blue
COLOUR_CT   = "#E07B39"   # ciphertext → orange
COLOUR_IV   = "#5BAD72"   # IV / XOR   → green
COLOUR_SEL  = "#C0392B"   # selected   → red outline
COLOUR_BG   = "#1E1E2E"
BLOCK_W     = 130         # block rectangle width
BLOCK_H     = 54          # block rectangle height
BLOCK_GAP   = 14          # horizontal gap between blocks
ARROW_COLOR = "#888888"


class _Tooltip:
    """Simple Tkinter tooltip shown on canvas hover."""

    def __init__(self, canvas: tk.Canvas) -> None:
        self._canvas = canvas
        self._win: Optional[tk.Toplevel] = None

    def show(self, x: int, y: int, text: str) -> None:
        self.hide()
        rx = self._canvas.winfo_rootx() + x + 15
        ry = self._canvas.winfo_rooty() + y + 10
        self._win = tk.Toplevel(self._canvas)
        self._win.wm_overrideredirect(True)
        self._win.wm_geometry(f"+{rx}+{ry}")
        label = tk.Label(
            self._win,
            text=text,
            font=("Courier New", 9),
            background="#FFFFE0",
            relief="solid",
            borderwidth=1,
            justify="left",
            padx=4,
            pady=2,
        )
        label.pack()

    def hide(self) -> None:
        if self._win:
            self._win.destroy()
            self._win = None


class BlockCanvas(ctk.CTkFrame):
    """Canvas that draws AES blocks with arrows and hover tooltips."""

    def __init__(self, parent: tk.Widget, **kwargs: object) -> None:
        super().__init__(parent, **kwargs)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._canvas = tk.Canvas(
            self,
            background=COLOUR_BG,
            highlightthickness=0,
        )
        self._canvas.grid(row=0, column=0, sticky="nsew")

        self._hscroll = ctk.CTkScrollbar(
            self, orientation="horizontal", command=self._canvas.xview
        )
        self._hscroll.grid(row=1, column=0, sticky="ew")
        self._canvas.configure(xscrollcommand=self._hscroll.set)

        self._tooltip = _Tooltip(self._canvas)
        self._blocks: list[BlockInfo] = []
        self._selected: Optional[int] = None
        self._block_ids: dict[int, list[int]] = {}  # index → [rect_id, ...]

        self._canvas.bind("<Motion>", self._on_motion)
        self._canvas.bind("<Leave>", lambda _e: self._tooltip.hide())
        self._canvas.bind("<Button-1>", self._on_click)

        self._detail_var: Optional[tk.StringVar] = None

    def set_detail_var(self, var: tk.StringVar) -> None:
        self._detail_var = var

    def draw(self, blocks: list[BlockInfo]) -> None:
        self._canvas.delete("all")
        self._blocks = blocks
        self._block_ids = {}
        self._selected = None

        if not blocks:
            return

        mode = blocks[0].mode_label
        total_w = len(blocks) * (BLOCK_W + BLOCK_GAP) + BLOCK_GAP + 20
        canvas_h = BLOCK_H * 3 + 80

        self._canvas.configure(scrollregion=(0, 0, total_w, canvas_h))

        for blk in blocks:
            x0 = BLOCK_GAP + blk.index * (BLOCK_W + BLOCK_GAP)
            self._draw_block(blk, x0, mode)

    def _draw_block(self, blk: BlockInfo, x0: int, mode: str) -> None:
        ids: list[int] = []
        y_pt  = 20
        y_iv  = y_pt + BLOCK_H + 18
        y_ct  = y_iv + BLOCK_H + 18

        # Plaintext rectangle
        r1 = self._canvas.create_rectangle(
            x0, y_pt, x0 + BLOCK_W, y_pt + BLOCK_H,
            fill=COLOUR_PT, outline="#3A79B0", width=2,
        )
        t1 = self._canvas.create_text(
            x0 + BLOCK_W // 2, y_pt + 10,
            text="Plaintext",
            font=("Courier New", 8),
            fill="white",
        )
        t1b = self._canvas.create_text(
            x0 + BLOCK_W // 2, y_pt + 28,
            text=blk.plaintext_hex[:16] + "…" if len(blk.plaintext_hex) > 16 else blk.plaintext_hex,
            font=("Courier New", 9, "bold"),
            fill="white",
        )

        # IV / XOR / Counter rectangle (hide for ECB)
        r2 = t2 = t2b = None
        if mode != "ECB" and blk.iv_or_xor_hex not in ("N/A", ""):
            label_iv = {"CBC": "XOR Input", "CTR": "Counter", "GCM": "Counter"}.get(mode, "IV")
            r2 = self._canvas.create_rectangle(
                x0, y_iv, x0 + BLOCK_W, y_iv + BLOCK_H,
                fill=COLOUR_IV, outline="#3A8F58", width=2,
            )
            t2 = self._canvas.create_text(
                x0 + BLOCK_W // 2, y_iv + 10,
                text=label_iv,
                font=("Courier New", 8),
                fill="white",
            )
            t2b = self._canvas.create_text(
                x0 + BLOCK_W // 2, y_iv + 28,
                text=blk.iv_or_xor_hex[:16] + "…" if len(blk.iv_or_xor_hex) > 16 else blk.iv_or_xor_hex,
                font=("Courier New", 9, "bold"),
                fill="white",
            )

        # Ciphertext rectangle
        r3 = self._canvas.create_rectangle(
            x0, y_ct, x0 + BLOCK_W, y_ct + BLOCK_H,
            fill=COLOUR_CT, outline="#B05A20", width=2,
        )
        t3 = self._canvas.create_text(
            x0 + BLOCK_W // 2, y_ct + 10,
            text="Ciphertext",
            font=("Courier New", 8),
            fill="white",
        )
        t3b = self._canvas.create_text(
            x0 + BLOCK_W // 2, y_ct + 28,
            text=blk.ciphertext_hex[:16] + "…" if len(blk.ciphertext_hex) > 16 else blk.ciphertext_hex,
            font=("Courier New", 9, "bold"),
            fill="white",
        )

        # Block index label
        idx_t = self._canvas.create_text(
            x0 + BLOCK_W // 2, y_ct + BLOCK_H + 8,
            text=f"Block {blk.index}",
            font=("Courier New", 8),
            fill="#AAAAAA",
        )

        # CBC chaining arrow (only for CBC, between blocks)
        if mode == "CBC" and blk.index > 0:
            prev_x_mid = x0 - BLOCK_GAP // 2
            self._canvas.create_line(
                x0 - BLOCK_GAP, y_ct + BLOCK_H // 2,
                x0, y_ct + BLOCK_H // 2,
                fill=ARROW_COLOR, arrow=tk.LAST, width=2,
            )

        # Gather all items for this block
        item_ids = [r1, t1, t1b, r3, t3, t3b, idx_t]
        if r2 is not None:
            item_ids += [r2, t2, t2b]
        self._block_ids[blk.index] = item_ids

    def _block_at(self, x: int) -> Optional[int]:
        """Return block index under canvas x coordinate, or None."""
        for idx, blk in enumerate(self._blocks):
            x0 = BLOCK_GAP + idx * (BLOCK_W + BLOCK_GAP)
            if x0 <= x <= x0 + BLOCK_W:
                return idx
        return None

    def _on_motion(self, event: tk.Event) -> None:  # type: ignore[override]
        cx = int(self._canvas.canvasx(event.x))
        idx = self._block_at(cx)
        if idx is not None:
            blk = self._blocks[idx]
            tip = (
                f"Block {blk.index}  [{blk.mode_label}]\n"
                f"Plaintext : {blk.plaintext_hex}\n"
                f"Ciphertext: {blk.ciphertext_hex}\n"
                f"IV/XOR    : {blk.iv_or_xor_hex}"
            )
            self._tooltip.show(event.x, event.y, tip)
        else:
            self._tooltip.hide()

    def _on_click(self, event: tk.Event) -> None:
        cx = int(self._canvas.canvasx(event.x))
        idx = self._block_at(cx)
        if idx is None:
            return

        # Reset previous selection
        if self._selected is not None and self._selected in self._block_ids:
            for item in self._block_ids[self._selected]:
                try:
                    self._canvas.itemconfigure(item, outline="")
                except tk.TclError:
                    pass

        self._selected = idx
        blk = self._blocks[idx]

        # Highlight selection with red outline on the block rectangles
        rects = [self._block_ids[idx][0], self._block_ids[idx][3]]
        for rect in rects:
            self._canvas.itemconfigure(rect, outline=COLOUR_SEL, width=3)

        if self._detail_var:
            self._detail_var.set(
                f"Block {blk.index} — {blk.mode_label}\n"
                f"Plaintext :\n  {blk.plaintext_hex}\n"
                f"Ciphertext:\n  {blk.ciphertext_hex}\n"
                f"IV / XOR  :\n  {blk.iv_or_xor_hex}"
            )


class AESTab(ctk.CTkFrame):
    """Full AES Modes tab widget."""

    def __init__(self, parent: tk.Widget, **kwargs: object) -> None:
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        # row 2 (comparison) is fixed height — no weight

        self._key: Optional[bytes] = None
        self._last_ciphertext: Optional[bytes] = None
        self._last_iv: Optional[bytes] = None
        self._last_nonce: Optional[bytes] = None
        self._last_tag: Optional[bytes] = None
        self._last_mode: str = "ECB"

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
        ctk.CTkLabel(ctrl, text="Plaintext:").grid(row=0, column=0, sticky="w", padx=(8, 2))
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
        self._mode_var = tk.StringVar(value="ECB")
        self._mode_menu = ctk.CTkOptionMenu(
            ctrl,
            values=["ECB", "CBC", "CTR", "GCM"],
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
        # Keep a trace so the Text widget stays in sync with the StringVar
        self._detail_var.trace_add(
            "write",
            lambda *_: self._sync_detail_text(),
        )

        # -------- Right: Image ECB demo --------
        right = ctk.CTkFrame(main)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_rowconfigure(2, weight=1)   # image area expands
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
            text="ECB leaks structure; CBC/CTR/GCM all produce noise — only ECB vs CBC shown here.",
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

        self._comp_vars: dict[str, tk.StringVar] = {}
        for col, mode in enumerate(["ECB", "CBC", "CTR", "GCM"]):
            f = ctk.CTkFrame(comp, fg_color="#2A2A3E")
            f.grid(row=1, column=col, padx=4, pady=(0, 6), sticky="nsew")
            f.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(
                f,
                text=mode,
                font=ctk.CTkFont(family="Courier New", size=12, weight="bold"),
                text_color={"ECB": "#E07B39", "CBC": "#5B9BD5", "CTR": "#5BAD72", "GCM": "#9B59B6"}[mode],
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

    def _resolve_key(self) -> bytes:
        """Parse key from hex field or generate a random AES-128 key."""
        raw = self._key_var.get().strip().replace(" ", "")
        if raw:
            try:
                key = bytes.fromhex(raw)
            except ValueError as exc:
                raise ValueError("Key must be a valid hex string.") from exc
            if len(key) not in (16, 24, 32):
                raise ValueError("Key must be 16, 24, or 32 bytes (32/48/64 hex chars).")
            return key
        key = os.urandom(16)
        self._key_var.set(key.hex())
        return key

    def _do_encrypt(self) -> None:
        try:
            key = self._resolve_key()
            plaintext = self._input_var.get().encode("utf-8")
            if not plaintext:
                messagebox.showwarning("Input required", "Please enter some plaintext first.")
                return

            mode = self._mode_var.get()
            self._last_mode = mode
            self._key = key

            if mode == "ECB":
                ct, blocks = encrypt_ecb(plaintext, key)
                self._last_ciphertext = ct
                self._last_iv = None
            elif mode == "CBC":
                iv_ct, blocks = encrypt_cbc(plaintext, key)
                self._last_iv = iv_ct[:16]
                self._last_ciphertext = iv_ct[16:]
            elif mode == "CTR":
                n_ct, blocks = encrypt_ctr(plaintext, key)
                self._last_nonce = n_ct[:16]
                self._last_ciphertext = n_ct[16:]
            elif mode == "GCM":
                n_ct, tag, blocks = encrypt_gcm(plaintext, key)
                self._last_nonce = n_ct[:12]
                self._last_ciphertext = n_ct[12:]
                self._last_tag = tag
            else:
                return

            self._block_canvas.draw(blocks)
            self._update_comparison(plaintext, key)

        except Exception as exc:
            messagebox.showerror("Encryption error", str(exc))

    def _do_decrypt(self) -> None:
        if self._last_ciphertext is None:
            messagebox.showinfo("Nothing to decrypt", "Encrypt something first.")
            return
        try:
            # Always read the key from the field so that editing it has real effect.
            raw = self._key_var.get().strip().replace(" ", "")
            if not raw:
                messagebox.showwarning(
                    "Key required",
                    "The key field is empty.\nEnter the hex key that was used to encrypt.",
                )
                return
            try:
                key = bytes.fromhex(raw)
            except ValueError:
                messagebox.showerror("Invalid key", "Key must be a valid hex string.")
                return
            if len(key) not in (16, 24, 32):
                messagebox.showerror(
                    "Invalid key",
                    f"Key must be 16, 24, or 32 bytes ({len(key)} bytes given).",
                )
                return

            mode = self._last_mode
            try:
                if mode == "ECB":
                    pt = decrypt_ecb(self._last_ciphertext, key)
                elif mode == "CBC":
                    pt = decrypt_cbc(self._last_ciphertext, key, self._last_iv)
                elif mode == "CTR":
                    pt = decrypt_ctr(self._last_ciphertext, key, self._last_nonce)
                elif mode == "GCM":
                    pt = decrypt_gcm(self._last_ciphertext, key, self._last_nonce, self._last_tag)
                else:
                    return
                self._input_var.set(pt.decode("utf-8", errors="replace"))

            except ValueError as exc:
                if "padding" in str(exc).lower():
                    # Wrong key → PKCS7 unpadding fails on garbage bytes.
                    # Show the raw garbled output so the user sees what the wrong
                    # key actually produces — the educational point of the demo.
                    if mode == "ECB":
                        raw = decrypt_ecb(self._last_ciphertext, key, strict=False)
                    else:  # CBC
                        raw = decrypt_cbc(self._last_ciphertext, key, self._last_iv, strict=False)
                    self._input_var.set(raw.decode("utf-8", errors="replace"))
                    messagebox.showwarning(
                        "Wrong key",
                        "Padding check failed — the key is incorrect.\n\n"
                        "The garbled output has been placed in the plaintext field\n"
                        "so you can see what the wrong key produces.",
                    )
                else:
                    messagebox.showerror("Decryption error", str(exc))

            except Exception as exc:
                # GCM raises InvalidTag (empty message) when the key is wrong.
                # Identify it by class name so we don't need to import the exception type.
                if type(exc).__name__ == "InvalidTag":
                    messagebox.showerror(
                        "Authentication failed (GCM)",
                        "The authentication tag does not match.\n\n"
                        "This means the key is wrong or the ciphertext was tampered with.\n"
                        "GCM refuses to return any output at all — this is exactly\n"
                        "why authenticated encryption is safer than ECB or CBC.",
                    )
                else:
                    messagebox.showerror("Decryption error", str(exc) or repr(exc))

        except Exception as exc:
            messagebox.showerror("Decryption error", str(exc))

    def _update_comparison(self, plaintext: bytes, key: bytes) -> None:
        ops = {
            "ECB": lambda: encrypt_ecb(plaintext, key),
            "CBC": lambda: encrypt_cbc(plaintext, key),
            "CTR": lambda: encrypt_ctr(plaintext, key),
            "GCM": lambda: encrypt_gcm(plaintext, key),
        }
        for mode, fn in ops.items():
            try:
                result = fn()
                if mode == "GCM":
                    ct_data = result[0]
                elif mode in ("CBC", "CTR"):
                    ct_data = result[0]
                else:
                    ct_data = result[0]

                ct_hex = ct_data.hex().upper()
                display = ct_hex[:64] + ("…" if len(ct_hex) > 64 else "")
                self._comp_vars[mode].set(display)
            except Exception:
                self._comp_vars[mode].set("(error)")

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
            orig_r = orig_img.resize((target_w, target_h), Image.LANCZOS)
            ecb_r  = ecb_img.resize((target_w, target_h), Image.LANCZOS)
            cbc_r  = cbc_img.resize((target_w, target_h), Image.LANCZOS)

            self._tk_images = [
                ImageTk.PhotoImage(orig_r),
                ImageTk.PhotoImage(ecb_r),
                ImageTk.PhotoImage(cbc_r),
            ]
            for i, lbl in enumerate(self._img_labels):
                lbl.configure(image=self._tk_images[i])

        except Exception as exc:
            messagebox.showerror("Image error", str(exc))
