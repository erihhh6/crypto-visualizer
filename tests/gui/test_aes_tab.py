"""AESTab: encryption round trips, block details and the image demo."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog
from typing import Any

import customtkinter as ctk
import pytest
from PIL import Image

from gui.aes_tab import AESTab
from modules.aes_modes import AesMode, PaddingError, decrypt, encrypt
from tests.gui.helpers import block_canvas, descendants, find_button, pump, require
from tests.markers import known_bug

_MESSAGE = "Attack at dawn - more than one 16-byte block"
_RIGHT_KEY = bytes(16)
_WRONG_KEY = bytes(15) + b"\x01"


@pytest.fixture
def tab(root: Any) -> Any:
    widget = AESTab(root)
    widget.pack(fill="both", expand=True)
    pump(root)
    return widget


def _entries(tab: Any) -> tuple[Any, Any]:
    """The plaintext and key fields (created left to right in that order)."""
    entries = [w for w in descendants(tab) if isinstance(w, ctk.CTkEntry)]
    require(len(entries) == 2, f"expected plaintext + key entries, got {len(entries)}")
    return entries[0], entries[1]


def _type(entry: Any, text: str) -> None:
    entry.delete(0, "end")
    entry.insert(0, text)


def _choose_mode(tab: Any, mode: AesMode) -> None:
    (mode_menu,) = [w for w in descendants(tab) if isinstance(w, ctk.CTkOptionMenu)]
    mode_menu.set(mode)


def _encrypt_then_decrypt_with(tab: Any, mode: AesMode, decrypt_key: bytes) -> Any:
    """Encrypt _MESSAGE with _RIGHT_KEY, clear the field, decrypt with *decrypt_key*."""
    plaintext, key = _entries(tab)
    _choose_mode(tab, mode)
    _type(plaintext, _MESSAGE)
    _type(key, _RIGHT_KEY.hex())
    find_button(tab, "Encrypt").invoke()
    block_canvas(tab)  # the blocks were drawn
    _type(plaintext, "")
    _type(key, decrypt_key.hex())
    find_button(tab, "Decrypt").invoke()
    return plaintext


@pytest.mark.parametrize("mode", list(AesMode))
def test_encrypt_then_decrypt_restores_the_plaintext(tab: Any, mode: AesMode) -> None:
    plaintext = _encrypt_then_decrypt_with(tab, mode, _RIGHT_KEY)
    assert plaintext.get() == _MESSAGE


def test_wrong_key_shows_the_garbled_output_with_a_warning(
    tab: Any, no_dialogs: list[str]
) -> None:
    # A random wrong key passes the padding check 1 time in 256; this pair fails.
    with pytest.raises(PaddingError):
        decrypt(encrypt(AesMode.ECB, _MESSAGE.encode(), _RIGHT_KEY), _WRONG_KEY)

    plaintext = _encrypt_then_decrypt_with(tab, AesMode.ECB, _WRONG_KEY)

    assert len(no_dialogs) == 1
    assert no_dialogs[0].startswith("showwarning: Wrong key")
    assert plaintext.get() not in ("", _MESSAGE)  # the garbled output is shown
    no_dialogs.clear()  # the warning was the expected outcome


def test_gcm_refuses_to_decrypt_with_a_wrong_key(
    tab: Any, no_dialogs: list[str]
) -> None:
    plaintext = _encrypt_then_decrypt_with(tab, AesMode.GCM, _WRONG_KEY)

    assert len(no_dialogs) == 1
    assert no_dialogs[0].startswith("showerror: Authentication failed (GCM)")
    assert plaintext.get() == ""  # GCM releases no output at all
    no_dialogs.clear()  # the error was the expected outcome


def test_detail_panel_shows_a_placeholder_before_any_click(tab: Any) -> None:
    panels = [w for w in descendants(tab) if isinstance(w, tk.Text)]
    require(len(panels) == 1, f"expected one detail panel, found {len(panels)}")
    assert panels[0].get("1.0", "end-1c").strip()


def _load_image(
    tab: Any, root: Any, monkeypatch: pytest.MonkeyPatch, path: Path
) -> None:
    """Click "Load BMP" and pick *path* in the (stubbed) file dialog."""
    monkeypatch.setattr(filedialog, "askopenfilename", lambda **_: str(path))
    find_button(tab, "Load BMP").invoke()
    pump(root)


@known_bug("the image demo gives CTkLabel Tk PhotoImages, which ignore HiDPI scaling")
@pytest.mark.filterwarnings("ignore:CTkLabel Warning:UserWarning")
def test_image_demo_uses_dpi_aware_images(
    tab: Any, root: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    image = tmp_path / "square.bmp"
    Image.new("RGB", (64, 64), "white").save(image)
    _load_image(tab, root, monkeypatch, image)

    shown = [
        w.cget("image")
        for w in descendants(tab)
        if isinstance(w, ctk.CTkLabel) and w.cget("image") is not None
    ]
    require(len(shown) == 3, f"expected original/ECB/CBC images, found {len(shown)}")
    assert all(isinstance(image, ctk.CTkImage) for image in shown)


# The PhotoImage warning is the HiDPI bug above; ignoring it here keeps this
# test about size only.
@known_bug("images are scaled to a fixed width only, so tall ones overflow the tab")
@pytest.mark.filterwarnings("ignore:CTkLabel Warning:UserWarning")
def test_loaded_image_fits_inside_the_tab(
    tab: Any, root: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tall_image = tmp_path / "tall.bmp"
    Image.new("RGB", (40, 2000), "white").save(tall_image)
    _load_image(tab, root, monkeypatch, tall_image)

    shown = [w for w in descendants(tab) if isinstance(w, tk.Label) and w.cget("image")]
    require(len(shown) == 3, f"expected original/ECB/CBC images, found {len(shown)}")
    for label in shown:
        height = int(label.tk.call("image", "height", label.cget("image")))
        assert height <= tab.winfo_height(), (
            f"{height}px image in a {tab.winfo_height()}px tab"
        )
