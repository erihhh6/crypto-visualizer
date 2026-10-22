"""AESTab: encryption round trips, block details and the image demo."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog
from typing import Any, NamedTuple

import customtkinter as ctk
import pytest
from PIL import Image

from gui.aes_tab import AESTab
from modules.aes_modes import AesMode, PaddingError, decrypt, encrypt
from tests.gui.helpers import (
    block_canvas,
    click_block,
    descendants,
    find_button,
    label_text,
    pump,
    require,
)
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


class _Fields(NamedTuple):
    plaintext: Any
    key: Any
    decrypted: Any


def _fields(tab: Any) -> _Fields:
    """The plaintext, key and Decrypted entries, in the order they are created."""
    entries = [w for w in descendants(tab) if isinstance(w, ctk.CTkEntry)]
    require(len(entries) == 3, f"expected 3 entry fields, found {len(entries)}")
    return _Fields(*entries)


def _type(entry: Any, text: str) -> None:
    entry.delete(0, "end")
    entry.insert(0, text)


def _choose_mode(tab: Any, mode: AesMode) -> None:
    (mode_menu,) = [w for w in descendants(tab) if isinstance(w, ctk.CTkOptionMenu)]
    mode_menu.set(mode)


def _encrypt(tab: Any, mode: AesMode) -> _Fields:
    """Encrypt _MESSAGE with _RIGHT_KEY in *mode*."""
    fields = _fields(tab)
    _choose_mode(tab, mode)
    _type(fields.plaintext, _MESSAGE)
    _type(fields.key, _RIGHT_KEY.hex())
    find_button(tab, "Encrypt").invoke()
    return fields


def _encrypt_then_decrypt_with(tab: Any, mode: AesMode, decrypt_key: bytes) -> _Fields:
    """Encrypt _MESSAGE with _RIGHT_KEY, then decrypt with *decrypt_key*."""
    fields = _encrypt(tab, mode)
    block_canvas(tab)  # the blocks were drawn
    _type(fields.key, decrypt_key.hex())
    find_button(tab, "Decrypt").invoke()
    return fields


@pytest.mark.parametrize("mode", list(AesMode))
def test_decrypting_shows_the_plaintext_in_its_own_field(
    tab: Any, mode: AesMode
) -> None:
    fields = _encrypt_then_decrypt_with(tab, mode, _RIGHT_KEY)

    assert fields.decrypted.get() == _MESSAGE
    assert fields.plaintext.get() == _MESSAGE  # what the user typed is untouched


def test_wrong_key_shows_the_garbled_output_with_a_warning(
    tab: Any, no_dialogs: list[str]
) -> None:
    # A random wrong key passes the padding check 1 time in 256; this pair fails.
    with pytest.raises(PaddingError):
        decrypt(encrypt(AesMode.ECB, _MESSAGE.encode(), _RIGHT_KEY), _WRONG_KEY)

    fields = _encrypt_then_decrypt_with(tab, AesMode.ECB, _WRONG_KEY)

    assert len(no_dialogs) == 1
    assert no_dialogs[0].startswith("showwarning: Wrong key")
    assert fields.decrypted.get() not in ("", _MESSAGE)  # the garbled output
    assert fields.plaintext.get() == _MESSAGE
    no_dialogs.clear()  # the warning was the expected outcome


def test_gcm_refuses_to_decrypt_with_a_wrong_key(
    tab: Any, no_dialogs: list[str]
) -> None:
    fields = _encrypt_then_decrypt_with(tab, AesMode.GCM, _RIGHT_KEY)
    require(fields.decrypted.get() == _MESSAGE, "decryption did not fill the field")

    _type(fields.key, _WRONG_KEY.hex())
    find_button(tab, "Decrypt").invoke()

    assert len(no_dialogs) == 1
    assert no_dialogs[0].startswith("showerror: Authentication failed (GCM)")
    # GCM releases nothing, and the earlier plaintext must not linger either.
    assert fields.decrypted.get() == ""
    no_dialogs.clear()  # the error was the expected outcome


def test_encrypting_again_clears_the_previous_decryption(tab: Any) -> None:
    fields = _encrypt_then_decrypt_with(tab, AesMode.CBC, _RIGHT_KEY)
    require(fields.decrypted.get() == _MESSAGE, "decryption did not fill the field")

    find_button(tab, "Encrypt").invoke()

    assert fields.decrypted.get() == ""


@pytest.mark.parametrize(
    ("key_text", "explanation"),
    [("not hex at all", "hexadecimal"), ("00ff", "32, 48 or 64 hex digits")],
)
def test_an_invalid_key_is_explained_instead_of_used(
    tab: Any, no_dialogs: list[str], key_text: str, explanation: str
) -> None:
    _type(_fields(tab).key, key_text)

    find_button(tab, "Encrypt").invoke()

    assert len(no_dialogs) == 1
    assert no_dialogs[0].startswith("showerror: Invalid key")
    assert explanation in no_dialogs[0]
    no_dialogs.clear()  # the explanation was the expected outcome


def test_an_empty_key_field_gets_a_fresh_aes128_key(tab: Any) -> None:
    fields = _fields(tab)
    _type(fields.key, "")

    find_button(tab, "Encrypt").invoke()

    assert len(bytes.fromhex(fields.key.get())) == 16


def _details(tab: Any) -> str:
    """Text of the read-only panel that describes the clicked block."""
    panels = [w for w in descendants(tab) if isinstance(w, tk.Text)]
    require(len(panels) == 1, f"expected one detail panel, found {len(panels)}")
    return str(panels[0].get("1.0", "end-1c"))


def test_detail_panel_shows_a_placeholder_before_any_click(tab: Any) -> None:
    assert _details(tab).strip()


def test_clicking_a_block_shows_its_details(tab: Any) -> None:
    _encrypt(tab, AesMode.CBC)

    click_block(block_canvas(tab), 1)

    details = _details(tab)
    assert details.startswith("Block 1 — CBC\nC1 = AES(P1 ⊕ C0)")
    assert _MESSAGE.encode()[16:32].hex().upper() in details


def test_encrypting_again_clears_the_block_details(tab: Any) -> None:
    _encrypt(tab, AesMode.CBC)
    placeholder = _details(tab)
    click_block(block_canvas(tab), 1)
    require(_details(tab) != placeholder, "clicking a block showed no details")

    find_button(tab, "Encrypt").invoke()  # new IV: block 1 is different now

    assert _details(tab) == placeholder


def test_encrypting_fills_the_comparison_for_every_mode(tab: Any) -> None:
    _encrypt(tab, AesMode.CBC)

    shown = [label_text(w) for w in descendants(tab) if isinstance(w, ctk.CTkLabel)]
    assert "(no data)" not in shown
    # ECB has no IV, so its ciphertext for this key is known in advance.
    ecb = encrypt(AesMode.ECB, _MESSAGE.encode(), _RIGHT_KEY).ciphertext.hex().upper()
    assert ecb[:64] + "…" in shown


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
