"""AESTab: round trips, block details, the mode comparison and the image demo."""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from pathlib import Path
from tkinter import filedialog
from typing import Any, NamedTuple

import customtkinter as ctk
import pytest
from PIL import Image

from gui.aes_tab import AESTab
from gui.mode_comparison import NEUTRAL, BlockStrip, ModeCard
from gui.palette import PANEL, TEXT, resolve
from modules.aes_modes import AesMode, PaddingError, decrypt, encrypt
from tests.gui.helpers import (
    block_canvas,
    click_block,
    descendants,
    find_button,
    item_option,
    label_text,
    pump,
    require,
)

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


def _encrypt(tab: Any, mode: AesMode, message: str = _MESSAGE) -> _Fields:
    """Encrypt *message* with _RIGHT_KEY in *mode*."""
    fields = _fields(tab)
    _choose_mode(tab, mode)
    _type(fields.plaintext, message)
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


def _press_enter(tab: Any, entry: Any) -> None:
    """Press Enter in a CustomTkinter entry, as Tk delivers it: to the focus."""
    (inner,) = [w for w in descendants(entry) if isinstance(w, tk.Entry)]
    inner.focus_force()
    pump(tab, 30)
    inner.event_generate("<Return>")


@pytest.mark.parametrize("field", ["plaintext", "key"])
def test_enter_in_the_plaintext_or_the_key_encrypts(tab: Any, field: str) -> None:
    fields = _fields(tab)
    _choose_mode(tab, AesMode.CBC)
    _type(fields.plaintext, _MESSAGE)
    _type(fields.key, _RIGHT_KEY.hex())

    _press_enter(tab, getattr(fields, field))

    click_block(block_canvas(tab), 1)  # the message was encrypted and drawn
    assert _details(tab).startswith("Block 1 — CBC")


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


def test_the_details_box_follows_the_theme(
    tab: Any, switch_appearance: Callable[[str], None]
) -> None:
    (details,) = [w for w in descendants(tab) if isinstance(w, tk.Text)]

    for mode, colour in (("Dark", 1), ("Light", 0)):
        switch_appearance(mode)
        assert (details["background"], details["foreground"]) == (
            PANEL[colour],
            TEXT[colour],
        )


def test_encrypting_again_clears_the_block_details(tab: Any) -> None:
    _encrypt(tab, AesMode.CBC)
    placeholder = _details(tab)
    click_block(block_canvas(tab), 1)
    require(_details(tab) != placeholder, "clicking a block showed no details")

    find_button(tab, "Encrypt").invoke()  # new IV: block 1 is different now

    assert _details(tab) == placeholder


# ---------------------------------------------------------------------------
# Mode comparison
# ---------------------------------------------------------------------------


def _cards(tab: Any) -> dict[AesMode, Any]:
    return {w.mode: w for w in descendants(tab) if isinstance(w, ModeCard)}


def _card_text(card: Any) -> str:
    labels = [w for w in descendants(card) if isinstance(w, ctk.CTkLabel)]
    return " ".join(label_text(w) for w in labels)


def _strip_colours(strip: BlockStrip) -> list[str]:
    return [item_option(strip, i, "fill") for i in strip.find_withtag("chip")]


def _colours(tab: Any) -> tuple[list[str], dict[AesMode, list[str]]]:
    """The colours of the plaintext's squares, and of each mode card's."""
    strips = [w for w in descendants(tab) if isinstance(w, BlockStrip)]
    (plaintext,) = [s for s in strips if not isinstance(s.master, ModeCard)]
    cards = {
        mode: _strip_colours(
            next(w for w in descendants(card) if isinstance(w, BlockStrip))
        )
        for mode, card in _cards(tab).items()
    }
    return _strip_colours(plaintext), cards


def test_each_card_gives_the_length_iv_and_tag(tab: Any) -> None:
    _encrypt(tab, AesMode.CBC)  # 44 bytes: ECB and CBC pad them to 48

    texts = {mode: _card_text(card) for mode, card in _cards(tab).items()}
    assert "48 bytes (padded) · no IV" in texts[AesMode.ECB]
    assert "48 bytes (padded) · IV " in texts[AesMode.CBC]
    assert "44 bytes · counter " in texts[AesMode.CTR]
    assert "44 bytes · IV " in texts[AesMode.GCM]
    assert " · tag " in texts[AesMode.GCM]


def test_only_ecb_repeats_the_plaintexts_pattern(tab: Any) -> None:
    _encrypt(tab, AesMode.CBC, "YELLOW SUBMARINE" * 2 + "!")

    plaintext, cards = _colours(tab)
    require(
        plaintext[0] == plaintext[1] != resolve(NEUTRAL) == plaintext[2],
        f"the two equal plaintext blocks are not marked: {plaintext}",
    )
    assert cards[AesMode.ECB] == plaintext
    for mode in (AesMode.CBC, AesMode.CTR, AesMode.GCM):
        assert set(cards[mode]) == {resolve(NEUTRAL)}, mode


def test_the_selected_modes_card_is_the_encryption_drawn_above(tab: Any) -> None:
    _encrypt(tab, AesMode.CBC)
    canvas = block_canvas(tab)
    x0, y0, x1, y1 = canvas.bbox("iv&&box")
    canvas.event_generate("<Button-1>", x=(x0 + x1) // 2, y=(y0 + y1) // 2)
    drawn_iv = _details(tab).splitlines()[-1].strip()
    require(len(drawn_iv) == 32, f"no IV in the details: {_details(tab)!r}")

    cards = _cards(tab)
    assert f"IV {drawn_iv[:6]}…" in _card_text(cards[AesMode.CBC])
    marked = [mode for mode, card in cards.items() if "drawn above" in _card_text(card)]
    assert marked == [AesMode.CBC]


def _load_image(
    tab: Any, root: Any, monkeypatch: pytest.MonkeyPatch, path: Path
) -> None:
    """Click "Open image…" and pick *path* in the (stubbed) file dialog."""
    monkeypatch.setattr(filedialog, "askopenfilename", lambda **_: str(path))
    find_button(tab, "Open image").invoke()
    pump(root)


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


def _views(tab: Any) -> list[tuple[int, int]]:
    """Each view's height, and the height of the label that has to hold it."""
    shown = [w for w in descendants(tab) if isinstance(w, tk.Label) and w.cget("image")]
    require(len(shown) == 3, f"expected original/ECB/CBC images, found {len(shown)}")
    return [
        (int(w.tk.call("image", "height", w.cget("image"))), w.master.winfo_height())
        for w in shown
    ]


def test_the_views_shrink_to_fit_a_small_window_and_grow_back(
    tab: Any, root: Any
) -> None:
    find_button(tab, "Use Sample").invoke()
    pump(root)
    full = _views(tab)

    root.geometry("900x450")
    pump(root, 300)
    small = _views(tab)
    root.geometry("1100x700")
    pump(root, 300)

    assert all(height <= room for height, room in small)
    assert small[0][0] < full[0][0]
    assert _views(tab) == full


def _size_note(tab: Any) -> str:
    notes = [
        label_text(w)
        for w in descendants(tab)
        if isinstance(w, ctk.CTkLabel) and "pixels encrypted" in label_text(w)
    ]
    require(len(notes) == 1, f"expected one size note, found {notes}")
    return notes[0]


def test_a_large_image_is_shrunk_and_says_so(
    tab: Any, root: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    large = tmp_path / "large.png"
    Image.new("RGB", (1200, 800), "white").save(large)

    _load_image(tab, root, monkeypatch, large)

    assert _size_note(tab) == "512×341 pixels encrypted (shrunk from 1200×800)"


def test_the_sample_image_is_shown_at_full_size(tab: Any, root: Any) -> None:
    find_button(tab, "Use Sample").invoke()
    pump(root)

    assert _size_note(tab) == "200×200 pixels encrypted"


def test_an_unreadable_file_is_explained(
    tab: Any,
    root: Any,
    no_dialogs: list[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    not_an_image = tmp_path / "notes.png"
    not_an_image.write_text("just text")

    _load_image(tab, root, monkeypatch, not_an_image)

    assert len(no_dialogs) == 1
    assert no_dialogs[0].startswith("showerror: Cannot open image")
    no_dialogs.clear()  # the explanation was the expected outcome
