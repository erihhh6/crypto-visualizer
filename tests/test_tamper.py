"""
Tests for modules/tamper.py.

Covers:
  - What a receiver gets with a wrong key, mode by mode, and how often
  - The attacker's XOR edit, and how each mode's receiver ends up
  - Input checks for the edit
"""

from __future__ import annotations

import os
import random

import pytest

from modules.aes_modes import BLOCK_SIZE, AesMode, encrypt
from modules.tamper import (
    PADDING_FALSE_ACCEPT_RATE,
    Verdict,
    count_accepted_wrong_keys,
    judge_edit,
    receive,
    replace_without_key,
    wrong_key,
)

KEY = bytes(range(16))
MESSAGE = b"Transfer from Alice to Bob: 100 EUR"  # "100" is in block 1


@pytest.fixture
def seeded_urandom(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every random key and IV reproducible, so counts are exact."""
    rng = random.Random(1)
    monkeypatch.setattr(os, "urandom", rng.randbytes)


# ---------------------------------------------------------------------------
# Wrong keys
# ---------------------------------------------------------------------------


def test_the_padding_false_accept_rate_is_about_1_in_255() -> None:
    assert pytest.approx(1 / 255) == PADDING_FALSE_ACCEPT_RATE


@pytest.mark.usefixtures("seeded_urandom")
@pytest.mark.parametrize("mode", [AesMode.ECB, AesMode.CBC])
def test_padding_lets_about_1_wrong_key_in_255_through(mode: AesMode) -> None:
    trials = 50_000  # expect 196 ± 14

    accepted = count_accepted_wrong_keys(encrypt(mode, MESSAGE, KEY), KEY, trials)

    assert 140 < accepted < 255, f"1 in {trials / accepted:.0f}"


@pytest.mark.parametrize(("mode", "rate"), [(AesMode.CTR, 1.0), (AesMode.GCM, 0.0)])
def test_ctr_accepts_every_wrong_key_and_gcm_none(mode: AesMode, rate: float) -> None:
    trials = 500

    accepted = count_accepted_wrong_keys(encrypt(mode, MESSAGE, KEY), KEY, trials)

    assert accepted == rate * trials


@pytest.mark.parametrize(
    ("mode", "refusal"),
    [(AesMode.ECB, "bad padding"), (AesMode.GCM, "authentication tag mismatch")],
)
def test_a_refusal_says_why(mode: AesMode, refusal: str) -> None:
    encrypted = encrypt(mode, MESSAGE, KEY)
    # The first key that fails: for ECB most do, for GCM all of them.
    outcome = next(
        o
        for o in (receive(encrypted, bytes([n]) * 16) for n in range(256))
        if not o.accepted
    )

    assert outcome.plaintext is None
    assert outcome.refusal == refusal


def test_a_wrong_key_with_lucky_padding_returns_garbage() -> None:
    encrypted = encrypt(AesMode.ECB, MESSAGE, KEY)
    lucky = next(
        o
        for o in (receive(encrypted, n.to_bytes(16, "big")) for n in range(1, 20_000))
        if o.accepted
    )

    assert lucky.plaintext not in (None, MESSAGE)
    assert lucky.refusal is None


def test_wrong_key_never_returns_the_right_one(monkeypatch: pytest.MonkeyPatch) -> None:
    draws = iter([KEY, bytes(16)])  # the first draw happens to be the right key
    monkeypatch.setattr(os, "urandom", lambda _n: next(draws))

    assert wrong_key(KEY) == bytes(16)


# ---------------------------------------------------------------------------
# Editing the ciphertext without the key
# ---------------------------------------------------------------------------


def _edit(mode: AesMode, old: bytes, new: bytes) -> tuple[bytes | None, Verdict]:
    forged = replace_without_key(encrypt(mode, MESSAGE, KEY), MESSAGE, old, new)
    outcome = receive(forged, KEY)
    return outcome.plaintext, judge_edit(outcome, MESSAGE, MESSAGE.replace(old, new))


@pytest.mark.parametrize(
    ("mode", "verdict"),
    [
        (AesMode.ECB, Verdict.GARBLED),
        (AesMode.CBC, Verdict.WITH_DAMAGE),
        (AesMode.CTR, Verdict.EXACT),
        (AesMode.GCM, Verdict.REFUSED),
    ],
)
def test_each_mode_meets_the_same_edit_differently(
    mode: AesMode, verdict: Verdict
) -> None:
    assert _edit(mode, b"100", b"900")[1] is verdict


def test_cbc_garbles_exactly_the_block_before_the_edit() -> None:
    received, _ = _edit(AesMode.CBC, b"100", b"900")
    assert received is not None
    wanted = MESSAGE.replace(b"100", b"900")

    assert received[BLOCK_SIZE:] == wanted[BLOCK_SIZE:]
    assert received[:BLOCK_SIZE] != wanted[:BLOCK_SIZE]


def test_cbc_edits_the_first_block_cleanly_through_the_iv() -> None:
    assert _edit(AesMode.CBC, b"Transfer", b"Withdraw")[1] is Verdict.EXACT


def test_a_cbc_edit_across_a_block_boundary_cannot_land_whole() -> None:
    # "Alice" spans bytes 14 to 18. Its block-1 part goes through C0, which
    # garbles all of block 0, including the part edited through the IV.
    received, verdict = _edit(AesMode.CBC, b"Alice", b"Mallo")
    assert received is not None

    assert verdict is Verdict.GARBLED
    assert received[BLOCK_SIZE:].startswith(b"llo to Bob")


def test_ecb_garbles_the_edited_block_and_nothing_else() -> None:
    received, _ = _edit(AesMode.ECB, b"100", b"900")
    assert received is not None
    block = slice(BLOCK_SIZE, 2 * BLOCK_SIZE)  # "100" is in block 1

    assert received[block] != MESSAGE[block]
    assert received[: block.start] == MESSAGE[: block.start]
    assert received[block.stop :] == MESSAGE[block.stop :]


def test_the_forgery_leaves_the_original_untouched() -> None:
    encrypted = encrypt(AesMode.CTR, MESSAGE, KEY)
    before = encrypted.ciphertext

    forged = replace_without_key(encrypted, MESSAGE, b"100", b"900")

    assert encrypted.ciphertext == before
    assert forged.ciphertext != before
    assert forged.blocks == ()  # the block detail described the original


@pytest.mark.parametrize(
    ("old", "new", "problem"),
    [
        (b"", b"", "no text to replace"),
        (b"100", b"1000", "as long as"),
        (b"200", b"900", "does not occur"),
    ],
)
def test_impossible_edits_are_explained(old: bytes, new: bytes, problem: str) -> None:
    with pytest.raises(ValueError, match=problem):
        replace_without_key(encrypt(AesMode.CTR, MESSAGE, KEY), MESSAGE, old, new)
