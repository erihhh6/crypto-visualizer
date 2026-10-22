"""
Tests for modules/aes_modes.py.

Covers:
  - NIST AES-128 known-answer test (FIPS 197, Appendix B)
  - Round trips for every mode and key size
  - Ciphertext shape: IV, tag and padding per mode
  - What each mode reveals: ECB repeats equal blocks, the others do not
  - Block detail: each block's aes_input reproduces the real ciphertext
  - Counter-block arithmetic at overflow (CTR, GCM)
  - Decryption failures: PaddingError (ECB, CBC), AuthenticationError (GCM)
  - Key parsing (hex) and validation, malformed input
  - encrypt_pixels_ecb / encrypt_pixels_cbc helpers
"""

from __future__ import annotations

import dataclasses
import os

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from modules.aes_modes import (
    BLOCK_SIZE,
    GCM_IV_SIZE,
    GCM_TAG_SIZE,
    KEY_SIZES,
    AesMode,
    AuthenticationError,
    EncryptionResult,
    PaddingError,
    ctr_counter_block,
    decrypt,
    encrypt,
    encrypt_pixels_cbc,
    encrypt_pixels_ecb,
    gcm_counter_block,
    key_from_hex,
)

STREAM_MODES = [AesMode.CTR, AesMode.GCM]  # XOR a keystream; no padding
RANDOMISED_MODES = [AesMode.CBC, AesMode.CTR, AesMode.GCM]

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def key128() -> bytes:
    return os.urandom(16)


@pytest.fixture
def plaintext() -> bytes:
    return b"Hello, Crypto! This message spans several AES blocks."


def _aes_block(key: bytes, block: bytes) -> bytes:
    """Encrypt one 16-byte block with the bare AES permutation."""
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def _flip_first_byte(data: bytes) -> bytes:
    return bytes([data[0] ^ 0x01]) + data[1:]


# ---------------------------------------------------------------------------
# NIST known-answer test — FIPS 197 Appendix B
# ---------------------------------------------------------------------------


def test_nist_fips197_known_answer() -> None:
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    expected_ct = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

    result = encrypt(AesMode.ECB, pt, key)

    # PKCS#7 adds a whole padding block to a 16-byte message; the first block
    # is the plain AES encryption the standard specifies.
    assert len(result.blocks) == 2
    assert result.blocks[0].ciphertext == expected_ct


# ---------------------------------------------------------------------------
# Round trips and ciphertext shape
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key_size", KEY_SIZES)
@pytest.mark.parametrize("mode", list(AesMode))
def test_decrypt_restores_the_plaintext(
    mode: AesMode, key_size: int, plaintext: bytes
) -> None:
    key = os.urandom(key_size)
    assert decrypt(encrypt(mode, plaintext, key), key) == plaintext


@pytest.mark.parametrize("mode", list(AesMode))
def test_empty_plaintext_round_trips(mode: AesMode, key128: bytes) -> None:
    assert decrypt(encrypt(mode, b"", key128), key128) == b""


@pytest.mark.parametrize(
    ("mode", "iv_size"),
    [
        (AesMode.ECB, None),
        (AesMode.CBC, BLOCK_SIZE),
        (AesMode.CTR, BLOCK_SIZE),
        (AesMode.GCM, GCM_IV_SIZE),
    ],
)
def test_iv_size_per_mode(
    mode: AesMode, iv_size: int | None, key128: bytes, plaintext: bytes
) -> None:
    iv = encrypt(mode, plaintext, key128).iv
    assert (None if iv is None else len(iv)) == iv_size


@pytest.mark.parametrize("mode", RANDOMISED_MODES)
def test_every_encryption_gets_a_fresh_iv(
    mode: AesMode, key128: bytes, plaintext: bytes
) -> None:
    assert encrypt(mode, plaintext, key128).iv != encrypt(mode, plaintext, key128).iv


@pytest.mark.parametrize("mode", list(AesMode))
def test_only_gcm_carries_a_full_length_tag(
    mode: AesMode, key128: bytes, plaintext: bytes
) -> None:
    tag = encrypt(mode, plaintext, key128).tag
    expected = GCM_TAG_SIZE if mode is AesMode.GCM else None
    assert (None if tag is None else len(tag)) == expected


@pytest.mark.parametrize("mode", list(AesMode))
def test_only_block_modes_pad(mode: AesMode, key128: bytes) -> None:
    ciphertext = encrypt(mode, b"short", key128).ciphertext
    assert len(ciphertext) == (BLOCK_SIZE if mode.pads else len(b"short"))


# ---------------------------------------------------------------------------
# What each mode reveals
# ---------------------------------------------------------------------------


def test_ecb_encrypts_equal_blocks_to_equal_ciphertext(key128: bytes) -> None:
    """ECB's defining weakness: repeated plaintext blocks show through."""
    blocks = encrypt(AesMode.ECB, b"A" * BLOCK_SIZE * 3, key128).blocks
    assert len({blk.ciphertext for blk in blocks[:3]}) == 1


@pytest.mark.parametrize("mode", RANDOMISED_MODES)
def test_other_modes_hide_repeated_blocks(mode: AesMode, key128: bytes) -> None:
    blocks = encrypt(mode, b"A" * BLOCK_SIZE * 3, key128).blocks
    assert len({blk.ciphertext for blk in blocks[:3]}) == 3


# ---------------------------------------------------------------------------
# Block detail vs. the real cipher
#
# The canvas teaches *how* each mode turns plaintext into ciphertext, so every
# value it shows must reproduce the ciphertext when fed to raw AES by hand.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", list(AesMode))
def test_blocks_cover_the_message_in_order(
    mode: AesMode, key128: bytes, plaintext: bytes
) -> None:
    result = encrypt(mode, plaintext, key128)

    assert [blk.index for blk in result.blocks] == list(range(len(result.blocks)))
    assert b"".join(blk.ciphertext for blk in result.blocks) == result.ciphertext
    # ECB and CBC show the padded message; CTR and GCM the message itself.
    assert b"".join(blk.plaintext for blk in result.blocks).startswith(plaintext)


@pytest.mark.parametrize("mode", list(AesMode))
def test_aes_input_reproduces_the_ciphertext(
    mode: AesMode, key128: bytes, plaintext: bytes
) -> None:
    for blk in encrypt(mode, plaintext, key128).blocks:
        aes_output = _aes_block(key128, blk.aes_input)
        if mode in STREAM_MODES:
            # Stream modes XOR the AES output (the keystream) into the plaintext.
            keystream = aes_output[: len(blk.plaintext)]
            expected = bytes(
                p ^ k for p, k in zip(blk.plaintext, keystream, strict=True)
            )
        else:
            expected = aes_output
        assert expected == blk.ciphertext, f"block {blk.index}"


# A random initial counter practically never overflows within one message,
# so the carry and wrap-around paths are pinned with chosen values.
@pytest.mark.parametrize(
    ("initial", "expected_next"),
    [
        pytest.param(
            bytes(8) + b"\xff" * 8,
            bytes(7) + b"\x01" + bytes(8),
            id="carries-into-high-half",
        ),
        pytest.param(b"\xff" * 16, bytes(16), id="wraps-at-2^128"),
    ],
)
def test_ctr_counter_follows_the_cipher_through_overflow(
    key128: bytes, initial: bytes, expected_next: bytes
) -> None:
    assert ctr_counter_block(initial, 1) == expected_next

    # Encrypting zeros returns the raw keystream: E_k(counter) per block.
    encryptor = Cipher(algorithms.AES(key128), modes.CTR(initial)).encryptor()
    keystream = encryptor.update(bytes(2 * BLOCK_SIZE)) + encryptor.finalize()
    assert keystream[BLOCK_SIZE:] == _aes_block(key128, expected_next)


def test_gcm_counter_starts_at_two_and_wraps_in_32_bits() -> None:
    iv = os.urandom(GCM_IV_SIZE)
    assert gcm_counter_block(iv, 0) == iv + b"\x00\x00\x00\x02"
    assert gcm_counter_block(iv, 2**32 - 2) == iv + b"\x00\x00\x00\x00"


def test_gcm_counter_needs_a_96_bit_iv() -> None:
    with pytest.raises(ValueError, match="GCM IV must be 12 bytes"):
        gcm_counter_block(bytes(16), 0)


# ---------------------------------------------------------------------------
# Decryption failures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", [AesMode.ECB, AesMode.CBC])
def test_invalid_padding_raises_with_the_raw_output(
    mode: AesMode, key128: bytes
) -> None:
    # A block that decrypts to sixteen 0x00 bytes: 0x00 is never valid PKCS#7
    # padding, so this is deterministic (a random wrong key passes 1 in 256).
    iv = os.urandom(BLOCK_SIZE) if mode is AesMode.CBC else None
    ciphertext = _aes_block(key128, iv or bytes(BLOCK_SIZE))  # CBC XORs the IV back
    encrypted = EncryptionResult(mode, ciphertext, blocks=(), iv=iv)

    with pytest.raises(PaddingError) as caught:
        decrypt(encrypted, key128)
    assert caught.value.raw == bytes(BLOCK_SIZE)


def test_gcm_rejects_a_modified_ciphertext(key128: bytes, plaintext: bytes) -> None:
    result = encrypt(AesMode.GCM, plaintext, key128)
    tampered = dataclasses.replace(
        result, ciphertext=_flip_first_byte(result.ciphertext)
    )
    with pytest.raises(AuthenticationError):
        decrypt(tampered, key128)


def test_gcm_rejects_a_modified_tag(key128: bytes, plaintext: bytes) -> None:
    result = encrypt(AesMode.GCM, plaintext, key128)
    assert result.tag is not None
    tampered = dataclasses.replace(result, tag=_flip_first_byte(result.tag))
    with pytest.raises(AuthenticationError):
        decrypt(tampered, key128)


def test_gcm_rejects_a_wrong_key(key128: bytes, plaintext: bytes) -> None:
    with pytest.raises(AuthenticationError):
        decrypt(encrypt(AesMode.GCM, plaintext, key128), os.urandom(16))


def test_ctr_cannot_detect_a_wrong_key(key128: bytes, plaintext: bytes) -> None:
    """CTR has no integrity check: a wrong key 'succeeds' with garbage."""
    garbage = decrypt(encrypt(AesMode.CTR, plaintext, key128), os.urandom(16))
    assert len(garbage) == len(plaintext)
    assert garbage != plaintext


# ---------------------------------------------------------------------------
# Key validation and malformed input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size", [0, 8, 15, 17, 33])
def test_encrypt_rejects_invalid_key_sizes(size: int, plaintext: bytes) -> None:
    with pytest.raises(ValueError, match="Key must be 16, 24, or 32 bytes"):
        encrypt(AesMode.ECB, plaintext, bytes(size))


def test_key_from_hex_ignores_whitespace_and_case() -> None:
    typed = " 00112233 44556677\t8899AaBb ccDDeeFF \n"
    assert key_from_hex(typed) == bytes.fromhex("00112233445566778899aabbccddeeff")


@pytest.mark.parametrize(
    ("typed", "explanation"),
    [
        ("not hex", "hexadecimal"),
        ("0" * 31, "hexadecimal"),  # an odd digit count is not whole bytes
        ("00ff", "32, 48 or 64 hex digits"),
        ("0" * 66, "32, 48 or 64 hex digits"),
    ],
)
def test_key_from_hex_explains_what_is_wrong(typed: str, explanation: str) -> None:
    with pytest.raises(ValueError, match=explanation):
        key_from_hex(typed)


def test_decrypt_rejects_invalid_key_sizes(key128: bytes, plaintext: bytes) -> None:
    with pytest.raises(ValueError, match="Key must be 16, 24, or 32 bytes"):
        decrypt(encrypt(AesMode.ECB, plaintext, key128), b"tooshort")


@pytest.mark.parametrize("mode", RANDOMISED_MODES)
def test_decrypt_without_iv_is_rejected(mode: AesMode, key128: bytes) -> None:
    encrypted = EncryptionResult(mode, bytes(BLOCK_SIZE), blocks=(), tag=bytes(16))
    with pytest.raises(ValueError, match="missing IV"):
        decrypt(encrypted, key128)


# ---------------------------------------------------------------------------
# Pixel encrypt helpers
# ---------------------------------------------------------------------------


class TestPixelHelpers:
    def test_ecb_output_length(self, key128: bytes) -> None:
        raw = os.urandom(200 * 200 * 3)
        out = encrypt_pixels_ecb(raw, key128)
        assert len(out) == len(raw)

    def test_cbc_output_length(self, key128: bytes) -> None:
        raw = os.urandom(200 * 200 * 3)
        out = encrypt_pixels_cbc(raw, key128)
        assert len(out) == len(raw)

    def test_ecb_deterministic_for_same_key(self, key128: bytes) -> None:
        """ECB is deterministic — same pixels + key always give same output."""
        raw = os.urandom(16 * 10)
        assert encrypt_pixels_ecb(raw, key128) == encrypt_pixels_ecb(raw, key128)

    def test_cbc_random_each_call(self, key128: bytes) -> None:
        """CBC uses a random IV each call, so output differs even for same input."""
        raw = os.urandom(16 * 10)
        assert encrypt_pixels_cbc(raw, key128) != encrypt_pixels_cbc(raw, key128)

    def test_ecb_pattern_leakage(self, key128: bytes) -> None:
        """Identical pixel blocks produce identical encrypted blocks (ECB weakness)."""
        block = bytes([128, 0, 0]) * (BLOCK_SIZE // 3 + 1)
        block = block[:BLOCK_SIZE]
        raw = block * 4
        out = encrypt_pixels_ecb(raw, key128)
        # All four 16-byte blocks of output should be identical
        chunks = [out[i : i + BLOCK_SIZE] for i in range(0, len(out), BLOCK_SIZE)]
        assert chunks[0] == chunks[1] == chunks[2] == chunks[3]
