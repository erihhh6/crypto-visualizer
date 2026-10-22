"""
Tests for modules/aes_modes.py.

Covers:
  - Round-trip correctness for all four modes (ECB, CBC, CTR, GCM)
  - BlockInfo metadata (count, labels, hex format)
  - Displayed per-block values reproduce the real ciphertext
  - Key size validation
  - encrypt_pixels_ecb / encrypt_pixels_cbc helpers
  - NIST AES-128-ECB known-answer test (FIPS 197, Appendix B)
"""

from __future__ import annotations

import os

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from modules.aes_modes import (
    BLOCK_SIZE,
    BlockInfo,
    decrypt_cbc,
    decrypt_ctr,
    decrypt_ecb,
    decrypt_gcm,
    encrypt_cbc,
    encrypt_ctr,
    encrypt_ecb,
    encrypt_gcm,
    encrypt_pixels_cbc,
    encrypt_pixels_ecb,
)
from tests.markers import known_bug

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def key128() -> bytes:
    return os.urandom(16)


@pytest.fixture
def key192() -> bytes:
    return os.urandom(24)


@pytest.fixture
def key256() -> bytes:
    return os.urandom(32)


@pytest.fixture
def plaintext() -> bytes:
    return b"Hello, Crypto! This message spans several AES blocks."


# ---------------------------------------------------------------------------
# NIST known-answer test — FIPS 197 Appendix B
# AES-128-ECB: one block, known key and plaintext
# ---------------------------------------------------------------------------


def test_nist_ecb_known_answer() -> None:
    """Encrypt the FIPS 197 Appendix B test vector with ECB and verify."""
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    expected_ct = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

    ct, blocks = encrypt_ecb(pt, key)
    # Our implementation applies PKCS7 padding, so a 16-byte input becomes 32 bytes
    # of ciphertext (16 data + 16 padding block). Compare only the first block.
    assert ct[:16] == expected_ct, f"NIST KAT failed: got {ct[:16].hex()}"
    assert blocks[0].ciphertext_hex == expected_ct.hex().upper()


# ---------------------------------------------------------------------------
# Round-trip tests
# ---------------------------------------------------------------------------


class TestECB:
    def test_roundtrip(self, key128: bytes, plaintext: bytes) -> None:
        ct, _ = encrypt_ecb(plaintext, key128)
        assert decrypt_ecb(ct, key128) == plaintext

    def test_roundtrip_aes256(self, key256: bytes, plaintext: bytes) -> None:
        ct, _ = encrypt_ecb(plaintext, key256)
        assert decrypt_ecb(ct, key256) == plaintext

    def test_block_metadata(self, key128: bytes, plaintext: bytes) -> None:
        _, blocks = encrypt_ecb(plaintext, key128)
        assert len(blocks) > 0
        for blk in blocks:
            assert isinstance(blk, BlockInfo)
            assert blk.mode_label == "ECB"
            assert blk.iv_or_xor_hex == "N/A"
            assert all(c in "0123456789ABCDEF" for c in blk.plaintext_hex)
            assert all(c in "0123456789ABCDEF" for c in blk.ciphertext_hex)

    def test_identical_blocks_produce_identical_ciphertext(self, key128: bytes) -> None:
        """ECB's defining weakness: equal plaintext blocks → equal ciphertext blocks."""
        block = b"AAAAAAAAAAAAAAAA"  # exactly 16 bytes
        pt = block * 3
        _, blocks = encrypt_ecb(pt, key128)
        assert len({blk.ciphertext_hex for blk in blocks[:3]}) == 1

    def test_block_indices(self, key128: bytes, plaintext: bytes) -> None:
        _, blocks = encrypt_ecb(plaintext, key128)
        for i, blk in enumerate(blocks):
            assert blk.index == i

    def test_invalid_key_raises(self, plaintext: bytes) -> None:
        with pytest.raises(ValueError, match="Key must be 16, 24, or 32 bytes"):
            encrypt_ecb(plaintext, b"tooshort")


class TestCBC:
    def test_roundtrip(self, key128: bytes, plaintext: bytes) -> None:
        iv_ct, _ = encrypt_cbc(plaintext, key128)
        iv, ct = iv_ct[:16], iv_ct[16:]
        assert decrypt_cbc(ct, key128, iv) == plaintext

    def test_roundtrip_aes192(self, key192: bytes, plaintext: bytes) -> None:
        iv_ct, _ = encrypt_cbc(plaintext, key192)
        iv, ct = iv_ct[:16], iv_ct[16:]
        assert decrypt_cbc(ct, key192, iv) == plaintext

    def test_iv_prepended(self, key128: bytes, plaintext: bytes) -> None:
        iv_ct, _ = encrypt_cbc(plaintext, key128)
        assert len(iv_ct) > BLOCK_SIZE  # IV + ciphertext

    def test_different_iv_each_call(self, key128: bytes, plaintext: bytes) -> None:
        iv_ct1, _ = encrypt_cbc(plaintext, key128)
        iv_ct2, _ = encrypt_cbc(plaintext, key128)
        assert iv_ct1[:16] != iv_ct2[:16], "IV should be random per call"

    def test_metadata_mode_label(self, key128: bytes, plaintext: bytes) -> None:
        _, blocks = encrypt_cbc(plaintext, key128)
        assert all(b.mode_label == "CBC" for b in blocks)

    def test_xor_input_present(self, key128: bytes, plaintext: bytes) -> None:
        _, blocks = encrypt_cbc(plaintext, key128)
        assert all(b.iv_or_xor_hex != "N/A" for b in blocks)

    def test_identical_blocks_differ(self, key128: bytes) -> None:
        """CBC chaining: equal plaintext blocks produce different ciphertext blocks."""
        block = b"AAAAAAAAAAAAAAAA"
        pt = block * 3
        _, blocks = encrypt_cbc(pt, key128)
        ct_hexes = [b.ciphertext_hex for b in blocks]
        assert len(set(ct_hexes)) == len(ct_hexes), "CBC blocks should all differ"


class TestCTR:
    def test_roundtrip(self, key128: bytes, plaintext: bytes) -> None:
        n_ct, _ = encrypt_ctr(plaintext, key128)
        nonce, ct = n_ct[:16], n_ct[16:]
        assert decrypt_ctr(ct, key128, nonce) == plaintext

    def test_no_padding_needed(self, key128: bytes) -> None:
        """CTR is a stream cipher — ciphertext length equals plaintext length."""
        pt = b"short"
        n_ct, _ = encrypt_ctr(pt, key128)
        ct = n_ct[16:]
        assert len(ct) == len(pt)

    def test_metadata_mode_label(self, key128: bytes, plaintext: bytes) -> None:
        _, blocks = encrypt_ctr(plaintext, key128)
        assert all(b.mode_label == "CTR" for b in blocks)

    def test_counter_block_in_metadata(self, key128: bytes, plaintext: bytes) -> None:
        _, blocks = encrypt_ctr(plaintext, key128)
        assert all(b.iv_or_xor_hex != "N/A" for b in blocks)


class TestGCM:
    def test_roundtrip(self, key128: bytes, plaintext: bytes) -> None:
        n_ct, tag, _ = encrypt_gcm(plaintext, key128)
        nonce, ct = n_ct[:12], n_ct[12:]
        assert decrypt_gcm(ct, key128, nonce, tag) == plaintext

    def test_tag_length(self, key128: bytes, plaintext: bytes) -> None:
        _, tag, _ = encrypt_gcm(plaintext, key128)
        assert len(tag) == 16

    def test_tampered_tag_rejected(self, key128: bytes, plaintext: bytes) -> None:
        n_ct, tag, _ = encrypt_gcm(plaintext, key128)
        nonce, ct = n_ct[:12], n_ct[12:]
        bad_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
        with pytest.raises(InvalidTag):
            decrypt_gcm(ct, key128, nonce, bad_tag)

    def test_metadata_mode_label(self, key128: bytes, plaintext: bytes) -> None:
        _, _, blocks = encrypt_gcm(plaintext, key128)
        assert all(b.mode_label == "GCM" for b in blocks)

    def test_nonce_is_12_bytes(self, key128: bytes, plaintext: bytes) -> None:
        n_ct, _, _ = encrypt_gcm(plaintext, key128)
        assert len(n_ct[:12]) == 12


# ---------------------------------------------------------------------------
# Displayed block values vs. the real cipher
#
# The canvas teaches *how* each mode turns plaintext into ciphertext, so every
# value it shows must reproduce the ciphertext when fed to raw AES by hand.
# ---------------------------------------------------------------------------


def _aes_block(key: bytes, block: bytes) -> bytes:
    """Encrypt one 16-byte block with the bare AES permutation."""
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def _keystream_reproduces_ciphertext(key: bytes, blocks: list[BlockInfo]) -> bool:
    """For counter modes: plaintext XOR E_k(counter) must equal the ciphertext."""
    for blk in blocks:
        pt = bytes.fromhex(blk.plaintext_hex)
        keystream = _aes_block(key, bytes.fromhex(blk.iv_or_xor_hex))
        expected = bytes(p ^ k for p, k in zip(pt, keystream[: len(pt)], strict=True))
        if expected != bytes.fromhex(blk.ciphertext_hex):
            return False
    return True


class TestBlockMetadataMatchesCipher:
    def test_cbc_xor_input_encrypts_to_ciphertext(
        self, key128: bytes, plaintext: bytes
    ) -> None:
        _, blocks = encrypt_cbc(plaintext, key128)
        for blk in blocks:
            xor_input = bytes.fromhex(blk.iv_or_xor_hex)
            assert _aes_block(key128, xor_input).hex().upper() == blk.ciphertext_hex

    @known_bug(
        "CTR shows nonce[:8] || block index as the counter, but the cipher "
        "increments the whole 16-byte nonce"
    )
    def test_ctr_counter_produces_the_keystream(
        self, key128: bytes, plaintext: bytes
    ) -> None:
        _, blocks = encrypt_ctr(plaintext, key128)
        assert _keystream_reproduces_ciphertext(key128, blocks)

    def test_gcm_counter_produces_the_keystream(
        self, key128: bytes, plaintext: bytes
    ) -> None:
        _, _, blocks = encrypt_gcm(plaintext, key128)
        assert _keystream_reproduces_ciphertext(key128, blocks)


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
