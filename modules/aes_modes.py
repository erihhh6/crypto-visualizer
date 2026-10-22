"""
AES mode implementations with block-level metadata for visualization.

Supports ECB, CBC, CTR, and GCM modes using PyCA cryptography library.
Each encrypt function returns ciphertext alongside a list of BlockInfo
objects that carry per-block metadata used by the GUI canvas.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16  # AES block size in bytes


@dataclass
class BlockInfo:
    """Metadata for a single 16-byte AES block, consumed by the visualizer."""

    index: int
    plaintext_hex: str  # plaintext block as hex string
    ciphertext_hex: str  # ciphertext block as hex string
    iv_or_xor_hex: str  # IV, XOR value, or counter block as hex string
    mode_label: str  # "ECB", "CBC", "CTR", "GCM"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _pad(data: bytes) -> bytes:
    """Apply PKCS7 padding to reach a multiple of BLOCK_SIZE."""
    padder = sym_padding.PKCS7(BLOCK_SIZE * 8).padder()
    return padder.update(data) + padder.finalize()


def _unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding."""
    unpadder = sym_padding.PKCS7(BLOCK_SIZE * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def _split_blocks(data: bytes) -> list[bytes]:
    """Split *data* into 16-byte blocks (data must already be padded)."""
    return [data[i : i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def _validate_key(key: bytes) -> None:
    if len(key) not in (16, 24, 32):
        raise ValueError(f"Key must be 16, 24, or 32 bytes; got {len(key)}")


# ---------------------------------------------------------------------------
# Encrypt functions
# ---------------------------------------------------------------------------


def encrypt_ecb(plaintext: bytes, key: bytes) -> tuple[bytes, list[BlockInfo]]:
    """
    Encrypt *plaintext* with AES-ECB.

    Returns
    -------
    ciphertext : bytes
        Full encrypted payload (padded).
    blocks : list[BlockInfo]
        Per-block metadata for visualization.
    """
    _validate_key(key)
    padded = _pad(plaintext)
    pt_blocks = _split_blocks(padded)

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(padded) + encryptor.finalize()
    ct_blocks = _split_blocks(ciphertext)

    blocks: list[BlockInfo] = []
    for i, (pt, ct) in enumerate(zip(pt_blocks, ct_blocks, strict=True)):
        blocks.append(
            BlockInfo(
                index=i,
                plaintext_hex=pt.hex().upper(),
                ciphertext_hex=ct.hex().upper(),
                iv_or_xor_hex="N/A",
                mode_label="ECB",
            )
        )
    return ciphertext, blocks


def encrypt_cbc(plaintext: bytes, key: bytes) -> tuple[bytes, list[BlockInfo]]:
    """
    Encrypt *plaintext* with AES-CBC (random IV prepended to ciphertext).

    Returns
    -------
    iv_ciphertext : bytes
        IV (16 bytes) concatenated with ciphertext.
    blocks : list[BlockInfo]
        Per-block metadata; *iv_or_xor_hex* holds the XOR input for each block.
    """
    _validate_key(key)
    iv = os.urandom(BLOCK_SIZE)
    padded = _pad(plaintext)
    pt_blocks = _split_blocks(padded)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    ct_blocks = _split_blocks(ciphertext)

    blocks: list[BlockInfo] = []
    prev = iv
    for i, (pt, ct) in enumerate(zip(pt_blocks, ct_blocks, strict=True)):
        xor_input = _xor_bytes(pt, prev)
        blocks.append(
            BlockInfo(
                index=i,
                plaintext_hex=pt.hex().upper(),
                ciphertext_hex=ct.hex().upper(),
                iv_or_xor_hex=xor_input.hex().upper(),
                mode_label="CBC",
            )
        )
        prev = ct
    return iv + ciphertext, blocks


def encrypt_ctr(plaintext: bytes, key: bytes) -> tuple[bytes, list[BlockInfo]]:
    """
    Encrypt *plaintext* with AES-CTR (random nonce prepended).

    Returns
    -------
    nonce_ciphertext : bytes
        16-byte nonce followed by ciphertext.
    blocks : list[BlockInfo]
        *iv_or_xor_hex* holds the counter block used for each plaintext block.
    """
    _validate_key(key)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Build counter blocks for metadata (nonce with last 8 bytes as big-endian counter)
    pt_blocks_raw = [
        plaintext[i : i + BLOCK_SIZE] for i in range(0, len(plaintext), BLOCK_SIZE)
    ]
    ct_blocks_raw = [
        ciphertext[i : i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)
    ]

    blocks: list[BlockInfo] = []
    for i, (pt, ct) in enumerate(zip(pt_blocks_raw, ct_blocks_raw, strict=True)):
        # Counter block = nonce[:8] || big-endian counter
        counter_block = nonce[:8] + struct.pack(">Q", i)
        blocks.append(
            BlockInfo(
                index=i,
                plaintext_hex=pt.hex().upper(),
                ciphertext_hex=ct.hex().upper(),
                iv_or_xor_hex=counter_block.hex().upper(),
                mode_label="CTR",
            )
        )
    return nonce + ciphertext, blocks


def encrypt_gcm(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, list[BlockInfo]]:
    """
    Encrypt *plaintext* with AES-GCM.

    Returns
    -------
    nonce_ciphertext : bytes
        12-byte nonce followed by ciphertext.
    tag : bytes
        16-byte authentication tag.
    blocks : list[BlockInfo]
        Per-block metadata; *iv_or_xor_hex* holds the counter block.
    """
    _validate_key(key)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    pt_blocks_raw = [
        plaintext[i : i + BLOCK_SIZE] for i in range(0, len(plaintext), BLOCK_SIZE)
    ]
    ct_blocks_raw = [
        ciphertext[i : i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)
    ]

    blocks: list[BlockInfo] = []
    for i, (pt, ct) in enumerate(zip(pt_blocks_raw, ct_blocks_raw, strict=True)):
        counter_block = nonce + struct.pack(">I", i + 2)  # GCM counter starts at 2
        blocks.append(
            BlockInfo(
                index=i,
                plaintext_hex=pt.hex().upper(),
                ciphertext_hex=ct.hex().upper(),
                iv_or_xor_hex=counter_block.hex().upper(),
                mode_label="GCM",
            )
        )
    return nonce + ciphertext, tag, blocks


# ---------------------------------------------------------------------------
# Decrypt functions
# ---------------------------------------------------------------------------


def decrypt_ecb(ciphertext: bytes, key: bytes, strict: bool = True) -> bytes:
    """
    Decrypt AES-ECB ciphertext.

    Parameters
    ----------
    strict : bool
        If True (default), strip and validate PKCS7 padding.
        If False, return raw decrypted bytes without touching padding —
        useful for showing garbled output when the key is wrong.
    """
    _validate_key(key)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return _unpad(padded) if strict else padded


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes, strict: bool = True) -> bytes:
    """
    Decrypt AES-CBC ciphertext (without IV prefix).

    Parameters
    ----------
    strict : bool
        If True (default), strip and validate PKCS7 padding.
        If False, return raw decrypted bytes without touching padding.
    """
    _validate_key(key)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return _unpad(padded) if strict else padded


def decrypt_ctr(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt AES-CTR ciphertext (without nonce prefix)."""
    _validate_key(key)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def decrypt_gcm(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    """Decrypt and verify AES-GCM ciphertext (without nonce prefix)."""
    _validate_key(key)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ---------------------------------------------------------------------------
# ECB image attack
# ---------------------------------------------------------------------------


def encrypt_pixels_ecb(pixel_bytes: bytes, key: bytes) -> bytes:
    """
    Encrypt raw RGB pixel data (from PIL tobytes()) with AES-ECB.

    Returns the same number of bytes as *pixel_bytes* so the result can
    be fed directly into PIL Image.frombytes().
    """
    _validate_key(key)
    padded = _pad(pixel_bytes)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return (encryptor.update(padded) + encryptor.finalize())[: len(pixel_bytes)]


def encrypt_pixels_cbc(pixel_bytes: bytes, key: bytes) -> bytes:
    """
    Encrypt raw RGB pixel data with AES-CBC (random IV, discarded).

    Returns the same number of bytes as *pixel_bytes* so the result can
    be fed directly into PIL Image.frombytes().
    """
    _validate_key(key)
    iv = os.urandom(BLOCK_SIZE)
    padded = _pad(pixel_bytes)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return (encryptor.update(padded) + encryptor.finalize())[: len(pixel_bytes)]
