"""
AES modes of operation (ECB, CBC, CTR, GCM) with per-block detail for teaching.

PyCA cryptography does the actual encryption. Alongside the ciphertext,
encrypt() records for every 16-byte block the value that went through the AES
block function, so the GUI can show how each mode turns plaintext into
ciphertext. Everything here is raw bytes; formatting is the GUI's job.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    CipherContext,
    algorithms,
    modes,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BLOCK_SIZE = 16  # AES block size in bytes
KEY_SIZES = (16, 24, 32)  # AES-128, AES-192, AES-256
# 96 bits: the IV length SP 800-38D recommends, which makes the first counter
# block simply IV || 0x00000001 (see gcm_counter_block).
GCM_IV_SIZE = 12
GCM_TAG_SIZE = 16  # full-length tag; AESGCM appends it to the ciphertext


class AesMode(StrEnum):
    """The block cipher modes of operation the visualiser demonstrates."""

    ECB = "ECB"
    CBC = "CBC"
    CTR = "CTR"
    GCM = "GCM"

    @property
    def pads(self) -> bool:
        """ECB and CBC encrypt whole blocks only, so plaintext is PKCS#7 padded."""
        return self in (AesMode.ECB, AesMode.CBC)


@dataclass(frozen=True)
class Block:
    """
    One block of an encryption (in CTR and GCM the last may be shorter).

    *aes_input* is the 16 bytes that went through the AES block function:

    - ECB: the plaintext block itself
    - CBC: the plaintext block XOR the previous ciphertext block (the IV first)
    - CTR, GCM: the counter block; the ciphertext is plaintext XOR AES(counter)

    *keystream* (CTR, GCM only) is the part of AES(counter) that was XORed into
    the plaintext: as many bytes as the block has, so a short last block uses
    only the start of it.
    """

    index: int
    plaintext: bytes
    aes_input: bytes
    ciphertext: bytes
    keystream: bytes | None = None


@dataclass(frozen=True)
class EncryptionResult:
    """Everything needed to decrypt again (given the key), plus per-block detail."""

    mode: AesMode
    ciphertext: bytes
    blocks: tuple[Block, ...]
    # CBC: IV. CTR: initial counter block. GCM: the 96-bit IV. ECB: none.
    iv: bytes | None = None
    tag: bytes | None = None  # GCM authentication tag


class DecryptionError(Exception):
    """The ciphertext could not be decrypted with the given key."""


class PaddingError(DecryptionError):
    """
    ECB/CBC: the decrypted data does not end in valid PKCS#7 padding.

    This almost always means a wrong key. *raw* holds the decrypted bytes with
    the padding left in place, so the GUI can show what a wrong key produces.
    """

    def __init__(self, raw: bytes) -> None:
        super().__init__("invalid PKCS#7 padding: the key is probably wrong")
        self.raw = raw


class AuthenticationError(DecryptionError):
    """GCM: the authentication tag does not match (wrong key or altered data)."""


def key_from_hex(text: str) -> bytes:
    """
    Parse an AES key typed as hexadecimal; whitespace between bytes is ignored.

    Raises ValueError with a message fit to show the user.
    """
    try:
        key = bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError(
            "Key must be hexadecimal: digits 0-9 and A-F, two per byte."
        ) from exc
    _validate_key(key)
    return key


# ---------------------------------------------------------------------------
# Counter blocks
# ---------------------------------------------------------------------------


def ctr_counter_block(initial_counter: bytes, block_index: int) -> bytes:
    """
    Return the counter block that AES-CTR encrypts for block *block_index*.

    The cipher treats all 16 bytes of the initial counter block as one
    big-endian integer: block i uses initial + i, carrying across the 64-bit
    boundary and wrapping at 2**128. Many protocols lay the block out as
    nonce || counter instead; PyCA does not, so the display must not either.
    """
    value = int.from_bytes(initial_counter, "big") + block_index
    return (value % (1 << 128)).to_bytes(BLOCK_SIZE, "big")


def gcm_counter_block(iv: bytes, block_index: int) -> bytes:
    """
    Return the counter block that AES-GCM encrypts for data block *block_index*.

    With a 96-bit IV, SP 800-38D starts from J0 = IV || 1 and reserves J0 for
    the tag, so data block i uses IV || (i + 2), where only the last 32 bits
    count (and wrap at 2**32).
    """
    _check_gcm_iv(iv)
    return iv + ((block_index + 2) % (1 << 32)).to_bytes(4, "big")


def gcm_pre_counter_block(iv: bytes) -> bytes:
    """
    Return J0, the pre-counter block of AES-GCM with a 96-bit IV: IV || 1.

    No data block uses it: it masks the tag, Tag = AES(J0) XOR GHASH(ciphertext).
    """
    _check_gcm_iv(iv)
    return iv + (1).to_bytes(4, "big")


def _check_gcm_iv(iv: bytes) -> None:
    if len(iv) != GCM_IV_SIZE:
        raise ValueError(f"GCM IV must be {GCM_IV_SIZE} bytes; got {len(iv)}")


# ---------------------------------------------------------------------------
# Encrypt / decrypt
# ---------------------------------------------------------------------------


def encrypt(mode: AesMode, plaintext: bytes, key: bytes) -> EncryptionResult:
    """Encrypt *plaintext* under *key* with a fresh random IV where *mode* needs one."""
    _validate_key(key)
    data = _pad(plaintext) if mode.pads else plaintext
    iv, ciphertext, tag = _seal(mode, data, key)
    return EncryptionResult(
        mode=mode,
        ciphertext=ciphertext,
        blocks=_describe_blocks(mode, data, ciphertext, iv),
        iv=iv,
        tag=tag,
    )


def decrypt(encrypted: EncryptionResult, key: bytes) -> bytes:
    """
    Decrypt *encrypted* with *key* and return the original plaintext.

    Raises PaddingError (ECB, CBC) or AuthenticationError (GCM) when the key is
    wrong. CTR has no such check: a wrong key silently yields garbage.
    """
    _validate_key(key)
    data = _open(encrypted, key)
    if not encrypted.mode.pads:
        return data
    try:
        return _unpad(data)
    except ValueError as exc:
        raise PaddingError(data) from exc


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


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _validate_key(key: bytes) -> None:
    if len(key) not in KEY_SIZES:
        raise ValueError(
            f"Key must be 16, 24, or 32 bytes (32, 48 or 64 hex digits); "
            f"got {len(key)} bytes"
        )


def _pad(data: bytes) -> bytes:
    """Apply PKCS7 padding to reach a multiple of BLOCK_SIZE."""
    padder = sym_padding.PKCS7(BLOCK_SIZE * 8).padder()
    return padder.update(data) + padder.finalize()


def _unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding (ValueError if it is not valid)."""
    unpadder = sym_padding.PKCS7(BLOCK_SIZE * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()


_COUNTER_MODES = (AesMode.CTR, AesMode.GCM)  # encrypt counters into a keystream


def _split_blocks(data: bytes) -> list[bytes]:
    """Split *data* into 16-byte blocks; the last one may be shorter."""
    return [data[i : i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def _apply(context: CipherContext, data: bytes) -> bytes:
    return context.update(data) + context.finalize()


def _seal(
    mode: AesMode, data: bytes, key: bytes
) -> tuple[bytes | None, bytes, bytes | None]:
    """Encrypt (already padded) *data* with a fresh IV: (iv, ciphertext, tag)."""
    aes = algorithms.AES(key)
    match mode:
        case AesMode.ECB:
            return None, _apply(Cipher(aes, modes.ECB()).encryptor(), data), None
        case AesMode.CBC:
            iv = os.urandom(BLOCK_SIZE)
            return iv, _apply(Cipher(aes, modes.CBC(iv)).encryptor(), data), None
        case AesMode.CTR:
            iv = os.urandom(BLOCK_SIZE)
            return iv, _apply(Cipher(aes, modes.CTR(iv)).encryptor(), data), None
        case AesMode.GCM:
            iv = os.urandom(GCM_IV_SIZE)
            sealed = AESGCM(key).encrypt(iv, data, None)  # ciphertext || tag
            return iv, sealed[:-GCM_TAG_SIZE], sealed[-GCM_TAG_SIZE:]


def _open(encrypted: EncryptionResult, key: bytes) -> bytes:
    """Decrypt to the still-padded data, verifying the tag for GCM."""
    aes = algorithms.AES(key)
    ciphertext = encrypted.ciphertext
    match encrypted.mode:
        case AesMode.ECB:
            return _apply(Cipher(aes, modes.ECB()).decryptor(), ciphertext)
        case AesMode.CBC:
            iv = _required(encrypted.iv, "IV")
            return _apply(Cipher(aes, modes.CBC(iv)).decryptor(), ciphertext)
        case AesMode.CTR:
            iv = _required(encrypted.iv, "IV")
            return _apply(Cipher(aes, modes.CTR(iv)).decryptor(), ciphertext)
        case AesMode.GCM:
            iv = _required(encrypted.iv, "IV")
            tag = _required(encrypted.tag, "authentication tag")
            try:
                return AESGCM(key).decrypt(iv, ciphertext + tag, None)
            except InvalidTag as exc:
                raise AuthenticationError("GCM authentication tag mismatch") from exc


def _required(value: bytes | None, what: str) -> bytes:
    """A parameter the mode cannot work without (absent only in malformed input)."""
    if value is None:
        raise ValueError(f"missing {what}")
    return value


def _describe_blocks(
    mode: AesMode, plaintext: bytes, ciphertext: bytes, iv: bytes | None
) -> tuple[Block, ...]:
    """Pair up plaintext and ciphertext blocks with the AES input of each."""
    pt_blocks = _split_blocks(plaintext)
    ct_blocks = _split_blocks(ciphertext)
    aes_inputs = _aes_inputs(mode, pt_blocks, ct_blocks, iv)
    return tuple(
        Block(
            index,
            pt,
            aes_input,
            ct,
            # C = P XOR keystream, so the keystream is P XOR C.
            keystream=_xor_bytes(pt, ct) if mode in _COUNTER_MODES else None,
        )
        for index, (pt, aes_input, ct) in enumerate(
            zip(pt_blocks, aes_inputs, ct_blocks, strict=True)
        )
    )


def _aes_inputs(
    mode: AesMode, pt_blocks: list[bytes], ct_blocks: list[bytes], iv: bytes | None
) -> list[bytes]:
    """What each block fed through the AES block function (see Block)."""
    if mode is AesMode.ECB:
        return pt_blocks
    if iv is None:
        raise ValueError(f"{mode} needs an IV")
    match mode:
        case AesMode.CBC:
            # Each plaintext block is XORed with the previous ciphertext block,
            # and the first one with the IV.
            previous = [iv, *ct_blocks[:-1]]
            return [
                _xor_bytes(pt, prev)
                for pt, prev in zip(pt_blocks, previous, strict=True)
            ]
        case AesMode.CTR:
            return [ctr_counter_block(iv, i) for i in range(len(pt_blocks))]
        case AesMode.GCM:
            return [gcm_counter_block(iv, i) for i in range(len(pt_blocks))]
