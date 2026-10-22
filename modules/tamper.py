"""
What each AES mode does with a wrong key or a tampered ciphertext.

Encryption hides a message; on its own it does not stop anyone changing it.

- Wrong key: ECB and CBC only fail by luck, when the garbage does not end in
  valid padding; about 1 wrong key in 255 passes. CTR never notices. GCM
  always refuses.
- Tampering: an attacker who knows where some text sits in the message XORs
  the ciphertext to change it, without the key. CTR applies the edit exactly;
  CBC applies it but garbles the block before (or applies it cleanly through
  the IV, in the first block); ECB only garbles. GCM refuses the result.
"""

from __future__ import annotations

import dataclasses
import os
from dataclasses import dataclass
from enum import StrEnum

from modules.aes_modes import (
    BLOCK_SIZE,
    AesMode,
    AuthenticationError,
    EncryptionResult,
    PaddingError,
    decrypt,
)

# Garbage passes a PKCS#7 check when it ends in 01, or 02 02, ... or sixteen
# 16s: probability 256^-1 + 256^-2 + ... + 256^-16, about 1 in 255.
PADDING_FALSE_ACCEPT_RATE = sum(256.0**-k for k in range(1, BLOCK_SIZE + 1))


@dataclass(frozen=True)
class Outcome:
    """What the receiver ends up with after decrypting."""

    mode: AesMode
    plaintext: bytes | None  # None: decryption refused
    refusal: str | None = None  # why it was refused

    @property
    def accepted(self) -> bool:
        return self.plaintext is not None


def receive(encrypted: EncryptionResult, key: bytes) -> Outcome:
    """Decrypt as the receiver would: the plaintext, or the error that stops it."""
    try:
        return Outcome(encrypted.mode, decrypt(encrypted, key))
    except PaddingError:
        return Outcome(encrypted.mode, None, "bad padding")
    except AuthenticationError:
        return Outcome(encrypted.mode, None, "authentication tag mismatch")


def wrong_key(right_key: bytes) -> bytes:
    """A random key of the same size that is not *right_key*."""
    while (key := os.urandom(len(right_key))) == right_key:
        pass  # a 2^-128 chance; checked so the experiment can never lie
    return key


def count_accepted_wrong_keys(
    encrypted: EncryptionResult, right_key: bytes, trials: int
) -> int:
    """How many of *trials* random wrong keys decrypt without any error."""
    return sum(receive(encrypted, wrong_key(right_key)).accepted for _ in range(trials))


def replace_without_key(
    encrypted: EncryptionResult, plaintext: bytes, old: bytes, new: bytes
) -> EncryptionResult:
    """
    The attacker's edit: turn *old* into *new* by XORing the ciphertext.

    The attacker knows where *old* sits in *plaintext* but not the key. For
    each byte to change, they XOR in old ^ new where it reaches that plaintext
    byte: in CTR and GCM the ciphertext byte itself; in CBC the byte at the
    same place in the previous ciphertext block, or in the IV for the first
    block. ECB has no such relation, so the same edit only scrambles a block.
    """
    if not old:
        raise ValueError("there is no text to replace")
    if len(old) != len(new):
        raise ValueError("the replacement must be as long as the text it replaces")
    offset = plaintext.find(old)
    if offset < 0:
        raise ValueError("the text to replace does not occur in the message")

    ciphertext = bytearray(encrypted.ciphertext)
    iv = bytearray(encrypted.iv or b"")
    for position, (a, b) in enumerate(zip(old, new, strict=True), start=offset):
        if encrypted.mode is AesMode.CBC:
            if position < BLOCK_SIZE:
                iv[position] ^= a ^ b
            else:
                ciphertext[position - BLOCK_SIZE] ^= a ^ b
        else:
            ciphertext[position] ^= a ^ b

    return dataclasses.replace(
        encrypted,
        ciphertext=bytes(ciphertext),
        iv=None if encrypted.iv is None else bytes(iv),
        blocks=(),  # the per-block detail described the untouched ciphertext
    )


class Verdict(StrEnum):
    """How an attempted edit turned out, from the attacker's point of view."""

    REFUSED = "refused"  # the receiver noticed
    EXACT = "exact"  # the receiver got exactly the attacker's text
    WITH_DAMAGE = "with damage"  # the edit landed, but other bytes changed too
    GARBLED = "garbled"  # the edit did not land; the message is just damaged


def judge_edit(outcome: Outcome, original: bytes, wanted: bytes) -> Verdict:
    """Compare what the receiver got with the message the attacker wanted."""
    received = outcome.plaintext
    if received is None:
        return Verdict.REFUSED
    if received == wanted:
        return Verdict.EXACT
    edited = [
        i for i, (a, b) in enumerate(zip(original, wanted, strict=True)) if a != b
    ]
    if len(received) == len(wanted) and all(received[i] == wanted[i] for i in edited):
        return Verdict.WITH_DAMAGE
    return Verdict.GARBLED
