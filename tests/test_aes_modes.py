"""
Tests for modules/aes_modes.py.

Covers:
  - Known answers: FIPS 197 Appendix B, SP 800-38A Appendix F (ECB, CBC, CTR)
    and the GCM specification's test cases, down to each block's AES input
    and output
  - Round trips for every mode and key size
  - Ciphertext shape: IV, tag and padding per mode
  - What each mode reveals: ECB repeats equal blocks, the others do not
  - Block detail: each block's aes_input and keystream reproduce the real
    ciphertext, and the GCM tag is GHASH masked with AES(J0)
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
    gcm_pre_counter_block,
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


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def _gf128_multiply(x: int, y: int) -> int:
    """Multiply in GCM's GF(2^128): SP 800-38D Algorithm 1 (x0 is the top bit)."""
    r = 0xE1 << 120
    z, v = 0, y
    for bit in range(127, -1, -1):
        if (x >> bit) & 1:
            z ^= v
        v = (v >> 1) ^ r if v & 1 else v >> 1
    return z


def _ghash(h: bytes, ciphertext: bytes) -> bytes:
    """GHASH_H over the ciphertext and the length block, with no associated data."""
    padded = ciphertext + bytes(-len(ciphertext) % BLOCK_SIZE)
    lengths = (0).to_bytes(8, "big") + (8 * len(ciphertext)).to_bytes(8, "big")
    data = padded + lengths
    y, h_int = 0, int.from_bytes(h, "big")
    for i in range(0, len(data), BLOCK_SIZE):
        block = int.from_bytes(data[i : i + BLOCK_SIZE], "big")
        y = _gf128_multiply(y ^ block, h_int)
    return y.to_bytes(BLOCK_SIZE, "big")


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
# Known answers for the modes — SP 800-38A Appendix F (ECB, CBC, CTR) and the
# test cases of the GCM specification (McGrew and Viega), which SP 800-38D
# builds on. Both publish what goes through AES for each block, so the block
# detail the GUI draws is checked too, not only the ciphertext.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _KnownAnswer:
    name: str
    mode: AesMode
    key: bytes
    iv: bytes | None  # SP 800-38A's IV or initial counter block; GCM's IV
    plaintext: bytes
    aes_inputs: tuple[bytes, ...]  # "Input Block" (SP 800-38A), Y1, Y2, ... (GCM)
    keystream: tuple[bytes, ...]  # "Output Block" (CTR), E(K, Y1), ... (GCM)
    ciphertext: bytes
    tag: bytes | None = None


def _blocks(*hex_blocks: str) -> tuple[bytes, ...]:
    return tuple(bytes.fromhex(block) for block in hex_blocks)


_SP800_38A_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
_SP800_38A_PLAINTEXT = b"".join(
    _blocks(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710",
    )
)
_GCM_TC3_KEY = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
_GCM_TC3_IV = bytes.fromhex("cafebabefacedbaddecaf888")
_GCM_TC3 = _KnownAnswer(
    "GCM test case 3",
    AesMode.GCM,
    _GCM_TC3_KEY,
    _GCM_TC3_IV,
    b"".join(
        _blocks(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b391aafd255",
        )
    ),
    aes_inputs=_blocks(
        "cafebabefacedbaddecaf88800000002",
        "cafebabefacedbaddecaf88800000003",
        "cafebabefacedbaddecaf88800000004",
        "cafebabefacedbaddecaf88800000005",
    ),
    keystream=_blocks(
        "9bb22ce7d9f372c1ee2b28722b25f206",
        "650d887c3936533a1b8d4e1ea39d2b5c",
        "3de91827c10e9a4f5240647ee5221f20",
        "aac9e6ccc0074ac0873b9ba85d908bd0",
    ),
    ciphertext=b"".join(
        _blocks(
            "42831ec2217774244b7221b784d0d49c",
            "e3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa05",
            "1ba30b396a0aac973d58e091473f5985",
        )
    ),
    tag=bytes.fromhex("4d5c2af327cd64a62cf35abd2ba6fab4"),
)

_KNOWN_ANSWERS = [
    _KnownAnswer(
        "SP 800-38A F.1.1 ECB-AES128",
        AesMode.ECB,
        _SP800_38A_KEY,
        None,
        _SP800_38A_PLAINTEXT,
        aes_inputs=_blocks(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710",
        ),
        keystream=(),
        ciphertext=b"".join(
            _blocks(
                "3ad77bb40d7a3660a89ecaf32466ef97",
                "f5d3d58503b9699de785895a96fdbaaf",
                "43b1cd7f598ece23881b00e3ed030688",
                "7b0c785e27e8ad3f8223207104725dd4",
            )
        ),
    ),
    _KnownAnswer(
        "SP 800-38A F.2.1 CBC-AES128",
        AesMode.CBC,
        _SP800_38A_KEY,
        bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        _SP800_38A_PLAINTEXT,
        aes_inputs=_blocks(
            "6bc0bce12a459991e134741a7f9e1925",
            "d86421fb9f1a1eda505ee1375746972c",
            "604ed7ddf32efdff7020d0238b7c2a5d",
            "8521f2fd3c8eef2cdc3da7e5c44ea206",
        ),
        keystream=(),
        ciphertext=b"".join(
            _blocks(
                "7649abac8119b246cee98e9b12e9197d",
                "5086cb9b507219ee95db113a917678b2",
                "73bed6b8e3c1743b7116e69e22229516",
                "3ff1caa1681fac09120eca307586e1a7",
            )
        ),
    ),
    _KnownAnswer(
        "SP 800-38A F.5.1 CTR-AES128",
        AesMode.CTR,
        _SP800_38A_KEY,
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        _SP800_38A_PLAINTEXT,
        # The counter carries out of the last byte: ...feff, then ...ff00.
        aes_inputs=_blocks(
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdff00",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdff01",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdff02",
        ),
        keystream=_blocks(
            "ec8cdf7398607cb0f2d21675ea9ea1e4",
            "362b7c3c6773516318a077d7fc5073ae",
            "6a2cc3787889374fbeb4c81b17ba6c44",
            "e89c399ff0f198c6d40a31db156cabfe",
        ),
        ciphertext=b"".join(
            _blocks(
                "874d6191b620e3261bef6864990db6ce",
                "9806f66b7970fdff8617187bb9fffdff",
                "5ae4df3edbd5d35e5b4f09020db03eab",
                "1e031dda2fbe03d1792170a0f3009cee",
            )
        ),
    ),
    _KnownAnswer(
        "GCM test case 1",
        AesMode.GCM,
        bytes(16),
        bytes(12),
        b"",
        aes_inputs=(),
        keystream=(),
        ciphertext=b"",
        tag=bytes.fromhex("58e2fccefa7e3061367f1d57a4e7455a"),
    ),
    _KnownAnswer(
        "GCM test case 2",
        AesMode.GCM,
        bytes(16),
        bytes(12),
        bytes(16),
        aes_inputs=_blocks("00000000000000000000000000000002"),
        keystream=_blocks("0388dace60b6a392f328c2b971b2fe78"),
        ciphertext=bytes.fromhex("0388dace60b6a392f328c2b971b2fe78"),
        tag=bytes.fromhex("ab6e47d42cec13bdf53a67b21257bddf"),
    ),
    _GCM_TC3,
]


def _encrypt_known_answer(
    monkeypatch: pytest.MonkeyPatch, vector: _KnownAnswer
) -> EncryptionResult:
    """encrypt() always draws a fresh IV: hand it the published one instead."""

    def published_iv(size: int) -> bytes:
        if vector.iv is None or size != len(vector.iv):
            pytest.fail(f"{vector.mode} asked for a {size}-byte IV")
        return vector.iv

    monkeypatch.setattr(os, "urandom", published_iv)
    return encrypt(vector.mode, vector.plaintext, vector.key)


@pytest.mark.parametrize("vector", _KNOWN_ANSWERS, ids=lambda v: v.name)
def test_encryption_matches_the_published_ciphertext(
    monkeypatch: pytest.MonkeyPatch, vector: _KnownAnswer
) -> None:
    result = _encrypt_known_answer(monkeypatch, vector)

    if vector.mode.pads:
        # The vectors leave padding out; PKCS#7 appends a whole block to
        # these 64 bytes, so the published blocks come first.
        assert len(result.ciphertext) == len(vector.ciphertext) + BLOCK_SIZE
    assert result.ciphertext[: len(vector.ciphertext)] == vector.ciphertext
    assert (result.iv, result.tag) == (vector.iv, vector.tag)


@pytest.mark.parametrize("vector", _KNOWN_ANSWERS, ids=lambda v: v.name)
def test_each_block_shows_what_the_standard_puts_through_aes(
    monkeypatch: pytest.MonkeyPatch, vector: _KnownAnswer
) -> None:
    result = _encrypt_known_answer(monkeypatch, vector)
    shown = result.blocks[: len(vector.aes_inputs)]

    assert tuple(block.aes_input for block in shown) == vector.aes_inputs
    if vector.keystream:
        assert tuple(block.keystream for block in shown) == vector.keystream


def test_gcm_tag_matches_the_specifications_intermediate_values() -> None:
    """GCM test case 3: Tag = GHASH(H, A, C) XOR E(K, Y0), with Y0 = J0."""
    y0 = bytes.fromhex("cafebabefacedbaddecaf88800000001")
    e_k_y0 = bytes.fromhex("3247184b3c4f69a44dbcd22887bbb418")
    h = bytes.fromhex("b83b533708bf535d0aa6e52980d53b78")
    ghash = bytes.fromhex("7f1b32b81b820d02614f8895ac1d4eac")

    assert gcm_pre_counter_block(_GCM_TC3_IV) == y0  # the tag's J0 in the diagram
    assert _aes_block(_GCM_TC3_KEY, y0) == e_k_y0
    assert _aes_block(_GCM_TC3_KEY, bytes(16)) == h
    # The reference GHASH, which the tag tests below rely on, is GCM's.
    assert _ghash(h, _GCM_TC3.ciphertext) == ghash
    assert _xor(ghash, e_k_y0) == _GCM_TC3.tag


@pytest.mark.parametrize(
    "vector",
    [v for v in _KNOWN_ANSWERS if not v.mode.pads],  # the vectors carry no padding
    ids=lambda v: v.name,
)
def test_decryption_recovers_the_published_plaintext(vector: _KnownAnswer) -> None:
    published = EncryptionResult(
        mode=vector.mode,
        ciphertext=vector.ciphertext,
        blocks=(),
        iv=vector.iv,
        tag=vector.tag,
    )

    assert decrypt(published, vector.key) == vector.plaintext


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


@pytest.mark.parametrize("mode", list(AesMode))
def test_keystream_is_the_used_part_of_aes_of_the_counter(
    mode: AesMode, key128: bytes, plaintext: bytes
) -> None:
    # The fixture's last block is short, so the cut-off keystream is covered.
    for blk in encrypt(mode, plaintext, key128).blocks:
        if mode in STREAM_MODES:
            used = _aes_block(key128, blk.aes_input)[: len(blk.plaintext)]
            assert blk.keystream == used, f"block {blk.index}"
        else:
            assert blk.keystream is None


def test_gcm_tag_is_ghash_masked_with_aes_of_the_pre_counter_block(
    key128: bytes, plaintext: bytes
) -> None:
    result = encrypt(AesMode.GCM, plaintext, key128)
    assert result.iv is not None

    hash_key = _aes_block(key128, bytes(BLOCK_SIZE))  # H = AES(0^128)
    mask = _aes_block(key128, gcm_pre_counter_block(result.iv))

    assert result.tag == _xor(mask, _ghash(hash_key, result.ciphertext))


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
    assert gcm_pre_counter_block(iv) == iv + b"\x00\x00\x00\x01"
    assert gcm_counter_block(iv, 0) == iv + b"\x00\x00\x00\x02"
    assert gcm_counter_block(iv, 2**32 - 2) == iv + b"\x00\x00\x00\x00"


def test_gcm_counter_needs_a_96_bit_iv() -> None:
    with pytest.raises(ValueError, match="GCM IV must be 12 bytes"):
        gcm_counter_block(bytes(16), 0)
    with pytest.raises(ValueError, match="GCM IV must be 12 bytes"):
        gcm_pre_counter_block(bytes(16))


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
