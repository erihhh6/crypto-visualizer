"""
Tests for modules/key_exchange.py.

Covers:
  - The RFC 3526 groups: each prime is the number its definition from π gives,
    a safe prime whose generator spans the prime-order subgroup
  - DH in both groups: public values follow from the exponents, both sides
    agree, fresh runs
  - Validation of received DH public values
  - ECDH: the public points and the shared secret follow from the scalars
  - The AES key: HKDF-SHA256 of the (padded) shared secret, per RFC 5869
  - Narrated steps: order, actors, and who may know each value
  - Equivalent key sizes (NIST SP 800-57)
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from modules.key_exchange import (
    AES_KEY_INFO,
    DH_EXPONENT_BITS,
    DH_GROUPS,
    EQUIVALENT_KEY_SIZES,
    MODP_2048,
    MODP_3072,
    Actor,
    DHExchange,
    DHGroup,
    ECDHExchange,
    KeyExchangeError,
    Step,
    Visibility,
    dh_steps,
    ecdh_steps,
    run_dh,
    run_ecdh,
    validate_dh_public_value,
)

STORY_ACTORS = [
    Actor.SYSTEM,
    Actor.ALICE,
    Actor.BOB,
    Actor.ALICE,
    Actor.BOB,
    Actor.BOTH,
]


def _group_id(group: DHGroup) -> str:
    return f"{group.bits}-bit"


@pytest.fixture(scope="module", params=DH_GROUPS, ids=_group_id)
def dh(request: pytest.FixtureRequest) -> DHExchange:
    group: DHGroup = request.param
    return run_dh(group)


@pytest.fixture(scope="module")
def ecdh() -> ECDHExchange:
    return run_ecdh()


def _is_probable_prime(n: int, rounds: int = 20) -> bool:
    """Miller-Rabin: a composite survives with probability below 4**-rounds."""
    if n < 4:
        return n in (2, 3)
    if n % 2 == 0:
        return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _values(step: Step) -> dict[str, tuple[object, Visibility]]:
    return {v.symbol: (v.value, v.visibility) for v in step.values}


def _pi_times_2_to(bits: int) -> int:
    """⌊2^bits × π⌋, from Machin's formula in exact integer arithmetic."""
    guard = 64  # extra bits absorb the rounding of every series term
    one = 1 << (bits + guard)

    def arctan_inv(x: int) -> int:  # arctan(1/x) × one
        total, power, n, sign = 0, one // x, 1, 1
        while power:
            total += sign * (power // n)
            power //= x * x
            n += 2
            sign = -sign
        return total

    return (16 * arctan_inv(5) - 4 * arctan_inv(239)) >> guard


def _hkdf_sha256(ikm: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF with no salt (HashLen zero bytes), from the standard library."""
    prk = hmac.new(bytes(32), ikm, hashlib.sha256).digest()
    okm, block = b"", b""
    for counter in range(1, -(-length // 32) + 1):
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
    return okm[:length]


# ---------------------------------------------------------------------------
# The RFC 3526 groups
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("group", "c"),
    [(MODP_2048, 124476), (MODP_3072, 1690314)],
    ids=["2048-bit", "3072-bit"],
)
def test_each_prime_is_what_rfc_3526_defines(group: DHGroup, c: int) -> None:
    """p = 2^n − 2^(n−64) − 1 + 2^64 × (⌊2^(n−130) π⌋ + c), RFC 3526."""
    n = group.bits
    assert group.p == 2**n - 2 ** (n - 64) - 1 + 2**64 * (_pi_times_2_to(n - 130) + c)


@pytest.mark.parametrize("group", DH_GROUPS, ids=_group_id)
def test_each_group_is_a_safe_prime_with_a_prime_order_generator(
    group: DHGroup,
) -> None:
    p, q = group.p, (group.p - 1) // 2
    assert _is_probable_prime(p)
    assert _is_probable_prime(q)
    assert pow(group.g, q, p) == 1  # g generates the subgroup of order q


def test_group_sizes_and_strengths_follow_sp_800_57() -> None:
    assert (MODP_2048.bits, MODP_2048.security_bits) == (2048, 112)
    assert (MODP_3072.bits, MODP_3072.security_bits) == (3072, 128)
    # 3072-bit DH sits on the same 128-bit row as 256-bit ECDH.
    assert (128, 3072, 256) in [
        (level.security_bits, level.ffdh_bits, level.ecdh_bits)
        for level in EQUIVALENT_KEY_SIZES
    ]


def test_dh_defaults_to_the_group_that_matches_p256() -> None:
    assert run_dh().group is MODP_3072


# ---------------------------------------------------------------------------
# Diffie-Hellman
# ---------------------------------------------------------------------------


def test_dh_public_values_follow_from_the_exponents(dh: DHExchange) -> None:
    assert dh.alice_public == pow(dh.g, dh.alice_private, dh.p)
    assert dh.bob_public == pow(dh.g, dh.bob_private, dh.p)


def test_dh_both_sides_derive_the_same_secret(dh: DHExchange) -> None:
    assert dh.shared_secret == pow(dh.bob_public, dh.alice_private, dh.p)
    assert dh.shared_secret == pow(dh.alice_public, dh.bob_private, dh.p)


def test_dh_private_exponents_are_short_but_large_enough(dh: DHExchange) -> None:
    for exponent in (dh.alice_private, dh.bob_private):
        assert 2 <= exponent < 2**DH_EXPONENT_BITS


def test_each_dh_run_uses_fresh_exponents() -> None:
    assert run_dh().alice_private != run_dh().alice_private


_OUT_OF_RANGE: dict[str, Callable[[int], int]] = {
    "0": lambda _p: 0,
    "1": lambda _p: 1,
    "p-1": lambda p: p - 1,
    "p": lambda p: p,
    "p+1": lambda p: p + 1,
}


@pytest.mark.parametrize("group", DH_GROUPS, ids=_group_id)
@pytest.mark.parametrize("bad", _OUT_OF_RANGE.values(), ids=_OUT_OF_RANGE.keys())
def test_out_of_range_public_values_are_rejected(
    group: DHGroup, bad: Callable[[int], int]
) -> None:
    with pytest.raises(KeyExchangeError, match="range"):
        validate_dh_public_value(bad(group.p), group)


@pytest.mark.parametrize("group", DH_GROUPS, ids=_group_id)
def test_public_values_outside_the_subgroup_are_rejected(group: DHGroup) -> None:
    # p ≡ 7 (mod 8), so -1 is a non-residue and 2 a residue: -2 = p - 2 lies
    # outside the prime-order subgroup that g = 2 generates.
    assert group.p % 8 == 7
    with pytest.raises(KeyExchangeError, match="subgroup"):
        validate_dh_public_value(group.p - 2, group)


def test_honest_public_values_are_accepted(dh: DHExchange) -> None:
    validate_dh_public_value(dh.alice_public, dh.group)
    validate_dh_public_value(dh.bob_public, dh.group)


# ---------------------------------------------------------------------------
# ECDH
# ---------------------------------------------------------------------------


def test_ecdh_public_points_follow_from_the_scalars(ecdh: ECDHExchange) -> None:
    for scalar, point in (
        (ecdh.alice_private, ecdh.alice_public),
        (ecdh.bob_private, ecdh.bob_public),
    ):
        numbers = ec.derive_private_key(scalar, ec.SECP256R1()).public_key()
        assert (numbers.public_numbers().x, numbers.public_numbers().y) == point


def test_ecdh_shared_secret_follows_from_the_scalars(ecdh: ECDHExchange) -> None:
    alice = ec.derive_private_key(ecdh.alice_private, ec.SECP256R1())
    bob = ec.derive_private_key(ecdh.bob_private, ec.SECP256R1())
    assert alice.exchange(ec.ECDH(), bob.public_key()) == ecdh.shared_secret
    assert len(ecdh.shared_secret) == 32  # the x-coordinate of a P-256 point


def test_each_ecdh_run_uses_fresh_keys() -> None:
    assert run_ecdh().alice_public != run_ecdh().alice_public


# ---------------------------------------------------------------------------
# The AES key
# ---------------------------------------------------------------------------


def test_dh_key_is_hkdf_of_the_shared_secret(dh: DHExchange) -> None:
    secret = dh.shared_secret.to_bytes((dh.p.bit_length() + 7) // 8, "big")
    assert dh.key == _hkdf_sha256(secret, AES_KEY_INFO, 32)


def test_the_dh_secret_is_left_padded_to_the_length_of_p(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # a = 1 and b = 8 give s = 2^8 = 256: two bytes, padded to the 384 of p.
    exponents = iter([1, 8])
    monkeypatch.setattr(
        "modules.key_exchange._dh_private_exponent", lambda: next(exponents)
    )

    exchange = run_dh(MODP_3072)

    assert exchange.shared_secret == 256
    assert exchange.key == _hkdf_sha256((256).to_bytes(384, "big"), AES_KEY_INFO, 32)


def test_ecdh_key_is_hkdf_of_the_shared_x_coordinate(ecdh: ECDHExchange) -> None:
    assert ecdh.key == _hkdf_sha256(ecdh.shared_secret, AES_KEY_INFO, 32)


# ---------------------------------------------------------------------------
# Narrated steps
# ---------------------------------------------------------------------------


def test_dh_story_has_six_steps_in_order(dh: DHExchange) -> None:
    steps = dh_steps(dh)
    assert [s.number for s in steps] == [1, 2, 3, 4, 5, 6]
    assert [s.actor for s in steps] == STORY_ACTORS


def test_dh_public_parameters_are_marked_public(dh: DHExchange) -> None:
    assert _values(dh_steps(dh)[0]) == {
        "p": (dh.p, Visibility.PUBLIC),
        "g": (dh.g, Visibility.PUBLIC),
    }


def test_dh_steps_carry_the_exchange_values(dh: DHExchange) -> None:
    steps = dh_steps(dh)
    assert _values(steps[1]) == {
        "a": (dh.alice_private, Visibility.PRIVATE),
        "A": (dh.alice_public, Visibility.PUBLIC),
    }
    assert _values(steps[2]) == {
        "b": (dh.bob_private, Visibility.PRIVATE),
        "B": (dh.bob_public, Visibility.PUBLIC),
    }
    for step in steps[3:5]:
        assert _values(step) == {"s": (dh.shared_secret, Visibility.SHARED_SECRET)}
    assert _values(steps[5]) == {"K": (dh.key, Visibility.SHARED_SECRET)}


def test_dh_first_step_names_the_group_and_its_strength(dh: DHExchange) -> None:
    description = dh_steps(dh)[0].description
    assert f"{dh.group.bits}-bit prime ({dh.group.name})" in description
    expected = "like P-256" if dh.group is MODP_3072 else "below P-256's 128"
    assert f"about {dh.group.security_bits}-bit security, {expected}" in description


def test_ecdh_story_has_six_steps_in_order(ecdh: ECDHExchange) -> None:
    steps = ecdh_steps(ecdh)
    assert [s.number for s in steps] == [1, 2, 3, 4, 5, 6]
    assert [s.actor for s in steps] == STORY_ACTORS


def test_ecdh_steps_carry_the_exchange_values(ecdh: ECDHExchange) -> None:
    steps = ecdh_steps(ecdh)
    assert _values(steps[0]) == {"curve": ("secp256r1", Visibility.PUBLIC)}
    assert _values(steps[1]) == {
        "dA": (ecdh.alice_private, Visibility.PRIVATE),
        "QA": (ecdh.alice_public, Visibility.PUBLIC),
    }
    assert _values(steps[2]) == {
        "dB": (ecdh.bob_private, Visibility.PRIVATE),
        "QB": (ecdh.bob_public, Visibility.PUBLIC),
    }
    for step in steps[3:5]:
        assert _values(step) == {"S.x": (ecdh.shared_secret, Visibility.SHARED_SECRET)}
    assert _values(steps[5]) == {"K": (ecdh.key, Visibility.SHARED_SECRET)}


# ---------------------------------------------------------------------------
# Equivalent key sizes
# ---------------------------------------------------------------------------


def test_equivalent_key_sizes_match_sp_800_57() -> None:
    assert [
        (level.security_bits, level.ffdh_bits, level.ecdh_bits)
        for level in EQUIVALENT_KEY_SIZES
    ] == [(128, 3072, 256), (192, 7680, 384), (256, 15360, 521)]
