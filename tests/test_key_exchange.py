"""
Tests for modules/key_exchange.py.

Covers:
  - The RFC 3526 group: a safe prime whose generator spans the prime-order
    subgroup (a typo anywhere in the 2048-bit constant breaks this)
  - DH: public values follow from the exponents, both sides agree, fresh runs
  - Validation of received DH public values
  - ECDH: the public points and the shared secret follow from the scalars
  - Narrated steps: order, actors, and who may know each value
  - Equivalent key sizes (NIST SP 800-57)
"""

from __future__ import annotations

import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from modules.key_exchange import (
    DH_EXPONENT_BITS,
    EQUIVALENT_KEY_SIZES,
    MODP2048_GENERATOR,
    MODP2048_PRIME,
    Actor,
    DHExchange,
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


@pytest.fixture(scope="module")
def dh() -> DHExchange:
    return run_dh()


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


# ---------------------------------------------------------------------------
# The RFC 3526 group
# ---------------------------------------------------------------------------


def test_group14_prime_is_a_2048_bit_safe_prime() -> None:
    p = MODP2048_PRIME
    assert p.bit_length() == 2048
    assert _is_probable_prime(p)
    assert _is_probable_prime((p - 1) // 2)


def test_generator_spans_the_prime_order_subgroup() -> None:
    q = (MODP2048_PRIME - 1) // 2
    assert pow(MODP2048_GENERATOR, q, MODP2048_PRIME) == 1


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


@pytest.mark.parametrize(
    "bad",
    [0, 1, MODP2048_PRIME - 1, MODP2048_PRIME, MODP2048_PRIME + 1],
    ids=["0", "1", "p-1", "p", "p+1"],
)
def test_out_of_range_public_values_are_rejected(bad: int) -> None:
    with pytest.raises(KeyExchangeError, match="range"):
        validate_dh_public_value(bad)


def test_public_values_outside_the_subgroup_are_rejected() -> None:
    # p ≡ 7 (mod 8), so -1 is a non-residue and 2 a residue: -2 = p - 2 lies
    # outside the prime-order subgroup that g = 2 generates.
    with pytest.raises(KeyExchangeError, match="subgroup"):
        validate_dh_public_value(MODP2048_PRIME - 2)


def test_honest_public_values_are_accepted(dh: DHExchange) -> None:
    validate_dh_public_value(dh.alice_public)
    validate_dh_public_value(dh.bob_public)


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
    for step in steps[3:]:
        assert _values(step) == {"s": (dh.shared_secret, Visibility.SHARED_SECRET)}


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
    for step in steps[3:]:
        assert _values(step) == {"S.x": (ecdh.shared_secret, Visibility.SHARED_SECRET)}


# ---------------------------------------------------------------------------
# Equivalent key sizes
# ---------------------------------------------------------------------------


def test_equivalent_key_sizes_match_sp_800_57() -> None:
    assert [
        (level.security_bits, level.ffdh_bits, level.ecdh_bits)
        for level in EQUIVALENT_KEY_SIZES
    ] == [(128, 3072, 256), (192, 7680, 384), (256, 15360, 521)]
