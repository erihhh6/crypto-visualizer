"""
Tests for modules/toy_curve.py.

Covers:
  - The toy curve's parameters: prime field, smooth curve, prime group order
  - The group law and double-and-add, checked against PyCA on real P-256
  - The toy ECDH exchange, and why its keys are no secret at all
"""

from __future__ import annotations

import random

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from modules.toy_curve import (
    TOY_CURVE,
    TOY_GENERATOR,
    TOY_ORDER,
    Curve,
    run_toy_ecdh,
)

# FIPS 186-4 D.1.2.3. The generator is not copied in: PyCA supplies it.
P256 = Curve(
    p=2**256 - 2**224 + 2**192 + 2**96 - 1,
    a=-3,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
)


def _is_prime(n: int) -> bool:
    return n > 1 and all(n % d for d in range(2, int(n**0.5) + 1))


def _pyca_public_point(k: int) -> tuple[int, int]:
    numbers = ec.derive_private_key(k, ec.SECP256R1()).public_key().public_numbers()
    return numbers.x, numbers.y


# ---------------------------------------------------------------------------
# The toy curve
# ---------------------------------------------------------------------------


def test_the_toy_curve_is_a_smooth_curve_over_a_prime_field() -> None:
    p, a, b = TOY_CURVE.p, TOY_CURVE.a, TOY_CURVE.b
    assert _is_prime(p)
    assert a == p - 3  # a = −3, as in P-256
    assert (4 * a**3 + 27 * b**2) % p != 0  # no cusps or self-crossings


def test_g_generates_every_point_of_the_toy_curve() -> None:
    points = TOY_CURVE.points()
    multiples = [TOY_CURVE.multiply(k, TOY_GENERATOR) for k in range(1, TOY_ORDER)]

    assert all(TOY_CURVE.contains(point) for point in points)
    assert len(points) + 1 == TOY_ORDER  # plus the point at infinity
    assert _is_prime(TOY_ORDER)
    assert set(multiples) == set(points)
    assert TOY_CURVE.multiply(TOY_ORDER, TOY_GENERATOR) is None


def test_the_toy_group_law() -> None:
    curve, points = TOY_CURVE, TOY_CURVE.points()
    rng = random.Random(0)
    for _ in range(300):
        p, q, r = rng.choice(points), rng.choice(points), rng.choice(points)
        negative_p = (p[0], -p[1] % curve.p)
        assert curve.add(p, None) == curve.add(None, p) == p  # identity
        assert curve.add(p, negative_p) is None  # inverse
        assert curve.add(p, q) == curve.add(q, p)
        assert curve.add(curve.add(p, q), r) == curve.add(p, curve.add(q, r))
        total = curve.add(p, q)
        assert total is None or curve.contains(total)


def test_multiply_is_repeated_addition() -> None:
    expected = None
    for k in range(TOY_ORDER + 2):
        assert TOY_CURVE.multiply(k, TOY_GENERATOR) == expected, f"k = {k}"
        expected = TOY_CURVE.add(expected, TOY_GENERATOR)


def test_multiply_rejects_a_negative_scalar() -> None:
    with pytest.raises(ValueError, match="negative"):
        TOY_CURVE.multiply(-1, TOY_GENERATOR)


@pytest.mark.parametrize("k", [1, 2, 3, 0xDEADBEEF, 2**255 + 12345])
def test_the_same_arithmetic_reproduces_pyca_on_p256(k: int) -> None:
    generator = _pyca_public_point(1)
    assert P256.contains(generator)

    assert P256.multiply(k, generator) == _pyca_public_point(k)


# ---------------------------------------------------------------------------
# Toy ECDH
# ---------------------------------------------------------------------------


def test_toy_ecdh_agrees_on_four_distinct_points() -> None:
    curve, g = TOY_CURVE, TOY_GENERATOR
    for _ in range(200):
        ex = run_toy_ecdh()

        assert ex.alice_public == curve.multiply(ex.alice_private, g)
        assert ex.bob_public == curve.multiply(ex.bob_private, g)
        assert ex.shared_point == curve.multiply(ex.alice_private, ex.bob_public)
        assert ex.shared_point == curve.multiply(ex.bob_private, ex.alice_public)
        assert len({g, ex.alice_public, ex.bob_public, ex.shared_point}) == 4


def test_toy_ecdh_redraws_keys_that_would_overlap_points(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # randbelow(n - 2) + 2 gives the keys: (2, 55) has dA × dB = 110 = 1 mod 109,
    # so S = G; (7, 7) makes QA = QB; (12, 22) is fine.
    draws = iter([0, 53, 5, 5, 10, 20])
    monkeypatch.setattr("modules.toy_curve.secrets.randbelow", lambda _n: next(draws))

    ex = run_toy_ecdh()

    assert (ex.alice_private, ex.bob_private) == (12, 22)


def test_a_toy_private_key_is_found_by_trying_every_multiple() -> None:
    """Why the toy curve is only for pictures: its discrete log is trivial."""
    ex = run_toy_ecdh()

    found = next(
        k
        for k in range(1, TOY_ORDER)
        if TOY_CURVE.multiply(k, TOY_GENERATOR) == ex.alice_public
    )

    assert found == ex.alice_private
