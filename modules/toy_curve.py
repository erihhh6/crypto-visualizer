"""
ECDH on a toy elliptic curve, small enough to plot every one of its points.

P-256 has about 2^256 points, so no picture can show them. The toy curve has
the same shape, y² = x³ − 3x + b over the integers mod a prime p, but with
p = 97 it has only 109 points (counting the point at infinity). The GUI replays
the ECDH exchange on it, so each step lands on a point you can see.

Never use a curve this small for real: anyone can recover a private key from
its public point by trying every multiple of G.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from modules.key_exchange import KeyExchangeError, Point


@dataclass(frozen=True)
class Curve:
    """The curve y² = x³ + ax + b over the integers mod a prime p."""

    p: int
    a: int
    b: int

    def contains(self, point: Point) -> bool:
        x, y = point
        return (y * y - (x**3 + self.a * x + self.b)) % self.p == 0

    def points(self) -> list[Point]:
        """Every point except the point at infinity (by brute force: p is tiny)."""
        roots: dict[int, list[int]] = {}
        for y in range(self.p):
            roots.setdefault(y * y % self.p, []).append(y)
        return [
            (x, y)
            for x in range(self.p)
            for y in roots.get((x**3 + self.a * x + self.b) % self.p, [])
        ]

    def add(self, first: Point | None, second: Point | None) -> Point | None:
        """
        The group law: chord through two points, tangent at one.

        None stands for the point at infinity, the group's identity.
        """
        if first is None:
            return second
        if second is None:
            return first
        p = self.p
        (x1, y1), (x2, y2) = first, second
        if x1 == x2 and (y1 + y2) % p == 0:
            return None  # P + (−P): the line is vertical
        if first == second:
            slope = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, p)  # tangent
        else:
            slope = (y2 - y1) * pow(x2 - x1, -1, p)  # chord
        x3 = (slope * slope - x1 - x2) % p
        return x3, (slope * (x1 - x3) - y1) % p

    def multiply(self, k: int, point: Point | None) -> Point | None:
        """k × point, by double-and-add."""
        if k < 0:
            raise ValueError("the scalar must not be negative")
        result: Point | None = None
        while k:
            if k & 1:
                result = self.add(result, point)
            point = self.add(point, point)
            k >>= 1
        return result


# Same a = −3 as P-256. The number of points, 109, is prime, so every point but
# the point at infinity generates the whole group, as P-256's G does.
TOY_CURVE = Curve(p=97, a=-3 % 97, b=10)
TOY_GENERATOR: Point = (1, 28)
TOY_ORDER = 109


@dataclass(frozen=True)
class ToyECDH:
    alice_private: int  # dA
    bob_private: int  # dB
    alice_public: Point  # QA = dA × G
    bob_public: Point  # QB = dB × G
    shared_point: Point  # S = dA × QB = dB × QA


def run_toy_ecdh() -> ToyECDH:
    """
    ECDH on the toy curve.

    The private keys are drawn so that G, QA, QB and S are four different
    points: a plot where two of them coincide would teach nothing.
    """
    while True:
        alice_private = 2 + secrets.randbelow(TOY_ORDER - 2)  # in [2, n - 1]
        bob_private = 2 + secrets.randbelow(TOY_ORDER - 2)
        # QA = QB needs dA = dB; S = G needs dA × dB = 1 (mod n).
        if (
            alice_private != bob_private
            and alice_private * bob_private % TOY_ORDER != 1
        ):
            break

    alice_public = _affine(TOY_CURVE.multiply(alice_private, TOY_GENERATOR))
    bob_public = _affine(TOY_CURVE.multiply(bob_private, TOY_GENERATOR))
    alice_shared = TOY_CURVE.multiply(alice_private, bob_public)
    bob_shared = TOY_CURVE.multiply(bob_private, alice_public)
    if alice_shared != bob_shared:
        raise KeyExchangeError("Alice and Bob computed different toy ECDH points")

    return ToyECDH(
        alice_private,
        bob_private,
        alice_public,
        bob_public,
        _affine(alice_shared),
    )


def _affine(point: Point | None) -> Point:
    """A point that cannot be at infinity (a multiple of G below its order)."""
    if point is None:
        raise KeyExchangeError("unexpected point at infinity")
    return point
