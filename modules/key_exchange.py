"""
Diffie-Hellman (finite field) and ECDH key agreement, told step by step.

run_dh() and run_ecdh() perform a real exchange and return every value
involved; dh_steps() and ecdh_steps() turn an exchange into the narrated steps
the GUI animates. Values stay raw (ints, bytes, points): formatting them is the
GUI's job.

DH uses the 2048-bit MODP group 14 from RFC 3526; ECDH uses NIST P-256
(secp256r1) through PyCA cryptography.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias

from cryptography.hazmat.primitives.asymmetric import ec

# RFC 3526 group 14: a 2048-bit safe prime p = 2q + 1, with generator 2.
MODP2048_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
MODP2048_GENERATOR = 2

# Private exponents are 256 random bits: at least twice the group's ~112-bit
# security strength, as short-exponent DH requires, and far cheaper than a
# full 2048-bit exponent.
DH_EXPONENT_BITS = 256

Point: TypeAlias = tuple[int, int]
RawValue: TypeAlias = int | bytes | str | Point


class Actor(StrEnum):
    SYSTEM = "System"
    ALICE = "Alice"
    BOB = "Bob"
    BOTH = "Both"


class Visibility(StrEnum):
    """Who may know a value."""

    PUBLIC = "public"  # anyone, eavesdroppers included
    PRIVATE = "private"  # its owner only; never sent and never shown
    SHARED_SECRET = "shared secret"  # Alice and Bob only; never sent


@dataclass(frozen=True)
class Value:
    symbol: str
    value: RawValue
    visibility: Visibility


@dataclass(frozen=True)
class Step:
    """One step of the story: who acts, what happens, which values appear."""

    number: int
    actor: Actor
    description: str
    values: tuple[Value, ...]


@dataclass(frozen=True)
class DHExchange:
    p: int
    g: int
    alice_private: int  # a
    bob_private: int  # b
    alice_public: int  # A = g^a mod p
    bob_public: int  # B = g^b mod p
    shared_secret: int  # g^(ab) mod p


@dataclass(frozen=True)
class ECDHExchange:
    curve_name: str
    alice_private: int  # dA
    bob_private: int  # dB
    alice_public: Point  # QA = dA × G
    bob_public: Point  # QB = dB × G
    shared_secret: bytes  # x-coordinate of dA × dB × G


@dataclass(frozen=True)
class SecurityLevel:
    """Key sizes giving about the same security (NIST SP 800-57 Part 1, Table 2)."""

    security_bits: int  # comparable symmetric key strength
    ffdh_bits: int  # finite-field DH (and RSA) modulus size
    ecdh_bits: int  # elliptic-curve key size


EQUIVALENT_KEY_SIZES = (
    SecurityLevel(128, 3072, 256),
    SecurityLevel(192, 7680, 384),
    # SP 800-57 asks for 512+ bits here; the standard curve is P-521.
    SecurityLevel(256, 15360, 521),
)


class KeyExchangeError(Exception):
    """A received public value is unsafe, or the two sides disagree."""


# ---------------------------------------------------------------------------
# Classical (finite-field) Diffie-Hellman
# ---------------------------------------------------------------------------


def run_dh() -> DHExchange:
    """Perform a full DH exchange in RFC 3526 group 14."""
    p, g = MODP2048_PRIME, MODP2048_GENERATOR
    a = _dh_private_exponent()
    b = _dh_private_exponent()
    alice_public = pow(g, a, p)
    bob_public = pow(g, b, p)

    # Each side checks the value it receives before raising it to its secret.
    validate_dh_public_value(bob_public, p)
    validate_dh_public_value(alice_public, p)
    alice_shared = pow(bob_public, a, p)
    bob_shared = pow(alice_public, b, p)
    if alice_shared != bob_shared:
        raise KeyExchangeError("Alice and Bob computed different DH secrets")

    return DHExchange(p, g, a, b, alice_public, bob_public, alice_shared)


def validate_dh_public_value(y: int, p: int = MODP2048_PRIME) -> None:
    """
    Reject a received DH public value that would expose the shared secret.

    0, 1 and p - 1 make the secret predictable, so y must lie in [2, p - 2].
    For a safe prime p = 2q + 1 it must also lie in the subgroup of prime
    order q (y^q = 1 mod p); otherwise a malicious peer could confine the
    secret to a tiny subgroup and guess it.
    """
    if not 2 <= y <= p - 2:
        raise KeyExchangeError("DH public value is outside the range [2, p - 2]")
    if pow(y, (p - 1) // 2, p) != 1:
        raise KeyExchangeError("DH public value is not in the prime-order subgroup")


def dh_steps(exchange: DHExchange) -> tuple[Step, ...]:
    """The DH exchange as six narrated steps."""
    public, private, shared = (
        Visibility.PUBLIC,
        Visibility.PRIVATE,
        Visibility.SHARED_SECRET,
    )
    secret = Value("s", exchange.shared_secret, shared)
    return (
        Step(
            1,
            Actor.SYSTEM,
            "Public parameters are agreed in advance:\n"
            "  p = a 2048-bit prime (RFC 3526 group 14)\n"
            "  g = 2, the generator\n"
            "Everyone knows them, eavesdroppers included.",
            (Value("p", exchange.p, public), Value("g", exchange.g, public)),
        ),
        Step(
            2,
            Actor.ALICE,
            "Alice picks a secret random exponent a,\n"
            "then computes her public value:\n"
            "  A = g^a mod p\n"
            "She sends A to Bob.",
            (
                Value("a", exchange.alice_private, private),
                Value("A", exchange.alice_public, public),
            ),
        ),
        Step(
            3,
            Actor.BOB,
            "Bob picks a secret random exponent b,\n"
            "then computes his public value:\n"
            "  B = g^b mod p\n"
            "He sends B to Alice.",
            (
                Value("b", exchange.bob_private, private),
                Value("B", exchange.bob_public, public),
            ),
        ),
        Step(
            4,
            Actor.ALICE,
            "Alice receives Bob's public value B.\n"
            "She computes the shared secret:\n"
            "  s = B^a mod p\n"
            "It is never sent over the wire.",
            (secret,),
        ),
        Step(
            5,
            Actor.BOB,
            "Bob receives Alice's public value A.\n"
            "He computes the shared secret:\n"
            "  s = A^b mod p\n"
            "It is never sent over the wire.",
            (secret,),
        ),
        Step(
            6,
            Actor.BOTH,
            "Both now hold the same s = g^(ab) mod p\n"
            "without ever sending a or b.\n"
            "A key derivation function turns s into symmetric keys.",
            (secret,),
        ),
    )


def _dh_private_exponent() -> int:
    """A random exponent in [2, 2^DH_EXPONENT_BITS)."""
    return 2 + secrets.randbelow(2**DH_EXPONENT_BITS - 2)


# ---------------------------------------------------------------------------
# ECDH (NIST P-256)
# ---------------------------------------------------------------------------


def run_ecdh() -> ECDHExchange:
    """Perform a full ECDH exchange on P-256."""
    curve = ec.SECP256R1()
    alice = ec.generate_private_key(curve)
    bob = ec.generate_private_key(curve)

    alice_shared = alice.exchange(ec.ECDH(), bob.public_key())
    bob_shared = bob.exchange(ec.ECDH(), alice.public_key())
    if alice_shared != bob_shared:
        raise KeyExchangeError("Alice and Bob computed different ECDH secrets")

    return ECDHExchange(
        curve_name=curve.name,
        alice_private=alice.private_numbers().private_value,
        bob_private=bob.private_numbers().private_value,
        alice_public=_point(alice.public_key()),
        bob_public=_point(bob.public_key()),
        shared_secret=alice_shared,
    )


def ecdh_steps(exchange: ECDHExchange) -> tuple[Step, ...]:
    """The ECDH exchange as six narrated steps."""
    public, private, shared = (
        Visibility.PUBLIC,
        Visibility.PRIVATE,
        Visibility.SHARED_SECRET,
    )
    secret = Value("S.x", exchange.shared_secret, shared)
    return (
        Step(
            1,
            Actor.SYSTEM,
            "Public parameters are agreed in advance:\n"
            "  Curve: NIST P-256 (secp256r1)\n"
            "    y² = x³ − 3x + b  (mod p)\n"
            "  and its generator point G.\n"
            "They are standardised and public.",
            (Value("curve", exchange.curve_name, public),),
        ),
        Step(
            2,
            Actor.ALICE,
            "Alice picks a secret random scalar dA,\n"
            "then computes her public key point:\n"
            "  QA = dA × G  (point multiplication)\n"
            "She sends QA (x, y) to Bob.",
            (
                Value("dA", exchange.alice_private, private),
                Value("QA", exchange.alice_public, public),
            ),
        ),
        Step(
            3,
            Actor.BOB,
            "Bob picks a secret random scalar dB,\n"
            "then computes his public key point:\n"
            "  QB = dB × G  (point multiplication)\n"
            "He sends QB (x, y) to Alice.",
            (
                Value("dB", exchange.bob_private, private),
                Value("QB", exchange.bob_public, public),
            ),
        ),
        Step(
            4,
            Actor.ALICE,
            "Alice receives Bob's public point QB.\n"
            "She computes the shared point:\n"
            "  S = dA × QB = dA × dB × G\n"
            "The x-coordinate of S is the shared secret.",
            (secret,),
        ),
        Step(
            5,
            Actor.BOB,
            "Bob receives Alice's public point QA.\n"
            "He computes the shared point:\n"
            "  S = dB × QA = dB × dA × G\n"
            "The x-coordinate of S is the shared secret.",
            (secret,),
        ),
        Step(
            6,
            Actor.BOTH,
            "Both hold the same S.x without ever\n"
            "sending dA or dB.\n"
            "256-bit ECDH ≈ 3072-bit classical DH in security.",
            (secret,),
        ),
    )


def _point(public_key: ec.EllipticCurvePublicKey) -> Point:
    numbers = public_key.public_numbers()
    return numbers.x, numbers.y
