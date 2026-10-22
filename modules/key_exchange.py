"""
Diffie-Hellman (finite field) and ECDH key agreement, told step by step.

run_dh() and run_ecdh() perform a real exchange and return every value
involved; dh_steps() and ecdh_steps() turn an exchange into the narrated steps
the GUI animates. Values stay raw (ints, bytes, points): formatting them is the
GUI's job.

DH uses the 2048- or 3072-bit MODP group from RFC 3526; ECDH uses NIST P-256
(secp256r1) through PyCA cryptography. Both end by deriving an AES-256 key
from the shared secret with HKDF-SHA256.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# RFC 3526 defines each prime as 2^n − 2^(n−64) − 1 + 2^64 × (⌊2^(n−130) π⌋ + c):
# safe primes p = 2q + 1, all with generator 2.

# Group 14: 2048 bits, c = 124476.
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

# Group 15: 3072 bits, c = 1690314.
MODP3072_PRIME = int(
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
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    16,
)
MODP_GENERATOR = 2

# Private exponents are 256 random bits: at least twice the group's security
# strength (112 or 128 bits), as short-exponent DH requires, and far cheaper
# than a full-length exponent.
DH_EXPONENT_BITS = 256

# HKDF's info string ties the derived key to its purpose (RFC 5869, 3.2).
AES_KEY_INFO = b"crypto-visualizer: AES-256 key"

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
class DHGroup:
    """A finite-field DH group: a safe prime p = 2q + 1 and a generator g."""

    name: str
    p: int
    g: int
    security_bits: int  # comparable symmetric strength (NIST SP 800-57)

    @property
    def bits(self) -> int:
        return self.p.bit_length()


MODP_2048 = DHGroup("RFC 3526 group 14", MODP2048_PRIME, MODP_GENERATOR, 112)
# 128-bit security, like P-256: the like-for-like comparison with ECDH.
MODP_3072 = DHGroup("RFC 3526 group 15", MODP3072_PRIME, MODP_GENERATOR, 128)
DH_GROUPS = (MODP_2048, MODP_3072)


@dataclass(frozen=True)
class DHExchange:
    group: DHGroup
    alice_private: int  # a
    bob_private: int  # b
    alice_public: int  # A = g^a mod p
    bob_public: int  # B = g^b mod p
    shared_secret: int  # s = g^(ab) mod p
    key: bytes  # K = HKDF(s), the AES-256 key both sides end up with

    @property
    def p(self) -> int:
        return self.group.p

    @property
    def g(self) -> int:
        return self.group.g


@dataclass(frozen=True)
class ECDHExchange:
    curve_name: str
    alice_private: int  # dA
    bob_private: int  # dB
    alice_public: Point  # QA = dA × G
    bob_public: Point  # QB = dB × G
    shared_secret: bytes  # x-coordinate of dA × dB × G
    key: bytes  # K = HKDF(S.x), the AES-256 key both sides end up with


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


def run_dh(group: DHGroup = MODP_3072) -> DHExchange:
    """Perform a full DH exchange in *group*, ending with the derived AES key."""
    p, g = group.p, group.g
    a = _dh_private_exponent()
    b = _dh_private_exponent()
    alice_public = pow(g, a, p)
    bob_public = pow(g, b, p)

    # Each side checks the value it receives before raising it to its secret.
    validate_dh_public_value(bob_public, group)
    validate_dh_public_value(alice_public, group)
    alice_shared = pow(bob_public, a, p)
    bob_shared = pow(alice_public, b, p)
    if alice_shared != bob_shared:
        raise KeyExchangeError("Alice and Bob computed different DH secrets")

    # As TLS 1.3 does (RFC 8446, 7.4.1), the secret is encoded big-endian and
    # left-padded with zeros to the length of p before it goes into the KDF.
    secret_bytes = alice_shared.to_bytes((group.bits + 7) // 8, "big")
    return DHExchange(
        group,
        a,
        b,
        alice_public,
        bob_public,
        alice_shared,
        derive_aes_key(secret_bytes),
    )


def validate_dh_public_value(y: int, group: DHGroup) -> None:
    """
    Reject a received DH public value that would expose the shared secret.

    0, 1 and p - 1 make the secret predictable, so y must lie in [2, p - 2].
    For a safe prime p = 2q + 1 it must also lie in the subgroup of prime
    order q (y^q = 1 mod p); otherwise a malicious peer could confine the
    secret to a tiny subgroup and guess it.
    """
    p = group.p
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
    group = exchange.group
    strength = f"about {group.security_bits}-bit security, " + (
        "like P-256" if group.security_bits >= 128 else "below P-256's 128"
    )
    return (
        Step(
            1,
            Actor.SYSTEM,
            "Public parameters are agreed in advance:\n"
            f"  p = a {group.bits}-bit prime ({group.name})\n"
            "  g = 2, the generator\n"
            f"That gives {strength}.\n"
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
            "Both hold s = g^(ab) mod p, but s is a number\n"
            "below p, not uniform random bits: never a key.\n"
            "Both feed it to HKDF-SHA256 and get the same\n"
            "AES-256 key K, without ever sending a or b.",
            (Value("K", exchange.key, shared),),
        ),
    )


def derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Turn a DH or ECDH shared secret into a 256-bit AES key with HKDF-SHA256.

    The secret is a group element: its bits are not uniformly random, and a
    DH secret is far longer than a key. HKDF (RFC 5869) extracts its entropy
    and expands it to exactly the key needed, bound to AES_KEY_INFO.
    """
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=AES_KEY_INFO)
    return hkdf.derive(shared_secret)


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
        key=derive_aes_key(alice_shared),
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
            "About 128-bit security, like 3072-bit DH.\n"
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
            "Both hold S.x, a curve coordinate: not\n"
            "uniform random bits, so never a key.\n"
            "Both feed it to HKDF-SHA256 and get the same\n"
            "AES-256 key K, without ever sending dA or dB.",
            (Value("K", exchange.key, shared),),
        ),
    )


def _point(public_key: ec.EllipticCurvePublicKey) -> Point:
    numbers = public_key.public_numbers()
    return numbers.x, numbers.y
