"""
Diffie-Hellman and ECDH key exchange with step-by-step metadata.

DH uses RFC 3526 Group 14 (2048-bit MODP group).
ECDH uses NIST SECP256R1 (P-256) via PyCA cryptography.

Both protocols expose each logical step as a DHStep dataclass so the
GUI animator can walk through the exchange interactively.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP256R1,
    generate_private_key,
)

# ---------------------------------------------------------------------------
# RFC 3526 Group 14 — 2048-bit MODP
# ---------------------------------------------------------------------------

_RFC3526_P = int(
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
_RFC3526_G = 2


def _short_hex(value: int, max_chars: int = 32) -> str:
    """Return a short uppercase hex representation of a large integer."""
    full = format(value, "X")
    if len(full) <= max_chars:
        return full
    return full[: max_chars // 2] + "…" + full[-(max_chars // 2) :]


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class DHStep:
    """A single step in a DH/ECDH key-exchange protocol, used for animation."""

    step_number: int
    actor: str  # "Alice", "Bob", "Both", "System"
    description: str  # human-readable explanation
    public_value: str  # short hex (max 32 chars visible)
    private_value: str  # masked if sensitive, e.g. "a = [PRIVATE]"
    is_public: bool  # True → value transmitted over the wire


# ---------------------------------------------------------------------------
# Classical DH (RFC 3526 Group 14)
# ---------------------------------------------------------------------------


def run_dh_exchange() -> list[DHStep]:
    """
    Execute a full 2048-bit DH key exchange and return annotated steps.

    Steps:
      1. System publishes p and g (public parameters)
      2. Alice generates private key a, computes A = g^a mod p
      3. Bob generates private key b, computes B = g^b mod p
      4. Alice computes shared = B^a mod p
      5. Bob computes shared = A^b mod p
      6. Verification that shared_alice == shared_bob
    """
    p = _RFC3526_P
    g = _RFC3526_G

    # Generate private keys as random integers in [2, p-2]
    a = int.from_bytes(os.urandom(32), "big") % (p - 3) + 2
    b = int.from_bytes(os.urandom(32), "big") % (p - 3) + 2

    A = pow(g, a, p)  # Alice's public value
    B = pow(g, b, p)  # Bob's public value

    shared_alice = pow(B, a, p)
    shared_bob = pow(A, b, p)

    assert shared_alice == shared_bob, "DH shared secret mismatch!"

    steps: list[DHStep] = [
        DHStep(
            step_number=1,
            actor="System",
            description=(
                "Public parameters are established:\n"
                "  p = 2048-bit prime (RFC 3526 Group 14)\n"
                f"  g = {g}\n"
                "These are known to everyone."
            ),
            public_value=_short_hex(g),
            private_value="p = [2048-bit prime]",
            is_public=True,
        ),
        DHStep(
            step_number=2,
            actor="Alice",
            description=(
                "Alice picks a secret random integer a,\n"
                "then computes her public value:\n"
                "  A = g^a mod p\n"
                "She sends A to Bob."
            ),
            public_value=_short_hex(A),
            private_value="a = [PRIVATE]",
            is_public=True,
        ),
        DHStep(
            step_number=3,
            actor="Bob",
            description=(
                "Bob picks a secret random integer b,\n"
                "then computes his public value:\n"
                "  B = g^b mod p\n"
                "He sends B to Alice."
            ),
            public_value=_short_hex(B),
            private_value="b = [PRIVATE]",
            is_public=True,
        ),
        DHStep(
            step_number=4,
            actor="Alice",
            description=(
                "Alice receives Bob's public value B.\n"
                "She computes the shared secret:\n"
                "  shared = B^a mod p\n"
                "This is NOT sent over the wire."
            ),
            public_value=_short_hex(shared_alice),
            private_value="a = [PRIVATE]",
            is_public=False,
        ),
        DHStep(
            step_number=5,
            actor="Bob",
            description=(
                "Bob receives Alice's public value A.\n"
                "He computes the shared secret:\n"
                "  shared = A^b mod p\n"
                "This is NOT sent over the wire."
            ),
            public_value=_short_hex(shared_bob),
            private_value="b = [PRIVATE]",
            is_public=False,
        ),
        DHStep(
            step_number=6,
            actor="Both",
            description=(
                "Both parties now hold the same shared secret\n"
                "without ever transmitting their private keys.\n"
                "shared_alice == shared_bob ✓\n"
                "This shared secret can be used to derive symmetric keys."
            ),
            public_value=_short_hex(shared_alice),
            private_value="Agreed!",
            is_public=False,
        ),
    ]
    return steps


# ---------------------------------------------------------------------------
# ECDH (SECP256R1 / P-256)
# ---------------------------------------------------------------------------


def run_ecdh_exchange() -> list[DHStep]:
    """
    Execute a full ECDH exchange on SECP256R1 and return annotated steps.

    Steps mirror the classical DH steps but use elliptic curve operations.
    """
    curve = SECP256R1()
    alice_private = generate_private_key(curve)
    bob_private = generate_private_key(curve)

    alice_public = alice_private.public_key()
    bob_public = bob_private.public_key()

    alice_shared = alice_private.exchange(ECDH(), bob_public)
    bob_shared = bob_private.exchange(ECDH(), alice_public)

    assert alice_shared == bob_shared, "ECDH shared secret mismatch!"

    # Extract public key coordinates for display
    alice_pub_numbers = alice_public.public_numbers()
    bob_pub_numbers = bob_public.public_numbers()

    alice_x = alice_pub_numbers.x
    alice_y = alice_pub_numbers.y
    bob_x = bob_pub_numbers.x
    bob_y = bob_pub_numbers.y

    steps: list[DHStep] = [
        DHStep(
            step_number=1,
            actor="System",
            description=(
                "Public parameters are established:\n"
                "  Curve: SECP256R1 (P-256, NIST)\n"
                "  Generator point G and curve equation\n"
                "    y² = x³ − 3x + b  (mod p)\n"
                "All parameters are standardised and public."
            ),
            public_value="SECP256R1",
            private_value="Curve params = [public]",
            is_public=True,
        ),
        DHStep(
            step_number=2,
            actor="Alice",
            description=(
                "Alice generates a random private scalar dA,\n"
                "then computes her public key point:\n"
                "  QA = dA × G  (point multiplication)\n"
                "She sends QA (x, y) to Bob."
            ),
            public_value=f"({_short_hex(alice_x, 16)}, {_short_hex(alice_y, 16)})",
            private_value="dA = [PRIVATE]",
            is_public=True,
        ),
        DHStep(
            step_number=3,
            actor="Bob",
            description=(
                "Bob generates a random private scalar dB,\n"
                "then computes his public key point:\n"
                "  QB = dB × G  (point multiplication)\n"
                "He sends QB (x, y) to Alice."
            ),
            public_value=f"({_short_hex(bob_x, 16)}, {_short_hex(bob_y, 16)})",
            private_value="dB = [PRIVATE]",
            is_public=True,
        ),
        DHStep(
            step_number=4,
            actor="Alice",
            description=(
                "Alice receives Bob's public point QB.\n"
                "She computes the shared point:\n"
                "  S = dA × QB = dA × dB × G\n"
                "The x-coordinate of S is the shared secret."
            ),
            public_value=alice_shared[:16].hex().upper() + "…",
            private_value="dA = [PRIVATE]",
            is_public=False,
        ),
        DHStep(
            step_number=5,
            actor="Bob",
            description=(
                "Bob receives Alice's public point QA.\n"
                "He computes the shared point:\n"
                "  S = dB × QA = dB × dA × G\n"
                "The x-coordinate of S is the shared secret."
            ),
            public_value=bob_shared[:16].hex().upper() + "…",
            private_value="dB = [PRIVATE]",
            is_public=False,
        ),
        DHStep(
            step_number=6,
            actor="Both",
            description=(
                "Both parties hold the same shared secret (x-coord of S).\n"
                "No private scalars were ever transmitted.\n"
                "shared_alice == shared_bob ✓\n"
                "256-bit ECDH ≈ 3072-bit classical DH in security."
            ),
            public_value=alice_shared[:16].hex().upper() + "…",
            private_value="Agreed!",
            is_public=False,
        ),
    ]
    return steps


def compare_dh_ecdh() -> dict[str, dict[str, int]]:
    """
    Return equivalent key-size comparison between classical DH and ECDH.

    Security levels and their approximate equivalent key sizes:

    | Security (bits) | DH / RSA (bits) | ECDH (bits) |
    |-----------------|-----------------|-------------|
    | 128             | 3072            | 256         |
    | 192             | 7680            | 384         |
    | 256             | 15360           | 521         |
    """
    return {
        "128bit": {"dh_bits": 3072, "ecdh_bits": 256},
        "192bit": {"dh_bits": 7680, "ecdh_bits": 384},
        "256bit": {"dh_bits": 15360, "ecdh_bits": 521},
    }
