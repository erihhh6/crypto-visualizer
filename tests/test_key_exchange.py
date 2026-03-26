"""
Tests for modules/key_exchange.py.

Covers:
  - run_dh_exchange: correct number of steps, actor labels, shared secret agreement
  - run_ecdh_exchange: same structure, ECDH-specific labels
  - compare_dh_ecdh: presence and values of all security levels
  - get_ecdh_curve_points: return shape and types
  - DHStep dataclass fields
"""

from __future__ import annotations

import pytest

from modules.key_exchange import (
    DHStep,
    run_dh_exchange,
    run_ecdh_exchange,
    get_ecdh_curve_points,
    compare_dh_ecdh,
)


# ---------------------------------------------------------------------------
# DHStep dataclass
# ---------------------------------------------------------------------------

class TestDHStep:
    def test_fields_present(self) -> None:
        step = DHStep(
            step_number=1,
            actor="Alice",
            description="Test step",
            public_value="DEADBEEF",
            private_value="a = [PRIVATE]",
            is_public=True,
        )
        assert step.step_number == 1
        assert step.actor == "Alice"
        assert step.is_public is True

    def test_private_step(self) -> None:
        step = DHStep(1, "Bob", "desc", "val", "b = [PRIVATE]", False)
        assert step.is_public is False


# ---------------------------------------------------------------------------
# Classical DH
# ---------------------------------------------------------------------------

class TestDHExchange:
    @pytest.fixture(scope="class")
    def steps(self) -> list[DHStep]:
        return run_dh_exchange()

    def test_returns_six_steps(self, steps: list[DHStep]) -> None:
        assert len(steps) == 6

    def test_step_numbers_sequential(self, steps: list[DHStep]) -> None:
        for i, step in enumerate(steps, start=1):
            assert step.step_number == i

    def test_actors(self, steps: list[DHStep]) -> None:
        actors = [s.actor for s in steps]
        assert actors[0] == "System"
        assert actors[1] == "Alice"
        assert actors[2] == "Bob"
        assert actors[3] == "Alice"
        assert actors[4] == "Bob"
        assert actors[5] == "Both"

    def test_public_steps_flagged(self, steps: list[DHStep]) -> None:
        # Steps 1, 2, 3 transmit values publicly
        assert steps[0].is_public is True
        assert steps[1].is_public is True
        assert steps[2].is_public is True

    def test_private_steps_flagged(self, steps: list[DHStep]) -> None:
        # Steps 4, 5 are private (shared secret computation)
        assert steps[3].is_public is False
        assert steps[4].is_public is False

    def test_shared_secrets_match(self, steps: list[DHStep]) -> None:
        """Alice and Bob must arrive at the same shared secret."""
        shared_alice = steps[3].public_value  # step 4
        shared_bob   = steps[4].public_value  # step 5
        assert shared_alice == shared_bob

    def test_public_values_are_strings(self, steps: list[DHStep]) -> None:
        for step in steps:
            assert isinstance(step.public_value, str)
            assert len(step.public_value) > 0

    def test_private_values_masked(self, steps: list[DHStep]) -> None:
        """Private values must never expose the raw integer."""
        private_steps = [s for s in steps if not s.is_public and s.actor in ("Alice", "Bob")]
        for step in private_steps:
            assert "[PRIVATE]" in step.private_value

    def test_descriptions_non_empty(self, steps: list[DHStep]) -> None:
        for step in steps:
            assert len(step.description.strip()) > 10

    def test_multiple_calls_produce_different_values(self) -> None:
        """DH uses random private keys — repeated calls should produce different public values."""
        steps_a = run_dh_exchange()
        steps_b = run_dh_exchange()
        # Alice's public value (step 2) should differ between runs
        assert steps_a[1].public_value != steps_b[1].public_value


# ---------------------------------------------------------------------------
# ECDH
# ---------------------------------------------------------------------------

class TestECDHExchange:
    @pytest.fixture(scope="class")
    def steps(self) -> list[DHStep]:
        return run_ecdh_exchange()

    def test_returns_six_steps(self, steps: list[DHStep]) -> None:
        assert len(steps) == 6

    def test_step_numbers_sequential(self, steps: list[DHStep]) -> None:
        for i, step in enumerate(steps, start=1):
            assert step.step_number == i

    def test_system_step_mentions_curve(self, steps: list[DHStep]) -> None:
        assert "SECP256R1" in steps[0].public_value or "SECP256R1" in steps[0].description

    def test_shared_secrets_match(self, steps: list[DHStep]) -> None:
        shared_alice = steps[3].public_value
        shared_bob   = steps[4].public_value
        assert shared_alice == shared_bob

    def test_both_actor_on_final_step(self, steps: list[DHStep]) -> None:
        assert steps[5].actor == "Both"

    def test_private_values_masked(self, steps: list[DHStep]) -> None:
        private_steps = [s for s in steps if not s.is_public and s.actor in ("Alice", "Bob")]
        for step in private_steps:
            assert "[PRIVATE]" in step.private_value

    def test_randomness_across_calls(self) -> None:
        s1 = run_ecdh_exchange()
        s2 = run_ecdh_exchange()
        assert s1[1].public_value != s2[1].public_value


# ---------------------------------------------------------------------------
# Key size comparison
# ---------------------------------------------------------------------------

class TestCompareDhEcdh:
    @pytest.fixture(scope="class")
    def cmp(self) -> dict:
        return compare_dh_ecdh()

    def test_all_security_levels_present(self, cmp: dict) -> None:
        assert "128bit" in cmp
        assert "192bit" in cmp
        assert "256bit" in cmp

    def test_known_values(self, cmp: dict) -> None:
        assert cmp["128bit"]["dh_bits"]   == 3072
        assert cmp["128bit"]["ecdh_bits"] == 256
        assert cmp["192bit"]["dh_bits"]   == 7680
        assert cmp["192bit"]["ecdh_bits"] == 384
        assert cmp["256bit"]["dh_bits"]   == 15360
        assert cmp["256bit"]["ecdh_bits"] == 521

    def test_dh_always_larger(self, cmp: dict) -> None:
        for level, vals in cmp.items():
            assert vals["dh_bits"] > vals["ecdh_bits"], f"DH should be larger at {level}"


# ---------------------------------------------------------------------------
# ECDH curve points
# ---------------------------------------------------------------------------

class TestECDHCurvePoints:
    @pytest.fixture(scope="class")
    def points(self) -> dict:
        return get_ecdh_curve_points()

    def test_required_keys(self, points: dict) -> None:
        for key in ("alice_pub", "bob_pub", "shared", "curve_name"):
            assert key in points

    def test_curve_name(self, points: dict) -> None:
        assert points["curve_name"] == "SECP256R1"

    def test_public_key_format(self, points: dict) -> None:
        for actor in ("alice_pub", "bob_pub"):
            x, y = points[actor]
            assert isinstance(x, int)
            assert isinstance(y, int)
            assert x > 0
            assert y > 0

    def test_shared_secret_is_bytes(self, points: dict) -> None:
        assert isinstance(points["shared"], bytes)
        assert len(points["shared"]) == 32  # SECP256R1 → 32-byte x-coordinate

    def test_public_keys_differ(self, points: dict) -> None:
        assert points["alice_pub"] != points["bob_pub"]

    def test_randomness_across_calls(self) -> None:
        p1 = get_ecdh_curve_points()
        p2 = get_ecdh_curve_points()
        assert p1["alice_pub"] != p2["alice_pub"]
