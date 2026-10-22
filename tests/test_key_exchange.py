"""
Tests for modules/key_exchange.py.

Covers:
  - run_dh_exchange: correct number of steps, actor labels, shared secret agreement
  - run_ecdh_exchange: same structure, ECDH-specific labels
  - compare_dh_ecdh: presence and values of all security levels
  - DHStep dataclass fields
"""

from __future__ import annotations

import pytest

from modules.key_exchange import (
    DHStep,
    compare_dh_ecdh,
    run_dh_exchange,
    run_ecdh_exchange,
)

# Module-scoped: each test class inspects one shared exchange run.


@pytest.fixture(scope="module")
def dh_steps() -> list[DHStep]:
    return run_dh_exchange()


@pytest.fixture(scope="module")
def ecdh_steps() -> list[DHStep]:
    return run_ecdh_exchange()


@pytest.fixture(scope="module")
def comparison() -> dict[str, dict[str, int]]:
    return compare_dh_ecdh()


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
    def test_returns_six_steps(self, dh_steps: list[DHStep]) -> None:
        assert len(dh_steps) == 6

    def test_step_numbers_sequential(self, dh_steps: list[DHStep]) -> None:
        for i, step in enumerate(dh_steps, start=1):
            assert step.step_number == i

    def test_actors(self, dh_steps: list[DHStep]) -> None:
        actors = [s.actor for s in dh_steps]
        assert actors[0] == "System"
        assert actors[1] == "Alice"
        assert actors[2] == "Bob"
        assert actors[3] == "Alice"
        assert actors[4] == "Bob"
        assert actors[5] == "Both"

    def test_public_steps_flagged(self, dh_steps: list[DHStep]) -> None:
        # Steps 1, 2, 3 transmit values publicly
        assert dh_steps[0].is_public is True
        assert dh_steps[1].is_public is True
        assert dh_steps[2].is_public is True

    def test_private_steps_flagged(self, dh_steps: list[DHStep]) -> None:
        # Steps 4, 5 are private (shared secret computation)
        assert dh_steps[3].is_public is False
        assert dh_steps[4].is_public is False

    def test_shared_secrets_match(self, dh_steps: list[DHStep]) -> None:
        """Alice and Bob must arrive at the same shared secret."""
        shared_alice = dh_steps[3].public_value  # step 4
        shared_bob = dh_steps[4].public_value  # step 5
        assert shared_alice == shared_bob

    def test_public_values_are_strings(self, dh_steps: list[DHStep]) -> None:
        for step in dh_steps:
            assert isinstance(step.public_value, str)
            assert len(step.public_value) > 0

    def test_private_values_masked(self, dh_steps: list[DHStep]) -> None:
        """Private values must never expose the raw integer."""
        private_steps = [
            s for s in dh_steps if not s.is_public and s.actor in ("Alice", "Bob")
        ]
        for step in private_steps:
            assert "[PRIVATE]" in step.private_value

    def test_descriptions_non_empty(self, dh_steps: list[DHStep]) -> None:
        for step in dh_steps:
            assert len(step.description.strip()) > 10

    def test_multiple_calls_produce_different_values(self) -> None:
        """DH uses random private keys, so repeated runs differ in public values."""
        steps_a = run_dh_exchange()
        steps_b = run_dh_exchange()
        # Alice's public value (step 2) should differ between runs
        assert steps_a[1].public_value != steps_b[1].public_value


# ---------------------------------------------------------------------------
# ECDH
# ---------------------------------------------------------------------------


class TestECDHExchange:
    def test_returns_six_steps(self, ecdh_steps: list[DHStep]) -> None:
        assert len(ecdh_steps) == 6

    def test_step_numbers_sequential(self, ecdh_steps: list[DHStep]) -> None:
        for i, step in enumerate(ecdh_steps, start=1):
            assert step.step_number == i

    def test_system_step_mentions_curve(self, ecdh_steps: list[DHStep]) -> None:
        first = ecdh_steps[0]
        assert "SECP256R1" in first.public_value or "SECP256R1" in first.description

    def test_shared_secrets_match(self, ecdh_steps: list[DHStep]) -> None:
        shared_alice = ecdh_steps[3].public_value
        shared_bob = ecdh_steps[4].public_value
        assert shared_alice == shared_bob

    def test_both_actor_on_final_step(self, ecdh_steps: list[DHStep]) -> None:
        assert ecdh_steps[5].actor == "Both"

    def test_private_values_masked(self, ecdh_steps: list[DHStep]) -> None:
        private_steps = [
            s for s in ecdh_steps if not s.is_public and s.actor in ("Alice", "Bob")
        ]
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
    def test_all_security_levels_present(
        self, comparison: dict[str, dict[str, int]]
    ) -> None:
        assert "128bit" in comparison
        assert "192bit" in comparison
        assert "256bit" in comparison

    def test_known_values(self, comparison: dict[str, dict[str, int]]) -> None:
        assert comparison["128bit"]["dh_bits"] == 3072
        assert comparison["128bit"]["ecdh_bits"] == 256
        assert comparison["192bit"]["dh_bits"] == 7680
        assert comparison["192bit"]["ecdh_bits"] == 384
        assert comparison["256bit"]["dh_bits"] == 15360
        assert comparison["256bit"]["ecdh_bits"] == 521

    def test_dh_always_larger(self, comparison: dict[str, dict[str, int]]) -> None:
        for level, vals in comparison.items():
            assert vals["dh_bits"] > vals["ecdh_bits"], (
                f"DH should be larger at {level}"
            )
