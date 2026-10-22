"""Tests for tests/markers.py — the known_bug marker must not go stale."""

from __future__ import annotations

import pytest

_KNOWN_BUG_TEST = """
from tests.markers import known_bug

@known_bug("demo bug")
def test_behaviour():
    assert {result}
"""


def test_known_bug_still_present_is_reported_as_xfail(
    pytester: pytest.Pytester,
) -> None:
    pytester.makepyfile(_KNOWN_BUG_TEST.format(result="False"))
    result = pytester.runpytest()
    result.assert_outcomes(xfailed=1)


def test_fixed_known_bug_fails_until_marker_is_removed(
    pytester: pytest.Pytester,
) -> None:
    pytester.makepyfile(_KNOWN_BUG_TEST.format(result="True"))
    result = pytester.runpytest()
    result.assert_outcomes(failed=1)
    result.stdout.fnmatch_lines(["*XPASS(strict)*known bug: demo bug*"])
