"""Tests for tests/markers.py — the known_bug marker must not go stale."""

from __future__ import annotations

import pytest

_KNOWN_BUG_TEST = """
from tests.markers import known_bug

@known_bug("demo bug"{options})
def test_behaviour():
    {body}
"""


def _known_bug_test(body: str, options: str = "") -> str:
    return _KNOWN_BUG_TEST.format(body=body, options=options)


def test_known_bug_still_present_is_reported_as_xfail(
    pytester: pytest.Pytester,
) -> None:
    pytester.makepyfile(_known_bug_test("assert False"))
    result = pytester.runpytest()
    result.assert_outcomes(xfailed=1)


def test_fixed_known_bug_fails_until_marker_is_removed(
    pytester: pytest.Pytester,
) -> None:
    pytester.makepyfile(_known_bug_test("assert True"))
    result = pytester.runpytest()
    result.assert_outcomes(failed=1)
    result.stdout.fnmatch_lines(["*XPASS(strict)*known bug: demo bug*"])


def test_unrelated_crash_is_not_mistaken_for_the_known_bug(
    pytester: pytest.Pytester,
) -> None:
    pytester.makepyfile(_known_bug_test("raise TypeError('typo')"))
    result = pytester.runpytest()
    result.assert_outcomes(failed=1)


def test_known_bug_elsewhere_runs_as_an_ordinary_test(
    pytester: pytest.Pytester,
) -> None:
    pytester.makepyfile(_known_bug_test("assert False", options=", when=False"))
    result = pytester.runpytest()
    result.assert_outcomes(failed=1)
