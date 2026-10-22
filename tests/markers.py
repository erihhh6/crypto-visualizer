"""Shared pytest markers for the test suite."""

from __future__ import annotations

import pytest


def known_bug(reason: str) -> pytest.MarkDecorator:
    """
    Mark a test that asserts the *correct* behaviour for a bug not yet fixed.

    The marker is a strict xfail: once the bug is fixed the test passes, and
    that unexpected pass fails the run. The fixing commit therefore has to
    delete the marker, so a known-bug test can never silently go stale.
    """
    return pytest.mark.xfail(reason=f"known bug: {reason}", strict=True)
