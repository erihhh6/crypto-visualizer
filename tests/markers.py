"""Shared pytest markers for the test suite."""

from __future__ import annotations

import pytest


def known_bug(
    reason: str,
    *,
    when: bool = True,
    raises: type[BaseException] | tuple[type[BaseException], ...] = AssertionError,
) -> pytest.MarkDecorator:
    """
    Mark a test that asserts the *correct* behaviour for a bug not yet fixed.

    The marker is a strict xfail: once the bug is fixed the test passes, and
    that unexpected pass fails the run. The fixing commit therefore has to
    delete the marker, so a known-bug test can never silently go stale.

    *when* scopes a platform-specific bug: where it is False, the test runs
    as an ordinary test and must pass.

    Only *raises* counts as the expected failure (a failed assertion by
    default). A test that crashes for an unrelated reason — a typo, a changed
    API, a Tk error — still fails loudly instead of hiding behind the marker.
    """
    return pytest.mark.xfail(
        when, reason=f"known bug: {reason}", raises=raises, strict=True
    )
