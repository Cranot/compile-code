"""Test-suite environment contract."""

from __future__ import annotations

import os

import pytest


def pytest_sessionstart(session: pytest.Session) -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.exit(
            "environment precondition unmet: test suite requires a non-root UID; "
            "run in the CI `check` job or rerun as an unprivileged user",
            returncode=2,
        )
