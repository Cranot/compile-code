from __future__ import annotations

import os
from datetime import date
from pathlib import Path

import pytest

from scripts import build_internal_index


def test_catalogue_is_byte_reproducible_across_path_order_mtime_and_wall_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FirstBuildDate(date):
        @classmethod
        def today(cls) -> FirstBuildDate:
            return cls(2026, 7, 28)

    class SecondBuildDate(date):
        @classmethod
        def today(cls) -> SecondBuildDate:
            return cls(2026, 7, 29)

    first = tmp_path / "short"
    second = tmp_path / "a-much-longer-directory"
    first.mkdir()
    second.mkdir()
    documents = {
        "2026-07-01-alpha.md": "# Alpha\n\n> First gist.\n",
        "undated.md": "# Undated\n\n> Second gist.\n",
    }
    for name, content in documents.items():
        (first / name).write_text(content, encoding="utf-8")
    for name, content in reversed(documents.items()):
        (second / name).write_text(content, encoding="utf-8")
    for path in first.iterdir():
        os.utime(path, (1_600_000_000, 1_600_000_000))
    for path in second.iterdir():
        os.utime(path, (1_800_000_000, 1_800_000_000))

    monkeypatch.setattr(build_internal_index, "date", FirstBuildDate, raising=False)
    first_bytes = build_internal_index.build_catalogue(first).encode()
    monkeypatch.setattr(build_internal_index, "date", SecondBuildDate)
    second_bytes = build_internal_index.build_catalogue(second).encode()

    assert first_bytes == second_bytes
    assert b"Generated catalogue" in first_bytes
    assert b"2026-07-01-alpha.md" in first_bytes
