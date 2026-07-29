from __future__ import annotations

import os
from pathlib import Path

import pytest

from scripts import build_internal_index
from scripts import inventory


def test_partial_nested_inventory_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    internal = tmp_path / "internal"
    nested = internal / "archive"
    nested.mkdir(parents=True)
    (nested / "one.md").write_text("# one\n", encoding="utf-8")
    real_scandir = os.scandir

    class PartialScandir:
        def __init__(self, path):
            self._path = Path(path)
            self._iterator = None

        def __enter__(self):
            self._iterator = real_scandir(self._path)
            iterator = self._iterator.__enter__()
            if self._path == nested:
                next(iterator)
                raise OSError("enumeration stopped")
            return iterator

        def __exit__(self, exc_type, exc, traceback):
            if self._iterator is not None:
                return self._iterator.__exit__(exc_type, exc, traceback)
            return False

    monkeypatch.setattr(inventory.os, "scandir", PartialScandir)

    with pytest.raises(inventory.InventoryError, match="could not establish filesystem inventory"):
        build_internal_index.build_catalogue(internal)


def test_healthy_internal_inventory_counts_root_and_nested_documents(tmp_path: Path) -> None:
    internal = tmp_path / "internal"
    nested = internal / "archive"
    nested.mkdir(parents=True)
    (internal / "root.md").write_text("# root\n", encoding="utf-8")
    (nested / "one.md").write_text("# one\n", encoding="utf-8")

    catalogue = build_internal_index.build_catalogue(internal)

    assert "2 markdown files (1 at root, 1 nested)" in catalogue
    assert "| `archive/` | 1 |" in catalogue
