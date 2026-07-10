from __future__ import annotations

import importlib.util
import pathlib
import sys

SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
spec = importlib.util.spec_from_file_location("check", SCRIPTS / "check.py")
check = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = check
assert spec.loader is not None
spec.loader.exec_module(check)


def test_flags_known_artifact_paths():
    assert check._path_is_committed_artifact(".venv/lib/python3.12/site-packages/foo.py")
    assert check._path_is_committed_artifact("node_modules/left-pad/index.js")
    assert check._path_is_committed_artifact("dist/compile_code-0.1.0-py3-none-any.whl")
    assert check._path_is_committed_artifact("src/compile_code.egg-info/PKG-INFO")
    assert check._path_is_committed_artifact("src/compile_code/__pycache__/cli.cpython-312.pyc")


def test_does_not_flag_real_source():
    assert not check._path_is_committed_artifact("src/compile_code/cli.py")
    assert not check._path_is_committed_artifact("scripts/check.py")
    assert not check._path_is_committed_artifact("README.md")
    assert not check._path_is_committed_artifact("tests/test_cli.py")
    assert not check._path_is_committed_artifact("src/compile_code/builder.py")
