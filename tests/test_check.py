from __future__ import annotations

import importlib.util
import pathlib
import subprocess
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


def test_release_lock_rejects_mutable_unhashed_and_url_requirements():
    problems = check._lock_problems(
        "release/bad.lock",
        "tool>=1\nother==2.0\npackage @ git+https://example.invalid/repo\n",
    )
    assert any("forbidden lock construct" in problem for problem in problems)
    assert any("unexpected or unpinned" in problem for problem in problems)
    assert any("has no SHA-256 hashes" in problem for problem in problems)


def test_release_lock_accepts_exact_hashed_requirement():
    requirement = "tool==1.2.3 --hash=sha256:" + "a" * 64 + "\n"
    assert check._lock_problems("release/good.lock", requirement) == []


def test_release_schema_json_rejects_duplicate_keys_and_oversize_input():
    try:
        check._strict_json_document(b'{"type":"object","type":"array"}', "schema")
    except ValueError as exc:
        assert "duplicate JSON key" in str(exc)
    else:  # pragma: no cover - fail with a focused message
        raise AssertionError("duplicate schema keys were accepted")

    try:
        check._strict_json_document(b" " * (check.MAX_SCHEMA_BYTES + 1), "schema")
    except ValueError as exc:
        assert "exceeds" in str(exc)
    else:  # pragma: no cover - fail with a focused message
        raise AssertionError("oversize schema was accepted")


def test_release_and_install_contracts_are_present():
    assert check.readme_sanity()
    assert check.release_sanity()


def test_gate_reports_a_missing_executable_without_traceback(monkeypatch, capsys):
    def missing(*args, **kwargs):
        raise FileNotFoundError("missing")

    monkeypatch.setattr(check.subprocess, "run", missing)

    assert check.run("required tool", ["missing-tool"]) is False
    output = capsys.readouterr().out
    assert "[check] required tool: FAIL" in output
    assert "required executable not found" in output


def test_source_test_environment_binds_pytest_to_this_checkout(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "stale-installed-package")

    environment = check._source_test_environment()

    assert environment["PYTHONPATH"].split(check.os.pathsep) == [str(check.ROOT / "src"), str(check.ROOT)]
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["PYTHONSAFEPATH"] == "1"
    assert environment["PYTHONDONTWRITEBYTECODE"] == "1"


def test_git_inventory_failure_blocks_leak_and_artifact_scans(monkeypatch, capsys):
    failure = subprocess.CompletedProcess(["git", "ls-files"], 1, stdout=b"", stderr=b"inventory failed")
    monkeypatch.setattr(check.subprocess, "run", lambda *args, **kwargs: failure)

    assert check.leak_scan() is False
    assert check.artifact_scan() is False
    output = capsys.readouterr().out
    assert output.count("git ls-files failed") == 2
