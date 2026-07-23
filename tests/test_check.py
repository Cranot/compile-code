from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
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


def test_unqualified_no_egress_claim_is_retired():
    assert check._retired_claim_hits("README.md", "nothing leaves your machine") == [
        "README.md:1: retired unqualified no-egress claim"
    ]
    assert (
        check._retired_claim_hits(
            "README.md",
            "compiler operations are local; external agents keep their provider boundary",
        )
        == []
    )


def test_stale_intent_procedure_count_is_retired():
    assert check._retired_claim_hits("README.md", "23 intent procedures") == [
        "README.md:1: retired Roam 13.10 intent-procedure count"
    ]
    assert (
        check._retired_claim_hits(
            "README.md",
            "22 canonical intent procedures in Roam 13.10",
        )
        == []
    )


def test_gate_reports_a_missing_executable_without_traceback(monkeypatch, capsys):
    def missing(*args, **kwargs):
        raise FileNotFoundError("missing")

    monkeypatch.setattr(check.subprocess, "run", missing)

    assert check.run("required tool", ["missing-tool"]) is False
    output = capsys.readouterr().out
    assert "[check] required tool: FAIL" in output
    assert "required executable not found" in output


def test_console_safe_escapes_characters_outside_the_active_encoding(monkeypatch):
    class NarrowStdout:
        encoding = "ascii"

    monkeypatch.setattr(check.sys, "stdout", NarrowStdout())

    assert check._console_safe("failure: \ufffd") == r"failure: \ufffd"


class _RecordHash:
    mode = "sha256"

    def __init__(self, payload: bytes):
        self.value = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")


class _Record:
    def __init__(self, name: str, payload: bytes):
        self.name = name
        self.hash = _RecordHash(payload)
        self.size = len(payload)


class _Distribution:
    version = check.ZIZMOR_VERSION

    def __init__(self, path: pathlib.Path, record: _Record):
        self.path = path
        self.files = [record]

    def locate_file(self, record: _Record) -> pathlib.Path:
        return self.path


def _install_fake_zizmor(monkeypatch, tmp_path, payload=b"reviewed-zizmor"):
    executable_name = "zizmor.exe" if sys.platform == "win32" else "zizmor"
    executable = tmp_path / executable_name
    executable.write_bytes(payload)
    record = _Record(executable_name, payload)
    distribution = _Distribution(executable, record)
    monkeypatch.setattr(check.importlib_metadata, "distribution", lambda name: distribution)
    monkeypatch.setattr(check.sysconfig, "get_path", lambda name: os.fspath(tmp_path))
    monkeypatch.setattr(check, "_zizmor_version", lambda path: f"zizmor {check.ZIZMOR_VERSION}")
    trusted_identity = (hashlib.sha256(payload).hexdigest(), len(payload))
    monkeypatch.setattr(check, "_trusted_zizmor_executables", lambda: frozenset({trusted_identity}))
    return executable, record, distribution


def test_zizmor_identity_binds_scripts_path_record_hash_size_and_version(monkeypatch, tmp_path):
    executable, _, _ = _install_fake_zizmor(monkeypatch, tmp_path)

    assert check._verified_zizmor_path() == executable


def test_zizmor_identity_rejects_version_path_and_content_drift(monkeypatch, tmp_path):
    executable, record, distribution = _install_fake_zizmor(monkeypatch, tmp_path)

    distribution.version = "1.26.1"
    try:
        check._verified_zizmor_path()
    except check.ToolIdentityError as exc:
        assert "version drift" in str(exc)
    else:  # pragma: no cover - fail with a focused message
        raise AssertionError("a drifted zizmor distribution version was accepted")

    distribution.version = check.ZIZMOR_VERSION
    monkeypatch.setattr(check.sysconfig, "get_path", lambda name: os.fspath(tmp_path / "other"))
    try:
        check._verified_zizmor_path()
    except check.ToolIdentityError as exc:
        assert "exactly one" in str(exc)
    else:  # pragma: no cover - fail with a focused message
        raise AssertionError("a zizmor executable outside the interpreter scripts directory was accepted")

    monkeypatch.setattr(check.sysconfig, "get_path", lambda name: os.fspath(tmp_path))
    executable.write_bytes(b"tampered-zizmor")
    record.size = len(b"tampered-zizmor")
    try:
        check._verified_zizmor_path()
    except check.ToolIdentityError as exc:
        assert "SHA-256" in str(exc)
    else:  # pragma: no cover - fail with a focused message
        raise AssertionError("a zizmor executable with a drifted digest was accepted")


def test_zizmor_identity_rejects_hardlinks_and_malformed_record_size(monkeypatch, tmp_path):
    executable, record, _ = _install_fake_zizmor(monkeypatch, tmp_path)
    os.link(executable, tmp_path / "zizmor-hardlink")

    try:
        check._verified_zizmor_path()
    except check.ToolIdentityError as exc:
        assert "hard link" in str(exc)
    else:  # pragma: no cover - fail with a focused message
        raise AssertionError("a multiply linked zizmor executable was accepted")

    (tmp_path / "zizmor-hardlink").unlink()
    record.size = "not-an-integer"
    try:
        check._verified_zizmor_path()
    except check.ToolIdentityError as exc:
        assert "size is malformed" in str(exc)
    else:  # pragma: no cover - fail with a focused message
        raise AssertionError("a malformed zizmor RECORD size escaped the gate")


def test_zizmor_identity_rejects_paired_executable_and_record_tampering(monkeypatch, tmp_path):
    executable, record, _ = _install_fake_zizmor(monkeypatch, tmp_path)
    tampered = b"paired-tampered-zizmor"
    executable.write_bytes(tampered)
    record.hash = _RecordHash(tampered)
    record.size = len(tampered)

    try:
        check._verified_zizmor_path()
    except check.ToolIdentityError as exc:
        assert "lock-derived artifact trust set" in str(exc)
    else:  # pragma: no cover - fail with a focused message
        raise AssertionError("paired executable and mutable RECORD tampering escaped the gate")


def test_zizmor_lock_extraction_keeps_exact_reviewed_hashes():
    requirement = check._locked_zizmor_requirement()

    assert requirement.startswith(f"zizmor=={check.ZIZMOR_VERSION} \\")
    assert len(check.re.findall(r"--hash=sha256:[0-9a-f]{64}", requirement)) == check.ZIZMOR_LOCK_ARTIFACT_HASH_COUNT
    assert hashlib.sha256(requirement.encode("utf-8")).hexdigest() == check.ZIZMOR_LOCK_STANZA_SHA256
    assert check._lock_problems("zizmor", requirement) == []


def test_zizmor_artifact_trust_manifest_covers_every_locked_artifact():
    identities = check._trusted_zizmor_executables()

    assert len(identities) == check.ZIZMOR_BINARY_WHEEL_COUNT
    assert ("93fdad7a072eecccfb328f97476074c0dca94bb077296a6033c3783bc218b6fa", 23491584) in identities


def test_zizmor_artifact_trust_manifest_rejects_semantic_tampering(monkeypatch, tmp_path):
    tampered = tmp_path / "zizmor-artifact-trust.json"
    payload = check.ZIZMOR_TRUST_MANIFEST.read_bytes().replace(b'"version": "1.27.0"', b'"version": "1.26.0"')
    tampered.write_bytes(payload)
    monkeypatch.setattr(check, "ZIZMOR_TRUST_MANIFEST", tampered)

    try:
        check._trusted_zizmor_executables()
    except check.ToolIdentityError as exc:
        assert "reviewed semantic digest" in str(exc)
    else:  # pragma: no cover - fail with a focused message
        raise AssertionError("semantic trust-manifest tampering escaped the gate")


def test_explicit_zizmor_bootstrap_uses_hashes_wheels_and_no_dependencies(monkeypatch, tmp_path):
    captured = {}

    def fake_run(title, command, *, env=None):
        captured["title"] = title
        captured["command"] = command
        captured["environment"] = env
        requirement = pathlib.Path(command[-1]).read_text(encoding="utf-8")
        assert requirement == check._locked_zizmor_requirement()
        return True

    executable = tmp_path / ("zizmor.exe" if sys.platform == "win32" else "zizmor")
    monkeypatch.setattr(check, "run", fake_run)
    monkeypatch.setattr(check, "_verified_zizmor_path", lambda: executable)

    assert check.bootstrap_zizmor()
    assert captured["command"][:5] == [sys.executable, "-m", "pip", "--isolated", "install"]
    for argument in (
        "--no-cache-dir",
        "--no-compile",
        "--no-deps",
        "--require-hashes",
        "--only-binary=:all:",
        "--force-reinstall",
    ):
        assert argument in captured["command"]
    assert captured["environment"]["PIP_CONFIG_FILE"] == os.devnull


def test_missing_zizmor_fails_both_mandatory_audits(monkeypatch, capsys):
    def missing():
        raise check.ToolIdentityError("missing")

    monkeypatch.setattr(check, "_verified_zizmor_path", missing)

    assert check.zizmor_gates() == [False, False, False]
    output = capsys.readouterr().out
    assert "zizmor identity: FAIL" in output
    assert "zizmor auditor medium+ (ignores disabled): FAIL" in output
    assert "zizmor --pedantic: FAIL" in output
    assert check.ZIZMOR_BOOTSTRAP_ARGUMENT in output


def test_zizmor_resolution_never_falls_back_to_path(monkeypatch, tmp_path):
    fake = tmp_path / ("zizmor.exe" if sys.platform == "win32" else "zizmor")
    fake.write_bytes(b"path-zizmor")
    monkeypatch.setenv("PATH", os.fspath(tmp_path))

    def missing(name):
        raise check.importlib_metadata.PackageNotFoundError(name)

    monkeypatch.setattr(check.importlib_metadata, "distribution", missing)

    try:
        check._verified_zizmor_path()
    except check.ToolIdentityError as exc:
        assert "is not installed" in str(exc)
    else:  # pragma: no cover - fail with a focused message
        raise AssertionError("an unreviewed PATH zizmor was accepted")


def test_source_test_environment_binds_pytest_to_this_checkout(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "stale-installed-package")
    monkeypatch.setenv("GIT_DIR", "outer-repository/.git")
    monkeypatch.setenv("GIT_INDEX_FILE", "outer-repository/index")
    monkeypatch.setenv("GIT_WORK_TREE", "outer-repository")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    environment = check._source_test_environment()

    assert environment["PYTHONPATH"].split(check.os.pathsep) == [str(check.ROOT / "src"), str(check.ROOT)]
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["PYTHONSAFEPATH"] == "1"
    assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
    assert "GIT_DIR" not in environment
    assert "GIT_INDEX_FILE" not in environment
    assert "GIT_WORK_TREE" not in environment
    assert environment["GITHUB_ACTIONS"] == "true"


def test_source_test_environment_keeps_nested_git_commits_out_of_outer_repository(monkeypatch, tmp_path):
    outer = tmp_path / "outer"
    inner = tmp_path / "inner"
    outer.mkdir()
    inner.mkdir()
    identity = ["-c", "user.name=Release Test", "-c", "user.email=release@example.invalid"]
    subprocess.run(["git", "init", "-q"], cwd=outer, check=True)
    (outer / "outer.txt").write_text("outer", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=outer, check=True)
    subprocess.run(["git", *identity, "commit", "-qm", "outer source"], cwd=outer, check=True)
    outer_head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=outer, check=True, capture_output=True, text=True
    ).stdout.strip()

    monkeypatch.setenv("GIT_DIR", str(outer / ".git"))
    monkeypatch.setenv("GIT_INDEX_FILE", str(outer / ".git" / "index"))
    monkeypatch.setenv("GIT_WORK_TREE", str(outer))
    environment = check._source_test_environment()

    subprocess.run(["git", "init", "-q"], cwd=inner, env=environment, check=True)
    (inner / "inner.txt").write_text("inner", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=inner, env=environment, check=True)
    subprocess.run(["git", *identity, "commit", "-qm", "inner source"], cwd=inner, env=environment, check=True)

    assert (
        subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=outer, check=True, capture_output=True, text=True
        ).stdout.strip()
        == outer_head
    )
    assert subprocess.run(
        ["git", "show", "--format=", "--name-only", "HEAD"],
        cwd=inner,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines() == ["inner.txt"]


def test_protected_command_fails_when_repository_state_changes(monkeypatch, capsys):
    states = iter((b"before", b"after"))
    monkeypatch.setattr(check, "_repository_state", lambda: next(states))
    monkeypatch.setattr(check.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0))

    assert check.run("mutating command", ["tool"], protect_repository=True) is False
    assert "command changed repository HEAD, index, or worktree state" in capsys.readouterr().out


def test_protected_command_checks_repository_after_launch_failure(monkeypatch, capsys):
    states = iter((b"before", b"after"))
    monkeypatch.setattr(check, "_repository_state", lambda: next(states))
    monkeypatch.setattr(check.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError()))

    assert check.run("missing mutator", ["tool"], protect_repository=True) is False
    output = capsys.readouterr().out
    assert "required executable not found" in output
    assert "command changed repository HEAD, index, or worktree state" in output


def test_repository_snapshot_ignores_inherited_git_redirection(monkeypatch):
    captured = {}

    def fake_run(*args, **kwargs):
        captured["command"] = args[0]
        captured["environment"] = kwargs["env"]
        return subprocess.CompletedProcess(args[0], 0, stdout=b"state", stderr=b"")

    monkeypatch.setenv("GIT_DIR", "redirected/.git")
    monkeypatch.setenv("GIT_WORK_TREE", "redirected")
    monkeypatch.setattr(check.subprocess, "run", fake_run)

    assert check._repository_state() == b"state"
    assert "--no-ahead-behind" in captured["command"]
    assert "GIT_DIR" not in captured["environment"]
    assert "GIT_WORK_TREE" not in captured["environment"]


def test_repository_snapshot_normalizes_launch_and_timeout_errors(monkeypatch):
    for failure, message in (
        (FileNotFoundError(), "git executable is unavailable"),
        (OSError("blocked"), "could not launch git status"),
        (subprocess.TimeoutExpired(["git"], 60), "snapshot timeout"),
    ):
        monkeypatch.setattr(
            check.subprocess, "run", lambda *args, failure=failure, **kwargs: (_ for _ in ()).throw(failure)
        )
        try:
            check._repository_state()
        except RuntimeError as exc:
            assert message in str(exc)
        else:  # pragma: no cover - fail with a focused message
            raise AssertionError("repository snapshot exception escaped normalization")


def test_git_inventory_failure_blocks_leak_and_artifact_scans(monkeypatch, capsys):
    failure = subprocess.CompletedProcess(["git", "ls-files"], 1, stdout=b"", stderr=b"inventory failed")
    monkeypatch.setattr(check.subprocess, "run", lambda *args, **kwargs: failure)

    assert check.leak_scan() is False
    assert check.artifact_scan() is False
    output = capsys.readouterr().out
    assert output.count("git ls-files failed") == 2
