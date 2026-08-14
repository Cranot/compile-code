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


# ---------------------------------------------------------------------------
# THE SKIP LIST AND THE FATAL LIST MUST BE ONE LIST.
#
# Measured at 4f3e203: ``secret_scan._SKIP_DIRS`` held 13 names and
# ``check.ARTIFACT_SEGMENTS`` 5, so eight directories were opened by no
# scanner and refused by no gate. Seven of them (``.eggs``, ``.mypy_cache``,
# ``.pytest_cache``, ``.roam``, ``.ruff_cache``, ``.tox``, ``venv``) were
# reachable in the current tracked tree -- ``git ls-files`` would carry a
# credential under any of them straight past all four gates, exit 0
# throughout. The eighth, ``.git``, is unreachable: git stages nothing under
# it (``git add .git/probe.txt`` exits 0 and adds nothing).
#
# The relation is pinned here because drift is how it arose, and because the
# consequence is silent in both directions: neither list failing tells you the
# other one changed.
# ---------------------------------------------------------------------------


def test_the_unopened_set_and_the_refused_set_are_the_same_list():
    from scripts import inventory, secret_scan

    assert set(secret_scan._SKIP_DIRS) == set(check.ARTIFACT_SEGMENTS), (
        "a directory is unread by one gate and untouched by the other"
    )
    assert set(check.ARTIFACT_SEGMENTS) == set(inventory.UNTRACKABLE_DIRECTORY_SEGMENTS), (
        "a gate re-forked its own copy of the list"
    )
    assert "venv" not in secret_scan._SKIP_DIRS, (
        "venv can be tracked source (CPython ships Lib/venv/__init__.py), so it cannot be left unread"
    )


def test_tool_state_directories_are_fatal_not_merely_unread():
    """Each name ``secret_scan`` declines to open must fail this gate, or the
    decline is an absent measurement published as a clean result."""
    for rel in (
        ".tox/py311/pip.conf",
        ".pytest_cache/v/cache/lastfailed",
        ".mypy_cache/3.12/builtins.data.json",
        ".ruff_cache/content",
        ".eggs/pkg/EGG-INFO/PKG-INFO",
        ".roam/index.db",
    ):
        assert check._path_is_committed_artifact(rel), f"{rel} is skipped unread and refused by nothing"


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


def test_environment_preconditions_name_root_uid(monkeypatch):
    monkeypatch.setattr(check.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(check, "_quality_tool_failures", lambda: [])
    failures = check._environment_precondition_failures(network_probe=lambda: None)
    assert any("non-root UID" in failure for failure in failures)


def test_environment_preconditions_name_unwritable_temp(monkeypatch):
    monkeypatch.setattr(check.os, "geteuid", lambda: 1000, raising=False)

    def blocked(*args, **kwargs):
        raise OSError("read-only temporary root")

    monkeypatch.setattr(check.tempfile, "NamedTemporaryFile", blocked)
    monkeypatch.setattr(check, "_quality_tool_failures", lambda: [])
    failures = check._environment_precondition_failures(network_probe=lambda: None)
    assert any("writable temporary directory" in failure for failure in failures)


def test_hook_wiring_exempts_ci(monkeypatch):
    monkeypatch.setenv("CI", "true")
    assert check._hook_wiring_failure() is None


def test_hook_wiring_names_unwired_clone(monkeypatch):
    monkeypatch.delenv("CI", raising=False)

    def unset(cmd, **kwargs):
        assert cmd[:3] == ["git", "config", "--get"]
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

    monkeypatch.setattr(check.subprocess, "run", unset)
    failure = check._hook_wiring_failure()
    assert failure is not None
    assert "core.hooksPath is unset" in failure
    assert "git config core.hooksPath .githooks" in failure


def test_hook_wiring_names_foreign_hooks_path(monkeypatch):
    monkeypatch.delenv("CI", raising=False)

    def foreign(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=".husky\n", stderr="")

    monkeypatch.setattr(check.subprocess, "run", foreign)
    failure = check._hook_wiring_failure()
    assert failure is not None
    assert ".husky" in failure


def test_hook_wiring_accepts_wired_clone(monkeypatch):
    monkeypatch.delenv("CI", raising=False)

    def wired(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=".githooks\n", stderr="")

    monkeypatch.setattr(check.subprocess, "run", wired)
    assert check._hook_wiring_failure() is None


def test_environment_preconditions_name_unwired_hooks(monkeypatch):
    monkeypatch.setattr(check.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(check, "_quality_tool_failures", lambda: [])
    monkeypatch.setattr(check, "_hook_wiring_failure", lambda: "git hooks are not wired (core.hooksPath is unset)")
    failures = check._environment_precondition_failures(network_probe=lambda: None)
    assert any("git hooks are not wired" in failure for failure in failures)


def test_environment_preconditions_name_missing_git(monkeypatch):
    monkeypatch.setattr(check.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(check.shutil, "which", lambda name: None if name == "git" else "/bin/tool")
    monkeypatch.setattr(check, "_quality_tool_failures", lambda: [])
    failures = check._environment_precondition_failures(network_probe=lambda: None)
    assert any("git executable" in failure for failure in failures)


def test_environment_preconditions_name_non_utf8_locale(monkeypatch):
    monkeypatch.setattr(check.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(check.locale, "getpreferredencoding", lambda _do_setlocale: "ISO-8859-1")
    monkeypatch.setattr(check, "_quality_tool_failures", lambda: [])
    failures = check._environment_precondition_failures(network_probe=lambda: None)
    assert any("UTF-8 locale" in failure for failure in failures)


def test_environment_preconditions_name_broken_clock(monkeypatch):
    monkeypatch.setattr(check.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(check.time, "time", lambda: float("nan"))
    monkeypatch.setattr(check, "_quality_tool_failures", lambda: [])
    failures = check._environment_precondition_failures(network_probe=lambda: None)
    assert any("finite, monotonic system clock" in failure for failure in failures)


def test_environment_preconditions_name_quality_tool_drift(monkeypatch):
    monkeypatch.setattr(check.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(check, "_quality_tool_failures", lambda: ["quality tool ruff==0.15.22 is required"])
    failures = check._environment_precondition_failures(network_probe=lambda: None)
    assert any("ruff==0.15.22" in failure for failure in failures)


def test_environment_preconditions_name_missing_sigstore_test_dependency(monkeypatch):
    monkeypatch.setattr(
        check,
        "_test_dependency_failures",
        lambda: ["test dependency sigstore==4.4.0 is required"],
    )
    monkeypatch.setattr(check, "_quality_tool_failures", lambda: [])
    failures = check._environment_precondition_failures(network_probe=lambda: None)
    assert any("sigstore==4.4.0" in failure for failure in failures)


def test_environment_preconditions_name_network_failure(monkeypatch):
    monkeypatch.setattr(check.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(check, "_quality_tool_failures", lambda: [])
    failures = check._environment_precondition_failures(
        network_probe=lambda: "network reachability to https://api.osv.dev/v1/querybatch failed"
    )
    assert any("network reachability" in failure for failure in failures)


def test_environment_preconditions_healthy_control(monkeypatch):
    monkeypatch.setattr(check.os, "geteuid", lambda: 1000, raising=False)
    # Pin a UTF-8 locale instead of assuming one. On this repo's Windows dev
    # machine the active encoding is CP1253, which the check correctly flags --
    # so a control that assumes UTF-8 fails for the right reason in the wrong
    # place. A control must establish its preconditions, not inherit them.
    monkeypatch.setattr(check.locale, "getpreferredencoding", lambda *_a: "UTF-8")
    monkeypatch.setattr(check, "_quality_tool_failures", lambda: [])
    monkeypatch.setattr(check, "_test_dependency_failures", lambda: [])
    monkeypatch.setattr(check, "_verified_zizmor_path", lambda: pathlib.Path("/trusted/zizmor"))
    assert check._environment_precondition_failures(network_probe=lambda: None) == []


def test_check_main_healthy_control_preserves_success(monkeypatch, capsys):
    monkeypatch.setattr(check, "environment_preconditions", lambda: True)
    monkeypatch.setattr(check, "dependency_audit", lambda: True)
    monkeypatch.setattr(check, "run", lambda *args, **kwargs: True)
    monkeypatch.setattr(check, "zizmor_gates", lambda: [True, True, True])
    monkeypatch.setattr(check, "leak_scan", lambda: True)
    monkeypatch.setattr(check, "artifact_scan", lambda: True)
    monkeypatch.setattr(check, "readme_sanity", lambda: True)
    monkeypatch.setattr(check, "internal_index", lambda: True)
    monkeypatch.setattr(check, "release_sanity", lambda: True)
    assert check.main([]) == 0
    assert capsys.readouterr().out.strip() == "[check] all gates passed — safe to push."


def test_check_main_reports_environment_before_running_gates(monkeypatch, capsys):
    def blocked():
        print("[check] BLOCKED — environment preconditions unmet: non-root UID")
        return False

    monkeypatch.setattr(check, "environment_preconditions", blocked)
    monkeypatch.setattr(check, "dependency_audit", lambda: (_ for _ in ()).throw(AssertionError("ran too soon")))
    assert check.main([]) == 1
    assert "environment preconditions" in capsys.readouterr().out


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
    assert ("942d65eff4e76dfb277dcf66c60c217aa3a6d92d3df04b746c80561d8277b6cc", 24175104) in identities


def test_zizmor_artifact_trust_manifest_rejects_semantic_tampering(monkeypatch, tmp_path):
    tampered = tmp_path / "zizmor-artifact-trust.json"
    payload = check.ZIZMOR_TRUST_MANIFEST.read_bytes().replace(b'"version": "1.29.0"', b'"version": "1.26.0"')
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


def test_empty_git_inventory_blocks_leak_and_artifact_scans(monkeypatch, capsys):
    """A successful-but-empty inventory is the dangerous case, not the failing one.

    ``git ls-files`` exits 0 with empty stdout whenever it is answering about
    an index that has nothing in it. Both scans are built as "hits found in
    the enumerated files", so an empty enumeration made them unconditional
    PASSes -- two of the thirteen gates reporting clean without opening a
    single file, and nothing in the output saying so.
    """
    empty = subprocess.CompletedProcess(["git", "ls-files"], 0, stdout=b"", stderr=b"")
    monkeypatch.setattr(check.subprocess, "run", lambda *args, **kwargs: empty)

    assert check.leak_scan() is False
    assert check.artifact_scan() is False
    output = capsys.readouterr().out
    assert output.count("zero tracked files") == 2


def test_leak_patterns_survive_utf16_tracked_files(tmp_path, monkeypatch):
    """A UTF-16 file read as UTF-8 is decoded wrong, not decoded empty.

    Every NUL padding byte is valid UTF-8, so ``errors="ignore"`` preserved
    them and a real token arrived as ``g\\x00h\\x00p\\x00_\\x00...`` -- matching
    nothing in the catalogue while the gate printed PASS. Windows PowerShell's
    ``>`` and ``Out-File`` write UTF-16LE by default, so this is how a token
    redirected to a file and committed slips a Windows-developed repo.
    """
    token = "ghp_" + "A" * 36
    encodings = {
        "utf8.txt": token.encode("utf-8"),
        "utf16le_bom.txt": token.encode("utf-16"),  # what PowerShell `>` writes
        "utf16be_bom.txt": b"\xfe\xff" + token.encode("utf-16-be"),
        "utf16le_raw.txt": token.encode("utf-16-le"),
    }
    monkeypatch.setattr(check, "ROOT", tmp_path)
    for name, blob in encodings.items():
        (tmp_path / name).write_bytes(blob)
        assert check._scan_file_for_leaks(name) == [f"  {name}:1  [GitHub token] redacted match"], name

    # A hit must still be reported exactly once when several views agree.
    (tmp_path / "plain.txt").write_bytes(token.encode("utf-8"))
    assert len(check._scan_file_for_leaks("plain.txt")) == 1

    # Clean UTF-8 text stays clean -- the extra views must not invent hits.
    (tmp_path / "clean.py").write_bytes(b"import os\nVALUE = 'not a credential'\n")
    assert check._scan_file_for_leaks("clean.py") == []


def test_git_inventory_ignores_inherited_git_redirection(monkeypatch):
    """check.py runs from .githooks/pre-push, where Git exports repository-local
    GIT_* controls. An inherited GIT_INDEX_FILE/GIT_DIR/GIT_WORK_TREE makes
    ``git ls-files`` enumerate a different index and exit 0 -- the same defence
    ``_repository_state()`` already applies has to apply here too."""
    captured = {}

    def fake_run(*args, **kwargs):
        captured["environment"] = kwargs["env"]
        return subprocess.CompletedProcess(args[0], 0, stdout=b"README.md\0scripts/check.py\0", stderr=b"")

    monkeypatch.setenv("GIT_INDEX_FILE", "elsewhere.index")
    monkeypatch.setenv("GIT_DIR", "redirected/.git")
    monkeypatch.setenv("GIT_WORK_TREE", "redirected")
    monkeypatch.setattr(check.subprocess, "run", fake_run)

    assert check._tracked_files() == ["README.md", "scripts/check.py"]
    assert [key for key in captured["environment"] if key.upper().startswith("GIT_")] == []


def test_git_inventory_includes_new_nonignored_files_with_clean_control(tmp_path, monkeypatch):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "README.md").write_text("healthy\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    (tmp_path / "fresh.py").write_text("healthy = True\n", encoding="utf-8")
    monkeypatch.setattr(check, "ROOT", tmp_path)

    assert check._tracked_files() == ["README.md", "fresh.py"]


def test_untracked_degenerate_inventory_blocks_leak_and_artifact_scans(tmp_path, monkeypatch, capsys):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "README.md").write_text("healthy\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    value = "gh" + "p_" + "A" * 36
    (tmp_path / "fresh.py").write_text("auth = " + repr(value) + "\n", encoding="utf-8")
    artifact = tmp_path / "build" / "generated.py"
    artifact.parent.mkdir()
    artifact.write_text("generated = True\n", encoding="utf-8")
    monkeypatch.setattr(check, "ROOT", tmp_path)

    assert check.leak_scan() is False
    assert check.artifact_scan() is False
    output = capsys.readouterr().out
    assert "examined 3 candidate paths" in output
    assert "fresh.py" in output
    assert "build/generated.py" in output


def test_tree_scans_report_healthy_inventory_counts(tmp_path, monkeypatch, capsys):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "README.md").write_text("healthy\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    (tmp_path / "fresh.py").write_text("healthy = True\n", encoding="utf-8")
    monkeypatch.setattr(check, "ROOT", tmp_path)

    assert check.leak_scan() is True
    assert check.artifact_scan() is True
    output = capsys.readouterr().out
    # The leak gate publishes files READ as well as paths considered: the two
    # numbers are different measurements and only the second one used to be
    # printed, which made "0 findings" unfalsifiable. The artifact gate keeps
    # the single count on purpose -- its subject IS the path, not the content.
    # "not read" closes the denominator: the gap between paths established and
    # files examined is named in the line rather than left for a reader to
    # subtract. That invisible gap is where a tracked credential sat.
    assert "established 2 candidate paths; examined 2 text files; 0 not read; 0 findings" in output
    assert output.count("examined 2 candidate paths") == 1


def test_leak_gate_reads_a_credential_under_a_binary_looking_name(tmp_path, monkeypatch, capsys):
    """A file NAME is not a measurement of the bytes behind it.

    This gate skipped ``.png``/``.jpg``/``.gif``/``.ico`` unread, so a repo of
    two credential-bearing files under those names printed
    ``PASS (examined 2 candidate paths; 0 findings)`` -- the signature false
    clean, with an honest denominator nothing acted on.
    """
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    key = "AKIA" + "Z" * 16
    (tmp_path / "logo.png").write_text(f'aws = "{key}"\n', encoding="utf-8")
    subprocess.run(["git", "add", "--", "logo.png"], cwd=tmp_path, check=True)
    monkeypatch.setattr(check, "ROOT", tmp_path)

    assert check.leak_scan() is False
    output = capsys.readouterr().out
    assert "examined 1 text files" in output
    assert "logo.png:1  [AWS access key]" in output


def test_leak_gate_carries_a_pattern_for_the_credential_it_publishes_with(tmp_path, monkeypatch, capsys):
    """This repository publishes to PyPI and reads ``release/*.lock``; it had
    no pattern for a PyPI upload token, which is what an ``--index-url`` line
    in one of those files would carry."""
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    token = "pypi-" + "AgEIcHlwaS5vcmcC" + "Aa9_-" * 24
    (tmp_path / "req.lock").write_text(f"--index-url https://u:{token}@index/simple\n", encoding="utf-8")
    subprocess.run(["git", "add", "--", "req.lock"], cwd=tmp_path, check=True)
    monkeypatch.setattr(check, "ROOT", tmp_path)

    assert check.leak_scan() is False
    assert "[PyPI upload token]" in capsys.readouterr().out


def test_leak_gate_carries_the_modern_ai_key_shapes_its_sk_pattern_cannot_reach(tmp_path, monkeypatch, capsys):
    """``sk-[A-Za-z0-9]{20,}`` needs 20+ ALPHANUMERICS right after ``sk-``.

    Every modern AI provider key puts a hyphen there -- ``sk-ant-oat01-``,
    ``sk-ant-api03-``, ``sk-proj-`` -- so the class breaks after 3 characters,
    well short of the floor, and this catalogue matched none of them.
    ``scripts/secret_scan.py``'s own docstring documented that limitation; the
    gap it left is not theoretical, because ``.githooks/pre-push`` runs THIS
    gate as its whole-tree arm and does not run ``secret_scan.py`` at all
    (only CI does). Measured before this pattern existed:
    ``check._leak_pattern_hits`` returned ``[]`` for all three shapes.
    """
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    planted = {
        "oat.py": "sk-" + "ant-" + "oat" + "01-" + "Aa9_-" * 12,
        "api.py": "sk-" + "ant-" + "api" + "03-" + "Bb8_-" * 12,
        "proj.py": "sk-" + "proj-" + "Cc7" * 12,
    }
    for name, token in planted.items():
        (tmp_path / name).write_text(f'key = "{token}"\n', encoding="utf-8")
        subprocess.run(["git", "add", "--", name], cwd=tmp_path, check=True)
    monkeypatch.setattr(check, "ROOT", tmp_path)

    assert check.leak_scan() is False
    output = capsys.readouterr().out
    for name in planted:
        assert f"{name}:1  [AI provider key]" in output, output


def test_binary_candidate_refuses_and_a_readable_companion_does_not_rescue_it(tmp_path, monkeypatch, capsys):
    """Fail closed, and stay closed once a readable file joins the tree.

    The all-binary tree already refused, via the range-global ``examined == 0``
    floor. That floor is defeated by ONE readable companion file, which is the
    whole escape: measured over the real 51-file tree, a NUL-prefixed blob
    carrying an ``sk-ant-oat01-`` token in an ``--index-url`` line printed
    ``[check] leak scan: PASS (established 52 candidate paths; examined 51 text
    files; 0 findings)`` -- the credential sitting in the silent remainder
    between the two numbers.

    Conservation survives: the refusal is one line naming the path, not
    catalogue noise from pattern-matching arbitrary bytes.
    """
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    token = "sk-" + "ant-" + "oat" + "01-" + "Aa7_-" * 12
    probe = b"\x00\x80" + f"index-url = https://__token__:{token}@pypi.example.invalid/simple\n".encode()
    (tmp_path / "toolstate.dat").write_bytes(probe)
    subprocess.run(["git", "add", "--", "toolstate.dat"], cwd=tmp_path, check=True)
    monkeypatch.setattr(check, "ROOT", tmp_path)

    assert check.leak_scan() is False
    output = capsys.readouterr().out
    assert "examined 0 text files" in output
    assert "toolstate.dat  [unscannable binary content]" in output

    (tmp_path / "readme.md").write_text("benign\n", encoding="utf-8")
    subprocess.run(["git", "add", "--", "readme.md"], cwd=tmp_path, check=True)
    assert check.leak_scan() is False, "one readable companion file turned the unread blob back into a PASS"
    output = capsys.readouterr().out
    assert "established 2 candidate paths; examined 1 text files; 1 not read; 1 findings" in output, output
    assert "toolstate.dat  [unscannable binary content]" in output


def test_an_untracked_binary_refuses_and_is_not_called_tracked(tmp_path, monkeypatch, capsys):
    """The population is candidates, so the disposition word must be too.

    ``_tracked_files`` is ``git ls-files --cached --others
    --exclude-standard``: an untracked, non-ignored working-tree file is in it.
    The refusal shipped calling such a path ``[tracked binary content]`` and
    prescribing ``git rm --cached``, which answers ``fatal: pathspec ... did
    not match any files`` for exactly those paths. Measured on the shipped
    gate with a stray ``stray-artifact.bin`` that was never ``git add``-ed:
    ``SECRET_SCAN_EXIT=1``, ``leak scan: FAIL ... [tracked binary content]``,
    and the printed remedy fatal. The refusal is correct and stays; the two
    false statements in it do not.
    """
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "readme.md").write_text("benign\n", encoding="utf-8")
    subprocess.run(["git", "add", "--", "readme.md"], cwd=tmp_path, check=True)
    (tmp_path / "stray-artifact.bin").write_bytes(b"\x00\x80local build output, never git add-ed\n")
    monkeypatch.setattr(check, "ROOT", tmp_path)

    assert check.leak_scan() is False, "a binary candidate must refuse whether or not it is tracked"
    output = capsys.readouterr().out
    line = next(entry for entry in output.splitlines() if "stray-artifact.bin" in entry)
    assert "[unscannable binary content]" in line, line
    assert "tracked" not in line.split("]")[0], f"an untracked candidate is described as tracked: {line}"
    assert ".gitignore" in line, f"the remedy for an untracked candidate is missing: {line}"
    probe = subprocess.run(
        ["git", "rm", "--cached", "stray-artifact.bin"], cwd=tmp_path, capture_output=True, text=True
    )
    assert probe.returncode != 0, "fixture drift: the path is tracked, so the old remedy would have worked"


def test_leak_gate_that_finds_nothing_reports_broken_not_pass(tmp_path, monkeypatch, capsys):
    """The planted-control discipline ``prepush_leak_scan`` already had, on
    the gate that lacked it: with ``LEAK_PATTERNS`` emptied, ``leak_scan()``
    printed ``PASS (examined 51 candidate paths; 0 findings)`` and returned
    True over the real repository."""
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "readme.md").write_text("benign\n", encoding="utf-8")
    subprocess.run(["git", "add", "--", "readme.md"], cwd=tmp_path, check=True)
    monkeypatch.setattr(check, "ROOT", tmp_path)
    assert check._leak_control_failures() == [], "the positive control does not pass on healthy code"

    monkeypatch.setattr(check, "LEAK_PATTERNS", [])

    assert check._leak_control_failures(), "an emptied catalogue passed the gate's own positive control"
    assert check.leak_scan() is False
    assert "BROKEN" in capsys.readouterr().out


def test_leak_control_covers_both_catalogue_families(monkeypatch):
    """One planted item per FAMILY -- a credential shape and a private-
    infrastructure string -- because a control exercising only a pattern
    already known to work proves nothing about the rest."""
    for label in ("AWS access key", "VPS-local path", "GitHub token", "AI provider key"):
        monkeypatch.setattr(check, "LEAK_PATTERNS", [p for p in check.LEAK_PATTERNS if p[1] != label])
        assert check._leak_control_failures() == [f"planted control leak not detected: {label}"]
        monkeypatch.undo()


def test_leak_control_fires_when_the_expectation_list_itself_is_edited(monkeypatch):
    """The control has TWO editable halves, and it used to guard only one.

    ``_leak_control_failures`` built its result as a comprehension over
    ``_LEAK_CONTROL_EXPECTED``, so deleting a family from that tuple could only
    ever shorten the list. Measured on the shipped gate: dropping ``"AI
    provider key"`` from the tuple returned ``[]`` and ``leak_scan()`` printed
    PASS, while dropping the same family from ``LEAK_PATTERNS`` returned the
    expected failure -- so the commit that added the family described the
    mechanism backwards, and the cheaper of the two edits was the unguarded
    one. The two sets must agree exactly, in both directions.
    """
    for label in check._LEAK_CONTROL_EXPECTED:
        monkeypatch.setattr(
            check, "_LEAK_CONTROL_EXPECTED", tuple(n for n in check._LEAK_CONTROL_EXPECTED if n != label)
        )
        assert check._leak_control_failures() == [
            f"planted control leak no longer declared in _LEAK_CONTROL_EXPECTED: {label}"
        ]
        monkeypatch.undo()


def test_leak_control_fails_if_the_utf16_decode_regresses(monkeypatch):
    """The GitHub half of the control rides in as UTF-16, so the decode fix is
    a live control on every run rather than only a test."""
    monkeypatch.setattr(check, "_scan_views", lambda data: [data.decode("utf-8", errors="ignore")])

    assert check._leak_control_failures() == ["planted control leak not detected: GitHub token"]


def test_empty_quality_source_inventory_fails_both_ruff_gates(tmp_path, monkeypatch, capsys):
    for name in ("src", "tests", "scripts"):
        (tmp_path / name).mkdir()
    monkeypatch.setattr(check, "ROOT", tmp_path)
    calls = []
    monkeypatch.setattr(check, "run", lambda title, command, **kwargs: calls.append((title, command)) or True)

    assert check.ruff_gates() == [False, False]
    assert calls == []
    output = capsys.readouterr().out
    assert output.count("could not establish Python source inventory") == 2


def test_healthy_quality_source_inventory_reaches_both_ruff_gates(tmp_path, monkeypatch):
    for name in ("src", "tests", "scripts"):
        directory = tmp_path / name
        directory.mkdir()
        (directory / f"{name}.py").write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setattr(check, "ROOT", tmp_path)
    calls = []
    monkeypatch.setattr(check, "run", lambda title, command, **kwargs: calls.append(title) or True)

    assert check.ruff_gates() == [True, True]
    assert calls == ["ruff check (3 Python files)", "ruff format --check (3 Python files)"]
