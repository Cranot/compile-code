"""compile-code CLI surface tests.

The CLI is a thin product driver over the roam-code toolchain; these tests
pin the surface contract (verbs exist, delegation arguments are correct,
doctor's state reporting) with the toolchain calls stubbed — no index or
subprocess work, so they run anywhere.
"""

from __future__ import annotations

import ast
import inspect
import json
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

import compile_code
import compile_code.cli as mod
from scripts import release_artifacts as release


ROOT = Path(__file__).resolve().parents[1]
TRUSTED_CLAUDE_PATH = r"C:\Tools\claude.exe" if mod.os.name == "nt" else "/opt/claude/bin/claude"


@pytest.fixture
def runner():
    return CliRunner()


def _stub_content_digest(monkeypatch, *claude_paths):
    """Stub `_content_digest` for fixture-fiction claude paths only.

    TRUSTED_CLAUDE_PATH (and lookalikes like ``f"{TRUSTED_CLAUDE_PATH}.replaced"``)
    have no real file behind them, so the real `_content_digest` returns None
    for them -- which the `_claude` command now treats as "unverifiable" and
    refuses. Tests that stub the claude side need a non-None stand-in.

    Every other path -- notably roam's own fixture-fiction path in `_roam_info`
    -- must keep delegating to the real function, which also returns None
    there. That None has to keep comparing equal to `_roam_info()`'s absent
    "digest" key (also None): stubbing this globally to a single constant
    breaks that pre-existing roam-side digest recheck instead.
    """
    original = mod._content_digest
    fake_paths = set(claude_paths) or {TRUSTED_CLAUDE_PATH}

    def fake(path, *, max_bytes=mod.MAX_ROAM_EXECUTABLE_BYTES):
        if path in fake_paths:
            return "sha256:teststub"
        return original(path, max_bytes=max_bytes)

    monkeypatch.setattr(mod, "_content_digest", fake)


@pytest.fixture
def roam_calls(monkeypatch):
    """Stub the toolchain; record argv per call."""
    calls = []
    wiring = {"active": False}
    original_project_wired = mod._project_wired
    original_delegate = mod._delegate

    class _P:
        returncode = 0

    def fake(*args, timeout=600):
        calls.append(list(args))
        if list(args) == ["hooks", "claude", "--write"]:
            wiring["active"] = True
        return _P()

    monkeypatch.setattr(mod, "_roam", fake)

    def delegate(*args, timeout=600, executable=None, env=None):
        if executable is None:
            return original_delegate(*args, timeout=timeout, env=env)
        calls.append(list(args))
        if list(args) == ["hooks", "claude", "--write"]:
            wiring["active"] = True
        return 0

    monkeypatch.setattr(mod, "_delegate", delegate)
    # Delegation-only tests run from the checkout, whose real Claude settings
    # must not be mutated by the successful stub.
    monkeypatch.setattr(mod, "_wire_roam_midtask_access", lambda **kwargs: None)
    monkeypatch.setattr(mod, "_project_wired", lambda: wiring["active"] or original_project_wired())
    monkeypatch.setattr(
        mod,
        "_claude_wiring_state",
        lambda: (True, "project") if wiring["active"] or original_project_wired() else (False, "settings_missing"),
    )
    monkeypatch.setattr(mod, "_inspect_roam", lambda timeout=10: _roam_info())
    monkeypatch.setattr(mod, "_attest_claude_hooks", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        mod,
        "_resolve_trusted_executable",
        lambda name, *, reject_workspace: (TRUSTED_CLAUDE_PATH, None) if name == "claude" else (None, "missing"),
    )
    _stub_content_digest(monkeypatch)
    return calls


def _roam_info(
    *,
    path: str | None = "/opt/roam/bin/roam",
    executable_version: str | None = mod.MIN_ROAM_VERSION,
    metadata_version: str | None = mod.MIN_ROAM_VERSION,
    state: str = "ok",
    detail: str | None = None,
) -> dict[str, str | None]:
    return {
        "path": path,
        "version": executable_version,
        "metadata_version": metadata_version,
        "state": state,
        "detail": detail,
    }


def _bound_verify_receipt(*, target_file_count: int = 1) -> dict[str, object]:
    return {
        "schema": "roam.verify.receipt.v3",
        "request_nonce": "a" * 32,
        "scope_sha256": "b" * 64,
        "content_sha256": "c" * 64,
        "content_sha256_before": "c" * 64,
        "content_sha256_after": "c" * 64,
        "target_file_count": target_file_count,
        "scope_stable": True,
        "request_match": True,
    }


def _verify_envelope(
    *,
    verdict: str = "PASS",
    score: int = 100,
    threshold: int = 70,
    receipt: dict[str, object] | None = None,
    violations: list[dict[str, object]] | None = None,
    verification_complete: bool = True,
    partial_success: bool = False,
) -> dict[str, object]:
    receipt = dict(receipt or _bound_verify_receipt())
    findings = list(violations or [])
    categories = {name: {"score": 100, "violation_count": 0, "violations": []} for name in mod._VERIFY_CATEGORY_NAMES}
    for finding in findings:
        category = finding["category"]
        categories[category]["score"] = score
        categories[category]["violations"].append(dict(finding))
        categories[category]["violation_count"] += 1
    categories["verification"] = {"score": 100, "violation_count": 0, "violations": []}
    return {
        "schema": "roam-envelope-v1",
        "schema_version": "1.1.0",
        "command": "verify",
        "version": mod.MIN_ROAM_VERSION,
        "project": "fixture",
        "summary": {
            "verdict": verdict,
            "score": score,
            "threshold": threshold,
            "files_checked": receipt["target_file_count"],
            "targets_checked": receipt["target_file_count"],
            "violation_count": len(findings),
            "checks_run": list(mod._VERIFY_DEFAULT_CHECKS),
            "verification_complete": verification_complete,
            "partial_success": partial_success,
            "state": "verified" if verification_complete else "verification_incomplete",
            "quality_band": "PASS" if score >= 80 else "WARN" if score >= 60 else "FAIL",
            "index_refresh": {"state": "current", "refreshed_file_count": 0},
            "verification_receipt": receipt,
        },
        "categories": categories,
        "violations": findings,
        "agent_contract": {"confidence": None, "facts": [], "risks": [], "next_commands": []},
        "_meta": {},
    }


def _no_changes_envelope(receipt: dict[str, object]) -> dict[str, object]:
    """The canonical 'nothing to verify' transaction roam emits for an empty scope."""
    envelope = _verify_envelope(receipt=receipt)
    summary = envelope["summary"]
    summary.update(
        verdict="PASS",
        score=100,
        files_checked=0,
        violation_count=0,
        checks_run=[],
        state="no_changes",
    )
    for key in ("targets_checked", "verification_receipt", "quality_band", "index_refresh"):
        summary.pop(key)
    envelope["categories"] = {
        name: (
            {"score": 100, "violations": [], "available": True}
            if name == "verification"
            else {"score": 100, "violations": []}
        )
        for name in mod._VERIFY_NO_CHANGES_CATEGORY_NAMES
    }
    return envelope


@pytest.fixture
def compatible_roam(monkeypatch):
    """Keep CLI tests independent of whichever roam shim the host PATH selects."""
    info = _roam_info()
    monkeypatch.setattr(mod, "_inspect_roam", lambda timeout=10: dict(info))
    return info


class TestSurface:
    def _delegates(self, runner, roam_calls, argv, expected):
        """Invoke argv and assert the toolchain was called exactly once with
        expected. Returns the Click result for any extra assertions."""
        res = runner.invoke(mod.cli, argv)
        assert roam_calls == [expected]
        return res

    def test_help_lists_all_verbs(self, runner):
        res = runner.invoke(mod.cli, ["--help"])
        for verb in ("init", "wire", "unwire", "baseline", "report", "claude", "run", "stats", "doctor"):
            assert verb in res.output

    def test_help_lists_every_registered_command(self, runner):
        # Self-updating: any @cli.command(...) added in future must surface in --help.
        output = runner.invoke(mod.cli, ["--help"]).output
        for name in mod.cli.commands.keys():
            assert name in output, f"registered command {name!r} missing from --help"

    def test_claude_help_preserves_zero_learning_curve_wording(self, runner):
        result = runner.invoke(mod.cli, ["claude", "--help"])
        assert result.exit_code == 0
        assert "zero-learning-curve" in result.output
        assert "zero- learning-curve" not in result.output

    def test_init_delegates(self, runner, roam_calls):
        res = self._delegates(runner, roam_calls, ["init"], ["init"])
        assert res.exit_code == 0

    def test_init_force_uses_index_force(self, runner, roam_calls):
        self._delegates(runner, roam_calls, ["init", "--force"], ["index", "--force"])

    def test_wire_claude_delegates_to_hooks(self, runner, roam_calls):
        res = self._delegates(runner, roam_calls, ["wire", "claude"], ["hooks", "claude", "--write"])
        assert res.exit_code == 0

    def test_wire_no_verify_and_user_flags_pass_through(self, runner, roam_calls):
        self._delegates(
            runner,
            roam_calls,
            ["wire", "claude", "--no-verify", "--user"],
            ["hooks", "claude", "--write", "--no-verify", "--user"],
        )

    def test_unwire_claude(self, runner, roam_calls):
        self._delegates(runner, roam_calls, ["unwire", "claude"], ["hooks", "claude", "--uninstall", "--write"])

    def test_unwire_user_flag_passes_through(self, runner, roam_calls):
        self._delegates(
            runner,
            roam_calls,
            ["unwire", "claude", "--user"],
            ["hooks", "claude", "--uninstall", "--write", "--user"],
        )

    def test_run_compiles_with_auto_artifact(self, runner, roam_calls):
        self._delegates(
            runner,
            roam_calls,
            ["run", "who calls handleSave"],
            ["compile", "who calls handleSave", "--artifact", "auto"],
        )

    def test_run_json_prepends_global_flag(self, runner, roam_calls):
        self._delegates(
            runner,
            roam_calls,
            ["run", "task", "--json"],
            ["--json", "compile", "task", "--artifact", "auto"],
        )

    def test_run_stamps_compile_agent_mode(self, runner, monkeypatch):
        seen = []

        def fake(*args, timeout=600):
            seen.append(mod.os.environ.get("ROAM_AGENT_MODE"))

            class _P:
                returncode = 0

            return _P()

        monkeypatch.setattr(mod, "_roam", fake)
        res = runner.invoke(mod.cli, ["run", "task"])

        assert res.exit_code == 0
        assert seen == ["compile"]
        assert "ROAM_AGENT_MODE" not in mod.os.environ

    def test_run_preserves_codex_agent_mode(self, runner, monkeypatch):
        seen = []

        def fake(*args, timeout=600):
            seen.append(mod.os.environ.get("ROAM_AGENT_MODE"))

            class _P:
                returncode = 0

            return _P()

        monkeypatch.setenv("ROAM_AGENT_MODE", "compile_codex")
        monkeypatch.setattr(mod, "_roam", fake)
        res = runner.invoke(mod.cli, ["run", "task"])

        assert res.exit_code == 0
        assert seen == ["compile_codex"]

    def test_stats_delegates(self, runner, roam_calls):
        self._delegates(runner, roam_calls, ["stats"], ["compile-stats"])

    def test_stats_does_not_stamp_compile_agent_mode(self, runner, monkeypatch):
        seen = []

        def fake(*args, timeout=600):
            seen.append(mod.os.environ.get("ROAM_AGENT_MODE"))

            class _P:
                returncode = 0

            return _P()

        monkeypatch.delenv("ROAM_AGENT_MODE", raising=False)
        monkeypatch.setattr(mod, "_roam", fake)
        res = runner.invoke(mod.cli, ["stats"])

        assert res.exit_code == 0
        assert seen == [None]
        assert "ROAM_AGENT_MODE" not in mod.os.environ

    def test_report_delegates_to_persisted_verify_report(self, runner, roam_calls):
        res = self._delegates(runner, roam_calls, ["report"], ["verify", "--report", "--persist"])
        assert res.exit_code == 0

    def test_baseline_help_lists_the_new_verb(self, runner):
        res = runner.invoke(mod.cli, ["baseline", "--help"])
        assert "Snapshot accepted debt" in res.output

    def test_verify_help_includes_scope_and_filter_options(self, runner):
        res = runner.invoke(mod.cli, ["verify", "--help"])
        assert "--changed" in res.output
        assert "--new-only" in res.output
        assert "--diff-only" in res.output


# The exact bytes a stub toolchain emits for `compile run --json`. Deliberately
# NOT a captured roam sample: a golden blob rots the moment roam adds a field,
# and the property under test is *fidelity*, not the current field list. The
# payload carries the two contract blocks a consumer must not lose plus one
# field this CLI has never heard of, so an enumerate-and-rebuild refactor fails
# even if the author remembered every field that existed on the day they wrote it.
_ENVELOPE_UNKNOWN_FIELD = "a_block_this_cli_has_never_heard_of"
_STUB_ENVELOPE = json.dumps(
    {
        "schema": "roam-envelope-v1",
        "schema_version": "1.0",
        "command": "compile",
        "orchestration_contract": {
            "schema_version": "1.0",
            "review_policy": "risk_gated",
            "obligations": [
                "1b. CRITIQUE the plan independently: before implementing, have a SEPARATE model attack the plan.",
                "4b. VERDICT before done: a SEPARATE model reviews the finished diff against the frozen criteria.",
            ],
            "criteria_templates": {
                "1b_plan_critique": "plan-critique-v1",
                "4b_done_verdict": "done-verdict-v1",
            },
        },
        "execution_contract": [
            "1. PLAN first",
            "2. IMPLEMENT in phases",
            "3. PROVE it",
            "4. RECHECK",
            "5. Done means run for real",
        ],
        _ENVELOPE_UNKNOWN_FIELD: {"nested": [1, 2, {"deep": True}]},
    },
    sort_keys=True,
).encode("utf-8")

_CLI_BOOTSTRAP = "import sys; from compile_code.cli import cli; sys.exit(cli())"


class TestCompileEnvelopePassthrough:
    """`compile run` must FORWARD the toolchain envelope, never rebuild it.

    The whole product value of this verb is that the agent receives roam's
    compiled envelope. That envelope grows: the review obligations
    (``orchestration_contract``) and the phased ``execution_contract`` were
    both added after this CLI shipped. A consumer that re-emits the envelope
    field-by-field looks correct on the day it is written and silently drops
    every block added afterwards -- the exact defect already found and fixed
    once in the Claude Code hook. These tests run the real process boundary
    (file descriptors, not a CliRunner string buffer) because that inheritance
    IS the forwarding mechanism.
    """

    def _make_trust_root(self, work: Path) -> None:
        """Anchor the workspace trust scan at *work* itself.

        ``_resolve_trusted_executable(reject_workspace=True)`` refuses a
        toolchain found inside the invoking checkout, and it walks parents
        until it finds Git/roam evidence. Giving the working directory its own
        credible ``.git`` stops that walk here, so the sibling stub directory
        is never swept into the rejected set by whatever happens to sit above
        the temporary path.
        """
        git = work / ".git"
        (git / "objects").mkdir(parents=True)
        (git / "refs").mkdir(parents=True)
        (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

    def _make_roam_stub(self, bindir: Path, payload: bytes) -> None:
        """Install a `roam` on PATH that writes *payload* to stdout verbatim."""
        bindir.mkdir(parents=True, exist_ok=True)
        emitter = bindir / "roam_stub.py"
        emitter.write_text(
            f"import sys\nsys.stdout.buffer.write({payload!r})\nsys.stdout.buffer.flush()\n",
            encoding="utf-8",
        )
        if mod.os.name == "nt":
            shim = bindir / "roam.cmd"
            shim.write_text(f'@echo off\r\n"{sys.executable}" "{emitter}"\r\n', encoding="utf-8")
        else:
            shim = bindir / "roam"
            shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{emitter}"\n', encoding="utf-8")
            shim.chmod(0o755)

    def _compiled_stdout(self, tmp_path: Path) -> bytes:
        """Raw stdout of `compile run --json` against the stub toolchain."""
        work = tmp_path / "work"
        work.mkdir()
        self._make_trust_root(work)
        bindir = tmp_path / "bin"
        self._make_roam_stub(bindir, _STUB_ENVELOPE)

        env = mod.os.environ.copy()
        env["PATH"] = str(bindir) + mod.os.pathsep + env.get("PATH", "")
        env["PYTHONPATH"] = str(ROOT / "src")
        proc = subprocess.run(
            [sys.executable, "-c", _CLI_BOOTSTRAP, "run", "--json", "fix the empty-payload bug in src/app.py"],
            cwd=work,
            env=env,
            capture_output=True,
            timeout=120,
        )
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        return proc.stdout

    def test_envelope_reaches_stdout_byte_for_byte(self, tmp_path):
        # Byte equality is the strongest statement of the forwarding contract:
        # nothing was parsed, re-serialized, reordered, wrapped, or truncated.
        assert self._compiled_stdout(tmp_path) == _STUB_ENVELOPE

    def test_review_obligations_survive_end_to_end(self, tmp_path):
        emitted = json.loads(_STUB_ENVELOPE)
        received = json.loads(self._compiled_stdout(tmp_path))

        contract = received.get("orchestration_contract")
        assert isinstance(contract, dict), "orchestration_contract was dropped by the consumer"
        # Assert the contract's shape, not a frozen wording: the obligations
        # are prose roam owns and will reword.
        assert set(contract) >= {"schema_version", "review_policy", "obligations", "criteria_templates"}
        assert contract["obligations"] == emitted["orchestration_contract"]["obligations"]
        assert contract["criteria_templates"] == emitted["orchestration_contract"]["criteria_templates"]
        assert set(contract["criteria_templates"]) == {"1b_plan_critique", "4b_done_verdict"}
        assert received.get("execution_contract") == emitted["execution_contract"]

    def test_a_field_this_cli_does_not_know_about_still_arrives(self, tmp_path):
        # The anti-enumeration guard. A passing suite that only covers today's
        # field list is not evidence of forwarding -- this is.
        received = json.loads(self._compiled_stdout(tmp_path))
        assert received.get(_ENVELOPE_UNKNOWN_FIELD) == {"nested": [1, 2, {"deep": True}]}
        assert set(received) == set(json.loads(_STUB_ENVELOPE))

    def test_run_never_reads_the_envelope_it_forwards(self):
        # A structural companion to the behavioral tests above: the forwarding
        # path must not acquire a capture step, because capturing is the first
        # move of every rebuild. `_delegate` streams; `_delegate_capturing`
        # does not, and belongs to the verify protocol only.
        source = inspect.getsource(mod._run.callback)
        assert "_delegate_capturing" not in source
        assert "json.loads" not in source
        assert "_strict_json_document" not in source


class TestVersionReporting:
    """A reported version that lies is worse than none: it silently
    invalidates every bug report and deploy verification that quotes it.

    ``compile --version`` resolves ``compile_code.__version__`` via
    ``importlib.metadata`` rather than a hardcoded literal (see
    ``compile_code/__init__.py``), so there is exactly one place a real
    literal-vs-pyproject drift could reappear if someone "optimized" that
    lookup away later. This guard pins the *outcome* (reported == declared),
    not a snapshot of today's string, so it fails the moment the two sources
    diverge for any reason — including a stale installed/editable dist whose
    metadata was never refreshed after a pyproject.toml version bump.
    """

    def test_reported_version_matches_pyproject_declared_version(self, runner):
        declared = release._project_version(ROOT)
        result = runner.invoke(mod.cli, ["--version"])

        assert result.exit_code == 0
        assert compile_code.__version__ == declared, (
            f"compile_code.__version__ ({compile_code.__version__!r}) has drifted from "
            f"pyproject.toml's declared version ({declared!r}) — reinstall the editable "
            "package (`pip install -e .`) so installed metadata matches the source tree."
        )
        assert result.output.strip() == f"cli, version {declared}"

    def test_version_flag_is_eager_and_short_circuits_the_group(self, runner):
        # --version must exit before the group body runs, so it never touches
        # the toolchain even if invoked alongside other (invalid) arguments.
        result = runner.invoke(mod.cli, ["--version", "not-a-real-subcommand"])
        assert result.exit_code == 0
        assert "version" in result.output


class TestDependencyFloor:
    def test_the_runtime_requirement_is_a_floor_with_no_product_major_ceiling(self):
        assert mod.MIN_ROAM_VERSION == "13.10.0"
        assert mod.ROAM_VERSION_REQUIREMENT == ">=13.10.0"
        assert mod.ROAM_PACKAGE_REQUIREMENT == "roam-code>=13.10.0"
        # The deleted ceiling must not return as a constant, a comparison, or a
        # clause. It detected nothing -- it deferred every compatibility
        # question to a human typing a bigger number -- while costing a total
        # outage on every kernel major bump.
        assert not hasattr(mod, "MAX_ROAM_MAJOR_EXCLUSIVE")
        assert "<" not in mod.ROAM_VERSION_REQUIREMENT
        source = (ROOT / "src" / "compile_code" / "cli.py").read_text(encoding="utf-8")
        assert "MAX_ROAM_MAJOR_EXCLUSIVE" not in source

    def test_the_packaging_pin_keeps_a_ceiling_and_shares_only_the_floor(self):
        # The pin is a RESOLVER input naming the newest major a receipt-v3
        # transaction has been run against; the runtime requirement is a
        # REFUSAL. They deliberately differ, and the floor is the only clause
        # they share -- a stale pin costs a dependency resolution, not a
        # verify outage.
        floor = mod.MIN_ROAM_VERSION
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        assert f'"roam-code<15,>={floor}"' in pyproject
        package_spec = re.search(r'"roam-code([^"\r\n]+)"', pyproject)
        assert package_spec is not None
        clauses = set(package_spec.group(1).split(","))
        assert clauses == {"<15", f">={floor}"}
        assert clauses & set(mod.ROAM_VERSION_REQUIREMENT.split(",")) == {f">={floor}"}
        for name in ("README.md", "AGENTS.md"):
            contents = (ROOT / name).read_text(encoding="utf-8")
            assert re.search(rf"roam-code[^\n]{{0,80}}>=\s*{re.escape(floor)}", contents)

    @pytest.mark.parametrize(
        ("function_name", "call_source"),
        [
            ("_ensure_indexed_for_launch", "if _require_index():"),
            ("_doctor", "indexed = _require_index()"),
        ],
    )
    def test_readme_prefetched_locations_match_current_source(self, function_name, call_source):
        source = (ROOT / "src" / "compile_code" / "cli.py").read_text(encoding="utf-8").splitlines()
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        definition_line = next(
            index for index, line in enumerate(source, 1) if line.startswith(f"def {function_name}(")
        )
        call_line = next(
            index
            for index, line in enumerate(source[definition_line:], definition_line + 1)
            if line.strip() == call_source
        )
        assert f"'location': 'src/compile_code/cli.py:{definition_line}'" in readme
        assert f"'call_location': 'src/compile_code/cli.py:{call_line}'" in readme


class TestRoamVersionEnforcement:
    @pytest.mark.parametrize(
        ("raw", "compatible"),
        [
            ("13.9.99", False),
            ("13.10.0rc1", False),
            ("13.10.0", True),
            ("13.10.0.post1", True),
            ("13.10.0dev1", False),
            ("13.99.0", True),
            ("13.99.0rc1", False),
            # No product-major ceiling: a newer kernel major clears the floor.
            # A PRERELEASE of it still does not, because the floor carries no
            # prerelease and an unreleased build is not a supported one.
            ("14.0.0rc1", False),
            ("14.0.0", True),
            ("99.0.0", True),
            ("not-a-version", False),
        ],
    )
    def test_minimum_comparison(self, raw, compatible):
        assert mod._version_meets_minimum(raw) is compatible

    def test_pathological_numeric_version_is_rejected_without_integer_failure(self):
        assert mod._version_meets_minimum("9" * 5000 + ".0.0") is False

    def test_inspection_runs_the_exact_path_and_keeps_metadata_separate(self, monkeypatch):
        chosen = r"C:\Tools\roam.exe"
        captured = {}
        monkeypatch.setenv("PYTHONPATH", "malicious")

        class _P:
            returncode = 0
            stdout = b"roam.EXE, version 13.10.2\n"
            stderr = b""

        def fake_run(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return _P()

        monkeypatch.setattr(mod, "_resolve_roam_executable", lambda: chosen)
        monkeypatch.setattr(mod, "_python_roam_metadata_version", lambda: "99.0.0")
        monkeypatch.setattr(mod, "_run_bounded_capture", fake_run)

        info = mod._inspect_roam()

        assert captured["argv"] == [chosen, "--version"]
        assert info["path"] == chosen
        assert info["version"] == "13.10.2"
        assert info["metadata_version"] == "99.0.0"
        assert "PYTHONPATH" not in captured["kwargs"]["env"]
        assert captured["kwargs"]["env"]["PYTHONSAFEPATH"] == "1"
        assert captured["kwargs"]["stdout_limit"] == mod.MAX_ROAM_VERSION_BYTES
        assert captured["kwargs"]["stderr_limit"] == mod.MAX_ROAM_VERSION_BYTES

    @pytest.mark.parametrize("noise_lines", [1, 3])
    def test_stderr_chatter_beside_a_good_version_is_refused_with_the_real_reason(self, monkeypatch, noise_lines):
        # Both streams must stay clean -- the version check is the one call this
        # CLI trusts a stranger's binary for -- so this still fails closed. But
        # "returned no parseable version" is false when the version was right
        # there on stdout, and it sends the reader to reinstall a roam that is
        # fine while the real cause (a plugin or wrapper writing to stderr) goes
        # unnamed. The refusal must distinguish the two.
        class _P:
            returncode = 0
            stdout = b"roam, version 13.10.2\n"
            stderr = b"DeprecationWarning: something in a plugin\n" * noise_lines

        monkeypatch.setattr(mod, "_resolve_roam_executable", lambda: r"C:\Tools\roam.exe")
        monkeypatch.setattr(mod, "_python_roam_metadata_version", lambda: None)
        monkeypatch.setattr(mod, "_run_bounded_capture", lambda argv, **kwargs: _P())

        info = mod._inspect_roam()

        assert info["state"] == "malformed_version"
        assert info["version"] is None
        detail = info["detail"]
        assert "13.10.2" in detail
        assert f"{noise_lines} line(s) to stderr" in detail
        # The untrusted line itself is never replayed into the verdict.
        assert "DeprecationWarning" not in detail

        problem = mod._roam_problem(info)
        assert problem is not None
        assert problem[0] == mod.EXIT_TOOLCHAIN
        assert "DeprecationWarning" not in problem[1]

    def test_a_genuinely_unparseable_version_keeps_the_plain_reason(self, monkeypatch):
        class _P:
            returncode = 0
            stdout = b"not a version line at all\n"
            stderr = b""

        monkeypatch.setattr(mod, "_resolve_roam_executable", lambda: r"C:\Tools\roam.exe")
        monkeypatch.setattr(mod, "_python_roam_metadata_version", lambda: None)
        monkeypatch.setattr(mod, "_run_bounded_capture", lambda argv, **kwargs: _P())

        info = mod._inspect_roam()

        assert info["state"] == "malformed_version"
        assert info["detail"] == "`roam --version` returned no parseable version"

    @pytest.mark.parametrize(
        "output",
        [
            "warning: injected\nroam, version 13.10.0\n",
            "roam, version 13.10.0\ntrailing diagnostic\n",
            "roam, version 13.10.0\nroam, version 13.10.0\n",
        ],
        ids=["prefix", "suffix", "duplicate"],
    )
    def test_version_parser_requires_one_canonical_line(self, output):
        assert mod._extract_roam_version(output) is None

    def test_trusted_tool_env_removes_workspace_and_interpreter_injection(self, monkeypatch, tmp_path):
        workspace = tmp_path / "workspace"
        external_bin = tmp_path / "external-bin"
        workspace.mkdir()
        external_bin.mkdir()
        (workspace / ".git").mkdir()
        monkeypatch.chdir(workspace)
        monkeypatch.setenv("PATH", f"{workspace}{mod.os.pathsep}{external_bin}")
        monkeypatch.setenv("PYTHONPATH", str(workspace))
        monkeypatch.setenv("PYTHONHOME", str(workspace))
        monkeypatch.setenv("GIT_DIR", str(workspace / "forged.git"))
        monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")

        env = mod._trusted_tool_env(git=True)

        assert env["PATH"] == str(external_bin.resolve())
        assert "PYTHONPATH" not in env
        assert "PYTHONHOME" not in env
        assert "GIT_DIR" not in env
        assert "GIT_CONFIG_KEY_0" not in env
        assert env["PYTHONSAFEPATH"] == "1"

    def test_verify_blocks_old_path_executable_even_with_newer_metadata(self, runner, monkeypatch):
        path = r"C:\old-bin\roam.exe"
        monkeypatch.setattr(
            mod,
            "_inspect_roam",
            lambda timeout=10: _roam_info(path=path, executable_version="13.9.9", metadata_version="13.10.4"),
        )
        monkeypatch.setattr(mod, "_roam_capture", lambda *a, **kw: pytest.fail("Verify must not run"))

        res = runner.invoke(mod.cli, ["verify"])

        assert res.exit_code == mod.EXIT_TOOLCHAIN
        assert "toolchain version mismatch" in res.output
        assert path in res.output
        assert "reports 13.9.9" in res.output
        assert "Python metadata reports roam-code 13.10.4" in res.output

    def test_verify_does_not_refuse_a_future_major_at_the_toolchain_gate(self, runner, monkeypatch):
        # The inverse of a refusal this build used to make. A product-major
        # ceiling turned every kernel major bump into `compile verify` exit 2
        # with no verification, against a roam whose own envelope declared
        # itself compatible. The gate must now stop at the floor and hand the
        # compatibility question to the envelope contract.
        path = r"C:\future-bin\roam.exe"
        reached = []

        class _ReachedVerifier(Exception):
            pass

        def _capture(*args, **kwargs):
            reached.append(True)
            raise _ReachedVerifier

        monkeypatch.setattr(
            mod,
            "_inspect_roam",
            lambda timeout=10: _roam_info(path=path, executable_version="99.0.0", metadata_version="99.0.0"),
        )
        monkeypatch.setattr(mod, "_roam_capture", _capture)

        result = runner.invoke(mod.cli, ["verify", "src/cli.py"])

        assert reached == [True], "a future major must reach the verifier, not a version refusal"
        assert isinstance(result.exception, _ReachedVerifier)
        assert "toolchain version mismatch" not in result.output

    def test_the_only_remediation_left_is_the_upgrade_that_is_actually_true(self):
        # The constraint is a floor, so a version refusal has exactly one cause
        # and "upgrade roam" is the true description of it. The second arm --
        # for callers above a ceiling, where pip resolved DOWNWARD and the word
        # "upgrade" described the opposite of what happened -- went with the
        # ceiling it existed to describe.
        fix = mod._roam_remediation()

        assert fix == 'python -m pip install --upgrade "roam-code>=13.10.0"'
        assert "OLDER" not in fix
        assert "<" not in fix

    def test_doctor_reports_path_version_and_metadata_separately(self, runner, monkeypatch, tmp_path):
        path = r"C:\old-bin\roam.exe"
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod.os.path, "expanduser", lambda value: str(tmp_path / "home"))
        monkeypatch.setattr(
            mod,
            "_inspect_roam",
            lambda timeout=10: _roam_info(path=path, executable_version="13.9.9", metadata_version="13.10.4"),
        )

        res = runner.invoke(mod.cli, ["doctor"])

        assert res.exit_code == mod.EXIT_TOOLCHAIN
        assert "toolchain : INCOMPATIBLE" in res.output
        assert f"roam path : {path}" in res.output
        assert "roam version: 13.9.9 (required >=13.10.0)" in res.output
        assert "python metadata: roam-code 13.10.4" in res.output


class TestFutureRoamMajorIsVerifiedNotRefused:
    """A newer kernel major is verified; the CONTRACT decides, not the number.

    Deleting the runtime product-major ceiling is only safe if the guards that
    read the actual contract still refuse at that future major. The ceiling
    itself refused there and detected nothing -- constructed drift probes run
    through the real verify path were caught by these guards, never by the
    version number -- so this class pins both halves at once: a future major
    with a readable envelope runs to a real verdict, and each envelope-level
    refusal still fires AT that same future major.
    """

    FUTURE = "99.0.0"

    @pytest.fixture(autouse=True)
    def _future_major_roam(self, monkeypatch):
        monkeypatch.setattr(mod, "_discover_verify_targets", lambda _root: [(" M", "changed.py")])
        monkeypatch.setattr(
            mod,
            "_inspect_roam",
            lambda timeout=10: _roam_info(executable_version=self.FUTURE, metadata_version=self.FUTURE),
        )

    def _invoke(self, runner, monkeypatch, mutate=None):
        def fake(*args, timeout=600, executable="roam", env=None):
            receipt = {
                "schema": mod.VERIFY_RECEIPT_SCHEMA,
                "request_nonce": env["ROAM_VERIFY_REQUEST_NONCE"],
                "scope_sha256": env["ROAM_VERIFY_SCOPE_SHA256"],
                "content_sha256": env["ROAM_VERIFY_CONTENT_SHA256"],
                "content_sha256_before": env["ROAM_VERIFY_CONTENT_SHA256"],
                "content_sha256_after": env["ROAM_VERIFY_CONTENT_SHA256"],
                "target_file_count": int(env["ROAM_VERIFY_SCOPE_COUNT"]),
                "scope_stable": True,
                "request_match": True,
            }
            envelope = _verify_envelope(receipt=receipt)
            envelope["version"] = self.FUTURE
            if mutate is not None:
                mutate(envelope)

            class _P:
                stdout = json.dumps(envelope)
                stderr = ""
                returncode = 0

            return _P()

        monkeypatch.setattr(mod, "_roam_capture", fake)
        return runner.invoke(mod.cli, ["verify"])

    def test_a_readable_envelope_from_a_future_major_is_verified(self, runner, monkeypatch):
        result = self._invoke(runner, monkeypatch)

        assert result.exit_code == 0
        assert "VERDICT: PASS" in result.output
        assert "toolchain version mismatch" not in result.output

    def test_a_different_envelope_major_still_refuses_at_a_future_product_major(self, runner, monkeypatch):
        result = self._invoke(runner, monkeypatch, lambda e: e.update(schema_version="2.0.0"))

        assert result.exit_code == mod.EXIT_TOOLCHAIN
        assert "envelope_schema_incompatible" in result.output

    def test_an_unknown_incompleteness_signal_still_refuses_and_names_the_field(self, runner, monkeypatch):
        result = self._invoke(runner, monkeypatch, lambda e: e.update(warnings=["something"]))

        assert result.exit_code == mod.EXIT_TOOLCHAIN
        assert "unknown_incompleteness_signal" in result.output
        assert "warnings" in result.output

    def test_a_neutral_additive_field_passes_and_is_disclosed_as_unread(self, runner, monkeypatch):
        result = self._invoke(
            runner,
            monkeypatch,
            lambda e: e.update(schema_version="1.3.0", provenance_note="built by a newer kernel"),
        )

        assert result.exit_code == 0
        assert "VERDICT: PASS" in result.output
        assert "provenance_note" in result.output


@pytest.mark.usefixtures("compatible_roam")
class TestWiringSmoke:
    def test_wire_round_trip_marks_repo_and_doctor_sees_it(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_text("")
        (tmp_path / ".claude").mkdir()
        calls = []

        class _P:
            returncode = 0

        def fake(*args, timeout=600):
            calls.append(list(args))
            if list(args) == ["hooks", "claude", "--write"]:
                _write_valid_claude_wiring(tmp_path)
            return _P()

        monkeypatch.setattr(mod, "_roam", fake)
        res = runner.invoke(mod.cli, ["wire", "claude"])
        assert res.exit_code == 0
        assert calls == [["hooks", "claude", "--write"]]
        doctor = runner.invoke(mod.cli, ["doctor"])
        assert "wired (project)" in doctor.output
        assert "VERDICT: ready" in doctor.output


class TestRoamMidtaskWiring:
    def _stub_successful_hook_write(self, monkeypatch, tmp_path):
        class _P:
            returncode = 0

        def fake(*args, timeout=600):
            assert list(args) == ["hooks", "claude", "--write"]
            _write_valid_claude_wiring(tmp_path)
            return _P()

        monkeypatch.setattr(mod, "_roam", fake)

    def test_wire_adds_curated_permissions_and_guidance_once(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        self._stub_successful_hook_write(monkeypatch, tmp_path)
        local_settings = tmp_path / ".claude" / "settings.local.json"
        local_settings.parent.mkdir()
        local_settings.write_text('{"permissions": {"allow": ["Bash(pytest:*)"]}, "theme": "dark"}')
        (tmp_path / "CLAUDE.md").write_text("# Existing instructions\n\nKeep this text.\n")

        first = runner.invoke(mod.cli, ["wire", "claude"])
        second = runner.invoke(mod.cli, ["wire", "claude"])

        assert first.exit_code == second.exit_code == 0
        settings = json.loads(local_settings.read_text())
        allow = settings["permissions"]["allow"]
        assert settings["theme"] == "dark"
        assert "Bash(pytest:*)" in allow
        for entry in mod.ROAM_MIDTASK_ALLOW:
            assert allow.count(entry) == 1
        guidance = (tmp_path / "CLAUDE.md").read_text()
        assert guidance.startswith("# Existing instructions\n\nKeep this text.\n")
        assert guidance.count(mod.ROAM_GUIDANCE_BEGIN) == 1
        assert guidance.count(mod.ROAM_GUIDANCE_END) == 1
        for command in mod.ROAM_MIDTASK_COMMANDS:
            assert guidance.count(f"`roam {command} --json`") == 1
        assert "roam ask --json" not in guidance
        assert "launch-time graph" in guidance
        assert "edits are invisible until the Stop hook" in guidance

    def test_wire_no_verify_still_adds_curated_permissions_and_guidance(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)

        class _P:
            returncode = 0

        def fake(*args, timeout=600):
            assert list(args) == ["hooks", "claude", "--write", "--no-verify"]
            _write_valid_claude_wiring(tmp_path, include_verify=False)
            return _P()

        monkeypatch.setattr(mod, "_roam", fake)

        result = runner.invoke(mod.cli, ["wire", "claude", "--no-verify"])

        assert result.exit_code == 0
        settings = json.loads((tmp_path / ".claude" / "settings.local.json").read_text())
        assert settings["permissions"]["allow"] == list(mod.ROAM_MIDTASK_ALLOW)
        guidance = (tmp_path / "CLAUDE.md").read_text()
        assert mod.ROAM_GUIDANCE_BEGIN in guidance
        assert mod.ROAM_GUIDANCE_END in guidance

    def test_wire_leaves_malformed_local_settings_and_guidance_untouched(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        self._stub_successful_hook_write(monkeypatch, tmp_path)
        local_settings = tmp_path / ".claude" / "settings.local.json"
        local_settings.parent.mkdir()
        local_settings.write_text("{not-json\n")
        claude_md = tmp_path / "CLAUDE.md"
        claude_md.write_text("# Existing instructions\n")

        result = runner.invoke(mod.cli, ["wire", "claude"])

        assert result.exit_code == 0
        assert local_settings.read_text() == "{not-json\n"
        assert claude_md.read_text() == "# Existing instructions\n"

    def test_midtask_merge_never_follows_a_settings_symlink(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        _write_valid_claude_wiring(tmp_path)
        external = tmp_path / "external-settings.json"
        external.write_text('{"permissions": {"allow": []}}\n', encoding="utf-8")
        local = tmp_path / ".claude" / "settings.local.json"
        try:
            local.symlink_to(external)
        except OSError as exc:
            pytest.skip(f"file symlinks unavailable: {exc}")
        before = external.read_bytes()

        mod._wire_roam_midtask_access(user_level=False)

        assert external.read_bytes() == before
        assert not (tmp_path / "CLAUDE.md").exists()

    def test_guidance_merge_never_follows_a_claude_md_symlink(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        _write_valid_claude_wiring(tmp_path)
        external = tmp_path / "external-instructions.md"
        external.write_text("# External\n", encoding="utf-8")
        guidance = tmp_path / "CLAUDE.md"
        try:
            guidance.symlink_to(external)
        except OSError as exc:
            pytest.skip(f"file symlinks unavailable: {exc}")
        before = external.read_bytes()

        mod._wire_roam_midtask_access(user_level=False)

        assert external.read_bytes() == before
        assert guidance.is_symlink()


class TestClaudeLaunch:
    def test_missing_claude_binary_exits_1(self, runner, roam_calls, monkeypatch):
        monkeypatch.setattr(
            mod,
            "_resolve_trusted_executable",
            lambda name, *, reject_workspace: (None, "missing"),
        )
        res = runner.invoke(mod.cli, ["claude"])
        assert res.exit_code == 1
        assert "not found on PATH" in res.output

    def _stub_launch(self, monkeypatch, rc=0):
        """Stub the launch seam; record (argv, env) per call."""
        launches = []

        def fake(argv, env, *, use_exec=None):
            launches.append((list(argv), dict(env)))
            return rc

        monkeypatch.setattr(mod, "_launch_agent", fake)
        return launches

    def test_indexes_wires_then_execs(self, runner, roam_calls, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)  # no index here
        launches = self._stub_launch(monkeypatch)
        res = runner.invoke(mod.cli, ["claude", "--", "-p", "hello"])
        assert res.exit_code == 0
        assert ["init"] in roam_calls
        assert ["hooks", "claude", "--write"] in roam_calls
        assert launches and launches[0][0][0] == TRUSTED_CLAUDE_PATH

    def test_all_in_one_launch_adds_project_midtask_access(self, runner, roam_calls, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        midtask_calls = []
        monkeypatch.setattr(mod, "_wire_roam_midtask_access", lambda **kwargs: midtask_calls.append(kwargs))
        launches = self._stub_launch(monkeypatch)

        result = runner.invoke(mod.cli, ["claude"])

        assert result.exit_code == 0
        assert ["hooks", "claude", "--write"] in roam_calls
        assert midtask_calls == [{"user_level": False}]
        assert launches

    def test_skips_wiring_when_repo_is_already_wired(self, runner, roam_calls, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        _write_valid_claude_wiring(tmp_path)
        midtask_calls = []
        monkeypatch.setattr(mod, "_wire_roam_midtask_access", lambda **kwargs: midtask_calls.append(kwargs))
        launches = self._stub_launch(monkeypatch)
        res = runner.invoke(mod.cli, ["claude"])
        assert res.exit_code == 0
        assert roam_calls == []
        assert midtask_calls == [{"user_level": False}]
        assert launches and launches[0][0][0] == TRUSTED_CLAUDE_PATH

    def test_existing_user_global_wiring_adds_user_midtask_access_without_rewrite(
        self, runner, roam_calls, monkeypatch, tmp_path
    ):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        monkeypatch.setattr(mod, "_claude_wiring_state", lambda: (True, "user"))
        midtask_calls = []
        monkeypatch.setattr(mod, "_wire_roam_midtask_access", lambda **kwargs: midtask_calls.append(kwargs))
        launches = self._stub_launch(monkeypatch)

        result = runner.invoke(mod.cli, ["claude"])

        assert result.exit_code == 0
        assert roam_calls == []
        assert midtask_calls == [{"user_level": True}]
        assert launches and launches[0][0][0] == TRUSTED_CLAUDE_PATH

    def test_wires_when_repo_is_indexed_but_unwired(self, runner, roam_calls, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        launches = self._stub_launch(monkeypatch)
        res = runner.invoke(mod.cli, ["claude"])
        assert res.exit_code == 0
        assert ["hooks", "claude", "--write"] in roam_calls
        assert launches and launches[0][0][0] == TRUSTED_CLAUDE_PATH

    def test_launch_exit_code_propagates(self, runner, roam_calls, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        _write_valid_claude_wiring(tmp_path)
        self._stub_launch(monkeypatch, rc=7)
        res = runner.invoke(mod.cli, ["claude"])
        assert res.exit_code == 7

    def test_read_only_sets_child_mode_enforcement(self, runner, roam_calls, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        monkeypatch.delenv("ROAM_AGENT_MODE", raising=False)
        monkeypatch.delenv("ROAM_MODE_ENFORCEMENT", raising=False)
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        _write_valid_claude_wiring(tmp_path)
        launches = self._stub_launch(monkeypatch)

        res = runner.invoke(mod.cli, ["claude", "--read-only"])

        assert res.exit_code == 0
        child_env = launches[0][1]
        assert child_env["ROAM_AGENT_MODE"] == "read_only"
        assert child_env["ROAM_MODE_ENFORCEMENT"] == "1"

    def test_claude_stamps_compile_claude_agent_mode(self, runner, roam_calls, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        monkeypatch.delenv("ROAM_AGENT_MODE", raising=False)
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        _write_valid_claude_wiring(tmp_path)
        launches = self._stub_launch(monkeypatch)

        res = runner.invoke(mod.cli, ["claude"])

        assert res.exit_code == 0
        assert launches[0][1]["ROAM_AGENT_MODE"] == "compile_claude"


@pytest.mark.usefixtures("compatible_roam")
class TestDoctor:
    def test_doctor_reports_present_verify_report_age(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        monkeypatch.setattr(mod.time, "time", lambda: 10_000.0)
        (tmp_path / ".roam").mkdir()
        report = tmp_path / ".roam" / "verify-report.json"
        report.write_text("{}")
        mod.os.utime(report, (9_880, 9_880))
        res = runner.invoke(mod.cli, ["doctor"])
        assert "verify report: present (2m old)" in res.output

    def test_doctor_reports_absent_verify_report(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        res = runner.invoke(mod.cli, ["doctor"])
        assert "verify report: none — run `compile report`" in res.output

    def test_doctor_reports_unwired_state(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        res = runner.invoke(mod.cli, ["doctor"])
        assert "absent" in res.output and "not wired" in res.output
        assert "install ok" in res.output

    def test_doctor_fails_without_toolchain(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            mod,
            "_inspect_roam",
            lambda timeout=10: _roam_info(
                path=None, executable_version=None, metadata_version="13.10.0", state="missing"
            ),
        )
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        res = runner.invoke(mod.cli, ["doctor"])
        assert res.exit_code == 2
        assert "toolchain missing" in res.output

    def test_doctor_sees_project_wiring(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        _write_valid_claude_wiring(tmp_path)
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_text("")
        res = runner.invoke(mod.cli, ["doctor"])
        assert "wired (project)" in res.output
        assert "VERDICT: ready" in res.output
        assert res.exit_code == 0

    def test_doctor_sees_user_global_wiring(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        home = tmp_path / "home"
        _write_valid_claude_wiring(home)
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(home))
        res = runner.invoke(mod.cli, ["doctor"])
        assert "wired (user-global)" in res.output


class TestFailurePaths:
    """Every toolchain failure mode must surface as a clean VERDICT line
    with the documented exit code — never a traceback."""

    def _raise_missing(self, *args, timeout=600):
        raise FileNotFoundError("roam")

    def _raise_timeout(self, *args, timeout=600):
        raise mod.subprocess.TimeoutExpired(cmd=["roam"], timeout=timeout)

    @pytest.mark.parametrize(
        "argv",
        [
            ["init"],
            ["wire", "claude"],
            ["unwire", "claude"],
            ["run", "task"],
            ["stats"],
        ],
    )
    def test_missing_toolchain_is_a_verdict_not_a_traceback(self, runner, monkeypatch, argv):
        monkeypatch.setattr(mod, "_roam", self._raise_missing)
        res = runner.invoke(mod.cli, argv)
        assert res.exit_code == 2
        assert "VERDICT: toolchain missing" in res.output
        assert "Traceback" not in res.output

    def test_timeout_is_a_verdict_with_exit_124(self, runner, monkeypatch):
        monkeypatch.setattr(mod, "_roam", self._raise_timeout)
        res = runner.invoke(mod.cli, ["run", "task"])
        assert res.exit_code == 124
        assert "timed out" in res.output

    def _raise_broken(self, *args, timeout=600):
        raise PermissionError(13, "Access is denied", "roam")

    @pytest.mark.parametrize("argv", [["init"], ["run", "task"], ["stats"]])
    def test_broken_toolchain_is_a_verdict_not_a_traceback(self, runner, monkeypatch, argv):
        # On PATH but unlaunchable (broken shim, wrong arch, permissions):
        # the docstring contract says exit 2 "toolchain missing/broken".
        monkeypatch.setattr(mod, "_roam", self._raise_broken)
        res = runner.invoke(mod.cli, argv)
        assert res.exit_code == 2
        assert "VERDICT: toolchain broken" in res.output
        assert "Traceback" not in res.output

    def test_run_refuses_empty_task_without_touching_the_toolchain(self, runner, monkeypatch):
        monkeypatch.setattr(mod, "_roam", lambda *a, timeout=600: pytest.fail("must not call the toolchain"))
        res = runner.invoke(mod.cli, ["run", "   "])
        assert res.exit_code == 1
        assert "VERDICT: empty task" in res.output
        assert "task argument is empty or whitespace" in res.output


class TestBoundedVerifyCapture:
    def test_every_verify_subprocess_boundary_uses_the_bounded_runner(self):
        boundaries = (
            mod._inspect_roam,
            mod._attest_claude_hooks,
            mod._discover_verify_targets,
            mod._roam_capture,
        )
        for boundary in boundaries:
            source = inspect.getsource(boundary)
            assert "_run_bounded_capture(" in source
            assert "subprocess.run(" not in source

    def test_drains_noisy_stdout_and_stderr_concurrently_with_bounded_retention(self, monkeypatch):
        monkeypatch.setattr(mod, "MAX_VERIFY_JSON_BYTES", 4096)
        monkeypatch.setattr(mod, "MAX_VERIFY_STDERR_BYTES", 2048)
        monkeypatch.setattr(mod, "_VERIFY_CAPTURE_CHUNK_BYTES", 512)
        script = (
            "import os\nchunk = b'x' * 4096\nfor _ in range(256):\n    os.write(1, chunk)\n    os.write(2, chunk)\n"
        )

        proc = mod._roam_capture("-c", script, timeout=15, executable=sys.executable, env=mod.os.environ.copy())

        assert proc.returncode == 0
        assert len(proc.stdout.encode("utf-8")) == mod.MAX_VERIFY_JSON_BYTES + 1
        assert len(proc.stderr.encode("utf-8")) == mod.MAX_VERIFY_STDERR_BYTES + 1
        with pytest.raises(ValueError, match="invalid_json_bytes"):
            mod._strict_json_document(proc.stdout, max_bytes=mod.MAX_VERIFY_JSON_BYTES)

    def test_timeout_kills_real_grandchild_that_retains_both_pipes(self):
        script = (
            "import subprocess, sys\n"
            "subprocess.Popen(\n"
            "    [sys.executable, '-c', 'import time; time.sleep(10)'],\n"
            "    stdout=sys.stdout, stderr=sys.stderr,\n"
            ")\n"
        )
        started = mod.time.monotonic()

        with pytest.raises(mod.subprocess.TimeoutExpired):
            mod._roam_capture("-c", script, timeout=0.25, executable=sys.executable, env=mod.os.environ.copy())

        assert mod.time.monotonic() - started < 2
        assert not any(thread.name.startswith("compile-boundary-") for thread in mod.threading.enumerate())


@pytest.mark.usefixtures("compatible_roam")
class TestVerifyToolchainFailureIsNotAVerifyFailure:
    """`compile verify` must not stack its failure block on a toolchain that
    never ran — and must not confuse roam's exit 2 (bad arguments) with the
    CLI's own EXIT_TOOLCHAIN (also 2)."""

    def test_missing_toolchain_skips_the_failure_block(self, runner, monkeypatch):
        def raise_missing(*args, timeout=600, executable="roam", env=None):
            raise FileNotFoundError("roam")

        monkeypatch.setattr(mod, "_roam_capture", raise_missing)
        res = runner.invoke(mod.cli, ["verify", "x.py"])
        assert res.exit_code == 2
        assert "VERDICT: toolchain missing" in res.output
        assert "verify failed" not in res.output

    def test_broken_toolchain_skips_the_failure_block(self, runner, monkeypatch):
        def raise_broken(*args, timeout=600, executable="roam", env=None):
            raise PermissionError(13, "Access is denied", "roam")

        monkeypatch.setattr(mod, "_roam_capture", raise_broken)
        res = runner.invoke(mod.cli, ["verify", "x.py"])
        assert res.exit_code == 2
        assert "VERDICT: toolchain broken" in res.output
        assert "verify failed" not in res.output

    def test_timeout_skips_the_failure_block(self, runner, monkeypatch):
        def raise_timeout(*args, timeout=600, executable="roam", env=None):
            raise mod.subprocess.TimeoutExpired(cmd=["roam"], timeout=timeout)

        monkeypatch.setattr(mod, "_roam_capture", raise_timeout)
        res = runner.invoke(mod.cli, ["verify", "x.py"])
        assert res.exit_code == 124
        assert "timed out" in res.output
        assert "verify failed" not in res.output

    def test_roam_exit_2_without_receipt_is_a_protocol_failure(self, runner, monkeypatch):
        class _P:
            returncode = 2
            stdout = "error: unknown flag --bogus\n"

        monkeypatch.setattr(mod, "_roam_capture", lambda *a, timeout=600, executable="roam", env=None: _P())
        res = runner.invoke(mod.cli, ["verify", "x.py"])
        assert res.exit_code == 2
        assert "VERDICT: verifier protocol failure" in res.output
        assert "receipt field/reason invalid_json_document" in res.output
        assert "scope target indices 0" in res.output
        assert "verify failed" not in res.output

    def test_unstructured_stderr_is_not_replayed(self, runner, monkeypatch):
        class _P:
            returncode = 1
            stdout = ""
            stderr = "RuntimeError: kernel exploded\n"

        monkeypatch.setattr(mod, "_roam_capture", lambda *a, timeout=600, executable="roam", env=None: _P())
        res = runner.invoke(mod.cli, ["verify", "x.py"])
        assert res.exit_code == mod.EXIT_TOOLCHAIN
        assert "kernel exploded" not in res.output + res.stderr
        assert res.output.count("VERDICT:") == 1

    def test_deeply_nested_json_is_a_protocol_verdict_not_a_traceback(self, runner, monkeypatch):
        class _P:
            returncode = 0
            stdout = "[" * 2000 + "0" + "]" * 2000
            stderr = ""

        monkeypatch.setattr(mod, "_roam_capture", lambda *args, **kwargs: _P())

        res = runner.invoke(mod.cli, ["verify", "x.py"])

        assert res.exit_code == mod.EXIT_TOOLCHAIN
        assert "VERDICT: verifier protocol failure" in res.output
        assert "Traceback" not in res.output + res.stderr
        assert "RecursionError" not in res.output + res.stderr


class TestLaunchAgentFailurePaths:
    """The agent launch seam maps every launch failure to a verdict + code —
    the PATH check at command start is advisory, so the race where the binary
    vanishes or cannot start must not traceback."""

    def test_exec_branch_hands_env_and_exact_argv_to_execv(self, monkeypatch):
        monkeypatch.setattr(mod.os, "environ", dict(mod.os.environ))
        recorded = {}
        monkeypatch.setattr(mod.os, "execv", lambda f, argv: recorded.update(file=f, argv=argv))
        rc = mod._launch_agent(["claude", "-p", "hi"], {"ROAM_AGENT_MODE": "compile_claude"}, use_exec=True)
        assert rc == 0
        assert recorded["file"] == "claude"
        assert recorded["argv"] == ["claude", "-p", "hi"]
        assert mod.os.environ["ROAM_AGENT_MODE"] == "compile_claude"

    def test_child_branch_propagates_exit_code(self, monkeypatch):
        class _P:
            returncode = 7

        monkeypatch.setattr(mod.subprocess, "run", lambda argv, check, env: _P())
        assert mod._launch_agent(["claude"], {}, use_exec=False) == 7

    def test_vanished_binary_is_a_verdict_exit_1(self, monkeypatch, capsys):
        def raise_missing(argv, check, env):
            raise FileNotFoundError("claude")

        monkeypatch.setattr(mod.subprocess, "run", raise_missing)
        assert mod._launch_agent(["claude"], {}, use_exec=False) == 1
        assert "vanished from PATH" in capsys.readouterr().out

    def test_unlaunchable_binary_is_a_verdict_exit_1(self, monkeypatch, capsys):
        monkeypatch.setattr(mod.os, "environ", dict(mod.os.environ))

        def raise_broken(f, argv):
            raise OSError(8, "Exec format error")

        monkeypatch.setattr(mod.os, "execv", raise_broken)
        assert mod._launch_agent(["claude"], {}, use_exec=True) == 1
        assert "could not launch" in capsys.readouterr().out

    def test_interrupt_maps_to_130(self, monkeypatch, capsys):
        def raise_interrupt(argv, check, env):
            raise KeyboardInterrupt()

        monkeypatch.setattr(mod.subprocess, "run", raise_interrupt)
        assert mod._launch_agent(["claude"], {}, use_exec=False) == 130
        assert "interrupted" in capsys.readouterr().out


@pytest.mark.usefixtures("compatible_roam")
class TestEncodingRobustness:
    """Settings and marker files written in non-UTF-8 encodings (PowerShell
    defaults to UTF-16 with a BOM) must degrade gracefully, never traceback."""

    def test_wired_in_treats_utf16_settings_as_unwired(self, tmp_path):
        settings = tmp_path / "settings.local.json"
        with open(settings, "w", encoding="utf-16") as fh:
            fh.write(f'{{"hooks": "{mod.HOOK_MARKER}"}}')
        assert mod._wired_in(str(settings)) is False

    def test_doctor_survives_utf16_settings_file(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        (tmp_path / ".claude").mkdir()
        with open(tmp_path / ".claude" / "settings.local.json", "w", encoding="utf-16") as fh:
            fh.write(f'{{"hooks": "{mod.HOOK_MARKER}"}}')
        res = runner.invoke(mod.cli, ["doctor"])
        assert res.exit_code == 0
        assert "not wired" in res.output
        assert "Traceback" not in res.output

    def test_merge_roam_guidance_leaves_utf16_claude_md_untouched(self, tmp_path):
        claude_md = tmp_path / "CLAUDE.md"
        with open(claude_md, "w", encoding="utf-16") as fh:
            fh.write("# Existing instructions\n")
        before = claude_md.read_bytes()
        mod._merge_roam_guidance(str(claude_md))  # must not raise
        assert claude_md.read_bytes() == before

    def test_corrupt_launch_head_marker_reads_as_unknown(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / ".compile-code-launch-head").write_bytes(b"\xff\xfe\x00garbage")
        assert mod._launch_index_head() is None


class TestEnsureIndexedForLaunch:
    """The index-delegation contract, tested directly — no click context."""

    def test_returns_0_when_already_indexed_and_head_is_unchanged(self, monkeypatch, capsys, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        monkeypatch.setattr(mod, "_delegate", lambda *a: pytest.fail("must not index"))
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        assert mod._ensure_indexed_for_launch() == 0
        assert capsys.readouterr().out == ""

    def test_index_marker_write_never_follows_a_roam_directory_symlink(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        external = tmp_path / "external-roam"
        external.mkdir()
        marker = external / ".compile-code-launch-head"
        marker.write_text("before\n", encoding="utf-8")
        try:
            (tmp_path / ".roam").symlink_to(external, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"directory symlinks unavailable: {exc}")

        mod._mark_launch_indexed("abc123")

        assert marker.read_text(encoding="utf-8") == "before\n"
        assert mod._require_index() is False

    def test_indexes_on_first_run_and_returns_0(self, monkeypatch, capsys):
        monkeypatch.setattr(mod, "_require_index", lambda: False)
        calls = []
        monkeypatch.setattr(mod, "_delegate", lambda *a: calls.append(a) or 0)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        wrote = {}

        def mark(head=None):
            wrote["head"] = head

        monkeypatch.setattr(mod, "_mark_launch_indexed", mark)
        assert mod._ensure_indexed_for_launch() == 0
        assert calls == [("init",)]
        assert wrote == {"head": None}
        assert "indexing repo (first run)" in capsys.readouterr().out

    def test_first_run_uses_exact_inspected_roam_and_sanitized_env(self, monkeypatch):
        monkeypatch.setattr(mod, "_require_index", lambda: False)
        captured = {}

        def delegate(*args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            return 0

        monkeypatch.setattr(mod, "_delegate", delegate)
        monkeypatch.setattr(mod, "_mark_launch_indexed", lambda head=None: None)
        env = {"PATH": "/trusted/bin", "PYTHONSAFEPATH": "1"}

        assert mod._ensure_indexed_for_launch(executable="/trusted/roam", env=env) == 0
        assert captured == {
            "args": ("init",),
            "kwargs": {"executable": "/trusted/roam", "env": env},
        }

    def test_indexing_failure_yields_verdict_and_code(self, monkeypatch, capsys):
        monkeypatch.setattr(mod, "_require_index", lambda: False)
        monkeypatch.setattr(mod, "_delegate", lambda *a: 2)
        assert mod._ensure_indexed_for_launch() == 2
        output = capsys.readouterr().out
        assert "VERDICT: indexing failed" in output
        assert ".roam/index.db was not created" in output
        assert "roam exit 2" in output

    def test_reindexes_when_head_marker_is_missing(self, monkeypatch, capsys):
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        monkeypatch.setattr(mod, "_launch_index_head", lambda: None)
        calls = []
        monkeypatch.setattr(mod, "_delegate", lambda *a: calls.append(a) or 0)
        wrote = {}
        monkeypatch.setattr(mod, "_mark_launch_indexed", lambda head=None: wrote.setdefault("head", head))
        assert mod._ensure_indexed_for_launch() == 0
        assert calls == [("index",)]
        assert wrote == {"head": None}
        assert "HEAD drift" in capsys.readouterr().out

    def test_reindexes_when_head_marker_changed(self, monkeypatch, capsys):
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        monkeypatch.setattr(mod, "_launch_index_head", lambda: "fff999")
        calls = []
        monkeypatch.setattr(mod, "_delegate", lambda *a: calls.append(a) or 0)
        wrote = {}
        monkeypatch.setattr(mod, "_mark_launch_indexed", lambda head=None: wrote.setdefault("head", head))
        assert mod._ensure_indexed_for_launch() == 0
        assert calls == [("index",)]
        assert wrote == {"head": None}
        assert "HEAD drift" in capsys.readouterr().out


class TestFailurePathsLaunch:
    @staticmethod
    def _stub_boundary(monkeypatch):
        monkeypatch.setattr(mod, "_inspect_roam", lambda timeout=10: _roam_info())
        monkeypatch.setattr(mod, "_attest_claude_hooks", lambda *args, **kwargs: True)
        monkeypatch.setattr(
            mod,
            "_resolve_trusted_executable",
            lambda name, *, reject_workspace: (TRUSTED_CLAUDE_PATH, None),
        )
        _stub_content_digest(monkeypatch)

    def test_claude_launch_blocks_on_wire_failure_by_default(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_text("")
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        (tmp_path / ".claude").mkdir()
        self._stub_boundary(monkeypatch)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")

        monkeypatch.setattr(mod, "_delegate", lambda *a, **kw: 1)
        launches = []
        monkeypatch.setattr(mod, "_launch_agent", lambda argv, env, **kw: launches.append(list(argv)) or 0)
        res = runner.invoke(mod.cli, ["claude"])
        assert "VERDICT: wiring failed" in res.output
        assert launches == []
        assert res.exit_code == 1

    def test_claude_launch_requires_explicit_opt_in_to_continue_unwired(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_text("")
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        self._stub_boundary(monkeypatch)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")

        monkeypatch.setattr(mod, "_delegate", lambda *a, **kw: 1)
        launches = []
        monkeypatch.setattr(mod, "_launch_agent", lambda argv, env, **kw: launches.append(list(argv)) or 0)

        res = runner.invoke(mod.cli, ["claude", "--allow-unwired"])

        assert "explicit degraded launch accepted" in res.output
        assert launches and launches[0][0] == TRUSTED_CLAUDE_PATH
        assert res.exit_code == 0


@pytest.mark.usefixtures("compatible_roam")
class TestVerifyFailureFormatting:
    """`compile verify` must turn a roam verify failure into a block that names
    the failing command, the changed files, a likely cause, and one local rerun."""

    FAIL_OUTPUT = (
        "VERDICT: FAIL (score 60/100) -- 2 issues in 1 changed file\n"
        "checks: naming, imports, error_handling, duplicates, syntax\n\n"
        "NAMING (40/100):\n"
        "  FAIL: src/bad.py:12 -- function 'Foo' should be snake_case\n\n"
        "SYNTAX (0/100):\n"
        "  FAIL: src/bad.py:30 -- python syntax error at line 30: unexpected indent\n"
    )

    @pytest.fixture(autouse=True)
    def _stable_changed_scope(self, monkeypatch):
        monkeypatch.setattr(mod, "_discover_verify_targets", lambda _root: [(" M", "changed.py")])

    def _capture(self, output, rc, *, effective_threshold=70, findings=None):
        """Stub _roam_capture to return a CompletedProcess-shaped object."""
        captured = {}
        provided_findings = findings

        class _P:
            def __init__(self, args, stdout):
                captured["args"] = list(args)
                self.stdout = stdout
                self.stderr = ""

            returncode = rc

        def fake(*args, timeout=600, executable="roam", env=None):
            captured["executable"] = executable
            captured["env"] = dict(env or {})
            raw = output
            match = re.match(r"VERDICT:\s+(PASS|WARN|FAIL)\s+\(score\s+(\d+)/100\)", output)
            if match and output.count("VERDICT:") == 1:
                verdict, score_raw = match.groups()
                if "--threshold" in args:
                    threshold_index = list(args).index("--threshold") + 1
                    threshold = int(args[threshold_index])
                else:
                    threshold = effective_threshold
                receipt = {
                    "schema": mod.VERIFY_RECEIPT_SCHEMA,
                    "request_nonce": env["ROAM_VERIFY_REQUEST_NONCE"],
                    "scope_sha256": env["ROAM_VERIFY_SCOPE_SHA256"],
                    "content_sha256": env["ROAM_VERIFY_CONTENT_SHA256"],
                    "content_sha256_before": env["ROAM_VERIFY_CONTENT_SHA256"],
                    "content_sha256_after": env["ROAM_VERIFY_CONTENT_SHA256"],
                    "target_file_count": int(env["ROAM_VERIFY_SCOPE_COUNT"]),
                    "scope_stable": True,
                    "request_match": True,
                }
                result_findings = list(provided_findings or [])
                if provided_findings is None and "src/bad.py:12" in output:
                    result_findings = [
                        {
                            "severity": "FAIL",
                            "category": "naming",
                            "file": "src/bad.py",
                            "line": 12,
                            "message": "function 'Foo' should be snake_case",
                        },
                        {
                            "severity": "FAIL",
                            "category": "syntax",
                            "file": "src/bad.py",
                            "line": 30,
                            "message": "python syntax error at line 30: unexpected indent",
                        },
                    ]
                envelope = _verify_envelope(
                    verdict=verdict,
                    score=int(score_raw),
                    threshold=threshold,
                    receipt=receipt,
                    violations=result_findings,
                )
                for finding in result_findings:
                    category = finding["category"]
                    envelope["categories"].setdefault(
                        category,
                        {"score": 0, "violation_count": 0, "violations": []},
                    )
                    if finding not in envelope["categories"][category]["violations"]:
                        envelope["categories"][category]["violations"].append(dict(finding))
                        envelope["categories"][category]["violation_count"] += 1
                raw = json.dumps(envelope)
            return _P(args, raw)

        return fake, captured

    def test_failing_files_dedupes_in_order(self):
        envelope = {
            "violations": [
                {"severity": "WARN", "file": "warn.py"},
                {"severity": "FAIL", "file": " leading.py"},
                {"severity": "FAIL", "file": "src/bad.py"},
                {"severity": "FAIL", "file": " leading.py"},
            ]
        }
        assert mod._failing_files(envelope) == [" leading.py", "src/bad.py"]

    def test_status_parser_covers_staged_unstaged_untracked_rename_and_deletion(self):
        raw = "M  staged.py\0 M unstaged.py\0?? untracked.py\0R  renamed.py\0old.py\0D  deleted.py\0"
        assert mod._parse_changed_status_paths(raw) == [
            "staged.py",
            "unstaged.py",
            "untracked.py",
            "renamed.py",
            "old.py",
            "deleted.py",
        ]

    def test_oversized_helper_returns_advisory_above_cap(self):
        advisory = mod._oversized_target_set([f"f{i}.py" for i in range(26)], cap=25)
        assert isinstance(advisory, str) and advisory
        assert "scope down" in advisory

    def test_oversized_helper_silent_at_or_below_cap(self):
        assert mod._oversized_target_set(["a.py", "b.py"], cap=25) is None
        assert mod._oversized_target_set([f"f{i}.py" for i in range(25)], cap=25) is None

    def test_classify_maps_failing_sections_to_causes(self):
        assert mod._classify_verify_failure(self.FAIL_OUTPUT, 5) == "naming violation + syntax error"

    def test_classify_falls_back_to_exit_code_without_fail_lines(self):
        assert mod._classify_verify_failure("VERDICT: FAIL (score 0/100)\n", 5) == "quality gate"
        assert mod._classify_verify_failure("no index\n", 3) == "index missing"
        assert mod._classify_verify_failure("oops\n", 99) == "verify failure"

    def test_format_contains_all_four_components(self):
        block = mod._format_verify_failure(
            command="compile verify src/bad.py",
            files=["src/bad.py"],
            cause="syntax error",
            next_action="compile verify src/bad.py",
        )
        assert block.startswith("VERDICT: verify failed.")
        assert "command : compile verify src/bad.py" in block
        assert "files   : src/bad.py" in block
        assert "cause   : syntax error" in block
        assert "next    : compile verify src/bad.py" in block

    def test_format_shows_placeholder_when_no_changed_files(self):
        block = mod._format_verify_failure(
            command="compile verify --changed", files=[], cause="quality gate", next_action="compile verify --changed"
        )
        assert "files   : (no changed files)" in block

    def test_verify_failure_emits_block_and_exit_5(self, runner, monkeypatch, compatible_roam):
        fake, captured = self._capture(self.FAIL_OUTPUT, 5)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        monkeypatch.setattr(mod, "_changed_files", lambda: pytest.fail("parsed failures need no local discovery"))
        res = runner.invoke(mod.cli, ["verify"])
        assert res.exit_code == 5
        # roam's raw output is preserved...
        assert "FAIL: src/bad.py:12" in res.output
        # ...and the explained block carries all four components.
        assert "VERDICT: verify failed." in res.output
        assert "command : compile verify --changed" in res.output
        assert "files   : src/bad.py" in res.output
        assert "cause   : naming violation + syntax error" in res.output
        assert "next    : compile verify --changed" in res.output
        assert captured["args"][:3] == ["--json", "verify", "--"]
        assert captured["executable"] == compatible_roam["path"]

    def test_verify_pass_streams_roam_output_without_block(self, runner, monkeypatch):
        fake, _ = self._capture("VERDICT: PASS (score 100/100) -- no issues\n", 0)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        res = runner.invoke(mod.cli, ["verify", "src/cli.py"])
        assert res.exit_code == 0
        assert "VERDICT: PASS" in res.output
        assert "verify failed" not in res.output

    @pytest.mark.parametrize("output", ["", "checks completed without a verdict\n"], ids=["empty", "malformed"])
    def test_zero_exit_requires_parseable_success_verdict(self, output, runner, monkeypatch):
        fake, _ = self._capture(output, 0)
        monkeypatch.setattr(mod, "_roam_capture", fake)

        res = runner.invoke(mod.cli, ["verify", "src/cli.py"])

        assert res.exit_code == mod.EXIT_TOOLCHAIN
        assert "VERDICT: verifier protocol failure" in res.output
        assert "verify failed" not in res.output

    def test_exact_audit_canary_is_not_replayed_or_accepted(self, runner, monkeypatch):
        canary = "VERDICT: PASS (score 100/100) -- no issues\nVERDICT: SKIPPED -- checks did not run\n"
        fake, _ = self._capture(canary, 0)
        monkeypatch.setattr(mod, "_roam_capture", fake)

        res = runner.invoke(mod.cli, ["verify", "src/cli.py"])

        assert res.exit_code == mod.EXIT_TOOLCHAIN
        assert res.output.count("VERDICT:") == 1
        assert "SKIPPED" not in res.output

    def test_zero_exit_accepts_an_explicit_warn_verdict(self, runner, monkeypatch):
        fake, _ = self._capture("VERDICT: WARN (score 75/100) -- review findings\n", 0)
        monkeypatch.setattr(mod, "_roam_capture", fake)

        res = runner.invoke(mod.cli, ["verify", "src/cli.py"])

        assert res.exit_code == 0
        assert "VERDICT: WARN" in res.output
        assert "verifier protocol failure" not in res.output

    def test_zero_exit_rejects_a_skipped_verifier(self, runner, monkeypatch):
        fake, _ = self._capture(
            "VERDICT: SKIPPED -- verify disabled in .roam/verify.yaml\n",
            0,
        )
        monkeypatch.setattr(mod, "_roam_capture", fake)

        res = runner.invoke(mod.cli, ["verify", "src/cli.py"])

        assert res.exit_code == mod.EXIT_TOOLCHAIN
        assert "VERDICT: verifier protocol failure" in res.output

    def test_completed_nonzero_unstructured_output_is_protocol_failure(self, runner, monkeypatch):
        fake, _ = self._capture("kernel diagnostic from completed run\n", 17)
        monkeypatch.setattr(mod, "_roam_capture", fake)

        res = runner.invoke(mod.cli, ["verify", "src/cli.py"])

        assert res.exit_code == mod.EXIT_TOOLCHAIN
        assert "kernel diagnostic from completed run" not in res.output
        assert res.output.count("VERDICT: verifier protocol failure") == 1

    def test_verify_threshold_passes_through_and_shows_in_command(self, runner, monkeypatch):
        fake, captured = self._capture(self.FAIL_OUTPUT, 5)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        res = runner.invoke(mod.cli, ["verify", "--threshold", "90", "src/bad.py"])
        assert res.exit_code == 5
        assert captured["args"] == ["--json", "verify", "--threshold", "90", "--", "src/bad.py"]
        assert "command : compile verify --threshold 90 --changed" in res.output
        assert "next    : compile verify --threshold 90 --changed" in res.output

    def test_verify_omits_threshold_so_repository_policy_governs(self, runner, monkeypatch):
        fake, captured = self._capture(
            "VERDICT: PASS (score 100/100) -- no issues\n",
            0,
            effective_threshold=83,
        )
        monkeypatch.setattr(mod, "_roam_capture", fake)

        res = runner.invoke(mod.cli, ["verify", "src/cli.py"])

        assert res.exit_code == 0
        assert captured["args"] == ["--json", "verify", "--", "src/cli.py"]
        assert "VERDICT: PASS" in res.output

    @pytest.mark.parametrize("threshold", ["-1", "101"])
    def test_verify_rejects_threshold_outside_closed_score_range(self, threshold, runner, monkeypatch):
        monkeypatch.setattr(mod, "_inspect_roam", lambda timeout=10: pytest.fail("must reject before delegation"))

        res = runner.invoke(mod.cli, ["verify", "--threshold", threshold, "src/cli.py"])

        assert res.exit_code == 2
        assert "Invalid value for '--threshold'" in res.output

    def test_recovery_command_is_content_free_and_shell_neutral(self):
        command = mod._render_verify_command(
            new_only=True,
            diff_only=True,
            threshold=90,
        )

        assert command == "compile verify --new-only --diff-only --threshold 90 --changed"
        assert command.split(" ", 1)[0] == "compile"
        assert not any(character in command for character in "'\";&|<>()`$\n\r")

    def test_changed_recovery_mode_is_executable_and_rejects_mixed_scope(self, runner, monkeypatch):
        fake, captured = self._capture("VERDICT: PASS (score 100/100) -- no changed files\n", 0)
        monkeypatch.setattr(mod, "_roam_capture", fake)

        changed = runner.invoke(mod.cli, ["verify", "--threshold", "90", "--changed"])
        mixed = runner.invoke(mod.cli, ["verify", "--changed", "src/a.py"])

        assert changed.exit_code == 0
        assert captured["args"][:4] == ["--json", "verify", "--threshold", "90"]
        assert mixed.exit_code == 2
        assert "cannot be combined" in mixed.output

    def test_failure_commands_quote_adversarial_paths_and_preserve_threshold(self, runner, monkeypatch):
        malicious_path = "src/a.py; Write-Output AUDIT_CANARY"
        findings = [
            {
                "severity": "FAIL",
                "category": "syntax",
                "file": malicious_path,
                "line": 1,
                "message": "syntax error",
            }
        ]
        fake, captured = self._capture(
            "VERDICT: FAIL (score 60/100) -- one issue\n",
            5,
            findings=findings,
        )
        monkeypatch.setattr(mod, "_roam_capture", fake)

        res = runner.invoke(
            mod.cli,
            ["verify", "--threshold", "90", "--", malicious_path, "src/a & b.py", "-leading.py"],
        )

        assert res.exit_code == 5
        assert captured["args"] == [
            "--json",
            "verify",
            "--threshold",
            "90",
            "--",
            "-leading.py",
            "src/a & b.py",
            malicious_path,
        ]
        command_lines = [line for line in res.output.splitlines() if "command :" in line or "next    :" in line]
        assert command_lines == [
            "  command : compile verify --threshold 90 --changed",
            "  next    : compile verify --threshold 90 --changed",
        ]
        assert all("AUDIT_CANARY" not in line and "&" not in line and ";" not in line for line in command_lines)

    @pytest.mark.skipif(mod.os.name != "nt", reason="Windows shell regression")
    def test_content_free_recovery_is_inert_in_cmd_and_powershell(self, tmp_path):
        (tmp_path / "compile.cmd").write_text("@echo off\r\necho %*\r\n", encoding="utf-8")
        env = mod.os.environ.copy()
        env["PATH"] = str(tmp_path) + mod.os.pathsep + env.get("PATH", "")
        command = mod._render_verify_command(new_only=False, diff_only=False, threshold=90)
        invocations = [[env.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", command]]
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if powershell:
            invocations.append([powershell, "-NoProfile", "-NonInteractive", "-Command", command])

        for argv in invocations:
            completed = subprocess.run(argv, env=env, check=False, capture_output=True, text=True, timeout=10)
            assert completed.returncode == 0
            assert "verify --threshold 90 --changed" in completed.stdout
            assert "AUDIT_CANARY" not in completed.stdout + completed.stderr

    def test_verify_new_only_and_diff_only_pass_through(self, runner, monkeypatch):
        fake, captured = self._capture(self.FAIL_OUTPUT, 5)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        res = runner.invoke(mod.cli, ["verify", "--new-only", "--diff-only", "src/bad.py"])
        assert res.exit_code == 5
        assert captured["args"] == [
            "--json",
            "verify",
            "--new-only",
            "--diff-only",
            "--",
            "src/bad.py",
        ]
        assert "command : compile verify --new-only --diff-only --changed" in res.output
        assert "next    : compile verify --new-only --diff-only --changed" in res.output

    def test_verify_no_argument_binds_discovered_scope_before_delegation(self, runner, monkeypatch):
        fake, captured = self._capture("VERDICT: PASS (score 100/100) -- no changed files\n", 0)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        res = runner.invoke(mod.cli, ["verify"])
        assert res.exit_code == 0
        assert captured["args"][:3] in (["--json", "verify", "--"], ["--json", "verify", "--changed"])
        assert captured["env"]["ROAM_VERIFY_SCOPE_COUNT"].isdigit()

    def test_no_argument_failure_uses_bound_scope_for_human_context(self, runner, monkeypatch):
        fake, captured = self._capture("VERDICT: FAIL (score 60/100) -- discovery-level failure\n", 5)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        res = runner.invoke(mod.cli, ["verify"])

        assert res.exit_code == 5
        assert captured["args"][:3] == ["--json", "verify", "--"]
        assert "files   : " in res.output
        assert "next    : compile verify --changed" in res.output

    def test_failure_block_reports_parsed_failing_scope_not_all_targets(self, runner, monkeypatch):
        fake, captured = self._capture(self.FAIL_OUTPUT, 5)
        monkeypatch.setattr(mod, "_roam_capture", fake)

        res = runner.invoke(mod.cli, ["verify", "src/good.py", "src/bad.py"])

        assert res.exit_code == 5
        assert captured["args"] == [
            "--json",
            "verify",
            "--",
            "src/bad.py",
            "src/good.py",
        ]
        assert "command : compile verify --changed" in res.output
        assert "files   : src/bad.py" in res.output
        assert "next    : compile verify --changed" in res.output

    def test_oversized_advisory_does_not_change_delegation(self, runner, monkeypatch):
        fake, captured = self._capture(self.FAIL_OUTPUT, 5)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        files = [f"f{i}.py" for i in range(30)]
        res = runner.invoke(mod.cli, ["verify", *files])
        assert res.exit_code == 5
        assert "scope down" in res.output
        assert captured["args"] == ["--json", "verify", "--", *sorted(files)]

    def test_no_advisory_for_small_explicit_list(self, runner, monkeypatch):
        fake, _ = self._capture("VERDICT: PASS (score 100/100) -- no issues\n", 0)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        res = runner.invoke(mod.cli, ["verify", "a.py", "b.py"])
        assert "scope down" not in res.output

    def _newer_producer(self, monkeypatch, rc, verdict):
        """Stub the toolchain as a roam one minor ahead of this build."""
        fake, captured = self._capture(verdict, rc)

        def newer(*args, timeout=600, executable="roam", env=None):
            proc = fake(*args, timeout=timeout, executable=executable, env=env)
            envelope = json.loads(proc.stdout)
            envelope["schema_version"] = "1.2.0"
            envelope["orchestration_contract"] = {"review_policy": "cross_family"}
            envelope["summary"]["residual_wave_note"] = "future"
            proc.stdout = json.dumps(envelope)
            return proc

        monkeypatch.setattr(mod, "_roam_capture", newer)
        return captured

    def test_verify_accepts_a_newer_producer_and_says_what_it_ignored(self, runner, monkeypatch):
        """An upstream envelope addition must not become a local verify outage."""
        self._newer_producer(monkeypatch, 0, "VERDICT: PASS (score 100/100) -- no issues\n")

        res = runner.invoke(mod.cli, ["verify", "changed.py"])

        assert res.exit_code == 0
        assert "protocol failure" not in res.output
        assert "VERDICT: PASS" in res.output
        assert "1.2.0" in res.output
        assert "orchestration_contract" in res.output
        assert "summary.residual_wave_note" in res.output

    def test_a_newer_producer_does_not_soften_a_real_gate_failure(self, runner, monkeypatch):
        self._newer_producer(monkeypatch, 5, self.FAIL_OUTPUT)

        res = runner.invoke(mod.cli, ["verify", "src/bad.py"])

        assert res.exit_code == 5
        assert "VERDICT: FAIL" in res.output
        assert "orchestration_contract" in res.output
        assert "cause   : naming violation + syntax error" in res.output

    def test_verify_still_refuses_an_envelope_missing_a_field_it_depends_on(self, runner, monkeypatch):
        fake, _ = self._capture("VERDICT: PASS (score 100/100) -- no issues\n", 0)

        def truncated(*args, timeout=600, executable="roam", env=None):
            proc = fake(*args, timeout=timeout, executable=executable, env=env)
            envelope = json.loads(proc.stdout)
            envelope.pop("categories")
            proc.stdout = json.dumps(envelope)
            return proc

        monkeypatch.setattr(mod, "_roam_capture", truncated)

        res = runner.invoke(mod.cli, ["verify", "changed.py"])

        assert res.exit_code == mod.EXIT_TOOLCHAIN
        assert "receipt field/reason envelope_contract" in res.output
        assert "VERDICT: PASS" not in res.output

    def test_verify_refuses_an_envelope_major_this_build_cannot_read(self, runner, monkeypatch):
        fake, _ = self._capture("VERDICT: PASS (score 100/100) -- no issues\n", 0)

        def breaking(*args, timeout=600, executable="roam", env=None):
            proc = fake(*args, timeout=timeout, executable=executable, env=env)
            envelope = json.loads(proc.stdout)
            envelope["schema_version"] = "2.0.0"
            proc.stdout = json.dumps(envelope)
            return proc

        monkeypatch.setattr(mod, "_roam_capture", breaking)

        res = runner.invoke(mod.cli, ["verify", "changed.py"])

        assert res.exit_code == mod.EXIT_TOOLCHAIN
        assert "receipt field/reason envelope_schema_incompatible" in res.output
        assert "upgrade compile-code" in res.output


class TestBaselineVerb:
    def test_baseline_refuses_dirty_tree(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_git_status_porcelain", lambda timeout=10: (0, " M src/cli.py\n"))
        monkeypatch.setattr(mod, "_roam", lambda *a, timeout=600: pytest.fail("must not baseline dirty trees"))
        res = runner.invoke(mod.cli, ["baseline"])
        assert res.exit_code == 1
        assert "dirty tree" in res.output
        assert "M src/cli.py" in res.output
        assert "Fix:" in res.output

    def test_baseline_clean_tree_remains_silent_and_successful(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_git_status_porcelain", lambda timeout=10: (0, ""))
        monkeypatch.setattr(mod, "_roam", lambda *a, timeout=600: SimpleNamespace(returncode=0))
        res = runner.invoke(mod.cli, ["baseline"])
        assert res.exit_code == 0
        assert "VERDICT: baseline refused" not in res.output

    def test_baseline_uses_report_baseline_write_with_raised_timeout(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_git_status_porcelain", lambda timeout=10: (0, ""))
        calls = []

        class _P:
            returncode = 0

        def fake(*args, timeout=600):
            calls.append((list(args), timeout))
            return _P()

        monkeypatch.setattr(mod, "_roam", fake)
        res = runner.invoke(mod.cli, ["baseline"])
        assert res.exit_code == 0
        assert calls == [(["verify", "--report", "--baseline-write"], mod.BASELINE_TIMEOUT)]

    def test_baseline_can_target_source_dirs(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "src").mkdir()
        (tmp_path / "tests").mkdir()
        monkeypatch.setattr(mod, "_git_status_porcelain", lambda timeout=10: (0, ""))
        calls = []

        class _P:
            returncode = 0

        def fake(*args, timeout=600):
            calls.append((list(args), timeout))
            return _P()

        monkeypatch.setattr(mod, "_roam", fake)
        res = runner.invoke(mod.cli, ["baseline", "src", "tests"])
        assert res.exit_code == 0
        assert calls == [(["verify", "--report", "--baseline-write", "src", "tests"], mod.BASELINE_TIMEOUT)]


class TestCommandInventory:
    def test_inventory_is_deterministic_and_complete(self):
        from compile_code.cli import _format_command_inventory

        commands = mod.cli.commands
        out1 = _format_command_inventory(commands)
        out2 = _format_command_inventory(commands)
        assert out1 == out2
        lines = out1.splitlines()
        names = [ln.split(" ", 1)[0] for ln in lines]
        assert names == sorted(mod.cli.commands.keys())
        assert set(names) == set(mod.cli.commands.keys())

    def test_commands_verb_prints_inventory(self, runner):
        res = runner.invoke(mod.cli, ["commands"])
        assert res.exit_code == 0
        from compile_code.cli import _format_command_inventory

        assert res.output.strip() == _format_command_inventory(mod.cli.commands).strip()


class TestVerifyReceiptV3Protocol:
    def _validate(
        self,
        raw: str,
        *,
        rc: int = 0,
        expected: dict[str, object] | None = None,
        root: Path | None = None,
    ):
        return mod._validate_verify_protocol(
            raw,
            returncode=rc,
            expected_receipt=expected or _bound_verify_receipt(),
            expected_roam_version=mod.MIN_ROAM_VERSION,
            expected_threshold=70,
            expected_root=root,
        )

    def test_accepts_one_complete_bound_receipt(self):
        envelope = _verify_envelope()
        assert self._validate(json.dumps(envelope)) == envelope

    def test_accepts_canonical_complete_no_changes_transaction(self):
        expected = _bound_verify_receipt(target_file_count=0)
        envelope = _no_changes_envelope(expected)
        assert self._validate(json.dumps(envelope), expected=expected) == envelope

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda envelope: envelope["categories"].pop("verification"),
            lambda envelope: envelope["categories"]["verification"].update(available=False),
            lambda envelope: envelope["categories"]["syntax"].update(skipped=True),
            lambda envelope: envelope["categories"]["syntax"].update(score=0),
            lambda envelope: envelope["categories"]["syntax"].update(
                violations=[{"severity": "FAIL", "category": "syntax", "file": "bad.py"}]
            ),
        ],
        ids=["missing-verification", "unavailable", "skipped", "failed-score", "hidden-finding"],
    )
    def test_rejects_noncanonical_no_changes_categories(self, mutate):
        expected = _bound_verify_receipt(target_file_count=0)
        envelope = _no_changes_envelope(expected)
        mutate(envelope)
        with pytest.raises(ValueError):
            self._validate(json.dumps(envelope), expected=expected)

    def test_accepts_complete_non_code_scope_accounting(self):
        envelope = _verify_envelope()
        envelope["summary"].update(
            files_checked=0,
            index_refresh={"state": "current", "refreshed_file_count": 0},
            scope={
                "target_file_count": 1,
                "indexed_file_count": 0,
                "non_code_file_count": 1,
                "unresolved_file_count": 1,
                "non_code_scope_definition": mod._VERIFY_NON_CODE_SCOPE_DEFINITION,
            },
        )
        assert self._validate(json.dumps(envelope)) == envelope
        assert "1 changed file" in mod._render_verify_envelope(envelope)

    def test_accepts_an_indexed_doc_in_scope(self):
        # Measured against roam-code 13.10.0 (the pinned floor) on this repo's
        # own tree with README.md in the changed set. roam indexes docs, so a
        # non-code target can resolve: `_verify_scope_summary` derives
        # unresolved as target_count - len(file_map) and omits the key at zero,
        # and never couples non_code_file_count to it.
        mod._validate_verify_scope_summary(
            {
                "target_file_count": 3,
                "indexed_file_count": 3,
                "non_code_file_count": 1,
                "non_code_scope_definition": mod._VERIFY_NON_CODE_SCOPE_DEFINITION,
            },
            expected_count=3,
            files_checked=3,
        )

    @pytest.mark.parametrize(
        "scope",
        [
            # roam emits the block only when a doc or an unresolved file exists.
            {"target_file_count": 3, "indexed_file_count": 3, "non_code_file_count": 0},
            # files_checked is len(file_map), so it must equal indexed_file_count.
            {"target_file_count": 3, "indexed_file_count": 2, "non_code_file_count": 1},
            # indexed + unresolved is the target count by construction.
            {
                "target_file_count": 3,
                "indexed_file_count": 3,
                "non_code_file_count": 1,
                "unresolved_file_count": 1,
            },
            # a non-code count larger than the scope it counts is not arithmetic.
            {"target_file_count": 3, "indexed_file_count": 3, "non_code_file_count": 4},
        ],
        ids=["block-without-a-reason", "checked-exceeds-indexed", "counts-do-not-add-up", "non-code-exceeds-scope"],
    )
    def test_scope_accounting_still_has_to_add_up(self, scope):
        with pytest.raises(ValueError, match="scope_binding"):
            mod._validate_verify_scope_summary(scope, expected_count=3, files_checked=3)

    def test_rejects_audit_exact_contradictory_two_line_canary(self):
        raw = "VERDICT: PASS (score 100/100) -- no issues\nVERDICT: SKIPPED -- checks did not run\n"
        with pytest.raises(ValueError):
            self._validate(raw)

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda envelope: envelope.pop("project"),
            lambda envelope: envelope.update(schema="roam-envelope-v2"),
            lambda envelope: envelope.update(skipped=True),
            lambda envelope: envelope.update(command="preflight"),
            lambda envelope: envelope["summary"].update(verdict="SKIPPED"),
            lambda envelope: envelope["summary"].update(verification_complete=False),
            lambda envelope: envelope["summary"].update(partial_success=True),
            lambda envelope: envelope["summary"].update(state="verification_incomplete"),
            lambda envelope: envelope["summary"].update(quality_band="FAIL"),
            lambda envelope: envelope["summary"].update(
                index_refresh={"state": "refresh_failed", "refreshed_file_count": 0}
            ),
            lambda envelope: envelope["summary"].update(skipped=True),
            lambda envelope: envelope["summary"].update(checks_run=["unknown_check"]),
            lambda envelope: envelope["summary"].update(index_refresh={"state": "current", "refreshed_file_count": 1}),
            lambda envelope: envelope["categories"].pop("claims"),
            lambda envelope: envelope["categories"].update(
                unknown={"score": 100, "violation_count": 0, "violations": []}
            ),
            lambda envelope: envelope["categories"]["syntax"].update(skipped=True),
            lambda envelope: envelope["categories"]["syntax"].pop("violation_count"),
            lambda envelope: envelope["categories"]["syntax"].update(available=False),
            lambda envelope: envelope["categories"]["syntax"].update(execution_state="skipped"),
            lambda envelope: envelope["categories"]["syntax"].update(execution_state="unknown"),
            lambda envelope: envelope["categories"]["syntax"].update(partial_success=True),
            lambda envelope: envelope["categories"]["syntax"].update(timed_out=True),
            lambda envelope: envelope["categories"]["syntax"].update(capped=True),
            lambda envelope: envelope["categories"]["verification"].update(score=0),
            lambda envelope: envelope["summary"]["verification_receipt"].update(schema="roam.verify.receipt.v2"),
            lambda envelope: envelope["summary"]["verification_receipt"].update(request_nonce="0" * 32),
            lambda envelope: envelope["summary"]["verification_receipt"].update(scope_sha256="0" * 64),
            lambda envelope: envelope["summary"]["verification_receipt"].update(content_sha256="0" * 64),
            lambda envelope: envelope["summary"]["verification_receipt"].update(content_sha256_before="0" * 64),
            lambda envelope: envelope["summary"]["verification_receipt"].update(content_sha256_after="0" * 64),
            lambda envelope: envelope["summary"]["verification_receipt"].update(target_file_count=2),
            lambda envelope: envelope["summary"]["verification_receipt"].update(scope_stable=False),
            lambda envelope: envelope["summary"]["verification_receipt"].update(request_match=False),
            lambda envelope: envelope["summary"]["verification_receipt"].update(extra="not closed"),
        ],
        ids=[
            "envelope-missing-required-key",
            "envelope-schema",
            "envelope-unknown-incompleteness-signal",
            "command",
            "skipped",
            "incomplete",
            "partial",
            "state",
            "quality-band",
            "index-refresh",
            "summary-skipped",
            "unknown-check",
            "current-index-claims-refresh",
            "missing-category",
            "unknown-category",
            "category-skipped",
            "category-missing-count",
            "category-unavailable",
            "category-skipped-state",
            "category-unknown-state",
            "category-partial",
            "category-timeout",
            "category-capped",
            "verification-category-failed",
            "receipt-schema",
            "nonce",
            "scope",
            "content",
            "before",
            "after",
            "count",
            "unstable",
            "request-mismatch",
            "receipt-extra-key",
        ],
    )
    def test_rejects_closed_protocol_mutations(self, mutate):
        envelope = _verify_envelope()
        mutate(envelope)
        with pytest.raises(ValueError):
            self._validate(json.dumps(envelope))

    # --- forward compatibility ------------------------------------------------
    # Roam adds envelope fields every release. A receiver that fails on "the
    # producer is newer than me" turns each upstream ship into a local outage
    # on envelopes that are valid and strictly richer -- so an unknown extra
    # field must be tolerated and disclosed, while a missing required field
    # stays a refusal. The two events must not share a verdict.

    @pytest.mark.parametrize("version", ["1.0.0", "1.1.0", "1.2.0", "1.9.4", "1.20.0"])
    def test_accepts_any_same_major_envelope_version(self, version):
        envelope = _verify_envelope()
        envelope["schema_version"] = version
        assert self._validate(json.dumps(envelope)) == envelope

    @pytest.mark.parametrize(
        "version",
        ["2.0.0", "0.9.0", "1.1", "1.1.0.0", "v1.1.0", "1.1.0-rc1", "", " 1.1.0", 110],
        ids=["major-bump", "major-zero", "two-part", "four-part", "prefixed", "suffixed", "empty", "padded", "int"],
    )
    def test_refuses_an_envelope_version_this_build_cannot_read(self, version):
        envelope = _verify_envelope()
        envelope["schema_version"] = version
        with pytest.raises(ValueError, match="envelope_schema_incompatible"):
            self._validate(json.dumps(envelope))

    def test_the_incompatibility_verdict_does_not_claim_a_floor_the_code_enforces(self):
        # The refusal text said this build "reads roam-envelope-v1 1.1.0 and
        # later same-major shapes". _envelope_schema_compatible compares the
        # MAJOR component only, so 1.0.0 is accepted too -- the sentence was
        # stricter than the gate it described, and a producer author reading it
        # would conclude a 1.0.x envelope is refused when it is not.
        assert mod._envelope_schema_compatible("1.0.0") is True

        envelope = _verify_envelope()
        envelope["schema_version"] = "2.0.0"
        with pytest.raises(ValueError, match="envelope_schema_incompatible") as error:
            self._validate(json.dumps(envelope))

        verdict = mod._verify_protocol_verdict(error.value, executable="roam", targets=["a.py"])
        assert "and later same-major" not in verdict
        assert f"any {mod.VERIFY_ENVELOPE_SCHEMA} major 1 shape" in verdict
        assert f"written against {mod.VERIFY_ENVELOPE_SCHEMA_VERSION}" in verdict

    def test_refuses_an_envelope_that_declares_no_version_at_all(self):
        envelope = _verify_envelope()
        envelope.pop("schema_version")
        with pytest.raises(ValueError, match="envelope_schema_incompatible"):
            self._validate(json.dumps(envelope))

    def test_a_newer_producers_unknown_fields_are_accepted_and_disclosed(self):
        envelope = _verify_envelope()
        envelope["schema_version"] = "1.2.0"
        envelope["orchestration_contract"] = {"review_policy": "cross_family"}
        envelope["summary"]["residual_wave_note"] = "future"
        envelope["categories"]["syntax"]["future_counter"] = 3

        assert self._validate(json.dumps(envelope)) == envelope

        rendered = mod._render_verify_envelope(envelope)
        assert "1.2.0" in rendered
        assert "orchestration_contract" in rendered
        assert "summary.residual_wave_note" in rendered
        assert "categories.syntax.future_counter" in rendered
        assert "does not read" in rendered

    @pytest.mark.parametrize("name", sorted(mod._VERIFY_ENVELOPE_KEYS - {"schema_version"}))
    def test_a_missing_required_field_still_fails_closed(self, name):
        envelope = _verify_envelope()
        envelope.pop(name)
        with pytest.raises(ValueError, match="envelope_contract"):
            self._validate(json.dumps(envelope))

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda envelope: envelope.update(not_run=True),
            lambda envelope: envelope["summary"].update(degraded=True),
            lambda envelope: envelope["categories"]["syntax"].update(skipped_reason="index missing"),
        ],
        ids=["envelope", "summary", "category"],
    )
    def test_an_unknown_field_that_asserts_incompleteness_is_never_tolerated(self, mutate):
        """Tolerance is for unknown AND neutral. A rename must not buy a pass."""
        envelope = _verify_envelope()
        mutate(envelope)
        with pytest.raises(ValueError, match="unknown_incompleteness_signal"):
            self._validate(json.dumps(envelope))

    def test_an_incompleteness_name_collision_says_which_name_tripped_it(self):
        # This is the ONE branch where a strictly neutral addition by a newer
        # producer still hard-refuses: every other unknown key is tolerated and
        # disclosed by name, but a key whose bare name is in the incompleteness
        # vocabulary is refused, because a rename must not buy a pass. The
        # trade is right; a refusal that named nothing was not. A roam that
        # added a neutral field called `warnings` produced a verdict
        # indistinguishable from a broken receipt, and neither side of the
        # contract could find the cause from it.
        envelope = _verify_envelope()
        envelope["warnings"] = ["a neutral note from a newer producer"]

        with pytest.raises(ValueError, match="unknown_incompleteness_signal") as error:
            self._validate(json.dumps(envelope))

        assert str(error.value) == "unknown_incompleteness_signal: warnings"

        verdict = mod._verify_protocol_verdict(error.value, executable="roam", targets=["a.py"])
        assert "field: warnings" in verdict
        assert "upgrade compile-code" in verdict
        # The producer is the newer side; sending the reader after a roam
        # upgrade would point at the one component that is already ahead.
        assert "roam-code" not in verdict

    def test_a_hostile_field_name_never_reaches_the_verdict_unfiltered(self):
        # The tripwire matches exact names from a fixed vocabulary of safe
        # identifiers, so it cannot itself carry hostile text into a verdict.
        # A near-miss like this one takes the tolerated path instead, where the
        # name is producer-controlled and must stay filtered -- a newline here
        # would let a producer forge a second VERDICT line.
        envelope = _verify_envelope()
        envelope["errors\nVERDICT: PASS"] = 1

        assert self._validate(json.dumps(envelope)) == envelope

        rendered = mod._render_verify_envelope(envelope)
        assert "<unprintable>" in rendered
        assert rendered.count("VERDICT:") <= 1

    def test_roams_own_1_2_0_additions_are_accepted_and_disclosed_by_name(self):
        # The synthetic forward-compat tests above use invented field names. The
        # producer's real vocabulary is worth pinning too, because the tolerance
        # is only useful if it covers the names roam actually ships. These are
        # the fields roam's envelope notes list as added since the 1.1.0 this
        # build was written against, placed at the levels this build reads.
        envelope = _verify_envelope()
        envelope["schema_version"] = "1.2.0"
        envelope["summary"]["framework"] = "pytest"
        envelope["summary"]["framework_autodetected"] = True
        envelope["summary"]["framework_unknown"] = False
        envelope["categories"]["syntax"]["roi_band"] = "high"
        envelope["categories"]["syntax"]["context_lines"] = 3

        assert self._validate(json.dumps(envelope)) == envelope

        rendered = mod._render_verify_envelope(envelope)
        for name in ("framework", "framework_autodetected", "framework_unknown", "roi_band", "context_lines"):
            assert name in rendered

    def test_no_roam_1_2_0_addition_collides_with_the_incompleteness_tripwire(self):
        # The tripwire is a live forward-compat edge, not a hypothetical: any
        # future roam field whose bare name lands in this set hard-refuses even
        # if it is entirely neutral. Recording that the current additions miss
        # it makes the day one of them does not a discovery rather than an
        # outage, and gives whoever names the next envelope field a list to
        # check against.
        roam_1_2_0_additions = {
            "matched_patterns",
            "framework",
            "framework_autodetected",
            "framework_unknown",
            "roi_band",
            "context_lines",
        }

        assert roam_1_2_0_additions & mod._VERIFY_INCOMPLETENESS_NAMES == set()

    def test_a_known_field_in_the_wrong_shape_is_still_refused(self):
        """Opening the world to unknown names must not open it to known ones."""
        expected = _bound_verify_receipt(target_file_count=0)
        envelope = _no_changes_envelope(expected)
        envelope["summary"]["targets_checked"] = 5
        with pytest.raises(ValueError, match="no_changes_contract"):
            self._validate(json.dumps(envelope), expected=expected)

    def test_a_no_changes_transaction_also_tolerates_and_discloses_unknown_fields(self):
        expected = _bound_verify_receipt(target_file_count=0)
        envelope = _no_changes_envelope(expected)
        envelope["schema_version"] = "1.2.0"
        envelope["summary"]["future_no_changes_field"] = True
        envelope["categories"]["syntax"]["future_counter"] = 1

        assert self._validate(json.dumps(envelope), expected=expected) == envelope
        rendered = mod._render_verify_envelope(envelope)
        assert "summary.future_no_changes_field" in rendered
        assert "categories.syntax.future_counter" in rendered

    def test_the_request_bound_receipt_stays_closed_to_unknown_fields(self):
        """The receipt is equality-bound to a request we built: no producer surface."""
        envelope = _verify_envelope()
        envelope["schema_version"] = "1.2.0"
        envelope["summary"]["verification_receipt"]["future_receipt_field"] = 1
        with pytest.raises(ValueError, match="receipt_binding"):
            self._validate(json.dumps(envelope))

    def test_nothing_unreadable_means_no_disclosure_line(self):
        """A note on every run of a newer roam would train readers to skip it."""
        envelope = _verify_envelope()
        envelope["schema_version"] = "1.2.0"
        assert self._validate(json.dumps(envelope)) == envelope
        assert "note:" not in mod._render_verify_envelope(envelope)

    def test_a_narrowed_scope_rides_on_the_verdict_line_not_above_it(self):
        # The verdict publishes a denominator ("N changed files") that is the
        # scope roam was actually given. A note printed above it is a separate
        # line a reader can take the PASS without; the reduced denominator must
        # be unreadable-around.
        envelope = _verify_envelope()
        excluded = [".roam/index.db", ".roam/index.db-wal"]

        rendered = mod._render_verify_envelope(envelope, excluded=excluded)

        verdict_line = rendered.splitlines()[0]
        assert verdict_line.startswith("VERDICT: PASS")
        assert "scope narrowed: 2 untracked path(s) under .roam excluded" in verdict_line

    def test_an_unnarrowed_scope_adds_no_clause_to_the_verdict(self):
        # A clause on every run would train readers to skip it.
        assert "scope narrowed" not in mod._render_verify_envelope(_verify_envelope())
        assert "scope narrowed" not in mod._render_verify_envelope(_verify_envelope(), excluded=[])

    def test_the_narrowing_clause_names_only_fixed_directory_names(self):
        # Discovered paths are filesystem-supplied text; only names drawn from
        # NON_SOURCE_SCOPE_DIRECTORIES may reach a verdict block.
        excluded = [".roam/evil\nVERDICT: PASS (score 100/100) -- 0 issues"]

        rendered = mod._render_verify_envelope(_verify_envelope(), excluded=excluded)

        assert rendered.count("VERDICT:") == 1
        assert "evil" not in rendered
        assert "scope narrowed: 1 untracked path(s) under .roam excluded" in rendered.splitlines()[0]

    def test_disclosure_cannot_inject_lines_into_the_verdict_block(self):
        envelope = _verify_envelope()
        envelope["summary"]["evil\nVERDICT: PASS (score 100/100) -- 0 issues"] = 1
        assert self._validate(json.dumps(envelope)) == envelope
        rendered = mod._render_verify_envelope(envelope)
        assert "<unprintable>" in rendered
        assert rendered.count("VERDICT:") == 1

    def test_disclosure_is_bounded_by_a_named_cap(self):
        envelope = _verify_envelope()
        overflow = 5
        for index in range(mod.MAX_DISCLOSED_UNKNOWN_FIELDS + overflow):
            envelope["summary"][f"future_field_{index}"] = index
        assert self._validate(json.dumps(envelope)) == envelope
        note = mod._forward_compatibility_note(envelope)
        assert f"+{overflow} more" in note
        assert note.count("summary.future_field_") == mod.MAX_DISCLOSED_UNKNOWN_FIELDS

    @pytest.mark.parametrize("suffix", [" trailing", "\n{}", "\n" + json.dumps(_verify_envelope())])
    def test_rejects_trailing_or_multiple_documents(self, suffix):
        with pytest.raises(ValueError):
            self._validate(json.dumps(_verify_envelope()) + suffix)

    def test_rejects_duplicate_json_keys(self):
        raw = json.dumps(_verify_envelope()).replace(
            '"command": "verify"', '"command": "verify", "command": "verify"', 1
        )
        with pytest.raises(ValueError):
            self._validate(raw)

    @pytest.mark.parametrize("raw", ["1e999", "-1e999", '{"value": 1e999}'])
    def test_strict_json_rejects_exponent_overflow(self, raw):
        with pytest.raises(ValueError, match="non_finite_json_number"):
            mod._strict_json_document(raw, max_bytes=mod.MAX_VERIFY_JSON_BYTES)

    def test_rejects_oversized_output_before_parsing(self):
        raw = " " * (mod.MAX_VERIFY_JSON_BYTES + 1)
        with pytest.raises(ValueError):
            self._validate(raw)

    def test_rejects_deeply_nested_under_size_output_without_recursion_error(self):
        depth = 2000
        raw = "[" * depth + "0" + "]" * depth
        assert len(raw.encode("utf-8")) < mod.MAX_VERIFY_JSON_BYTES

        with pytest.raises(ValueError, match="json_nesting_limit"):
            self._validate(raw)

    def test_nesting_guard_ignores_brackets_inside_json_strings(self):
        raw = json.dumps({"value": "[{" * (mod.MAX_STRICT_JSON_DEPTH + 1)})

        assert mod._strict_json_document(raw, max_bytes=mod.MAX_VERIFY_JSON_BYTES) == json.loads(raw)

    def test_decoder_recursion_error_is_normalized_to_invalid_document(self, monkeypatch):
        def recurse(*args, **kwargs):
            raise RecursionError("adversarial decoder depth")

        monkeypatch.setattr(mod.json, "loads", recurse)
        with pytest.raises(ValueError, match="invalid_json_document"):
            mod._strict_json_document("{}", max_bytes=mod.MAX_VERIFY_JSON_BYTES)

    def test_rejects_pass_with_fail_evidence(self):
        finding = {"severity": "FAIL", "category": "syntax", "file": "bad.py", "line": 1}
        with pytest.raises(ValueError):
            self._validate(json.dumps(_verify_envelope(violations=[finding])))

    def test_rejects_top_level_and_category_finding_contradiction(self):
        finding = {"severity": "WARN", "category": "n1", "file": "model.py", "line": 1}
        envelope = _verify_envelope(violations=[finding])
        envelope["summary"]["checks_run"].append("n1")
        envelope["categories"]["n1"]["violations"][0]["file"] = "different.py"

        with pytest.raises(ValueError, match="finding_multiset_contradiction"):
            self._validate(json.dumps(envelope))

    def test_rejects_finding_multiplicity_contradiction(self):
        finding = {"severity": "WARN", "category": "n1", "file": "model.py", "line": 1}
        envelope = _verify_envelope(violations=[finding])
        envelope["summary"]["checks_run"].append("n1")
        envelope["violations"].append(dict(finding))
        envelope["summary"]["violation_count"] = 2

        with pytest.raises(ValueError, match="finding_multiset_contradiction"):
            self._validate(json.dumps(envelope))

    @pytest.mark.parametrize("file_path", ["../../outside.py", "/outside.py", "C:/outside.py", "src/../outside.py"])
    def test_rejects_non_root_contained_finding_paths(self, file_path):
        finding = {"severity": "WARN", "category": "n1", "file": file_path, "line": 1}
        envelope = _verify_envelope(violations=[finding])
        envelope["summary"]["checks_run"].append("n1")

        with pytest.raises(ValueError, match="invalid_finding_path"):
            self._validate(json.dumps(envelope))

    def test_rejects_finding_path_redirected_outside_the_bound_root(self, tmp_path):
        root = tmp_path / "repo"
        external = tmp_path / "external"
        root.mkdir()
        external.mkdir()
        (external / "outside.py").write_text("outside\n", encoding="utf-8")
        try:
            (root / "redirect").symlink_to(external, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"directory links unavailable: {exc}")
        finding = {"severity": "WARN", "category": "n1", "file": "redirect/outside.py", "line": 1}
        envelope = _verify_envelope(violations=[finding])
        envelope["summary"]["checks_run"].append("n1")

        with pytest.raises(ValueError, match="invalid_finding_path"):
            self._validate(json.dumps(envelope), root=root)

    def test_rejects_pass_verdict_with_warn_score_band(self):
        envelope = _verify_envelope(verdict="PASS", score=70, threshold=70)

        with pytest.raises(ValueError, match="completion_binding"):
            self._validate(json.dumps(envelope))

    def test_accepts_pass_with_selected_advisory_warn_evidence(self):
        finding = {"severity": "WARN", "category": "n1", "file": "model.py", "line": 1}
        envelope = _verify_envelope(violations=[finding])
        envelope["summary"]["checks_run"].append("n1")
        assert self._validate(json.dumps(envelope)) == envelope

    @pytest.mark.parametrize(
        "finding",
        [
            {"severity": "INFO", "category": "n1", "file": "model.py", "line": 1},
            {"severity": "WARN", "category": "syntax", "file": "bad.py", "line": 1},
        ],
        ids=["info", "non-advisory-warn"],
    )
    def test_rejects_pass_with_noncanonical_nonfailing_evidence(self, finding):
        envelope = _verify_envelope(violations=[finding])
        if finding["category"] == "n1":
            envelope["summary"]["checks_run"].append("n1")
        with pytest.raises(ValueError):
            self._validate(json.dumps(envelope))

    def test_rejects_finding_from_a_check_not_claimed_as_run(self):
        finding = {"severity": "WARN", "category": "n1", "file": "model.py", "line": 1}
        with pytest.raises(ValueError):
            self._validate(json.dumps(_verify_envelope(verdict="WARN", violations=[finding])))

    def test_rejects_returncode_verdict_contradictions(self):
        with pytest.raises(ValueError):
            self._validate(json.dumps(_verify_envelope()), rc=5)
        failed = _verify_envelope(
            verdict="FAIL",
            score=0,
            violations=[{"severity": "FAIL", "category": "syntax", "file": "bad.py", "line": 1}],
        )
        with pytest.raises(ValueError):
            self._validate(json.dumps(failed), rc=0)

    def test_request_snapshot_binds_sorted_names_and_exact_bytes(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        (tmp_path / "a.py").write_bytes(b"print('a')\n")
        (tmp_path / "b.py").write_bytes(b"print('b')\n")

        root, targets, receipt, env, _excluded = mod._prepare_verify_request(("b.py", "a.py", "a.py"))

        a_digest = mod.hashlib.sha256(b"print('a')\n").hexdigest()
        b_digest = mod.hashlib.sha256(b"print('b')\n").hexdigest()
        manifest = [["a.py", f"sha256:{a_digest}"], ["b.py", f"sha256:{b_digest}"]]
        payload = json.dumps(manifest, ensure_ascii=False, separators=(",", ":"))
        assert root == tmp_path
        assert targets == ["a.py", "b.py"]
        assert receipt["scope_sha256"] == mod._verification_scope_sha256(targets)
        assert receipt["content_sha256"] == mod.hashlib.sha256(payload.encode()).hexdigest()
        assert env["ROAM_VERIFY_REQUEST_NONCE"] == receipt["request_nonce"]
        assert env["ROAM_VERIFY_SCOPE_COUNT"] == "2"

        (tmp_path / "a.py").write_bytes(b"mutated\n")
        assert mod._verification_content_sha256(root, targets) != receipt["content_sha256"]

    def test_request_snapshot_preserves_leading_space_and_hashes_that_exact_file(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        (tmp_path / " leading.py").write_bytes(b"leading-space\n")
        (tmp_path / "leading.py").write_bytes(b"different-file\n")

        root, targets, receipt, _env, _excluded = mod._prepare_verify_request((" leading.py",))

        digest = mod.hashlib.sha256(b"leading-space\n").hexdigest()
        payload = json.dumps([[" leading.py", f"sha256:{digest}"]], ensure_ascii=False, separators=(",", ":"))
        assert root == tmp_path
        assert targets == [" leading.py"]
        assert receipt["content_sha256"] == mod.hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def test_parent_redirect_after_precheck_is_rejected_before_hashing(self, monkeypatch, tmp_path):
        root = tmp_path / "repo"
        source = root / "src"
        external = tmp_path / "external"
        source.mkdir(parents=True)
        external.mkdir()
        (source / "target.py").write_bytes(b"inside\n")
        (external / "target.py").write_bytes(b"outside\n")
        original_snapshot = mod._verification_parent_snapshot
        raced = False

        def swap_after_snapshot(bound_root, parent):
            nonlocal raced
            snapshot = original_snapshot(bound_root, parent)
            if not raced and Path(parent) == source:
                raced = True
                source.rename(root / "src-original")
                try:
                    source.symlink_to(external, target_is_directory=True)
                except OSError as exc:
                    (root / "src-original").rename(source)
                    pytest.skip(f"directory links unavailable: {exc}")
            return snapshot

        monkeypatch.setattr(mod, "_verification_parent_snapshot", swap_after_snapshot)

        with pytest.raises(ValueError, match="scope_file_changed_during_hash"):
            mod._verification_content_sha256(root, ["src/target.py"])

    def test_post_open_parent_snapshot_mismatch_fails_on_every_platform(self, monkeypatch, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        (source / "target.py").write_bytes(b"inside\n")
        original_snapshot = mod._verification_parent_snapshot
        calls = 0

        def drift_after_open(root, parent):
            nonlocal calls
            calls += 1
            resolved, states = original_snapshot(root, parent)
            return (resolved if calls == 1 else f"{resolved}-redirected", states)

        monkeypatch.setattr(mod, "_verification_parent_snapshot", drift_after_open)

        with pytest.raises(ValueError, match="scope_file_changed_during_hash"):
            mod._verification_content_sha256(tmp_path, ["src/target.py"])
        assert calls == 2

    def test_windows_reparse_points_are_treated_as_links(self):
        reparse = getattr(mod.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if not reparse:
            pytest.skip("platform exposes no reparse-point stat flag")
        info = SimpleNamespace(st_mode=mod.stat.S_IFDIR, st_file_attributes=reparse)

        assert mod._is_link_or_reparse(info) is True

    def test_scope_normalization_preserves_legal_whitespace_and_posix_backslashes(self):
        assert mod._verification_scope_paths([" trailing.py ", " leading.py"]) == [" leading.py", " trailing.py "]
        literal_backslash = r"src\literal.py"
        expected = "src/literal.py" if mod.os.name == "nt" else literal_backslash
        assert mod._verification_scope_paths([literal_backslash]) == [expected]

    def test_git_status_parser_preserves_leading_space_filename(self):
        assert mod._parse_verify_status_records(b"??  leading.py\0") == [("??", " leading.py")]

    def test_git_status_parser_keeps_the_status_column_that_narrowing_depends_on(self):
        # Dropping the status column is what forced narrowing onto the path name.
        raw = b" M venv/mypkg/mod.py\0?? .roam/index.db-wal\0R  new.py\0old.py\0"
        assert mod._parse_verify_status_records(raw) == [
            (" M", "venv/mypkg/mod.py"),
            ("??", ".roam/index.db-wal"),
            ("R ", "new.py"),
            ("R ", "old.py"),
        ]

    @pytest.mark.skipif(mod.os.name == "nt", reason="POSIX surrogateescape regression")
    def test_git_status_parser_explicitly_rejects_undecodable_filename_bytes(self):
        with pytest.raises(ValueError, match="scope_path_undecodable"):
            mod._parse_verify_status_records(b"?? bad-\xff.py\0")

    def test_changed_file_discovery_uses_bounded_binary_capture(self, monkeypatch, tmp_path):
        captured = {}

        class _P:
            returncode = 0
            stdout = b"??  leading.py\0"
            stderr = b""

        def fake_capture(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return _P()

        monkeypatch.setattr(mod, "_resolve_trusted_executable", lambda *args, **kwargs: ("/trusted/git", None))
        monkeypatch.setattr(mod, "_run_bounded_capture", fake_capture)

        assert mod._discover_verify_targets(tmp_path) == [("??", " leading.py")]
        assert captured["kwargs"]["cwd"] == str(tmp_path)
        assert captured["kwargs"]["stdout_limit"] == mod.MAX_VERIFY_GIT_STATUS_BYTES
        assert captured["kwargs"]["stderr_limit"] == mod.MAX_VERIFY_STDERR_BYTES

    def test_scope_paths_reject_control_characters(self):
        with pytest.raises(ValueError):
            mod._verification_scope_paths(["safe.py", "bad\nname.py"])

    def test_untracked_tool_state_directories_are_not_source_for_discovery(self):
        paths = [
            ".roam/index.db",
            ".roam/index.db-wal",
            "src/a.py",
            "node_modules/pkg/index.js",
            "__pycache__/cli.cpython-313.pyc",
            "app/.venv/lib/site.py",
            ".roamignore",
            "venv",
            "tools/venvsetup.py",
        ]
        kept, excluded = mod._partition_non_source_scope(paths, untracked=set(paths))

        assert kept == [
            "src/a.py",
            ".roamignore",
            "venv",
            "tools/venvsetup.py",
        ]
        assert excluded == [
            ".roam/index.db",
            ".roam/index.db-wal",
            "node_modules/pkg/index.js",
            "__pycache__/cli.cpython-313.pyc",
            "app/.venv/lib/site.py",
        ]

    def test_tracked_source_under_a_tool_state_directory_stays_in_scope(self):
        # `git add` is the project declaring a path is source. The narrowing
        # exists for a live UNTRACKED index that moves while roam reads it; that
        # argument does not reach a committed file, and dropping it removed real
        # code from --changed coverage behind a PASS. CPython ships
        # Lib/venv/__init__.py -- the name is not a measurement.
        paths = [
            "venv/mypkg/mod.py",
            "node_modules/pkg/index.js",
            ".roam/index.db-wal",
            "src/a.py",
        ]
        kept, excluded = mod._partition_non_source_scope(paths, untracked={".roam/index.db-wal"})

        assert kept == ["venv/mypkg/mod.py", "node_modules/pkg/index.js", "src/a.py"]
        assert excluded == [".roam/index.db-wal"]

    def test_partition_has_no_trackedness_default_because_the_silent_answer_is_wrong(self):
        # Assume-untracked drops tracked source with no error; assume-tracked can
        # only fail loudly at bind time. Neither is a safe default, so there is none.
        with pytest.raises(TypeError):
            mod._partition_non_source_scope(["venv/mypkg/mod.py"])

    def test_descent_and_discovery_share_one_non_source_directory_set(self, tmp_path):
        # Two sets would be free to drift, and the drift is invisible: descent
        # would refuse a directory that discovery had already handed to roam.
        #
        # THE DESCENT HALF IS A BEHAVIOURAL PROPERTY, derived from the constant
        # rather than named in a string. The version of this test that only
        # asserted `"NON_SOURCE_SCOPE_DIRECTORIES" in getsource(...)` for BOTH
        # sides was replaced by one that asserted it for discovery only, plus a
        # behavioural test exercising the single name "venv" -- and that trade
        # was measured to lose a mutation class: rewriting cli.py's
        # `skip_dirs = NON_SOURCE_SCOPE_DIRECTORIES` to
        # `skip_dirs = frozenset({"venv"})` left the whole suite green at 332
        # passed / 8 skipped, while handing roam `src/.git/config`,
        # `src/.roam/index.db` and `src/__pycache__/*.pyc` as verify targets --
        # the exact false scope the constant exists to prevent. Every name is
        # covered here because the loop is over the constant itself.
        assert "NON_SOURCE_SCOPE_DIRECTORIES" in inspect.getsource(mod._partition_non_source_scope)
        assert ".roam" in mod.NON_SOURCE_SCOPE_DIRECTORIES

        root = tmp_path / "src"
        root.mkdir()
        (root / "app.py").write_text("z=1\n", encoding="utf-8")
        for name in sorted(mod.NON_SOURCE_SCOPE_DIRECTORIES):
            (root / name).mkdir()
            (root / name / "inside.py").write_text("x=1\n", encoding="utf-8")

        assert mod._expand_verify_targets(["src"], tmp_path) == ["src/app.py"], (
            "explicit descent no longer prunes every name in the shared set"
        )
        # ...and each pruned name is still reachable when it is the one NAMED,
        # so the set is a descent filter and not a refusal of the path.
        for name in sorted(mod.NON_SOURCE_SCOPE_DIRECTORIES):
            assert mod._expand_verify_targets([f"src/{name}"], tmp_path) == [f"src/{name}/inside.py"]

    def test_explicit_descent_prunes_nested_tool_state_names_but_never_the_named_one(self, tmp_path):
        # THE RESIDUAL, AS A PROPERTY. The claim this replaces was a
        # getsource() string check -- it passed whether descent pruned by name
        # or did not prune at all. Mutating the skip test in
        # _expand_verify_targets to `if name not in skip_dirs or True:` (which
        # removes the pruning entirely while leaving the constant's NAME in the
        # source) left the whole suite green: 330 passed, 8 skipped, zero
        # failures. A comment-shaped test guarding a comment-shaped claim is
        # how the same bound came to be written wrong twice in this file.
        #
        # Every value below was measured on a real git repository before it was
        # written here.
        (tmp_path / "venv" / "mypkg").mkdir(parents=True)
        (tmp_path / "venv" / "__init__.py").write_text("x=1\n", encoding="utf-8")
        (tmp_path / "venv" / "mypkg" / "mod.py").write_text("y=1\n", encoding="utf-8")
        (tmp_path / "src" / "venv").mkdir(parents=True)
        (tmp_path / "src" / "pkg").mkdir(parents=True)
        (tmp_path / "src" / "app.py").write_text("z=1\n", encoding="utf-8")
        (tmp_path / "src" / "pkg" / "mod.py").write_text("r=1\n", encoding="utf-8")
        (tmp_path / "src" / "venv" / "mod.py").write_text("q=1\n", encoding="utf-8")

        # The directory NAMED on the command line is descended even when its
        # own name is in the set -- `pending` is seeded from it unfiltered.
        assert sorted(mod._expand_verify_targets(["venv"], tmp_path)) == [
            "venv/__init__.py",
            "venv/mypkg/mod.py",
        ]
        # A NESTED directory by that name is pruned. This is the residual, and
        # src/venv/mod.py here stands for tracked source that `compile verify
        # src` silently omits from the delegated scope.
        assert sorted(mod._expand_verify_targets(["src"], tmp_path)) == [
            "src/app.py",
            "src/pkg/mod.py",
        ]
        # ...and it stays reachable by naming the subtree or the file.
        assert mod._expand_verify_targets(["src/venv"], tmp_path) == ["src/venv/mod.py"]
        assert mod._expand_verify_targets(["src/venv/mod.py"], tmp_path) == ["src/venv/mod.py"]

    def test_a_trailing_slash_never_reaches_descent_at_all(self):
        # The command form the superseded wording gave for the bound above.
        # _verification_scope_paths runs on the explicit argument BEFORE
        # _expand_verify_targets, and PurePosixPath("venv/").as_posix() is
        # "venv", so the canonical-form check refuses it: exit 2, no descent,
        # no delegation. Shell tab-completion appends exactly this slash.
        with pytest.raises(ValueError, match="scope_path_not_canonical"):
            mod._verification_scope_paths(["venv/"])

    def test_changed_scope_excludes_roams_own_live_index(self, monkeypatch, tmp_path):
        # A project that does not gitignore .roam/ makes `git status -uall`
        # report roam's live SQLite index as changed work. Binding it as a
        # verify target can never succeed -- the WAL moves while roam reads it.
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        (tmp_path / ".roam").mkdir()
        for name in ("index.db", "index.db-shm", "index.db-wal", "index.lock", "index.state"):
            (tmp_path / ".roam" / name).write_bytes(b"tool-state\n")
        (tmp_path / "alpha.py").write_bytes(b"print('a')\n")
        discovered = [
            ".roam/index.db",
            ".roam/index.db-shm",
            ".roam/index.db-wal",
            ".roam/index.lock",
            ".roam/index.state",
            "alpha.py",
        ]
        monkeypatch.setattr(
            mod,
            "_discover_verify_targets",
            lambda _root: [("??", path) for path in discovered[:5]] + [(" M", "alpha.py")],
        )

        _root, targets, receipt, env, excluded = mod._prepare_verify_request(())

        assert targets == ["alpha.py"]
        assert env["ROAM_VERIFY_SCOPE_COUNT"] == "1"
        assert receipt["target_file_count"] == 1
        assert sorted(excluded) == sorted(discovered[:5])

    def test_a_tracked_index_is_the_projects_own_declaration_and_is_verified(self, monkeypatch, tmp_path):
        # The counterpart to the test above: the same paths, committed. Nothing
        # is narrowed, because narrowing them would silently drop what the
        # project chose to track. The residual is disclosed, not hidden -- a
        # project that commits its live index gets it bound as a target.
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        (tmp_path / "venv" / "mypkg").mkdir(parents=True)
        (tmp_path / "venv" / "mypkg" / "mod.py").write_bytes(b"def helper():\n    return 1\n")
        (tmp_path / "alpha.py").write_bytes(b"print('a')\n")
        monkeypatch.setattr(
            mod,
            "_discover_verify_targets",
            lambda _root: [(" M", "venv/mypkg/mod.py"), (" M", "alpha.py")],
        )

        _root, targets, receipt, env, excluded = mod._prepare_verify_request(())

        assert targets == ["alpha.py", "venv/mypkg/mod.py"]
        assert env["ROAM_VERIFY_SCOPE_COUNT"] == "2"
        assert receipt["target_file_count"] == 2
        assert excluded == []

    def test_every_narrowed_path_is_untracked_so_the_gitignore_remedy_can_apply(self, monkeypatch, tmp_path):
        # The remedy printed to the operator is "add these to .gitignore".
        # .gitignore does not untrack, so that sentence is only true while every
        # excluded path is one git has never been told about. Pin the property,
        # not the sentence.
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        (tmp_path / "alpha.py").write_bytes(b"print('a')\n")
        records = [
            ("??", ".roam/index.db-wal"),
            (" M", "venv/mypkg/mod.py"),
            ("??", "node_modules/pkg/index.js"),
            (" M", "alpha.py"),
        ]
        monkeypatch.setattr(mod, "_discover_verify_targets", lambda _root: list(records))
        untracked = {path for status, path in records if status == mod.GIT_STATUS_UNTRACKED}

        _source, excluded = mod._discovered_scope(tmp_path)

        assert excluded  # the narrowing still happens
        assert set(excluded) <= untracked

    def test_explicit_targets_are_never_silently_dropped(self, monkeypatch, tmp_path):
        # Discovery guesses at scope, so it may filter; an explicit path is the
        # caller's stated intent and must be verified or refused, never dropped.
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_bytes(b"tool-state\n")

        _root, targets, _receipt, _env, excluded = mod._prepare_verify_request((".roam/index.db",))

        assert targets == [".roam/index.db"]
        assert excluded == []

    def test_verify_discloses_that_it_narrowed_the_changed_scope(self, runner, monkeypatch, compatible_roam, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        (tmp_path / "alpha.py").write_bytes(b"print('a')\n")
        monkeypatch.setattr(
            mod,
            "_discover_verify_targets",
            lambda _root: [("??", ".roam/index.db"), ("??", "node_modules/pkg/index.js"), (" M", "alpha.py")],
        )
        monkeypatch.setattr(mod, "_delegate_capturing", lambda *args, **kwargs: (0, None))

        result = runner.invoke(mod.cli, ["verify", "--changed"])

        # No envelope came back, so there is no VERDICT line to carry the
        # narrowing: it gets its own line rather than going unsaid.
        assert "2 untracked path(s)" in result.output
        assert "node_modules" in result.output
        assert ".roam" in result.output
        assert "Traceback" not in result.output

    def test_a_pass_over_a_narrowed_scope_says_so_in_the_same_sentence(
        self, runner, monkeypatch, compatible_roam, tmp_path
    ):
        # End to end: tracked source under venv/ is verified, the untracked
        # index is not, and the PASS carries its own reduced denominator.
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        (tmp_path / "alpha.py").write_bytes(b"print('a')\n")
        (tmp_path / "venv" / "mypkg").mkdir(parents=True)
        (tmp_path / "venv" / "mypkg" / "mod.py").write_bytes(b"def helper():\n    return 1\n")
        monkeypatch.setattr(
            mod,
            "_discover_verify_targets",
            lambda _root: [(" M", "alpha.py"), (" M", "venv/mypkg/mod.py"), ("??", ".roam/index.db-wal")],
        )
        seen: dict[str, object] = {}

        def fake_delegate(*argv, executable, env):
            seen["argv"] = list(argv)
            receipt = _bound_verify_receipt(target_file_count=int(env["ROAM_VERIFY_SCOPE_COUNT"]))
            receipt.update(
                request_nonce=env["ROAM_VERIFY_REQUEST_NONCE"],
                scope_sha256=env["ROAM_VERIFY_SCOPE_SHA256"],
                content_sha256=env["ROAM_VERIFY_CONTENT_SHA256"],
                content_sha256_before=env["ROAM_VERIFY_CONTENT_SHA256"],
                content_sha256_after=env["ROAM_VERIFY_CONTENT_SHA256"],
            )
            return 0, json.dumps(_verify_envelope(receipt=receipt))

        monkeypatch.setattr(mod, "_delegate_capturing", fake_delegate)

        result = runner.invoke(mod.cli, ["verify", "--changed"])

        assert result.exit_code == 0
        assert seen["argv"] == ["--json", "verify", "--", "alpha.py", "venv/mypkg/mod.py"]
        verdict_line = next(line for line in result.output.splitlines() if line.startswith("VERDICT:"))
        assert "2 changed files" in verdict_line
        assert "scope narrowed: 1 untracked path(s) under .roam excluded" in verdict_line
        assert "Traceback" not in result.output

    def test_tool_state_only_change_names_the_remedy_that_works(self, runner, monkeypatch, compatible_roam, tmp_path):
        # Nothing source changed, so verify delegates --changed and roam
        # rediscovers the same tool state. .gitignore is the only real fix.
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        monkeypatch.setattr(
            mod,
            "_discover_verify_targets",
            lambda _root: [("??", ".roam/index.db"), ("??", ".roam/index.db-wal")],
        )
        monkeypatch.setattr(mod, "_delegate_capturing", lambda *args, **kwargs: (5, "{}"))

        result = runner.invoke(mod.cli, ["verify", "--changed"])

        assert result.exit_code == mod.EXIT_TOOLCHAIN
        assert "no source path changed" in result.output
        # True only because narrowing is untracked-only: .gitignore removes an
        # untracked path from `git status -uall`, and cannot untrack a tracked one.
        assert "Add .roam/ to .gitignore" in result.output
        assert "Traceback" not in result.output

    def test_scope_instability_verdict_does_not_prescribe_a_roam_upgrade(self):
        # These two reasons are raised by this CLI's own post-run recheck, never
        # by roam's receipt, so a newer roam cannot be the remedy.
        for reason in ("post_verify_content_changed", "post_verify_scope_changed"):
            verdict = mod._verify_protocol_verdict(
                ValueError(reason),
                executable="roam",
                targets=["a.py"],
            )
            assert "pip install --upgrade" not in verdict
            assert "changed while verify ran" in verdict
            assert reason in verdict

    @pytest.mark.parametrize("unsafe", ["../escape", "bad\nname.py", "bad\udcff.py"])
    def test_prepare_rejects_unsafe_scope_before_any_filesystem_expansion(self, monkeypatch, tmp_path, unsafe):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        monkeypatch.setattr(mod, "_expand_verify_targets", lambda *_args: pytest.fail("must validate first"))

        with pytest.raises(ValueError):
            mod._prepare_verify_request((unsafe,))

    def test_verify_reports_unsafe_filename_without_substitution_or_traceback(
        self, runner, monkeypatch, compatible_roam
    ):
        monkeypatch.setattr(
            mod,
            "_prepare_verify_request",
            lambda _files: (_ for _ in ()).throw(ValueError("scope_path_undecodable")),
        )

        result = runner.invoke(mod.cli, ["verify", "unsafe.py"])

        assert result.exit_code == mod.EXIT_TOOLCHAIN
        assert "not representable as UTF-8" in result.output
        assert "scope location unavailable" in result.output
        assert "Traceback" not in result.output

    def test_verify_explicitly_rejects_newline_filename(self, runner, compatible_roam):
        result = runner.invoke(mod.cli, ["verify", "bad\nname.py"])

        assert result.exit_code == mod.EXIT_TOOLCHAIN
        assert "unsafe control character" in result.output
        assert "including a newline" in result.output
        assert "target index 0" in result.output
        assert "bad\\nname.py" in result.output
        assert "Traceback" not in result.output

    def test_verify_does_not_echo_credential_shaped_scope_path(self, runner, compatible_roam):
        field = "to" + "ken="
        secret_path = field + "runtime-value\n.py"
        result = runner.invoke(mod.cli, ["verify", secret_path])
        assert result.exit_code == mod.EXIT_TOOLCHAIN
        assert "target index 0" in result.output
        assert "<credential-shaped path omitted>" in result.output
        assert "runtime-value" not in result.output

    @pytest.mark.parametrize(
        "path", ["../escape.py", "src/../escape.py", "./file.py", "/tmp/file.py", "C:/tmp/file.py"]
    )
    def test_scope_paths_reject_noncanonical_or_absolute_names(self, path):
        with pytest.raises(ValueError):
            mod._verification_scope_paths([path])

    def test_explicit_directory_growth_after_verify_fails_closed(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        expected = _bound_verify_receipt()
        env = {
            "ROAM_VERIFY_REQUEST_NONCE": expected["request_nonce"],
            "ROAM_VERIFY_SCOPE_SHA256": expected["scope_sha256"],
            "ROAM_VERIFY_CONTENT_SHA256": expected["content_sha256"],
            "ROAM_VERIFY_SCOPE_COUNT": "1",
        }
        monkeypatch.setattr(mod, "_inspect_roam", lambda timeout=10: _roam_info())
        monkeypatch.setattr(
            mod,
            "_prepare_verify_request",
            lambda files: (tmp_path, ["src/a.py"], expected, env, []),
        )
        monkeypatch.setattr(
            mod,
            "_delegate_capturing",
            lambda *args, **kwargs: (0, json.dumps(_verify_envelope(receipt=expected))),
        )
        monkeypatch.setattr(
            mod,
            "_verification_content_sha256",
            lambda root, targets: expected["content_sha256"],
        )
        monkeypatch.setattr(mod, "_expand_verify_targets", lambda targets, root: ["src/a.py", "src/new.py"])

        result = runner.invoke(mod.cli, ["verify", "src"])

        assert result.exit_code == mod.EXIT_TOOLCHAIN
        assert result.output.count("VERDICT:") == 1
        assert "verifier protocol failure" in result.output


class TestAtomicWriteConcurrency:
    def test_absent_target_is_never_overwritten_if_created_at_commit(self, monkeypatch, tmp_path):
        target = tmp_path / "settings.json"
        original_link = mod.os.link
        injected = False

        def create_competitor_before_link(source, destination, *args, **kwargs):
            nonlocal injected
            if Path(destination) == target and not injected:
                injected = True
                target.write_text("competitor", encoding="utf-8")
            return original_link(source, destination, *args, **kwargs)

        monkeypatch.setattr(mod.os, "link", create_competitor_before_link)

        assert mod._atomic_write_utf8(target, "compile", max_bytes=1024, expected_previous=None) is False
        assert target.read_text(encoding="utf-8") == "competitor"

    def test_two_absent_target_writers_have_exactly_one_winner(self, monkeypatch, tmp_path):
        target = tmp_path / "settings.json"
        original_link = mod.os.link
        commit_entered = threading.Event()
        release_commit = threading.Event()
        first_commit = True
        results: dict[str, bool] = {}

        def pause_first_commit(source, destination, *args, **kwargs):
            nonlocal first_commit
            if Path(destination) == target and first_commit:
                first_commit = False
                commit_entered.set()
                assert release_commit.wait(5)
            return original_link(source, destination, *args, **kwargs)

        def write(label, value):
            results[label] = mod._atomic_write_utf8(target, value, max_bytes=1024, expected_previous=None)

        monkeypatch.setattr(mod.os, "link", pause_first_commit)
        first = threading.Thread(target=write, args=("first", "first"), daemon=True)
        second = threading.Thread(target=write, args=("second", "second"), daemon=True)
        first.start()
        assert commit_entered.wait(5)
        second.start()
        release_commit.set()
        first.join(5)
        second.join(5)

        assert not first.is_alive() and not second.is_alive()
        assert sorted(results.values()) == [False, True]
        assert target.read_text(encoding="utf-8") in {"first", "second"}
        assert not list(tmp_path.glob(".compile-code-*.lock"))

    def test_existing_target_compare_and_swap_serializes_replacements(self, monkeypatch, tmp_path):
        target = tmp_path / "settings.json"
        target.write_text("old", encoding="utf-8")
        original_replace = mod.os.replace
        commit_entered = threading.Event()
        release_commit = threading.Event()
        first_commit = True
        results: dict[str, bool] = {}

        def pause_first_replace(source, destination, *args, **kwargs):
            nonlocal first_commit
            if Path(destination) == target and first_commit:
                first_commit = False
                commit_entered.set()
                assert release_commit.wait(5)
            return original_replace(source, destination, *args, **kwargs)

        def write(label, value):
            results[label] = mod._atomic_write_utf8(target, value, max_bytes=1024, expected_previous="old")

        monkeypatch.setattr(mod.os, "replace", pause_first_replace)
        first = threading.Thread(target=write, args=("first", "first"), daemon=True)
        second = threading.Thread(target=write, args=("second", "second"), daemon=True)
        first.start()
        assert commit_entered.wait(5)
        second.start()
        release_commit.set()
        first.join(5)
        second.join(5)

        assert not first.is_alive() and not second.is_alive()
        assert sorted(results.values()) == [False, True]
        assert target.read_text(encoding="utf-8") in {"first", "second"}

    def test_same_content_replacement_inode_is_not_accepted(self, monkeypatch, tmp_path):
        target = tmp_path / "settings.json"
        competitor = tmp_path / "competitor.json"
        target.write_text("old", encoding="utf-8")
        original_open = mod.os.open
        original_replace = mod.os.replace
        injected = False

        def replace_before_temporary_open(path, flags, *args, **kwargs):
            nonlocal injected
            candidate = Path(path)
            if (
                not injected
                and candidate.parent == tmp_path
                and candidate.name.startswith(".settings.json.")
                and candidate.name.endswith(".tmp")
            ):
                injected = True
                competitor.write_text("old", encoding="utf-8")
                original_replace(competitor, target)
            return original_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(mod.os, "open", replace_before_temporary_open)

        assert mod._atomic_write_utf8(target, "compile", max_bytes=1024, expected_previous="old") is False
        assert target.read_text(encoding="utf-8") == "old"

    def test_existing_target_compare_and_swap_is_cross_process(self, tmp_path):
        target = tmp_path / "settings.json"
        gate = tmp_path / "start"
        target.write_text("old", encoding="utf-8")
        program = (
            "import sys,time\n"
            "from pathlib import Path\n"
            "from compile_code.cli import _atomic_write_utf8\n"
            "target,gate,value = map(Path, sys.argv[1:])\n"
            "deadline = time.monotonic() + 10\n"
            "while not gate.exists():\n"
            "    if time.monotonic() > deadline: raise SystemExit(3)\n"
            "    time.sleep(0.01)\n"
            "print(int(_atomic_write_utf8(target, str(value), max_bytes=1024, expected_previous='old')))\n"
        )
        env = mod.os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        processes = [
            subprocess.Popen(
                [sys.executable, "-c", program, str(target), str(gate), value],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for value in ("first", "second")
        ]
        gate.write_text("go", encoding="utf-8")
        completed = [process.communicate(timeout=15) for process in processes]

        assert [process.returncode for process in processes] == [0, 0], completed
        assert sorted(stdout.strip() for stdout, _stderr in completed) == ["0", "1"]
        assert target.read_text(encoding="utf-8") in {"first", "second"}


class TestVerifyDirectoryTraversal:
    def test_expansion_is_deterministic_without_os_walk(self, tmp_path):
        source = tmp_path / "src"
        (source / "a").mkdir(parents=True)
        (source / "b").mkdir()
        for relative in ("a.py", "z.py", "a/y.py", "b/x.py"):
            (source / relative).write_text(relative, encoding="utf-8")

        first = mod._expand_verify_targets(["src"], tmp_path)
        second = mod._expand_verify_targets(["src"], tmp_path)

        assert first == second == ["src/a.py", "src/z.py", "src/a/y.py", "src/b/x.py"]
        assert "os.walk" not in inspect.getsource(mod._expand_verify_targets)

    def test_directory_limit_fails_closed(self, monkeypatch, tmp_path):
        (tmp_path / "src" / "nested").mkdir(parents=True)
        (tmp_path / "src" / "nested" / "a.py").write_text("pass\n", encoding="utf-8")
        monkeypatch.setattr(mod, "MAX_VERIFY_DIRECTORIES", 1)

        with pytest.raises(ValueError, match="verification_directory_limit"):
            mod._expand_verify_targets(["src"], tmp_path)

    def test_empty_directory_cannot_disappear_beside_a_valid_file(self, tmp_path):
        (tmp_path / "empty").mkdir()
        (tmp_path / "valid.py").write_text("pass\n", encoding="utf-8")

        with pytest.raises(ValueError, match="verification_directory_empty"):
            mod._expand_verify_targets(["empty", "valid.py"], tmp_path)

    def test_entry_limit_fails_closed_and_is_disclosed(self, monkeypatch, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        (source / "a.py").write_text("pass\n", encoding="utf-8")
        (source / "b.py").write_text("pass\n", encoding="utf-8")
        monkeypatch.setattr(mod, "MAX_VERIFY_DIRECTORY_ENTRIES", 1)

        with pytest.raises(ValueError, match="verification_directory_entry_limit") as error:
            mod._expand_verify_targets(["src"], tmp_path)

        verdict = mod._unsafe_scope_verdict(error.value)
        assert verdict is not None
        assert "1-entry safety limit" in verdict

    def test_cli_discloses_directory_entry_limit(self, runner, monkeypatch, compatible_roam):
        monkeypatch.setattr(mod, "MAX_VERIFY_DIRECTORY_ENTRIES", 7)
        monkeypatch.setattr(
            mod,
            "_prepare_verify_request",
            lambda _files: (_ for _ in ()).throw(ValueError("verification_directory_entry_limit")),
        )

        result = runner.invoke(mod.cli, ["verify", "src"])

        assert result.exit_code == mod.EXIT_TOOLCHAIN
        assert result.output.count("VERDICT:") == 1
        assert "7-entry safety limit" in result.output

    def test_partial_scandir_error_never_returns_partial_scope(self, monkeypatch, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        (source / "a.py").write_text("pass\n", encoding="utf-8")

        class BrokenScan:
            yielded = False

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def __iter__(self):
                return self

            def __next__(self):
                if not self.yielded:
                    self.yielded = True
                    return SimpleNamespace(name="a.py")
                raise OSError("directory read failed")

        monkeypatch.setattr(mod.os, "scandir", lambda _path: BrokenScan())

        with pytest.raises(ValueError, match="verification_directory_unreadable"):
            mod._expand_verify_targets(["src"], tmp_path)

    def test_link_entry_fails_closed_instead_of_disappearing_from_scope(self, tmp_path):
        source = tmp_path / "src"
        external = tmp_path / "external.py"
        source.mkdir()
        external.write_text("outside\n", encoding="utf-8")
        try:
            (source / "linked.py").symlink_to(external)
        except OSError as exc:
            pytest.skip(f"file links unavailable: {exc}")

        with pytest.raises(ValueError, match="verification_directory_unsafe"):
            mod._expand_verify_targets(["src"], tmp_path)

    def test_traversal_deadline_fails_closed(self, monkeypatch, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        (source / "a.py").write_text("pass\n", encoding="utf-8")
        ticks = iter([0.0, 0.0, mod.MAX_VERIFY_TRAVERSAL_SECONDS + 1.0])
        monkeypatch.setattr(mod.time, "monotonic", lambda: next(ticks))

        with pytest.raises(ValueError, match="verification_directory_timeout"):
            mod._expand_verify_targets(["src"], tmp_path)

    @pytest.mark.parametrize(
        ("constant", "value", "reason"),
        (
            ("MAX_VERIFY_DIRECTORIES", 1, "verification_directory_limit"),
            ("MAX_VERIFY_DIRECTORY_ENTRIES", 1, "verification_directory_entry_limit"),
        ),
    )
    def test_a_racing_bound_names_every_axis_not_only_the_one_that_fired(
        self, monkeypatch, tmp_path, constant, value, reason
    ):
        # Three bounds share one traversal loop and which one trips is decided
        # by filesystem throughput, not by policy: the same tree on the same
        # machine has reported a different reason on a different day. A reason
        # that names only its own bound reports that coin flip as a finding.
        # Every branch must state directories, entries and seconds so the
        # reader can predict the other bounds on their own hardware.
        source = tmp_path / "src" / "nested"
        source.mkdir(parents=True)
        (source / "a.py").write_text("pass\n", encoding="utf-8")
        (source / "b.py").write_text("pass\n", encoding="utf-8")
        monkeypatch.setattr(mod, constant, value)

        with pytest.raises(ValueError, match=reason) as error:
            mod._expand_verify_targets(["src"], tmp_path)

        raw = str(error.value)
        assert raw.startswith(f"{reason}: ")
        assert "directories" in raw and "entries" in raw and "dirs/s" in raw

        verdict = mod._unsafe_scope_verdict(error.value)
        assert verdict is not None
        assert "directories" in verdict and "entries" in verdict and "dirs/s" in verdict

    def test_the_traversal_deadline_also_names_every_axis(self, monkeypatch, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        (source / "a.py").write_text("pass\n", encoding="utf-8")
        ticks = iter([0.0, 0.0, mod.MAX_VERIFY_TRAVERSAL_SECONDS + 1.0])
        monkeypatch.setattr(mod.time, "monotonic", lambda: next(ticks))

        with pytest.raises(ValueError, match="verification_directory_timeout") as error:
            mod._expand_verify_targets(["src"], tmp_path)

        verdict = mod._unsafe_scope_verdict(error.value)
        assert verdict is not None
        assert f"{mod.MAX_VERIFY_TRAVERSAL_SECONDS:g}-second safety limit at " in verdict
        assert f"of {mod.MAX_VERIFY_DIRECTORIES} directories" in verdict
        assert f"of {mod.MAX_VERIFY_DIRECTORY_ENTRIES} entries" in verdict
        assert f"{mod.MAX_VERIFY_TRAVERSAL_SECONDS + 1.0:.1f}s of" in verdict

    def test_a_reason_without_a_position_still_renders(self):
        # Older raise sites and forwarded reasons carry no detail; the verdict
        # must degrade to the bare bound rather than to a dangling preposition.
        verdict = mod._unsafe_scope_verdict(ValueError("verification_directory_timeout"))

        assert verdict is not None
        assert f"{mod.MAX_VERIFY_TRAVERSAL_SECONDS:g}-second safety limit." in verdict
        assert " at " not in verdict


def _write_valid_claude_wiring(root: Path, *, hook_version: int = 10, include_verify: bool = True) -> Path:
    claude_dir = root / ".claude"
    hook_dir = claude_dir / "hooks"
    hook_dir.mkdir(parents=True, exist_ok=True)
    ups = hook_dir / mod.HOOK_MARKER
    stop = hook_dir / "roam-verify-stop.py"
    ups.write_text(
        "#!/usr/bin/env python3\n"
        f"# roam-hook-version: {hook_version}\n"
        'HOOK_EVENT = "UserPromptSubmit"\n'
        'COMMAND = ["roam", "--json", "compile", "prompt"]\n'
        "def _policy_snapshot(): pass\n",
        encoding="utf-8",
    )
    stop.write_text(
        "#!/usr/bin/env python3\n"
        f"# roam-hook-version: {hook_version}\n"
        'SCHEMA = "roam.verify.receipt.v3"\n'
        'ENV = ("ROAM_VERIFY_REQUEST_NONCE", "ROAM_VERIFY_SCOPE_SHA256", "ROAM_VERIFY_CONTENT_SHA256")\n'
        "def _verify_protocol_state(): pass\n"
        "def _verification_snapshot(): pass\n"
        'FIELDS = ("scope_stable", "content_sha256_before", "content_sha256_after")\n',
        encoding="utf-8",
    )
    hooks = {
        "UserPromptSubmit": [{"hooks": [{"type": "command", "command": _roam_13_10_hook_command(ups)}]}],
    }
    if include_verify:
        hooks["Stop"] = [{"hooks": [{"type": "command", "command": _roam_13_10_hook_command(stop)}]}]
    else:
        stop.unlink()
    settings = {"hooks": hooks}
    settings_path = claude_dir / "settings.json"
    settings_path.write_text(json.dumps(settings), encoding="utf-8")
    return settings_path


def _roam_13_10_hook_command(path: Path) -> str:
    """Mirror Roam 13.10's private producer without importing another checkout."""
    argv = [sys.executable, str(path.resolve(strict=True))]
    return subprocess.list2cmdline(argv) if mod.os.name == "nt" else " ".join(shlex.quote(part) for part in argv)


class TestClaudeStructuralReadiness:
    @pytest.mark.parametrize(
        "raw",
        [
            '{"notes":"roam-compile-ups.py"}',
            "not json; roam-compile-ups.py",
            '{"hooks":"roam-compile-ups.py"}',
        ],
    )
    def test_marker_substrings_never_count_as_wired(self, tmp_path, raw):
        settings = tmp_path / "settings.json"
        settings.write_text(raw, encoding="utf-8")
        assert mod._wired_in(str(settings)) is False

    def test_requires_both_events_and_exact_hook_paths(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        settings_path = _write_valid_claude_wiring(tmp_path)
        assert mod._wired_in(str(settings_path)) is True

        settings = json.loads(settings_path.read_text(encoding="utf-8"))
        settings["hooks"]["WrongEvent"] = settings["hooks"].pop("Stop")
        settings_path.write_text(json.dumps(settings), encoding="utf-8")
        assert mod._wired_in(str(settings_path)) is False

        settings_path = _write_valid_claude_wiring(tmp_path)
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
        settings["hooks"]["Stop"][0]["hooks"][0]["command"] = "python3 /tmp/roam-verify-stop.py"
        settings_path.write_text(json.dumps(settings), encoding="utf-8")
        assert mod._wired_in(str(settings_path)) is False

    def test_roam_13_10_producer_command_is_accepted_without_generalizing_interpreters(self, tmp_path):
        hook = tmp_path / "hooks with spaces" / mod.HOOK_MARKER
        hook.parent.mkdir()
        hook.write_text("# hook\n", encoding="utf-8")
        produced = _roam_13_10_hook_command(hook)

        assert mod._hook_command_matches(produced, hook) is True
        assert mod._hook_command_matches(f"python3 {hook}", hook) is False
        assert mod._hook_command_matches(produced + " --extra", hook) is False
        assert mod._hook_command_matches(produced.replace(sys.executable, str(hook), 1), hook) is False

    def test_rejects_missing_and_stale_hook_bodies(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        settings_path = _write_valid_claude_wiring(tmp_path)
        (tmp_path / ".claude" / "hooks" / "roam-verify-stop.py").unlink()
        assert mod._wired_in(str(settings_path)) is False

        settings_path = _write_valid_claude_wiring(tmp_path, hook_version=9)
        assert mod._wired_in(str(settings_path)) is False

    def test_rejects_duplicate_settings_keys_and_command_suffixes(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        settings_path = _write_valid_claude_wiring(tmp_path)
        raw = settings_path.read_text(encoding="utf-8")
        settings_path.write_text(raw[:-1] + ', "hooks": {} }', encoding="utf-8")
        assert mod._wired_in(str(settings_path)) is False

        settings_path = _write_valid_claude_wiring(tmp_path)
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
        settings["hooks"]["Stop"][0]["hooks"][0]["command"] += " --forged"
        settings_path.write_text(json.dumps(settings), encoding="utf-8")
        assert mod._wired_in(str(settings_path)) is False

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda settings: settings.update(disableAllHooks=True),
            lambda settings: settings["hooks"]["Stop"][0].update(matcher="never"),
            lambda settings: settings["hooks"]["Stop"][0]["hooks"][0].__setitem__("async", True),
        ],
        ids=["disabled", "conditioned-rule", "noncanonical-handler"],
    )
    def test_rejects_disabled_or_noncanonical_hook_entries(self, monkeypatch, tmp_path, mutate):
        monkeypatch.chdir(tmp_path)
        settings_path = _write_valid_claude_wiring(tmp_path)
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
        mutate(settings)
        settings_path.write_text(json.dumps(settings), encoding="utf-8")
        assert mod._wired_in(str(settings_path)) is False

    def test_local_hooks_override_cannot_fall_through_to_valid_project_hooks(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        _write_valid_claude_wiring(tmp_path)
        local = tmp_path / ".claude" / "settings.local.json"
        local.write_text(json.dumps({"hooks": {}}), encoding="utf-8")

        ready, reason = mod._project_wiring_state()

        assert ready is False
        assert reason == "hook_event_missing"

        local.write_text(json.dumps({"theme": "dark"}), encoding="utf-8")
        assert mod._project_wiring_state() == (True, "ready")

    def test_effective_disable_all_hooks_precedence_is_enforced(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        settings_path = _write_valid_claude_wiring(tmp_path)
        home = tmp_path / "home"
        user_dir = home / ".claude"
        user_dir.mkdir(parents=True)
        (user_dir / "settings.json").write_text(json.dumps({"disableAllHooks": True}), encoding="utf-8")
        monkeypatch.setattr(mod.os.path, "expanduser", lambda value: str(home))

        assert mod._claude_wiring_state() == (False, "hooks_disabled")

        settings = json.loads(settings_path.read_text(encoding="utf-8"))
        settings["disableAllHooks"] = False
        settings_path.write_text(json.dumps(settings), encoding="utf-8")
        assert mod._claude_wiring_state() == (True, "project")

    def test_runtime_readiness_rejects_symlinked_hook_directory(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        _write_valid_claude_wiring(tmp_path)
        hook_dir = tmp_path / ".claude" / "hooks"
        external_hooks = tmp_path / "external-hooks"
        hook_dir.rename(external_hooks)
        try:
            hook_dir.symlink_to(external_hooks, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"directory symlinks unavailable: {exc}")

        ready, reason = mod._project_wiring_state()

        assert ready is False
        assert reason == "settings_path_unsafe"

    @pytest.mark.parametrize("marker_kind", ["empty_git", "empty_index", "non_sqlite_index"])
    def test_workspace_trust_roots_ignore_unsubstantiated_repository_markers(self, monkeypatch, tmp_path, marker_kind):
        workspace = tmp_path / "workspace"
        nested = workspace / "src" / "package"
        nested.mkdir(parents=True)
        if marker_kind == "empty_git":
            (workspace / ".git").mkdir()
        else:
            roam_dir = workspace / ".roam"
            roam_dir.mkdir()
            contents = b"" if marker_kind == "empty_index" else b"not a SQLite database"
            (roam_dir / "index.db").write_bytes(contents)
        monkeypatch.chdir(nested)

        roots = mod._workspace_trust_roots()

        assert roots[0] == nested.resolve()
        assert workspace.resolve() not in roots

    def test_workspace_trust_roots_accept_real_git_repository(self, monkeypatch, tmp_path):
        repository = tmp_path / "repository"
        repository.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
        nested = repository / "src" / "package"
        nested.mkdir(parents=True)
        monkeypatch.chdir(nested)

        assert mod._workspace_trust_roots() == (nested.resolve(), repository.resolve())

    def test_workspace_trust_roots_accept_valid_sqlite_index(self, monkeypatch, tmp_path):
        workspace = tmp_path / "workspace"
        roam_dir = workspace / ".roam"
        roam_dir.mkdir(parents=True)
        with sqlite3.connect(roam_dir / "index.db") as connection:
            connection.execute("CREATE TABLE indexed_files(path TEXT PRIMARY KEY)")
        nested = workspace / "src" / "package"
        nested.mkdir(parents=True)
        monkeypatch.chdir(nested)

        assert mod._workspace_trust_roots() == (nested.resolve(), workspace.resolve())

    def test_trusted_resolver_rejects_workspace_path_injection(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        injected = tmp_path / ("claude.exe" if mod.os.name == "nt" else "claude")
        injected.write_text("fake", encoding="utf-8")
        if mod.os.name != "nt":
            injected.chmod(0o755)
        monkeypatch.setattr("shutil.which", lambda _name: str(injected))
        path, reason = mod._resolve_trusted_executable("claude", reject_workspace=True)
        assert path is None
        assert reason == "workspace_path"

    def test_trusted_resolver_accepts_external_absolute_install(self, monkeypatch, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        monkeypatch.chdir(workspace)
        external = tmp_path / "bin" / ("claude.exe" if mod.os.name == "nt" else "claude")
        external.parent.mkdir()
        external.write_text("real", encoding="utf-8")
        if mod.os.name != "nt":
            external.chmod(0o755)
        monkeypatch.setattr("shutil.which", lambda _name: str(external))
        path, reason = mod._resolve_trusted_executable("claude", reject_workspace=True)
        assert path == str(external.resolve())
        assert reason is None

    def test_roam_resolver_rejects_workspace_path_injection(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        injected = tmp_path / ("roam.exe" if mod.os.name == "nt" else "roam")
        injected.write_text("fake", encoding="utf-8")
        if mod.os.name != "nt":
            injected.chmod(0o755)
        monkeypatch.setattr("shutil.which", lambda _name: str(injected))
        assert mod._resolve_roam_executable() is None

    def test_exact_roam_producer_attests_current_hook_bodies(self, monkeypatch):
        captured = {}
        envelope = {
            "schema": mod.VERIFY_ENVELOPE_SCHEMA,
            "schema_version": mod.VERIFY_ENVELOPE_SCHEMA_VERSION,
            "command": "hooks",
            "version": mod.MIN_ROAM_VERSION,
            "summary": {
                "verdict": "roam Claude Code hooks wired + current",
                "already_installed": True,
                "foreign_bodies": [],
                "hook_body_version": mod.MIN_CLAUDE_HOOK_VERSION,
                "body_states": {filename: "current" for filename in mod.HOOK_FILENAMES},
            },
        }

        class _P:
            returncode = 0
            stdout = json.dumps(envelope).encode("utf-8")
            stderr = b""

        def fake_run(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return _P()

        monkeypatch.setattr(mod, "_run_bounded_capture", fake_run)

        assert mod._attest_claude_hooks("/trusted/roam", mod.MIN_ROAM_VERSION, user_level=True) is True
        assert captured["argv"] == ["/trusted/roam", "--json", "hooks", "claude", "--user"]
        assert captured["kwargs"]["env"]["ROAM_DEFAULT_JSON_BUDGET"] == "0"
        assert captured["kwargs"]["stdout_limit"] == mod.MAX_VERIFY_JSON_BYTES
        assert captured["kwargs"]["stderr_limit"] == mod.MAX_VERIFY_STDERR_BYTES

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("already_installed", False),
            ("foreign_bodies", [mod.HOOK_MARKER]),
            ("hook_body_version", mod.MIN_CLAUDE_HOOK_VERSION - 1),
            ("body_states", {mod.HOOK_MARKER: "current", "roam-verify-stop.py": "modified"}),
        ],
    )
    def test_producer_attestation_rejects_noncanonical_state(self, monkeypatch, field, value):
        summary = {
            "verdict": "hooks",
            "already_installed": True,
            "foreign_bodies": [],
            "hook_body_version": mod.MIN_CLAUDE_HOOK_VERSION,
            "body_states": {filename: "current" for filename in mod.HOOK_FILENAMES},
        }
        summary[field] = value

        class _P:
            returncode = 0
            stdout = json.dumps(
                {
                    "schema": mod.VERIFY_ENVELOPE_SCHEMA,
                    "schema_version": mod.VERIFY_ENVELOPE_SCHEMA_VERSION,
                    "command": "hooks",
                    "version": mod.MIN_ROAM_VERSION,
                    "summary": summary,
                }
            ).encode("utf-8")
            stderr = b""

        monkeypatch.setattr(mod, "_run_bounded_capture", lambda *args, **kwargs: _P())
        assert mod._attest_claude_hooks("/trusted/roam", mod.MIN_ROAM_VERSION, user_level=False) is False

    @pytest.mark.parametrize(
        ("schema_version", "attested"),
        [("1.1.0", True), ("1.2.0", True), ("1.9.0", True), ("2.0.0", False), ("nope", False)],
    )
    def test_producer_attestation_reads_any_same_major_envelope(self, monkeypatch, schema_version, attested):
        """Hook attestation is a second copy of the verify gate: same rule applies.

        Pinning the exact envelope string here made every roam minor release
        report `hooks:producer_attestation` on launch, on wiring that was
        canonical and current.
        """

        class _P:
            returncode = 0
            stdout = json.dumps(
                {
                    "schema": mod.VERIFY_ENVELOPE_SCHEMA,
                    "schema_version": schema_version,
                    "command": "hooks",
                    "version": mod.MIN_ROAM_VERSION,
                    "summary": {
                        "verdict": "hooks",
                        "already_installed": True,
                        "foreign_bodies": [],
                        "hook_body_version": mod.MIN_CLAUDE_HOOK_VERSION,
                        "body_states": {filename: "current" for filename in mod.HOOK_FILENAMES},
                    },
                }
            ).encode("utf-8")
            stderr = b""

        monkeypatch.setattr(mod, "_run_bounded_capture", lambda *args, **kwargs: _P())
        assert mod._attest_claude_hooks("/trusted/roam", mod.MIN_ROAM_VERSION, user_level=False) is attested

    def test_cached_index_and_head_marker_cannot_bypass_roam_reinspection(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_text("", encoding="utf-8")
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n", encoding="utf-8")
        _write_valid_claude_wiring(tmp_path)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        monkeypatch.setattr(
            mod,
            "_resolve_trusted_executable",
            lambda name, *, reject_workspace: (TRUSTED_CLAUDE_PATH, None),
        )
        _stub_content_digest(monkeypatch)
        inspections = []
        monkeypatch.setattr(
            mod,
            "_inspect_roam",
            lambda timeout=10: (
                inspections.append(True)
                or _roam_info(executable_version="13.9.9", metadata_version=mod.MIN_ROAM_VERSION)
            ),
        )
        monkeypatch.setattr(mod, "_attest_claude_hooks", lambda *args, **kwargs: pytest.fail("old Roam"))
        launches = []
        monkeypatch.setattr(mod, "_launch_agent", lambda *args, **kwargs: launches.append(True) or 0)

        result = runner.invoke(mod.cli, ["claude"])

        assert result.exit_code == mod.EXIT_TOOLCHAIN
        assert inspections == [True]
        assert "toolchain version mismatch" in result.output
        assert launches == []

    def test_allow_unwired_discloses_toolchain_degradation(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_text("", encoding="utf-8")
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n", encoding="utf-8")
        _write_valid_claude_wiring(tmp_path)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        monkeypatch.setattr(
            mod,
            "_resolve_trusted_executable",
            lambda name, *, reject_workspace: (TRUSTED_CLAUDE_PATH, None),
        )
        _stub_content_digest(monkeypatch)
        monkeypatch.setattr(
            mod,
            "_inspect_roam",
            lambda timeout=10: _roam_info(executable_version="13.9.9", metadata_version=mod.MIN_ROAM_VERSION),
        )
        launches = []
        monkeypatch.setattr(mod, "_launch_agent", lambda argv, env, **kwargs: launches.append(argv) or 0)

        result = runner.invoke(mod.cli, ["claude", "--allow-unwired"])

        assert result.exit_code == 0
        assert "explicit degraded launch accepted (--allow-unwired)" in result.output
        assert "toolchain" in result.output
        assert launches == [[TRUSTED_CLAUDE_PATH]]

    def test_roam_executable_drift_is_rejected_before_launch(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_text("", encoding="utf-8")
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n", encoding="utf-8")
        _write_valid_claude_wiring(tmp_path)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        monkeypatch.setattr(
            mod,
            "_resolve_trusted_executable",
            lambda name, *, reject_workspace: (TRUSTED_CLAUDE_PATH, None),
        )
        _stub_content_digest(monkeypatch)
        inspections = iter(
            [
                _roam_info(path="/trusted/roam-a"),
                _roam_info(path="/trusted/roam-b"),
            ]
        )
        monkeypatch.setattr(mod, "_inspect_roam", lambda timeout=10: next(inspections))
        monkeypatch.setattr(
            mod, "_attest_claude_hooks", lambda *args, **kwargs: pytest.fail("drift must block attestation")
        )
        launches = []
        monkeypatch.setattr(mod, "_launch_agent", lambda *args, **kwargs: launches.append(True) or 0)

        result = runner.invoke(mod.cli, ["claude"])

        assert result.exit_code == mod.EXIT_TOOLCHAIN
        assert "Roam executable/version changed" in result.output
        assert launches == []

    def test_claude_executable_drift_is_rejected_even_when_hooks_are_ready(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_text("", encoding="utf-8")
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n", encoding="utf-8")
        _write_valid_claude_wiring(tmp_path)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        paths = iter([TRUSTED_CLAUDE_PATH, f"{TRUSTED_CLAUDE_PATH}.replaced"])
        monkeypatch.setattr(
            mod,
            "_resolve_trusted_executable",
            lambda name, *, reject_workspace: (next(paths), None),
        )
        _stub_content_digest(monkeypatch, TRUSTED_CLAUDE_PATH, f"{TRUSTED_CLAUDE_PATH}.replaced")
        monkeypatch.setattr(mod, "_inspect_roam", lambda timeout=10: _roam_info())
        monkeypatch.setattr(mod, "_attest_claude_hooks", lambda *args, **kwargs: True)
        launches = []
        monkeypatch.setattr(mod, "_launch_agent", lambda *args, **kwargs: launches.append(True) or 0)

        result = runner.invoke(mod.cli, ["claude"])

        assert result.exit_code == 1
        assert "Claude executable changed" in result.output
        assert launches == []


class TestToolchainVersionGatingPartition:
    """Which verbs refuse an out-of-interval roam, pinned as an exact partition.

    Two independent reviews of the same tree published two different, both
    wrong, lists of the commands that delegate to roam WITHOUT checking its
    version -- one named `wire` as not delegating (its whole body is one call
    that delegates), the other dropped `wire` and still missed `unwire`. A
    residual that two readers cannot state correctly from the source is not a
    residual anyone can decide about, so it is derived here instead of
    described.

    This pins a REAL and deliberate asymmetry: `compile verify` refuses a roam
    outside `ROAM_VERSION_REQUIREMENT`, while seven other verbs will happily
    drive that same roam. Closing it refuses MORE and is allowed; leaving it
    keeps a working escape hatch on the day a new roam major lands. Either way
    the next command added must land on one side of this list on purpose --
    adding one that delegates without gating fails here until it is listed.
    """

    @staticmethod
    def _call_graph() -> dict[str, ast.FunctionDef]:
        source = Path(mod.__file__).read_text(encoding="utf-8")
        return {node.name: node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.FunctionDef)}

    @classmethod
    def _reaches(cls, name: str, predicate, funcs, seen: frozenset[str] = frozenset()) -> bool:
        if name in seen or name not in funcs:
            return False
        for node in ast.walk(funcs[name]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if predicate(node.func.id) or cls._reaches(node.func.id, predicate, funcs, seen | {name}):
                    return True
        return False

    def _partition(self) -> tuple[set[str], set[str]]:
        funcs = self._call_graph()
        gated, delegating = set(), set()
        for name, command in mod.cli.commands.items():
            entry = command.callback.__name__
            if self._reaches(entry, lambda called: called == "_roam_problem", funcs):
                gated.add(name)
            if self._reaches(entry, lambda called: called.startswith("_delegate"), funcs):
                delegating.add(name)
        return gated, delegating

    def test_only_these_verbs_check_the_roam_version(self):
        gated, _ = self._partition()
        assert gated == {"verify", "claude", "doctor"}

    def test_every_other_delegating_verb_drives_an_unchecked_roam(self):
        gated, delegating = self._partition()
        # Seven, not the five either review reported. `wire` and `unwire` each
        # consist of a single call whose only exit is through `_delegate`.
        assert delegating - gated == {"baseline", "init", "report", "run", "stats", "wire", "unwire"}

    def test_the_asymmetry_is_reachable_and_not_a_parsing_artifact(self):
        # `wire`'s entire body is the delegating call, so "it does not
        # delegate" cannot be true of any code path.
        assert "_exit_after_canonical_claude_hook_update" in inspect.getsource(mod._wire.callback)
        assert "_delegate(" in inspect.getsource(mod._exit_after_canonical_claude_hook_update)
        # And the gate that `verify` has really is absent from theirs.
        assert "_roam_problem" in inspect.getsource(mod._verify.callback)
        assert "_roam_problem" not in inspect.getsource(mod._report.callback)
