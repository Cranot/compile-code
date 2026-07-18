"""compile-code CLI surface tests.

The CLI is a thin product driver over the roam-code toolchain; these tests
pin the surface contract (verbs exist, delegation arguments are correct,
doctor's state reporting) with the toolchain calls stubbed — no index or
subprocess work, so they run anywhere.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

import compile_code.cli as mod


ROOT = Path(__file__).resolve().parents[1]
TRUSTED_CLAUDE_PATH = r"C:\Tools\claude.exe" if mod.os.name == "nt" else "/opt/claude/bin/claude"


@pytest.fixture
def runner():
    return CliRunner()


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

    def test_verify_help_includes_new_only_and_diff_only(self, runner):
        res = runner.invoke(mod.cli, ["verify", "--help"])
        assert "--new-only" in res.output
        assert "--diff-only" in res.output


class TestDependencyFloor:
    def test_runtime_metadata_and_docs_share_the_13_9_floor(self):
        assert mod.MIN_ROAM_VERSION == "13.10.0"
        floor = mod.MIN_ROAM_VERSION
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        assert f'"roam-code>={floor}"' in pyproject
        for name in ("README.md", "AGENTS.md"):
            contents = (ROOT / name).read_text(encoding="utf-8")
            assert re.search(rf"roam-code[^\n]{{0,80}}>=\s*{re.escape(floor)}", contents)


class TestRoamVersionEnforcement:
    @pytest.mark.parametrize(
        ("raw", "compatible"),
        [
            ("13.9.99", False),
            ("13.10.0rc1", False),
            ("13.10.0", True),
            ("13.10.0.post1", True),
            ("13.10.0dev1", False),
            ("not-a-version", False),
        ],
    )
    def test_minimum_comparison(self, raw, compatible):
        assert mod._version_meets_minimum(raw) is compatible

    def test_inspection_runs_the_exact_path_and_keeps_metadata_separate(self, monkeypatch):
        chosen = r"C:\Tools\roam.exe"
        captured = {}
        monkeypatch.setenv("PYTHONPATH", "malicious")

        class _P:
            returncode = 0
            stdout = "roam.EXE, version 13.10.2\n"
            stderr = ""

        def fake_run(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return _P()

        monkeypatch.setattr(mod, "_resolve_roam_executable", lambda: chosen)
        monkeypatch.setattr(mod, "_python_roam_metadata_version", lambda: "99.0.0")
        monkeypatch.setattr(mod.subprocess, "run", fake_run)

        info = mod._inspect_roam()

        assert captured["argv"] == [chosen, "--version"]
        assert info["path"] == chosen
        assert info["version"] == "13.10.2"
        assert info["metadata_version"] == "99.0.0"
        assert "PYTHONPATH" not in captured["kwargs"]["env"]
        assert captured["kwargs"]["env"]["PYTHONSAFEPATH"] == "1"

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

    def test_skips_wiring_when_repo_is_already_wired(self, runner, roam_calls, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        _write_valid_claude_wiring(tmp_path)
        launches = self._stub_launch(monkeypatch)
        res = runner.invoke(mod.cli, ["claude"])
        assert res.exit_code == 0
        assert roam_calls == []
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
        assert "VERDICT: indexing failed" in capsys.readouterr().out

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
        monkeypatch.setattr(mod, "_discover_verify_targets", lambda _root: ["changed.py"])

    def _capture(self, output, rc):
        """Stub _roam_capture to return a CompletedProcess-shaped object."""
        captured = {}

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
                threshold_index = list(args).index("--threshold") + 1
                threshold = int(args[threshold_index])
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
                findings = []
                if "src/bad.py:12" in output:
                    findings = [
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
                    violations=findings,
                )
                for finding in findings:
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
        assert mod._failing_files(self.FAIL_OUTPUT) == ["src/bad.py"]

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
        assert "next    : compile verify src/bad.py" in res.output
        assert captured["args"][:4] == ["--json", "verify", "--threshold", "70"]
        assert captured["args"][4] == "--"
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
        assert "command : compile verify --threshold 90 src/bad.py" in res.output

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
            "--threshold",
            "70",
            "--",
            "src/bad.py",
        ]
        assert "command : compile verify --new-only --diff-only src/bad.py" in res.output
        assert "next    : compile verify --new-only --diff-only src/bad.py" in res.output

    def test_verify_no_argument_binds_discovered_scope_before_delegation(self, runner, monkeypatch):
        fake, captured = self._capture("VERDICT: PASS (score 100/100) -- no changed files\n", 0)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        res = runner.invoke(mod.cli, ["verify"])
        assert res.exit_code == 0
        assert captured["args"][:4] == ["--json", "verify", "--threshold", "70"]
        assert captured["args"][4] in {"--", "--changed"}
        assert captured["env"]["ROAM_VERIFY_SCOPE_COUNT"].isdigit()

    def test_no_argument_failure_uses_bound_scope_for_human_context(self, runner, monkeypatch):
        fake, captured = self._capture("VERDICT: FAIL (score 60/100) -- discovery-level failure\n", 5)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        res = runner.invoke(mod.cli, ["verify"])

        assert res.exit_code == 5
        assert captured["args"][:4] == ["--json", "verify", "--threshold", "70"]
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
            "--threshold",
            "70",
            "--",
            "src/bad.py",
            "src/good.py",
        ]
        assert "command : compile verify src/good.py src/bad.py" in res.output
        assert "files   : src/bad.py" in res.output
        assert "next    : compile verify src/bad.py" in res.output

    def test_oversized_advisory_does_not_change_delegation(self, runner, monkeypatch):
        fake, captured = self._capture(self.FAIL_OUTPUT, 5)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        files = [f"f{i}.py" for i in range(30)]
        res = runner.invoke(mod.cli, ["verify", *files])
        assert res.exit_code == 5
        assert "scope down" in res.output
        assert captured["args"] == ["--json", "verify", "--threshold", "70", "--", *sorted(files)]

    def test_no_advisory_for_small_explicit_list(self, runner, monkeypatch):
        fake, _ = self._capture("VERDICT: PASS (score 100/100) -- no issues\n", 0)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        res = runner.invoke(mod.cli, ["verify", "a.py", "b.py"])
        assert "scope down" not in res.output


class TestBaselineVerb:
    def test_baseline_refuses_dirty_tree(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_git_status_porcelain", lambda timeout=10: (0, " M src/cli.py\n"))
        monkeypatch.setattr(mod, "_roam", lambda *a, timeout=600: pytest.fail("must not baseline dirty trees"))
        res = runner.invoke(mod.cli, ["baseline"])
        assert res.exit_code == 1
        assert "dirty tree" in res.output

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
    def _validate(self, raw: str, *, rc: int = 0, expected: dict[str, object] | None = None):
        return mod._validate_verify_protocol(
            raw,
            returncode=rc,
            expected_receipt=expected or _bound_verify_receipt(),
            expected_roam_version=mod.MIN_ROAM_VERSION,
            expected_threshold=70,
        )

    def test_accepts_one_complete_bound_receipt(self):
        envelope = _verify_envelope()
        assert self._validate(json.dumps(envelope)) == envelope

    def test_accepts_canonical_complete_no_changes_transaction(self):
        expected = _bound_verify_receipt(target_file_count=0)
        envelope = _verify_envelope(receipt=expected)
        summary = envelope["summary"]
        summary.update(
            verdict="PASS",
            score=100,
            files_checked=0,
            violation_count=0,
            checks_run=[],
            state="no_changes",
        )
        summary.pop("targets_checked")
        summary.pop("verification_receipt")
        summary.pop("quality_band")
        summary.pop("index_refresh")
        envelope["categories"] = {
            name: (
                {"score": 100, "violations": [], "available": True}
                if name == "verification"
                else {"score": 100, "violations": []}
            )
            for name in mod._VERIFY_NO_CHANGES_CATEGORY_NAMES
        }
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
        envelope = _verify_envelope(receipt=expected)
        summary = envelope["summary"]
        summary.update(
            verdict="PASS",
            score=100,
            files_checked=0,
            violation_count=0,
            checks_run=[],
            state="no_changes",
        )
        summary.pop("targets_checked")
        summary.pop("verification_receipt")
        summary.pop("quality_band")
        summary.pop("index_refresh")
        envelope["categories"] = {
            name: (
                {"score": 100, "violations": [], "available": True}
                if name == "verification"
                else {"score": 100, "violations": []}
            )
            for name in mod._VERIFY_NO_CHANGES_CATEGORY_NAMES
        }
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

    def test_rejects_audit_exact_contradictory_two_line_canary(self):
        raw = "VERDICT: PASS (score 100/100) -- no issues\nVERDICT: SKIPPED -- checks did not run\n"
        with pytest.raises(ValueError):
            self._validate(raw)

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda envelope: envelope.update(extra="not closed"),
            lambda envelope: envelope.update(schema="roam-envelope-v2"),
            lambda envelope: envelope.update(schema_version="1.2.0"),
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
            "envelope-extra-key",
            "envelope-schema",
            "envelope-version",
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

    def test_rejects_oversized_output_before_parsing(self):
        raw = " " * (mod.MAX_VERIFY_JSON_BYTES + 1)
        with pytest.raises(ValueError):
            self._validate(raw)

    def test_rejects_pass_with_fail_evidence(self):
        finding = {"severity": "FAIL", "category": "syntax", "file": "bad.py", "line": 1}
        with pytest.raises(ValueError):
            self._validate(json.dumps(_verify_envelope(violations=[finding])))

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

        root, targets, receipt, env = mod._prepare_verify_request(("b.py", "a.py", "a.py"))

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

    def test_scope_paths_reject_control_characters(self):
        with pytest.raises(ValueError):
            mod._verification_scope_paths(["safe.py", "bad\nname.py"])

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
            lambda files: (tmp_path, ["src/a.py"], expected, env),
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


def _write_valid_claude_wiring(root: Path, *, hook_version: int = 10) -> Path:
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
    settings = {
        "hooks": {
            "UserPromptSubmit": [{"hooks": [{"type": "command", "command": f"python3 {ups}"}]}],
            "Stop": [{"hooks": [{"type": "command", "command": f"python3 {stop}"}]}],
        }
    }
    settings_path = claude_dir / "settings.json"
    settings_path.write_text(json.dumps(settings), encoding="utf-8")
    return settings_path


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
            stdout = json.dumps(envelope)

        def fake_run(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return _P()

        monkeypatch.setattr(mod.subprocess, "run", fake_run)

        assert mod._attest_claude_hooks("/trusted/roam", mod.MIN_ROAM_VERSION, user_level=True) is True
        assert captured["argv"] == ["/trusted/roam", "--json", "hooks", "claude", "--user"]
        assert captured["kwargs"]["env"]["ROAM_DEFAULT_JSON_BUDGET"] == "0"

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
            )

        monkeypatch.setattr(mod.subprocess, "run", lambda *args, **kwargs: _P())
        assert mod._attest_claude_hooks("/trusted/roam", mod.MIN_ROAM_VERSION, user_level=False) is False

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
        monkeypatch.setattr(mod, "_inspect_roam", lambda timeout=10: _roam_info())
        monkeypatch.setattr(mod, "_attest_claude_hooks", lambda *args, **kwargs: True)
        launches = []
        monkeypatch.setattr(mod, "_launch_agent", lambda *args, **kwargs: launches.append(True) or 0)

        result = runner.invoke(mod.cli, ["claude"])

        assert result.exit_code == 1
        assert "Claude executable changed" in result.output
        assert launches == []
