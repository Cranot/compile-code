"""compile-code CLI surface tests.

The CLI is a thin product driver over the roam-code toolchain; these tests
pin the surface contract (verbs exist, delegation arguments are correct,
doctor's state reporting) with the toolchain calls stubbed — no index or
subprocess work, so they run anywhere.
"""

from __future__ import annotations

from importlib.metadata import version

import pytest
from click.testing import CliRunner

import compile_code.cli as mod


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def roam_calls(monkeypatch):
    """Stub the toolchain; record argv per call."""
    calls = []

    class _P:
        returncode = 0

    def fake(*args, timeout=600):
        calls.append(list(args))
        return _P()

    monkeypatch.setattr(mod, "_roam", fake)
    return calls


def _version_tuple(raw: str) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in raw.split("."):
        digits = []
        for char in chunk:
            if char.isdigit():
                digits.append(char)
            else:
                break
        if not digits:
            break
        parts.append(int("".join(digits)))
        if len(parts) == 3:
            break
    return tuple(parts)


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

    def test_stats_delegates(self, runner, roam_calls):
        self._delegates(runner, roam_calls, ["stats"], ["compile-stats"])

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
    def test_installed_roam_code_satisfies_launch_floor(self):
        assert _version_tuple(version("roam-code")) >= (13, 7, 0)


class TestWiringSmoke:
    def test_wire_round_trip_marks_repo_and_doctor_sees_it(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_on_path", lambda name: True)
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_text("")
        (tmp_path / ".claude").mkdir()
        calls = []

        class _P:
            returncode = 0

        def fake(*args, timeout=600):
            calls.append(list(args))
            if list(args) == ["hooks", "claude", "--write"]:
                (tmp_path / ".claude" / "settings.local.json").write_text(f'{{"hooks": "{mod.HOOK_MARKER}"}}')
            return _P()

        monkeypatch.setattr(mod, "_roam", fake)
        res = runner.invoke(mod.cli, ["wire", "claude"])
        assert res.exit_code == 0
        assert calls == [["hooks", "claude", "--write"]]
        doctor = runner.invoke(mod.cli, ["doctor"])
        assert "wired (project)" in doctor.output
        assert "VERDICT: ready" in doctor.output


class TestClaudeLaunch:
    def test_missing_claude_binary_exits_1(self, runner, roam_calls, monkeypatch):
        monkeypatch.setattr(mod, "_on_path", lambda name: False)
        res = runner.invoke(mod.cli, ["claude"])
        assert res.exit_code == 1
        assert "not found on PATH" in res.output

    def test_indexes_wires_then_execs(self, runner, roam_calls, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)  # no index here
        monkeypatch.setattr(mod, "_on_path", lambda name: True)
        execs = []
        monkeypatch.setattr(mod.os, "execvp", lambda f, argv: execs.append((f, argv)))
        res = runner.invoke(mod.cli, ["claude", "--", "-p", "hello"])
        assert res.exit_code == 0
        assert ["init"] in roam_calls
        assert ["hooks", "claude", "--write"] in roam_calls
        assert execs and execs[0][0] == "claude"

    def test_skips_wiring_when_repo_is_already_wired(self, runner, roam_calls, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_on_path", lambda name: True)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".claude" / "settings.local.json").write_text(f'{{"hooks": "{mod.HOOK_MARKER}"}}')
        execs = []
        monkeypatch.setattr(mod.os, "execvp", lambda f, argv: execs.append((f, argv)))
        res = runner.invoke(mod.cli, ["claude"])
        assert res.exit_code == 0
        assert roam_calls == []
        assert execs and execs[0][0] == "claude"

    def test_wires_when_repo_is_indexed_but_unwired(self, runner, roam_calls, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_on_path", lambda name: True)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        execs = []
        monkeypatch.setattr(mod.os, "execvp", lambda f, argv: execs.append((f, argv)))
        res = runner.invoke(mod.cli, ["claude"])
        assert res.exit_code == 0
        assert ["hooks", "claude", "--write"] in roam_calls
        assert execs and execs[0][0] == "claude"


class TestDoctor:
    def test_doctor_reports_present_verify_report_age(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_on_path", lambda name: True)
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
        monkeypatch.setattr(mod, "_on_path", lambda name: True)
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        res = runner.invoke(mod.cli, ["doctor"])
        assert "verify report: none — run `compile report`" in res.output

    def test_doctor_reports_unwired_state(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_on_path", lambda name: True)
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        res = runner.invoke(mod.cli, ["doctor"])
        assert "absent" in res.output and "not wired" in res.output
        assert "install ok" in res.output

    def test_doctor_fails_without_toolchain(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_on_path", lambda name: False)
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        res = runner.invoke(mod.cli, ["doctor"])
        assert res.exit_code == 2
        assert "toolchain missing" in res.output

    def test_doctor_sees_project_wiring(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_on_path", lambda name: True)
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".claude" / "settings.json").write_text('{"hooks": "roam-compile-ups.py"}')
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_text("")
        res = runner.invoke(mod.cli, ["doctor"])
        assert "wired (project)" in res.output
        assert "VERDICT: ready" in res.output
        assert res.exit_code == 0

    def test_doctor_sees_user_global_wiring(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_on_path", lambda name: True)
        home = tmp_path / "home"
        (home / ".claude").mkdir(parents=True)
        (home / ".claude" / "settings.json").write_text('{"hooks": "roam-compile-ups.py"}')
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
    def test_claude_launch_warns_on_wire_failure_but_continues(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_text("")
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        (tmp_path / ".claude").mkdir()
        monkeypatch.setattr(mod, "_on_path", lambda name: True)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")

        class _Fail:
            returncode = 1

        monkeypatch.setattr(mod, "_roam", lambda *a, timeout=600: _Fail())
        execs = []
        monkeypatch.setattr(mod.os, "execvp", lambda f, argv: execs.append((f, argv)))
        res = runner.invoke(mod.cli, ["claude"])
        assert "wiring failed (continuing without hooks" in res.output
        assert execs and execs[0][0] == "claude"
        assert res.exit_code == 0


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

    def _capture(self, output, rc):
        """Stub _roam_capture to return a CompletedProcess-shaped object."""
        captured = {}

        class _P:
            def __init__(self, args):
                captured["args"] = list(args)

            returncode = rc
            stdout = output

        def fake(*args, timeout=600):
            return _P(args)

        return fake, captured

    def test_failing_files_dedupes_in_order(self):
        assert mod._failing_files(self.FAIL_OUTPUT) == ["src/bad.py"]

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

    def test_verify_failure_emits_block_and_exit_5(self, runner, monkeypatch):
        fake, captured = self._capture(self.FAIL_OUTPUT, 5)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        monkeypatch.setattr(mod, "_changed_files", lambda: ["src/bad.py"])
        res = runner.invoke(mod.cli, ["verify"])
        assert res.exit_code == 5
        # roam's raw output is preserved...
        assert "FAIL: src/bad.py:12" in res.output
        # ...and the explained block carries all four components.
        assert "VERDICT: verify failed." in res.output
        assert "command : compile verify src/bad.py" in res.output
        assert "files   : src/bad.py" in res.output
        assert "cause   : naming violation + syntax error" in res.output
        assert "next    : compile verify src/bad.py" in res.output
        # delegated to roam verify with the resolved files + default threshold.
        assert captured["args"] == ["verify", "--threshold", "70", "src/bad.py"]

    def test_verify_pass_streams_roam_output_without_block(self, runner, monkeypatch):
        fake, _ = self._capture("VERDICT: PASS (score 100/100) -- no issues\n", 0)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        res = runner.invoke(mod.cli, ["verify", "src/cli.py"])
        assert res.exit_code == 0
        assert "VERDICT: PASS" in res.output
        assert "verify failed" not in res.output

    def test_verify_threshold_passes_through_and_shows_in_command(self, runner, monkeypatch):
        fake, captured = self._capture(self.FAIL_OUTPUT, 5)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        res = runner.invoke(mod.cli, ["verify", "--threshold", "90", "src/bad.py"])
        assert res.exit_code == 5
        assert captured["args"] == ["verify", "--threshold", "90", "src/bad.py"]
        assert "command : compile verify --threshold 90 src/bad.py" in res.output

    def test_verify_new_only_and_diff_only_pass_through(self, runner, monkeypatch):
        fake, captured = self._capture(self.FAIL_OUTPUT, 5)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        res = runner.invoke(mod.cli, ["verify", "--new-only", "--diff-only", "src/bad.py"])
        assert res.exit_code == 5
        assert captured["args"] == ["verify", "--new-only", "--diff-only", "--threshold", "70", "src/bad.py"]
        assert "command : compile verify --new-only --diff-only src/bad.py" in res.output
        assert "next    : compile verify --new-only --diff-only src/bad.py" in res.output

    def test_verify_no_changed_files_delegates_changed_flag(self, runner, monkeypatch):
        fake, captured = self._capture("VERDICT: PASS (score 100/100) -- no changed files\n", 0)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        monkeypatch.setattr(mod, "_changed_files", lambda: [])
        res = runner.invoke(mod.cli, ["verify"])
        assert res.exit_code == 0
        assert captured["args"] == ["verify", "--threshold", "70", "--changed"]


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
