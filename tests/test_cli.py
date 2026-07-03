"""compile-code CLI surface tests.

The CLI is a thin product driver over the roam-code toolchain; these tests
pin the surface contract (verbs exist, delegation arguments are correct,
doctor's state reporting) with the toolchain calls stubbed — no index or
subprocess work, so they run anywhere.
"""

from __future__ import annotations

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


class TestSurface:
    def _delegates(self, runner, roam_calls, argv, expected):
        """Invoke argv and assert the toolchain was called exactly once with
        expected. Returns the Click result for any extra assertions."""
        res = runner.invoke(mod.cli, argv)
        assert roam_calls == [expected]
        return res

    def test_help_lists_all_verbs(self, runner):
        res = runner.invoke(mod.cli, ["--help"])
        for verb in ("init", "wire", "unwire", "claude", "run", "stats", "doctor"):
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


class TestDoctor:
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

    def test_returns_0_when_already_indexed(self, monkeypatch, capsys):
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_delegate", lambda *a: pytest.fail("must not index"))
        assert mod._ensure_indexed_for_launch() == 0
        assert capsys.readouterr().out == ""

    def test_indexes_on_first_run_and_returns_0(self, monkeypatch, capsys):
        monkeypatch.setattr(mod, "_require_index", lambda: False)
        calls = []
        monkeypatch.setattr(mod, "_delegate", lambda *a: calls.append(a) or 0)
        assert mod._ensure_indexed_for_launch() == 0
        assert calls == [("init",)]
        assert "indexing repo (first run)" in capsys.readouterr().out

    def test_indexing_failure_yields_verdict_and_code(self, monkeypatch, capsys):
        monkeypatch.setattr(mod, "_require_index", lambda: False)
        monkeypatch.setattr(mod, "_delegate", lambda *a: 2)
        assert mod._ensure_indexed_for_launch() == 2
        assert "VERDICT: indexing failed" in capsys.readouterr().out


class TestFailurePathsLaunch:
    def test_claude_launch_warns_on_wire_failure_but_continues(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_text("")
        monkeypatch.setattr(mod, "_on_path", lambda name: True)

        class _Fail:
            returncode = 1

        monkeypatch.setattr(mod, "_roam", lambda *a, timeout=600: _Fail())
        execs = []
        monkeypatch.setattr(mod.os, "execvp", lambda f, argv: execs.append((f, argv)))
        res = runner.invoke(mod.cli, ["claude"])
        assert "wiring failed (continuing without hooks" in res.output
        assert execs and execs[0][0] == "claude"
        assert res.exit_code == 0
