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
from compile_code.cli import cli


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
    def test_help_lists_all_verbs(self, runner):
        res = runner.invoke(cli, ["--help"])
        for verb in ("init", "wire", "unwire", "claude", "run", "stats", "doctor"):
            assert verb in res.output

    def test_init_delegates(self, runner, roam_calls):
        res = runner.invoke(cli, ["init"])
        assert res.exit_code == 0
        assert roam_calls == [["init"]]

    def test_init_force_uses_index_force(self, runner, roam_calls):
        runner.invoke(cli, ["init", "--force"])
        assert roam_calls == [["index", "--force"]]

    def test_wire_claude_delegates_to_hooks(self, runner, roam_calls):
        res = runner.invoke(cli, ["wire", "claude"])
        assert res.exit_code == 0
        assert roam_calls == [["hooks", "claude", "--write"]]

    def test_wire_no_verify_and_user_flags_pass_through(self, runner, roam_calls):
        runner.invoke(cli, ["wire", "claude", "--no-verify", "--user"])
        assert roam_calls == [["hooks", "claude", "--write", "--no-verify", "--user"]]

    def test_unwire_claude(self, runner, roam_calls):
        runner.invoke(cli, ["unwire", "claude"])
        assert roam_calls == [["hooks", "claude", "--uninstall", "--write"]]

    def test_unwire_user_flag_passes_through(self, runner, roam_calls):
        runner.invoke(cli, ["unwire", "claude", "--user"])
        assert roam_calls == [["hooks", "claude", "--uninstall", "--write", "--user"]]

    def test_run_compiles_with_auto_artifact(self, runner, roam_calls):
        runner.invoke(cli, ["run", "who calls handleSave"])
        assert roam_calls == [["compile", "who calls handleSave", "--artifact", "auto"]]

    def test_run_json_prepends_global_flag(self, runner, roam_calls):
        runner.invoke(cli, ["run", "task", "--json"])
        assert roam_calls == [["--json", "compile", "task", "--artifact", "auto"]]

    def test_stats_delegates(self, runner, roam_calls):
        runner.invoke(cli, ["stats"])
        assert roam_calls == [["compile-stats"]]


class TestClaudeLaunch:
    def test_missing_claude_binary_exits_1(self, runner, roam_calls, monkeypatch):
        monkeypatch.setattr(mod.shutil, "which", lambda name: None)
        res = runner.invoke(cli, ["claude"])
        assert res.exit_code == 1
        assert "not found on PATH" in res.output

    def test_indexes_wires_then_execs(self, runner, roam_calls, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)  # no index here
        monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/bin/claude")
        execs = []
        monkeypatch.setattr(mod.os, "execvp", lambda f, argv: execs.append((f, argv)))
        res = runner.invoke(cli, ["claude", "--", "-p", "hello"])
        assert res.exit_code == 0
        assert ["init"] in roam_calls
        assert ["hooks", "claude", "--write"] in roam_calls
        assert execs and execs[0][0] == "claude"


class TestDoctor:
    def test_doctor_reports_unwired_state(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/bin/roam")
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        res = runner.invoke(cli, ["doctor"])
        assert "absent" in res.output and "not wired" in res.output
        assert "install ok" in res.output

    def test_doctor_fails_without_toolchain(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod.shutil, "which", lambda name: None)
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        res = runner.invoke(cli, ["doctor"])
        assert res.exit_code == 2
        assert "toolchain missing" in res.output

    def test_doctor_sees_project_wiring(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/bin/roam")
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".claude" / "settings.json").write_text('{"hooks": "roam-compile-ups.py"}')
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_text("")
        res = runner.invoke(cli, ["doctor"])
        assert "wired (project)" in res.output
        assert "VERDICT: ready" in res.output
        assert res.exit_code == 0

    def test_doctor_sees_user_global_wiring(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/bin/roam")
        home = tmp_path / "home"
        (home / ".claude").mkdir(parents=True)
        (home / ".claude" / "settings.json").write_text('{"hooks": "roam-compile-ups.py"}')
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(home))
        res = runner.invoke(cli, ["doctor"])
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
        res = runner.invoke(cli, argv)
        assert res.exit_code == 2
        assert "VERDICT: toolchain missing" in res.output
        assert "Traceback" not in res.output

    def test_timeout_is_a_verdict_with_exit_124(self, runner, monkeypatch):
        monkeypatch.setattr(mod, "_roam", self._raise_timeout)
        res = runner.invoke(cli, ["run", "task"])
        assert res.exit_code == 124
        assert "timed out" in res.output

    def test_claude_launch_warns_on_wire_failure_but_continues(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_text("")
        monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/bin/claude")

        class _Fail:
            returncode = 1

        monkeypatch.setattr(mod, "_roam", lambda *a, timeout=600: _Fail())
        execs = []
        monkeypatch.setattr(mod.os, "execvp", lambda f, argv: execs.append((f, argv)))
        res = runner.invoke(cli, ["claude"])
        assert "wiring failed (continuing without hooks" in res.output
        assert execs and execs[0][0] == "claude"
        assert res.exit_code == 0
