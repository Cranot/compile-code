from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "classify_sessions.py"
SPEC = importlib.util.spec_from_file_location("compile_code_classify_sessions", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
classify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = classify
SPEC.loader.exec_module(classify)


def _user(content: object) -> dict[str, object]:
    return {"type": "user", "message": {"content": content}}


def _assistant(*blocks: dict[str, object]) -> dict[str, object]:
    return {"type": "assistant", "message": {"content": list(blocks)}}


def _bash(tool_id: str, command: str) -> dict[str, object]:
    return {"type": "tool_use", "name": "Bash", "id": tool_id, "input": {"command": command}}


def _read(tool_id: str, path: str) -> dict[str, object]:
    return {"type": "tool_use", "name": "Read", "id": tool_id, "input": {"file_path": path}}


def _result(tool_id: str, *, failed: bool = False) -> dict[str, object]:
    return {
        "type": "tool_result",
        "tool_use_id": tool_id,
        "is_error": failed,
        "content": "FAILED RESULT_CANARY" if failed else "ok",
    }


def _write_ledger(path: Path, rows: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _retry_rows() -> list[object]:
    prompt = "PROMPT_CANARY repair the payment flow"
    command = "pytest COMMAND_CANARY tests/private_test.py"
    target = "C:/private/PATH_CANARY/customer.py"
    return [
        _user(prompt),
        _user(prompt),
        _assistant(_bash("bash-1", command)),
        _user([_result("bash-1", failed=True)]),
        _assistant(_bash("bash-2", command)),
        _assistant(_read("read-1", target)),
        _assistant(_read("read-2", target)),
    ]


def _run_json(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, dict[str, object], str]:
    code = classify.main([*argv, "--json"])
    captured = capsys.readouterr()
    return code, json.loads(captured.out), captured.err


def test_no_implicit_home_or_environment_scan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys):
    hidden = tmp_path / ".claude" / "projects" / "SECRET_SESSION_ID.jsonl"
    _write_ledger(hidden, _retry_rows())
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("CLAUDE_PROFILE_DIR", str(tmp_path))

    code, report, stderr = _run_json(capsys)

    assert code == 2
    assert stderr == ""
    assert report["error"]["code"] == "explicit_source_required"
    assert report["summary"]["scanned_sessions"] == 0
    assert "SECRET_SESSION_ID" not in json.dumps(report)


def test_default_json_is_aggregate_only_and_preserves_pattern_statistics(tmp_path: Path, capsys):
    ledger_root = tmp_path / "ledgers"
    _write_ledger(ledger_root / "SECRET_SESSION_ALPHA.jsonl", _retry_rows())
    _write_ledger(ledger_root / "SECRET_SESSION_BETA.jsonl", _retry_rows())

    code, report, _ = _run_json(capsys, str(ledger_root))
    rendered = json.dumps(report)

    assert code == 0
    assert report["privacy"] == {
        "content_included": False,
        "mode": "aggregate_only",
        "session_identifiers_included": False,
        "source_paths_included": False,
    }
    assert report["summary"] == {
        "bucket_totals": {
            "repeated_prompt": 2,
            "repeated_tool_use": 2,
            "verify_fail_aftermath": 2,
        },
        "retry_like_sessions": 2,
        "scanned_sessions": 2,
    }
    assert report["pattern_statistics"]["bash"]["sessions_with_repeats"] == 2
    assert report["pattern_statistics"]["read"]["excess_repetitions"] == 2
    assert report["pattern_statistics"]["prompt"]["repeated_occurrences"] == 4
    assert report["cross_session_retry_clusters"] == {
        "cluster_count": 1,
        "largest_cluster": 2,
        "sessions_in_clusters": 2,
        "size_histogram": {"2": 1},
    }
    for secret in (
        "PROMPT_CANARY",
        "COMMAND_CANARY",
        "PATH_CANARY",
        "RESULT_CANARY",
        "SECRET_SESSION_ALPHA",
        "SECRET_SESSION_BETA",
        str(tmp_path),
    ):
        assert secret not in rendered
    assert "sensitive_content" not in report


def test_default_prose_never_prints_content_or_identifiers(tmp_path: Path, capsys):
    ledger = tmp_path / "SECRET_SESSION_PROSE.jsonl"
    _write_ledger(ledger, _retry_rows())

    assert classify.main([str(ledger)]) == 0
    rendered = capsys.readouterr().out

    assert "privacy mode: aggregate_only" in rendered
    assert "invalid_rows=0" in rendered
    for secret in ("PROMPT_CANARY", "COMMAND_CANARY", "PATH_CANARY", "SECRET_SESSION_PROSE", str(tmp_path)):
        assert secret not in rendered


def test_sensitive_samples_require_the_narrow_explicit_opt_in(tmp_path: Path, capsys):
    ledger = tmp_path / "SECRET_SESSION_OPT_IN.jsonl"
    _write_ledger(ledger, _retry_rows())

    code, report, _ = _run_json(capsys, str(ledger), "--include-sensitive-content")
    rendered = json.dumps(report)

    assert code == 0
    assert report["privacy"]["mode"] == "sensitive_content"
    assert report["privacy"]["content_included"] is True
    assert "sensitive_content" in report
    assert "SECRET_SESSION_OPT_IN" in rendered
    assert "PROMPT_CANARY" in rendered
    assert "COMMAND_CANARY" in rendered
    assert "PATH_CANARY" in rendered


def test_file_discovery_is_capped_and_discloses_truncation(tmp_path: Path, capsys):
    for index in range(5):
        _write_ledger(tmp_path / f"session-{index}.jsonl", [_user(f"prompt-{index}")])

    code, report, _ = _run_json(capsys, str(tmp_path), "--max-files", "2")
    discovery = report["scan"]["discovery"]

    assert code == 0
    assert report["summary"]["scanned_sessions"] == 2
    assert discovery["ledgers_discovered"] == 2
    assert discovery["file_limit_reached"] is True
    assert report["scan"]["truncation"]["occurred"] is True


def test_capped_discovery_is_deterministic_across_scandir_order(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for name in ("charlie.jsonl", "alpha.jsonl", "bravo.jsonl"):
        _write_ledger(tmp_path / name, [_user(name)])
    real_scandir = os.scandir
    reverse = False

    class ReorderedScandir:
        def __init__(self, path: os.PathLike[str] | str) -> None:
            with real_scandir(path) as entries:
                self.entries = list(entries)

        def __enter__(self):
            return iter(sorted(self.entries, key=lambda entry: entry.name, reverse=reverse))

        def __exit__(self, exc_type, exc, traceback):
            return False

    monkeypatch.setattr(classify.os, "scandir", ReorderedScandir)
    limits = classify.ScanLimits(max_files=2)
    first_disclosure = classify.ScanDisclosure()
    first = classify._discover_session_ledgers([tmp_path], limits, first_disclosure)

    reverse = True
    second_disclosure = classify.ScanDisclosure()
    second = classify._discover_session_ledgers([tmp_path], limits, second_disclosure)

    assert [candidate.path.name for candidate in first] == ["alpha.jsonl", "bravo.jsonl"]
    assert [candidate.path.name for candidate in second] == ["alpha.jsonl", "bravo.jsonl"]
    assert first_disclosure.file_limit_reached is True
    assert second_disclosure.file_limit_reached is True


def test_partial_directory_enumeration_is_excluded_and_counted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _write_ledger(tmp_path / "alpha.jsonl", [_user("alpha")])
    _write_ledger(tmp_path / "bravo.jsonl", [_user("bravo")])
    real_scandir = os.scandir
    with real_scandir(tmp_path) as iterator:
        first_entry = next(iterator)

    class FailingScandir:
        yielded = False

        def __init__(self, path: os.PathLike[str] | str) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def __iter__(self):
            return self

        def __next__(self):
            if not self.yielded:
                self.yielded = True
                return first_entry
            raise OSError("enumeration failed")

    monkeypatch.setattr(classify.os, "scandir", FailingScandir)
    disclosure = classify.ScanDisclosure()

    candidates = classify._discover_session_ledgers([tmp_path], classify.ScanLimits(), disclosure)

    assert candidates == []
    assert disclosure.discovery_entries_seen == 1
    assert disclosure.discovery_errors == 1
    assert disclosure.ledgers_discovered == 0


def test_discovery_entry_budget_is_hard_and_disclosed(tmp_path: Path, capsys):
    for index in range(4):
        (tmp_path / f"ordinary-{index}.txt").write_text("not a ledger", encoding="utf-8")

    code, report, _ = _run_json(capsys, str(tmp_path), "--max-discovery-entries", "1")

    assert code == 1
    assert report["scan"]["discovery"]["entries_seen"] == 1
    assert report["scan"]["discovery"]["limit_reached"] is True
    assert report["scan"]["truncation"]["occurred"] is True


def test_invalid_and_oversized_rows_have_content_free_disclosure(tmp_path: Path, capsys):
    ledger = tmp_path / "invalid.jsonl"
    oversized = json.dumps(_user("OVERSIZED_CANARY_" + "x" * 300))
    ledger.write_bytes(("{bad json}\n" + oversized + "\n" + json.dumps(_user("valid")) + "\n").encode())

    code, report, _ = _run_json(capsys, str(ledger), "--max-line-bytes", "128")
    rows = report["scan"]["rows"]

    assert code == 0
    assert rows["invalid_json"] == 1
    assert rows["oversized"] == 1
    assert rows["invalid_total"] == 2
    assert rows["parsed"] == 1
    assert "OVERSIZED_CANARY" not in json.dumps(report)


def test_duplicate_json_keys_are_rejected_at_every_object_depth(tmp_path: Path, capsys):
    ledger = tmp_path / "duplicate-keys.jsonl"
    duplicate = '{"type":"user","message":{"content":"DUPLICATE_CANARY","content":"DUPLICATE_CANARY"}}\n'
    ledger.write_text(duplicate + json.dumps(_user("valid")) + "\n", encoding="utf-8")

    code, report, _ = _run_json(capsys, str(ledger), "--include-sensitive-content")

    assert code == 0
    assert report["scan"]["rows"]["invalid_json"] == 1
    assert report["scan"]["rows"]["parsed"] == 1
    assert report["scan"]["rows"]["typed"] == 1
    assert "DUPLICATE_CANARY" not in json.dumps(report)


def test_file_byte_and_row_budgets_are_disclosed(tmp_path: Path, capsys):
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    _write_ledger(first, [_user("a" * 80), _user("b" * 80), _user("c" * 80)])
    _write_ledger(second, [_user("second")])

    code, report, _ = _run_json(
        capsys,
        str(tmp_path),
        "--max-total-bytes",
        "140",
        "--max-file-bytes",
        "140",
        "--max-line-bytes",
        "120",
        "--max-lines-per-file",
        "1",
    )
    scan = report["scan"]

    assert code == 0
    assert scan["bytes_read"] <= 140
    assert scan["rows"]["row_limit_files"] >= 1
    assert scan["files"]["truncated"] >= 1
    assert scan["truncation"]["occurred"] is True


def test_global_byte_budget_stops_later_files_and_discloses_partial_row(tmp_path: Path, capsys):
    _write_ledger(tmp_path / "first.jsonl", [_user("a" * 100)])
    _write_ledger(tmp_path / "second.jsonl", [_user("b" * 100)])

    code, report, _ = _run_json(
        capsys,
        str(tmp_path),
        "--max-total-bytes",
        "64",
        "--max-file-bytes",
        "256",
        "--max-line-bytes",
        "256",
    )
    scan = report["scan"]

    assert code == 0
    assert scan["bytes_read"] == 64
    assert scan["truncation"]["total_byte_limit_reached"] is True
    assert scan["files"]["skipped_total_budget"] == 1
    assert scan["rows"]["truncated"] == 1


def test_symlinked_ledger_is_rejected_without_reading_target(tmp_path: Path, capsys):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "OUTSIDE_SESSION_ID.jsonl"
    _write_ledger(outside, _retry_rows())
    link = root / "linked.jsonl"
    try:
        link.symlink_to(outside)
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation is unavailable")

    code, report, _ = _run_json(capsys, str(root))

    assert code == 1
    assert report["summary"]["scanned_sessions"] == 0
    assert report["scan"]["files"]["rejected_symlink"] >= 1
    assert "OUTSIDE_SESSION_ID" not in json.dumps(report)
    assert "PROMPT_CANARY" not in json.dumps(report)


def test_hardlinked_ledger_is_rejected(tmp_path: Path, capsys):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.jsonl"
    _write_ledger(outside, _retry_rows())
    linked = root / "linked.jsonl"
    try:
        os.link(outside, linked)
    except OSError:
        pytest.skip("hard-link creation is unavailable")

    code, report, _ = _run_json(capsys, str(root))

    assert code == 1
    assert report["summary"]["scanned_sessions"] == 0
    assert report["scan"]["files"]["rejected_hardlink"] == 1


def test_post_discovery_symlink_swap_is_rejected(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    ledger = root / "session.jsonl"
    outside = tmp_path / "outside.jsonl"
    _write_ledger(ledger, [_user("inside")])
    _write_ledger(outside, [_user("OUTSIDE_CANARY")])
    limits = classify.ScanLimits(max_files=2)
    disclosure = classify.ScanDisclosure()
    candidates = classify._discover_session_ledgers([root], limits, disclosure)
    assert len(candidates) == 1
    ledger.unlink()
    try:
        ledger.symlink_to(outside)
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation is unavailable")

    analysis = classify._classify_candidate(
        candidates[0],
        limits,
        classify.ReadBudget(limits.max_total_bytes),
        disclosure,
        b"test-key",
        False,
    )

    assert analysis is None
    assert disclosure.files_rejected_symlink >= 1
    assert disclosure.files_scanned == 0


def test_post_discovery_regular_file_swap_is_rejected(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    ledger = root / "session.jsonl"
    _write_ledger(ledger, [_user("inside")])
    limits = classify.ScanLimits(max_files=2)
    disclosure = classify.ScanDisclosure()
    candidates = classify._discover_session_ledgers([root], limits, disclosure)
    assert len(candidates) == 1
    ledger.unlink()
    _write_ledger(ledger, [_user("REPLACEMENT_CANARY")])

    analysis = classify._classify_candidate(
        candidates[0],
        limits,
        classify.ReadBudget(limits.max_total_bytes),
        disclosure,
        b"test-key",
        False,
    )

    assert analysis is None
    assert disclosure.files_rejected_race == 1
    assert disclosure.files_scanned == 0


def test_malformed_typed_rows_are_counted_without_aborting(tmp_path: Path, capsys):
    ledger = tmp_path / "shape.jsonl"
    _write_ledger(ledger, [["not", "an", "object"], {"type": "user", "message": None}, _user("valid")])

    code, report, _ = _run_json(capsys, str(ledger))

    assert code == 0
    assert report["scan"]["rows"]["invalid_shape"] == 2
    assert report["scan"]["rows"]["typed"] == 1
    assert report["scan"]["rows"]["invalid_total"] == 2


def test_invalid_utf8_and_deep_json_are_bounded_invalid_rows(tmp_path: Path, capsys):
    ledger = tmp_path / "adversarial.jsonl"
    deep_json = ("[" * 50_000 + "0" + "]" * 50_000 + "\n").encode()
    ledger.write_bytes(b'{"text":"\xff"}\n' + deep_json + (json.dumps(_user("valid")) + "\n").encode())

    code, report, _ = _run_json(capsys, str(ledger), "--max-line-bytes", "131072")
    rows = report["scan"]["rows"]

    assert code == 0
    assert rows["invalid_encoding"] == 1
    assert rows["invalid_json"] == 1
    assert rows["typed"] == 1
    assert rows["invalid_total"] == 2


def test_oversized_integer_json_is_a_bounded_invalid_row(tmp_path: Path, capsys):
    ledger = tmp_path / "oversized-integer.jsonl"
    oversized_integer = b'{"type":"user","message":{"content":' + (b"9" * 5_000) + b"}}\n"
    ledger.write_bytes(oversized_integer + (json.dumps(_user("valid")) + "\n").encode())

    code, report, _ = _run_json(capsys, str(ledger))
    rows = report["scan"]["rows"]

    assert code == 0
    assert rows["invalid_json"] == 1
    assert rows["typed"] == 1
    assert rows["invalid_total"] == 1


def test_early_eof_against_opening_size_is_disclosed_as_truncated():
    class RecordingStream(io.BytesIO):
        def __init__(self, value: bytes) -> None:
            super().__init__(value)
            self.readline_limits: list[int] = []

        def readline(self, size: int = -1, /) -> bytes:
            self.readline_limits.append(size)
            return super().readline(size)

    stream = RecordingStream(b"{}\n")
    limits = classify.ScanLimits(max_total_bytes=100, max_file_bytes=100, max_line_bytes=16)
    budget = classify.ReadBudget(100)
    disclosure = classify.ScanDisclosure()

    rows = list(classify._bounded_lines(stream, 100, limits, budget, disclosure))

    assert rows == [b"{}\n"]
    assert disclosure.bytes_read == 3
    assert disclosure.files_truncated == 1
    assert disclosure.public(limits)["truncation"]["occurred"] is True
    assert stream.readline_limits
    assert all(0 < read_limit <= limits.max_line_bytes + 1 for read_limit in stream.readline_limits)


def test_file_change_during_read_is_disclosed_without_reading_appended_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    ledger = tmp_path / "changing.jsonl"
    _write_ledger(ledger, [_user("original")])
    opening_size = ledger.stat().st_size
    limits = classify.ScanLimits(max_files=2)
    disclosure = classify.ScanDisclosure()
    candidates = classify._discover_session_ledgers([ledger], limits, disclosure)
    original_bounded_lines = classify._bounded_lines
    changed = False

    def changing_lines(stream, expected_size, scan_limits, budget, scan_disclosure):
        nonlocal changed
        for raw in original_bounded_lines(stream, expected_size, scan_limits, budget, scan_disclosure):
            yield raw
            if not changed:
                with ledger.open("ab") as target:
                    target.write((json.dumps(_user("appended")) + "\n").encode())
                changed = True

    monkeypatch.setattr(classify, "_bounded_lines", changing_lines)

    analysis = classify._classify_candidate(
        candidates[0],
        limits,
        classify.ReadBudget(limits.max_total_bytes),
        disclosure,
        b"test-key",
        False,
    )
    public = disclosure.public(limits)

    assert analysis is None
    assert changed is True
    assert disclosure.bytes_read == opening_size
    assert disclosure.files_changed_during_read == 1
    assert disclosure.files_truncated == 1
    assert disclosure.files_scanned == 0
    assert disclosure.rows_parsed == 0
    assert public["files"]["changed_during_read"] == 1
    assert public["truncation"]["occurred"] is True


def test_path_replacement_during_read_is_disclosed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    ledger = tmp_path / "replace-me.jsonl"
    replacement = tmp_path / "replacement.jsonl"
    _write_ledger(ledger, [_user("original")])
    _write_ledger(replacement, [_user("replacement")])
    limits = classify.ScanLimits(max_files=2)
    disclosure = classify.ScanDisclosure()
    candidates = classify._discover_session_ledgers([ledger], limits, disclosure)
    original_bounded_lines = classify._bounded_lines
    replaced = False

    def replacing_lines(stream, expected_size, scan_limits, budget, scan_disclosure):
        nonlocal replaced
        for raw in original_bounded_lines(stream, expected_size, scan_limits, budget, scan_disclosure):
            yield raw
            if not replaced:
                try:
                    os.replace(replacement, ledger)
                except OSError:
                    pytest.skip("the platform does not permit replacing an open file")
                replaced = True

    monkeypatch.setattr(classify, "_bounded_lines", replacing_lines)

    analysis = classify._classify_candidate(
        candidates[0],
        limits,
        classify.ReadBudget(limits.max_total_bytes),
        disclosure,
        b"test-key",
        False,
    )

    assert analysis is None
    assert replaced is True
    assert disclosure.files_changed_during_read == 1
    assert disclosure.files_truncated == 1
    assert disclosure.files_scanned == 0
    assert disclosure.rows_parsed == 0
    assert disclosure.public(limits)["truncation"]["occurred"] is True


def test_post_read_state_rejects_a_different_path_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    ledger = tmp_path / "opened.jsonl"
    replacement = tmp_path / "different.jsonl"
    _write_ledger(ledger, [_user("opened")])
    _write_ledger(replacement, [_user("different")])
    limits = classify.ScanLimits(max_files=2)
    disclosure = classify.ScanDisclosure()
    candidate = classify._discover_session_ledgers([ledger], limits, disclosure)[0]
    opened = classify._secure_open_candidate(candidate, disclosure)
    assert opened is not None
    stream, opened_state = opened
    replacement_state = replacement.lstat()
    path_type = type(ledger)
    original_lstat = path_type.lstat

    def replacement_lstat(path):
        if path == ledger:
            return replacement_state
        return original_lstat(path)

    with stream:
        monkeypatch.setattr(path_type, "lstat", replacement_lstat)
        assert classify._read_state_is_stable(candidate, stream, opened_state) is False


def test_file_shrink_during_read_is_disclosed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    ledger = tmp_path / "shrink-me.jsonl"
    _write_ledger(ledger, [_user("first"), _user("second")])
    opening_size = ledger.stat().st_size
    limits = classify.ScanLimits(max_files=2)
    disclosure = classify.ScanDisclosure()
    candidates = classify._discover_session_ledgers([ledger], limits, disclosure)
    original_bounded_lines = classify._bounded_lines
    shrunk = False

    def shrinking_lines(stream, expected_size, scan_limits, budget, scan_disclosure):
        nonlocal shrunk
        for raw in original_bounded_lines(stream, expected_size, scan_limits, budget, scan_disclosure):
            yield raw
            if not shrunk:
                try:
                    os.truncate(ledger, 0)
                except OSError:
                    pytest.skip("the platform does not permit shrinking an open file")
                shrunk = True

    monkeypatch.setattr(classify, "_bounded_lines", shrinking_lines)

    analysis = classify._classify_candidate(
        candidates[0],
        limits,
        classify.ReadBudget(limits.max_total_bytes),
        disclosure,
        b"test-key",
        False,
    )

    assert analysis is None
    assert shrunk is True
    assert ledger.stat().st_size < opening_size
    assert disclosure.files_changed_during_read == 1
    assert disclosure.files_truncated == 1
    assert disclosure.files_scanned == 0
    assert disclosure.rows_parsed == 0
    assert disclosure.public(limits)["truncation"]["occurred"] is True


def test_source_contains_no_implicit_profile_scan_or_unbounded_recursive_glob():
    source = SCRIPT.read_text(encoding="utf-8")

    assert "Path.home(" not in source
    assert "CLAUDE_PROFILE_DIR" not in source
    assert ".rglob(" not in source
    assert "capture_output=True" not in source


@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--max-files", "0"),
        ("--max-files", str(classify.HARD_MAX_FILES + 1)),
        ("--max-total-bytes", "0"),
        ("--top", str(classify.HARD_MAX_TOP + 1)),
    ],
)
def test_cli_rejects_unbounded_or_out_of_range_limits(flag: str, value: str):
    with pytest.raises(SystemExit) as error:
        classify.main(["somewhere", flag, value])
    assert error.value.code == 2
