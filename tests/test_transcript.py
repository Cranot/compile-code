"""Mechanical transcript artifact tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

from click.testing import CliRunner

import compile_code.cli as cli_mod
import compile_code.transcript as transcript_mod


def _write_jsonl(path: Path, events: list[object]) -> list[str]:
    lines = [json.dumps(event, ensure_ascii=False, separators=(",", ":")) for event in events]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return lines


def _user(text: str) -> dict[str, object]:
    return {"type": "user", "message": {"role": "user", "content": text}}


def _assistant(*blocks: dict[str, object]) -> dict[str, object]:
    return {"type": "assistant", "message": {"role": "assistant", "content": list(blocks)}}


def _tool_result(text: str, *, is_error: bool = False) -> dict[str, object]:
    return {
        "type": "user",
        "message": {
            "role": "user",
            "content": [{"type": "tool_result", "content": text, "is_error": is_error}],
        },
    }


def _rich_fixture(path: Path) -> list[str]:
    return _write_jsonl(
        path,
        [
            _user("Repair src/app.py without changing its interface."),
            _assistant(
                {"type": "tool_use", "name": "Edit", "input": {"file_path": "src/app.py"}},
                {"type": "tool_use", "name": "Read", "input": {"file_path": "src/config.py"}},
            ),
            _assistant(
                {
                    "type": "tool_use",
                    "name": "Bash",
                    "input": {"command": "python -m pytest tests/test_app.py"},
                }
            ),
            _tool_result("3 passed in 0.12s"),
            _assistant({"type": "text", "text": "Updated src/app.py and preserved the interface."}),
        ],
    )


def test_results_note_has_every_section_and_verbatim_quotes(tmp_path: Path) -> None:
    source = tmp_path / "session.jsonl"
    lines = _rich_fixture(source)

    result = CliRunner().invoke(cli_mod.cli, ["transcript", str(source)])

    assert result.exit_code == 0
    for heading in (
        "## Ask",
        "## Activity summary",
        "## Files edited",
        "## Files read",
        "## Commands run",
        "## Test signals",
        "## Outcome",
    ):
        assert heading in result.output
    for quote in (
        "Repair src/app.py without changing its interface.",
        "src/app.py",
        "src/config.py",
        "python -m pytest tests/test_app.py",
        "3 passed in 0.12s",
        "Updated src/app.py and preserved the interface.",
    ):
        assert f"> {quote}" in result.output
        assert any(quote in line for line in lines)
    assert "Edit" in result.output
    assert "Bash" in result.output


def test_handoff_uses_last_error_and_last_test_signal(tmp_path: Path) -> None:
    source = tmp_path / "session.jsonl"
    _write_jsonl(
        source,
        [
            _user("Inspect the failing check."),
            _tool_result("first failure", is_error=True),
            _tool_result("1 failed in 0.10s"),
            _tool_result("last failure", is_error=True),
            _tool_result("Tests: 2 passed, 2 total"),
            _user("Preserve exact evidence."),
            _assistant({"type": "text", "text": "Recorded the observed state."}),
        ],
    )

    result = CliRunner().invoke(cli_mod.cli, ["transcript", str(source), "--artifact", "handoff-brief"])

    assert result.exit_code == 0
    assert "## User asks" in result.output
    assert "## State" in result.output
    assert result.output.index("> Inspect the failing check.") < result.output.index("> Preserve exact evidence.")
    assert "> last failure" in result.output
    assert "> first failure" not in result.output
    assert "> Tests: 2 passed, 2 total" in result.output
    assert "> 1 failed in 0.10s" not in result.output
    assert "> Recorded the observed state." in result.output


def test_handoff_states_missing_errors_and_tests(tmp_path: Path) -> None:
    source = tmp_path / "session.jsonl"
    _write_jsonl(source, [_user("Summarize the session."), _assistant({"type": "text", "text": "Done."})])

    result = CliRunner().invoke(cli_mod.cli, ["transcript", str(source), "--artifact", "handoff-brief"])

    assert result.exit_code == 0
    assert "Last error: not found in transcript" in result.output
    assert "Last test signal: not found in transcript" in result.output


def test_evidence_is_conservative_deterministic_and_hash_bound(tmp_path: Path) -> None:
    source = tmp_path / "session.jsonl"
    lines = _rich_fixture(source)
    runner = CliRunner()

    first = runner.invoke(cli_mod.cli, ["transcript", str(source), "--artifact", "evidence"])
    second = runner.invoke(cli_mod.cli, ["transcript", str(source), "--artifact", "evidence"])

    assert first.exit_code == 0
    assert second.exit_code == 0
    assert first.output_bytes == second.output_bytes
    evidence = json.loads(first.output)
    assert evidence["schema_version"] == transcript_mod.EVIDENCE_SCHEMA_VERSION
    assert evidence["source"]["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert evidence["source"]["total_lines"] == len(lines)
    coverage = evidence["coverage"]
    assert coverage["parsed_events"] + coverage["skipped_unparseable"] + coverage["skipped_oversized"] + coverage[
        "unknown_type_events"
    ] == len(lines)
    for fact in evidence["facts"]:
        assert fact["quote"] in lines[fact["line"] - 1]
    signal = next(fact for fact in evidence["facts"] if fact["kind"] == "test_signal")
    assert signal["value"]["counts"] == {"passed": 3}


def test_tolerant_reader_discloses_unknown_malformed_and_oversized_lines(tmp_path: Path) -> None:
    source = tmp_path / "session.jsonl"
    valid = json.dumps(_user("Keep reading after skipped lines."), separators=(",", ":"))
    unknown = json.dumps({"type": "progress", "detail": "synthetic"}, separators=(",", ":"))
    oversized = json.dumps({"type": "progress", "padding": "x" * transcript_mod.MAX_LINE_BYTES})
    source.write_text(f"{unknown}\n{{malformed\n{oversized}\n{valid}\n", encoding="utf-8")

    result = CliRunner().invoke(cli_mod.cli, ["transcript", str(source), "--artifact", "evidence"])

    assert result.exit_code == 0
    coverage = json.loads(result.output)["coverage"]
    assert coverage["parsed_events"] == 1
    assert coverage["skipped_unparseable"] == 1
    assert coverage["skipped_oversized"] == 1
    assert coverage["unknown_type_events"] == 1
    assert sum(coverage[key] for key in transcript_mod.CONSERVATION_FIELDS) == 4


def test_output_file_is_written_atomically(tmp_path: Path) -> None:
    source = tmp_path / "session.jsonl"
    target = tmp_path / "result.md"
    _write_jsonl(source, [_user("Write the result."), _assistant({"type": "text", "text": "Complete."})])

    result = CliRunner().invoke(cli_mod.cli, ["transcript", str(source), "--out", str(target)])

    assert result.exit_code == 0
    assert result.output == ""
    assert target.read_text(encoding="utf-8").startswith("# Transcript Results Note\n")
    target.write_text("stale artifact\n", encoding="utf-8")
    replaced = CliRunner().invoke(cli_mod.cli, ["transcript", str(source), "--out", str(target)])
    assert replaced.exit_code == 0
    assert target.read_text(encoding="utf-8").startswith("# Transcript Results Note\n")


def test_quote_truncation_keeps_a_verbatim_prefix(tmp_path: Path) -> None:
    source = tmp_path / "session.jsonl"
    ask = "x" * (transcript_mod.MAX_QUOTE_CHARS + 23)
    lines = _write_jsonl(source, [_user(ask)])

    result = CliRunner().invoke(cli_mod.cli, ["transcript", str(source), "--artifact", "evidence"])

    assert result.exit_code == 0
    fact = next(item for item in json.loads(result.output)["facts"] if item["kind"] == "user_ask")
    assert fact["quote"] == ask[: transcript_mod.MAX_QUOTE_CHARS]
    assert lines[0].startswith('{"type":"user"')
    assert fact["quote"] in lines[0]
    assert fact["quote_truncated"] is True
    assert fact["quote_full_length"] == len(ask)
    markdown = CliRunner().invoke(cli_mod.cli, ["transcript", str(source)])
    assert markdown.exit_code == 0
    assert "[truncated] Full quote length:" in markdown.output


def test_emit_path_refuses_a_corrupted_extractor_quote(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "session.jsonl"
    _write_jsonl(source, [_user("Keep evidence exact.")])
    extracted = transcript_mod.extract_transcript(source, parse_json=cli_mod._strict_json_document)
    corrupted = replace(extracted, facts=[replace(extracted.facts[0], quote="corrupted quotation")])
    monkeypatch.setattr(transcript_mod, "extract_transcript", lambda *_args, **_kwargs: corrupted)

    result = CliRunner().invoke(cli_mod.cli, ["transcript", str(source), "--artifact", "evidence"])

    assert result.exit_code == 1
    assert result.output.startswith("VERDICT: transcript refused: internal extraction defect")
    assert "Traceback" not in result.output


def test_help_discloses_verbatim_sensitive_content_contract() -> None:
    result = CliRunner().invoke(cli_mod.cli, ["transcript", "--help"])

    assert result.exit_code == 0
    assert "quote the transcript verbatim" in result.output
    assert "Sensitive input produces sensitive output" in result.output
    assert "redaction is not performed" in result.output


def test_command_inventory_contains_transcript() -> None:
    result = CliRunner().invoke(cli_mod.cli, ["commands"])

    assert result.exit_code == 0
    assert any(line.startswith("transcript — ") for line in result.output.splitlines())


def test_missing_file_is_a_verdict(tmp_path: Path) -> None:
    _assert_refusal(tmp_path / "missing.jsonl")


def test_directory_is_a_verdict(tmp_path: Path) -> None:
    _assert_refusal(tmp_path)


def test_empty_file_is_a_verdict(tmp_path: Path) -> None:
    source = tmp_path / "empty.jsonl"
    source.write_bytes(b"")
    _assert_refusal(source)


def test_non_utf8_file_is_a_verdict(tmp_path: Path) -> None:
    source = tmp_path / "binary.jsonl"
    source.write_bytes(b"\xff\n")
    _assert_refusal(source)


def test_all_lines_unparseable_is_a_verdict(tmp_path: Path) -> None:
    source = tmp_path / "malformed.jsonl"
    source.write_text("{bad\n[]\n", encoding="utf-8")
    _assert_refusal(source)


def test_over_total_cap_is_a_verdict(tmp_path: Path) -> None:
    source = tmp_path / "large.jsonl"
    source.write_bytes(b" " * (transcript_mod.MAX_TRANSCRIPT_BYTES + 1))
    _assert_refusal(source)


def _assert_refusal(path: Path) -> None:
    result = CliRunner().invoke(cli_mod.cli, ["transcript", str(path)])
    assert result.exit_code == 1
    assert result.output.startswith("VERDICT:")
    assert len(result.output.splitlines()) == 1
    assert "Traceback" not in result.output
