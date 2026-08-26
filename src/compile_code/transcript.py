"""Mechanical extraction and rendering for Claude Code JSONL transcripts.

Coverage is conservative: every physical input line belongs to exactly one of
``parsed_events``, ``skipped_unparseable``, ``skipped_oversized``, or
``unknown_type_events``. Their sum therefore equals ``source.total_lines``.
"""

from __future__ import annotations

import codecs
import hashlib
import json
import os
import re
import stat
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

EVIDENCE_SCHEMA_VERSION = "compile-code.transcript.evidence.v1"
MAX_TRANSCRIPT_BYTES = 16 * 1024 * 1024
MAX_LINE_BYTES = 256 * 1024
MAX_QUOTE_CHARS = 2_000
MAX_LIST_ITEMS = 100
MAX_FACTS = 2_000
MAX_RENDER_BYTES = 16 * 1024 * 1024
CONSERVATION_FIELDS = (
    "parsed_events",
    "skipped_unparseable",
    "skipped_oversized",
    "unknown_type_events",
)

_KNOWN_EVENT_TYPES = frozenset({"user", "assistant"})
_EDIT_TOOL_NAMES = frozenset({"edit", "editfile", "multiedit", "write", "writefile", "applypatch"})
_READ_TOOL_NAMES = frozenset({"read", "readfile"})
_SHELL_TOOL_NAMES = frozenset({"bash", "bashcommand", "shell", "shellcommand"})
_PYTEST_COUNT = re.compile(r"(?<!\w)(\d+)\s+(passed|failed|errors?)\b", re.IGNORECASE)
_TESTS_SUMMARY = re.compile(r"^\s*Tests:\s+", re.IGNORECASE)
_TESTS_COUNT = re.compile(r"(?<!\w)(\d+)\s+(passed|failed|errors?|skipped|todo|total)\b", re.IGNORECASE)

ParseJSON = Callable[..., object]


class TranscriptError(ValueError):
    """A typed, user-facing transcript refusal."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Fact:
    """One bounded fact and the exact source-line quote supporting it."""

    kind: str
    value: object
    quote: str
    line: int
    quote_truncated: bool = False
    quote_full_length: int | None = None

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "kind": self.kind,
            "value": self.value,
            "quote": self.quote,
            "line": self.line,
        }
        if self.quote_truncated:
            payload["quote_truncated"] = True
            payload["quote_full_length"] = self.quote_full_length
        return payload


@dataclass(frozen=True)
class Coverage:
    parsed_events: int = 0
    skipped_unparseable: int = 0
    skipped_oversized: int = 0
    unknown_type_events: int = 0

    def as_dict(self, *, facts_omitted: int) -> dict[str, int]:
        return {
            "parsed_events": self.parsed_events,
            "skipped_unparseable": self.skipped_unparseable,
            "skipped_oversized": self.skipped_oversized,
            "unknown_type_events": self.unknown_type_events,
            "facts_omitted": facts_omitted,
        }


@dataclass(frozen=True)
class TranscriptData:
    source_path: str
    sha256: str
    total_lines: int
    coverage: Coverage
    event_counts: dict[str, int]
    tool_counts: dict[str, int]
    tool_first: list[Fact]
    tool_names: list[str]
    total_tool_calls: int
    user_asks: list[Fact]
    total_user_asks: int
    files_edited: list[Fact]
    total_files_edited: int
    files_read: list[Fact]
    total_files_read: int
    commands: list[Fact]
    total_commands: int
    test_signals: list[Fact]
    total_test_signals: int
    last_test_signal: Fact | None
    last_error: Fact | None
    final_assistant_text: Fact | None
    facts: list[Fact]
    facts_omitted: int
    source_lines: dict[int, str] = field(repr=False)


@dataclass
class _Builder:
    source_path: str
    coverage_counts: Counter[str] = field(default_factory=Counter)
    event_counts: Counter[str] = field(default_factory=Counter)
    tool_counts: Counter[str] = field(default_factory=Counter)
    tool_first: list[Fact] = field(default_factory=list)
    tool_names: list[str] = field(default_factory=list)
    displayed_tool_names: set[str] = field(default_factory=set)
    total_tool_calls: int = 0
    user_asks: list[Fact] = field(default_factory=list)
    total_user_asks: int = 0
    files_edited: list[Fact] = field(default_factory=list)
    edited_paths: set[str] = field(default_factory=set)
    files_read: list[Fact] = field(default_factory=list)
    read_paths: set[str] = field(default_factory=set)
    commands: list[Fact] = field(default_factory=list)
    total_commands: int = 0
    test_signals: list[Fact] = field(default_factory=list)
    total_test_signals: int = 0
    last_test_signal: Fact | None = None
    last_test_signal_source: str | None = None
    last_error: Fact | None = None
    last_error_source: str | None = None
    final_assistant_text: Fact | None = None
    final_assistant_source: str | None = None
    facts: list[Fact] = field(default_factory=list)
    facts_omitted: int = 0
    source_lines: dict[int, str] = field(default_factory=dict)

    def retain_source(self, fact: Fact, source_line: str) -> None:
        self.source_lines.setdefault(fact.line, source_line)

    def add_evidence(self, fact: Fact, source_line: str) -> None:
        if len(self.facts) < MAX_FACTS:
            self.facts.append(fact)
            self.retain_source(fact, source_line)
        else:
            self.facts_omitted += 1


def extract_transcript(path: Path, *, parse_json: ParseJSON) -> TranscriptData:
    """Stream a v1 transcript and retain only bounded artifact material."""
    builder = _Builder(source_path=str(path))
    digest, total_lines = _read_lines(path, parse_json=parse_json, builder=builder)
    if total_lines == 0:
        raise TranscriptError("empty_file")
    if builder.coverage_counts["parsed_events"] == 0 and builder.coverage_counts["unknown_type_events"] == 0:
        raise TranscriptError("no_readable_events")
    for fact, source_line in (
        (builder.last_test_signal, builder.last_test_signal_source),
        (builder.last_error, builder.last_error_source),
        (builder.final_assistant_text, builder.final_assistant_source),
    ):
        if fact is not None and source_line is None:
            raise TranscriptError("internal_quote_mismatch")
        if fact is not None and source_line is not None:
            builder.retain_source(fact, source_line)
    if builder.final_assistant_text is not None and builder.final_assistant_source is not None:
        builder.add_evidence(builder.final_assistant_text, builder.final_assistant_source)
    coverage = Coverage(**{name: builder.coverage_counts[name] for name in CONSERVATION_FIELDS})
    if sum(coverage.as_dict(facts_omitted=builder.facts_omitted)[name] for name in CONSERVATION_FIELDS) != total_lines:
        raise TranscriptError("internal_coverage_mismatch")
    return TranscriptData(
        source_path=builder.source_path,
        sha256=digest,
        total_lines=total_lines,
        coverage=coverage,
        event_counts=dict(builder.event_counts),
        tool_counts=dict(builder.tool_counts),
        tool_first=builder.tool_first,
        tool_names=builder.tool_names,
        total_tool_calls=builder.total_tool_calls,
        user_asks=builder.user_asks,
        total_user_asks=builder.total_user_asks,
        files_edited=builder.files_edited,
        total_files_edited=len(builder.edited_paths),
        files_read=builder.files_read,
        total_files_read=len(builder.read_paths),
        commands=builder.commands,
        total_commands=builder.total_commands,
        test_signals=builder.test_signals,
        total_test_signals=builder.total_test_signals,
        last_test_signal=builder.last_test_signal,
        last_error=builder.last_error,
        final_assistant_text=builder.final_assistant_text,
        facts=builder.facts,
        facts_omitted=builder.facts_omitted,
        source_lines=builder.source_lines,
    )


def compile_transcript(path: Path, *, artifact: str, parse_json: ParseJSON) -> str:
    """Extract, self-check, and deterministically render one artifact."""
    data = extract_transcript(path, parse_json=parse_json)
    _verify_quotes(data)
    renderers = {
        "results-note": _render_results_note,
        "handoff-brief": _render_handoff_brief,
        "evidence": _render_evidence,
    }
    try:
        rendered = renderers[artifact](data)
    except KeyError as exc:
        raise TranscriptError("unknown_artifact") from exc
    if len(rendered.encode("utf-8")) > MAX_RENDER_BYTES:
        raise TranscriptError("render_too_large")
    return rendered


def _read_lines(path: Path, *, parse_json: ParseJSON, builder: _Builder) -> tuple[str, int]:
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise TranscriptError("missing_file") from exc
    except OSError as exc:
        raise TranscriptError("unreadable_file") from exc
    if not stat.S_ISREG(before.st_mode):
        raise TranscriptError("not_regular_file")
    if before.st_size > MAX_TRANSCRIPT_BYTES:
        raise TranscriptError("total_size_limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise TranscriptError("unreadable_file") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_file(before, opened):
            raise TranscriptError("file_changed")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            digest, total_lines, total_bytes = _consume_stream(stream, parse_json=parse_json, builder=builder)
        after_open = os.fstat(descriptor)
        try:
            after_path = path.lstat()
        except OSError as exc:
            raise TranscriptError("file_changed") from exc
        if (
            total_bytes != opened.st_size
            or not _same_file(opened, after_open, include_metadata=True)
            or not _same_file(before, after_path, include_metadata=True)
        ):
            raise TranscriptError("file_changed")
        return digest, total_lines
    finally:
        os.close(descriptor)


def _consume_stream(stream: BinaryIO, *, parse_json: ParseJSON, builder: _Builder) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    total_lines = 0
    total_bytes = 0
    while True:
        raw_line = stream.readline(MAX_LINE_BYTES + 1)
        if not raw_line:
            break
        total_lines += 1
        chunks = [raw_line]
        oversized = len(raw_line) > MAX_LINE_BYTES
        while raw_line and not raw_line.endswith(b"\n") and len(raw_line) == MAX_LINE_BYTES + 1:
            raw_line = stream.readline(MAX_LINE_BYTES + 1)
            if raw_line:
                chunks.append(raw_line)
                oversized = True
        for chunk in chunks:
            total_bytes += len(chunk)
            if total_bytes > MAX_TRANSCRIPT_BYTES:
                raise TranscriptError("total_size_limit")
            digest.update(chunk)
            try:
                decoder.decode(chunk, final=False)
            except UnicodeDecodeError as exc:
                raise TranscriptError("non_utf8_file") from exc
        if oversized:
            builder.coverage_counts["skipped_oversized"] += 1
            continue
        try:
            source_line = chunks[0].decode("utf-8").removesuffix("\n").removesuffix("\r")
        except UnicodeDecodeError as exc:
            raise TranscriptError("non_utf8_file") from exc
        _consume_line(source_line, total_lines, parse_json=parse_json, builder=builder)
    try:
        decoder.decode(b"", final=True)
    except UnicodeDecodeError as exc:
        raise TranscriptError("non_utf8_file") from exc
    return digest.hexdigest(), total_lines, total_bytes


def _consume_line(source_line: str, line_number: int, *, parse_json: ParseJSON, builder: _Builder) -> None:
    try:
        event = parse_json(source_line, max_bytes=MAX_LINE_BYTES)
    except (RecursionError, TypeError, UnicodeError, ValueError):
        builder.coverage_counts["skipped_unparseable"] += 1
        return
    if not isinstance(event, dict):
        builder.coverage_counts["skipped_unparseable"] += 1
        return
    event_type = event.get("type")
    if not isinstance(event_type, str) or event_type not in _KNOWN_EVENT_TYPES:
        builder.coverage_counts["unknown_type_events"] += 1
        return
    message = event.get("message")
    if not isinstance(message, dict) or message.get("role") != event_type:
        builder.coverage_counts["skipped_unparseable"] += 1
        return
    content = message.get("content")
    if not isinstance(content, (str, list)):
        builder.coverage_counts["skipped_unparseable"] += 1
        return
    builder.coverage_counts["parsed_events"] += 1
    builder.event_counts[event_type] += 1
    if event_type == "user":
        _extract_user_ask(content, source_line, line_number, builder)
    else:
        _extract_assistant_text(content, source_line, line_number, builder)
    if isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use":
                _extract_tool_use(block, source_line, line_number, builder)
            elif block.get("type") == "tool_result":
                _extract_tool_result(block, source_line, line_number, builder)


def _extract_user_ask(content: str | list[object], source_line: str, line_number: int, builder: _Builder) -> None:
    if isinstance(content, str):
        texts = [content]
        carries_result = False
    else:
        carries_result = any(isinstance(block, dict) and block.get("type") == "tool_result" for block in content)
        texts = [
            block["text"]
            for block in content
            if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str)
        ]
    if carries_result or not texts:
        return
    preferred = texts[0] if len(texts) == 1 else source_line
    fact = _make_fact("user_ask", preferred, source_line, line_number)
    builder.total_user_asks += 1
    if len(builder.user_asks) < MAX_LIST_ITEMS:
        builder.user_asks.append(fact)
        builder.retain_source(fact, source_line)
    builder.add_evidence(fact, source_line)


def _extract_assistant_text(content: str | list[object], source_line: str, line_number: int, builder: _Builder) -> None:
    if isinstance(content, str):
        texts = [content]
    else:
        texts = [
            block["text"]
            for block in content
            if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str)
        ]
    for text in texts:
        fact = _make_fact("final_assistant_text", text, source_line, line_number)
        builder.final_assistant_text = fact
        builder.final_assistant_source = source_line


def _extract_tool_use(block: dict[str, object], source_line: str, line_number: int, builder: _Builder) -> None:
    name = block.get("name")
    inputs = block.get("input")
    if not isinstance(name, str) or not isinstance(inputs, dict):
        return
    tool_fact = _make_fact("tool_use", name, source_line, line_number)
    builder.total_tool_calls += 1
    builder.tool_counts[name] += 1
    if name not in builder.displayed_tool_names and len(builder.tool_first) < MAX_LIST_ITEMS:
        builder.displayed_tool_names.add(name)
        builder.tool_first.append(tool_fact)
        builder.tool_names.append(name)
        builder.retain_source(tool_fact, source_line)
    builder.add_evidence(tool_fact, source_line)
    normalized = _normalized_tool_name(name)
    file_path = inputs.get("file_path")
    if isinstance(file_path, str) and file_path:
        if normalized in _EDIT_TOOL_NAMES:
            _record_file(file_path, edited=True, source_line=source_line, line_number=line_number, builder=builder)
        elif normalized in _READ_TOOL_NAMES:
            _record_file(file_path, edited=False, source_line=source_line, line_number=line_number, builder=builder)
    command = inputs.get("command")
    if normalized in _SHELL_TOOL_NAMES and isinstance(command, str) and command:
        fact = _make_fact("command", command, source_line, line_number)
        builder.total_commands += 1
        if len(builder.commands) < MAX_LIST_ITEMS:
            builder.commands.append(fact)
            builder.retain_source(fact, source_line)
        builder.add_evidence(fact, source_line)


def _record_file(
    file_path: str,
    *,
    edited: bool,
    source_line: str,
    line_number: int,
    builder: _Builder,
) -> None:
    kind = "file_edited" if edited else "file_read"
    seen = builder.edited_paths if edited else builder.read_paths
    stored = builder.files_edited if edited else builder.files_read
    if file_path in seen:
        return
    seen.add(file_path)
    fact = _make_fact(kind, file_path, source_line, line_number)
    if len(stored) < MAX_LIST_ITEMS:
        stored.append(fact)
        builder.retain_source(fact, source_line)
    builder.add_evidence(fact, source_line)


def _extract_tool_result(block: dict[str, object], source_line: str, line_number: int, builder: _Builder) -> None:
    texts = list(_tool_result_texts(block.get("content")))
    if block.get("is_error") is True:
        preferred = texts[0] if len(texts) == 1 else source_line
        fact = _make_fact("error", preferred, source_line, line_number)
        builder.last_error = fact
        builder.last_error_source = source_line
        builder.add_evidence(fact, source_line)
    for text in texts:
        for signal_text in text.splitlines():
            if not _is_test_signal(signal_text):
                continue
            initial = _make_fact("test_signal", signal_text, source_line, line_number)
            counts = _test_counts(initial.quote)
            fact = Fact(
                kind=initial.kind,
                value={"text": initial.quote, "counts": counts},
                quote=initial.quote,
                line=initial.line,
                quote_truncated=initial.quote_truncated,
                quote_full_length=initial.quote_full_length,
            )
            builder.total_test_signals += 1
            if len(builder.test_signals) < MAX_LIST_ITEMS:
                builder.test_signals.append(fact)
                builder.retain_source(fact, source_line)
            builder.last_test_signal = fact
            builder.last_test_signal_source = source_line
            builder.add_evidence(fact, source_line)


def _tool_result_texts(content: object) -> Iterator[str]:
    if isinstance(content, str):
        yield content
    elif isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
                yield block["text"]


def _is_test_signal(text: str) -> bool:
    if _TESTS_SUMMARY.match(text):
        return bool(_TESTS_COUNT.search(text))
    return bool(_PYTEST_COUNT.search(text))


def _test_counts(text: str) -> dict[str, int]:
    pattern = _TESTS_COUNT if _TESTS_SUMMARY.match(text) else _PYTEST_COUNT
    counts: Counter[str] = Counter()
    for count, label in pattern.findall(text):
        normalized = "error" if label.lower() in {"error", "errors"} else label.lower()
        counts[normalized] += int(count)
    return dict(sorted(counts.items()))


def _normalized_tool_name(name: str) -> str:
    leaf = re.split(r"__|[/:.]", name)[-1]
    return re.sub(r"[^a-z0-9]", "", leaf.lower())


def _make_fact(kind: str, preferred: str, source_line: str, line_number: int) -> Fact:
    full_quote = preferred if preferred in source_line else source_line
    truncated = len(full_quote) > MAX_QUOTE_CHARS
    quote = full_quote[:MAX_QUOTE_CHARS]
    return Fact(
        kind=kind,
        value=quote,
        quote=quote,
        line=line_number,
        quote_truncated=truncated,
        quote_full_length=len(full_quote) if truncated else None,
    )


def _verify_quotes(data: TranscriptData) -> None:
    facts = list(data.facts)
    facts.extend(data.tool_first)
    facts.extend(data.user_asks)
    facts.extend(data.files_edited)
    facts.extend(data.files_read)
    facts.extend(data.commands)
    facts.extend(data.test_signals)
    facts.extend(
        item for item in (data.last_test_signal, data.last_error, data.final_assistant_text) if item is not None
    )
    for fact in facts:
        source_line = data.source_lines.get(fact.line)
        if source_line is None or fact.quote not in source_line:
            raise TranscriptError("internal_quote_mismatch")


def _render_results_note(data: TranscriptData) -> str:
    lines = ["# Transcript Results Note", "", "## Ask", ""]
    if data.user_asks:
        lines.extend(_quote_lines(data.user_asks[0]))
    else:
        lines.append("none found in transcript")
    lines.extend(["", "## Activity summary", ""])
    lines.extend(
        [
            f"- User events: {data.event_counts.get('user', 0)}",
            f"- Assistant events: {data.event_counts.get('assistant', 0)}",
            f"- Unknown-type events: {data.coverage.unknown_type_events}",
            f"- Unparseable lines: {data.coverage.skipped_unparseable}",
            f"- Oversized lines: {data.coverage.skipped_oversized}",
            f"- Total tool calls: {data.total_tool_calls}",
        ]
    )
    lines.extend(["", "Tool calls by name:", ""])
    if data.tool_first:
        for name, fact in zip(data.tool_names, data.tool_first, strict=True):
            lines.append(f"{data.tool_counts[name]} call(s); first source line {fact.line}:")
            lines.extend(["", *_blockquote_lines(fact), ""])
        omitted = data.total_tool_calls - sum(data.tool_counts[name] for name in data.tool_names)
        if omitted:
            lines.append(f"{omitted} additional tool call(s) omitted by the artifact list cap.")
    else:
        lines.append("none found in transcript")
    _append_fact_section(lines, "Files edited", data.files_edited, data.total_files_edited, "file")
    _append_fact_section(lines, "Files read", data.files_read, data.total_files_read, "file")
    _append_fact_section(lines, "Commands run", data.commands, data.total_commands, "command")
    _append_fact_section(lines, "Test signals", data.test_signals, data.total_test_signals, "test signal")
    lines.extend(["", "## Outcome", ""])
    if data.final_assistant_text is None:
        lines.append("none found in transcript")
    else:
        lines.extend(_quote_lines(data.final_assistant_text))
    return "\n".join(lines).rstrip() + "\n"


def _render_handoff_brief(data: TranscriptData) -> str:
    lines = ["# Transcript Handoff Brief", "", "## User asks", ""]
    if data.user_asks:
        for index, fact in enumerate(data.user_asks, start=1):
            lines.append(f"Ask {index}, source line {fact.line}:")
            lines.extend(["", *_blockquote_lines(fact), ""])
        _append_omission(lines, data.total_user_asks, len(data.user_asks), "user ask")
    else:
        lines.append("not found in transcript")
    lines.extend(["", "## State", "", "Files edited:", ""])
    if data.files_edited:
        for fact in data.files_edited:
            lines.extend(_quote_lines(fact))
            lines.append("")
        _append_omission(lines, data.total_files_edited, len(data.files_edited), "file")
    else:
        lines.append("not found in transcript")
    lines.extend(["", f"Commands run: {data.total_commands}", "", "Last error:", ""])
    if data.last_error is None:
        lines.append("Last error: not found in transcript")
    else:
        lines.extend(_quote_lines(data.last_error))
    lines.extend(["", "Last test signal:", ""])
    if data.last_test_signal is None:
        lines.append("Last test signal: not found in transcript")
    else:
        lines.extend(_quote_lines(data.last_test_signal))
    lines.extend(["", "Final assistant text:", ""])
    if data.final_assistant_text is None:
        lines.append("Final assistant text: not found in transcript")
    else:
        lines.extend(_quote_lines(data.final_assistant_text))
    return "\n".join(lines).rstrip() + "\n"


def _render_evidence(data: TranscriptData) -> str:
    payload = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "source": {
            "path": data.source_path,
            "sha256": data.sha256,
            "total_lines": data.total_lines,
        },
        "coverage": data.coverage.as_dict(facts_omitted=data.facts_omitted),
        "facts": [fact.as_dict() for fact in data.facts],
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"


def _append_fact_section(lines: list[str], heading: str, facts: list[Fact], total: int, singular_name: str) -> None:
    lines.extend(["", f"## {heading}", ""])
    if not facts:
        lines.append("none found in transcript")
        return
    for fact in facts:
        lines.extend(_quote_lines(fact))
        lines.append("")
    _append_omission(lines, total, len(facts), singular_name)


def _append_omission(lines: list[str], total: int, shown: int, singular_name: str) -> None:
    omitted = total - shown
    if omitted:
        lines.append(f"{omitted} additional {singular_name}(s) omitted by the artifact list cap.")


def _quote_lines(fact: Fact) -> list[str]:
    return [f"Source line {fact.line}:", "", *_blockquote_lines(fact)]


def _blockquote_lines(fact: Fact) -> list[str]:
    lines = [f"> {fact.quote}"]
    if fact.quote_truncated:
        lines.append(f"[truncated] Full quote length: {fact.quote_full_length} characters.")
    return lines


def _same_file(left: os.stat_result, right: os.stat_result, *, include_metadata: bool = False) -> bool:
    same_identity = (
        stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
    )
    if not include_metadata:
        return same_identity
    return (
        same_identity
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
    )
