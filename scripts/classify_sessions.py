#!/usr/bin/env python3
"""Mine aggregate retry patterns from explicitly selected session ledgers.

Developer-only: this script is not shipped and is not wired into the release
gate. It deliberately has no implicit home-directory scan. Pass one or more
ledger files/directories, or name a Claude ledger root explicitly::

    python scripts/classify_sessions.py /srv/private/claude/projects
    python scripts/classify_sessions.py --claude-ledger-root /srv/private/claude/projects --json

The default report is aggregate-only. It never emits source paths, session
identifiers, prompts, commands, or Read targets. A bounded diagnostic view of
those sensitive values is available only with ``--include-sensitive-content``.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import itertools
import json
import os
import re
import secrets
import stat
import sys
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Iterator
from dataclasses import asdict, dataclass, field
from heapq import nlargest
from pathlib import Path
from typing import BinaryIO, TypeVar

_VERIFY_TOKENS = ("check.py", "pytest", "ruff", "verify")
_VERIFY_PATTERNS = tuple(re.compile(r"\b" + re.escape(token) + r"\b") for token in _VERIFY_TOKENS)
_FAIL_MARKERS = ("Traceback", "BLOCKED", "FAILED", "FAIL:", "tests failed", "error:")

BUCKETS = ("repeated_tool_use", "repeated_prompt", "verify_fail_aftermath")
_PATTERN_KINDS = ("bash", "read", "prompt")
_T = TypeVar("_T")

DEFAULT_MAX_FILES = 1_000
HARD_MAX_FILES = 10_000
DEFAULT_MAX_DISCOVERY_ENTRIES = 100_000
HARD_MAX_DISCOVERY_ENTRIES = 1_000_000
DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024
HARD_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_MAX_FILE_BYTES = 16 * 1024 * 1024
HARD_MAX_FILE_BYTES = 128 * 1024 * 1024
DEFAULT_MAX_LINE_BYTES = 512 * 1024
HARD_MAX_LINE_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_LINES_PER_FILE = 100_000
HARD_MAX_LINES_PER_FILE = 1_000_000
DEFAULT_TOP = 15
HARD_MAX_TOP = 100
_SENSITIVE_SAMPLE_CHARS = 512
_SEARCHABLE_RESULT_CHARS = 16_384
_SEARCHABLE_RESULT_NODES = 512
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


@dataclass(frozen=True)
class ScanLimits:
    """Hard-bounded scan budgets, included verbatim in every report."""

    max_files: int = DEFAULT_MAX_FILES
    max_discovery_entries: int = DEFAULT_MAX_DISCOVERY_ENTRIES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES
    max_lines_per_file: int = DEFAULT_MAX_LINES_PER_FILE


@dataclass
class ScanDisclosure:
    """Content-free accounting for rejected, invalid, and truncated input."""

    source_count: int = 0
    sources_missing: int = 0
    sources_rejected_symlink: int = 0
    sources_rejected_non_regular: int = 0
    discovery_entries_seen: int = 0
    discovery_errors: int = 0
    discovery_limit_reached: bool = False
    file_limit_reached: bool = False
    ledgers_discovered: int = 0
    duplicate_ledgers: int = 0
    files_rejected_symlink: int = 0
    files_rejected_non_regular: int = 0
    files_rejected_hardlink: int = 0
    files_rejected_outside_root: int = 0
    files_rejected_race: int = 0
    files_changed_during_read: int = 0
    files_unreadable: int = 0
    files_scanned: int = 0
    files_truncated: int = 0
    files_skipped_total_budget: int = 0
    bytes_read: int = 0
    total_byte_limit_reached: bool = False
    row_limit_files: int = 0
    rows_seen: int = 0
    rows_parsed: int = 0
    rows_typed: int = 0
    rows_blank: int = 0
    rows_invalid_json: int = 0
    rows_invalid_encoding: int = 0
    rows_invalid_shape: int = 0
    rows_ignored: int = 0
    rows_oversized: int = 0
    rows_truncated: int = 0

    def public(self, limits: ScanLimits) -> dict[str, object]:
        invalid_rows = (
            self.rows_invalid_json
            + self.rows_invalid_encoding
            + self.rows_invalid_shape
            + self.rows_oversized
            + self.rows_truncated
        )
        truncated = any(
            (
                self.discovery_limit_reached,
                self.file_limit_reached,
                self.total_byte_limit_reached,
                self.files_truncated > 0,
                self.row_limit_files > 0,
            )
        )
        return {
            "limits": asdict(limits),
            "sources": {
                "requested": self.source_count,
                "missing": self.sources_missing,
                "rejected_symlink": self.sources_rejected_symlink,
                "rejected_non_regular": self.sources_rejected_non_regular,
            },
            "discovery": {
                "entries_seen": self.discovery_entries_seen,
                "errors": self.discovery_errors,
                "limit_reached": self.discovery_limit_reached,
                "file_limit_reached": self.file_limit_reached,
                "ledgers_discovered": self.ledgers_discovered,
                "duplicate_ledgers": self.duplicate_ledgers,
            },
            "files": {
                "scanned": self.files_scanned,
                "truncated": self.files_truncated,
                "skipped_total_budget": self.files_skipped_total_budget,
                "rejected_symlink": self.files_rejected_symlink,
                "rejected_non_regular": self.files_rejected_non_regular,
                "rejected_hardlink": self.files_rejected_hardlink,
                "rejected_outside_root": self.files_rejected_outside_root,
                "rejected_race": self.files_rejected_race,
                "changed_during_read": self.files_changed_during_read,
                "unreadable": self.files_unreadable,
            },
            "bytes_read": self.bytes_read,
            "rows": {
                "seen": self.rows_seen,
                "parsed": self.rows_parsed,
                "typed": self.rows_typed,
                "blank": self.rows_blank,
                "invalid_json": self.rows_invalid_json,
                "invalid_encoding": self.rows_invalid_encoding,
                "invalid_shape": self.rows_invalid_shape,
                "ignored": self.rows_ignored,
                "oversized": self.rows_oversized,
                "truncated": self.rows_truncated,
                "row_limit_files": self.row_limit_files,
                "invalid_total": invalid_rows,
            },
            "truncation": {
                "occurred": truncated,
                "total_byte_limit_reached": self.total_byte_limit_reached,
            },
        }


@dataclass
class ReadBudget:
    remaining: int


@dataclass(frozen=True)
class LedgerCandidate:
    path: Path
    root: Path
    identity: tuple[int, int]


@dataclass(frozen=True)
class Signal:
    index: int
    fingerprint: str
    sample: str | None


@dataclass
class SessionEvidence:
    prompts: list[Signal] = field(default_factory=list)
    bash_keys: list[Signal] = field(default_factory=list)
    read_keys: list[Signal] = field(default_factory=list)
    tool_uses: dict[str, tuple[int, bool, str | None]] = field(default_factory=dict)
    results: dict[str, bool] = field(default_factory=dict)


@dataclass
class SessionAnalysis:
    path: Path
    buckets: dict[str, bool]
    pattern_statistics: dict[str, dict[str, int]]
    sensitive_repeats: dict[str, list[tuple[int, str]]]
    verify_failure_count: int
    verify_failure_samples: list[str]
    primary_prompt_fingerprint: str | None
    primary_prompt_sample: str | None
    n_prompts: int


def _command_contains_verify_signal(command: str) -> bool:
    return any(pattern.search(command) for pattern in _VERIFY_PATTERNS)


def _is_reparse_point(file_stat: os.stat_result) -> bool:
    return bool(getattr(file_stat, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT)


def _is_link_like(file_stat: os.stat_result) -> bool:
    return stat.S_ISLNK(file_stat.st_mode) or _is_reparse_point(file_stat)


def _identity(file_stat: os.stat_result) -> tuple[int, int]:
    return file_stat.st_dev, file_stat.st_ino


def _stable_file_state(file_stat: os.stat_result) -> tuple[object, ...]:
    """Return security-relevant state that reading the file does not mutate."""
    # Windows can publish a delayed ``st_ctime_ns`` update when a newly written
    # handle is first reopened. Identity, size, mtime, mode, and link count stay
    # stable across lstat/fstat there and still detect replacement or mutation.
    change_time_ns = None if os.name == "nt" else file_stat.st_ctime_ns
    return (
        _identity(file_stat),
        file_stat.st_mode,
        file_stat.st_nlink,
        file_stat.st_size,
        file_stat.st_mtime_ns,
        change_time_ns,
        getattr(file_stat, "st_uid", None),
        getattr(file_stat, "st_gid", None),
    )


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _path_sort_key(path: Path) -> tuple[str, str]:
    """Return a filesystem-order-independent key for bounded selection."""
    absolute = os.path.abspath(os.fspath(path))
    return os.path.normcase(absolute), absolute


def _bounded_sorted_directory_paths(
    directory: Path,
    limits: ScanLimits,
    disclosure: ScanDisclosure,
) -> list[Path] | None:
    """Stage one complete directory before sorting; reject a partial capped view."""
    remaining = limits.max_discovery_entries - disclosure.discovery_entries_seen
    if remaining <= 0:
        disclosure.discovery_limit_reached = True
        return None
    staged: list[Path] = []
    try:
        with os.scandir(directory) as iterator:
            for entry in iterator:
                if len(staged) >= remaining:
                    # One bounded lookahead establishes overflow. None of this
                    # directory's arbitrary enumeration order enters selection.
                    disclosure.discovery_entries_seen += len(staged)
                    disclosure.discovery_limit_reached = True
                    return None
                staged.append(Path(entry.path))
    except OSError:
        # A partially enumerated directory is never admitted to the result.
        disclosure.discovery_entries_seen += len(staged)
        disclosure.discovery_errors += 1
        return []
    disclosure.discovery_entries_seen += len(staged)
    staged.sort(key=_path_sort_key)
    return staged


def _discover_session_ledgers(
    sources: list[Path], limits: ScanLimits, disclosure: ScanDisclosure
) -> list[LedgerCandidate]:
    """Discover regular, single-link JSONL files without following links."""
    disclosure.source_count = len(sources)
    candidates: list[LedgerCandidate] = []
    seen: set[tuple[int, int]] = set()

    def add_candidate(path: Path, root: Path, file_stat: os.stat_result) -> None:
        if file_stat.st_nlink != 1:
            disclosure.files_rejected_hardlink += 1
            return
        identity = _identity(file_stat)
        if identity in seen:
            disclosure.duplicate_ledgers += 1
            return
        seen.add(identity)
        candidates.append(LedgerCandidate(path=path, root=root, identity=identity))

    def inspect_entry(path: Path, root: Path, file_stat: os.stat_result) -> None:
        if _is_link_like(file_stat):
            disclosure.files_rejected_symlink += 1
            return
        if not stat.S_ISREG(file_stat.st_mode):
            disclosure.files_rejected_non_regular += 1
            return
        add_candidate(path, root, file_stat)

    for source in sources:
        if disclosure.discovery_limit_reached:
            break
        try:
            source_stat = source.lstat()
        except FileNotFoundError:
            disclosure.sources_missing += 1
            continue
        except OSError:
            disclosure.discovery_errors += 1
            continue
        if _is_link_like(source_stat):
            disclosure.sources_rejected_symlink += 1
            continue
        try:
            source_root = source.resolve(strict=True)
        except OSError:
            disclosure.discovery_errors += 1
            continue
        if stat.S_ISREG(source_stat.st_mode):
            if source.suffix.lower() != ".jsonl":
                disclosure.sources_rejected_non_regular += 1
                continue
            inspect_entry(source, source_root.parent, source_stat)
            continue
        if not stat.S_ISDIR(source_stat.st_mode):
            disclosure.sources_rejected_non_regular += 1
            continue

        pending = [source]
        while pending and not disclosure.discovery_limit_reached:
            directory = pending.pop()
            entry_paths = _bounded_sorted_directory_paths(directory, limits, disclosure)
            if entry_paths is None:
                break
            child_directories: list[Path] = []
            for entry_path in entry_paths:
                try:
                    # pathlib's lstat preserves Windows file identity and
                    # link-count fields that DirEntry.stat can zero out.
                    entry_stat = entry_path.lstat()
                except OSError:
                    disclosure.discovery_errors += 1
                    continue
                if _is_link_like(entry_stat):
                    disclosure.files_rejected_symlink += 1
                    continue
                if stat.S_ISDIR(entry_stat.st_mode):
                    child_directories.append(entry_path)
                    continue
                if entry_path.suffix.lower() != ".jsonl":
                    continue
                inspect_entry(entry_path, source_root, entry_stat)
            # Stack order preserves a lexicographic depth-first traversal.
            pending.extend(reversed(child_directories))

    candidates.sort(key=lambda candidate: _path_sort_key(candidate.path))
    if len(candidates) > limits.max_files:
        disclosure.file_limit_reached = True
        del candidates[limits.max_files :]
    disclosure.ledgers_discovered = len(candidates)
    return candidates


def _secure_open_candidate(
    candidate: LedgerCandidate, disclosure: ScanDisclosure
) -> tuple[BinaryIO, os.stat_result] | None:
    """Open the same contained regular inode that discovery approved."""
    try:
        before = candidate.path.lstat()
        if _is_link_like(before):
            disclosure.files_rejected_symlink += 1
            return None
        if not stat.S_ISREG(before.st_mode):
            disclosure.files_rejected_non_regular += 1
            return None
        if before.st_nlink != 1:
            disclosure.files_rejected_hardlink += 1
            return None
        if _identity(before) != candidate.identity:
            disclosure.files_rejected_race += 1
            return None
        resolved = candidate.path.resolve(strict=True)
        if not _within(resolved, candidate.root):
            disclosure.files_rejected_outside_root += 1
            return None
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(candidate.path, flags)
    except OSError:
        disclosure.files_unreadable += 1
        return None

    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_link_like(opened)
            or opened.st_nlink != 1
            or _stable_file_state(opened) != _stable_file_state(before)
        ):
            disclosure.files_rejected_race += 1
            os.close(fd)
            return None
        return os.fdopen(fd, "rb"), opened
    except Exception:
        os.close(fd)
        disclosure.files_unreadable += 1
        return None


def _bounded_lines(
    stream: BinaryIO,
    expected_size: int,
    limits: ScanLimits,
    budget: ReadBudget,
    disclosure: ScanDisclosure,
) -> Iterator[bytes]:
    """Yield complete bounded lines and account for every discarded byte."""
    # Read at most the descriptor's opening snapshot. Concurrent appends cannot
    # silently expand the analysis or consume the next file's global budget.
    file_budget = min(limits.max_file_bytes, budget.remaining, expected_size)
    file_bytes = 0
    rows = 0
    reached_eof = False
    file_truncated = expected_size > file_budget

    while rows < limits.max_lines_per_file and file_bytes < file_budget and budget.remaining > 0:
        available = min(file_budget - file_bytes, budget.remaining)
        read_limit = min(limits.max_line_bytes + 1, available)
        raw = stream.readline(read_limit)
        if not raw:
            reached_eof = True
            break
        consumed = len(raw)
        file_bytes += consumed
        budget.remaining -= consumed
        disclosure.bytes_read += consumed
        rows += 1
        disclosure.rows_seen += 1

        complete = raw.endswith(b"\n") or file_bytes >= expected_size
        if len(raw) > limits.max_line_bytes:
            disclosure.rows_oversized += 1
            while not raw.endswith(b"\n") and file_bytes < file_budget and budget.remaining > 0:
                available = min(file_budget - file_bytes, budget.remaining)
                raw = stream.readline(min(64 * 1024, available))
                if not raw:
                    reached_eof = True
                    break
                consumed = len(raw)
                file_bytes += consumed
                budget.remaining -= consumed
                disclosure.bytes_read += consumed
            if not raw.endswith(b"\n") and not reached_eof:
                file_truncated = True
            continue
        if not complete:
            disclosure.rows_truncated += 1
            file_truncated = True
            break
        yield raw

    if reached_eof and file_bytes < expected_size:
        # EOF before the descriptor's opening size is a concurrent shrink (or
        # equivalent state change), even when the last observed row ended with
        # a newline. Never report that snapshot as complete.
        file_truncated = True
    if rows >= limits.max_lines_per_file and file_bytes < expected_size:
        disclosure.row_limit_files += 1
        file_truncated = True
    if budget.remaining <= 0 and file_bytes < expected_size:
        disclosure.total_byte_limit_reached = True
        file_truncated = True
    if file_bytes >= limits.max_file_bytes and file_bytes < expected_size:
        file_truncated = True
    if (
        not reached_eof
        and file_bytes < expected_size
        and (file_bytes >= file_budget or rows >= limits.max_lines_per_file)
    ):
        file_truncated = True
    if file_truncated:
        disclosure.files_truncated += 1


def _read_state_is_stable(
    candidate: LedgerCandidate,
    stream: BinaryIO,
    opened: os.stat_result,
) -> bool:
    """Confirm the open inode and its path remained unchanged during the read."""
    try:
        descriptor_before = os.fstat(stream.fileno())
        path_before = candidate.path.lstat()
        resolved_now = candidate.path.resolve(strict=True)
        path_after = candidate.path.lstat()
        descriptor_after = os.fstat(stream.fileno())
    except (OSError, RuntimeError, ValueError):
        return False
    if (
        not stat.S_ISREG(descriptor_before.st_mode)
        or _is_link_like(descriptor_before)
        or descriptor_before.st_nlink != 1
        or not stat.S_ISREG(path_before.st_mode)
        or _is_link_like(path_before)
        or path_before.st_nlink != 1
        or not stat.S_ISREG(path_after.st_mode)
        or _is_link_like(path_after)
        or path_after.st_nlink != 1
        or not stat.S_ISREG(descriptor_after.st_mode)
        or _is_link_like(descriptor_after)
        or descriptor_after.st_nlink != 1
        or not _within(resolved_now, candidate.root)
    ):
        return False
    opening_state = _stable_file_state(opened)
    return all(
        _stable_file_state(current) == opening_state
        for current in (descriptor_before, path_before, path_after, descriptor_after)
    )


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _iter_records(
    candidate: LedgerCandidate,
    limits: ScanLimits,
    budget: ReadBudget,
    disclosure: ScanDisclosure,
) -> Iterator[object]:
    opened = _secure_open_candidate(candidate, disclosure)
    if opened is None:
        return
    stream, opened_state = opened
    expected_size = opened_state.st_size
    truncated_before = disclosure.files_truncated
    records: list[object] = []
    read_failed = False
    stable = False
    with stream:
        try:
            for raw in _bounded_lines(stream, expected_size, limits, budget, disclosure):
                try:
                    line = raw.decode("utf-8")
                except UnicodeDecodeError:
                    disclosure.rows_invalid_encoding += 1
                    continue
                line = line.strip()
                if not line:
                    disclosure.rows_blank += 1
                    continue
                try:
                    record = json.loads(line, object_pairs_hook=_reject_duplicate_json_keys)
                except (ValueError, RecursionError):
                    disclosure.rows_invalid_json += 1
                    continue
                records.append(record)
        except OSError:
            read_failed = True
            disclosure.files_unreadable += 1
        finally:
            stable = _read_state_is_stable(candidate, stream, opened_state)
    if not stable:
        disclosure.files_changed_during_read += 1
    if read_failed or not stable:
        if disclosure.files_truncated == truncated_before:
            disclosure.files_truncated += 1
        return
    # Parsed records become classifier evidence only after the descriptor and
    # path identity have survived the final stability check.
    disclosure.files_scanned += 1
    disclosure.rows_parsed += len(records)
    yield from records


def _ledger_field(obj: dict[str, object], key: str, default: object = None) -> object:
    return obj[key] if key in obj else default


def _real_user_text(content: object) -> str | None:
    if isinstance(content, str):
        return content.strip() or None
    if not isinstance(content, list):
        return None
    text = None
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "text":
            continue
        value = block.get("text")
        if isinstance(value, str) and value.strip():
            text = value.strip()
    return text


def _bounded_searchable_text(raw: object) -> str:
    """Extract bounded strings from arbitrary JSON without recursive walking."""
    pending = [raw]
    pieces: list[str] = []
    chars = 0
    nodes = 0
    while pending and nodes < _SEARCHABLE_RESULT_NODES and chars < _SEARCHABLE_RESULT_CHARS:
        value = pending.pop()
        nodes += 1
        if isinstance(value, str):
            piece = value[: _SEARCHABLE_RESULT_CHARS - chars]
            pieces.append(piece)
            chars += len(piece)
        elif isinstance(value, list):
            pending.extend(reversed(value[:_SEARCHABLE_RESULT_NODES]))
        elif isinstance(value, dict):
            selected = itertools.islice(value.values(), _SEARCHABLE_RESULT_NODES)
            pending.extend(reversed(list(selected)))
    return " ".join(pieces)


def _fingerprint(key: bytes, kind: str, value: str) -> str:
    payload = kind.encode("ascii") + b"\0" + value.encode("utf-8", errors="replace")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _sensitive_sample(value: str) -> str:
    # Content mode is explicit, but samples still need to be inert when copied
    # through terminals, logs, and JSON viewers.
    clean = "".join(character if character >= " " and character != "\x7f" else " " for character in value)
    clean = " ".join(clean.split())
    return clean[:_SENSITIVE_SAMPLE_CHARS]


def _signal(index: int, kind: str, value: str, key: bytes, include_sensitive_content: bool) -> Signal:
    sample = _sensitive_sample(value) if include_sensitive_content else None
    return Signal(index=index, fingerprint=_fingerprint(key, kind, value), sample=sample)


def _valid_tool_id(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 256:
        return None
    return value


def _index_user_turn(
    evidence: SessionEvidence,
    index: int,
    content: object,
    key: bytes,
    include_sensitive_content: bool,
) -> None:
    text = _real_user_text(content)
    if text:
        evidence.prompts.append(_signal(index, "prompt", text, key, include_sensitive_content))
    if not isinstance(content, list):
        return
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_result":
            continue
        tool_id = _valid_tool_id(block.get("tool_use_id"))
        if tool_id is None:
            continue
        body = _bounded_searchable_text(block.get("content"))
        evidence.results[tool_id] = bool(block.get("is_error")) or any(marker in body for marker in _FAIL_MARKERS)


def _index_assistant_turn(
    evidence: SessionEvidence,
    index: int,
    content: object,
    key: bytes,
    include_sensitive_content: bool,
) -> None:
    if not isinstance(content, list):
        return
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_use":
            continue
        name = block.get("name")
        payload = block.get("input")
        input_obj = payload if isinstance(payload, dict) else {}
        if name == "Bash":
            value = input_obj.get("command")
            kind = "bash"
        elif name == "Read":
            value = input_obj.get("file_path")
            kind = "read"
        else:
            continue
        if not isinstance(value, str) or not value:
            continue
        signal = _signal(index, kind, value, key, include_sensitive_content)
        if kind == "bash":
            evidence.bash_keys.append(signal)
        else:
            evidence.read_keys.append(signal)
        tool_id = _valid_tool_id(block.get("id"))
        if tool_id is not None:
            sample = _sensitive_sample(value) if include_sensitive_content else None
            evidence.tool_uses[tool_id] = (index, kind == "bash" and _command_contains_verify_signal(value), sample)


def _as_typed_turn(record: object, disclosure: ScanDisclosure) -> tuple[str, object] | None:
    if not isinstance(record, dict):
        disclosure.rows_invalid_shape += 1
        return None
    record_type = record.get("type")
    if record_type not in ("user", "assistant"):
        disclosure.rows_ignored += 1
        return None
    message = record.get("message")
    if not isinstance(message, dict) or "content" not in message:
        disclosure.rows_invalid_shape += 1
        return None
    disclosure.rows_typed += 1
    return record_type, message["content"]


def _collect_evidence(
    candidate: LedgerCandidate,
    limits: ScanLimits,
    budget: ReadBudget,
    disclosure: ScanDisclosure,
    key: bytes,
    include_sensitive_content: bool,
) -> SessionEvidence | None:
    files_before = disclosure.files_scanned
    evidence = SessionEvidence()
    for index, record in enumerate(_iter_records(candidate, limits, budget, disclosure)):
        turn = _as_typed_turn(record, disclosure)
        if turn is None:
            continue
        record_type, content = turn
        if record_type == "user":
            _index_user_turn(evidence, index, content, key, include_sensitive_content)
        else:
            _index_assistant_turn(evidence, index, content, key, include_sensitive_content)
    return evidence if disclosure.files_scanned > files_before else None


def _repeated(signals: list[Signal]) -> tuple[dict[str, int], dict[str, str]]:
    counts = Counter(signal.fingerprint for signal in signals)
    repeats = {fingerprint: count for fingerprint, count in counts.items() if count >= 2}
    samples = {
        signal.fingerprint: signal.sample
        for signal in signals
        if signal.fingerprint in repeats and signal.sample is not None
    }
    return repeats, samples


def _one_session_pattern_statistics(repeats: dict[str, int]) -> dict[str, int]:
    values = list(repeats.values())
    return {
        "sessions_with_repeats": int(bool(values)),
        "distinct_in_session_patterns": len(values),
        "repeated_occurrences": sum(values),
        "excess_repetitions": sum(count - 1 for count in values),
        "max_repetitions": max(values, default=0),
    }


def _verify_failures(evidence: SessionEvidence) -> tuple[int, list[str], bool]:
    failed: list[tuple[int, str | None]] = []
    for tool_id, (index, is_verify, sample) in evidence.tool_uses.items():
        if is_verify and evidence.results.get(tool_id, False):
            failed.append((index, sample))
    first_failure = min((index for index, _ in failed), default=-1)
    activity = [signal.index for signal in evidence.bash_keys + evidence.read_keys + evidence.prompts]
    aftermath = first_failure >= 0 and any(index > first_failure for index in activity)
    samples = [sample for _, sample in failed if sample is not None]
    return len(failed), samples, aftermath


def _classify_candidate(
    candidate: LedgerCandidate,
    limits: ScanLimits,
    budget: ReadBudget,
    disclosure: ScanDisclosure,
    key: bytes,
    include_sensitive_content: bool,
) -> SessionAnalysis | None:
    evidence = _collect_evidence(candidate, limits, budget, disclosure, key, include_sensitive_content)
    if evidence is None:
        return None
    repeated_patterns: dict[str, dict[str, int]] = {}
    pattern_statistics: dict[str, dict[str, int]] = {}
    sensitive_repeats: dict[str, list[tuple[int, str]]] = {}
    for kind, signals in (
        ("bash", evidence.bash_keys),
        ("read", evidence.read_keys),
        ("prompt", evidence.prompts),
    ):
        repeats, samples = _repeated(signals)
        repeated_patterns[kind] = repeats
        pattern_statistics[kind] = _one_session_pattern_statistics(repeats)
        sensitive_repeats[kind] = [
            (count, samples.get(fingerprint, ""))
            for fingerprint, count in _top(repeats.items(), 2, lambda item: item[1])
        ]
    verify_failure_count, verify_failure_samples, aftermath = _verify_failures(evidence)
    primary = evidence.prompts[0] if evidence.prompts else None
    return SessionAnalysis(
        path=candidate.path,
        buckets={
            "repeated_tool_use": bool(repeated_patterns["bash"] or repeated_patterns["read"]),
            "repeated_prompt": bool(repeated_patterns["prompt"]),
            "verify_fail_aftermath": bool(verify_failure_count and aftermath),
        },
        pattern_statistics=pattern_statistics,
        sensitive_repeats=sensitive_repeats,
        verify_failure_count=verify_failure_count,
        verify_failure_samples=verify_failure_samples,
        primary_prompt_fingerprint=primary.fingerprint if primary else None,
        primary_prompt_sample=primary.sample if primary else None,
        n_prompts=len(evidence.prompts),
    )


def _pattern_summary(sessions: list[SessionAnalysis], kind: str) -> dict[str, int]:
    rows = [session.pattern_statistics[kind] for session in sessions]
    return {
        "sessions_with_repeats": sum(row["sessions_with_repeats"] for row in rows),
        "distinct_in_session_patterns": sum(row["distinct_in_session_patterns"] for row in rows),
        "repeated_occurrences": sum(row["repeated_occurrences"] for row in rows),
        "excess_repetitions": sum(row["excess_repetitions"] for row in rows),
        "max_repetitions": max((row["max_repetitions"] for row in rows), default=0),
    }


def _cluster_data(sessions: list[SessionAnalysis]) -> tuple[dict[str, list[SessionAnalysis]], dict[str, object]]:
    by_prompt: dict[str, list[SessionAnalysis]] = defaultdict(list)
    for session in sessions:
        if session.primary_prompt_fingerprint:
            by_prompt[session.primary_prompt_fingerprint].append(session)
    clusters = {key: rows for key, rows in by_prompt.items() if len(rows) >= 2}
    histogram = Counter(len(rows) for rows in clusters.values())
    safe = {
        "cluster_count": len(clusters),
        "sessions_in_clusters": sum(len(rows) for rows in clusters.values()),
        "largest_cluster": max((len(rows) for rows in clusters.values()), default=0),
        "size_histogram": {str(size): count for size, count in sorted(histogram.items())},
    }
    return clusters, safe


def _session_signal_count(session: SessionAnalysis) -> int:
    return sum(session.buckets.values())


def _top(items: Iterable[_T], count: int, key: Callable[[_T], int]) -> list[_T]:
    return nlargest(count, items, key=key) if count > 0 else []


def _sensitive_session_detail(session: SessionAnalysis, pattern_top: int = 2) -> dict[str, object]:
    repeated: dict[str, list[dict[str, object]]] = {}
    for kind in _PATTERN_KINDS:
        repeated[kind] = [
            {"content": sample, "count": count} for count, sample in session.sensitive_repeats[kind][:pattern_top]
        ]
    return {
        "source_path": _sensitive_sample(str(session.path)),
        "buckets": session.buckets,
        "n_prompts": session.n_prompts,
        "primary_prompt": session.primary_prompt_sample or "",
        "repeated_patterns": repeated,
        "verify_failures": session.verify_failure_samples[:pattern_top],
    }


def _build_report(
    sessions: list[SessionAnalysis],
    limits: ScanLimits,
    disclosure: ScanDisclosure,
    include_sensitive_content: bool,
    top: int,
) -> dict[str, object]:
    flagged = [session for session in sessions if any(session.buckets.values())]
    bucket_totals = {bucket: sum(session.buckets[bucket] for session in sessions) for bucket in BUCKETS}
    clusters, safe_clusters = _cluster_data(sessions)
    report: dict[str, object] = {
        "schema": "compile-code.transcript-patterns.v1",
        "privacy": {
            "mode": "sensitive_content" if include_sensitive_content else "aggregate_only",
            "content_included": include_sensitive_content,
            "source_paths_included": include_sensitive_content,
            "session_identifiers_included": include_sensitive_content,
        },
        "scan": disclosure.public(limits),
        "summary": {
            "scanned_sessions": len(sessions),
            "retry_like_sessions": len(flagged),
            "bucket_totals": bucket_totals,
        },
        "pattern_statistics": {kind: _pattern_summary(sessions, kind) for kind in _PATTERN_KINDS}
        | {
            "verify": {
                "failed_verify_steps": sum(session.verify_failure_count for session in sessions),
                "sessions_with_failure_aftermath": bucket_totals["verify_fail_aftermath"],
            }
        },
        "cross_session_retry_clusters": safe_clusters,
    }
    if include_sensitive_content:
        ranked_sessions = _top(flagged, top, _session_signal_count)
        ranked_clusters = _top(clusters.values(), top, len)
        report["sensitive_content"] = {
            "warning": "Explicitly requested content-bearing diagnostic samples.",
            "sessions": [_sensitive_session_detail(session) for session in ranked_sessions],
            "sessions_truncated": len(ranked_sessions) < len(flagged),
            "retry_clusters": [
                {
                    "primary_prompt": rows[0].primary_prompt_sample or "",
                    "count": len(rows),
                    "source_paths": [_sensitive_sample(str(row.path)) for row in rows[:top]],
                    "source_paths_truncated": len(rows) > top,
                }
                for rows in ranked_clusters
            ],
            "clusters_truncated": len(ranked_clusters) < len(clusters),
        }
    return report


def _print_prose_report(report: dict[str, object]) -> None:
    privacy = report["privacy"]
    summary = report["summary"]
    scan = report["scan"]
    print(f"[classify] privacy mode: {privacy['mode']}")
    print(
        f"[classify] scanned {summary['scanned_sessions']} session ledger(s); "
        f"{summary['retry_like_sessions']} retry-like (compiler miss)."
    )
    print("[classify] bucket hits:")
    for bucket in BUCKETS:
        print(f"  {bucket:22s} {summary['bucket_totals'][bucket]}")
    print("[classify] aggregate repeated-pattern statistics:")
    for kind in _PATTERN_KINDS:
        stats = report["pattern_statistics"][kind]
        print(
            f"  {kind:8s} sessions={stats['sessions_with_repeats']} "
            f"patterns={stats['distinct_in_session_patterns']} "
            f"excess={stats['excess_repetitions']}"
        )
    rows = scan["rows"]
    files = scan["files"]
    print(
        f"[classify] disclosure: files={files['scanned']} bytes={scan['bytes_read']} "
        f"invalid_rows={rows['invalid_total']} truncated={scan['truncation']['occurred']}"
    )
    sensitive = report.get("sensitive_content")
    if not isinstance(sensitive, dict):
        return
    print("[classify] sensitive content was explicitly requested:")
    for session in sensitive["sessions"]:
        print(f"  source={json.dumps(session['source_path'], ensure_ascii=True)} buckets={session['buckets']}")
        for kind, patterns in session["repeated_patterns"].items():
            for item in patterns:
                print(f"    {kind} x{item['count']}: {json.dumps(item['content'], ensure_ascii=True)}")


def _bounded_positive_int(name: str, hard_max: int) -> Callable[[str], int]:
    def parse(raw: str) -> int:
        try:
            value = int(raw)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{name} must be an integer") from exc
        if value < 1 or value > hard_max:
            raise argparse.ArgumentTypeError(f"{name} must be between 1 and {hard_max}")
        return value

    return parse


def _empty_error_report(code: str, limits: ScanLimits, disclosure: ScanDisclosure) -> dict[str, object]:
    report = _build_report([], limits, disclosure, False, 0)
    report["error"] = {
        "code": code,
        "message": "Pass an explicit ledger file/directory or --claude-ledger-root.",
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*", type=Path, help="Explicit session .jsonl files or directories.")
    parser.add_argument(
        "--claude-ledger-root",
        action="append",
        default=[],
        type=Path,
        help="Explicit Claude projects/ledger root; may be repeated.",
    )
    parser.add_argument(
        "--include-sensitive-content",
        action="store_true",
        help="Include bounded prompt/command/path samples. Default output is aggregate-only.",
    )
    parser.add_argument(
        "--max-files",
        "--limit",
        dest="max_files",
        type=_bounded_positive_int("max-files", HARD_MAX_FILES),
        default=DEFAULT_MAX_FILES,
        help="Maximum ledger files to scan; --limit is a compatibility alias and zero is rejected.",
    )
    parser.add_argument(
        "--max-discovery-entries",
        type=_bounded_positive_int("max-discovery-entries", HARD_MAX_DISCOVERY_ENTRIES),
        default=DEFAULT_MAX_DISCOVERY_ENTRIES,
    )
    parser.add_argument(
        "--max-total-bytes",
        type=_bounded_positive_int("max-total-bytes", HARD_MAX_TOTAL_BYTES),
        default=DEFAULT_MAX_TOTAL_BYTES,
    )
    parser.add_argument(
        "--max-file-bytes",
        type=_bounded_positive_int("max-file-bytes", HARD_MAX_FILE_BYTES),
        default=DEFAULT_MAX_FILE_BYTES,
    )
    parser.add_argument(
        "--max-line-bytes",
        type=_bounded_positive_int("max-line-bytes", HARD_MAX_LINE_BYTES),
        default=DEFAULT_MAX_LINE_BYTES,
    )
    parser.add_argument(
        "--max-lines-per-file",
        type=_bounded_positive_int("max-lines-per-file", HARD_MAX_LINES_PER_FILE),
        default=DEFAULT_MAX_LINES_PER_FILE,
    )
    parser.add_argument("--top", type=_bounded_positive_int("top", HARD_MAX_TOP), default=DEFAULT_TOP)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of prose.")
    args = parser.parse_args(argv)

    limits = ScanLimits(
        max_files=args.max_files,
        max_discovery_entries=args.max_discovery_entries,
        max_total_bytes=args.max_total_bytes,
        max_file_bytes=args.max_file_bytes,
        max_line_bytes=args.max_line_bytes,
        max_lines_per_file=args.max_lines_per_file,
    )
    disclosure = ScanDisclosure()
    sources = [*args.paths, *args.claude_ledger_root]
    if not sources:
        report = _empty_error_report("explicit_source_required", limits, disclosure)
        if args.json:
            json.dump(report, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        else:
            print("[classify] explicit source required; no home directory was scanned.", file=sys.stderr)
        return 2

    candidates = _discover_session_ledgers(sources, limits, disclosure)
    key = secrets.token_bytes(32)
    budget = ReadBudget(limits.max_total_bytes)
    sessions: list[SessionAnalysis] = []
    for index, candidate in enumerate(candidates):
        if budget.remaining <= 0:
            disclosure.total_byte_limit_reached = True
            disclosure.files_skipped_total_budget += len(candidates) - index
            break
        session = _classify_candidate(
            candidate,
            limits,
            budget,
            disclosure,
            key,
            args.include_sensitive_content,
        )
        if session is not None:
            sessions.append(session)

    report = _build_report(sessions, limits, disclosure, args.include_sensitive_content, args.top)
    if args.json:
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        _print_prose_report(report)
    return 0 if sessions else 1


if __name__ == "__main__":
    raise SystemExit(main())
