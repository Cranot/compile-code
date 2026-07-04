#!/usr/bin/env python3
"""Classify Claude Code session ledgers into prompt-compiler misses.

Developer-only — not part of the shipped product surface and not wired into
``scripts/check.py``'s gate. Run by hand::

    python3 scripts/classify_sessions.py             # scan default ledgers
    python3 scripts/classify_sessions.py PATH...     # one or more .jsonl / dirs
    python3 scripts/classify_sessions.py --json      # machine-readable

The compile loop's whole pitch is that it pre-resolves repo facts *before* the
agent's first token, so the agent answers instead of re-grepping. A session
ledger (.jsonl transcript) is therefore ground truth for whether that worked:
a session where the agent re-derived something is a session the compiler
*should* have pre-resolved but didn't — a compiler miss. We bucket each ledger
by three retry-like signatures:

  repeated_tool_use     the same Bash command or Read file_path ran >= 2× —
                        the agent re-grepped / re-read instead of answering
                        from a pre-compiled envelope.
  repeated_prompt       the same user-prompt text was sent >= 2× in one session
                        (a literal retry) or recurs as the primary prompt across
                        >= 2 ledgers (an autopilot retry of the same backlog
                        item).
  verify_fail_aftermath a verify-shaped step (``check.py`` / ``roam verify`` /
                        ``pytest`` / ``ruff``) exited nonzero AND the session
                        kept working afterwards — the agent cleaned up a verify
                        failure the loop surfaced.

A session landing in any bucket is flagged as a compiler miss. None of this
touches the product: it reads ledgers only and prints a summary.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Callable
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# Commands whose nonzero exit (or printed failure) is a verify signal the agent
# must clean up. Kept broad on purpose: this repo's gate is check.py, the
# kernel's is `roam verify`, and CI shells out to pytest/ruff directly.
VERIFY_RE = re.compile(r"\b(?:check\.py|roam\s+verify|pytest|ruff(?:\s+check|\s+format)?|verify)\b")
# Result-content fallback for tools that report failure without a nonzero exit.
FAIL_MARKERS = ("Traceback", "BLOCKED", "FAILED", "FAIL:", "tests failed", "error:")
FAIL_RE = re.compile("|".join(re.escape(marker) for marker in FAIL_MARKERS))

BUCKETS = ("repeated_tool_use", "repeated_prompt", "verify_fail_aftermath")


@dataclass
class SessionEvidence:
    """Ledger facts needed to decide whether a session is a compiler miss."""

    prompts: list[tuple[int, str]] = field(default_factory=list)
    bash_keys: list[tuple[int, str]] = field(default_factory=list)
    read_keys: list[tuple[int, str]] = field(default_factory=list)
    tool_uses: dict[object, tuple[int, str]] = field(default_factory=dict)
    results: dict[object, tuple[bool, str]] = field(default_factory=dict)


def _ledger_field(obj: dict[str, object], key: str, default: object = None) -> object:
    """Return a JSON object field without making local reads look like queries."""
    return obj[key] if key in obj else default


def _ledger_str_field(obj: dict[str, object], key: str) -> str:
    value = _ledger_field(obj, key, "")
    return value if isinstance(value, str) else ""


def _text_from_message_block(block: object) -> str | None:
    """Return text from one ledger content block when it is a text payload."""
    if not isinstance(block, dict):
        return None
    if "type" not in block or block["type"] != "text":
        return None
    raw_text = block["text"] if "text" in block else ""
    return (raw_text or "").strip() or None


def _real_user_text(content: object) -> str | None:
    """Return a real user prompt, or None for tool-result round-trips.

    A genuine user turn is either a bare string or a list containing a ``text``
    block; a ``tool_result``-only message is the tool round-trip, not a prompt.
    """
    if isinstance(content, str):
        return content.strip() or None
    if isinstance(content, list):
        text = None
        for block in content:
            text = _text_from_message_block(block) or text
        return text
    return None


def _tool_result_body_preserves_searchable_text(raw: object, json_dumps: Callable[[object], str]) -> str:
    """Return result content as text so failure markers remain searchable."""
    if isinstance(raw, str):
        return raw
    return json_dumps(raw) if raw else ""


def _iter_records(path: Path):
    """Yield parsed JSON records from a session ledger, skipping bad lines."""
    try:
        with path.open(encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    except OSError:
        return


def _index_user_turn_for_retry_evidence(evidence: SessionEvidence, idx: int, content: object) -> None:
    """Index user-role facts that can prove a retry-like session."""
    text = _real_user_text(content)
    if text:
        evidence.prompts.append((idx, text))
    if not isinstance(content, list):
        return
    hoisted_json_dumps = json.dumps
    hoisted_tool_result_body_preserves_searchable_text = _tool_result_body_preserves_searchable_text
    for block in content:
        if not isinstance(block, dict) or _ledger_field(block, "type") != "tool_result":
            continue
        raw = _ledger_field(block, "content")
        body = hoisted_tool_result_body_preserves_searchable_text(raw, hoisted_json_dumps)
        evidence.results[_ledger_field(block, "tool_use_id")] = (bool(_ledger_field(block, "is_error")), body)


def _index_assistant_turn_for_retry_evidence(evidence: SessionEvidence, idx: int, content: object) -> None:
    """Index assistant tool calls that can prove repeated work or verify cleanup."""
    if not isinstance(content, list):
        return
    hoisted_ledger_str_field = _ledger_str_field
    for block in content:
        if not isinstance(block, dict) or _ledger_field(block, "type") != "tool_use":
            continue
        name = _ledger_field(block, "name")
        inp = _ledger_field(block, "input", {})
        input_obj = inp if isinstance(inp, dict) else {}
        key = ""
        if name == "Bash":
            key = hoisted_ledger_str_field(input_obj, "command")
            evidence.bash_keys.append((idx, key))
        elif name == "Read":
            key = hoisted_ledger_str_field(input_obj, "file_path")
            evidence.read_keys.append((idx, key))
        if key:
            evidence.tool_uses[_ledger_field(block, "id")] = (idx, key)


def _iter_typed_records(path: Path):
    """Yield (index, role, content) for each user/assistant turn in a ledger."""
    hoisted_ledger_field = _ledger_field
    for idx, rec in enumerate(_iter_records(path)):
        if not isinstance(rec, dict):
            continue
        rtype = hoisted_ledger_field(rec, "type")
        if rtype not in ("user", "assistant"):
            continue
        msg = hoisted_ledger_field(rec, "message")
        if not isinstance(msg, dict):
            continue
        content = hoisted_ledger_field(msg, "content")
        yield idx, rtype, content


def _collect_retry_evidence_in_one_scan(path: Path) -> SessionEvidence:
    """Preserve one-pass ledger scanning while separating retry evidence rules."""
    evidence = SessionEvidence()
    for idx, rtype, content in _iter_typed_records(path):
        if rtype == "user":
            _index_user_turn_for_retry_evidence(evidence, idx, content)
        else:
            _index_assistant_turn_for_retry_evidence(evidence, idx, content)
    return evidence


def _retry_proving_repeats(pairs: list[tuple[int, str]]) -> dict[str, int]:
    counts = Counter(k for _, k in pairs if k)
    return {k: n for k, n in counts.items() if n >= 2}


def _first_verify_line_preserves_failure_signal(command: str) -> str:
    stripped = command.strip()
    return stripped.splitlines()[0][:80] if stripped else "(empty)"


def _tool_result_preserves_verify_failure_signal(is_err: bool, body: str) -> bool:
    return is_err or bool(FAIL_RE.search(body))


def _verify_candidates_preserve_failure_context(evidence: SessionEvidence) -> list[tuple[object, int, str]]:
    """Return verify-shaped tool calls with the display text needed on failure."""
    verify_candidates: list[tuple[object, int, str]] = []
    for tid, (idx, cmd) in evidence.tool_uses.items():
        if not VERIFY_RE.search(cmd):
            continue
        verify_candidates.append((tid, idx, _first_verify_line_preserves_failure_signal(cmd)))
    return verify_candidates


def _verify_failures_with_aftermath(evidence: SessionEvidence) -> tuple[list[str], bool]:
    # Verify-fail aftermath: a verify-shaped Bash step failed at index F and at
    # least one tool call or prompt came after the earliest such F. Using the
    # first failure keeps the signature "the session continued past a failure".
    verify_fails: list[str] = []
    fail_indices: list[int] = []
    hoisted_tool_result_preserves_verify_failure_signal = _tool_result_preserves_verify_failure_signal
    for tid, idx, first_line in _verify_candidates_preserve_failure_context(evidence):
        is_err, body = evidence.results[tid] if tid in evidence.results else (False, "")
        if not hoisted_tool_result_preserves_verify_failure_signal(is_err, body):
            continue
        verify_fails.append(first_line)
        fail_indices.append(idx)
    # Guard the empty case explicitly: min() on an empty list would otherwise
    # raise, and the `and` below would not short-circuit an eager generator.
    first_fail = min(fail_indices) if fail_indices else -1
    activity_indices = [j for j, _ in evidence.bash_keys + evidence.read_keys + evidence.prompts]
    aftermath = first_fail >= 0 and any(i > first_fail for i in activity_indices)
    return verify_fails, aftermath


def classify_session(path: Path) -> dict:
    """Bucket one session ledger; return per-bucket flags plus the evidence."""
    evidence = _collect_retry_evidence_in_one_scan(path)
    bash_repeats = _retry_proving_repeats(evidence.bash_keys)
    read_repeats = _retry_proving_repeats(evidence.read_keys)
    prompt_repeats = _retry_proving_repeats(evidence.prompts)
    verify_fails, aftermath = _verify_failures_with_aftermath(evidence)

    return {
        "path": str(path),
        "buckets": {
            "repeated_tool_use": bool(bash_repeats or read_repeats),
            "repeated_prompt": bool(prompt_repeats),
            "verify_fail_aftermath": bool(verify_fails and aftermath),
        },
        "counts": {
            "bash_repeats": bash_repeats,
            "read_repeats": read_repeats,
            "prompt_repeats": prompt_repeats,
            "verify_fails": verify_fails,
        },
        "primary_prompt": evidence.prompts[0][1][:200] if evidence.prompts else "",
        "n_prompts": len(evidence.prompts),
    }


def _default_scan_dirs() -> list[Path]:
    """Ledger locations: an explicit profile dir, then the home default."""
    dirs: list[Path] = []
    profile = os.environ.get("CLAUDE_PROFILE_DIR")
    if profile:
        dirs.append(Path(profile) / ".claude" / "projects")
    dirs.append(Path.home() / ".claude" / "projects")
    return dirs


def _gather(paths: list[Path]) -> list[Path]:
    """Resolve CLI paths to .jsonl files, or fall back to default scan dirs."""
    if paths:
        files: list[Path] = []
        for p in paths:
            if p.is_dir():
                files.extend(sorted(p.rglob("*.jsonl")))
            elif p.suffix == ".jsonl":
                files.append(p)
        return files
    files = []
    for d in _default_scan_dirs():
        if d.is_dir():
            files.extend(sorted(d.rglob("*.jsonl")))
    return files


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("paths", nargs="*", type=Path, help="Session .jsonl files or dirs (default: scan Claude ledgers).")
    ap.add_argument("--limit", type=int, default=0, help="Cap sessions scanned (0 = no cap).")
    ap.add_argument("--top", type=int, default=15, help="Detail rows / clusters to print.")
    ap.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of prose.")
    ns = ap.parse_args(argv)

    files = _gather(ns.paths)
    if ns.limit:
        files = files[: ns.limit]
    if not files:
        print("[classify] no session ledgers found (pass a path or set CLAUDE_PROFILE_DIR).", file=sys.stderr)
        return 1

    sessions = [classify_session(p) for p in files]
    flagged = [s for s in sessions if any(s["buckets"].values())]
    bucket_totals = {b: sum(1 for s in sessions if s["buckets"][b]) for b in BUCKETS}

    # Cross-session retry clusters: the same primary prompt driving >= 2 ledgers.
    by_prompt: dict[str, list[str]] = defaultdict(list)
    for s in sessions:
        if s["primary_prompt"]:
            by_prompt[s["primary_prompt"]].append(s["path"])
    retry_clusters = {p: paths for p, paths in by_prompt.items() if len(paths) >= 2}

    if ns.json:
        json.dump(
            {
                "scanned": len(sessions),
                "flagged": len(flagged),
                "bucket_totals": bucket_totals,
                "retry_clusters": retry_clusters,
                "sessions": sessions,
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
        return 0

    print(f"[classify] scanned {len(sessions)} session ledger(s); {len(flagged)} retry-like (compiler miss).")
    print("[classify] bucket hits:")
    for b in BUCKETS:
        print(f"  {b:22s} {bucket_totals[b]}")
    if retry_clusters:
        ranked = sorted(retry_clusters.items(), key=lambda kv: len(kv[1]), reverse=True)[: ns.top]
        print(f"[classify] cross-session retry clusters ({len(retry_clusters)} prompt(s), top {len(ranked)}):")
        for prompt, paths in ranked:
            print(f"  [{len(paths)}x] {prompt[:90]}")
    print(f"[classify] top {min(ns.top, len(flagged))} retry-like session(s):")
    for s in sorted(flagged, key=lambda s: sum(s["buckets"].values()), reverse=True)[: ns.top]:
        tags = ",".join(b for b in BUCKETS if s["buckets"][b]) or "-"
        print(f"  [{tags}] {Path(s['path']).name}")
        for cmd, n in sorted(s["counts"]["bash_repeats"].items(), key=lambda kv: kv[1], reverse=True)[:2]:
            print(f"        bash x{n}: {cmd[:70]}")
        for fp, n in sorted(s["counts"]["read_repeats"].items(), key=lambda kv: kv[1], reverse=True)[:2]:
            print(f"        read x{n}: {fp}")
        if s["counts"]["verify_fails"]:
            print(f"        verify-fail: {s['counts']['verify_fails'][0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
