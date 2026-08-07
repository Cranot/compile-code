#!/usr/bin/env python3
"""prepush_leak_scan.py -- the BLOCKING pre-push leak gate over PUSHED HISTORY.

``scripts/check.py``'s ``leak_scan()`` (and CI's ``scripts/secret_scan.py``)
scan the current tracked-plus-new candidate tree. That is blind to a secret or internal-only
string that was committed and then "fixed" by a LATER commit in the same
push: the final tree is clean, but the blob object for the earlier commit
still travels to the remote and is retrievable from history forever. For a
public remote, purging history after the fact does not un-publish it -- the
bytes may already be cloned, cached, or indexed. This is the same failure
shape that forced a history purge for a customer-name leak elsewhere in this
project's toolchain (roam-code / stoa's ROADMAP 4.3).

This script closes that gap by scanning the EXACT commit range about to
leave the machine, not the working tree: every commit's message and the
full new content of every path it touches, using the same two pattern
catalogues the whole-tree gates already use --
``scripts.check.LEAK_PATTERNS`` (credential shapes + private-infrastructure
strings) and ``scripts.secret_scan.SECRET_PATTERN_DEFS`` (the broader
credential catalogue, masked/entropy-filtered). Reusing the catalogues
(rather than a third pattern list) means a pattern only needs tightening or
adding in one place to close a gap in both the tree scan and the range scan.

RANGE RESOLUTION: see prepush_refs.py (stdlib-only, copy-portable; ported
from stoa's autopilot/prepush_refs.py, itself ported from roam-code's
scripts/prepush_refs.py). Reads git's pre-push stdin ref-update stream via
--pre-push-updates (the authoritative source: local/remote ref + oid per
updated ref, including the first-push-of-a-new-branch case where the remote
oid is all-zero, and the deletion case where the local oid is all-zero). A
--range REV..REV override is provided for manual runs and testing without
constructing a stdin capture file. With neither flag (manual/standalone
invocation), falls back to this branch's configured upstream (@{u}); if none
is configured, refuses to guess and fails closed rather than silently
scanning nothing.

PERFORMANCE: one git subprocess per commit (times two or three surfaces) is
slow enough to tempt --no-verify once a push carries more than a handful of
commits. Every git call below is therefore BATCHED across the whole commit
range: one `diff-tree --stdin` call for changed paths + blob oids, one
`cat-file --batch` call for every commit message and every blob's content.
Total git subprocess count is O(1) in the number of commits (a small
constant), not O(commits) or O(files).

SIZE IS NOT A REASON TO REPORT CLEAN: a blob too large to scan is
UNANALYZABLE, which is a third state, not a synonym for "no findings". This
script used to floor an over-large blob to an empty list of text views, and
an empty list makes the scan loop iterate zero times -- so the blob's bytes
were rendered as `clean` and the push was authorised. One byte either side of
the threshold decided whether a credential was caught (4,194,304 -> BLOCKED;
4,194,305 -> clean), which means padding defeated the gate. Every blob is now
scanned regardless of size, in bounded line batches; the only remaining cap
is an absolute ceiling that is a LOUD REFUSAL (exit 3), never a silent skip.
Every invocation publishes its denominator -- blobs scanned, bytes scanned,
blobs skipped, blobs unanalyzable -- so "0 findings" can be checked against
how much was actually read.

A NAME IS NOT A MEASUREMENT: this script used to decide "binary, do not
open" from a path's suffix, so a plain-text file carrying a credential and
committed as `logo.png` was never read and the range printed `clean (1
commit(s) scanned, 0 findings; blobs: 0 scanned / 0 bytes, 0 binary-skipped,
1 path-filtered, 0 unanalyzable)` -- exit 0, the honest denominator right
there in the line and nothing acting on it. Binary is now decided from the
bytes (`inventory.is_binary_content`), the surviving path exclusions are
structural only, and the ledger is GATED: if the range changed paths and this
scanner opened no blob at all, the verdict is a refusal, not `clean`.

POSITIVE CONTROL: a scanner that reports clean while reading nothing is
indistinguishable from a clean repository unless it is asked to find
something it planted itself. Every invocation runs a sentinel blob carrying
one credential per catalogue through the same `_read_blob`/`_scan_text` path
the real blobs take (placed past the first line batch, so a batching bug that
drops the tail is caught too). If either planted credential is not found, the
scanner reports BROKEN and exits 4 rather than reporting 0 findings.

Exit codes: 0 = clean. 2 = leak(s) found. 3 = content this gate did not read
-- at least one blob was unanalyzable, or the range changed paths and no blob
was opened at all ("I could not check this" is a failure of the gate, not a pass).
4 = the scanner's own positive control failed -- it is broken, and its
verdict means nothing. 1 = usage error or a git command needed to resolve
the range failed (fail closed -- never silently pass). When more than one
applies the precedence is 4 > 2 > 3, and every applicable section is printed.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import check  # noqa: E402
import inventory  # noqa: E402
import prepush_refs  # noqa: E402
import secret_scan  # noqa: E402

# How many lines of one text view are handed to the catalogues at a time.
# Scanning is line-oriented in both catalogues (``secret_scan.scan_text``
# iterates ``splitlines()``; every ``LEAK_PATTERNS`` entry is confined to one
# line), so cutting on line boundaries cannot split a match -- no overlap
# window is needed and no finding or line number changes. Two things get
# strictly better, both measured on this repository's own toolchain:
#
#   * Peak decoded memory stops tracking blob size. A 16 MiB blob of ordinary
#     text peaked at +23.0 MiB scanned whole and +0.5 MiB scanned in batches.
#   * ``check._leak_pattern_hits`` resolves a match to a line number with
#     ``text.count("\n", 0, m.start())``, which is O(text) PER MATCH -- i.e.
#     quadratic in a blob with many matches. Batching bounds the ``text`` in
#     that expression: a 4.9 MiB match-dense blob went from 50.9s to 5.7s.
_SCAN_BATCH_LINES = 512

# Absolute ceiling on a single blob, and the ONLY cap left. Crossing it is a
# refusal (exit 3), not a skip -- see the module docstring. The number is not
# load-bearing for correctness: at any ceiling, over-size blocks rather than
# passes. It is a TIME budget, chosen from measurement rather than the memory
# guess the old 4 MiB cap was justified by (a guess that was already false --
# ``_batch_blobs_and_messages`` has the whole blob resident in memory before
# anything here sees it, so skipping the decode saved no allocation at all).
# Measured end-to-end throughput of the two catalogues on this machine is
# ~1 MiB/s for line-dense text and ~4 MiB/s for minified single-line text, so
# 16 MiB bounds one pathological blob at roughly 16 seconds. For scale, the
# largest blob anywhere in this repository's history is 191 KB.
_SCAN_CEILING_BYTES = 16 * 1024 * 1024

# The three dispositions a blob can have. Explicitly three-valued: the defect
# this replaced used list-emptiness as its only channel, which collapsed
# "nothing found in it" and "never looked at it" into the same answer.
_SCANNED = "scanned"
_SKIPPED_BINARY = "skipped-binary"
_UNANALYZABLE = "unanalyzable"

Finding = tuple[str, int, str, str]  # (label, line_no, kind, detail)


@dataclass
class _Ledger:
    """The denominator behind the verdict: what was read, and what was not.

    Printed on every invocation, clean or not. "0 findings" is only meaningful
    next to how many blobs and bytes produced it -- this scanner has already
    demonstrated once that it can report clean having decoded nothing.

    The counts are split by WHY content went unread, because those states are
    not equivalent. ``binary_skipped`` bytes were read and classified.
    ``path_filtered`` bytes were never opened -- a decision from the path
    alone -- which is the same epistemic state as ``unanalyzable`` and is why
    ``considered`` and ``opened`` exist: a range that changed files while this
    scanner opened none of them has no basis for the word "clean".

    ``corpus_exempt`` is deliberately outside ``considered``. It is one named,
    reviewed path (``scripts/secret_scan.py``'s ``_OWN_TEST_CORPUS_FILES``)
    whose content is secret-shaped by construction -- a decided exemption, not
    a guess about unknown content, and the only path filter of that kind.
    """

    blobs_scanned: int = 0
    bytes_scanned: int = 0
    considered: int = 0
    path_filtered: list[str] = field(default_factory=list)
    corpus_exempt: list[str] = field(default_factory=list)
    binary_skipped: list[tuple[str, int]] = field(default_factory=list)
    unanalyzable: list[tuple[str, int, str]] = field(default_factory=list)

    @property
    def opened(self) -> int:
        """Blobs whose bytes this scanner actually held and classified."""
        return self.blobs_scanned + len(self.binary_skipped) + len(self.unanalyzable)

    def summary(self) -> str:
        return (
            f"blobs: {self.blobs_scanned} scanned / {self.bytes_scanned} bytes, "
            f"{len(self.binary_skipped)} binary-skipped, {len(self.path_filtered)} path-filtered, "
            f"{len(self.corpus_exempt)} corpus-exempt, {len(self.unanalyzable)} unanalyzable"
        )


def _git_bytes(repo_root: str, args: list[str], *, operation: str, input_bytes: bytes | None = None) -> bytes:
    proc = subprocess.run(
        ["git", "--no-replace-objects", *args],
        cwd=repo_root,
        input=input_bytes,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()
        raise prepush_refs.PrePushGitError(f"{operation} failed (git exit {proc.returncode}): {detail}")
    return proc.stdout


def _repo_root() -> str:
    raw = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, check=False)
    if raw.returncode != 0 or not raw.stdout.strip():
        sys.stderr.write("ERROR: not inside a git repository (git rev-parse failed).\n")
        raise SystemExit(1)
    return raw.stdout.decode("utf-8", errors="replace").strip()


class _Reading(NamedTuple):
    """What this scanner did with one blob, said out loud.

    ``disposition`` is one of ``_SCANNED`` / ``_SKIPPED_BINARY`` /
    ``_UNANALYZABLE``. It is a separate field from ``views`` on purpose: the
    predecessor of this type was a bare ``list[str]`` whose emptiness meant
    "skip", and a caller that iterates an empty list zero times cannot tell
    that apart from having scanned the content and found nothing. That is
    exactly how a 4 MiB+ blob carrying a live credential was rendered as
    ``clean`` with exit 0.
    """

    disposition: str
    views: list[str]
    reason: str


def _read_blob(data: bytes) -> _Reading:
    """Every text reading of a historical blob, plus what was NOT read and why.

    ``check._scan_views`` is the landed working-tree rule (f84025f); routing
    pushed history through it is what closes the gap that commit recorded as
    still open here. A UTF-16 blob used to be dropped by the ``b"\\x00" in
    data`` binary test, so a credential committed in a UTF-16 file published
    with the push while this gate reported clean — and purging history after a
    push does not un-publish it. Windows PowerShell's ``>`` and ``Out-File``
    emit UTF-16LE by default, which is how such a file gets committed at all.

    Size is no longer a reason to read nothing: blobs of ANY size up to the
    absolute ceiling are scanned, in bounded batches, and crossing the ceiling
    is a refusal the caller must surface, not a quiet ``[]``.

    Genuine binary is still not pattern-matched — the conservation rule from
    the UTF-16 fix, since a gate buried in noise from every committed object
    file is a gate that gets bypassed — but it is now DISCLOSED in the
    denominator rather than silently dropped. It stays non-fatal because the
    bytes were read and classified: that is a decision about this content, not
    an admission that the scanner could not look.
    """
    if len(data) > _SCAN_CEILING_BYTES:
        return _Reading(_UNANALYZABLE, [], f"exceeds the {_SCAN_CEILING_BYTES}-byte scan ceiling")
    if inventory.is_binary_content(data):
        return _Reading(_SKIPPED_BINARY, [], "binary content (NUL bytes, not UTF-16 text)")
    return _Reading(_SCANNED, check._scan_views(data), "")


def _line_batches(text: str):
    """Yield ``(first_line_no, batch_text)`` covering *text* exactly once.

    Every batch ends on a line boundary (or at the end of *text*), so a match
    can never straddle two batches and no overlap window is required: both
    catalogues match within a single line by construction. ``first_line_no``
    is the 1-based line number of the batch's first line in the whole text, so
    a hit reported at local line ``n`` sits at ``first_line_no + n - 1``.

    A blob with no newlines at all — a minified bundle, say — yields one batch
    holding the whole text, which is correct rather than merely tolerated: it
    is one line, and there is no boundary to cut on.
    """
    start, line_no, size = 0, 1, len(text)
    while start < size:
        end, newlines = start, 0
        while newlines < _SCAN_BATCH_LINES:
            nl = text.find("\n", end)
            if nl == -1:
                end = size
                break
            end = nl + 1
            newlines += 1
        yield line_no, text[start:end]
        start = end
        line_no += newlines


def _scan_text(label: str, text: str) -> list[Finding]:
    """Apply BOTH catalogues to *text* in bounded line batches.

    Single entry point for every surface this script inspects — commit
    identity, commit message, and blob content — so the positive control
    exercises the same code every real finding travels through.
    """
    findings: list[Finding] = []
    for first_line, batch in _line_batches(text):
        for line_no, kind in check._leak_pattern_hits(batch):
            findings.append((label, first_line + line_no - 1, kind, "redacted match"))
        for hit in secret_scan.scan_text(label, batch):
            findings.append((label, first_line + hit["line"] - 1, hit["pattern_name"], hit["matched_text"]))
    return findings


def _path_disposition(path: str) -> str:
    """Why (or whether) this path's blob goes unopened -- decided by NAME.

    Only structural exclusions remain here. The suffix test that used to be
    the last line of this function decided "binary" from the file name, so a
    plain-text credential file committed as ``logo.png`` was never opened and
    the range printed ``clean`` with ``0 scanned / 0 bytes``. Binary is now
    decided from the bytes in ``_read_blob``, where the evidence is.
    """
    if secret_scan._is_own_test_corpus(path):
        return "corpus-exempt"
    if check._path_is_committed_artifact(path) or secret_scan._in_skip_dir(path):
        return "path-filtered"
    return "scan"


# --- batched git access -----------------------------------------------------
# Both functions below issue exactly ONE git subprocess for the entire commit
# range, using `--stdin` batch modes and matching each output record back to
# its commit by checking a line against the caller-supplied set of requested
# SHAs -- not a generic "looks like a hex string" regex, since a file's own
# content could coincidentally contain a hex-looking line. Only a line that
# is EXACTLY one of the SHAs we asked about can start a new block.


def _batch_changed_paths(repo_root: str, shas: list[str]) -> dict[str, list[tuple[str, str]]]:
    """Return {sha: [(path, new_blob_oid), ...]} for every commit in *shas*.

    No rename detection (``-M``/``-C`` not passed) is deliberate: without it,
    a rename is reported as a plain delete (filtered by --diff-filter=d) plus
    a plain add of the new path, which is exactly the content newly present
    at this commit under this path -- precisely what needs scanning.
    """
    if not shas:
        return {}
    sha_set = set(shas)
    stdin = ("\n".join(shas) + "\n").encode("ascii")
    raw = _git_bytes(
        repo_root,
        ["diff-tree", "--raw", "-r", "--root", "-m", "--always", "--diff-filter=d", "--stdin"],
        operation="batch-list changed paths",
        input_bytes=stdin,
    )
    text = raw.decode("utf-8", errors="replace")
    result: dict[str, list[tuple[str, str]]] = {sha: [] for sha in shas}
    headers_seen: set[str] = set()
    current: str | None = None
    for line in text.split("\n"):
        if not line:
            continue
        if line in sha_set:
            current = line
            headers_seen.add(line)
            continue
        if line.startswith(":"):
            if current is None:
                raise prepush_refs.PrePushGitError(f"diff-tree --stdin output before any commit header: {line!r}")
            meta, sep, path = line.partition("\t")
            if not sep:
                raise prepush_refs.PrePushGitError(f"malformed diff-tree raw entry: {line!r}")
            fields = meta.split(" ")
            if len(fields) < 5:
                raise prepush_refs.PrePushGitError(f"malformed diff-tree raw entry: {line!r}")
            new_oid = fields[3]
            result[current].append((path, new_oid))
            continue
        raise prepush_refs.PrePushGitError(f"unexpected diff-tree --stdin line: {line!r}")
    try:
        inventory.require_complete_inventory(shas, headers_seen, label="diff-tree per-commit path inventory")
    except inventory.InventoryError as exc:
        raise prepush_refs.PrePushGitError(str(exc)) from exc
    return result


def _batch_blobs_and_messages(
    repo_root: str, commit_shas: list[str], blob_oids: list[str]
) -> tuple[dict[str, str], dict[str, bytes]]:
    """One `git cat-file --batch` call for every commit object (kept whole)
    and every blob object (its content) needed anywhere in the range.
    Returns ({commit_sha: full_commit_object_text}, {blob_oid: raw_bytes}).

    The commit object is kept WHOLE -- header included -- because the
    `author` and `committer` header lines carry a name and an email address
    that publish with the commit exactly like its message does, and are
    exactly as unremovable afterwards. This function used to discard the
    header and return only the message, which left that surface unscanned.
    `_scan_range` splits the two apart so each is reported under its own
    label with its own line numbers."""
    commit_objs: dict[str, str] = {}
    blobs: dict[str, bytes] = {}
    all_oids = list(dict.fromkeys([*commit_shas, *blob_oids]))
    if not all_oids:
        return commit_objs, blobs

    stdin = ("\n".join(all_oids) + "\n").encode("ascii")
    proc = subprocess.run(
        ["git", "--no-replace-objects", "cat-file", "--batch"],
        cwd=repo_root,
        input=stdin,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()
        raise prepush_refs.PrePushGitError(f"cat-file --batch failed (git exit {proc.returncode}): {detail}")

    data = proc.stdout
    pos = 0
    seen: set[str] = set()
    while pos < len(data):
        nl = data.find(b"\n", pos)
        if nl == -1:
            raise prepush_refs.PrePushGitError("cat-file --batch: truncated header")
        header = data[pos:nl].decode("ascii", errors="replace")
        pos = nl + 1
        if header.endswith(" missing"):
            oid = header[: -len(" missing")]
            raise prepush_refs.PrePushGitError(f"cat-file --batch: object {oid} is missing")
        parts = header.split(" ")
        if len(parts) != 3:
            raise prepush_refs.PrePushGitError(f"cat-file --batch: malformed header {header!r}")
        oid, obj_type, size_str = parts
        size = int(size_str)
        content = data[pos : pos + size]
        pos += size
        if pos >= len(data) or data[pos : pos + 1] != b"\n":
            raise prepush_refs.PrePushGitError(f"cat-file --batch: missing trailing newline after {oid}")
        pos += 1
        seen.add(oid)
        if obj_type == "commit":
            commit_objs[oid] = content.decode("utf-8", errors="replace")
        elif obj_type == "blob":
            blobs[oid] = content
        # tree/tag objects can appear if a caller ever asks for one; neither
        # surface needs them, so they're read (keeping the stream aligned)
        # and discarded.

    missing = set(all_oids) - seen
    if missing:
        raise prepush_refs.PrePushGitError(f"cat-file --batch: no record returned for {sorted(missing)[:5]}")
    return commit_objs, blobs


def _scan_range(repo_root: str, shas: list[str]) -> tuple[list[Finding], _Ledger]:
    """Scan every commit's message and the full new content of every path it
    touches. Full-blob content (not just the commit's own diff) matters
    because a pure rename or a change elsewhere in the file can leave a
    leaked line present without it ever appearing as an added line in that
    commit's own patch.

    Returns the findings AND the ledger of what was read to produce them, so
    the caller can publish the denominator and refuse to call an unanalyzable
    blob clean."""
    findings: list[Finding] = []
    ledger = _Ledger()

    changed = _batch_changed_paths(repo_root, shas)

    wanted_paths: dict[str, str] = {}  # blob oid -> path, for surviving (unskipped) entries per commit
    per_commit_paths: dict[str, list[tuple[str, str]]] = {}
    for sha in shas:
        keep: list[tuple[str, str]] = []
        for path, oid in changed.get(sha, []):
            disposition = _path_disposition(path)
            if disposition == "corpus-exempt":
                ledger.corpus_exempt.append(f"{sha[:10]}:{path}")
                continue
            ledger.considered += 1
            if disposition == "path-filtered":
                ledger.path_filtered.append(f"{sha[:10]}:{path}")
                continue
            keep.append((path, oid))
        per_commit_paths[sha] = keep
        for path, oid in keep:
            wanted_paths[oid] = path

    commit_objs, blobs = _batch_blobs_and_messages(repo_root, shas, list(wanted_paths.keys()))

    for sha in shas:
        short = sha[:10]

        # A commit object is "<header block>\n\n<message>". Scan both halves.
        # If the separator is absent the object is malformed; treat the whole
        # thing as header so it is still scanned rather than silently dropped.
        raw_commit = commit_objs.get(sha, "")
        header, sep, message = raw_commit.partition("\n\n")
        if not sep:
            header, message = raw_commit, ""

        # Identity metadata publishes with the commit and cannot be edited
        # out afterwards any more than the message can. A real name, a
        # personal address, or an employer domain left in user.name /
        # user.email travels to the remote in these two lines.
        identity = "\n".join(line for line in header.splitlines() if line.startswith(("author ", "committer ")))
        findings += _scan_text(f"{short} (commit identity)", identity)
        findings += _scan_text(f"{short} (commit message)", message)

        for path, oid in per_commit_paths.get(sha, []):
            path_label = f"{short}:{path}"
            raw = blobs.get(oid)
            if raw is None:
                continue
            reading = _read_blob(raw)
            if reading.disposition == _UNANALYZABLE:
                ledger.unanalyzable.append((path_label, len(raw), reading.reason))
                continue
            if reading.disposition == _SKIPPED_BINARY:
                ledger.binary_skipped.append((path_label, len(raw)))
                continue
            ledger.blobs_scanned += 1
            ledger.bytes_scanned += len(raw)
            for text in reading.views:
                findings += _scan_text(path_label, text)

    return findings, ledger


def _dedupe(findings: list[Finding]) -> list[Finding]:
    return list(dict.fromkeys(findings))


def _print_report(findings: list[Finding]) -> None:
    sys.stderr.write(f"\nBLOCKED: {len(findings)} potential leak(s) in the commits about to be pushed:\n")
    for label, line_no, kind, detail in findings[:20]:
        loc = f"{label}:{line_no}" if line_no else label
        sys.stderr.write(f"  {loc}  [{kind}] {detail}\n")
    if len(findings) > 20:
        sys.stderr.write(f"  ... and {len(findings) - 20} more\n")
    sys.stderr.write(
        "\n"
        "Remediation:\n"
        "  - Fixing the tree in a later commit does not un-publish history --\n"
        "    the earlier commit's blob still travels to the remote. Amend or\n"
        "    rebase the offending commit(s) (or drop them) and push again.\n"
        "  - False positive on a credential-shaped pattern? Tighten or exempt\n"
        "    it in scripts/secret_scan.py's SECRET_PATTERN_DEFS.\n"
        "  - False positive on a LEAK_PATTERNS entry? Tighten it in\n"
        "    scripts/check.py.\n"
        "  - Deliberate one-off bypass (rare, discouraged): git push --no-verify\n"
    )


def _print_unread_range(ledger: _Ledger) -> None:
    sys.stderr.write(
        f"\nUNSCANNED: this range changed {ledger.considered} path(s) and this gate opened none of them:\n"
    )
    for label in ledger.path_filtered[:20]:
        sys.stderr.write(f"  {label}  [excluded by path, content never read]\n")
    if len(ledger.path_filtered) > 20:
        sys.stderr.write(f"  ... and {len(ledger.path_filtered) - 20} more\n")
    sys.stderr.write(
        "\n"
        "This is NOT a pass. 'clean' here would rest on the commit messages\n"
        "alone: no blob's bytes were read, so the verdict was not computed\n"
        "from the content about to be published. Options:\n"
        "  - Do not publish these paths: they are build artifacts or skipped\n"
        "    directories, which the tree gates already refuse to track.\n"
        "  - Prove them by hand, then bypass this one push deliberately:\n"
        "    git push --no-verify\n"
    )


def _print_unscannable(ledger: _Ledger) -> None:
    sys.stderr.write(
        f"\nUNSCANNABLE: {len(ledger.unanalyzable)} blob(s) in the commits about to be pushed could not be scanned:\n"
    )
    for label, size, reason in ledger.unanalyzable:
        sys.stderr.write(f"  {label}  {size} bytes  [{reason}]\n")
    sys.stderr.write(
        "\n"
        "This is NOT a pass. Content this gate did not read is content it\n"
        "cannot call clean, and a blob that publishes unread publishes\n"
        "permanently. Options:\n"
        "  - Do not publish the blob: drop it from the range, or move it out\n"
        "    of git (release asset, LFS, generated at build time).\n"
        "  - Prove it by hand, then bypass this one push deliberately:\n"
        "    git push --no-verify\n"
        "  - Raising the ceiling in scripts/prepush_leak_scan.py is a\n"
        "    performance decision, not a fix: the point is that over-size\n"
        "    refuses instead of passing, at whatever the ceiling is.\n"
    )


# --- positive control -------------------------------------------------------
# Assembled by concatenation so this file's own source text never contains a
# contiguous match: the whole-tree gates (scripts/check.py's leak_scan and
# CI's scripts/secret_scan.py) read this file like any other, and only
# tests/test_secret_scan.py is path-exempt. Real credentials do not arrive
# pre-split, so this costs the catalogues nothing.
_CONTROL_LABEL = "<scanner positive control>"
_CONTROL_EXPECTED = ("AWS access key", "Anthropic OAuth Token")
_CONTROL_AWS = "AK" + "IA" + "S" * 16
_CONTROL_ANTHROPIC = "sk-" + "ant-" + "oat" + "01-" + "Aa9_-" * 12


def _control_blob() -> bytes:
    """A sentinel blob planting one credential per catalogue, past a batch edge.

    The filler runs one line beyond ``_SCAN_BATCH_LINES`` so the planted
    credentials land in the SECOND batch: a batching bug that scans only the
    first batch, or that drops the tail, fails this control instead of
    reporting a clean repository.
    """
    filler = "# positive control filler\n" * (_SCAN_BATCH_LINES + 1)
    return f'{filler}aws = "{_CONTROL_AWS}"\nkey = "{_CONTROL_ANTHROPIC}"\n'.encode()


def _self_test_failures() -> list[str]:
    """Empty iff the scanner can still find something it planted itself.

    A scanner that reads nothing reports exactly what a clean repository
    reports. This one has already demonstrated it can do that -- an over-size
    blob decoded to an empty view list and every downstream loop ran zero
    times, printing ``clean``. So "0 findings" and "the scanner stopped
    working" must stop being the same output, and the only way to tell them
    apart is to require a known-positive on every run, through the same
    ``_read_blob``/``_scan_text`` path a real blob takes.
    """
    reading = _read_blob(_control_blob())
    if reading.disposition != _SCANNED:
        return [f"control blob was not scanned (disposition={reading.disposition!r}: {reading.reason})"]
    if not reading.views:
        return ["control blob decoded to zero text views"]
    kinds = {kind for view in reading.views for _, _, kind, _ in _scan_text(_CONTROL_LABEL, view)}
    return [f"planted control credential not detected: {name}" for name in _CONTROL_EXPECTED if name not in kinds]


def _resolve_commits(repo_root: str, args: argparse.Namespace) -> list[str]:
    if args.range:
        raw = _git_bytes(repo_root, ["rev-list", args.range], operation=f"resolve range {args.range}")
        return [s for s in raw.decode("ascii", errors="strict").split() if s]

    if args.pre_push_updates:
        if args.pre_push_updates == "-":
            text = sys.stdin.read()
        else:
            try:
                text = Path(args.pre_push_updates).read_text(encoding="utf-8")
            except OSError as exc:
                sys.stderr.write(f"ERROR: cannot read --pre-push-updates {args.pre_push_updates}: {exc}\n")
                raise SystemExit(1) from exc
        try:
            updates = prepush_refs.parse_pre_push_updates(text)
        except prepush_refs.PrePushUpdateError as exc:
            sys.stderr.write(f"ERROR: malformed pre-push update stream: {exc}\n")
            raise SystemExit(1) from exc
        if not updates:
            # Git never invokes pre-push with zero updates; an empty stream
            # here means the capture step itself is broken. Fail closed.
            sys.stderr.write("ERROR: --pre-push-updates contained no ref updates.\n")
            raise SystemExit(1)
        return prepush_refs.resolve_commits(repo_root, updates, remote_name=args.remote_name)

    # No stdin capture supplied (manual/standalone run). Fall back to the
    # conventional "what am I about to push" range IF this branch has an
    # upstream configured; otherwise there is no safe default -- refuse to
    # guess and say so, rather than silently scanning nothing.
    proc = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        sys.stderr.write(
            "ERROR: no --range or --pre-push-updates given, and this branch has no\n"
            "  upstream (@{u}) to fall back to. Pass --range <rev>..<rev> or\n"
            "  --pre-push-updates <path> explicitly. Refusing to scan nothing.\n"
        )
        raise SystemExit(1)
    upstream = proc.stdout.decode("utf-8", errors="replace").strip()
    raw = _git_bytes(repo_root, ["rev-list", f"{upstream}..HEAD"], operation=f"resolve {upstream}..HEAD")
    return [s for s in raw.decode("ascii", errors="strict").split() if s]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--range", help="explicit rev-list range/rev, e.g. origin/main..HEAD (manual/test use)")
    mode.add_argument(
        "--pre-push-updates",
        dest="pre_push_updates",
        metavar="FILE",
        help="path to a captured pre-push stdin stream, or '-' for stdin",
    )
    parser.add_argument("--remote-name", default=None, help="git's $1 (informational)")
    parser.add_argument("--remote-url", default=None, help="git's $2 (informational)")
    args = parser.parse_args(argv)

    # Positive control FIRST, on every invocation including the ones that go
    # on to fail for other reasons: a broken scanner must not be able to
    # produce any verdict at all, not merely be caught on the happy path.
    broken = _self_test_failures()
    if broken:
        sys.stderr.write("\nBROKEN: prepush_leak_scan's own positive control failed:\n")
        for problem in broken:
            sys.stderr.write(f"  {problem}\n")
        sys.stderr.write(
            "\nThis scanner cannot find a credential it planted itself, so it\n"
            "cannot be trusted to report on the commits about to be pushed.\n"
            "Its '0 findings' would mean nothing. Fix the scanner; do not push.\n"
        )
        return 4

    repo_root = _repo_root()
    try:
        commits = _resolve_commits(repo_root, args)
    except prepush_refs.PrePushGitError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 1

    if not commits:
        print("prepush_leak_scan: clean (0 commits in range)")
        return 0

    try:
        raw_findings, ledger = _scan_range(repo_root, commits)
    except prepush_refs.PrePushGitError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 1
    findings = _dedupe(raw_findings)

    # The denominator publishes on EVERY path, clean or blocked. Without it
    # "0 findings" is unfalsifiable: it is what a working scan of a clean
    # range prints and also what a scan that read nothing prints. And it is
    # now ACTED on: a range that changed paths while this gate opened no blob
    # at all cannot be called clean, whichever rule kept the bytes closed.
    unread_range = ledger.considered > 0 and ledger.opened == 0
    if not findings and not ledger.unanalyzable and not unread_range:
        print(f"prepush_leak_scan: clean ({len(commits)} commit(s) scanned, 0 findings; {ledger.summary()})")
        for label, size in ledger.binary_skipped:
            print(f"  skipped (binary, not pattern-matched): {label}  {size} bytes")
        for label in ledger.path_filtered:
            print(f"  excluded by path (content not read): {label}")
        for label in ledger.corpus_exempt:
            print(f"  exempt (scanner's own test corpus): {label}")
        return 0

    sys.stderr.write(f"prepush_leak_scan: {len(commits)} commit(s) scanned; {ledger.summary()}\n")
    if findings:
        _print_report(findings)
    if ledger.unanalyzable:
        _print_unscannable(ledger)
    if unread_range:
        _print_unread_range(ledger)
    return 2 if findings else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
