#!/usr/bin/env python3
"""prepush_leak_scan.py -- the BLOCKING pre-push leak gate over PUSHED HISTORY.

``scripts/check.py``'s ``leak_scan()`` (and CI's ``scripts/secret_scan.py``)
scan the current TRACKED TREE. That is blind to a secret or internal-only
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

Exit codes: 0 = clean. 2 = leak(s) found. 1 = usage error or a git command
needed to resolve the range failed (fail closed -- never silently pass).
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import check  # noqa: E402
import prepush_refs  # noqa: E402
import secret_scan  # noqa: E402

# Defensive bound on a single blob's size before it is decoded and scanned.
# Neither catalogue defines one; a pathological huge tracked blob (e.g. a
# vendored data file) should be skipped, not decoded wholesale into memory.
_MAX_BLOB_BYTES = 4 * 1024 * 1024


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


# Everything a text file may legitimately contain outside the printable set.
_TEXT_CONTROL_CHARS = frozenset("\t\n\r\f\v")


def _is_utf16_text(data: bytes) -> bool:
    """True iff NUL-bearing *data* is UTF-16 text rather than binary.

    A byte-order mark settles it. Without one, the bytes are accepted as text
    only when removing the NUL padding leaves strictly-valid UTF-8 carrying no
    control characters a text file would not — which a PNG, a zip or an object
    file will not satisfy, so the binary skip below is preserved.
    """
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return True
    try:
        text = data.replace(b"\x00", b"").decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    return not any(ch < " " and ch not in _TEXT_CONTROL_CHARS for ch in text)


def _decode_views(data: bytes) -> list[str]:
    """Every text reading of a historical blob; empty means 'skip'.

    ``check._scan_views`` is the landed working-tree rule (f84025f); routing
    pushed history through it is what closes the gap that commit recorded as
    still open here. A UTF-16 blob used to be dropped by the ``b"\\x00" in
    data`` binary test, so a credential committed in a UTF-16 file published
    with the push while this gate reported clean — and purging history after a
    push does not un-publish it. Windows PowerShell's ``>`` and ``Out-File``
    emit UTF-16LE by default, which is how such a file gets committed at all.

    Genuine binary is still skipped, and over-large blobs still are too.
    """
    if len(data) > _MAX_BLOB_BYTES:
        return []
    if b"\x00" in data and not _is_utf16_text(data):
        return []
    return check._scan_views(data)


def _should_scan_path(path: str) -> bool:
    if check._path_is_committed_artifact(path):
        return False
    if secret_scan._in_skip_dir(path):
        return False
    if secret_scan._is_own_test_corpus(path):
        return False
    return Path(path).suffix.lower() not in secret_scan._BINARY_EXTENSIONS


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
        ["diff-tree", "--raw", "-r", "--root", "-m", "--diff-filter=d", "--stdin"],
        operation="batch-list changed paths",
        input_bytes=stdin,
    )
    text = raw.decode("utf-8", errors="replace")
    result: dict[str, list[tuple[str, str]]] = {sha: [] for sha in shas}
    current: str | None = None
    for line in text.split("\n"):
        if not line:
            continue
        if line in sha_set:
            current = line
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


Finding = tuple[str, int, str, str]  # (label, line_no, kind, detail)


def _scan_range(repo_root: str, shas: list[str]) -> list[Finding]:
    """Scan every commit's message and the full new content of every path it
    touches. Full-blob content (not just the commit's own diff) matters
    because a pure rename or a change elsewhere in the file can leave a
    leaked line present without it ever appearing as an added line in that
    commit's own patch."""
    findings: list[Finding] = []

    changed = _batch_changed_paths(repo_root, shas)

    wanted_paths: dict[str, str] = {}  # blob oid -> path, for surviving (unskipped) entries per commit
    per_commit_paths: dict[str, list[tuple[str, str]]] = {}
    for sha in shas:
        keep = [(path, oid) for path, oid in changed.get(sha, []) if _should_scan_path(path)]
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
        ident_label = f"{short} (commit identity)"
        for line_no, label in check._leak_pattern_hits(identity):
            findings.append((ident_label, line_no, label, "redacted match"))
        for f in secret_scan.scan_text(ident_label, identity):
            findings.append((ident_label, f["line"], f["pattern_name"], f["matched_text"]))

        msg_label = f"{short} (commit message)"
        for line_no, label in check._leak_pattern_hits(message):
            findings.append((msg_label, line_no, label, "redacted match"))
        for f in secret_scan.scan_text(msg_label, message):
            findings.append((msg_label, f["line"], f["pattern_name"], f["matched_text"]))

        for path, oid in per_commit_paths.get(sha, []):
            path_label = f"{short}:{path}"
            raw = blobs.get(oid)
            if raw is None:
                continue
            for text in _decode_views(raw):
                for line_no, label in check._leak_pattern_hits(text):
                    findings.append((path_label, line_no, label, "redacted match"))
                for f in secret_scan.scan_text(path_label, text):
                    findings.append((path_label, f["line"], f["pattern_name"], f["matched_text"]))

    return findings


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
        return prepush_refs.resolve_commits(repo_root, updates)

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
        findings = _dedupe(_scan_range(repo_root, commits))
    except prepush_refs.PrePushGitError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 1

    if not findings:
        print(f"prepush_leak_scan: clean ({len(commits)} commit(s) scanned, 0 findings)")
        return 0

    _print_report(findings)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
