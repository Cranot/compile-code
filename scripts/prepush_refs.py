"""prepush_refs.py -- generic parser for git's pre-push ref-update stream.

Git passes one update line per updated ref to a pre-push hook's stdin::

    <local-ref> <local-oid> <remote-ref> <remote-oid>

This module turns that stream into the exact commit range(s) about to be
published. Stdlib-only (``re``, ``subprocess``, ``dataclasses`` only), no
dependency on this repo's scanners, layout, or naming -- the file is meant
to be copy-portable verbatim into any other git repo (roam-code, compile-
code, ...); only the caller (a project's own scanner driver) is project-
specific.

Ported from roam-code's ``scripts/prepush_refs.py`` (D:/Safe/Projects/
roam-code) with one deliberate simplification: instead of an authoritative
``git ls-remote`` network round-trip to bound a brand-new ref's scan, this
version bounds it locally via ``--not --remotes`` (everything already
reachable from some remote-tracking ref is presumably already published).
That is a heuristic, not a proof -- a stale remote-tracking ref could under-
exclude a few already-published commits -- but the failure direction is
always safe (a few extra already-published commits get harmlessly re-
scanned; nothing pushed is ever skipped), and it keeps the gate network-
free, which matters more for a hook that runs on every single push.

Deliberately excludes ``--branches`` from that bound: the ref being pushed
IS a local branch, so its own tip is trivially "reachable from a local
branch" and including ``--branches`` in the exclusion set would silently
scan nothing at all on a first push of a new branch. Only remote-tracking
refs (``refs/remotes/*``) count as evidence of prior publication.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

_OID_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


class PrePushUpdateError(ValueError):
    """Raised when git's pre-push ref-update stream is malformed."""


class PrePushGitError(RuntimeError):
    """Raised when a git command needed to resolve the push range fails."""


@dataclass(frozen=True)
class RefUpdate:
    local_ref: str
    local_oid: str
    remote_ref: str
    remote_oid: str

    @property
    def is_deletion(self) -> bool:
        """A deleting push (``git push origin :branch``) has an all-zero local oid."""
        return not self.local_oid.strip("0")

    @property
    def is_new_remote_ref(self) -> bool:
        """First push of this ref: the remote has no prior oid for it (all-zero)."""
        return not self.remote_oid.strip("0")


def parse_pre_push_updates(text: str) -> list[RefUpdate]:
    """Parse a complete pre-push stdin stream. Raises on any malformed line
    (fail closed: an update this parser cannot make sense of must block the
    push, not be silently skipped)."""
    updates: list[RefUpdate] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        if not raw_line:
            continue  # a trailing blank line from the final newline is not an error
        fields = raw_line.split(" ")
        if len(fields) != 4 or any(not field for field in fields):
            raise PrePushUpdateError(f"malformed pre-push update at line {line_no}: {raw_line!r}")
        local_ref, local_oid, remote_ref, remote_oid = fields
        local_oid = local_oid.lower()
        remote_oid = remote_oid.lower()
        if not _OID_RE.fullmatch(local_oid) or not _OID_RE.fullmatch(remote_oid):
            raise PrePushUpdateError(f"invalid object id at line {line_no}: {raw_line!r}")
        if len(local_oid) != len(remote_oid):
            raise PrePushUpdateError(f"mixed object id algorithms at line {line_no}: {raw_line!r}")
        updates.append(RefUpdate(local_ref, local_oid, remote_ref, remote_oid))
    return updates


def _git_bytes(repo_root: str | None, args: list[str], *, operation: str) -> bytes:
    proc = subprocess.run(
        ["git", "--no-replace-objects", *args],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()
        suffix = f": {detail}" if detail else ""
        raise PrePushGitError(f"{operation} failed (git exit {proc.returncode}){suffix}")
    return proc.stdout


def resolve_commits(repo_root: str, updates: list[RefUpdate]) -> list[str]:
    """Return the deduplicated, order-stable list of commit SHAs newly
    introduced by *updates* -- the exact set about to be published.

    Deletions contribute nothing (nothing new reaches the remote). An
    existing ref is bounded to ``remote_oid..local_oid``. A brand-new ref
    (first push -- ``remote_oid`` is all-zero, which happens regardless of
    whether the local branch has an ``@{u}`` configured) is bounded to
    everything reachable from ``local_oid`` that isn't already reachable
    from some remote-tracking ref.
    """
    seen: set[str] = set()
    commits: list[str] = []
    for update in updates:
        if update.is_deletion:
            continue
        if update.is_new_remote_ref:
            args = ["rev-list", update.local_oid, "--not", "--remotes"]
        else:
            args = ["rev-list", f"{update.remote_oid}..{update.local_oid}"]
        raw = _git_bytes(repo_root, args, operation=f"resolve push range for {update.local_ref}")
        for sha in raw.decode("ascii", errors="strict").split():
            if sha not in seen:
                seen.add(sha)
                commits.append(sha)
    return commits
