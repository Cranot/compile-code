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
version uses only remote-tracking refs for the TARGET remote. A commit cached
under a private or otherwise different remote is not evidence it already
reached the current target. With no target name, a new ref scans its full
reachable history rather than trusting an ambiguous cached inventory.

Deliberately excludes ``--branches`` from that bound: the ref being pushed
IS a local branch, so its own tip is trivially "reachable from a local
branch" and including ``--branches`` in the exclusion set would silently
scan nothing at all on a first push of a new branch. Only remote-tracking
refs for the named target count as evidence of prior publication there.

A REF UPDATE PUBLISHES MORE THAN COMMITS, which is why ``resolve_commits``
is no longer the whole answer. An annotated tag is an OBJECT with its own
message and its own tagger identity, and it points at a commit the remote
usually already has -- so the commit range for that update is EMPTY while a
brand-new object full of author-controlled text publishes. The ref NAME
publishes too, on every update, and is text nobody else has scanned either.
``resolve_push_surfaces`` returns all three surfaces plus anything it could
not classify, so a caller can never again read "no commits" as "nothing to
read".
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


def resolve_commits(repo_root: str, updates: list[RefUpdate], *, remote_name: str | None = None) -> list[str]:
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
            args = ["rev-list", update.local_oid]
            if remote_name:
                args.extend(["--not", f"--remotes={remote_name}"])
        else:
            args = ["rev-list", f"{update.remote_oid}..{update.local_oid}"]
        raw = _git_bytes(repo_root, args, operation=f"resolve push range for {update.local_ref}")
        for sha in raw.decode("ascii", errors="strict").split():
            if sha not in seen:
                seen.add(sha)
                commits.append(sha)
    return commits


# How many levels of tag-pointing-at-tag to follow before refusing. A chain
# longer than this is not something git produces in ordinary use, and an
# unbounded loop over attacker-influenced object graph shape is not something
# a gate should offer.
_MAX_TAG_CHAIN = 16


@dataclass(frozen=True)
class PushSurfaces:
    """Everything an update stream publishes that carries readable text.

    ``commits`` is the range ``resolve_commits`` already returned. The other
    three exist because that range is not the whole publication:

    * ``tag_objects`` -- oids of annotated tag objects newly reaching the
      remote. A tag object holds a message and a tagger line, both
      author-controlled, and it is a NEW object even when it points at a
      commit the remote already has. That is the case where ``commits`` is
      empty and nothing was ever read.
    * ``ref_names`` -- the local and remote ref names of every non-deleting
      update. A ref name publishes verbatim and is chosen by hand.
    * ``unreadable`` -- ``(ref, oid, type)`` for any update whose object is
      neither a commit nor a tag. The caller must refuse on these: an object
      this resolver cannot classify is one no scanner has read.

    ``deletions`` is counted, not scanned: a deleting push publishes no new
    object and no new name. It is reported so an all-deletions push says so
    rather than looking like a scan that found nothing.
    """

    commits: list[str]
    tag_objects: list[str]
    ref_names: list[str]
    unreadable: list[tuple[str, str, str]]
    deletions: int = 0


def _object_types(repo_root: str, oids: list[str]) -> dict[str, str]:
    """{oid: git object type} in ONE ``cat-file --batch-check`` call.

    A missing object raises rather than being dropped: this runs on oids git
    itself just handed the hook, so "missing" means the repository state moved
    underneath the gate and no verdict from it would be meaningful.
    """
    if not oids:
        return {}
    unique = list(dict.fromkeys(oids))
    proc = subprocess.run(
        ["git", "--no-replace-objects", "cat-file", "--batch-check"],
        cwd=repo_root,
        input=("\n".join(unique) + "\n").encode("ascii"),
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()
        raise PrePushGitError(f"classify pushed ref objects failed (git exit {proc.returncode}): {detail}")
    types: dict[str, str] = {}
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        fields = line.split(" ")
        if len(fields) < 2 or fields[1] in {"missing", "ambiguous"}:
            raise PrePushGitError(f"cannot classify pushed object: {line.strip()!r}")
        types[fields[0]] = fields[1]
    absent = [oid for oid in unique if oid not in types]
    if absent:
        raise PrePushGitError(f"cat-file --batch-check returned no type for {absent[:5]}")
    return types


def _tag_target(repo_root: str, oid: str) -> str:
    """The oid an annotated tag object points at, read from the object itself."""
    raw = _git_bytes(repo_root, ["cat-file", "tag", oid], operation=f"read tag object {oid}")
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if line.startswith("object "):
            return line[len("object ") :].strip()
        if not line.strip():
            break
    raise PrePushGitError(f"tag object {oid} has no 'object' header")


def resolve_push_surfaces(repo_root: str, updates: list[RefUpdate], *, remote_name: str | None = None) -> PushSurfaces:
    """Every readable surface *updates* publishes -- see :class:`PushSurfaces`.

    Written as a separate entry point rather than folded into
    ``resolve_commits`` so that function keeps its narrow, already-ported
    contract; callers that need the whole publication ask for the whole
    publication.
    """
    tag_objects: list[str] = []
    ref_names: list[str] = []
    unreadable: list[tuple[str, str, str]] = []
    deletions = 0

    live = [u for u in updates if not u.is_deletion]
    deletions = len(updates) - len(live)
    for update in live:
        for name in (update.local_ref, update.remote_ref):
            if name and name not in ref_names:
                ref_names.append(name)

    types = _object_types(repo_root, [u.local_oid for u in live])
    pending: list[tuple[str, str]] = []
    for update in live:
        kind = types[update.local_oid]
        if kind == "tag":
            pending.append((update.local_ref, update.local_oid))
        elif kind != "commit":
            unreadable.append((update.local_ref, update.local_oid, kind))

    depth = 0
    while pending:
        if depth > _MAX_TAG_CHAIN:
            raise PrePushGitError(f"tag chain deeper than {_MAX_TAG_CHAIN} objects; refusing to follow further")
        depth += 1
        nxt: list[tuple[str, str]] = []
        for ref, oid in pending:
            if oid in tag_objects:
                continue
            tag_objects.append(oid)
            target = _tag_target(repo_root, oid)
            if _object_types(repo_root, [target])[target] == "tag":
                nxt.append((ref, target))
        pending = nxt

    return PushSurfaces(
        commits=resolve_commits(repo_root, updates, remote_name=remote_name),
        tag_objects=tag_objects,
        ref_names=ref_names,
        unreadable=unreadable,
        deletions=deletions,
    )
