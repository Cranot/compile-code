"""scripts/prepush_leak_scan.py must actually block a push carrying a leak that
only exists in HISTORY, and must not block a clean one.

BLIND SPOT this closes: scripts/check.py's leak_scan() (and CI's
scripts/secret_scan.py) both scan the current tracked-plus-new candidate tree. A secret
committed and then "fixed" by a later commit in the same push is invisible
to either -- the final tree is clean -- but the earlier commit's blob still
reaches the remote the moment the push completes, and purging history
afterwards does not un-publish it (it may already be cloned, cached, or
indexed). This is the exact shape that forced a history purge for a
customer-name leak elsewhere in this project's toolchain (roam-code / stoa's
ROADMAP 4.3); scripts/prepush_leak_scan.py closes the same gap here by
scanning the exact pushed commit range instead of the working tree.

Uses an ISOLATED temp git repo (not this repo's own history) so the test has
no dependency on compile-code's actual commits and is safe to run anywhere,
including CI's checkout.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PREPUSH_LEAK_SCAN = ROOT / "scripts" / "prepush_leak_scan.py"


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, f"git {' '.join(args)} failed: {proc.stderr}"
    return proc.stdout.strip()


def _commit(repo: Path, rel_path: str, content: str, message: str) -> str:
    path = repo / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _git(repo, "add", rel_path)
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    d = tmp_path / "prepush_leak_scan_fixture_repo"
    d.mkdir()
    _git(d, "init", "-q")
    _git(d, "config", "user.email", "test@example.invalid")
    _git(d, "config", "user.name", "prepush-leak-scan-test")
    return d


def _run(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(PREPUSH_LEAK_SCAN), *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )


def test_leak_several_commits_back_is_caught_even_after_a_later_commit_removes_it(repo: Path) -> None:
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    leak_secret = "AKIA" + "Z" * 16  # synthetic, matches check.py's LEAK_PATTERNS AWS shape
    _commit(
        repo,
        "config.py",
        f'AWS_KEY = "{leak_secret}"\n',
        "add config (planted leak)",
    )
    _commit(repo, "config.py", "AWS_KEY = os.environ['AWS_KEY']\n", "rotate/remove the secret from the tree")
    _commit(repo, "notes.txt", "unrelated\n", "unrelated benign change")
    tip = _commit(repo, "notes2.txt", "more unrelated\n", "another unrelated benign change")

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 2, f"expected BLOCKED, got exit {result.returncode}:\n{result.stderr}"
    assert "AWS access key" in result.stderr
    # The leak commit itself is not the pushed tip -- confirm the report still
    # attributes the finding to that specific (non-HEAD) commit's short sha,
    # not just "somewhere in the range".
    assert "config.py" in result.stderr

    # The whole-tree gate this closes the gap for really does miss it: prove
    # the blind spot stays reproducible, not just historically true.
    tree_text = (repo / "config.py").read_text(encoding="utf-8")
    assert leak_secret not in tree_text


def test_clean_range_passes(repo: Path) -> None:
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    tip = _commit(
        repo,
        "notes.txt",
        "still nothing interesting: tokens and keys discussed only in prose\n",
        "clean follow-up commit",
    )

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 0, f"expected clean, got exit {result.returncode}:\n{result.stdout}\n{result.stderr}"
    assert "clean" in result.stdout


def test_allow_empty_commit_has_a_complete_zero_path_inventory(repo: Path) -> None:
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    _git(repo, "commit", "--allow-empty", "-qm", "intentional empty commit")
    tip = _git(repo, "rev-parse", "HEAD")

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 0, f"a proven empty path set was mistaken for an absent inventory:\n{result.stderr}"
    assert "1 commit(s) scanned, 0 findings" in result.stdout


def test_partial_per_commit_path_inventory_fails_closed(monkeypatch) -> None:
    from scripts import prepush_leak_scan

    first = "a" * 40
    second = "b" * 40
    monkeypatch.setattr(
        prepush_leak_scan,
        "_git_bytes",
        lambda *args, **kwargs: (first + "\n").encode("ascii"),
    )

    with pytest.raises(prepush_leak_scan.prepush_refs.PrePushGitError, match="missing 1 of 2 requested commits"):
        prepush_leak_scan._batch_changed_paths(".", [first, second])


def test_new_branch_first_push_is_scanned_not_skipped(repo: Path) -> None:
    """The --pre-push-updates path with an all-zero remote oid (first push of
    a new ref) must still resolve and scan real commits, not treat 'no known
    remote state' as 'nothing to check'."""
    _commit(repo, "readme.txt", "benign\n", "benign base commit")
    leak_secret = "AKIA" + "Y" * 16
    tip = _commit(repo, "config.py", f'AWS_KEY = "{leak_secret}"\n', "add config (planted leak, first push)")

    updates_file = repo / "updates.txt"
    zero = "0" * 40
    updates_file.write_text(f"refs/heads/feature {tip} refs/heads/feature {zero}\n", encoding="utf-8")

    result = _run(repo, "--pre-push-updates", "updates.txt")

    assert result.returncode == 2, f"expected BLOCKED on first push, got exit {result.returncode}:\n{result.stderr}"
    assert "AWS access key" in result.stderr


def test_new_target_remote_does_not_trust_another_remotes_cached_inventory(repo: Path) -> None:
    """A commit cached under a different remote has not reached this target."""
    value = "AK" + "IA" + "Q" * 16
    tip = _commit(repo, "config.py", f'value = "{value}"\n', "private-only commit")
    _git(repo, "update-ref", "refs/remotes/private/main", tip)
    updates_file = repo / "updates.txt"
    zero = "0" * 40
    updates_file.write_text(f"refs/heads/main {tip} refs/heads/main {zero}\n", encoding="utf-8")

    result = _run(repo, "--pre-push-updates", "updates.txt", "--remote-name", "public")

    assert result.returncode == 2, f"another remote hid a first-publication commit:\n{result.stdout}\n{result.stderr}"
    assert "AWS access key" in result.stderr


def test_malformed_updates_file_fails_closed(repo: Path) -> None:
    _commit(repo, "readme.txt", "benign\n", "benign base commit")
    updates_file = repo / "updates.txt"
    updates_file.write_text("not a valid ref update line\n", encoding="utf-8")

    result = _run(repo, "--pre-push-updates", "updates.txt")

    assert result.returncode == 1, "a malformed update stream must block (exit 1), never silently pass"
    assert "malformed" in result.stderr.lower()


def test_deletion_update_scans_nothing_and_passes(repo: Path) -> None:
    """A branch-deletion push (local oid all-zero) publishes no new bytes."""
    tip = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    updates_file = repo / "updates.txt"
    zero = "0" * 40
    updates_file.write_text(f"refs/heads/feature {zero} refs/heads/feature {tip}\n", encoding="utf-8")

    result = _run(repo, "--pre-push-updates", "updates.txt")

    assert result.returncode == 0
    assert "0 commits" in result.stdout


def test_no_mode_and_no_upstream_fails_closed_instead_of_scanning_nothing(repo: Path) -> None:
    """Manual invocation with neither --range nor --pre-push-updates, and no
    configured upstream, must refuse to guess -- never silently pass."""
    _commit(repo, "readme.txt", "benign\n", "benign base commit")

    result = _run(repo)

    assert result.returncode == 1
    assert "no --range or --pre-push-updates" in result.stderr


def test_an_unresolved_template_placeholder_is_clean_in_every_blob_that_carries_it(repo: Path) -> None:
    """A range scan reads every commit's own blob, so a marker added at the tip
    cannot clean an earlier commit. This exercises the shape that does not need
    one: an un-interpolated ``{secret}`` is template SYNTAX, and the placeholder
    rule -- not any path exemption -- is what keeps it clean in both blobs.

    THE CLAIM THIS TEST USED TO MAKE WAS FALSE. It was named for the per-path
    heuristic exemption and its docstring said "three blobs in this
    repository's own pending push carry the unmarked fixture line", offered as
    the measured reason that exemption had to survive. Re-measured: the pending
    push carries none, and this scenario passes with the exemption removed
    because it never depended on it. The exemption is gone; the scenario is
    still worth pinning, under a name that says what it actually proves."""
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    _commit(
        repo,
        "tests/test_secret_scan.py",
        "hits = _detect(f\"API_KEY = '{secret}'\")\n",
        "add secret scan gate (unmarked f-string template)",
    )
    tip = _commit(
        repo,
        "tests/test_secret_scan.py",
        "hits = _detect(f\"API_KEY = '{secret}'\")  # f-string template  # secretsallow\n",
        "annotate the gate's own test-helper line",
    )

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 0, f"expected clean, got exit {result.returncode}:\n{result.stdout}\n{result.stderr}"


def test_no_path_is_exempt_from_the_catalogue(repo: Path) -> None:
    """The inverse of a measured exposure, pinned at the range arm.

    Measured before the per-path rule was removed: all seven heuristic shapes,
    committed at ``tests/test_secret_scan.py``, were reported clean by this
    scanner with exit 0, while the same lines at any other path exited 2. The
    path decided the verdict. It no longer does -- and an unrelated file under
    ``tests/`` was never exempt either, which is the half that already worked.
    """
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    heuristic = "api" + "_secret = " + '"aB3xQ7zRt9LmZp2w"'
    vendor = "AKIA" + "W" * 16

    at_the_old_exempt_path = _commit(
        repo, "tests/test_secret_scan.py", heuristic + "\n", "commit a heuristic shape at the former exempt path"
    )
    result = _run(repo, "--range", f"{base}..{at_the_old_exempt_path}")
    assert result.returncode == 2, f"expected BLOCKED, got exit {result.returncode}:\n{result.stderr}"
    assert "Generic Secret Assignment" in result.stderr

    marked = _commit(
        repo,
        "tests/test_secret_scan.py",
        heuristic + "  # secretsallow\n",
        "annotate it per line, which is the only suppression left",
    )
    result = _run(repo, "--range", f"{at_the_old_exempt_path}..{marked}")
    assert result.returncode == 0, f"expected clean, got exit {result.returncode}:\n{result.stderr}"

    elsewhere = _commit(
        repo,
        "tests/test_something_else.py",
        f'AWS_KEY = "{vendor}"\n',
        "accidentally commit a real-shaped secret in an unrelated test file",
    )
    result = _run(repo, "--range", f"{marked}..{elsewhere}")
    assert result.returncode == 2, f"expected BLOCKED, got exit {result.returncode}:\n{result.stderr}"
    assert "tests/test_something_else.py" in result.stderr


def test_secret_name_constant_is_not_flagged_across_history(repo: Path) -> None:
    """Reproduces compile-code's other real false positive: a constant whose
    value NAMES a secret (e.g. a GitHub Actions secret to read at runtime)
    is not itself a credential value, in the commit that introduces it --
    not just after a later commit adds a suppression marker."""
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    tip = _commit(
        repo,
        "scripts/release_artifacts.py",
        'RELEASE_GUARD_SECRET = "RELEASE_GUARD_READ_TOKEN"\n',
        "add release guard (secret NAME, not a value)",
    )

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 0, f"expected clean, got exit {result.returncode}:\n{result.stdout}\n{result.stderr}"


def test_secret_scan_catalogue_is_also_applied_to_pushed_history(repo: Path) -> None:
    """The broader scripts/secret_scan.py catalogue (not just check.py's four
    LEAK_PATTERNS) must also see historical blob content, e.g. an Anthropic
    key shape that check.py's own AKIA/PEM/sk- patterns would not catch."""
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    anthropic_key = "sk-ant-oat01-" + "Aa9_-" * 12
    _commit(repo, "config.py", f'ANTHROPIC_KEY = "{anthropic_key}"\n', "add config (planted anthropic key)")
    tip = _commit(repo, "config.py", "ANTHROPIC_KEY = os.environ['ANTHROPIC_KEY']\n", "rotate the key out of the tree")

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 2, f"expected BLOCKED, got exit {result.returncode}:\n{result.stderr}"
    assert "Anthropic OAuth Token" in result.stderr


def test_commit_identity_metadata_is_scanned_not_just_the_message(repo: Path) -> None:
    """The `author`/`committer` header lines publish with the commit exactly
    like its message does, and are exactly as unremovable afterwards. The
    scanner used to `partition("\n\n")` the commit object and keep only the
    message, so a credential, a real name, or an employer domain sitting in
    user.name / user.email travelled to the remote completely unscanned."""
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")

    # Plant the leak ONLY in the identity metadata. The tree, the diff and
    # the commit message are all clean, so every other surface this scanner
    # inspects stays quiet -- if this test fails, the identity surface is the
    # only thing that could have caught it.
    # Built by concatenation, never written as a literal, so this test file
    # does not itself trip the gate it is testing (same convention as the
    # other planted-leak tests above).
    leak_secret = "AKIA" + "V" * 16
    _git(repo, "config", "user.name", leak_secret)
    tip = _commit(repo, "notes.txt", "nothing interesting here\n", "an entirely unremarkable commit subject")

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 2, f"expected BLOCKED, got exit {result.returncode}:\n{result.stdout}\n{result.stderr}"
    assert "commit identity" in result.stderr, result.stderr
    assert "AWS" in result.stderr, result.stderr


def test_clean_commit_identity_does_not_false_positive(repo: Path) -> None:
    """An ordinary name/email pair must not trip the new identity surface --
    a gate that fires on every commit is a gate that gets bypassed."""
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    tip = _commit(repo, "notes.txt", "still benign\n", "clean follow-up commit")

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 0, f"expected clean, got exit {result.returncode}:\n{result.stdout}\n{result.stderr}"


def _commit_bytes(repo: Path, rel_path: str, blob: bytes, message: str) -> str:
    """Commit raw BYTES, so an encoding can be pinned exactly."""
    path = repo / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    _git(repo, "add", rel_path)
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.mark.parametrize(
    ("label", "encode"),
    [
        # What Windows PowerShell's `>` and Out-File actually emit.
        ("utf-16 with BOM", lambda text: text.encode("utf-16")),
        # BOM-less: every byte is valid UTF-8, so a BOM check alone cannot
        # see this one and the UTF-8 read "succeeds" into NUL-interleaved text.
        ("utf-16 without BOM", lambda text: text.encode("utf-16-le")),
    ],
)
def test_utf16_blob_in_pushed_history_is_scanned(repo: Path, label: str, encode) -> None:
    """A UTF-16 blob used to publish unseen -- the gap f84025f left open here.

    That commit fixed the working-tree scanner and recorded that this script,
    which decodes historical blobs itself, still dropped UTF-16 via its
    `b"\x00" in data` binary test. A credential committed in a UTF-16 file
    therefore travelled to the remote while this gate printed clean, and
    purging history after a push does not un-publish it.
    """
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    token = "gh" + "p_" + "A9f2Kd8Lm3" + "Qp7Rt1Zx5V" + "b6Nc4Ye0Wu" + "2Ij8Hq"
    _commit_bytes(repo, "cred.md", encode(f'api = "{token}"\n'), "add a credential in a wide encoding")
    tip = _commit(repo, "cred.md", "api = os.environ['API']\n", "rotate the credential out of the tree")

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 2, f"{label} blob published unseen (exit {result.returncode}):\n{result.stderr}"
    assert "cred.md" in result.stderr


def test_binary_blobs_are_not_pattern_matched_but_refuse_the_push(repo: Path) -> None:
    """Conservation AND fail-closed, on the history arm.

    Conservation survives: a binary blob still produces no credential-shaped
    finding, so widening the text rule has not buried the gate in noise from
    every committed PNG and object file. What changed is the verdict: an
    unopened blob is refused by name (exit 3, UNSCANNED) instead of riding in
    a bucket the clean-path condition never consulted.

    Why that mattered: ``binary_skipped`` was deliberately excluded from the
    clean condition, which is the same "defeated by a single readable
    companion" shape this script had already fixed for ``path_filtered``. A
    NUL-prefixed blob carrying an ``sk-ant-oat01-`` token published under the
    word "clean", exit 0.
    """
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    png = bytes.fromhex("89504e470d0a1a0a0000000d49484452") + bytes(range(256)) * 8
    elf = b"\x7fELF\x02\x01\x01" + bytes(range(256)) * 8
    _commit_bytes(repo, "image.dat", png, "add a png-shaped blob")
    tip = _commit_bytes(repo, "object.dat", elf, "add an object-file-shaped blob")

    result = _run(repo, "--range", f"{base}..{tip}")

    # Exit 3 is "read nothing here", not 2 ("found a credential"): the bytes
    # produced no pattern hits, which is the conservation half of this test.
    assert result.returncode == 3, f"unopened blobs reported clean (exit {result.returncode}):\n{result.stdout}"
    assert "image.dat" in result.stderr and "object.dat" in result.stderr


def test_binary_blob_beside_a_readable_companion_still_refuses(repo: Path) -> None:
    """The escape a range-global denominator cannot see.

    One readable file in the same commit puts ``opened`` above zero, so any
    guard keyed on "the whole range went unread" passes. The refusal is
    per-blob for exactly that reason.
    """
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    token = "sk-" + "ant-" + "oat" + "01-" + "Aa7_-" * 12
    probe = b"\x00\x80" + f"index-url = https://__token__:{token}@pypi.example.invalid/simple\n".encode()
    (repo / "companion.txt").write_text("plainly readable\n", encoding="utf-8")
    _git(repo, "add", "companion.txt")
    tip = _commit_bytes(repo, "release/toolstate.dat", probe, "add tool state beside a readable file")

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 3, f"a readable companion rescued an unopened blob:\n{result.stdout}"
    assert "release/toolstate.dat" in result.stderr


# ---------------------------------------------------------------------------
# Size must never be a reason to report clean.
#
# The defect: _decode_views returned [] for any blob over a 4 MiB cap, using
# list-emptiness as its ONLY channel. _scan_range then iterated zero times and
# main() rendered the UNSCANNED blob as `clean`, exit 0 -- which .githooks/
# pre-push consumes as permission to push. Measured before the fix, scanning
# only the commit that added the blob so range selection is not a confound:
#
#     4,194,304 bytes -> exit 2  BLOCKED
#     4,194,305 bytes -> exit 0  clean
#
# One byte across the threshold hid a real-shaped GitHub token. This is not
# adversarial-only: a legitimately large asset -- a generated dataset, a
# minified vendor bundle -- with a credential anywhere in it pushed clean.
# ---------------------------------------------------------------------------

_HISTORICAL_CAP_BYTES = 4 * 1024 * 1024


def _github_token() -> str:
    """A real-SHAPED, never-issued GitHub token, split so this test file's own
    source text carries no contiguous match (the gates read it like any other
    file; only tests/test_secret_scan.py is path-exempt)."""
    return "gh" + "p_" + "A1b2C3d4E5f6" + "G7h8I9j0K1l2" + "M3n4O5p6Q7r8"


def _padded_credential_blob(total_bytes: int) -> bytes:
    """`total_bytes` of blob whose LAST line is a credential.

    The padding is one long line rather than many short ones purely for test
    speed; the credential's own line is what has to be found either way.
    """
    tail = f"TOKEN = {_github_token()}\n".encode()
    pad = total_bytes - len(tail) - 1
    assert pad > 0
    return b"x" * pad + b"\n" + tail


@pytest.mark.parametrize("total_bytes", [_HISTORICAL_CAP_BYTES, _HISTORICAL_CAP_BYTES + 1])
def test_padding_across_the_old_size_cap_no_longer_hides_a_credential(repo: Path, total_bytes: int) -> None:
    """THE regression for the reported defect: the same credential either side
    of the historical 4 MiB cap, both caught.

    Before the fix, `_HISTORICAL_CAP_BYTES` exited 2 and `+ 1` exited 0 --
    padding a blob by a single byte bought the credential a free ride to the
    remote. Parametrised over both sides on purpose: asserting only the large
    case would also pass a scanner that had simply become unable to report
    clean at all.
    """
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    tip = _commit_bytes(repo, "dataset.txt", _padded_credential_blob(total_bytes), "add a large generated asset")

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 2, (
        f"a {total_bytes}-byte blob carrying a credential was not blocked "
        f"(exit {result.returncode}):\n{result.stdout}\n{result.stderr}"
    )
    assert "GitHub" in result.stderr, result.stderr
    assert "dataset.txt" in result.stderr, result.stderr


def test_a_genuinely_clean_large_blob_still_passes(repo: Path) -> None:
    """NEGATIVE CONTROL. "Block everything over 4 MiB" would satisfy the test
    above while making the gate useless, so a clean blob comfortably past the
    historical cap has to keep exiting 0 -- and has to be reported as SCANNED,
    not merely as producing no findings."""
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    size = _HISTORICAL_CAP_BYTES + 4096
    body = b"lorem ipsum dolor sit amet, tokens and keys discussed only in prose\n" * (size // 68)
    tip = _commit_bytes(repo, "dataset.txt", body, "add a large but entirely clean generated asset")

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 0, f"a clean large blob was blocked:\n{result.stdout}\n{result.stderr}"
    assert "clean" in result.stdout
    assert f"{len(body)} bytes" in result.stdout, (
        f"the clean verdict does not disclose that the large blob was actually read:\n{result.stdout}"
    )


def test_a_blob_over_the_ceiling_is_unscannable_never_clean(repo: Path) -> None:
    """The one remaining cap is a LOUD REFUSAL, not a silent skip.

    The blob here carries no credential at all, which is the point: "I could
    not check this" has to block on its own, without a finding to justify it.
    Exit 3 and the word `clean` must not appear.
    """
    from scripts import prepush_leak_scan

    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    oversize = prepush_leak_scan._SCAN_CEILING_BYTES + 1
    tip = _commit_bytes(repo, "huge.txt", b"y" * oversize, "add a blob past the scan ceiling")

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 3, (
        f"an unscannable blob did not block (exit {result.returncode}):\n{result.stdout}\n{result.stderr}"
    )
    assert "clean" not in result.stdout, f"an unread blob was rendered as clean:\n{result.stdout}"
    assert "UNSCANNABLE" in result.stderr, result.stderr
    assert "huge.txt" in result.stderr, "the refusal does not name the blob it refused"
    assert str(oversize) in result.stderr, "the refusal does not publish the blob's size"


def test_clean_verdict_publishes_its_denominator(repo: Path) -> None:
    """`0 findings` is unfalsifiable on its own -- it is what a working scan of
    a clean range prints and also what a scan that read nothing prints. The
    counts of blobs and bytes actually read must ride along with the verdict."""
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    tip = _commit(repo, "notes.txt", "nothing interesting\n", "clean follow-up commit")

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 0, result.stderr
    assert "blobs: 1 scanned" in result.stdout, result.stdout
    assert "0 unanalyzable" in result.stdout, result.stdout
    assert "bytes" in result.stdout, result.stdout


def test_binary_skips_are_named_in_the_refusal_not_only_counted(repo: Path) -> None:
    """Disclosure was never the missing half -- action was.

    The count ``1 binary-skipped`` printed on the clean line for a whole
    release cycle. A number nothing keys a verdict on is not a gate, so the
    blob is now named in a refusal and the denominator still rides with it.
    """
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    tip = _commit_bytes(repo, "object.dat", b"\x7fELF\x02\x01\x01" + bytes(range(256)) * 8, "add an object blob")

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 3, result.stdout
    assert "1 binary-skipped" in result.stderr, result.stderr
    assert "object.dat" in result.stderr, "a skipped blob is not named anywhere in the verdict"


def test_credential_committed_under_a_binary_looking_name_is_read(repo: Path) -> None:
    """A file NAME is not a measurement of the bytes behind it.

    Measured on the shipped scanner, with the credential in a plain-text file
    committed as ``logo.png``::

        prepush_leak_scan: clean (1 commit(s) scanned, 0 findings; blobs: 0
        scanned / 0 bytes, 0 binary-skipped, 1 path-filtered, 0 unanalyzable)

    exit 0 -- the word "clean" over zero bytes read, with the honest
    denominator printed right beside it and nothing acting on it.
    """
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    tip = _commit(repo, "logo.png", f'aws = "{"AKIA" + "Z" * 16}"\n', "credential under a binary-looking name")

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 2, f"expected BLOCKED, got exit {result.returncode}:\n{result.stdout}"
    assert "logo.png" in result.stderr


def test_pypi_token_in_a_lock_file_is_read(repo: Path) -> None:
    """``.lock`` sat in the do-not-open suffix list beside ``.exe``, so pip
    requirement files -- the natural home for an ``--index-url`` credential --
    were opened by no scanner at all."""
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    token = "pypi-" + "AgEIcHlwaS5vcmcC" + "Aa9_-" * 24
    tip = _commit(repo, "release/tooling-requirements.lock", f"--index-url https://u:{token}@i/s\n", "pin tooling")

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 2, f"expected BLOCKED, got exit {result.returncode}:\n{result.stdout}"
    assert "tooling-requirements.lock" in result.stderr


def test_range_whose_every_path_went_unopened_refuses_instead_of_passing(repo: Path) -> None:
    """The ledger is now GATED, not merely published. A range that changed
    paths while this gate opened no blob at all has no basis for "clean": the
    verdict would rest on the commit messages alone."""
    _commit(repo, "build/generated.py", "generated = True\n", "commit a build artifact")

    result = _run(repo, "--range", "HEAD")

    assert result.returncode == 3, f"expected a refusal, got exit {result.returncode}:\n{result.stdout}"
    assert "UNSCANNED" in result.stderr
    assert "build/generated.py" in result.stderr, "the refusal does not name the path it never opened"


def test_one_readable_companion_file_does_not_clear_an_unopened_path(repo: Path) -> None:
    """The refusal above was range-global, so a single readable path in the
    same commit defeated it. Measured on the shipped gate: this exact commit
    printed ``clean (1 commit(s) scanned, 0 findings; blobs: 1 scanned / 45
    bytes, ... 1 path-filtered ...)`` and exited 0, with a real-shaped
    ``sk-ant-oat01-`` token in the unopened blob. Whether a blob was read is a
    fact about that blob, so the refusal has to be about that blob."""
    token = "sk-" + "ant-" + "oat" + "01-" + "Qw7zR2mK9bT4xL6vN8pD3sG5hJ1cF0yA" * 2
    (repo / ".tox").mkdir(parents=True, exist_ok=True)
    (repo / ".tox" / "pip.conf").write_text(f"extra-index-url = https://x:{token}@i.invalid/s\n", encoding="utf-8")
    (repo / "benign.txt").write_text("plain tracked text\n", encoding="utf-8")
    _git(repo, "add", ".tox/pip.conf", "benign.txt")
    _git(repo, "commit", "-q", "-m", "a skipped path beside a readable one")

    result = _run(repo, "--range", "HEAD")

    assert result.returncode == 3, f"a readable companion cleared an unopened path (exit {result.returncode})"
    assert "clean" not in result.stdout, f"an unread blob was rendered as clean:\n{result.stdout}"
    assert "UNSCANNED" in result.stderr
    assert ".tox/pip.conf" in result.stderr, "the refusal does not name the path it never opened"


def test_the_unread_path_refusal_states_a_remedy_that_is_true(repo: Path) -> None:
    """The old text told the operator these paths are "build artifacts or
    skipped directories, which the tree gates already refuse to track" --
    measured false for 7 of the 13 skipped names at the time, including the one
    a credential was reproduced under. The gate's own remediation repeated the
    wrong bound. It is true now only because the two lists were merged."""
    _commit(repo, "build/generated.py", "generated = True\n", "commit a build artifact")

    result = _run(repo, "--range", "HEAD")

    assert result.returncode == 3
    assert "artifact_scan" in result.stderr, "the remedy does not name the gate that makes the claim true"
    assert "git rm --cached" in result.stderr, "the remedy does not say how to untrack the path"


def test_the_scanners_own_test_path_is_scanned_like_any_other(repo: Path) -> None:
    """The inverse of the exemption test this replaces.

    ``_path_disposition`` inherited a WHOLE-FILE exemption from
    ``secret_scan``, so a contiguous live-format credential committed at that
    path published under the word "clean", exit 0. A split fixture still
    passes -- real credentials do not arrive pre-split, which is the discipline
    that made the blanket unnecessary in the first place.
    """
    split = _commit(repo, "tests/test_secret_scan.py", 'planted = "AKIA" + "W" * 16\n', "split fixture")
    result = _run(repo, "--range", "HEAD")
    assert result.returncode == 0, f"a SPLIT fixture was refused:\n{result.stdout}{result.stderr}"

    token = "sk-" + "ant-" + "oat" + "01-" + "Aa9_-" * 12
    tip = _commit(repo, "tests/test_secret_scan.py", f'leaked = "{token}"\n', "contiguous credential")

    result = _run(repo, "--range", f"{split}..{tip}")

    assert result.returncode == 2, f"a contiguous credential published clean:\n{result.stdout}"
    assert "tests/test_secret_scan.py" in result.stderr


def test_credential_past_the_first_line_batch_is_found_with_a_true_line_number(repo: Path) -> None:
    """Blobs are scanned in bounded line batches. A batching bug that scans
    only the first batch, or that restarts line numbering per batch, would
    still pass every small-blob test in this file."""
    from scripts import prepush_leak_scan

    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    leading = prepush_leak_scan._SCAN_BATCH_LINES * 3 + 7
    body = "# filler\n" * leading + f"TOKEN = {_github_token()}\n"
    tip = _commit(repo, "late.txt", body, "credential well past the first batch boundary")

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 2, f"a credential past the batch boundary was missed:\n{result.stdout}"
    assert f"late.txt:{leading + 1}" in result.stderr, (
        f"expected the true line number {leading + 1}, got:\n{result.stderr}"
    )


def test_line_batches_cover_the_text_exactly_once_with_correct_line_numbers() -> None:
    """Property pinning the batching primitive itself: concatenating the
    batches reproduces the input byte for byte (nothing dropped, nothing
    double-scanned), and each batch's reported first line is its real one."""
    from scripts import prepush_leak_scan

    for text in (
        "",
        "no trailing newline",
        "one\n",
        "".join(f"line {i}\n" for i in range(prepush_leak_scan._SCAN_BATCH_LINES * 2 + 3)),
        "".join(f"line {i}\n" for i in range(prepush_leak_scan._SCAN_BATCH_LINES * 2)) + "tail without newline",
        "x" * 100_000,  # a single enormous line: no boundary to cut on
    ):
        batches = list(prepush_leak_scan._line_batches(text))
        assert "".join(chunk for _, chunk in batches) == text
        for first_line, chunk in batches:
            assert text.splitlines()[first_line - 1 : first_line - 1 + len(chunk.splitlines())] == chunk.splitlines()


def test_scanner_that_finds_nothing_reports_broken_not_clean(repo: Path, monkeypatch) -> None:
    """ "0 findings" and "the scanner stopped working" must stop being the same
    output. Neutering the scan makes the planted positive control disappear,
    which has to surface as BROKEN and a non-zero exit -- not as a clean
    range."""
    from scripts import prepush_leak_scan

    _commit(repo, "readme.txt", "benign\n", "benign base commit")
    assert prepush_leak_scan._self_test_failures() == [], "the positive control does not pass on healthy code"

    monkeypatch.setattr(prepush_leak_scan, "_scan_text", lambda label, text: [])
    assert prepush_leak_scan._self_test_failures(), "a scanner that reads nothing passed its own positive control"

    monkeypatch.chdir(repo)
    assert prepush_leak_scan.main(["--range", "HEAD"]) == 4


def test_positive_control_covers_both_catalogues(monkeypatch) -> None:
    """One planted credential per catalogue, not one overall: roam-code's
    first gate against this defect self-tested with a GitHub token, passed,
    and let a real Anthropic token through untouched. Breaking EITHER
    catalogue must fail the control."""
    from scripts import prepush_leak_scan

    for target, attribute in (
        (prepush_leak_scan.check, "_leak_pattern_hits"),
        (prepush_leak_scan.secret_scan, "scan_text"),
    ):
        monkeypatch.setattr(target, attribute, lambda *args, **kwargs: [])
        assert prepush_leak_scan._self_test_failures(), f"neutering {attribute} did not fail the positive control"
        monkeypatch.undo()
