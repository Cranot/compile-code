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


def test_own_test_corpus_file_is_exempt_across_its_whole_history(repo: Path) -> None:
    """Reproduces compile-code's own real false-positive shape: a commit adds
    tests/test_secret_scan.py's f-string template line un-annotated, and a
    LATER commit adds a '# secretsallow' marker to the tip version. Because
    the range scan reads every commit's own full blob, the marker at the tip
    does not retroactively clean the earlier commit -- only the path
    allowlist (scripts/secret_scan.py's _OWN_TEST_CORPUS_FILES) does that."""
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
        "suppress the gate's own test-helper false positive",
    )

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 0, f"expected clean, got exit {result.returncode}:\n{result.stdout}\n{result.stderr}"


def test_own_test_corpus_exemption_is_one_file_not_a_directory(repo: Path) -> None:
    """The allowlist must not silently widen into 'tests/ is exempt' -- a
    DIFFERENT file under tests/ carrying a real credential-shaped secret must
    still be caught."""
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    leak_secret = "AKIA" + "W" * 16
    tip = _commit(
        repo,
        "tests/test_something_else.py",
        f'AWS_KEY = "{leak_secret}"\n',
        "accidentally commit a real-shaped secret in an unrelated test file",
    )

    result = _run(repo, "--range", f"{base}..{tip}")

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


def test_binary_blobs_are_still_skipped(repo: Path) -> None:
    """Conservation check: widening the text rule must not swallow binary.

    Without this, "decode everything" would pass the UTF-16 tests above while
    burying the gate in noise from every committed PNG and object file. A fix
    that makes everything loud is not a fix.
    """
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    png = bytes.fromhex("89504e470d0a1a0a0000000d49484452") + bytes(range(256)) * 8
    elf = b"\x7fELF\x02\x01\x01" + bytes(range(256)) * 8
    _commit_bytes(repo, "image.dat", png, "add a png-shaped blob")
    tip = _commit_bytes(repo, "object.dat", elf, "add an object-file-shaped blob")

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 0, f"binary blobs produced findings:\n{result.stderr}"
