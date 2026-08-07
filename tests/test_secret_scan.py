"""The secret scanner must detect the credentials this repo's own users hold.

compile-code ships an AI dev tool, so Anthropic/OpenAI/xAI/Groq/HuggingFace/
Replicate keys are the credentials most likely to sit in a fixture, a pasted
log, or a ``.env`` -- and this repo had zero coverage for them until this
scan was added (four narrow patterns lived in ``scripts/check.py`` then, and
its generic ``sk-`` pattern did not match key shapes with a hyphen right
after the prefix, which is exactly how Anthropic's and OpenAI's project keys
are shaped; that gate has since grown a pattern for them, and both
catalogues are now checked, because neither is a superset of the other).

METHOD NOTE -- why one case PER PROVIDER FAMILY:
the first gate built against this defect (roam-code's) self-tested with a
planted GitHub token, passed, and was declared working, while a real
Anthropic OAuth token sailed straight through. A self-test that exercises a
pattern already known to be covered proves nothing about coverage. So every
family gets its own planted case, and benign text must stay clean so the
catalogue cannot "pass" by matching everything.

Planted secrets are synthetic and built via string concatenation, never as
one contiguous literal -- this scanner does not exempt ``tests/`` (mirroring
roam-code's own scripts/secret_scan.py, which has no test-path exemption
either), so a contiguous planted secret in this very file would trip the
gate it is testing. Real secrets do not arrive pre-split like this.
"""

from __future__ import annotations

import subprocess

import pytest

from scripts import secret_scan


def _detect(text: str) -> set[str]:
    return {f["pattern_name"] for f in secret_scan.scan_text("planted.txt", text)}


# (planted secret built from fragments, expected pattern name)
PROVIDER_FAMILY_CASES = [
    ("sk-ant-oat01-" + "Aa9_-" * 12, "Anthropic OAuth Token"),
    ("sk-ant-api03-" + "Bb8_-" * 12, "Anthropic API Key"),
    ("sk-proj-" + "Cc7" * 12, "OpenAI Project Key"),
    ("sk-" + "D" * 48, "OpenAI API Key"),
    ("xai-" + "E" * 24, "xAI API Key"),
    ("gsk_" + "F" * 24, "Groq API Key"),
    ("hf_" + "G" * 34, "HuggingFace Token"),
    ("r8_" + "H" * 37, "Replicate API Token"),
    ("AKIA" + "I" * 16, "AWS Access Key"),
    ("ghp_" + "J" * 36, "GitHub Personal Access Token (classic)"),
    # Fine-grained PATs match NEITHER of the two ghp_/gh[pousr]_ shapes above:
    # the prefix is github_pat_, so the character class breaks at "gi".
    # Measured before this case existed -- check.py caught it and this
    # 33-pattern catalogue did not, on all 51 candidate files.
    ("github_pat_" + "11ABCDEFG0" + "P" * 47, "GitHub Fine-Grained PAT"),
    ("glpat-" + "K" * 20, "GitLab Token"),
    ("sk_live_" + "L" * 24, "Stripe Secret Key"),
    ("AIza" + "M" * 35, "Google API Key"),
    ("npm_" + "N" * 36, "NPM Token"),
    ("-----BEGIN " + "RSA PRIVATE KEY-----", "Private Key"),
]


@pytest.mark.parametrize(("secret", "expected"), PROVIDER_FAMILY_CASES)
def test_provider_family_is_detected(secret: str, expected: str) -> None:
    """Each credential family is caught by its own named pattern."""
    hits = _detect(f"API_KEY = '{secret}'")  # f-string template, not a literal value  # secretsallow
    assert hits, f"{expected}: no pattern fired -- this credential would leak"
    assert expected in hits, f"{expected}: expected that pattern, got {sorted(hits)}"


BENIGN = [
    "lets refactor the parser and add a test",
    "why cant it just reuse the existing index instead of rebuilding",
    "the sk- prefix is discussed in our docs but this is not a key",
    "def add(a, b):\n    return a + b",
    "https://example.com/some/path?q=search",
    "API_KEY = 'placeholder'",
]


@pytest.mark.parametrize("text", BENIGN)
def test_benign_text_is_not_flagged(text: str) -> None:
    """Ordinary prose and placeholders must not fire -- otherwise the
    catalogue could 'pass' every detection test by matching everything."""
    assert not _detect(text), f"false positive on: {text!r}"


@pytest.mark.parametrize(
    ("label", "encode"),
    [
        ("utf-8", lambda text: text.encode("utf-8")),
        ("utf-8-BOM", lambda text: text.encode("utf-8-sig")),
        ("utf-16-BOM", lambda text: text.encode("utf-16")),
        ("utf-16-LE-no-BOM", lambda text: text.encode("utf-16-le")),
        ("utf-16-BE-no-BOM", lambda text: text.encode("utf-16-be")),
    ],
)
def test_repo_scan_detects_every_supported_text_encoding_with_clean_control(
    tmp_path, monkeypatch, label: str, encode
) -> None:
    value = "gh" + "p_" + "A9f2Kd8Lm3" + "Qp7Rt1Zx5V" + "b6Nc4Ye0Wu" + "2Ij8Hq"
    planted = f'auth = "{value}"\n'
    expected_count = len(secret_scan.scan_text("planted.txt", planted))
    assert expected_count > 0

    planted_name = "planted.txt"
    clean_name = "clean.txt"
    (tmp_path / planted_name).write_bytes(encode(planted))
    (tmp_path / clean_name).write_bytes(encode("auth = os.environ['AUTH']\n"))
    monkeypatch.setattr(secret_scan, "_tracked_files", lambda root: [planted_name, clean_name])

    findings = secret_scan.scan_repo(tmp_path)

    assert len([item for item in findings if item["file"] == planted_name]) == expected_count, label
    assert [item for item in findings if item["file"] == clean_name] == [], label


def test_repo_scan_deduplicates_views_to_utf8_count_with_clean_control(tmp_path, monkeypatch) -> None:
    value = "gh" + "p_" + "A9f2Kd8Lm3" + "Qp7Rt1Zx5V" + "b6Nc4Ye0Wu" + "2Ij8Hq"
    planted = f'auth = "{value}"\n'

    utf8_name = "utf8.txt"
    utf16_name = "utf16.txt"
    overlap_name = "nul-bearing.txt"
    clean_name = "clean.txt"
    (tmp_path / utf8_name).write_bytes(planted.encode("utf-8"))
    (tmp_path / utf16_name).write_bytes(planted.encode("utf-16-le"))
    (tmp_path / overlap_name).write_bytes(planted.encode("utf-8") + b"\x00")
    (tmp_path / clean_name).write_bytes(b"auth = os.environ['AUTH']\n\x00")
    monkeypatch.setattr(
        secret_scan,
        "_tracked_files",
        lambda root: [utf8_name, utf16_name, overlap_name, clean_name],
    )

    findings = secret_scan.scan_repo(tmp_path)
    counts = {
        name: len([item for item in findings if item["file"] == name]) for name in (utf8_name, utf16_name, overlap_name)
    }

    assert counts[utf8_name] > 0
    assert counts[utf16_name] == counts[utf8_name]
    assert counts[overlap_name] == counts[utf8_name]
    assert [item for item in findings if item["file"] == clean_name] == []


def test_catalogue_covers_the_major_ai_providers() -> None:
    """Guards the gap itself: a future edit that drops the whole AI-provider
    category should fail here even if every individual case above vanished."""
    names = {d["name"] for d in secret_scan.SECRET_PATTERN_DEFS}
    required = {
        "Anthropic OAuth Token",
        "Anthropic API Key",
        "OpenAI Project Key",
        "OpenAI API Key",
        "xAI API Key",
        "Groq API Key",
        "HuggingFace Token",
        "Replicate API Token",
    }
    missing = required - names
    assert not missing, f"AI-provider patterns missing from the catalogue: {sorted(missing)}"


def test_mask_secret_never_returns_the_full_value() -> None:
    secret = "sk-" + "Z" * 48
    masked = secret_scan.mask_secret(secret)
    assert secret not in masked
    assert masked != secret
    assert masked.startswith("sk-Z")


# --- name-vs-value discrimination -------------------------------------------
# These test cases use plain contiguous literals because they exercise the
# HEURISTIC half of the catalogue (Generic Secret Assignment), which is the
# only half suppressed on this path -- see secret_scan._HEURISTIC_EXEMPT_FILES.
# A VENDOR shape must still be split here like anywhere else: this file is
# read and vendor-scanned like every other candidate.


def test_screaming_snake_identifier_value_is_not_flagged() -> None:
    """A bare SCREAMING_SNAKE_CASE value is the NAME of a secret (an env var
    or GitHub Actions secret to read at runtime), not a credential value --
    real-world case: scripts/release_artifacts.py's RELEASE_GUARD_SECRET."""
    assert not _detect('RELEASE_GUARD_SECRET = "RELEASE_GUARD_READ_TOKEN"')


def test_screaming_snake_rule_does_not_swallow_a_real_looking_secret() -> None:
    """The identifier-value discrimination must be narrow: a value with
    mixed case and digits (i.e. actual entropy, not just an identifier
    shape) still has to fire Generic Secret Assignment."""
    hits = _detect('API_SECRET = "aB3xQ7zRt9LmZp2w"')  # secretsallow
    assert "Generic Secret Assignment" in hits


def test_screaming_snake_rule_does_not_weaken_vendor_patterns() -> None:
    """AWS Access Key IDs are themselves canonically all-uppercase-and-
    digits -- the identifier-value discrimination is scoped to the generic
    assignment patterns only and must not exempt a vendor-shaped credential
    just because it happens to look like a constant name."""
    hits = _detect("AWS_KEY = 'AKIA" + "Q" * 16 + "'")
    assert "AWS Access Key" in hits


def test_unresolved_template_placeholder_value_is_not_flagged() -> None:
    """An un-interpolated f-string/format placeholder like '{secret}' is
    template syntax, not a literal value -- real-world case: this file's own
    f"API_KEY = '{secret}'" parametrized-test line, and prose (e.g. a commit
    message) that quotes it verbatim."""
    assert not _detect("API_KEY = '{secret}'")
    assert not _detect("API_KEY = '${secret}'")
    assert not _detect("API_KEY = '%(secret)s'")


# --- no file is exempt from the VENDOR catalogue -----------------------------
#
# This file used to be skipped WHOLE, on the argument that a secret scanner
# cannot be tested without secret-shaped strings. Measured, that argument
# covered 1 line out of 538 -- every other fixture is already split across
# string-literal concatenations by this file's own documented discipline --
# while the blanket removed the file from 2 of the 3 catalogues that read the
# tree. 11 of 15 provider families had ZERO coverage inside it.
#
# What survives is a suppression of the seven HEURISTIC shapes on this one
# path, which is as far as the argument actually reaches: a fixture that trips
# "Generic Secret Assignment" is doing its job, and nothing legitimate here
# produces an sk-ant-oat01- or an AKIA.


def test_only_heuristic_shapes_are_suppressed_and_only_on_one_path() -> None:
    """The exemption is a CATALOGUE narrowing, not a skip, on one named path."""
    assert secret_scan._HEURISTIC_EXEMPT_FILES == frozenset({"tests/test_secret_scan.py"})
    assert secret_scan._is_heuristic_exempt("tests/test_secret_scan.py")
    assert secret_scan._is_heuristic_exempt("tests\\test_secret_scan.py")
    assert not secret_scan._is_heuristic_exempt("tests/test_secret_scan_other.py")
    assert not secret_scan._is_heuristic_exempt("tests/test_prepush_leak_scan.py")
    assert not secret_scan._is_heuristic_exempt("scripts/secret_scan.py")


def test_every_suppressed_name_is_a_real_catalogue_entry() -> None:
    """A rename in ``SECRET_PATTERN_DEFS`` must not silently widen or empty the
    suppressed half. The two lists live apart so the catalogue stays a verbatim
    port, which is exactly the drift this pins."""
    catalogue = {d["name"] for d in secret_scan.SECRET_PATTERN_DEFS}

    assert secret_scan.HEURISTIC_PATTERN_NAMES <= catalogue
    vendor = catalogue - secret_scan.HEURISTIC_PATTERN_NAMES
    # Every provider family in the reproduction matrix has to be on the vendor
    # side, or suppressing "heuristics" would still hide a real credential.
    for name in (
        "Anthropic OAuth Token",
        "Anthropic API Key",
        "OpenAI Project Key",
        "OpenAI API Key",
        "AWS Access Key",
        "GitHub Token",
        "GitLab Token",
        "Stripe Secret Key",
        "Google API Key",
        "NPM Token",
        "PyPI Token",
        "Private Key",
    ):
        assert name in vendor, f"{name} would be suppressed on the exempt path"


def test_heuristic_shapes_are_still_suppressed_on_the_exempt_path() -> None:
    """Conservation: the half of the argument that was always sound.

    A fixture line asserting that ``SECRET = "<value>"`` fires the generic rule
    is doing its job. Suppressed only where the exemption applies -- the same
    line anywhere else is a finding.
    """
    line = 'API_SECRET = "aB3xQ7zRt9LmZp2w"'  # secretsallow

    exempt = secret_scan.scan_text("tests/test_secret_scan.py", line, skip_heuristics=True)
    elsewhere = secret_scan.scan_text("tests/test_secret_scan.py", line)

    assert exempt == []
    assert [f["pattern_name"] for f in elsewhere] == ["Generic Secret Assignment"]


def test_a_live_credential_in_this_scanners_own_test_file_is_refused(tmp_path, monkeypatch, capsys) -> None:
    """The inverse of the test this replaces, and the whole point of the fix.

    Measured on the shipped scanner with a CONTIGUOUS live-format token
    appended to the real tracked file: ``secret scan: PASS ... 1 corpus-exempt
    ... 0 findings`` exit 0, ``check.leak_scan()`` True, ``artifact_scan()``
    True, and ``prepush_leak_scan`` clean exit 0 -- four gates, all green,
    over a credential in a tracked file. 11 of 15 provider families evaded
    every gate there; the 4 that did not were caught only by the overlap with
    ``check.py``'s 8-pattern catalogue, which is coincidence, not design.
    """
    token = "sk-" + "ant-" + "oat" + "01-" + "Aa9_-" * 12
    root = _repo_with(
        tmp_path,
        {
            "tests/test_secret_scan.py": f'LEAKED_TOKEN = "{token}"\n'.encode(),
            "readme.md": b"benign\n",
        },
    )
    monkeypatch.setattr(secret_scan, "ROOT", root)

    assert secret_scan.main([]) == 1
    error = capsys.readouterr().err
    assert "tests/test_secret_scan.py" in error
    assert "Anthropic OAuth Token" in error


def test_the_surviving_suppression_has_no_residents_at_the_tip() -> None:
    """The real tracked file scans clean under the FULL catalogue.

    This is the cost side of the fix, pinned rather than asserted. The one line
    that trips a heuristic carries the per-line ``# secretsallow`` marker, so
    the remaining exemption suppresses nothing today -- and if a future fixture
    starts relying on it, this test says so instead of the reliance being
    invisible.
    """
    path = secret_scan.ROOT / "tests" / "test_secret_scan.py"
    findings = secret_scan.scan_text("tests/test_secret_scan.py", path.read_text(encoding="utf-8"))

    assert findings == [], f"this scanner's own test file no longer scans clean: {findings}"


# --- the gate must never report clean without having read anything ----------


def test_tracked_inventory_ignores_inherited_git_redirection(monkeypatch, tmp_path) -> None:
    """``git ls-files`` must answer about THIS tree.

    An ambient ``GIT_INDEX_FILE``/``GIT_DIR``/``GIT_WORK_TREE`` points it at
    another index: exit 0, empty stdout, no error -- and the whole scan then
    reports clean having opened nothing.
    """
    captured: dict[str, object] = {}

    def fake_run(*args, **kwargs):
        captured["environment"] = kwargs["env"]
        return subprocess.CompletedProcess(args[0], 0, stdout=b"README.md\0", stderr=b"")

    monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "elsewhere.index"))
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "elsewhere.git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path))
    monkeypatch.setattr(secret_scan.subprocess, "run", fake_run)

    assert secret_scan._tracked_files(tmp_path) == ["README.md"]
    assert not [key for key in captured["environment"] if key.upper().startswith("GIT_")]


def test_empty_tracked_inventory_fails_the_scan_closed(monkeypatch, tmp_path) -> None:
    """Zero tracked files means the inventory did not compute, not that the
    repository is clean. A successful-but-empty ``git ls-files`` must not let
    the CI secret gate exit 0 without decoding a single byte."""
    empty = subprocess.CompletedProcess(["git", "ls-files"], 0, stdout=b"", stderr=b"")
    monkeypatch.setattr(secret_scan.subprocess, "run", lambda *args, **kwargs: empty)

    with pytest.raises(SystemExit) as excinfo:
        secret_scan._tracked_files(tmp_path)
    assert "zero tracked files" in str(excinfo.value)


def test_new_nonignored_file_is_scanned_and_healthy_inventory_stays_clean(tmp_path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "README.md").write_text("healthy\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    value = "gh" + "p_" + "A9f2Kd8Lm3" + "Qp7Rt1Zx5V" + "b6Nc4Ye0Wu" + "2Ij8Hq"
    (tmp_path / "fresh.py").write_text("auth = " + repr(value) + "\n", encoding="utf-8")

    findings = secret_scan.scan_repo(tmp_path)

    assert secret_scan._tracked_files(tmp_path) == ["README.md", "fresh.py"]
    assert any(finding["file"] == "fresh.py" for finding in findings)
    (tmp_path / "fresh.py").write_text("auth = os.environ['AUTH']\n", encoding="utf-8")
    assert secret_scan.scan_repo(tmp_path) == []


def test_clean_secret_scan_reports_established_and_examined_counts(tmp_path, monkeypatch, capsys) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "README.md").write_text("healthy\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    (tmp_path / "fresh.py").write_text("healthy = True\n", encoding="utf-8")
    monkeypatch.setattr(secret_scan, "ROOT", tmp_path)

    assert secret_scan.main([]) == 0
    assert (
        "established 2 candidate paths; examined 2 text files; 0 binary-skipped; "
        "0 path-skipped; 0 absent; 0 unscannable; 0 heuristics-suppressed; 0 findings" in capsys.readouterr().out
    )


def test_unreadable_tracked_file_is_reported_not_skipped(monkeypatch, tmp_path) -> None:
    """Content the scanner could not decode is not content it proved clean.

    ``scripts/check.py::_scan_file_for_leaks`` already reports an unreadable
    tracked file; this scanner used to ``continue`` past it.
    """
    (tmp_path / "locked.py").write_text("placeholder\n", encoding="utf-8")
    monkeypatch.setattr(secret_scan, "_tracked_files", lambda root: ["locked.py"])

    def deny(self, *args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(secret_scan.Path, "read_bytes", deny)

    findings = secret_scan.scan_repo(tmp_path)
    assert [(f["file"], f["pattern_name"]) for f in findings] == [("locked.py", "Unscannable Candidate File")]


# ---------------------------------------------------------------------------
# A NAME IS NOT A MEASUREMENT.
#
# The scanner used to decide "binary, do not open" from a suffix list, so it
# never read a file it had already enumerated as a candidate. Measured on the
# shipped scanner: a plain-text file named ``logo.png`` carrying an AWS access
# key produced ``candidates=2 examined=1 findings=0`` -- and because ``.lock``
# sat in that same list beside ``.exe``, all four ``release/*.lock`` files
# (plain-text pip requirement files, the natural home for an ``--index-url``
# credential) were examined by no scanner at all.
# ---------------------------------------------------------------------------


def _repo_with(tmp_path, files: dict[str, bytes]):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    for rel, blob in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
        subprocess.run(["git", "add", "--", rel], cwd=tmp_path, check=True)
    return tmp_path


def test_credential_under_a_binary_looking_name_is_read_not_skipped(tmp_path) -> None:
    key = "AKIA" + "Z" * 16
    root = _repo_with(tmp_path, {"logo.png": f'aws = "{key}"\n'.encode()})

    scan = secret_scan._scan_repo(root)

    assert scan.files_examined == 1, "the file was enumerated as a candidate and then never opened"
    assert [(f["file"], f["pattern_name"]) for f in scan.findings] == [("logo.png", "AWS Access Key")]


def test_pypi_token_in_a_lock_file_is_found(tmp_path) -> None:
    """``release/*.lock`` are plain-text pip requirement files. A publish
    credential's natural home is their ``--index-url`` line, and ``.lock`` was
    on the do-not-open list, so this file was read by nothing."""
    token = "pypi-" + "AgEIcHlwaS5vcmcC" + "Aa9_-" * 24
    root = _repo_with(tmp_path, {"release/tooling-requirements.lock": f"--index-url https://u:{token}@i/s\n".encode()})

    scan = secret_scan._scan_repo(root)

    assert scan.files_examined == 1
    assert [(f["file"], f["pattern_name"]) for f in scan.findings] == [
        ("release/tooling-requirements.lock", "PyPI Token")
    ]


def test_genuine_binary_is_not_pattern_matched_but_is_refused_by_name(tmp_path) -> None:
    """Conservation AND fail-closed in one fixture.

    Conservation: a real PNG still produces no credential-shaped finding --
    deciding from content must not turn every committed image into catalogue
    noise. Fail-closed: it produces an ``Unscannable Candidate File`` finding
    instead of a silent bucket entry, because no pattern ever ran over those
    bytes and "0 findings" for them is a verdict this scan did not compute.
    """
    png = bytes.fromhex("89504e470d0a1a0a0000000d49484452") + bytes(range(256)) * 4
    root = _repo_with(tmp_path, {"image.png": png, "readme.md": b"benign\n"})

    scan = secret_scan._scan_repo(root)

    assert (scan.candidates, scan.files_examined, scan.binary_skipped) == (2, 1, 1)
    assert [(f["file"], f["pattern_name"]) for f in scan.findings] == [("image.png", "Unscannable Candidate File")]
    assert scan.unaccounted == 0


def test_binary_credential_beside_one_readable_file_refuses(tmp_path, monkeypatch, capsys) -> None:
    """The escape the ``examined == 0`` floor could never catch.

    A NUL-prefixed file whose remaining bytes are a live-format credential is
    classified binary by every gate here, so no catalogue reads it -- and the
    only guard was a RANGE-GLOBAL floor that a single readable companion file
    defeats. Measured on the shipped scanner over the real 51-file tree, this
    exact probe produced ``PASS ... 1 binary-skipped ... 0 findings``, exit 0.

    The existing binary fixtures were single-file repositories, which is why
    the floor looked sufficient and the companion escape survived.
    """
    token = "sk-" + "ant-" + "oat" + "01-" + "Aa7_-" * 12
    probe = b"\x00\x80" + f"index-url = https://__token__:{token}@pypi.example.invalid/simple\n".encode()
    root = _repo_with(tmp_path, {"release/toolstate.dat": probe, "readme.md": b"benign\n"})
    monkeypatch.setattr(secret_scan, "ROOT", root)

    assert secret_scan.main([]) == 1
    error = capsys.readouterr().err
    assert "release/toolstate.dat" in error, "the unread tracked file is not named in the refusal"
    assert "Unscannable Candidate File" in error


def test_scan_that_read_nothing_refuses_instead_of_passing(tmp_path, monkeypatch, capsys) -> None:
    """``examined == 0`` is the estate's signature false clean: the same output
    a working scan of a clean tree prints, with an empty denominator behind
    it. The printed number is now acted on, not merely disclosed.

    The fixture is a path-skipped candidate rather than a binary one: binary
    content is a finding now, so it exits 1 before this floor is reached. The
    floor stays because it is correct -- it was never sufficient on its own,
    since a single readable companion file lifts ``examined`` above zero.
    """
    root = _repo_with(tmp_path, {"build/generated.py": b"generated = True\n"})
    monkeypatch.setattr(secret_scan, "ROOT", root)

    assert secret_scan.main([]) == 3
    assert "read the content of none of them" in capsys.readouterr().err


def test_scanner_that_finds_nothing_reports_broken_not_clean(tmp_path, monkeypatch, capsys) -> None:
    """The planted-control discipline ``prepush_leak_scan`` already had. With
    the catalogue emptied this scanner printed ``PASS (established 51
    candidate paths; examined 46 text files; 0 findings)`` over the real
    repository and returned 0."""
    root = _repo_with(tmp_path, {"readme.md": b"benign\n"})
    monkeypatch.setattr(secret_scan, "ROOT", root)
    assert secret_scan._self_test_failures() == [], "the positive control does not pass on healthy code"

    monkeypatch.setattr(secret_scan, "_COMPILED_PATTERNS", [])

    assert secret_scan._self_test_failures(), "an emptied catalogue passed the scanner's own positive control"
    assert secret_scan.main([]) == 4
    assert "positive control failed" in capsys.readouterr().err


def test_positive_control_covers_a_family_the_narrow_catalogue_misses(monkeypatch) -> None:
    """One planted case per provider FAMILY, never one overall: the first gate
    built against this defect self-tested with a GitHub token, passed, and let
    a real Anthropic OAuth token through untouched."""
    survivors = [p for p in secret_scan._COMPILED_PATTERNS if p["name"] != "Anthropic OAuth Token"]
    monkeypatch.setattr(secret_scan, "_COMPILED_PATTERNS", survivors)

    assert secret_scan._self_test_failures() == ["planted control secret not detected: Anthropic OAuth Token"]


def test_tracked_symlink_is_reported_and_worktree_deletion_is_not(monkeypatch, tmp_path) -> None:
    """A symlink can point the scanner's read outside the scanned content, so
    it is a finding. A tracked path deleted from the worktree genuinely has no
    content to scan, so it stays a skip -- a true nothing, not an uncomputed
    one."""
    monkeypatch.setattr(secret_scan, "_tracked_files", lambda root: ["link.py", "deleted.py"])
    monkeypatch.setattr(secret_scan.Path, "is_symlink", lambda self: self.name == "link.py")

    findings = secret_scan.scan_repo(tmp_path)
    assert [(f["file"], f["matched_text"]) for f in findings] == [("link.py", "symlink candidate")]


# ---------------------------------------------------------------------------
# A DIRECTORY THAT IS NEVER OPENED IS INVISIBLE TO EVERY PATTERN.
#
# The suffix half of name-based skipping was removed at 4f3e203; the DIRECTORY
# half stayed, with the claim that the residual was "already fatal at the tree
# gate (artifact_scan), so the exposure is history-only". Measured, that was
# true for 5 of the 13 skipped names and false for the other 7 -- and the
# exposure was reachable in the CURRENT tracked tree, not only in history. A
# tracked ``venv/pip.conf`` carrying an ``sk-ant-oat01-`` token passed
# secret_scan (PASS, exit 0), check.leak_scan (PASS), check.artifact_scan
# (PASS) and prepush_leak_scan (clean, exit 0) simultaneously.
#
# Widening the catalogue would not have touched it: secret_scan's catalogue
# ALREADY matched that content when handed it. The bytes were never read.
# ---------------------------------------------------------------------------

_PLANTED_ANTHROPIC_TOKEN = "sk-" + "ant-" + "oat" + "01-" + "Qw7zR2mK9bT4xL6vN8pD3sG5hJ1cF0yA" * 2
_PLANTED_PIP_CONF = f"[global]\nextra-index-url = https://x:{_PLANTED_ANTHROPIC_TOKEN}@i.invalid/s\n".encode()


def test_credential_tracked_under_a_venv_directory_is_read(tmp_path) -> None:
    """``venv`` is the one skipped name that can legitimately BE tracked source
    -- CPython ships ``Lib/venv/__init__.py`` -- so it cannot be made fatal,
    which under the rule below means it cannot be left unread either. It is
    scanned now; ``.gitignore`` keeps a local virtualenv out of the inventory.
    """
    root = _repo_with(tmp_path, {"venv/pip.conf": _PLANTED_PIP_CONF, "benign.txt": b"plain text\n"})

    scan = secret_scan._scan_repo(root)

    assert scan.path_skipped == (), "venv/ is still being skipped unread"
    assert [(f["file"], f["pattern_name"]) for f in scan.findings] == [("venv/pip.conf", "Anthropic OAuth Token")]


def test_skipped_path_is_counted_and_named_never_silently_absent(tmp_path, monkeypatch, capsys) -> None:
    """The remaining skips must show up IN the denominator. The shipped verdict
    printed ``established 54 candidate paths; examined 51 text files`` over a
    tree holding a tracked credential: the three unexamined paths were the
    entire defect, published as nothing but a gap between two numbers."""
    root = _repo_with(tmp_path, {".tox/py311/pip.conf": _PLANTED_PIP_CONF, "benign.txt": b"plain text\n"})
    monkeypatch.setattr(secret_scan, "ROOT", root)

    scan = secret_scan._scan_repo(root)
    assert scan.path_skipped == (".tox/py311/pip.conf",)
    assert scan.unaccounted == 0, "a candidate path reached no disposition"

    assert secret_scan.main([]) == 0
    out = capsys.readouterr().out
    assert "1 path-skipped" in out, out
    assert ".tox/py311/pip.conf" in out, "a skipped path is not named anywhere in the verdict"


def test_every_candidate_path_lands_in_exactly_one_bucket(tmp_path) -> None:
    """The reconciliation itself, over one candidate of every disposition."""
    png = bytes.fromhex("89504e470d0a1a0a0000000d49484452") + bytes(range(256)) * 4
    root = _repo_with(
        tmp_path,
        {
            "benign.txt": b"plain text\n",
            "image.png": png,
            "build/generated.py": b"generated = True\n",
            "tests/test_secret_scan.py": b"corpus\n",
        },
    )

    scan = secret_scan._scan_repo(root)

    # The scanner's own test file is now READ like any other candidate, so it
    # lands in ``files_examined``. ``heuristics_suppressed`` is a disclosure
    # about WHICH catalogue ran there, not a bucket outside the denominator.
    assert (scan.candidates, scan.files_examined, scan.binary_skipped) == (4, 2, 1)
    assert scan.path_skipped == ("build/generated.py",)
    assert scan.heuristics_suppressed == ("tests/test_secret_scan.py",)
    assert scan.unaccounted == 0


def test_unreconciled_denominator_refuses_instead_of_passing(tmp_path, monkeypatch, capsys) -> None:
    """A future edit that adds a silent ``continue`` to the scan loop must fail
    loudly rather than shrink the denominator behind a PASS. Simulated by
    dropping a candidate on the floor."""
    root = _repo_with(tmp_path, {"benign.txt": b"plain text\n", "other.txt": b"also plain\n"})
    monkeypatch.setattr(secret_scan, "ROOT", root)
    real_scan_repo = secret_scan._scan_repo
    monkeypatch.setattr(
        secret_scan,
        "_scan_repo",
        lambda root: real_scan_repo(root)._replace(files_examined=1),
    )

    assert secret_scan.main([]) == 5
    assert "reached no disposition" in capsys.readouterr().err
