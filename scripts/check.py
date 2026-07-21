#!/usr/bin/env python3
"""Pre-push pipeline — every commit ships polished or not at all.

Mirrors roam-code's prepush_check discipline at this repo's scale:
locked-graph vulnerability audit, lint, format, workflow security, tests,
leak/package sweeps, README truth, and release-contract sanity. Wired via
``.githooks/pre-push`` (``git config core.hooksPath .githooks``);
run by hand any time: ``python3 scripts/check.py``.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import importlib.metadata as importlib_metadata
import importlib.util
import json
import math
import os
import re
import stat
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Credential shapes + private-infrastructure strings that must never ship.
LEAK_PATTERNS = [
    (r"(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})", "GitHub token"),
    (r"sk-[A-Za-z0-9]{20,}", "API secret key"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "PEM private key"),
    (r"/root/(apps|services|repos)/", "VPS-local path"),
    (r"\binternal/(planning|dogfood)/", "private internal reference"),
    (r"(?i)\b(transcripts?|session-exports?)/", "private transcript export reference"),
]
ARTIFACT_SEGMENTS = (".venv", "node_modules", "dist", "build", "__pycache__")

# Claims retired by the 2026-07-14 public-claims audit. A match fails unless
# an allow-marker shares its line(s) — i.e. the claim is quoted as corrected
# history ("an earlier ... wording", a parity caveat), not asserted as truth.
RETIRED_CLAIMS = [
    (r"91%\s+of\s+envelopes", "retired 91% pre-executed claim (corrected: 57% L1 + ~33% facts)", ()),
    (r"10/10[\s\S]{0,40}?both\s+arms", "10/10 both-arms phrasing without the parity caveat", ("parity", "n=10")),
    (r"[−-]86%\s+turns", "retired -86% Opus turns claim (corrected: -33% overall)", ("corrected",)),
    (r"pip\s+install\s+compile-code(?![\w-])", "unpinned bare pip install compile-code", ("pypi", "uninstall")),
]
RELEASE_LOCKS = (
    "release/tooling-requirements.lock",
    "release/build-requirements.lock",
    "release/smoke-requirements.lock",
)
RELEASE_REQUIREMENT = re.compile(r"(?m)^([a-z0-9][a-z0-9._-]*)==([^\s;\\]+).*$")
MAX_SCHEMA_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 128
MAX_CHECK_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_ZIZMOR_BYTES = 64 * 1024 * 1024
MAX_ZIZMOR_TRUST_BYTES = 64 * 1024
ZIZMOR_DISTRIBUTION = "zizmor"
ZIZMOR_VERSION = "1.27.0"
ZIZMOR_BOOTSTRAP_ARGUMENT = "--bootstrap-zizmor"
ZIZMOR_LOCK_STANZA_SHA256 = "12d59686b33400defcea1970cb2b8a876d88aba0c556e5c2b14762a60b4f7480"
ZIZMOR_LOCK_ARTIFACT_HASH_COUNT = 11
ZIZMOR_BINARY_WHEEL_COUNT = 10
ZIZMOR_TRUST_SCHEMA = "compile-code.release-tool-artifacts.v1"
ZIZMOR_TRUST_MANIFEST = ROOT / "release" / "zizmor-artifact-trust.json"
ZIZMOR_TRUST_MANIFEST_SHA256 = "c5f5d33c91bbf4f56bb30f629edd4978c22d11503b9db42a5dff62c6d6260763"
ZIZMOR_AUDITOR_POLICY = ("--persona", "auditor", "--no-ignores", "--min-severity", "medium")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class ToolIdentityError(RuntimeError):
    """An installed release tool does not match its reviewed lock identity."""


def _console_safe(value: str) -> str:
    """Keep bounded tool diagnostics printable on narrow Windows consoles."""
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        return value.encode(encoding, "backslashreplace").decode(encoding)
    except LookupError:
        return value.encode("ascii", "backslashreplace").decode("ascii")


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _parse_bounded_json_int(value: str) -> int:
    if len(value.removeprefix("-")) > 128:
        raise ValueError("JSON integer literal is oversized")
    return int(value)


def _parse_finite_json_float(value: str) -> float:
    if len(value) > 128:
        raise ValueError("JSON floating-point literal is oversized")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number: {value}")
    return parsed


def _strict_json_document(data: bytes, label: str) -> object:
    if len(data) > MAX_SCHEMA_BYTES:
        raise ValueError(f"{label} exceeds {MAX_SCHEMA_BYTES} bytes")
    depth = 0
    in_string = False
    escaped = False
    for value in data:
        if in_string:
            if escaped:
                escaped = False
            elif value == 0x5C:
                escaped = True
            elif value == 0x22:
                in_string = False
            continue
        if value == 0x22:
            in_string = True
        elif value in {0x5B, 0x7B}:
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError(f"{label} exceeds the JSON nesting limit")
        elif value in {0x5D, 0x7D}:
            depth -= 1
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"non-finite JSON number: {value}")),
            parse_float=_parse_finite_json_float,
            parse_int=_parse_bounded_json_int,
        )
    except RecursionError as exc:
        raise ValueError(f"{label} exceeds the JSON nesting limit") from exc


def _path_is_committed_artifact(rel: str) -> bool:
    """Return whether a tracked relative path belongs to a build artifact."""
    return any(segment in ARTIFACT_SEGMENTS or segment.endswith(".egg-info") for segment in rel.split("/"))


def _without_git_controls(environment: dict[str, str] | None = None) -> dict[str, str]:
    """Copy an environment without repository-redirection controls exported by Git hooks."""
    source = os.environ if environment is None else environment
    return {key: value for key, value in source.items() if not key.upper().startswith("GIT_")}


def _repository_state() -> bytes:
    """Return a stable snapshot that binds HEAD, index, and tracked/untracked state."""
    try:
        proc = subprocess.run(
            [
                "git",
                "status",
                "--porcelain=v2",
                "--branch",
                "--no-ahead-behind",
                "--untracked-files=all",
                "-z",
            ],
            cwd=ROOT,
            env=_without_git_controls(),
            capture_output=True,
            timeout=60,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("git executable is unavailable") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("git status exceeded the 60s snapshot timeout") from exc
    except OSError as exc:
        raise RuntimeError(f"could not launch git status: {exc}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()[-1_000:]
        raise RuntimeError(f"git status failed ({proc.returncode}): {detail}")
    return proc.stdout


def run(
    title: str,
    cmd: list[str],
    *,
    env: dict[str, str] | None = None,
    protect_repository: bool = False,
) -> bool:
    repository_before: bytes | None = None
    detail = ""
    execution_error = ""
    output_bounded = True
    returncode: int | None = None
    if protect_repository:
        try:
            repository_before = _repository_state()
        except RuntimeError as exc:
            print(f"[check] {title}: FAIL")
            print(f"could not snapshot repository before the command: {exc}")
            return False
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            proc = subprocess.run(cmd, cwd=ROOT, env=env, stdout=stdout, stderr=stderr, timeout=1200)
            returncode = proc.returncode
            stdout_size = os.fstat(stdout.fileno()).st_size
            stderr_size = os.fstat(stderr.fileno()).st_size
            output_bounded = stdout_size <= MAX_CHECK_OUTPUT_BYTES and stderr_size <= MAX_CHECK_OUTPUT_BYTES
            if proc.returncode != 0 or not output_bounded:
                stdout.seek(max(0, stdout_size - 2_000))
                stderr.seek(max(0, stderr_size - 2_000))
                detail = (stdout.read(2_000) + stderr.read(2_000)).decode("utf-8", "replace").strip()
    except FileNotFoundError:
        execution_error = f"required executable not found: {cmd[0]}"
    except OSError as exc:
        execution_error = f"could not launch {cmd[0]}: {exc}"
    except subprocess.TimeoutExpired:
        execution_error = f"command exceeded the 1200s gate timeout: {' '.join(cmd)}"
    repository_unchanged = True
    repository_error = ""
    if repository_before is not None:
        try:
            repository_unchanged = _repository_state() == repository_before
        except RuntimeError as exc:
            repository_unchanged = False
            repository_error = f"could not snapshot repository after the command: {exc}"
    ok = returncode == 0 and not execution_error and output_bounded and repository_unchanged
    print(f"[check] {title}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        if execution_error:
            print(execution_error)
        if repository_error:
            print(repository_error)
        elif not repository_unchanged:
            print("command changed repository HEAD, index, or worktree state")
        if not output_bounded:
            print(f"command output exceeded the {MAX_CHECK_OUTPUT_BYTES}-byte per-stream limit")
        if detail:
            print(_console_safe(detail[-2_000:]))
    return ok


def _normalized_path(path: Path) -> str:
    """Return a platform-normalized absolute path without requiring existence."""
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _hash_regular_file(path: Path, *, expected_size: int) -> bytes:
    """Hash one stable, singly linked regular file without following a final symlink."""
    if expected_size < 1 or expected_size > MAX_ZIZMOR_BYTES:
        raise ToolIdentityError("zizmor RECORD size is outside the accepted bound")
    try:
        before_path = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise ToolIdentityError(f"zizmor executable is unavailable: {exc}") from exc
    if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
        raise ToolIdentityError("zizmor executable must be a regular non-symlink file")
    if before_path.st_nlink != 1:
        raise ToolIdentityError("zizmor executable must have exactly one hard link")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ToolIdentityError(f"zizmor executable could not be opened safely: {exc}") from exc
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise ToolIdentityError("zizmor executable changed before identity verification")
        if opened.st_size != expected_size:
            raise ToolIdentityError("zizmor executable size does not match its wheel RECORD")
        while chunk := os.read(descriptor, min(1024 * 1024, MAX_ZIZMOR_BYTES + 1 - total)):
            total += len(chunk)
            if total > MAX_ZIZMOR_BYTES:
                raise ToolIdentityError("zizmor executable exceeds the accepted size bound")
            digest.update(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise ToolIdentityError(f"zizmor executable could not be read safely: {exc}") from exc
    finally:
        os.close(descriptor)
    try:
        after_path = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise ToolIdentityError("zizmor executable disappeared during identity verification") from exc

    def identity(info: os.stat_result) -> tuple[int, ...]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
        )

    identity_before = identity(before_path)
    identity_opened = identity(opened)
    identity_after = identity(after)
    identity_path_after = identity(after_path)
    if len({identity_before, identity_opened, identity_after, identity_path_after}) != 1:
        raise ToolIdentityError("zizmor executable changed during identity verification")
    if total != expected_size:
        raise ToolIdentityError("zizmor executable ended before its wheel RECORD size")
    return digest.digest()


def _zizmor_version(path: Path) -> str:
    """Read a small exact version response without buffering attacker-sized output."""
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            proc = subprocess.run(
                [str(path), "--version"],
                cwd=ROOT,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=30,
                check=False,
            )
            stdout_size = os.fstat(stdout.fileno()).st_size
            stderr_size = os.fstat(stderr.fileno()).st_size
            if proc.returncode != 0 or stdout_size > 4096 or stderr_size:
                raise ToolIdentityError("zizmor --version did not return one bounded successful response")
            stdout.seek(0)
            output = stdout.read(4097).decode("utf-8", "strict")
            expected = f"zizmor {ZIZMOR_VERSION}"
            if output not in {expected, f"{expected}\n", f"{expected}\r\n"}:
                raise ToolIdentityError("zizmor --version returned unexpected bytes")
            return expected
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
        raise ToolIdentityError(f"zizmor --version could not be verified: {exc}") from exc


def _verified_zizmor_path() -> Path:
    """Resolve zizmor only from this interpreter's exact installed distribution."""
    trusted_executables = _trusted_zizmor_executables()
    try:
        distribution = importlib_metadata.distribution(ZIZMOR_DISTRIBUTION)
    except importlib_metadata.PackageNotFoundError as exc:
        raise ToolIdentityError(f"{ZIZMOR_DISTRIBUTION}=={ZIZMOR_VERSION} is not installed") from exc
    try:
        if distribution.version != ZIZMOR_VERSION:
            raise ToolIdentityError(
                f"zizmor version drift: installed {distribution.version}; expected {ZIZMOR_VERSION}"
            )

        executable_name = "zizmor.exe" if sys.platform == "win32" else "zizmor"
        scripts_location = sysconfig.get_path("scripts")
        if not scripts_location:
            raise ToolIdentityError("active Python has no configured scripts directory")
        expected_path = Path(os.path.abspath(os.fspath(Path(scripts_location) / executable_name)))
        records = []
        for record in distribution.files or ():
            if record.name != executable_name:
                continue
            candidate = Path(os.path.abspath(os.fspath(distribution.locate_file(record))))
            if _normalized_path(candidate) == _normalized_path(expected_path):
                records.append((record, candidate))
        if len(records) != 1:
            raise ToolIdentityError("zizmor wheel RECORD does not bind exactly one configured scripts executable")

        record, candidate = records[0]
        if record.hash is None or record.hash.mode != "sha256" or record.size is None:
            raise ToolIdentityError("zizmor wheel RECORD lacks a SHA-256 or size")
        try:
            record_size = int(record.size)
        except (TypeError, ValueError) as exc:
            raise ToolIdentityError("zizmor wheel RECORD size is malformed") from exc
        actual_digest = _hash_regular_file(candidate, expected_size=record_size)
        record_hash = base64.urlsafe_b64encode(actual_digest).rstrip(b"=").decode("ascii")
        if record_hash != record.hash.value:
            raise ToolIdentityError("zizmor executable SHA-256 does not match its wheel RECORD")
        if (actual_digest.hex(), record_size) not in trusted_executables:
            raise ToolIdentityError("zizmor executable is absent from the checked-in lock-derived artifact trust set")
        version = _zizmor_version(candidate)
        if version != f"zizmor {ZIZMOR_VERSION}":
            raise ToolIdentityError(f"zizmor executable reported an unexpected version: {version!r}")
        return candidate
    except ToolIdentityError:
        raise
    except Exception as exc:
        raise ToolIdentityError(f"zizmor installation metadata is malformed ({type(exc).__name__})") from exc


def _locked_zizmor_requirement() -> str:
    """Extract the one reviewed zizmor stanza without duplicating its wheel hashes."""
    lock_path = ROOT / "release" / "tooling-requirements.lock"
    try:
        text = lock_path.read_text(encoding="utf-8")
        starts = list(RELEASE_REQUIREMENT.finditer(text))
    except (OSError, UnicodeError) as exc:
        raise ToolIdentityError("tooling lock is unavailable or not UTF-8") from exc
    matches = []
    for index, match in enumerate(starts):
        if match.group(1) != ZIZMOR_DISTRIBUTION:
            continue
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        matches.append((match, text[match.start() : end].rstrip() + "\n"))
    if len(matches) != 1 or matches[0][0].group(2) != ZIZMOR_VERSION:
        raise ToolIdentityError(f"tooling lock must contain exactly {ZIZMOR_DISTRIBUTION}=={ZIZMOR_VERSION}")
    requirement = matches[0][1]
    problems = _lock_problems("release/tooling-requirements.lock:zizmor", requirement)
    hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", requirement)
    digest = hashlib.sha256(requirement.encode("utf-8")).hexdigest()
    if (
        problems
        or len(hashes) != ZIZMOR_LOCK_ARTIFACT_HASH_COUNT
        or len(hashes) != len(set(hashes))
        or digest != ZIZMOR_LOCK_STANZA_SHA256
    ):
        raise ToolIdentityError("zizmor lock stanza does not match the exact reviewed wheel hash set")
    return requirement


def _trusted_zizmor_executables() -> frozenset[tuple[str, int]]:
    """Load the immutable executable identities extracted from every locked wheel."""
    requirement = _locked_zizmor_requirement()
    lock_hashes = set(re.findall(r"--hash=sha256:([0-9a-f]{64})", requirement))
    try:
        raw = ZIZMOR_TRUST_MANIFEST.read_bytes()
    except OSError as exc:
        raise ToolIdentityError("zizmor artifact trust manifest is unavailable") from exc
    if len(raw) > MAX_ZIZMOR_TRUST_BYTES:
        raise ToolIdentityError("zizmor artifact trust manifest exceeds its size bound")
    try:
        document = _strict_json_document(raw, "zizmor artifact trust manifest")
        canonical = json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ToolIdentityError("zizmor artifact trust manifest is not strict bounded JSON") from exc
    if hashlib.sha256(canonical).hexdigest() != ZIZMOR_TRUST_MANIFEST_SHA256:
        raise ToolIdentityError("zizmor artifact trust manifest does not match its reviewed semantic digest")
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "distribution",
        "version",
        "lock_stanza_sha256",
        "artifacts",
    }:
        raise ToolIdentityError("zizmor artifact trust manifest has an unexpected top-level shape")
    if (
        document["schema"] != ZIZMOR_TRUST_SCHEMA
        or document["distribution"] != ZIZMOR_DISTRIBUTION
        or document["version"] != ZIZMOR_VERSION
        or document["lock_stanza_sha256"] != ZIZMOR_LOCK_STANZA_SHA256
    ):
        raise ToolIdentityError("zizmor artifact trust manifest metadata does not match the reviewed lock")
    artifacts = document["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != ZIZMOR_LOCK_ARTIFACT_HASH_COUNT:
        raise ToolIdentityError("zizmor artifact trust manifest has an unexpected artifact count")

    archive_hashes: set[str] = set()
    filenames: set[str] = set()
    executable_identities: set[tuple[str, int]] = set()
    source_count = 0
    wheel_count = 0
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ToolIdentityError("zizmor artifact trust manifest contains a non-object artifact")
        filename = artifact.get("filename")
        archive_hash = artifact.get("archive_sha256")
        if (
            not isinstance(filename, str)
            or not filename
            or Path(filename).name != filename
            or any(ord(character) < 32 for character in filename)
            or not isinstance(archive_hash, str)
            or _SHA256_HEX.fullmatch(archive_hash) is None
            or filename in filenames
            or archive_hash in archive_hashes
        ):
            raise ToolIdentityError("zizmor artifact trust manifest contains an invalid or duplicate artifact")
        filenames.add(filename)
        archive_hashes.add(archive_hash)

        if artifact.get("source_only") is True:
            if set(artifact) != {"filename", "archive_sha256", "source_only"} or not filename.endswith(".tar.gz"):
                raise ToolIdentityError("zizmor source artifact trust entry is malformed")
            source_count += 1
            continue
        if set(artifact) != {"filename", "archive_sha256", "executable_sha256", "executable_size"}:
            raise ToolIdentityError("zizmor wheel artifact trust entry is malformed")
        executable_hash = artifact["executable_sha256"]
        executable_size = artifact["executable_size"]
        if (
            not filename.endswith(".whl")
            or not isinstance(executable_hash, str)
            or _SHA256_HEX.fullmatch(executable_hash) is None
            or not isinstance(executable_size, int)
            or isinstance(executable_size, bool)
            or executable_size < 1
            or executable_size > MAX_ZIZMOR_BYTES
            or (executable_hash, executable_size) in executable_identities
        ):
            raise ToolIdentityError("zizmor wheel artifact trust entry has an invalid executable identity")
        executable_identities.add((executable_hash, executable_size))
        wheel_count += 1

    if (
        archive_hashes != lock_hashes
        or source_count != 1
        or wheel_count != ZIZMOR_BINARY_WHEEL_COUNT
        or len(executable_identities) != ZIZMOR_BINARY_WHEEL_COUNT
    ):
        raise ToolIdentityError("zizmor artifact trust manifest does not cover the exact reviewed lock artifacts")
    return frozenset(executable_identities)


def bootstrap_zizmor() -> bool:
    """Explicitly install only the exact hash-locked zizmor wheel, then verify it."""
    try:
        requirement = _locked_zizmor_requirement()
    except (OSError, ToolIdentityError) as exc:
        print("[check] bootstrap exact zizmor: FAIL")
        print(f"  {exc}")
        return False
    requirement_path: Path | None = None
    cleanup_error: OSError | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".lock", delete=False) as handle:
            handle.write(requirement)
            requirement_path = Path(handle.name)
        environment = os.environ.copy()
        environment.update(
            {
                "PIP_CONFIG_FILE": os.devnull,
                "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                "PIP_NO_INPUT": "1",
            }
        )
        installed = run(
            "bootstrap exact hash-locked zizmor",
            [
                sys.executable,
                "-m",
                "pip",
                "--isolated",
                "install",
                "--no-cache-dir",
                "--no-compile",
                "--no-deps",
                "--require-hashes",
                "--only-binary=:all:",
                "--force-reinstall",
                "-r",
                str(requirement_path),
            ],
            env=environment,
        )
        if not installed:
            return False
        importlib.invalidate_caches()
        path = _verified_zizmor_path()
    except (OSError, ToolIdentityError) as exc:
        print("[check] verify bootstrapped zizmor identity: FAIL")
        print(f"  {exc}")
        return False
    finally:
        if requirement_path is not None:
            try:
                requirement_path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                cleanup_error = exc
    if cleanup_error is not None:
        print("[check] remove temporary zizmor lock: FAIL")
        print(f"  {cleanup_error}")
        return False
    print(f"[check] verify bootstrapped zizmor identity: PASS ({path.name} {ZIZMOR_VERSION})")
    return True


def zizmor_gates() -> list[bool]:
    """Run both mandatory workflow audits with one exact verified executable."""
    try:
        zizmor = _verified_zizmor_path()
    except ToolIdentityError as exc:
        print("[check] zizmor identity: FAIL")
        print(f"  {exc}")
        print(f"  repair: {sys.executable} scripts/check.py {ZIZMOR_BOOTSTRAP_ARGUMENT}")
        print("[check] zizmor auditor medium+ (ignores disabled): FAIL (verified executable unavailable)")
        print("[check] zizmor --pedantic: FAIL (verified executable unavailable)")
        return [False, False, False]
    print(f"[check] zizmor identity: PASS ({zizmor.name} {ZIZMOR_VERSION})")
    results = [
        True,
        run(
            "zizmor auditor medium+ (ignores disabled)",
            [str(zizmor), *ZIZMOR_AUDITOR_POLICY, ".github/workflows"],
        ),
        run("zizmor --pedantic", [str(zizmor), "--pedantic", ".github/workflows"]),
    ]
    try:
        same_path = _verified_zizmor_path()
    except ToolIdentityError as exc:
        print("[check] zizmor identity recheck: FAIL")
        print(f"  {exc}")
        results.append(False)
    else:
        unchanged = _normalized_path(same_path) == _normalized_path(zizmor)
        print(f"[check] zizmor identity recheck: {'PASS' if unchanged else 'FAIL'}")
        results.append(unchanged)
    return results


def _source_test_environment() -> dict[str, str]:
    """Bind pytest to this checkout instead of any previously installed wheel."""
    # Git hooks export repository-local GIT_* controls. Passing those into a
    # test that creates a nested repository can redirect its commits into this
    # checkout, despite the subprocess using a different cwd.
    environment = _without_git_controls()
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            # Tests import the release helper through the repository's
            # ``scripts`` namespace, while the product package must resolve
            # from ``src`` ahead of any installed wheel.
            "PYTHONPATH": os.pathsep.join((str(ROOT / "src"), str(ROOT))),
            "PYTHONSAFEPATH": "1",
        }
    )
    return environment


def _scan_file_for_leaks(rel: str) -> list[str]:
    """All leak-pattern hits in one tracked file, formatted for display."""
    path = ROOT / rel
    if path.is_symlink():
        return [f"  {rel}  [tracked symlink] release source must be regular"]
    if path.suffix in (".png", ".jpg", ".gif", ".ico"):
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return [f"  {rel}  [unreadable tracked file] {exc}"]
    hits: list[str] = []
    for pattern, label in LEAK_PATTERNS:
        for m in re.finditer(pattern, text):
            line = text.count("\n", 0, m.start()) + 1
            hits.append(f"  {rel}:{line}  [{label}] redacted match")
    return hits


def _tracked_files() -> list[str]:
    """Return the exact NUL-delimited Git inventory or fail the gate closed."""
    try:
        proc = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"could not enumerate tracked files: {exc}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()[-1_000:]
        raise RuntimeError(f"git ls-files failed ({proc.returncode}): {detail}")
    return [os.fsdecode(item) for item in proc.stdout.split(b"\0") if item]


def leak_scan() -> bool:
    try:
        tracked = _tracked_files()
    except RuntimeError as exc:
        print("[check] leak scan: FAIL")
        print(f"  {exc}")
        return False
    hits = [hit for rel in tracked for hit in _scan_file_for_leaks(rel)]
    print(f"[check] leak scan: {'PASS' if not hits else 'FAIL'}")
    for h in hits[:10]:
        print(h)
    return not hits


def artifact_scan() -> bool:
    try:
        tracked = _tracked_files()
    except RuntimeError as exc:
        print("[check] artifact scan: FAIL")
        print(f"  {exc}")
        return False
    hits = [rel for rel in tracked if _path_is_committed_artifact(rel)]
    print(f"[check] artifact scan: {'PASS' if not hits else 'FAIL'}")
    for rel in hits[:10]:
        print(f"  {rel}  [committed artifact]")
    return not hits


def _floor_drift(pyproject: str, docs: dict[str, str]) -> list[str]:
    """Keep the closed roam-code compatibility interval honest across surfaces."""
    pin = re.search(r'"roam-code([^"\r\n]+)"', pyproject)
    if not pin:
        return ["roam-code pin missing from pyproject.toml"]
    clauses = [clause.strip() for clause in pin.group(1).split(",")]
    floors = [clause.removeprefix(">=") for clause in clauses if clause.startswith(">=")]
    ceilings = [
        clause.removeprefix("<") for clause in clauses if clause.startswith("<") and not clause.startswith("<=")
    ]
    if len(clauses) != 2 or len(floors) != 1 or len(ceilings) != 1:
        return ["roam-code pin must contain exactly one inclusive floor and one exclusive ceiling"]
    floor = floors[0]
    ceiling = ceilings[0]
    if floor != "13.10.0" or ceiling != "14":
        return [f"roam-code compatibility interval drifted to >={floor},<{ceiling}"]
    problems = []
    comments = re.findall(r"#\s*>=([\d.]+),\s*<([\d.]+):", pyproject)
    if comments != [(floor, ceiling)]:
        problems.append("pyproject.toml compatibility comment must match the closed roam-code interval")
    for name, doc in docs.items():
        quotes = re.findall(r"roam-code[^\n]{0,60}?>=\s*([\d.]+)", doc)
        if not quotes:
            problems.append(f"{name}: no roam-code floor mention found to verify against the pin")
        problems += [f"{name} quotes roam-code >={q} but the pin is >={floor}" for q in quotes if q != floor]
    readme = docs.get("README.md", "")
    ranges = re.findall(r"roam-code[^\n]{0,80}?>=\s*([\d.]+),\s*<\s*([\d.]+)", readme)
    if (floor, ceiling) not in ranges:
        problems.append("README.md: closed roam-code compatibility interval is missing")
    return problems


def _retired_claim_hits(name: str, doc: str) -> list[str]:
    """Unannotated reappearances of retired public claims in one doc."""
    hits = []
    for pattern, label, allow in RETIRED_CLAIMS:
        for m in re.finditer(pattern, doc, re.IGNORECASE):
            line_start = doc.rfind("\n", 0, m.start()) + 1
            line_end = doc.find("\n", m.end())
            segment = doc[line_start : line_end if line_end != -1 else len(doc)].lower()
            if any(marker in segment for marker in allow):
                continue
            problems_line = doc.count("\n", 0, m.start()) + 1
            hits.append(f"{name}:{problems_line}: {label}")
    return hits


def readme_sanity() -> bool:
    """The promises a reader acts on first must stay true."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    normalized_text = re.sub(r"\s+", " ", text)
    problems = []
    if 'python -m pip install "compile-code @ git+https://github.com/Cranot/compile-code.git@v0.2.0"' not in text:
        problems.append("install command missing")
    if 'python -m pip install "compile-code==0.2.0"' not in text:
        problems.append("future owner-gated PyPI install command missing")
    if "`roam-code 13.10.0` is available on PyPI" not in text:
        problems.append("dependency publication gate missing")
    for release_guard in (
        "RELEASE_GUARD_READ_TOKEN",
        "release-guard",
        "55007746",
        "prevent_self_review=false",
        "`v*`",
        "Administration: read",
        "Contents: read",
        "exactly the wheel, sdist, SBOM, and manifest",
        "without resolving `roam-code`",
    ):
        if release_guard not in normalized_text:
            problems.append(f"immutable GitHub Release guidance missing: {release_guard}")
    if text.count("# compile-code") < 1:
        problems.append("title missing")
    docs = {"README.md": text, "AGENTS.md": agents}
    problems += _floor_drift(pyproject, docs)
    for name, doc in docs.items():
        problems += _retired_claim_hits(name, doc)
    print(f"[check] README sanity: {'PASS' if not problems else 'FAIL'}")
    for p in problems:
        print("  -", p)
    return not problems


def _load_release_module():
    """Load the release validator without making scripts a runtime package."""
    path = ROOT / "scripts" / "release_artifacts.py"
    spec = importlib.util.spec_from_file_location("compile_code_release_artifacts", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load scripts/release_artifacts.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _lock_problems(relative: str, text: str) -> list[str]:
    """Reject mutable, unhashed, URL-based, or script-capable lock entries."""
    problems = []
    lowered = text.lower()
    for forbidden in (
        "--config-settings",
        "--editable",
        "--extra-index-url",
        "--find-links",
        "--global-option",
        "--index-url",
        "--install-option",
        "--no-binary",
        "--trusted-host",
        " -e ",
        "git+",
    ):
        if forbidden in lowered:
            problems.append(f"{relative}: forbidden lock construct {forbidden.strip()}")
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if RELEASE_REQUIREMENT.match(line):
            continue
        if re.fullmatch(r"--hash=sha256:[0-9a-f]{64}(?:\s+\\)?", stripped):
            continue
        problems.append(f"{relative}:{line_number}: unexpected or unpinned requirement syntax")
    starts = list(RELEASE_REQUIREMENT.finditer(text))
    if not starts:
        problems.append(f"{relative}: no exact requirements found")
        return problems
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        block = text[match.start() : end]
        version = match.group(2)
        if not re.fullmatch(r"(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){1,3}", version):
            problems.append(f"{relative}: non-canonical exact version for {match.group(1)}: {version}")
        if "--hash=sha256:" not in block:
            problems.append(f"{relative}: {match.group(1)} has no SHA-256 hashes")
    return problems


def release_sanity() -> bool:
    """Static release contract: exact backend, closed schema/locks, hardened workflows."""
    problems = []
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    required_metadata = (
        'requires = ["setuptools==83.0.0", "wheel==0.47.0"]',
        'build-backend = "setuptools.build_meta"',
        'license = "Apache-2.0"',
        'license-files = ["LICENSE"]',
    )
    for fragment in required_metadata:
        if fragment not in pyproject:
            problems.append(f"pyproject.toml: missing release metadata {fragment}")
    if "License :: OSI Approved" in pyproject:
        problems.append("pyproject.toml: legacy license classifier conflicts with PEP 639")
    if re.search(r"(?m)^dynamic\s*=", pyproject):
        problems.append("pyproject.toml: dynamic metadata is forbidden at the release boundary")

    for relative in RELEASE_LOCKS:
        path = ROOT / relative
        if not path.is_file():
            problems.append(f"{relative}: lock missing")
            continue
        problems.extend(_lock_problems(relative, path.read_text(encoding="utf-8")))

    tooling_lock = (ROOT / "release" / "tooling-requirements.lock").read_text(encoding="utf-8")
    for exact_tool in (
        "build==1.5.0",
        "pip==26.1.2",
        "pytest==9.1.1",
        "pyyaml==6.0.3",
        "ruff==0.15.22",
        "setuptools==83.0.0",
        "twine==6.2.0",
        "wheel==0.47.0",
        "zizmor==1.27.0",
    ):
        if not re.search(rf"(?m)^{re.escape(exact_tool)}(?:\s|$)", tooling_lock):
            problems.append(f"tooling lock: required exact tool missing: {exact_tool}")

    schema_path = ROOT / "release" / "manifest.schema.json"
    try:
        schema = _strict_json_document(schema_path.read_bytes(), "manifest schema")
        if not isinstance(schema, dict):
            raise ValueError("manifest schema root must be an object")
        if schema.get("additionalProperties") is not False:
            problems.append("manifest schema: root object is not closed")
        evidence = schema["properties"]["evidence"]
        if evidence.get("additionalProperties") is not False:
            problems.append("manifest schema: evidence policy is not closed")
        expected_evidence = {
            "build_attestation": {"const": "github-build-provenance"},
            "dependency_audit": {"const": "osv-locked-graphs"},
            "pypi_publish_attestation": {"const": "pypi-integrity-api-pep740"},
            "release_attestation": {"const": "github-immutable-release"},
        }
        if evidence.get("properties") != expected_evidence:
            problems.append("manifest schema: evidence policy drift")
        tag_object = schema["properties"]["source"]["properties"]["tag_object_sha"]
        if tag_object.get("pattern") != "^[0-9a-f]{40}$":
            problems.append("manifest schema: annotated tag object binding missing")
        item = schema["properties"]["files"]["items"]
        if item.get("additionalProperties") is not False:
            problems.append("manifest schema: file records are not closed")
        prefix_items = schema["properties"]["files"]["prefixItems"]
        if any(prefix["allOf"][0].get("$ref") != "#/properties/files/items" for prefix in prefix_items):
            problems.append("manifest schema: ordered records do not inherit the closed file schema")
        role_order = [prefix["allOf"][1]["properties"]["role"]["const"] for prefix in prefix_items]
        if role_order != ["wheel", "sdist", "sbom"]:
            problems.append("manifest schema: canonical role order is not encoded")
        sbom_maximum = item["allOf"][0]["then"]["properties"]["size"]["maximum"]
        if sbom_maximum != 8 * 1024 * 1024:
            problems.append("manifest schema: SBOM size limit differs from the validator")
    except (OSError, KeyError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        problems.append(f"manifest schema invalid: {exc}")

    try:
        release_module = _load_release_module()
        release_module.locked_requirement_queries(ROOT)
        problems.extend(release_module.audit_repository(ROOT))
    except (ImportError, OSError, RuntimeError) as exc:
        problems.append(f"release validator failed to load: {exc}")

    release_workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    ci_workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    workflow_assertions = {
        "release.yml": (
            "install-smoke --bundle release-bundle --mode package-only",
            "install-smoke --bundle release-bundle --mode resolve",
            "python scripts/release_artifacts.py audit-locks",
            "verify --bundle release-bundle --dist pypi-dist --github-source",
            "pypi-state --bundle release-bundle --dist pypi-dist --github-source --wait-seconds 120 --github-output",
            "pypi-state --bundle release-bundle --dist pypi-dist --github-source --require-exact",
            "skip-existing: false",
            "actions/attest-build-provenance@",
            "github-artifact-state",
            "github-release-state",
            "RELEASE_GUARD_READ_TOKEN",
            "name: release-guard",
            "octokit/request-action@b91aabaa861c777dcdb14e2387e30eddf04619ae",
            "route: GET /repos/{owner}/{repo}/git/tags/{tag_sha}",
            "ncipollo/release-action@339a81892b84b4eeb0f6e744e4574d79d0d9b8dd",
            "needs.github_release_preflight.outputs.bundle_artifact_id == needs.build.outputs.bundle_artifact_id",
            "needs.github_release_preflight.outputs.bundle_artifact_digest == needs.build.outputs.bundle_artifact_digest",
            "needs.github_release_preflight.outputs.source_sha == github.sha",
            'immutableCreate: "false"',
            "artifactContentType: application/octet-stream",
            'artifactErrorsFailBuild: "true"',
            'replacesArtifacts: "false"',
            "--require-draft-exact --wait-seconds 120 --github-output",
            "github_release_draft_verify",
            "github_release_publish",
            "route: GET /repos/{owner}/{repo}/releases/assets/{asset_id}",
            "route: PATCH /repos/{owner}/{repo}/releases/{release_id}",
            "fromJSON(steps.remote_manifest.outputs.data).id == fromJSON(needs.github_release_draft_verify.outputs.manifest_asset_id)",
            "pypi-state --bundle release-bundle --dist pypi-dist --github-source --require-exact --wait-seconds 300",
        ),
        "ci.yml": ("--no-compile --no-build-isolation --only-binary=:all: -e .",),
    }
    for workflow_name, fragments in workflow_assertions.items():
        workflow = release_workflow if workflow_name == "release.yml" else ci_workflow
        normalized_workflow = re.sub(r"\s+", " ", workflow)
        for fragment in fragments:
            if re.sub(r"\s+", " ", fragment) not in normalized_workflow:
                problems.append(f"{workflow_name}: missing install/release assertion {fragment}")

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    release_dates = re.findall(r"(?m)^## 0\.2\.0 - (\d{4}-\d{2}-\d{2})$", changelog)
    if release_dates != ["2026-07-21"]:
        problems.append(f"CHANGELOG.md: expected one 0.2.0 release heading dated 2026-07-21, got {release_dates}")
    print(f"[check] release sanity: {'PASS' if not problems else 'FAIL'}")
    for problem in problems:
        print("  -", problem)
    return not problems


def dependency_audit() -> bool:
    """Fail closed on known vulnerabilities in the exact universal release locks."""
    try:
        audited = _load_release_module().audit_locked_requirements(ROOT)
    except (ImportError, OSError, RuntimeError) as exc:
        print("[check] locked dependency audit: FAIL")
        print(f"  {exc}")
        return False
    print(f"[check] locked dependency audit: PASS ({audited} exact package versions; no resolution)")
    return True


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        if arguments == [ZIZMOR_BOOTSTRAP_ARGUMENT]:
            return 0 if bootstrap_zizmor() else 1
        print(f"usage: {Path(sys.argv[0]).name} [{ZIZMOR_BOOTSTRAP_ARGUMENT}]")
        return 2
    results = [
        dependency_audit(),
        run("ruff check", [sys.executable, "-m", "ruff", "check", "src", "tests", "scripts"]),
        run("ruff format --check", [sys.executable, "-m", "ruff", "format", "--check", "src", "tests", "scripts"]),
        *zizmor_gates(),
        run(
            "pytest",
            [sys.executable, "-m", "pytest", "tests/", "-q"],
            env=_source_test_environment(),
            protect_repository=True,
        ),
        leak_scan(),
        artifact_scan(),
        readme_sanity(),
        release_sanity(),
    ]
    if all(results):
        print("[check] all gates passed — safe to push.")
        return 0
    print("[check] BLOCKED — fix the failures above before pushing.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
