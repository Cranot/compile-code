#!/usr/bin/env python3
"""Build, normalize, validate, and smoke-test compile-code releases.

The release boundary is deliberately standard-library-heavy.  The builder may
execute the reviewed PEP 517 backend, but the publisher receives only two
already-validated distributions and never executes repository code.
"""

from __future__ import annotations

import argparse
import base64
import csv
import email.policy
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import venv
import zipfile
from datetime import datetime, timezone
from email.parser import BytesParser
from importlib import metadata as importlib_metadata
from pathlib import Path, PurePosixPath
from typing import Any, Callable

try:  # Python 3.10 release checks receive tomli from the hashed tooling lock.
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised by the 3.10 CI lane
    import tomli as tomllib  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parent.parent
PROJECT = "compile-code"
WHEEL_STEM = "compile_code"
REPOSITORY = "Cranot/compile-code"
REPOSITORY_URL = f"https://github.com/{REPOSITORY}"
OWNER = "Cranot"
MANIFEST_NAME = "release-manifest.json"
MANIFEST_SCHEMA = "https://github.com/Cranot/compile-code/releases/schema/manifest-v1"
MANIFEST_VERSION = 1
BUILD_RECORD_SCHEMA = "compile-code-build-v1"
BUILD_REQUIRES = ["setuptools==83.0.0", "wheel==0.47.0"]
RUNTIME_REQUIRES = ["roam-code>=13.10.0", "click>=8.0"]
DEV_REQUIRES = ["pytest==9.1.1", "PyYAML==6.0.3", "ruff==0.15.22", "zizmor==1.27.0"]
PROJECT_URLS = {
    "Homepage": "https://github.com/Cranot/compile-code",
    "Issues": "https://github.com/Cranot/compile-code/issues",
    "Toolchain": "https://github.com/Cranot/roam-code",
}
CONSOLE_SCRIPTS = {
    "cmpl": "compile_code.cli:cli",
    "compile": "compile_code.cli:cli",
    "compile-code": "compile_code.cli:cli",
}
SMOKE_CLICK_VERSION = "8.4.2"
VERSION_RE = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\Z")
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
SHA512_RE = re.compile(r"[0-9a-f]{128}\Z")
MAX_ARCHIVE_ENTRIES = 2_048
MAX_MEMBER_SIZE = 32 * 1024 * 1024
MAX_ARCHIVE_SIZE = 128 * 1024 * 1024
MAX_JSON_SIZE = 8 * 1024 * 1024
MAX_PYPROJECT_SIZE = 1024 * 1024
MAX_COMMAND_DIAGNOSTIC_SIZE = 4 * 1024 * 1024
MAX_GITHUB_OUTPUT_SIZE = 1024 * 1024
MEDIA_TYPES = {
    "wheel": "application/zip",
    "sdist": "application/gzip",
    "sbom": "application/vnd.cyclonedx+json",
}
ARCHIVE_LEAK_PATTERNS = (
    (re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"), "GitHub token"),
    (re.compile(rb"sk-[A-Za-z0-9]{20,}"), "API secret key"),
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "PEM private key"),
    (re.compile(rb"/root/(?:apps|services|repos)/"), "private server path"),
    (re.compile(rb"(?:^|/)internal/(?:planning|dogfood)/", re.IGNORECASE), "private repository data"),
    (re.compile(rb"(?:^|/)(?:transcripts?|session-exports?)/", re.IGNORECASE), "private transcript export"),
)
SETUPTOOLS_GENERATED_SETUP_CFG = re.compile(rb"\[egg_info\]\r?\ntag_build = ?\r?\ntag_date = 0\r?\n(?:\r?\n)?\Z")
FORBIDDEN_BUILD_SOURCE_PATHS = ("MANIFEST.in", "setup.cfg", "setup.py")
PROJECT_KEYS = {
    "authors",
    "classifiers",
    "dependencies",
    "description",
    "keywords",
    "license",
    "license-files",
    "name",
    "optional-dependencies",
    "readme",
    "requires-python",
    "scripts",
    "urls",
    "version",
}


class ReleaseError(RuntimeError):
    """A release invariant failed closed."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseError(message)


def _file_identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _is_reparse_point(value: os.stat_result) -> bool:
    attributes = getattr(value, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse_flag)


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    """Bind identity and mutation fields around one bounded file read."""
    return bool(
        _file_identity(left) == _file_identity(right)
        and left.st_mode == right.st_mode
        and left.st_nlink == right.st_nlink
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        # Windows filesystem filters can refresh ctime across handles. Linux,
        # where releases run, retains the stronger ctime binding as well.
        and (os.name == "nt" or left.st_ctime_ns == right.st_ctime_ns)
    )


def _validated_real_directory(path: Path, *, label: str) -> Path:
    """Require one existing directory with no symlink/reparse hop."""
    absolute = Path(os.path.abspath(path))
    try:
        resolved = absolute.resolve(strict=True)
        current = os.lstat(absolute)
    except OSError as exc:
        raise ReleaseError(f"{label} directory is unavailable: {absolute}: {exc}") from exc
    _require(
        os.path.normcase(str(resolved)) == os.path.normcase(str(absolute)),
        f"{label} directory traverses a symlink or reparse point: {absolute}",
    )
    _require(
        stat.S_ISDIR(current.st_mode) and not _is_reparse_point(current),
        f"{label} must be a real directory: {absolute}",
    )
    return absolute


def _read_bounded_regular_file(path: Path, *, label: str, max_bytes: int) -> bytes:
    """Read one stable, singly-linked file without following its leaf link."""
    _require(max_bytes >= 0, f"{label}: invalid read limit")
    _validated_real_directory(path.parent, label=f"{label} parent")
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise ReleaseError(f"cannot inspect {label}: {path}: {exc}") from exc
    _require(
        stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode) and not _is_reparse_point(before),
        f"{label} must be a regular, non-symlink file: {path}",
    )
    _require(before.st_nlink == 1, f"{label} must not be hard-linked: {path}")
    _require(before.st_size <= max_bytes, f"{label} exceeds the {max_bytes}-byte input limit: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseError(f"cannot open {label}: {path}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        _require(_same_file_state(before, opened), f"{label} changed before it could be read: {path}")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            _require(size <= max_bytes, f"{label} exceeds the {max_bytes}-byte input limit: {path}")
            chunks.append(chunk)
        opened_after = os.fstat(descriptor)
        try:
            after = os.lstat(path)
        except OSError as exc:
            raise ReleaseError(f"{label} changed while it was read: {path}: {exc}") from exc
        _require(
            _same_file_state(opened, opened_after) and _same_file_state(before, after),
            f"{label} changed while it was read: {path}",
        )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _hash_bytes(payload: bytes) -> dict[str, str]:
    return {"sha256": hashlib.sha256(payload).hexdigest(), "sha512": hashlib.sha512(payload).hexdigest()}


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        _require(written > 0, "release control-plane write made no forward progress")
        offset += written


def _append_github_output(lines: list[str]) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    _require(bool(output), "GITHUB_OUTPUT is not set")
    path = Path(str(output))
    _validated_real_directory(path.parent, label="GITHUB_OUTPUT parent")
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise ReleaseError(f"GITHUB_OUTPUT is unavailable: {path}: {exc}") from exc
    _require(
        stat.S_ISREG(before.st_mode)
        and not stat.S_ISLNK(before.st_mode)
        and not _is_reparse_point(before)
        and before.st_nlink == 1,
        "GITHUB_OUTPUT must be a singly-linked regular file",
    )
    payload = "".join(f"{line}\n" for line in lines).encode("utf-8")
    _require(
        before.st_size + len(payload) <= MAX_GITHUB_OUTPUT_SIZE,
        f"GITHUB_OUTPUT exceeds the {MAX_GITHUB_OUTPUT_SIZE}-byte limit",
    )
    flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        _require(_same_file_state(before, opened), "GITHUB_OUTPUT changed before append")
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        _require(
            _file_identity(after) == _file_identity(opened)
            and after.st_nlink == 1
            and after.st_size == opened.st_size + len(payload),
            "GITHUB_OUTPUT changed during append",
        )
    finally:
        os.close(descriptor)


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json_bytes(data: bytes, label: str) -> Any:
    _require(len(data) <= MAX_JSON_SIZE, f"{label}: JSON exceeds {MAX_JSON_SIZE} bytes")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"{label}: invalid UTF-8 JSON: {exc}") from exc


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label}: expected an object")
    actual = set(value)
    _require(actual == expected, f"{label}: keys must be {sorted(expected)}; got {sorted(actual)}")
    return value


def _canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _validate_version(version: Any) -> str:
    _require(isinstance(version, str) and VERSION_RE.fullmatch(version) is not None, "version must be strict X.Y.Z")
    return version


def _validate_sha(source_sha: Any) -> str:
    _require(
        isinstance(source_sha, str) and SHA_RE.fullmatch(source_sha) is not None, "source SHA must be lowercase 40-hex"
    )
    return source_sha


def _validate_tag(tag: Any, version: str) -> str:
    _require(isinstance(tag, str) and tag == f"v{version}", f"tag must be exactly v{version}")
    return tag


def _validate_epoch(value: Any) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool), "SOURCE_DATE_EPOCH must be an integer")
    _require(315_532_800 <= value <= 4_102_444_799, "SOURCE_DATE_EPOCH is outside the ZIP/gzip release range")
    return value


def _safe_archive_name(name: str, *, allow_directory: bool = False) -> str:
    _require(name != "" and "\x00" not in name and "\\" not in name, f"unsafe archive path: {name!r}")
    directory = name.endswith("/")
    candidate = name[:-1] if directory else name
    path = PurePosixPath(candidate)
    _require(not path.is_absolute(), f"absolute archive path: {name!r}")
    _require(all(part not in {"", ".", ".."} for part in path.parts), f"traversing archive path: {name!r}")
    _require(str(path) == candidate, f"non-canonical archive path: {name!r}")
    _require(not directory or allow_directory, f"directory entry is not allowed here: {name!r}")
    return candidate


def _safe_bundle_filename(name: Any) -> str:
    _require(isinstance(name, str), "bundle filename must be a string")
    _require(name == Path(name).name and "/" not in name and "\\" not in name, f"unsafe bundle filename: {name!r}")
    _require(name not in {"", ".", ".."} and not name.startswith("."), f"unsafe bundle filename: {name!r}")
    _require(all(ord(char) >= 32 for char in name), f"control character in bundle filename: {name!r}")
    return name


def _read_pyproject_bytes(data: bytes, label: str = "pyproject.toml") -> dict[str, Any]:
    _require(len(data) <= MAX_PYPROJECT_SIZE, f"{label}: TOML exceeds {MAX_PYPROJECT_SIZE} bytes")
    try:
        parsed = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseError(f"{label}: invalid TOML: {exc}") from exc
    _validate_pyproject(parsed, label)
    return parsed


def _read_pyproject(root: Path) -> dict[str, Any]:
    path = root / "pyproject.toml"
    return _read_pyproject_bytes(_read_bounded_regular_file(path, label="pyproject.toml", max_bytes=MAX_PYPROJECT_SIZE))


def _validate_pyproject(parsed: dict[str, Any], label: str) -> None:
    build = parsed.get("build-system")
    _require(isinstance(build, dict), f"{label}: build-system table missing")
    _require(set(build) == {"build-backend", "requires"}, f"{label}: build-system table must be closed")
    _require(build.get("build-backend") == "setuptools.build_meta", f"{label}: unexpected build backend")
    _require(build.get("requires") == BUILD_REQUIRES, f"{label}: build requirements must be exact: {BUILD_REQUIRES}")

    project = parsed.get("project")
    _require(isinstance(project, dict), f"{label}: project table missing")
    _require("dynamic" not in project, f"{label}: dynamic metadata/lifecycle imports are forbidden")
    _require(set(project) == PROJECT_KEYS, f"{label}: project metadata table must be closed")
    _require(project.get("name") == PROJECT, f"{label}: project name mismatch")
    _validate_version(project.get("version"))
    _require(project.get("readme") == "README.md", f"{label}: readme path must be exactly README.md")
    _require(project.get("requires-python") == ">=3.10", f"{label}: Python compatibility contract drift")
    _require(project.get("license") == "Apache-2.0", f"{label}: use the PEP 639 SPDX license string")
    _require(project.get("license-files") == ["LICENSE"], f"{label}: license-files must be exactly ['LICENSE']")
    _require(project.get("authors") == [{"name": OWNER}], f"{label}: author metadata contract drift")
    _require(project.get("dependencies") == RUNTIME_REQUIRES, f"{label}: runtime dependency contract drift")
    _require(
        project.get("optional-dependencies") == {"dev": DEV_REQUIRES},
        f"{label}: development dependency contract drift",
    )
    _require(project.get("scripts") == CONSOLE_SCRIPTS, f"{label}: console-script contract drift")
    _require(project.get("urls") == PROJECT_URLS, f"{label}: project URL contract drift")

    setuptools_config = parsed.get("tool", {}).get("setuptools", {})
    _require(isinstance(setuptools_config, dict), f"{label}: tool.setuptools must be an object")
    _require(set(setuptools_config) <= {"packages"}, f"{label}: executable/custom setuptools hooks are forbidden")
    packages = setuptools_config.get("packages", {})
    _require(isinstance(packages, dict) and set(packages) == {"find"}, f"{label}: package discovery contract drift")
    _require(packages.get("find") == {"where": ["src"]}, f"{label}: package discovery must be src-only")


def _project_version(root: Path) -> str:
    return _validate_version(_read_pyproject(root)["project"]["version"])


def _run(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    binary: bool = False,
    timeout: int = 300,
) -> bytes | str:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            stdout=stdout,
            stderr=stderr,
            timeout=timeout,
            check=False,
        )
        stdout_size = os.fstat(stdout.fileno()).st_size
        stderr_size = os.fstat(stderr.fileno()).st_size
        _require(
            stdout_size <= MAX_COMMAND_DIAGNOSTIC_SIZE and stderr_size <= MAX_COMMAND_DIAGNOSTIC_SIZE,
            f"command output exceeded {MAX_COMMAND_DIAGNOSTIC_SIZE} bytes: {' '.join(argv)}",
        )
        stdout.seek(0)
        stderr.seek(0)
        stdout_bytes = stdout.read(MAX_COMMAND_DIAGNOSTIC_SIZE + 1)
        stderr_bytes = stderr.read(MAX_COMMAND_DIAGNOSTIC_SIZE + 1)
    if proc.returncode != 0:
        detail = (stdout_bytes + stderr_bytes).decode("utf-8", "replace").strip()[-4_000:]
        raise ReleaseError(f"command failed ({proc.returncode}): {' '.join(argv)}\n{detail}")
    return stdout_bytes if binary else stdout_bytes.decode("utf-8", "replace")


def _git(root: Path, *args: str) -> str:
    return str(_run(["git", *args], cwd=root, timeout=60)).strip()


def source_context_from_github(
    root: Path,
    environ: dict[str, str] | None = None,
    *,
    allow_untracked: bool = False,
) -> dict[str, Any]:
    env = os.environ if environ is None else environ
    _require(env.get("GITHUB_REPOSITORY") == REPOSITORY, f"release repository must be {REPOSITORY}")
    _require(env.get("GITHUB_REPOSITORY_OWNER") == OWNER, f"release owner must be {OWNER}")
    _require(env.get("GITHUB_ACTOR") == OWNER, f"release actor must be {OWNER}")
    _require(env.get("GITHUB_TRIGGERING_ACTOR") == OWNER, f"release triggering actor must be {OWNER}")
    _require(env.get("GITHUB_EVENT_NAME") == "push", "release must be a tag push event")

    version = _project_version(root)
    ref = env.get("GITHUB_REF", "")
    _require(ref == f"refs/tags/v{version}", f"event ref must be refs/tags/v{version}")
    event_sha = env.get("GITHUB_SHA", "")
    _validate_sha(event_sha)

    _require(_git(root, "cat-file", "-t", ref) == "tag", "release tag must be an annotated tag object")
    source_sha = _git(root, "rev-parse", f"{ref}^{{commit}}")
    _validate_sha(source_sha)
    event_commit = _git(root, "rev-parse", f"{event_sha}^{{commit}}")
    head = _git(root, "rev-parse", "HEAD")
    _require(event_commit == source_sha == head, "event SHA, annotated tag target, and checked-out HEAD must match")
    untracked_mode = "no" if allow_untracked else "all"
    _require(
        _git(root, "status", "--porcelain=v1", f"--untracked-files={untracked_mode}") == "",
        "release checkout must be clean",
    )

    epoch_text = _git(root, "show", "-s", "--format=%ct", source_sha)
    _require(epoch_text.isascii() and epoch_text.isdigit(), "commit timestamp is not a canonical epoch")
    source_date_epoch = _validate_epoch(int(epoch_text))
    return {
        "repository": REPOSITORY_URL,
        "sha": source_sha,
        "tag": f"v{version}",
        "source_date_epoch": source_date_epoch,
        "version": version,
    }


def _assert_release_tools() -> None:
    expected = {"build": "1.5.0", "pip": "26.1.2", "setuptools": "83.0.0", "wheel": "0.47.0"}
    for distribution, version in expected.items():
        try:
            actual = importlib_metadata.version(distribution)
        except importlib_metadata.PackageNotFoundError as exc:
            raise ReleaseError(f"release tool missing: {distribution}=={version}") from exc
        _require(actual == version, f"release tool drift: {distribution}=={actual}; expected {version}")


def assert_unprivileged_runner(environ: dict[str, str] | None = None) -> None:
    env = os.environ if environ is None else environ
    if hasattr(os, "geteuid"):
        _require(os.geteuid() != 0, "builder must not run as root")
    for name in ("ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "TWINE_PASSWORD", "PYPI_API_TOKEN"):
        _require(not env.get(name), f"unprivileged builder unexpectedly received {name}")


def _git_archive(root: Path, source_sha: str) -> bytes:
    # Do not let subprocess capture buffer an attacker-sized repository before
    # the release limit can be checked. Both channels spill to anonymous files.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        proc = subprocess.run(
            ["git", "archive", "--format=tar", source_sha],
            cwd=root,
            stdout=stdout,
            stderr=stderr,
            timeout=60,
            check=False,
        )
        stdout_size = os.fstat(stdout.fileno()).st_size
        stderr_size = os.fstat(stderr.fileno()).st_size
        _require(stderr_size <= MAX_COMMAND_DIAGNOSTIC_SIZE, "git archive diagnostic output is oversized")
        stderr.seek(0)
        detail = stderr.read(MAX_COMMAND_DIAGNOSTIC_SIZE).decode("utf-8", "replace").strip()[-4_000:]
        _require(proc.returncode == 0, f"git archive failed ({proc.returncode}): {detail}")
        _require(0 < stdout_size <= MAX_ARCHIVE_SIZE, "git archive is missing or oversized")
        stdout.seek(0)
        data = stdout.read(MAX_ARCHIVE_SIZE + 1)
    _require(len(data) == stdout_size, "git archive changed while it was read")
    return data


def _extract_source_archive(data: bytes, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    seen: set[str] = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        members = archive.getmembers()
        _require(len(members) <= MAX_ARCHIVE_ENTRIES, "source archive has too many entries")
        for member in members:
            name = _safe_archive_name(member.name, allow_directory=True)
            folded = name.casefold()
            _require(folded not in seen, f"duplicate source archive path: {name}")
            seen.add(folded)
            target = destination.joinpath(*PurePosixPath(name).parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            _require(member.isfile(), f"source archive contains non-regular entry: {name}")
            _require(0 <= member.size <= MAX_MEMBER_SIZE, f"source archive member is oversized: {name}")
            total += member.size
            _require(total <= MAX_ARCHIVE_SIZE, "source archive expands beyond the size limit")
            stream = archive.extractfile(member)
            _require(stream is not None, f"could not read source archive member: {name}")
            payload = stream.read(member.size + 1)
            _require(len(payload) == member.size, f"source archive member size mismatch: {name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)


def _zip_timestamp(epoch: int) -> tuple[int, int, int, int, int, int]:
    stamp = datetime.fromtimestamp(max(epoch, 315_532_800), tz=timezone.utc)
    return (stamp.year, stamp.month, stamp.day, stamp.hour, stamp.minute, stamp.second - stamp.second % 2)


def _scan_payload(name: str, data: bytes) -> None:
    for pattern, label in ARCHIVE_LEAK_PATTERNS:
        _require(pattern.search(data) is None, f"{name}: package-content leak detected ({label})")


def _read_zip_files(path: Path, *, archive_bytes: bytes | None = None) -> dict[str, bytes]:
    if archive_bytes is None:
        archive_bytes = _read_bounded_regular_file(path, label="wheel", max_bytes=MAX_ARCHIVE_SIZE)
    files: dict[str, bytes] = {}
    folded: set[str] = set()
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            infos = archive.infolist()
            _require(len(infos) <= MAX_ARCHIVE_ENTRIES, "wheel has too many entries")
            for info in infos:
                name = _safe_archive_name(info.filename, allow_directory=True)
                key = name.casefold()
                _require(key not in folded, f"duplicate/case-colliding wheel path: {name}")
                folded.add(key)
                if info.is_dir():
                    continue
                mode = (info.external_attr >> 16) & 0xFFFF
                _require(not stat.S_ISLNK(mode), f"wheel symlink is forbidden: {name}")
                _require(0 <= info.file_size <= MAX_MEMBER_SIZE, f"wheel member is oversized: {name}")
                total += info.file_size
                _require(total <= MAX_ARCHIVE_SIZE, "wheel expands beyond the size limit")
                files[name] = archive.read(info)
    except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as exc:
        raise ReleaseError(f"invalid wheel archive: {exc}") from exc
    return files


def _wheel_record(files: dict[str, bytes], record_name: str) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name in sorted(files):
        digest = base64.urlsafe_b64encode(hashlib.sha256(files[name]).digest()).rstrip(b"=").decode("ascii")
        writer.writerow((name, f"sha256={digest}", str(len(files[name]))))
    writer.writerow((record_name, "", ""))
    return output.getvalue().encode("utf-8")


def _wheel_bytes(files: dict[str, bytes], epoch: int) -> bytes:
    timestamp = _zip_timestamp(epoch)
    output = io.BytesIO()
    try:
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
            for name in sorted(files):
                info = zipfile.ZipInfo(name, date_time=timestamp)
                info.create_system = 3
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.extra = b""
                info.comment = b""
                archive.writestr(info, files[name], compress_type=zipfile.ZIP_STORED)
    except (OSError, zipfile.LargeZipFile) as exc:
        raise ReleaseError(f"could not write deterministic wheel: {exc}") from exc
    return output.getvalue()


def _write_wheel(path: Path, files: dict[str, bytes], epoch: int) -> None:
    path.write_bytes(_wheel_bytes(files, epoch))


def _expected_wheel_name(version: str) -> str:
    return f"{WHEEL_STEM}-{version}-py3-none-any.whl"


def _expected_sdist_name(version: str) -> str:
    return f"{WHEEL_STEM}-{version}.tar.gz"


def _expected_sbom_name(version: str) -> str:
    return f"{WHEEL_STEM}-{version}.cdx.json"


def _build_record(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "project": PROJECT,
        "schema": BUILD_RECORD_SCHEMA,
        "source_date_epoch": source["source_date_epoch"],
        "source_sha": source["sha"],
        "tag": source["tag"],
        "version": source["version"],
    }


def normalize_wheel(raw: Path, output: Path, source: dict[str, Any]) -> None:
    version = _validate_version(source["version"])
    _require(raw.name == _expected_wheel_name(version), f"unexpected wheel filename: {raw.name}")
    files = _read_zip_files(raw)
    dist_info = f"{WHEEL_STEM}-{version}.dist-info"
    record_name = f"{dist_info}/RECORD"
    _require(f"{dist_info}/METADATA" in files, "wheel METADATA missing")
    _require(f"{dist_info}/WHEEL" in files, "wheel WHEEL metadata missing")
    files.pop(record_name, None)
    build_name = f"{dist_info}/compile_code-build.json"
    files[build_name] = _canonical_json(_build_record(source))
    for name, data in files.items():
        _scan_payload(name, data)
    files[record_name] = _wheel_record(files, record_name)
    _write_wheel(output, files, source["source_date_epoch"])


def _read_tar_files(path: Path, *, archive_bytes: bytes | None = None) -> tuple[str, dict[str, bytes]]:
    if archive_bytes is None:
        archive_bytes = _read_bounded_regular_file(path, label="sdist", max_bytes=MAX_ARCHIVE_SIZE)
    files: dict[str, bytes] = {}
    folded: set[str] = set()
    roots: set[str] = set()
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            members = archive.getmembers()
            _require(len(members) <= MAX_ARCHIVE_ENTRIES, "sdist has too many entries")
            for member in members:
                name = _safe_archive_name(member.name, allow_directory=True)
                roots.add(PurePosixPath(name).parts[0])
                key = name.casefold()
                _require(key not in folded, f"duplicate/case-colliding sdist path: {name}")
                folded.add(key)
                if member.isdir():
                    continue
                _require(member.isfile(), f"sdist link/device is forbidden: {name}")
                _require(0 <= member.size <= MAX_MEMBER_SIZE, f"sdist member is oversized: {name}")
                total += member.size
                _require(total <= MAX_ARCHIVE_SIZE, "sdist expands beyond the size limit")
                stream = archive.extractfile(member)
                _require(stream is not None, f"could not read sdist member: {name}")
                payload = stream.read(member.size + 1)
                _require(len(payload) == member.size, f"sdist member size mismatch: {name}")
                files[name] = payload
    except (OSError, tarfile.TarError, gzip.BadGzipFile) as exc:
        raise ReleaseError(f"invalid sdist archive: {exc}") from exc
    _require(len(roots) == 1, f"sdist must have one top-level root; got {sorted(roots)}")
    return next(iter(roots)), files


def _sdist_payload_allowed(relative: str) -> bool:
    if relative in {"LICENSE", "PKG-INFO", "README.md", "pyproject.toml", "RELEASE.json"}:
        return True
    path = PurePosixPath(relative)
    return (
        len(path.parts) >= 3
        and path.parts[:2] == ("src", "compile_code")
        and "__pycache__" not in path.parts
        and (path.suffix in {".py", ".pyi"} or path.name == "py.typed")
    )


def _tar_bytes(files: dict[str, bytes], epoch: int) -> bytes:
    directories: set[str] = set()
    for name in files:
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            directories.add(str(parent))
            parent = parent.parent
    entries = [(name, True) for name in directories] + [(name, False) for name in files]
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name, is_directory in sorted(entries):
            info = tarfile.TarInfo(f"{name}/" if is_directory else name)
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = epoch
            info.pax_headers = {}
            if is_directory:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.size = 0
                archive.addfile(info)
            else:
                payload = files[name]
                info.type = tarfile.REGTYPE
                info.mode = 0o644
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def _stored_gzip(payload: bytes, epoch: int) -> bytes:
    """Emit gzip with stored DEFLATE blocks, independent of zlib versions."""
    header = b"\x1f\x8b\x08\x00" + struct.pack("<I", epoch) + b"\x00\xff"
    blocks = bytearray()
    if not payload:
        blocks.extend(b"\x01\x00\x00\xff\xff")
    else:
        offset = 0
        while offset < len(payload):
            chunk = payload[offset : offset + 65_535]
            offset += len(chunk)
            blocks.append(1 if offset == len(payload) else 0)
            blocks.extend(struct.pack("<H", len(chunk)))
            blocks.extend(struct.pack("<H", 0xFFFF ^ len(chunk)))
            blocks.extend(chunk)
    trailer = struct.pack("<II", __import__("zlib").crc32(payload) & 0xFFFFFFFF, len(payload) & 0xFFFFFFFF)
    return header + bytes(blocks) + trailer


def normalize_sdist(raw: Path, output: Path, source: dict[str, Any]) -> None:
    version = _validate_version(source["version"])
    _require(raw.name == _expected_sdist_name(version), f"unexpected sdist filename: {raw.name}")
    raw_root, raw_files = _read_tar_files(raw)
    expected_root = f"{WHEEL_STEM}-{version}"
    _require(raw_root == expected_root, f"sdist root must be {expected_root}; got {raw_root}")
    files: dict[str, bytes] = {}
    for name, data in raw_files.items():
        relative = str(PurePosixPath(name).relative_to(raw_root))
        _require(relative not in {"setup.py", "MANIFEST.in"}, f"sdist lifecycle script is forbidden: {relative}")
        if relative == "setup.cfg":
            _require(
                SETUPTOOLS_GENERATED_SETUP_CFG.fullmatch(data) is not None,
                "sdist setup.cfg differs from Setuptools' inert generated egg_info record",
            )
            continue
        if _sdist_payload_allowed(relative):
            files[f"{expected_root}/{relative}"] = data
    required = {
        "LICENSE",
        "PKG-INFO",
        "README.md",
        "pyproject.toml",
        "src/compile_code/__init__.py",
        "src/compile_code/cli.py",
    }
    present = {str(PurePosixPath(name).relative_to(expected_root)) for name in files}
    _require(required <= present, f"sdist is missing required payloads: {sorted(required - present)}")
    files[f"{expected_root}/RELEASE.json"] = _canonical_json(_build_record(source))
    for name, data in files.items():
        _scan_payload(name, data)
    output.write_bytes(_stored_gzip(_tar_bytes(files, source["source_date_epoch"]), source["source_date_epoch"]))


def _hashes(path: Path, *, max_bytes: int = MAX_ARCHIVE_SIZE) -> dict[str, str]:
    payload = _read_bounded_regular_file(path, label=f"artifact {path.name}", max_bytes=max_bytes)
    return _hash_bytes(payload)


def _sri(algorithm: str, hexdigest: str) -> str:
    return f"{algorithm}-{base64.b64encode(bytes.fromhex(hexdigest)).decode('ascii')}"


def _file_record(path: Path, role: str) -> dict[str, Any]:
    limit = MAX_JSON_SIZE if role == "sbom" else MAX_ARCHIVE_SIZE
    payload = _read_bounded_regular_file(path, label=f"{role} artifact", max_bytes=limit)
    hashes = _hash_bytes(payload)
    return {
        "filename": path.name,
        "hashes": hashes,
        "media_type": MEDIA_TYPES[role],
        "role": role,
        "size": len(payload),
        "sri": {algorithm: _sri(algorithm, digest) for algorithm, digest in hashes.items()},
    }


def _requirement_name(requirement: str) -> str:
    name = re.split(r"[<>=!~;\[\s]", requirement, maxsplit=1)[0]
    _require(name != "", f"invalid requirement: {requirement}")
    return _canonical_name(name)


def _sbom_bytes(
    *,
    version: str,
    source: dict[str, Any],
    dependencies: list[str],
    distributions: list[Path],
) -> bytes:
    package_ref = f"pkg:pypi/{PROJECT}@{version}"
    dependency_components = []
    dependency_refs = []
    for requirement in dependencies:
        name = _requirement_name(requirement)
        reference = f"pkg:pypi/{name}"
        dependency_refs.append(reference)
        dependency_components.append(
            {
                "bom-ref": reference,
                "name": name,
                "properties": [{"name": "compile-code:requirement", "value": requirement}],
                "purl": reference,
                "type": "library",
            }
        )
    artifact_components = []
    for path in sorted(distributions, key=lambda item: item.name):
        digests = _hashes(path)
        artifact_components.append(
            {
                "bom-ref": f"artifact:{path.name}",
                "hashes": [
                    {"alg": "SHA-256", "content": digests["sha256"]},
                    {"alg": "SHA-512", "content": digests["sha512"]},
                ],
                "name": path.name,
                "type": "file",
            }
        )
    timestamp = (
        datetime.fromtimestamp(source["source_date_epoch"], tz=timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"{REPOSITORY_URL}@{source['sha']}:{version}")
    document = {
        "bomFormat": "CycloneDX",
        "components": dependency_components + artifact_components,
        "dependencies": [
            {"dependsOn": sorted(dependency_refs), "ref": package_ref},
            *({"dependsOn": [], "ref": ref} for ref in sorted(dependency_refs)),
        ],
        "metadata": {
            "component": {
                "bom-ref": package_ref,
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "name": PROJECT,
                "properties": [
                    {"name": "compile-code:source-sha", "value": source["sha"]},
                    {"name": "compile-code:source-tag", "value": source["tag"]},
                ],
                "purl": package_ref,
                "type": "application",
                "version": version,
            },
            "timestamp": timestamp,
            "tools": {"components": [{"name": "compile-code-release", "type": "application", "version": "1"}]},
        },
        "serialNumber": f"urn:uuid:{serial}",
        "specVersion": "1.6",
        "version": 1,
    }
    return _canonical_json(document)


def _manifest_bytes(source: dict[str, Any], files: list[Path]) -> bytes:
    roles = {".whl": "wheel", ".gz": "sdist", ".json": "sbom"}
    records = [_file_record(path, roles[path.suffix]) for path in files]
    records.sort(key=lambda record: {"wheel": 0, "sdist": 1, "sbom": 2}[record["role"]])
    document = {
        "files": records,
        "project": PROJECT,
        "schema": MANIFEST_SCHEMA,
        "schema_version": MANIFEST_VERSION,
        "source": {
            "repository": REPOSITORY_URL,
            "sha": source["sha"],
            "source_date_epoch": source["source_date_epoch"],
        },
        "tag": source["tag"],
        "version": source["version"],
    }
    return _canonical_json(document)


def _prepare_empty_directory(path: Path) -> None:
    if path.exists():
        _validated_real_directory(path, label="output")
        _require(not any(path.iterdir()), f"output directory must be empty: {path}")
    else:
        _validated_real_directory(path.parent, label="output parent")
        path.mkdir()
        _validated_real_directory(path, label="output")


def _validate_source_tree_for_build(source_root: Path, *, expected_version: str) -> dict[str, Any]:
    """Reject executable legacy packaging inputs before invoking PEP 517."""
    _validated_real_directory(source_root, label="extracted source")
    parsed = _read_pyproject(source_root)
    _require(parsed["project"]["version"] == expected_version, "extracted source version differs from release")
    for relative in FORBIDDEN_BUILD_SOURCE_PATHS:
        _require(not os.path.lexists(source_root / relative), f"pre-build lifecycle input is forbidden: {relative}")
    for relative, limit in (
        ("LICENSE", MAX_MEMBER_SIZE),
        ("README.md", MAX_MEMBER_SIZE),
        ("src/compile_code/__init__.py", MAX_MEMBER_SIZE),
        ("src/compile_code/cli.py", MAX_MEMBER_SIZE),
    ):
        _read_bounded_regular_file(source_root / relative, label=f"source {relative}", max_bytes=limit)
    return parsed


def _closed_build_environment(epoch: int, scratch: Path) -> dict[str, str]:
    """Build with only OS launch state plus deterministic, networkless controls."""
    allowed = ("COMSPEC", "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR")
    env = {name: os.environ[name] for name in allowed if os.environ.get(name)}
    env.update(
        {
            "APPDATA": str(scratch),
            "HOME": str(scratch),
            "LC_ALL": "C.UTF-8" if os.name != "nt" else "C",
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "SOURCE_DATE_EPOCH": str(epoch),
            "TEMP": str(scratch),
            "TMP": str(scratch),
            "TMPDIR": str(scratch),
            "TZ": "UTC",
            "USERPROFILE": str(scratch),
            "XDG_CACHE_HOME": str(scratch),
            "XDG_CONFIG_HOME": str(scratch),
        }
    )
    return env


def _invoke_build(source_root: Path, output: Path, epoch: int) -> None:
    output.mkdir(parents=True, exist_ok=False)
    scratch = output.parent / f"scratch-{output.name}"
    scratch.mkdir(exist_ok=False)
    env = _closed_build_environment(epoch, scratch)
    _run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--sdist",
            "--wheel",
            "--outdir",
            str(output),
            str(source_root),
        ],
        # Keep the source checkout off Python's initial import path so a
        # repository-level build.py/sitecustomize.py cannot shadow tooling.
        cwd=output.parent,
        env=env,
        timeout=300,
    )


def _normalize_build(raw: Path, normalized: Path, source: dict[str, Any]) -> tuple[Path, Path]:
    normalized.mkdir(parents=True, exist_ok=False)
    expected = {_expected_wheel_name(source["version"]), _expected_sdist_name(source["version"])}
    actual = {path.name for path in raw.iterdir() if path.is_file()}
    _require(actual == expected, f"backend artifact set mismatch: expected {sorted(expected)}, got {sorted(actual)}")
    wheel = normalized / _expected_wheel_name(source["version"])
    sdist = normalized / _expected_sdist_name(source["version"])
    normalize_wheel(raw / wheel.name, wheel, source)
    normalize_sdist(raw / sdist.name, sdist, source)
    return wheel, sdist


def build_release(root: Path, bundle: Path, dist: Path, source: dict[str, Any]) -> dict[str, Any]:
    _assert_release_tools()
    _prepare_empty_directory(bundle)
    _prepare_empty_directory(dist)
    archive = _git_archive(root, source["sha"])
    temp_base = os.environ.get("RUNNER_TEMP") or os.environ.get("TEMP") or os.environ.get("TMP")
    with tempfile.TemporaryDirectory(prefix="compile-code-release-", dir=temp_base) as temporary:
        work = Path(temporary)
        normalized_builds: list[tuple[Path, Path]] = []
        for ordinal in ("a", "b"):
            source_root = work / f"source-{ordinal}"
            raw = work / f"raw-{ordinal}"
            normalized = work / f"normalized-{ordinal}"
            _extract_source_archive(archive, source_root)
            _validate_source_tree_for_build(source_root, expected_version=source["version"])
            _invoke_build(source_root, raw, source["source_date_epoch"])
            normalized_builds.append(_normalize_build(raw, normalized, source))

        first, second = normalized_builds
        for first_path, second_path in zip(first, second, strict=True):
            _require(first_path.name == second_path.name, "two-build artifact names differ")
            first_bytes = _read_bounded_regular_file(
                first_path, label=f"first build {first_path.name}", max_bytes=MAX_ARCHIVE_SIZE
            )
            second_bytes = _read_bounded_regular_file(
                second_path, label=f"second build {second_path.name}", max_bytes=MAX_ARCHIVE_SIZE
            )
            _require(first_bytes == second_bytes, f"two-build byte mismatch: {first_path.name}")

        published: list[Path] = []
        for path in first:
            destination = bundle / path.name
            shutil.copyfile(path, destination)
            shutil.copyfile(path, dist / path.name)
            published.append(destination)

    parsed = _read_pyproject(root)
    sbom = bundle / _expected_sbom_name(source["version"])
    sbom.write_bytes(
        _sbom_bytes(
            version=source["version"],
            source=source,
            dependencies=list(parsed["project"]["dependencies"]),
            distributions=published,
        )
    )
    (bundle / MANIFEST_NAME).write_bytes(_manifest_bytes(source, [*published, sbom]))
    manifest = verify_bundle(bundle, dist=dist, expected_source=source)
    return manifest


def _parse_metadata(data: bytes, label: str) -> dict[str, Any]:
    try:
        message = BytesParser(policy=email.policy.compat32).parsebytes(data)
    except Exception as exc:  # email's parser exposes several malformed-input exceptions
        raise ReleaseError(f"{label}: invalid core metadata: {exc}") from exc
    single_headers = ("License-Expression", "Metadata-Version", "Name", "Requires-Python", "Version")
    for header in single_headers:
        _require(len(message.get_all(header, [])) == 1, f"{label}: {header} must occur exactly once")
    requires = [re.sub(r"\s+", "", value) for value in message.get_all("Requires-Dist", [])]
    return {
        "license_files": message.get_all("License-File", []),
        "metadata_version": message.get("Metadata-Version"),
        "name": message.get("Name"),
        "provides_extra": sorted(message.get_all("Provides-Extra", [])),
        "version": message.get("Version"),
        "requires_python": message.get("Requires-Python"),
        "requires_dist": requires,
        "license_expression": message.get("License-Expression"),
    }


def _expected_metadata_requirements(project: dict[str, Any]) -> list[str]:
    requirements = [re.sub(r"\s+", "", item) for item in project.get("dependencies", [])]
    optional = project.get("optional-dependencies", {})
    _require(isinstance(optional, dict), "project optional-dependencies must be an object")
    for extra, values in optional.items():
        _require(isinstance(extra, str) and isinstance(values, list), "optional dependency group is malformed")
        for requirement in values:
            _require(
                isinstance(requirement, str) and ";" not in requirement,
                "optional requirement markers need explicit validator support",
            )
            normalized_requirement = re.sub(r"\s+", "", requirement)
            requirements.append(f'{normalized_requirement};extra=="{extra}"')
    return requirements


def _validate_entry_points(data: bytes) -> None:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ReleaseError("wheel entry_points.txt is not UTF-8") from exc
    section = ""
    found: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
            continue
        _require(section == "console_scripts" and "=" in stripped, "unexpected wheel entry-point section")
        name, target = (part.strip() for part in stripped.split("=", 1))
        _require(name not in found, f"duplicate console script: {name}")
        found[name] = target
    _require(found == CONSOLE_SCRIPTS, f"wheel console scripts drift: {found}")


def _validate_wheel_metadata(data: bytes) -> None:
    try:
        message = BytesParser(policy=email.policy.compat32).parsebytes(data)
    except Exception as exc:
        raise ReleaseError(f"invalid wheel WHEEL metadata: {exc}") from exc
    allowed = {"Generator", "Root-Is-Purelib", "Tag", "Wheel-Version"}
    _require(set(message.keys()) == allowed, f"wheel WHEEL metadata fields drift: {message.keys()}")
    for header in ("Generator", "Root-Is-Purelib", "Wheel-Version"):
        _require(len(message.get_all(header, [])) == 1, f"wheel {header} must occur exactly once")
    _require(message.get("Wheel-Version") == "1.0", "wheel format version drift")
    _require(message.get("Root-Is-Purelib") == "true", "wheel must remain pure Python")
    _require(message.get_all("Tag", []) == ["py3-none-any"], "wheel compatibility tag drift")
    _require(bool(message.get("Generator")), "wheel generator is missing")


def _inspect_wheel(path: Path, manifest: dict[str, Any]) -> tuple[dict[str, Any], dict[str, bytes], bytes, bytes]:
    version = manifest["version"]
    source = manifest["source"]
    tag = manifest["tag"]
    _require(path.name == _expected_wheel_name(version), "wheel filename/version mismatch")
    archive_bytes = _read_bounded_regular_file(path, label="wheel", max_bytes=MAX_ARCHIVE_SIZE)
    files = _read_zip_files(path, archive_bytes=archive_bytes)
    _require(archive_bytes == _wheel_bytes(files, source["source_date_epoch"]), "wheel byte encoding is not canonical")
    dist_info = f"{WHEEL_STEM}-{version}.dist-info"
    record_name = f"{dist_info}/RECORD"
    build_name = f"{dist_info}/compile_code-build.json"
    metadata_name = f"{dist_info}/METADATA"
    entry_points_name = f"{dist_info}/entry_points.txt"
    wheel_metadata_name = f"{dist_info}/WHEEL"
    license_name = f"{dist_info}/licenses/LICENSE"
    expected_dist_info = {
        record_name,
        build_name,
        metadata_name,
        entry_points_name,
        wheel_metadata_name,
        license_name,
        f"{dist_info}/top_level.txt",
    }
    actual_dist_info = {name for name in files if name.startswith(f"{dist_info}/")}
    _require(
        actual_dist_info == expected_dist_info,
        f"wheel metadata inventory drift: expected {sorted(expected_dist_info)}, got {sorted(actual_dist_info)}",
    )
    for name, payload in files.items():
        _require(name.startswith("compile_code/") or name.startswith(f"{dist_info}/"), f"unexpected wheel root: {name}")
        _require(
            ".data/" not in name and not name.endswith(".pth"), f"wheel install/startup script is forbidden: {name}"
        )
        _require(not name.endswith("setup.py"), f"wheel lifecycle script is forbidden: {name}")
        _scan_payload(name, payload)

    with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            _require(
                info.compress_type == zipfile.ZIP_STORED, f"wheel entry is not canonically stored: {info.filename}"
            )
            _require(
                info.date_time == _zip_timestamp(source["source_date_epoch"]), f"wheel timestamp drift: {info.filename}"
            )
            _require(((info.external_attr >> 16) & 0o777) == 0o644, f"wheel mode drift: {info.filename}")

    build_record = _load_json_bytes(files[build_name], build_name)
    _exact_keys(build_record, {"project", "schema", "source_date_epoch", "source_sha", "tag", "version"}, build_name)
    expected_build = {
        "project": PROJECT,
        "schema": BUILD_RECORD_SCHEMA,
        "source_date_epoch": source["source_date_epoch"],
        "source_sha": source["sha"],
        "tag": tag,
        "version": version,
    }
    _require(build_record == expected_build, "wheel source binding mismatch")

    try:
        rows = list(csv.reader(io.StringIO(files[record_name].decode("utf-8"))))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ReleaseError(f"invalid wheel RECORD: {exc}") from exc
    _require(all(len(row) == 3 for row in rows), "wheel RECORD rows must have three fields")
    names = [row[0] for row in rows]
    _require(len(names) == len(set(names)) and set(names) == set(files), "wheel RECORD inventory mismatch")
    for name, digest, size in rows:
        if name == record_name:
            _require(digest == "" and size == "", "wheel RECORD self-row must be unhashed")
            continue
        expected_digest = base64.urlsafe_b64encode(hashlib.sha256(files[name]).digest()).rstrip(b"=").decode("ascii")
        _require(
            digest == f"sha256={expected_digest}" and size == str(len(files[name])), f"wheel RECORD mismatch: {name}"
        )
    _validate_entry_points(files[entry_points_name])
    _validate_wheel_metadata(files[wheel_metadata_name])
    package_files = {
        name.removeprefix("compile_code/"): payload
        for name, payload in files.items()
        if name.startswith("compile_code/")
    }
    _require(
        {"__init__.py", "cli.py"} <= set(package_files),
        "wheel package payload is missing required Compile modules",
    )
    return (
        _parse_metadata(files[metadata_name], metadata_name),
        package_files,
        files[license_name],
        files[metadata_name],
    )


def _inspect_sdist(
    path: Path, manifest: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, bytes], bytes, bytes]:
    version = manifest["version"]
    source = manifest["source"]
    tag = manifest["tag"]
    _require(path.name == _expected_sdist_name(version), "sdist filename/version mismatch")
    archive_bytes = _read_bounded_regular_file(path, label="sdist", max_bytes=MAX_ARCHIVE_SIZE)
    root, files = _read_tar_files(path, archive_bytes=archive_bytes)
    _require(
        archive_bytes == _stored_gzip(_tar_bytes(files, source["source_date_epoch"]), source["source_date_epoch"]),
        "sdist byte encoding is not canonical",
    )
    expected_root = f"{WHEEL_STEM}-{version}"
    _require(root == expected_root, "sdist root/version mismatch")
    relative_files: dict[str, bytes] = {}
    for name, payload in files.items():
        relative = str(PurePosixPath(name).relative_to(root))
        _require(_sdist_payload_allowed(relative), f"extra file in normalized sdist: {relative}")
        _require(
            relative not in {"setup.py", "setup.cfg", "MANIFEST.in"}, f"sdist lifecycle script is forbidden: {relative}"
        )
        _scan_payload(name, payload)
        relative_files[relative] = payload
    required = {
        "LICENSE",
        "PKG-INFO",
        "README.md",
        "RELEASE.json",
        "pyproject.toml",
        "src/compile_code/__init__.py",
        "src/compile_code/cli.py",
    }
    _require(required <= set(relative_files), f"sdist payload missing: {sorted(required - set(relative_files))}")

    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        for member in archive.getmembers():
            _require(
                member.uid == 0 and member.gid == 0 and member.uname == "" and member.gname == "",
                f"sdist owner drift: {member.name}",
            )
            _require(member.mtime == source["source_date_epoch"], f"sdist timestamp drift: {member.name}")
            expected_mode = 0o755 if member.isdir() else 0o644
            _require(member.mode == expected_mode, f"sdist mode drift: {member.name}")
            _require(not member.pax_headers, f"sdist PAX metadata is forbidden: {member.name}")

    release_record = _load_json_bytes(relative_files["RELEASE.json"], "sdist RELEASE.json")
    _exact_keys(
        release_record, {"project", "schema", "source_date_epoch", "source_sha", "tag", "version"}, "sdist RELEASE.json"
    )
    expected_release = {
        "project": PROJECT,
        "schema": BUILD_RECORD_SCHEMA,
        "source_date_epoch": source["source_date_epoch"],
        "source_sha": source["sha"],
        "tag": tag,
        "version": version,
    }
    _require(release_record == expected_release, "sdist source binding mismatch")
    parsed = _read_pyproject_bytes(relative_files["pyproject.toml"], "sdist pyproject.toml")
    package_prefix = "src/compile_code/"
    package_files = {
        name.removeprefix(package_prefix): payload
        for name, payload in relative_files.items()
        if name.startswith(package_prefix)
    }
    return (
        parsed,
        _parse_metadata(relative_files["PKG-INFO"], "sdist PKG-INFO"),
        package_files,
        relative_files["LICENSE"],
        relative_files["PKG-INFO"],
    )


def _validate_manifest(document: Any, canonical_bytes: bytes) -> dict[str, Any]:
    manifest = _exact_keys(
        document, {"files", "project", "schema", "schema_version", "source", "tag", "version"}, "manifest"
    )
    _require(_canonical_json(manifest) == canonical_bytes, "manifest must use canonical JSON encoding")
    _require(
        manifest["schema"] == MANIFEST_SCHEMA
        and type(manifest["schema_version"]) is int
        and manifest["schema_version"] == MANIFEST_VERSION,
        "manifest schema mismatch",
    )
    _require(manifest["project"] == PROJECT, "manifest project mismatch")
    version = _validate_version(manifest["version"])
    _validate_tag(manifest["tag"], version)
    source = _exact_keys(manifest["source"], {"repository", "sha", "source_date_epoch"}, "manifest.source")
    _require(source["repository"] == REPOSITORY_URL, "manifest source repository mismatch")
    _validate_sha(source["sha"])
    _validate_epoch(source["source_date_epoch"])

    records = manifest["files"]
    _require(isinstance(records, list) and len(records) == 3, "manifest must contain exactly wheel, sdist, and SBOM")
    names: set[str] = set()
    roles: set[str] = set()
    role_order: list[str] = []
    for index, value in enumerate(records):
        record = _exact_keys(
            value, {"filename", "hashes", "media_type", "role", "size", "sri"}, f"manifest.files[{index}]"
        )
        filename = _safe_bundle_filename(record["filename"])
        _require(filename not in names, f"duplicate manifest filename: {filename}")
        names.add(filename)
        role = record["role"]
        _require(role in MEDIA_TYPES and role not in roles, f"duplicate/unknown manifest role: {role}")
        roles.add(role)
        role_order.append(role)
        _require(record["media_type"] == MEDIA_TYPES[role], f"manifest media type mismatch: {filename}")
        _require(type(record["size"]) is int and 0 < record["size"] <= MAX_ARCHIVE_SIZE, f"invalid size: {filename}")
        if role == "sbom":
            _require(record["size"] <= MAX_JSON_SIZE, f"SBOM exceeds the {MAX_JSON_SIZE}-byte limit")
        hashes = _exact_keys(record["hashes"], {"sha256", "sha512"}, f"manifest hash: {filename}")
        _require(
            isinstance(hashes["sha256"], str) and HASH_RE.fullmatch(hashes["sha256"]) is not None,
            f"invalid SHA-256: {filename}",
        )
        _require(
            isinstance(hashes["sha512"], str) and SHA512_RE.fullmatch(hashes["sha512"]) is not None,
            f"invalid SHA-512: {filename}",
        )
        sri = _exact_keys(record["sri"], {"sha256", "sha512"}, f"manifest SRI: {filename}")
        _require(
            sri == {algorithm: _sri(algorithm, digest) for algorithm, digest in hashes.items()},
            f"SRI mismatch: {filename}",
        )
    _require(roles == set(MEDIA_TYPES), "manifest role set mismatch")
    _require(role_order == ["wheel", "sdist", "sbom"], "manifest file records are not in canonical role order")
    expected_names = {_expected_wheel_name(version), _expected_sdist_name(version), _expected_sbom_name(version)}
    _require(names == expected_names, f"manifest artifact names mismatch: {sorted(names)}")
    return manifest


def verify_bundle(
    bundle: Path,
    *,
    dist: Path | None = None,
    expected_source: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _validated_real_directory(bundle, label="release bundle")
    manifest_path = bundle / MANIFEST_NAME
    manifest_bytes = _read_bounded_regular_file(manifest_path, label="release manifest", max_bytes=MAX_JSON_SIZE)
    manifest = _validate_manifest(_load_json_bytes(manifest_bytes, MANIFEST_NAME), manifest_bytes)
    if expected_source is not None:
        _require(manifest["version"] == expected_source["version"], "manifest version differs from validated source")
        _require(manifest["tag"] == expected_source["tag"], "manifest tag differs from validated source")
        _require(manifest["source"]["sha"] == expected_source["sha"], "manifest SHA differs from validated source")
        _require(
            manifest["source"]["source_date_epoch"] == expected_source["source_date_epoch"],
            "manifest epoch differs from validated source",
        )

    records = {record["role"]: record for record in manifest["files"]}
    expected_files = {MANIFEST_NAME, *(record["filename"] for record in records.values())}
    actual_entries = list(bundle.iterdir())
    for entry in actual_entries:
        try:
            entry_state = os.lstat(entry)
        except OSError as exc:
            raise ReleaseError(f"bundle entry cannot be inspected: {entry}: {exc}") from exc
        _require(
            stat.S_ISREG(entry_state.st_mode)
            and not stat.S_ISLNK(entry_state.st_mode)
            and not _is_reparse_point(entry_state)
            and entry_state.st_nlink == 1,
            "bundle contains a directory, link, or reparse point",
        )
    _require({entry.name for entry in actual_entries} == expected_files, "bundle contains missing or extra files")
    paths: dict[str, Path] = {}
    for role, record in records.items():
        path = bundle / record["filename"]
        limit = MAX_JSON_SIZE if role == "sbom" else MAX_ARCHIVE_SIZE
        payload = _read_bounded_regular_file(path, label=f"{role} artifact", max_bytes=limit)
        _require(len(payload) == record["size"], f"artifact size mismatch: {path.name}")
        _require(_hash_bytes(payload) == record["hashes"], f"artifact hash mismatch: {path.name}")
        paths[role] = path

    wheel_metadata, wheel_package, wheel_license, wheel_metadata_bytes = _inspect_wheel(paths["wheel"], manifest)
    sdist_project, sdist_metadata, sdist_package, sdist_license, sdist_metadata_bytes = _inspect_sdist(
        paths["sdist"], manifest
    )
    _require(wheel_package == sdist_package, "wheel package payload differs from the source distribution")
    _require(wheel_license == sdist_license, "wheel and sdist license payloads differ")
    _require(wheel_metadata_bytes == sdist_metadata_bytes, "wheel and sdist core metadata bytes differ")
    _require(b"Apache License" in wheel_license and b"Version 2.0" in wheel_license, "Apache-2.0 license text missing")
    optional_groups = sorted(sdist_project["project"].get("optional-dependencies", {}))
    expected_metadata = {
        "license_files": ["LICENSE"],
        "metadata_version": "2.4",
        "name": PROJECT,
        "provides_extra": optional_groups,
        "version": manifest["version"],
        "requires_python": sdist_project["project"]["requires-python"],
        "requires_dist": _expected_metadata_requirements(sdist_project["project"]),
    }
    for metadata_label, package_metadata in (("wheel", wheel_metadata), ("sdist", sdist_metadata)):
        for key, value in expected_metadata.items():
            _require(package_metadata[key] == value, f"{metadata_label} metadata mismatch: {key}")
        _require(
            package_metadata["license_expression"] == "Apache-2.0", f"{metadata_label} SPDX license metadata missing"
        )

    expected_sbom = _sbom_bytes(
        version=manifest["version"],
        source={
            "sha": manifest["source"]["sha"],
            "tag": manifest["tag"],
            "source_date_epoch": manifest["source"]["source_date_epoch"],
        },
        dependencies=list(sdist_project["project"]["dependencies"]),
        distributions=[paths["wheel"], paths["sdist"]],
    )
    sbom_bytes = _read_bounded_regular_file(paths["sbom"], label="SBOM", max_bytes=MAX_JSON_SIZE)
    _load_json_bytes(sbom_bytes, paths["sbom"].name)
    _require(sbom_bytes == expected_sbom, "SBOM content/source/artifact binding mismatch")

    if dist is not None:
        _validated_real_directory(dist, label="distribution")
        expected_dist = {paths["wheel"].name, paths["sdist"].name}
        actual_dist = list(dist.iterdir())
        for path in actual_dist:
            try:
                state = os.lstat(path)
            except OSError as exc:
                raise ReleaseError(f"distribution entry cannot be inspected: {path}: {exc}") from exc
            _require(
                stat.S_ISREG(state.st_mode)
                and not stat.S_ISLNK(state.st_mode)
                and not _is_reparse_point(state)
                and state.st_nlink == 1,
                "distribution directory contains a directory, link, or reparse point",
            )
        _require(
            {path.name for path in actual_dist} == expected_dist,
            "distribution directory contains missing or extra files",
        )
        for role in ("wheel", "sdist"):
            transported = _read_bounded_regular_file(
                dist / paths[role].name,
                label=f"transported {role}",
                max_bytes=MAX_ARCHIVE_SIZE,
            )
            bundled = _read_bounded_regular_file(paths[role], label=f"bundled {role}", max_bytes=MAX_ARCHIVE_SIZE)
            _require(
                transported == bundled,
                f"distribution substitution: {paths[role].name}",
            )
    return manifest


def twine_check(bundle: Path) -> None:
    manifest = verify_bundle(bundle)
    files = {record["role"]: bundle / record["filename"] for record in manifest["files"]}
    _run(
        [sys.executable, "-m", "twine", "check", "--strict", str(files["wheel"]), str(files["sdist"])],
        cwd=ROOT,
        timeout=120,
    )


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        parsed = urllib.parse.urlparse(newurl)
        _require(
            parsed.scheme == "https" and parsed.hostname in {"pypi.org", "files.pythonhosted.org"},
            "unsafe registry redirect",
        )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch_url(url: str, *, max_bytes: int) -> bytes:
    parsed = urllib.parse.urlparse(url)
    _require(
        parsed.scheme == "https" and parsed.hostname in {"pypi.org", "files.pythonhosted.org"},
        f"unsafe registry URL: {url}",
    )
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": "compile-code-release/1"}
    )
    opener = urllib.request.build_opener(_SafeRedirect())
    with opener.open(request, timeout=30) as response:
        final = urllib.parse.urlparse(response.geturl())
        _require(
            final.scheme == "https" and final.hostname in {"pypi.org", "files.pythonhosted.org"},
            "unsafe final registry URL",
        )
        data = response.read(max_bytes + 1)
    _require(len(data) <= max_bytes, f"registry response exceeds {max_bytes} bytes")
    return data


def _fetch_pypi_json() -> dict[str, Any] | None:
    try:
        data = _fetch_url(f"https://pypi.org/pypi/{PROJECT}/json", max_bytes=MAX_JSON_SIZE)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise ReleaseError(f"PyPI registry request failed: HTTP {exc.code}") from exc
    document = _load_json_bytes(data, "PyPI project JSON")
    _require(isinstance(document, dict), "PyPI project JSON must be an object")
    return document


def _remote_release_state(
    bundle: Path,
    dist: Path,
    *,
    expected_source: dict[str, Any] | None = None,
    fetch_project: Callable[[], dict[str, Any] | None] = _fetch_pypi_json,
    fetch_bytes: Callable[[str], bytes] | None = None,
) -> str:
    manifest = verify_bundle(bundle, dist=dist, expected_source=expected_source)
    project = fetch_project()
    if project is None:
        return "missing"
    info = project.get("info")
    _require(
        isinstance(info, dict) and _canonical_name(str(info.get("name", ""))) == PROJECT,
        "PyPI namespace identity mismatch",
    )
    releases = project.get("releases")
    _require(isinstance(releases, dict), "PyPI releases inventory missing")
    rows = releases.get(manifest["version"])
    if not rows:
        intended = tuple(int(part) for part in manifest["version"].split("."))
        published = [
            tuple(int(part) for part in version.split(".")) for version in releases if VERSION_RE.fullmatch(version)
        ]
        _require(not published or max(published) < intended, "refusing a non-monotonic PyPI version")
        return "missing"
    _require(isinstance(rows, list), "PyPI release inventory is malformed")
    _require(all(isinstance(row, dict) for row in rows), "PyPI release row must be an object")

    records = {record["filename"]: record for record in manifest["files"] if record["role"] in {"wheel", "sdist"}}
    remote_names = [_safe_bundle_filename(row.get("filename")) for row in rows]
    _require(
        len(remote_names) == len(set(remote_names)) and set(remote_names) == set(records),
        "PyPI release has missing, duplicate, or extra files",
    )
    downloader = fetch_bytes or (lambda url: _fetch_url(url, max_bytes=MAX_ARCHIVE_SIZE))
    for row in rows:
        filename = _safe_bundle_filename(row.get("filename"))
        record = records[filename]
        expected_type = "bdist_wheel" if record["role"] == "wheel" else "sdist"
        _require(row.get("packagetype") == expected_type, f"PyPI package type mismatch: {filename}")
        _require(row.get("yanked") is False, f"PyPI artifact is yanked: {filename}")
        _require(row.get("size") == record["size"], f"PyPI artifact size mismatch: {filename}")
        digests = row.get("digests")
        _require(
            isinstance(digests, dict) and digests.get("sha256") == record["hashes"]["sha256"],
            f"PyPI SHA-256 mismatch: {filename}",
        )
        url = row.get("url")
        _require(isinstance(url, str), f"PyPI URL missing: {filename}")
        parsed_url = urllib.parse.urlparse(url)
        _require(
            parsed_url.scheme == "https" and parsed_url.hostname in {"pypi.org", "files.pythonhosted.org"},
            f"unsafe registry URL: {url}",
        )
        remote = downloader(url)
        _require(
            isinstance(remote, bytes) and len(remote) <= MAX_ARCHIVE_SIZE, f"PyPI payload is oversized: {filename}"
        )
        local = _read_bounded_regular_file(
            dist / filename, label=f"local publication {filename}", max_bytes=MAX_ARCHIVE_SIZE
        )
        _require(remote == local, f"PyPI exact-byte mismatch: {filename}")
    return "exact"


def pypi_state(
    bundle: Path,
    dist: Path,
    *,
    require_exact: bool,
    wait_seconds: int,
    expected_source: dict[str, Any] | None = None,
) -> str:
    deadline = time.monotonic() + wait_seconds
    while True:
        state = _remote_release_state(bundle, dist, expected_source=expected_source)
        if state == "exact":
            return state
        if not require_exact:
            return state
        if time.monotonic() >= deadline:
            raise ReleaseError("PyPI release did not become byte-exact before the deadline")
        time.sleep(min(10, max(1, int(deadline - time.monotonic()))))


def _write_github_output(state: str) -> None:
    _require(state in {"missing", "exact"}, "invalid publication state")
    _append_github_output(
        [
            f"state={state}",
            f"publish_required={'true' if state == 'missing' else 'false'}",
        ]
    )


def _venv_python(directory: Path) -> Path:
    return directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _smoke_environment() -> dict[str, str]:
    env = os.environ.copy()
    for name in tuple(env):
        normalized_name = name.upper()
        if normalized_name.startswith(("PIP_", "UV_")) or normalized_name in {
            "PYTHONHOME",
            "PYTHONPATH",
            "SETUPTOOLS_SCM_PRETEND_VERSION",
            "SETUPTOOLS_SCM_PRETEND_VERSION_FOR_COMPILE_CODE",
        }:
            env.pop(name, None)
    env.update(
        {
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_INDEX_URL": "https://pypi.org/simple",
            "PIP_NO_INPUT": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
        }
    )
    return env


def _run_install_smoke(artifact: Path, version: str, mode: str, temp_root: Path) -> None:
    environment = _smoke_environment()
    with tempfile.TemporaryDirectory(prefix=f"smoke-{artifact.suffix.lstrip('.')}-", dir=temp_root) as temporary:
        environment_root = Path(temporary) / "venv"
        venv.EnvBuilder(with_pip=True, clear=True, symlinks=False).create(environment_root)
        python = _venv_python(environment_root)
        common = [str(python), "-m", "pip", "install", "--disable-pip-version-check", "--no-cache-dir", "--no-compile"]
        _run(
            [
                *common,
                "--require-hashes",
                "--only-binary=:all:",
                "-r",
                str(ROOT / "release" / "build-requirements.lock"),
            ],
            cwd=ROOT,
            env=environment,
            timeout=180,
        )
        if mode == "package-only":
            _run(
                [
                    *common,
                    "--require-hashes",
                    "--only-binary=:all:",
                    "-r",
                    str(ROOT / "release" / "smoke-requirements.lock"),
                ],
                cwd=ROOT,
                env=environment,
                timeout=180,
            )
            install = [*common, "--no-build-isolation", "--no-deps", str(artifact)]
        else:
            install = [*common, "--no-build-isolation", "--only-binary=:all:", str(artifact)]
        _run(install, cwd=ROOT, env=environment, timeout=300)
        assertion = (
            "import importlib.metadata as m, compile_code; "
            f"assert m.version('compile-code') == {version!r}; "
            "assert compile_code.__version__ == m.version('compile-code')"
        )
        if mode == "package-only":
            assertion += f"; assert m.version('click') == {SMOKE_CLICK_VERSION!r}"
        _run([str(python), "-I", "-c", assertion], cwd=temp_root, env=environment, timeout=60)
        scripts = environment_root / ("Scripts" if os.name == "nt" else "bin")
        for name in ("compile", "compile-code", "cmpl"):
            executable = scripts / (f"{name}.exe" if os.name == "nt" else name)
            output = _run([str(executable), "--help"], cwd=temp_root, env=environment, timeout=60)
            _require(
                isinstance(output, str) and "Usage:" in output and "Traceback" not in output,
                f"help smoke failed: {name}",
            )


def install_smoke(bundle: Path, mode: str, temp_root: Path) -> None:
    _require(mode in {"package-only", "resolve"}, "unknown install smoke mode")
    _validated_real_directory(temp_root, label="smoke TEMP root")
    manifest = verify_bundle(bundle)
    artifacts = [bundle / record["filename"] for record in manifest["files"] if record["role"] in {"wheel", "sdist"}]
    for artifact in artifacts:
        _run_install_smoke(artifact, manifest["version"], mode, temp_root)


def audit_workflow_text(text: str, name: str) -> list[str]:
    problems: list[str] = []
    uses_pattern = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
    immutable_action = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}\Z")
    for action in uses_pattern.findall(text):
        if not immutable_action.fullmatch(action):
            problems.append(f"{name}: mutable or local action reference: {action}")

    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^(\s*)(?:-\s*)?run:\s*(.*)$", line)
        if not match:
            index += 1
            continue
        indent = len(match.group(1))
        block = [match.group(2)]
        index += 1
        while index < len(lines):
            next_line = lines[index]
            if next_line.strip() and len(next_line) - len(next_line.lstrip()) <= indent:
                break
            block.append(next_line)
            index += 1
        if "${{" in "\n".join(block):
            problems.append(f"{name}: GitHub expression embedded in a shell run block")
    lowered = text.lower()
    for forbidden in ("pull_request_target:", "workflow_run:", "curl |", "wget |", "bash <(", "sudo "):
        if forbidden in lowered:
            problems.append(f"{name}: forbidden workflow construct: {forbidden.strip()}")
    if re.search(r"(?im)\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba|z|k)?sh\b", text):
        problems.append(f"{name}: network download piped to a shell")
    if "ubuntu-latest" in text:
        problems.append(f"{name}: mutable ubuntu-latest runner label")
    return problems


def audit_repository(root: Path = ROOT) -> list[str]:
    problems: list[str] = []
    workflow_dir = root / ".github" / "workflows"
    workflows = sorted(workflow_dir.glob("*.yml")) + sorted(workflow_dir.glob("*.yaml"))
    if not workflows:
        return ["no GitHub workflows found"]
    for workflow in workflows:
        problems.extend(audit_workflow_text(workflow.read_text(encoding="utf-8"), workflow.name))
    release_path = workflow_dir / "release.yml"
    if not release_path.is_file():
        problems.append("release.yml missing")
        return problems
    release = release_path.read_text(encoding="utf-8")
    required_fragments = (
        "github.repository == 'Cranot/compile-code'",
        "github.actor == 'Cranot'",
        "environment:",
        "name: pypi",
        "github.triggering_actor == 'Cranot'",
        "id-token: write",
        "attestations: write",
        "skip-existing: true",
        "attestations: true",
        "verify --bundle release-bundle --dist pypi-dist --github-source",
        "--github-source --github-output",
        "--github-source --require-exact",
    )
    for fragment in required_fragments:
        if fragment not in release:
            problems.append(f"release.yml missing hardened release fragment: {fragment}")
    if "workflow_dispatch:" in release or "inputs:" in release or "secrets." in release:
        problems.append("release.yml may not accept user inputs or static publication secrets")
    if release.count("id-token: write") != 2 or release.count("attestations: write") != 1:
        problems.append("release.yml elevated permission inventory drift")
    if release.count("fetch-depth: 0") != 3:
        problems.append("release.yml must fetch annotated tag objects in all three source-verifying jobs")
    for forbidden_permission in ("actions: write", "contents: write", "packages: write", "write-all"):
        if forbidden_permission in release:
            problems.append(f"release.yml forbidden permission: {forbidden_permission}")
    if "continue-on-error:" in release:
        problems.append("release.yml may not suppress a release gate")
    publish_match = re.search(r"(?ms)^  publish:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)", release)
    if not publish_match or re.search(r"(?m)^\s+run:", publish_match.group(1)):
        problems.append("privileged publish job must contain no run steps")
    elif "actions/checkout@" in publish_match.group(1) or "actions/setup-python@" in publish_match.group(1):
        problems.append("privileged publish job may not check out or execute source")
    return problems


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("assert-runner", help="Prove the builder has no root/OIDC/publication credentials.")

    source = subparsers.add_parser("source", help="Validate the GitHub tag/source context.")
    source.add_argument("--github-output", action="store_true", help="Append closed validated values to GITHUB_OUTPUT.")

    build = subparsers.add_parser("build", help="Build twice, normalize, compare, and emit a release bundle.")
    build.add_argument("--bundle", type=Path, required=True)
    build.add_argument("--dist", type=Path, required=True)

    verify = subparsers.add_parser(
        "verify", help="Validate a closed release bundle and optional publication directory."
    )
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--dist", type=Path)
    verify.add_argument(
        "--github-source",
        action="store_true",
        help="Bind the downloaded bundle back to the current GitHub tag checkout.",
    )

    twine = subparsers.add_parser("twine-check", help="Run strict Twine metadata checks over the closed distributions.")
    twine.add_argument("--bundle", type=Path, required=True)

    registry = subparsers.add_parser("pypi-state", help="Require missing or exact-byte-idempotent PyPI state.")
    registry.add_argument("--bundle", type=Path, required=True)
    registry.add_argument("--dist", type=Path, required=True)
    registry.add_argument("--require-exact", action="store_true")
    registry.add_argument("--wait-seconds", type=int, default=0)
    registry.add_argument("--github-output", action="store_true")
    registry.add_argument(
        "--github-source",
        action="store_true",
        help="Bind the registry decision back to the current GitHub tag checkout.",
    )

    smoke = subparsers.add_parser(
        "install-smoke", help="Install wheel and sdist in separate clean virtual environments."
    )
    smoke.add_argument("--bundle", type=Path, required=True)
    smoke.add_argument("--mode", choices=("package-only", "resolve"), required=True)
    smoke.add_argument("--temp-root", type=Path, required=True)

    subparsers.add_parser(
        "audit-workflows", help="Audit immutable pins, injection boundaries, and privilege separation."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "assert-runner":
            assert_unprivileged_runner()
            print("release runner: unprivileged and publication-credential-free")
        elif args.command == "source":
            context = source_context_from_github(ROOT)
            print(json.dumps(context, sort_keys=True))
            if args.github_output:
                _append_github_output(
                    [f"{key}={context[key]}" for key in ("version", "tag", "sha", "source_date_epoch")]
                )
        elif args.command == "build":
            context = source_context_from_github(ROOT)
            manifest = build_release(ROOT, args.bundle.resolve(), args.dist.resolve(), context)
            print(f"release build: deterministic {manifest['tag']} at {manifest['source']['sha']}")
        elif args.command == "verify":
            expected_source = source_context_from_github(ROOT, allow_untracked=True) if args.github_source else None
            manifest = verify_bundle(
                args.bundle.resolve(),
                dist=args.dist.resolve() if args.dist else None,
                expected_source=expected_source,
            )
            print(f"release bundle: verified {manifest['tag']} at {manifest['source']['sha']}")
        elif args.command == "twine-check":
            twine_check(args.bundle.resolve())
            print("twine check: PASS")
        elif args.command == "pypi-state":
            _require(0 <= args.wait_seconds <= 600, "wait-seconds must be between 0 and 600")
            expected_source = source_context_from_github(ROOT, allow_untracked=True) if args.github_source else None
            state = pypi_state(
                args.bundle.resolve(),
                args.dist.resolve(),
                require_exact=args.require_exact,
                wait_seconds=args.wait_seconds,
                expected_source=expected_source,
            )
            print(f"PyPI state: {state}")
            if args.github_output:
                _write_github_output(state)
        elif args.command == "install-smoke":
            install_smoke(args.bundle.resolve(), args.mode, args.temp_root.resolve())
            print(f"install smoke ({args.mode}): PASS")
        elif args.command == "audit-workflows":
            problems = audit_repository(ROOT)
            _require(not problems, "\n".join(problems))
            print("workflow audit: PASS")
        else:  # pragma: no cover - argparse keeps this unreachable
            raise ReleaseError(f"unsupported command: {args.command}")
    except (OSError, subprocess.TimeoutExpired, ReleaseError) as exc:
        print(f"RELEASE BLOCKED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
