#!/usr/bin/env python3
"""Build, normalize, validate, and smoke-test compile-code releases.

The release boundary is deliberately standard-library-heavy.  The builder may
execute the reviewed PEP 517 backend, but the publisher receives only two
already-validated distributions and never executes repository code.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import email.policy
import gzip
import hashlib
import io
import json
import math
import os
import platform
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
GITHUB_API_VERSION = "2026-03-10"
GITHUB_WORKFLOW_ARTIFACT_NAME = "compile-code-release-bundle"
GITHUB_RELEASE_SIGNER_WORKFLOW = f"{REPOSITORY}/.github/workflows/release.yml"
GITHUB_CLI_VERSION = "2.96.0"
GITHUB_CLI_MINIMUM_SAFE_VERSION = (2, 93, 0)
GITHUB_CLI_ARCHIVE_NAME = f"gh_{GITHUB_CLI_VERSION}_linux_amd64.tar.gz"
GITHUB_CLI_ARCHIVE_URL = f"https://github.com/cli/cli/releases/download/v{GITHUB_CLI_VERSION}/{GITHUB_CLI_ARCHIVE_NAME}"
# Independently matched against the official v2.96.0 checksum list, immutable
# release-API asset digest, and downloaded bytes on 2026-07-18.  The member hash
# additionally binds the only executable that this verifier writes and invokes.
GITHUB_CLI_ARCHIVE_SIZE = 14_652_560
GITHUB_CLI_ARCHIVE_SHA256 = "83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60"
GITHUB_CLI_ARCHIVE_MEMBER = f"gh_{GITHUB_CLI_VERSION}_linux_amd64/bin/gh"
GITHUB_CLI_ARCHIVE_ENTRIES = 231
GITHUB_CLI_ARCHIVE_EXPANDED_SIZE = 41_089_793
GITHUB_CLI_BINARY_SIZE = 40_722_594
GITHUB_CLI_BINARY_SHA256 = "56b8bbbb27b066ecb33dbef9a256dc9d1314adaeff0908a752feba6c34053b40"
GITHUB_CLI_INSTALL_DIRECTORY = f"compile-code-gh-{GITHUB_CLI_VERSION}"
GITHUB_CLI_ENVIRONMENT_VARIABLE = "COMPILE_GITHUB_CLI"
GITHUB_CLI_DOWNLOAD_TIMEOUT_SECONDS = 60
GITHUB_CLI_SOCKET_TIMEOUT_SECONDS = 10
GITHUB_CLI_DOWNLOAD_CHUNK_SIZE = 1024 * 1024
RELEASE_GUARD_ENVIRONMENT = "release-guard"
RELEASE_GUARD_SECRET = "RELEASE_GUARD_READ_TOKEN"
RELEASE_GUARD_POLICY_ID = 55_007_746
RELEASE_GUARD_TAG_PATTERN = "v*"
EXPECTED_LOCKED_VERSION_COUNT = 47
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PYPI_PUBLISH_ATTESTATION_TYPE = "https://docs.pypi.org/attestations/publish/v1"
PYPI_INTEGRITY_MEDIA_TYPE = "application/vnd.pypi.integrity.v1+json"
EVIDENCE_POLICY = {
    "build_attestation": "github-build-provenance",
    "dependency_audit": "osv-locked-graphs",
    "pypi_publish_attestation": "pypi-integrity-api-pep740",
    "release_attestation": "github-immutable-release",
}
RELEASE_ACTION_INVENTORY = {
    "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373": 1,
    "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0": 6,
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c": 11,
    "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1": 6,
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a": 2,
    "ncipollo/release-action@339a81892b84b4eeb0f6e744e4574d79d0d9b8dd": 1,
    "octokit/request-action@b91aabaa861c777dcdb14e2387e30eddf04619ae": 10,
    "pypa/gh-action-pypi-publish@cef221092ed1bacb1cc03d23a2d87d1d172e277b": 1,
}
LOCK_GRAPHS = (
    ("build-requirements.in", "build-requirements.lock"),
    ("smoke-requirements.in", "smoke-requirements.lock"),
    ("tooling-requirements.in", "tooling-requirements.lock"),
)
OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
BUILD_REQUIRES = ["setuptools==83.0.0", "wheel==0.47.0"]
RUNTIME_REQUIRES = ["roam-code<14,>=13.10.0", "click>=8.0"]
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
REQUIRED_ROAM_VERIFY_PROTOCOL = "roam.verify.receipt.v3"
REQUIRED_CLAUDE_HOOK_READINESS = "Roam-generated Claude hooks accepted by Compile doctor"
VERSION_RE = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\Z")
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
SHA512_RE = re.compile(r"[0-9a-f]{128}\Z")
MAX_ARCHIVE_ENTRIES = 2_048
MAX_MEMBER_SIZE = 32 * 1024 * 1024
MAX_ARCHIVE_SIZE = 128 * 1024 * 1024
MAX_TAR_STREAM_SIZE = MAX_ARCHIVE_SIZE + (MAX_ARCHIVE_ENTRIES * 1_024) + 1_024
MAX_JSON_SIZE = 8 * 1024 * 1024
MAX_JSON_DEPTH = 128
MAX_PYPROJECT_SIZE = 1024 * 1024
MAX_COMMAND_DIAGNOSTIC_SIZE = 4 * 1024 * 1024
MAX_GITHUB_OUTPUT_SIZE = 1024 * 1024
MAX_GITHUB_RELEASE_LIST_PAGES = 100
MAX_GITHUB_EXPRESSION_INTEGER = (1 << 53) - 1
MAX_LOCK_SIZE = 1024 * 1024
MAX_OSV_RESPONSE_SIZE = 8 * 1024 * 1024
MAX_OSV_QUERIES = 1_000
MAX_ATTESTATION_STATEMENT_SIZE = 64 * 1024
MEDIA_TYPES = {
    "wheel": "application/zip",
    "sdist": "application/gzip",
    "sbom": "application/vnd.cyclonedx+json",
}
RELEASE_MEDIA_TYPES = {**MEDIA_TYPES, "manifest": "application/json"}
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
LOCK_REQUIREMENT_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)==((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){1,3})"
    r"(?:\s*;\s*([^\\\r\n]+))?\s*\\\s*$"
)
INPUT_REQUIREMENT_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)==((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){1,3})"
    r"(?:\s*;\s*([^\r\n]+))?\s*$"
)
LOCK_HASH_RE = re.compile(r"^--hash=sha256:([0-9a-f]{64})(?:\s+\\)?$")
OSV_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")


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


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _parse_bounded_json_int(value: str) -> int:
    if len(value.removeprefix("-")) > 128:
        raise ValueError("JSON integer literal is oversized")
    return int(value)


def _parse_finite_json_float(value: str) -> float:
    if len(value) > 128:
        raise ValueError("JSON floating-point literal is oversized")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number is forbidden: {value}")
    return parsed


def _preflight_json_depth(data: bytes, label: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for value in data:
        if in_string:
            if escaped:
                escaped = False
            elif value == 0x5C:  # backslash
                escaped = True
            elif value == 0x22:  # quote
                in_string = False
            continue
        if value == 0x22:
            in_string = True
        elif value in {0x5B, 0x7B}:  # [ {
            depth += 1
            _require(depth <= MAX_JSON_DEPTH, f"{label}: JSON nesting exceeds {MAX_JSON_DEPTH}")
        elif value in {0x5D, 0x7D}:  # ] }
            depth -= 1


def _load_json_bytes(data: bytes, label: str) -> Any:
    _require(len(data) <= MAX_JSON_SIZE, f"{label}: JSON exceeds {MAX_JSON_SIZE} bytes")
    _preflight_json_depth(data, label)
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
            parse_float=_parse_finite_json_float,
            parse_int=_parse_bounded_json_int,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ReleaseError(f"{label}: invalid strict UTF-8 JSON: {exc}") from exc


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
    _require(
        set(parsed) == {"build-system", "project", "tool"},
        f"{label}: root table must contain only build-system, project, and tool",
    )
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

    tools = parsed.get("tool")
    _require(isinstance(tools, dict) and set(tools) == {"ruff", "setuptools"}, f"{label}: tool table must be closed")
    _require(tools.get("ruff") == {"line-length": 120}, f"{label}: Ruff release configuration drift")
    setuptools_config = tools.get("setuptools", {})
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


def _validate_github_cli_release_url(url: Any, *, initial: bool, label: str) -> urllib.parse.ParseResult:
    _require(isinstance(url, str) and url.isascii(), f"unsafe {label}: {url!r}")
    _require(
        not any(ord(character) < 0x20 or character == "\\" for character in url),
        f"unsafe {label}: {url!r}",
    )
    try:
        parsed = urllib.parse.urlparse(url)
        port = parsed.port
    except ValueError as exc:
        raise ReleaseError(f"unsafe {label}: {url!r}: {exc}") from exc
    expected_host = "github.com" if initial else "release-assets.githubusercontent.com"
    _require(
        parsed.scheme == "https"
        and parsed.hostname == expected_host
        and port in {None, 443}
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment,
        f"unsafe {label}: {url!r}",
    )
    if initial:
        _require(url == GITHUB_CLI_ARCHIVE_URL, "GitHub CLI archive URL drift")
    else:
        _require(bool(parsed.path) and parsed.path != "/", "GitHub CLI release-asset path is missing")
    return parsed


class _GitHubCliRedirect(urllib.request.HTTPRedirectHandler):
    """Permit one credential-free redirect from GitHub to its release CDN."""

    def __init__(self) -> None:
        super().__init__()
        self.redirect_count = 0

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        self.redirect_count += 1
        _require(self.redirect_count == 1, "GitHub CLI archive redirected more than once")
        _require(code in {301, 302, 307, 308}, f"GitHub CLI archive used unexpected redirect status {code}")
        _validate_github_cli_release_url(req.full_url, initial=True, label="GitHub CLI archive URL")
        _validate_github_cli_release_url(newurl, initial=False, label="GitHub CLI release-asset redirect")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        _require(redirected is not None, "GitHub CLI archive redirect was not followed")
        redirected.headers.pop("Authorization", None)
        redirected.unredirected_hdrs.pop("Authorization", None)
        return redirected


def _fetch_github_cli_archive(*, opener: Any | None = None) -> bytes:
    """Fetch exactly one reviewed official archive with bounded unauthenticated I/O."""
    _validate_github_cli_release_url(
        GITHUB_CLI_ARCHIVE_URL,
        initial=True,
        label="GitHub CLI archive URL",
    )
    request = urllib.request.Request(
        GITHUB_CLI_ARCHIVE_URL,
        headers={
            "Accept": "application/octet-stream",
            "User-Agent": "compile-code-release-bootstrap/1",
        },
    )
    client = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), _GitHubCliRedirect())
    deadline = time.monotonic() + GITHUB_CLI_DOWNLOAD_TIMEOUT_SECONDS
    with client.open(request, timeout=GITHUB_CLI_SOCKET_TIMEOUT_SECONDS) as response:
        _validate_github_cli_release_url(
            response.geturl(),
            initial=False,
            label="final GitHub CLI release-asset URL",
        )
        _require(response.getcode() == 200, f"GitHub CLI archive returned HTTP {response.getcode()}")
        _require(
            response.headers.get("Content-Type") == "application/octet-stream",
            "GitHub CLI archive media type mismatch",
        )
        _require(
            response.headers.get("Content-Length") == str(GITHUB_CLI_ARCHIVE_SIZE),
            "GitHub CLI archive Content-Length mismatch",
        )
        _require(
            response.headers.get("Content-Disposition") == f"attachment; filename={GITHUB_CLI_ARCHIVE_NAME}",
            "GitHub CLI archive filename metadata mismatch",
        )
        chunks: list[bytes] = []
        received = 0
        read_once = getattr(response, "read1", response.read)
        while received < GITHUB_CLI_ARCHIVE_SIZE:
            _require(time.monotonic() < deadline, "GitHub CLI archive download exceeded its wall-clock deadline")
            chunk = read_once(min(GITHUB_CLI_DOWNLOAD_CHUNK_SIZE, GITHUB_CLI_ARCHIVE_SIZE - received))
            _require(chunk, "GitHub CLI archive ended before its declared byte length")
            received += len(chunk)
            _require(received <= GITHUB_CLI_ARCHIVE_SIZE, "GitHub CLI archive exceeded its exact byte length")
            chunks.append(chunk)
            _require(time.monotonic() < deadline, "GitHub CLI archive download exceeded its wall-clock deadline")
        archive_bytes = b"".join(chunks)
    _require(len(archive_bytes) == GITHUB_CLI_ARCHIVE_SIZE, "GitHub CLI archive byte length mismatch")
    _require(
        hashlib.sha256(archive_bytes).hexdigest() == GITHUB_CLI_ARCHIVE_SHA256,
        "GitHub CLI archive SHA-256 mismatch",
    )
    return archive_bytes


def _github_cli_binary_from_archive(archive_bytes: bytes) -> bytes:
    _require(
        isinstance(archive_bytes, bytes) and len(archive_bytes) == GITHUB_CLI_ARCHIVE_SIZE,
        "GitHub CLI archive byte length mismatch",
    )
    _require(
        hashlib.sha256(archive_bytes).hexdigest() == GITHUB_CLI_ARCHIVE_SHA256,
        "GitHub CLI archive SHA-256 mismatch",
    )
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            members = archive.getmembers()
            _require(
                len(members) == GITHUB_CLI_ARCHIVE_ENTRIES,
                "GitHub CLI archive member-count mismatch",
            )
            _require(
                sum(member.size for member in members) == GITHUB_CLI_ARCHIVE_EXPANDED_SIZE,
                "GitHub CLI archive expanded-size mismatch",
            )
            names: set[str] = set()
            target: tarfile.TarInfo | None = None
            for member in members:
                name = _safe_archive_name(member.name)
                _require(name not in names, f"duplicate GitHub CLI archive member: {name}")
                names.add(name)
                _require(member.isfile(), f"GitHub CLI archive contains a non-file member: {name}")
                _require(
                    0 <= member.size <= GITHUB_CLI_ARCHIVE_EXPANDED_SIZE,
                    f"GitHub CLI archive member is oversized: {name}",
                )
                if name == GITHUB_CLI_ARCHIVE_MEMBER:
                    target = member
            _require(target is not None, "GitHub CLI executable member is missing")
            _require(target.size == GITHUB_CLI_BINARY_SIZE, "GitHub CLI executable size metadata mismatch")
            _require(target.mode & 0o777 == 0o755, "GitHub CLI executable mode mismatch")
            stream = archive.extractfile(target)
            _require(stream is not None, "GitHub CLI executable member is unreadable")
            binary = stream.read(GITHUB_CLI_BINARY_SIZE + 1)
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ReleaseError(f"GitHub CLI archive is malformed: {exc}") from exc
    _require(len(binary) == GITHUB_CLI_BINARY_SIZE, "GitHub CLI executable byte length mismatch")
    _require(
        hashlib.sha256(binary).hexdigest() == GITHUB_CLI_BINARY_SHA256,
        "GitHub CLI executable SHA-256 mismatch",
    )
    return binary


def _github_cli_target(environ: dict[str, str] | None = None) -> tuple[Path, Path]:
    env = os.environ if environ is None else environ
    runner_temp_value = env.get("RUNNER_TEMP", "")
    _require(
        runner_temp_value
        and runner_temp_value.isascii()
        and not any(ord(character) < 0x20 for character in runner_temp_value),
        "RUNNER_TEMP is missing or unsafe",
    )
    runner_temp_path = Path(runner_temp_value)
    _require(runner_temp_path.is_absolute(), "RUNNER_TEMP must be an absolute path")
    runner_temp = _validated_real_directory(runner_temp_path, label="RUNNER_TEMP")
    if os.name == "posix":
        runner_temp_state = os.lstat(runner_temp)
        _require(runner_temp_state.st_uid == os.geteuid(), "RUNNER_TEMP is not owned by the release user")
        _require(runner_temp_state.st_mode & 0o022 == 0, "RUNNER_TEMP is group/world writable")
    root = ROOT.resolve()
    _require(
        runner_temp != root and root not in runner_temp.parents,
        "GitHub CLI must be installed outside the source workspace",
    )
    install_directory = runner_temp / GITHUB_CLI_INSTALL_DIRECTORY
    return install_directory, install_directory / "gh"


def _validate_github_cli_executable(
    executable: Path,
    *,
    run_command: Callable[..., bytes | str] = _run,
) -> str:
    install_directory = _validated_real_directory(executable.parent, label="GitHub CLI install")
    _require(install_directory.name == GITHUB_CLI_INSTALL_DIRECTORY, "GitHub CLI install directory drift")
    directory_state = os.lstat(install_directory)
    if os.name == "posix":
        _require(directory_state.st_uid == os.geteuid(), "GitHub CLI install directory owner mismatch")
        _require(directory_state.st_mode & 0o022 == 0, "GitHub CLI install directory is group/world writable")
    payload = _read_bounded_regular_file(
        executable,
        label="GitHub CLI executable",
        max_bytes=GITHUB_CLI_BINARY_SIZE,
    )
    _require(len(payload) == GITHUB_CLI_BINARY_SIZE, "GitHub CLI executable byte length mismatch")
    _require(hashlib.sha256(payload).hexdigest() == GITHUB_CLI_BINARY_SHA256, "GitHub CLI executable SHA-256 mismatch")
    executable_state = os.lstat(executable)
    if os.name == "posix":
        _require(executable_state.st_uid == os.geteuid(), "GitHub CLI executable owner mismatch")
        _require(executable_state.st_mode & 0o111 != 0, "GitHub CLI executable mode is not executable")
        _require(executable_state.st_mode & 0o022 == 0, "GitHub CLI executable is group/world writable")
    version_environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
    }
    output = run_command([str(executable), "--version"], cwd=ROOT, env=version_environment, timeout=30)
    _require(isinstance(output, str), "GitHub CLI version output is not text")
    lines = output.rstrip("\r\n").splitlines()
    _require(
        len(lines) == 2
        and re.fullmatch(
            rf"gh version {re.escape(GITHUB_CLI_VERSION)} \([0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}\)",
            lines[0],
        )
        is not None
        and lines[1] == f"https://github.com/cli/cli/releases/tag/v{GITHUB_CLI_VERSION}",
        f"GitHub CLI must report exact version {GITHUB_CLI_VERSION}",
    )
    return str(executable)


def _require_github_cli_platform() -> None:
    _require(sys.platform == "linux", "the pinned GitHub CLI archive requires Linux")
    _require(platform.machine().lower() in {"amd64", "x86_64"}, "the pinned GitHub CLI archive requires amd64")


def install_github_cli(
    *,
    environ: dict[str, str] | None = None,
    fetch_archive: Callable[[], bytes] = _fetch_github_cli_archive,
    run_command: Callable[..., bytes | str] = _run,
) -> Path:
    """Install the one reviewed gh binary into an exclusive runner-temp path."""
    _require_github_cli_platform()
    version_tuple = tuple(int(part) for part in GITHUB_CLI_VERSION.split("."))
    _require(version_tuple >= GITHUB_CLI_MINIMUM_SAFE_VERSION, "pinned GitHub CLI is below the safe version floor")
    install_directory, executable = _github_cli_target(environ)
    try:
        os.mkdir(install_directory, 0o700)
    except FileExistsError as exc:
        raise ReleaseError(f"GitHub CLI install target already exists: {install_directory}") from exc
    archive_bytes = fetch_archive()
    binary = _github_cli_binary_from_archive(archive_bytes)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(executable, flags, 0o500)
    try:
        _write_all(descriptor, binary)
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o500)
        else:  # pragma: no cover - Windows-only compatibility for local verification
            os.chmod(executable, 0o500)
        os.fsync(descriptor)
        written = os.fstat(descriptor)
        _require(written.st_size == GITHUB_CLI_BINARY_SIZE, "GitHub CLI executable write was incomplete")
    finally:
        os.close(descriptor)
    os.chmod(install_directory, 0o500)
    _validate_github_cli_executable(executable, run_command=run_command)
    return executable


def _github_cli_executable(environ: dict[str, str] | None = None) -> str:
    env = os.environ if environ is None else environ
    _install_directory, expected = _github_cli_target(env)
    configured_value = env.get(GITHUB_CLI_ENVIRONMENT_VARIABLE, "")
    _require(configured_value and Path(configured_value).is_absolute(), "controlled GitHub CLI path is missing")
    configured = Path(os.path.abspath(configured_value))
    _require(
        os.path.normcase(str(configured)) == os.path.normcase(str(expected)),
        "controlled GitHub CLI path does not match RUNNER_TEMP",
    )
    return _validate_github_cli_executable(configured)


def _run_github_cli(arguments: list[str], *, timeout: int = 120) -> str:
    """Re-prove the absolute binary hash and exact version before every gh call."""
    executable = _github_cli_executable()
    environment = {
        "GH_CONFIG_DIR": str(Path(executable).parent),
        "GH_HOST": "github.com",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "GH_PROMPT_DISABLED": "1",
        "GH_TOKEN": _github_token(),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
    }
    result = _run([executable, *arguments], cwd=ROOT, env=environment, timeout=timeout)
    _require(isinstance(result, str), "GitHub CLI command output is not text")
    return result


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
    tag_object_sha = _git(root, "rev-parse", f"{ref}^{{tag}}")
    _validate_sha(tag_object_sha)
    source_sha = _git(root, "rev-parse", f"{ref}^{{commit}}")
    _validate_sha(source_sha)
    tag_headers = _git(root, "cat-file", "-p", tag_object_sha).partition("\n\n")[0].splitlines()
    direct_headers: dict[str, list[str]] = {}
    for line in tag_headers:
        if line.startswith(" "):
            continue
        key, separator, value = line.partition(" ")
        if separator:
            direct_headers.setdefault(key, []).append(value)
    _require(direct_headers.get("object") == [source_sha], "annotated tag must directly target the source commit")
    _require(direct_headers.get("type") == ["commit"], "annotated tag target must be a commit")
    _require(direct_headers.get("tag") == [f"v{version}"], "annotated tag name differs from the release tag")
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
        "tag_object_sha": tag_object_sha,
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
        member_count = 0
        for member in archive:
            member_count += 1
            _require(member_count <= MAX_ARCHIVE_ENTRIES, "source archive has too many entries")
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


def _preflight_zip_archive(archive_bytes: bytes) -> int:
    """Bound the central directory before ZipFile allocates its entry list."""
    _require(0 < len(archive_bytes) <= MAX_ARCHIVE_SIZE, "wheel is missing or oversized")
    minimum_eocd_size = 22
    maximum_comment_size = 65_535
    search_start = max(0, len(archive_bytes) - minimum_eocd_size - maximum_comment_size)
    eocd_offset = archive_bytes.rfind(b"PK\x05\x06", search_start)
    _require(eocd_offset >= 0 and eocd_offset + minimum_eocd_size <= len(archive_bytes), "wheel EOCD is missing")
    (
        signature,
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_size,
    ) = struct.unpack_from("<4s4H2LH", archive_bytes, eocd_offset)
    _require(signature == b"PK\x05\x06", "wheel EOCD signature mismatch")
    _require(disk_number == central_disk == 0, "multi-disk wheel is forbidden")
    _require(disk_entries == total_entries, "wheel central-directory entry count mismatch")
    _require(total_entries not in {0, 0xFFFF}, "empty or ZIP64 wheel is forbidden")
    _require(total_entries <= MAX_ARCHIVE_ENTRIES, "wheel has too many entries")
    _require(central_size != 0xFFFFFFFF and central_offset != 0xFFFFFFFF, "ZIP64 wheel is forbidden")
    _require(
        eocd_offset + minimum_eocd_size + comment_size == len(archive_bytes),
        "wheel has trailing bytes or a malformed archive comment",
    )
    _require(
        central_offset + central_size == eocd_offset,
        "wheel central-directory bounds are non-canonical",
    )
    cursor = central_offset
    counted_entries = 0
    while cursor < eocd_offset:
        _require(cursor + 46 <= eocd_offset, "wheel central-directory record is truncated")
        _require(archive_bytes[cursor : cursor + 4] == b"PK\x01\x02", "wheel central-directory signature mismatch")
        filename_size, extra_size, record_comment_size = struct.unpack_from("<3H", archive_bytes, cursor + 28)
        record_size = 46 + filename_size + extra_size + record_comment_size
        _require(cursor + record_size <= eocd_offset, "wheel central-directory record exceeds its bounds")
        counted_entries += 1
        _require(counted_entries <= MAX_ARCHIVE_ENTRIES, "wheel has too many entries")
        cursor += record_size
    _require(cursor == eocd_offset, "wheel central-directory does not end at the EOCD")
    _require(counted_entries == total_entries, "wheel central-directory entry count mismatch")
    return total_entries


def _read_zip_files(path: Path, *, archive_bytes: bytes | None = None) -> dict[str, bytes]:
    if archive_bytes is None:
        archive_bytes = _read_bounded_regular_file(path, label="wheel", max_bytes=MAX_ARCHIVE_SIZE)
    expected_entries = _preflight_zip_archive(archive_bytes)
    files: dict[str, bytes] = {}
    folded: set[str] = set()
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            infos = archive.infolist()
            _require(len(infos) == expected_entries, "wheel central-directory entry count changed during parsing")
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
                payload = archive.read(info)
                _require(len(payload) == info.file_size, f"wheel member size mismatch: {name}")
                files[name] = payload
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
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(archive_bytes), mode="rb") as compressed:
            tar_bytes = compressed.read(MAX_TAR_STREAM_SIZE + 1)
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        raise ReleaseError(f"invalid sdist gzip stream: {exc}") from exc
    _require(len(tar_bytes) <= MAX_TAR_STREAM_SIZE, "sdist decompressed stream exceeds the size limit")
    files: dict[str, bytes] = {}
    folded: set[str] = set()
    roots: set[str] = set()
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
            member_count = 0
            for member in archive:
                member_count += 1
                _require(member_count <= MAX_ARCHIVE_ENTRIES, "sdist has too many entries")
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
        "evidence": EVIDENCE_POLICY,
        "files": records,
        "project": PROJECT,
        "schema": MANIFEST_SCHEMA,
        "schema_version": MANIFEST_VERSION,
        "source": {
            "repository": REPOSITORY_URL,
            "sha": source["sha"],
            "source_date_epoch": source["source_date_epoch"],
            "tag_object_sha": source["tag_object_sha"],
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
    """Build with scrubbed launch state and package-index access disabled."""
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
    _validated_real_directory(raw, label="backend output")
    expected = {_expected_wheel_name(source["version"]), _expected_sdist_name(source["version"])}
    entries = list(raw.iterdir())
    for path in entries:
        try:
            state = os.lstat(path)
        except OSError as exc:
            raise ReleaseError(f"backend output cannot be inspected: {path}: {exc}") from exc
        _require(
            stat.S_ISREG(state.st_mode)
            and not stat.S_ISLNK(state.st_mode)
            and not _is_reparse_point(state)
            and state.st_nlink == 1,
            f"backend output must contain only singly-linked regular artifacts: {path.name}",
        )
    actual = {path.name for path in entries}
    _require(actual == expected, f"backend artifact set mismatch: expected {sorted(expected)}, got {sorted(actual)}")
    normalized.mkdir(parents=True, exist_ok=False)
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
    sections: set[str] = set()
    found: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
            _require(section == "console_scripts", f"unexpected wheel entry-point section: {section}")
            _require(section not in sections, f"duplicate wheel entry-point section: {section}")
            sections.add(section)
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
        document,
        {"evidence", "files", "project", "schema", "schema_version", "source", "tag", "version"},
        "manifest",
    )
    _require(_canonical_json(manifest) == canonical_bytes, "manifest must use canonical JSON encoding")
    _require(
        manifest["schema"] == MANIFEST_SCHEMA
        and type(manifest["schema_version"]) is int
        and manifest["schema_version"] == MANIFEST_VERSION,
        "manifest schema mismatch",
    )
    _require(manifest["project"] == PROJECT, "manifest project mismatch")
    evidence = _exact_keys(
        manifest["evidence"],
        set(EVIDENCE_POLICY),
        "manifest.evidence",
    )
    _require(evidence == EVIDENCE_POLICY, "manifest evidence policy mismatch")
    version = _validate_version(manifest["version"])
    _validate_tag(manifest["tag"], version)
    source = _exact_keys(
        manifest["source"], {"repository", "sha", "source_date_epoch", "tag_object_sha"}, "manifest.source"
    )
    _require(source["repository"] == REPOSITORY_URL, "manifest source repository mismatch")
    _validate_sha(source["sha"])
    _validate_sha(source["tag_object_sha"])
    _require(source["tag_object_sha"] != source["sha"], "annotated tag object must differ from its source commit")
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
            manifest["source"]["tag_object_sha"] == expected_source["tag_object_sha"],
            "manifest tag object differs from validated source",
        )
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


def _release_text(path: Path, *, label: str) -> str:
    data = _read_bounded_regular_file(path, label=label, max_bytes=MAX_LOCK_SIZE)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseError(f"{label} must be UTF-8: {exc}") from exc
    _require("\x00" not in text, f"{label} contains a NUL byte")
    text = text.replace("\r\n", "\n")
    _require("\r" not in text, f"{label} contains a bare carriage return")
    return text


def _validate_requirement_marker(marker: str | None, *, label: str) -> None:
    if marker is None:
        return
    _require(
        0 < len(marker) <= 1_000 and marker.isascii() and not any(ord(character) < 0x20 for character in marker),
        f"{label} contains an unsafe environment marker",
    )


def _parse_release_input(path: Path) -> dict[str, str]:
    label = f"release input {path.name}"
    text = _release_text(path, label=label)
    requirements: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = INPUT_REQUIREMENT_RE.fullmatch(stripped)
        _require(match is not None, f"{label}:{line_number}: requirement must use one exact version")
        name = _canonical_name(match.group(1))
        _require(name != "roam-code", f"{label} must not resolve the unpublished roam-code dependency")
        _require(name not in requirements, f"{label} contains a duplicate requirement: {name}")
        _validate_requirement_marker(match.group(3), label=f"{label}:{line_number}")
        requirements[name] = match.group(2)
    _require(requirements, f"{label} contains no requirements")
    return requirements


def _parse_release_lock(path: Path, *, input_name: str) -> dict[str, str]:
    label = f"release lock {path.name}"
    text = _release_text(path, label=label)
    lines = text.splitlines()
    _require(len(lines) >= 3, f"{label} is truncated")
    _require(
        lines[0] == "# This file was autogenerated by uv via the following command:",
        f"{label} is missing the uv provenance header",
    )
    expected_command = (
        f"#    uv pip compile release/{input_name} --universal --python-version 3.10 --generate-hashes "
        f"--no-emit-index-url --output-file release/{path.name}"
    )
    _require(
        lines[1].replace("\\", "/") == expected_command,
        f"{label} generation command drift",
    )
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
        " @ ",
        " -e ",
        "git+",
        "http://",
        "https://",
    ):
        _require(forbidden not in lowered, f"{label} contains forbidden construct: {forbidden.strip()}")

    starts: list[tuple[int, re.Match[str]]] = []
    for line_number, line in enumerate(lines, 1):
        match = LOCK_REQUIREMENT_RE.fullmatch(line)
        if match is not None:
            starts.append((line_number, match))
            continue
        stripped = line.strip()
        _require(
            not stripped or stripped.startswith("#") or LOCK_HASH_RE.fullmatch(stripped) is not None,
            f"{label}:{line_number}: unexpected or unpinned requirement syntax",
        )
    _require(starts, f"{label} contains no exact requirements")
    first_requirement_line = starts[0][0]
    _require(
        not any(LOCK_HASH_RE.fullmatch(line.strip()) for line in lines[: first_requirement_line - 1]),
        f"{label} contains an orphaned hash",
    )

    requirements: dict[str, str] = {}
    for index, (line_number, match) in enumerate(starts):
        block_end = starts[index + 1][0] - 1 if index + 1 < len(starts) else len(lines)
        hashes = [
            hash_match.group(1)
            for line in lines[line_number:block_end]
            if (hash_match := LOCK_HASH_RE.fullmatch(line.strip())) is not None
        ]
        name = _canonical_name(match.group(1))
        _require(name != "roam-code", f"{label} must not resolve the unpublished roam-code dependency")
        _require(name not in requirements, f"{label} contains a duplicate requirement: {name}")
        _require(hashes, f"{label}:{line_number}: {name} has no SHA-256 hashes")
        _require(len(hashes) == len(set(hashes)), f"{label}:{line_number}: {name} has duplicate hashes")
        _validate_requirement_marker(match.group(3), label=f"{label}:{line_number}")
        requirements[name] = match.group(2)
    return requirements


def locked_requirement_queries(
    root: Path = ROOT,
) -> tuple[list[dict[str, Any]], dict[tuple[str, str], tuple[str, ...]]]:
    """Return a stable OSV query set from the three universal hashed graphs."""
    release_dir = _validated_real_directory(root / "release", label="release lock")
    provenance: dict[tuple[str, str], set[str]] = {}
    for input_name, lock_name in LOCK_GRAPHS:
        roots = _parse_release_input(release_dir / input_name)
        locked = _parse_release_lock(release_dir / lock_name, input_name=input_name)
        for name, version in roots.items():
            _require(
                locked.get(name) == version,
                f"release lock {lock_name} is stale for root {name}=={version}",
            )
        for name, version in locked.items():
            provenance.setdefault((name, version), set()).add(lock_name)
    _require(
        len(provenance) == EXPECTED_LOCKED_VERSION_COUNT,
        f"locked dependency query count must remain exactly {EXPECTED_LOCKED_VERSION_COUNT}; got {len(provenance)}",
    )
    ordered = sorted(provenance)
    queries = [{"package": {"ecosystem": "PyPI", "name": name}, "version": version} for name, version in ordered]
    return queries, {key: tuple(sorted(provenance[key])) for key in ordered}


class _RejectOSVRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        raise ReleaseError(f"OSV audit endpoint unexpectedly redirected with HTTP {code}")


def _fetch_osv_batch(payload: bytes) -> Any:
    _require(0 < len(payload) <= MAX_JSON_SIZE, "OSV query payload is missing or oversized")
    request = urllib.request.Request(
        OSV_QUERY_BATCH_URL,
        data=payload,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "compile-code-release-audit/1",
        },
    )
    opener = urllib.request.build_opener(_RejectOSVRedirect())
    try:
        with opener.open(request, timeout=30) as response:
            _require(response.geturl() == OSV_QUERY_BATCH_URL, "OSV audit response came from an unexpected URL")
            _require(response.getcode() == 200, f"OSV audit returned HTTP {response.getcode()}")
            content_type = response.headers.get_content_type()
            _require(content_type == "application/json", f"OSV audit returned unexpected media type: {content_type}")
            data = response.read(MAX_OSV_RESPONSE_SIZE + 1)
    except urllib.error.HTTPError as exc:
        raise ReleaseError(f"OSV audit request failed: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise ReleaseError(f"OSV audit request failed: {exc.reason}") from exc
    _require(len(data) <= MAX_OSV_RESPONSE_SIZE, "OSV audit response is oversized")
    return _load_json_bytes(data, "OSV querybatch response")


def audit_locked_requirements(
    root: Path = ROOT,
    *,
    fetch_json: Callable[[bytes], Any] = _fetch_osv_batch,
) -> int:
    """Audit only exact lock rows; never invoke pip or resolve project dependencies."""
    queries, provenance = locked_requirement_queries(root)
    document = fetch_json(_canonical_json({"queries": queries}))
    response = _exact_keys(document, {"results"}, "OSV querybatch response")
    results = response["results"]
    _require(isinstance(results, list), "OSV querybatch results must be an array")
    _require(len(results) == len(queries), "OSV querybatch result count mismatch")

    findings: list[str] = []
    for index, (query, result) in enumerate(zip(queries, results, strict=True)):
        _require(isinstance(result, dict), f"OSV querybatch result {index} must be an object")
        _require(
            set(result) <= {"vulns", "next_page_token"},
            f"OSV querybatch result {index} contains unknown fields",
        )
        _require("next_page_token" not in result, f"OSV querybatch result {index} is incomplete and paginated")
        vulnerabilities = result.get("vulns", [])
        _require(isinstance(vulnerabilities, list), f"OSV querybatch result {index} vulnerabilities must be an array")
        package = query["package"]["name"]
        version = query["version"]
        seen_ids: set[str] = set()
        for vulnerability in vulnerabilities:
            row = _exact_keys(vulnerability, {"id", "modified"}, f"OSV vulnerability for {package}=={version}")
            identifier = row["id"]
            modified = row["modified"]
            _require(
                isinstance(identifier, str) and OSV_ID_RE.fullmatch(identifier) is not None,
                f"OSV vulnerability ID is malformed for {package}=={version}",
            )
            _require(
                isinstance(modified, str)
                and 10 <= len(modified) <= 100
                and modified.isascii()
                and modified.endswith("Z"),
                f"OSV vulnerability modified timestamp is malformed for {package}=={version}",
            )
            _require(identifier not in seen_ids, f"OSV returned a duplicate vulnerability ID for {package}=={version}")
            seen_ids.add(identifier)
            graphs = ",".join(provenance[(package, version)])
            findings.append(f"{package}=={version}:{identifier}[{graphs}]")
    if findings:
        display = "; ".join(sorted(findings)[:20])
        suffix = "" if len(findings) <= 20 else f"; plus {len(findings) - 20} more"
        raise ReleaseError(f"locked dependency vulnerabilities found ({len(findings)}): {display}{suffix}")
    return len(queries)


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        _validate_registry_url(newurl, label="registry redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _validate_registry_url(url: Any, *, label: str = "registry URL") -> urllib.parse.ParseResult:
    _require(
        isinstance(url, str)
        and url.isascii()
        and not any(character.isspace() or ord(character) < 0x20 or character == "\\" for character in url),
        f"unsafe {label}: {url!r}",
    )
    try:
        parsed = urllib.parse.urlparse(url)
        port = parsed.port
    except ValueError as exc:
        raise ReleaseError(f"unsafe {label}: {url!r}: {exc}") from exc
    _require(
        parsed.scheme == "https"
        and parsed.hostname in {"pypi.org", "files.pythonhosted.org"}
        and port in {None, 443}
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment,
        f"unsafe {label}: {url}",
    )
    return parsed


def _fetch_url(url: str, *, max_bytes: int, accept: str = "application/octet-stream") -> bytes:
    _validate_registry_url(url)
    _require(
        isinstance(accept, str)
        and 0 < len(accept) <= 200
        and accept.isascii()
        and not any(character.isspace() or ord(character) < 0x20 for character in accept),
        "unsafe registry Accept media type",
    )
    request = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "compile-code-release/1"})
    opener = urllib.request.build_opener(_SafeRedirect())
    with opener.open(request, timeout=30) as response:
        _validate_registry_url(response.geturl(), label="final registry URL")
        _require(response.getcode() == 200, f"registry request returned HTTP {response.getcode()}")
        data = response.read(max_bytes + 1)
    _require(len(data) <= max_bytes, f"registry response exceeds {max_bytes} bytes")
    return data


def _fetch_pypi_json() -> dict[str, Any] | None:
    try:
        data = _fetch_url(
            f"https://pypi.org/pypi/{PROJECT}/json",
            max_bytes=MAX_JSON_SIZE,
            accept="application/json",
        )
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise ReleaseError(f"PyPI registry request failed: HTTP {exc.code}") from exc
    document = _load_json_bytes(data, "PyPI project JSON")
    _require(isinstance(document, dict), "PyPI project JSON must be an object")
    return document


def _fetch_pypi_provenance(version: str, filename: str) -> dict[str, Any] | None:
    version = _validate_version(version)
    filename = _safe_bundle_filename(filename)
    url = (
        f"https://pypi.org/integrity/{urllib.parse.quote(PROJECT, safe='')}/"
        f"{urllib.parse.quote(version, safe='')}/{urllib.parse.quote(filename, safe='')}/provenance"
    )
    try:
        data = _fetch_url(url, max_bytes=MAX_JSON_SIZE, accept=PYPI_INTEGRITY_MEDIA_TYPE)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise ReleaseError(f"PyPI Integrity API request failed: HTTP {exc.code}") from exc
    document = _load_json_bytes(data, f"PyPI provenance for {filename}")
    _require(isinstance(document, dict), f"PyPI provenance must be an object: {filename}")
    return document


def _decode_bounded_base64(value: Any, *, label: str, max_bytes: int) -> bytes:
    _require(isinstance(value, str) and value.isascii(), f"{label} must be base64 text")
    _require(0 < len(value) <= ((max_bytes + 2) // 3) * 4, f"{label} exceeds the encoded size limit")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ReleaseError(f"{label} is not canonical base64") from exc
    _require(0 < len(decoded) <= max_bytes, f"{label} exceeds the decoded size limit")
    _require(base64.b64encode(decoded).decode("ascii") == value, f"{label} is not canonical base64")
    return decoded


def _validate_pypi_publish_provenance(document: Any, *, filename: str, sha256: str) -> None:
    provenance = _exact_keys(document, {"attestation_bundles", "version"}, f"PyPI provenance for {filename}")
    _require(type(provenance["version"]) is int and provenance["version"] == 1, "PyPI provenance version mismatch")
    bundles = provenance["attestation_bundles"]
    _require(isinstance(bundles, list) and 0 < len(bundles) <= 128, "PyPI provenance bundle inventory is malformed")
    matched_publish_attestations = 0
    for bundle_index, bundle_value in enumerate(bundles):
        bundle = _exact_keys(
            bundle_value,
            {"attestations", "publisher"},
            f"PyPI provenance bundle {bundle_index}",
        )
        publisher = bundle["publisher"]
        _require(isinstance(publisher, dict), f"PyPI provenance publisher {bundle_index} must be an object")
        _require(
            {"claims", "kind"} <= set(publisher),
            f"PyPI provenance publisher {bundle_index} is missing required identity fields",
        )
        claims = publisher["claims"]
        _require(claims is None or isinstance(claims, dict), "PyPI provenance publisher claims are malformed")
        expected_publisher = (
            publisher.get("kind") == "GitHub"
            and publisher.get("repository") == REPOSITORY
            and publisher.get("workflow") == "release.yml"
            and publisher.get("environment") == "pypi"
        )
        attestations = bundle["attestations"]
        _require(
            isinstance(attestations, list) and 0 < len(attestations) <= 128,
            f"PyPI provenance attestation inventory is malformed: bundle {bundle_index}",
        )
        if not expected_publisher:
            continue
        for attestation_index, attestation_value in enumerate(attestations):
            label = f"PyPI attestation {bundle_index}:{attestation_index} for {filename}"
            _require(isinstance(attestation_value, dict), f"{label} must be an object")
            _require(
                {"envelope", "verification_material", "version"} <= set(attestation_value),
                f"{label} is missing required fields",
            )
            _require(
                type(attestation_value["version"]) is int and attestation_value["version"] == 1,
                f"{label} version mismatch",
            )
            verification_material = attestation_value["verification_material"]
            _require(isinstance(verification_material, dict), f"{label} verification material must be an object")
            _require(
                {"certificate", "transparency_entries"} <= set(verification_material),
                f"{label} verification material is incomplete",
            )
            _decode_bounded_base64(
                verification_material["certificate"],
                label=f"{label} certificate",
                max_bytes=64 * 1024,
            )
            transparency_entries = verification_material["transparency_entries"]
            _require(
                isinstance(transparency_entries, list)
                and 0 < len(transparency_entries) <= 128
                and all(isinstance(entry, dict) for entry in transparency_entries),
                f"{label} transparency log evidence is missing",
            )
            envelope = attestation_value["envelope"]
            _require(isinstance(envelope, dict), f"{label} envelope must be an object")
            _require({"signature", "statement"} <= set(envelope), f"{label} envelope is incomplete")
            _decode_bounded_base64(envelope["signature"], label=f"{label} signature", max_bytes=4 * 1024)
            statement_bytes = _decode_bounded_base64(
                envelope["statement"],
                label=f"{label} statement",
                max_bytes=MAX_ATTESTATION_STATEMENT_SIZE,
            )
            statement = _exact_keys(
                _load_json_bytes(statement_bytes, f"{label} statement"),
                {"_type", "predicate", "predicateType", "subject"},
                f"{label} statement",
            )
            _require(statement["_type"] == IN_TOTO_STATEMENT_TYPE, f"{label} in-toto statement type mismatch")
            subjects = statement["subject"]
            _require(isinstance(subjects, list) and len(subjects) == 1, f"{label} must bind exactly one subject")
            subject = _exact_keys(subjects[0], {"digest", "name"}, f"{label} subject")
            _require(subject["name"] == filename, f"{label} subject filename mismatch")
            digest = subject["digest"]
            _require(isinstance(digest, dict), f"{label} subject digest must be an object")
            _require(digest.get("sha256") == sha256, f"{label} subject SHA-256 mismatch")
            if statement["predicateType"] == PYPI_PUBLISH_ATTESTATION_TYPE:
                _require(statement["predicate"] in ({}, None), f"{label} publish predicate must be empty")
                matched_publish_attestations += 1
    _require(
        matched_publish_attestations >= 1,
        f"PyPI provenance lacks the expected Cranot/compile-code release.yml pypi publish attestation: {filename}",
    )


def _remote_release_state(
    bundle: Path,
    dist: Path,
    *,
    expected_source: dict[str, Any] | None = None,
    fetch_project: Callable[[], dict[str, Any] | None] = _fetch_pypi_json,
    fetch_bytes: Callable[[str], bytes] | None = None,
    fetch_provenance: Callable[[str, str], dict[str, Any] | None] = _fetch_pypi_provenance,
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
    attestation_pending = False
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
        _validate_registry_url(url)
        remote = downloader(url)
        _require(
            isinstance(remote, bytes) and len(remote) <= MAX_ARCHIVE_SIZE, f"PyPI payload is oversized: {filename}"
        )
        local = _read_bounded_regular_file(
            dist / filename, label=f"local publication {filename}", max_bytes=MAX_ARCHIVE_SIZE
        )
        _require(remote == local, f"PyPI exact-byte mismatch: {filename}")
        provenance = fetch_provenance(manifest["version"], filename)
        if provenance is None:
            attestation_pending = True
        else:
            _validate_pypi_publish_provenance(
                provenance,
                filename=filename,
                sha256=record["hashes"]["sha256"],
            )
    return "attestation_pending" if attestation_pending else "exact"


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
        if state == "missing" and not require_exact:
            return state
        if state == "attestation_pending" and wait_seconds == 0:
            raise ReleaseError("PyPI files are exact but their publish attestations are not yet available")
        if time.monotonic() >= deadline:
            raise ReleaseError("PyPI release did not become byte-exact with publish attestations before the deadline")
        time.sleep(min(10, max(1, int(deadline - time.monotonic()))))


def _write_github_output(state: str) -> None:
    _require(state in {"missing", "exact"}, "invalid publication state")
    _append_github_output(
        [
            f"state={state}",
            f"publish_required={'true' if state == 'missing' else 'false'}",
        ]
    )


def _release_name(version: str) -> str:
    return f"compile-code v{_validate_version(version)}"


def _release_body(version: str) -> str:
    version = _validate_version(version)
    return (
        f"compile-code {version} release artifacts. The closed asset set is byte-bound by "
        f"{MANIFEST_NAME} and requires GitHub build-provenance plus immutable-release attestations."
    )


def _validate_github_token(token: Any, label: str) -> str:
    _require(
        isinstance(token, str)
        and 20 <= len(token) <= 2_048
        and token.isascii()
        and not any(character.isspace() or ord(character) < 0x20 for character in token),
        f"{label} must contain one bounded GitHub token",
    )
    return token


def _github_token(environ: dict[str, str] | None = None) -> str:
    env = os.environ if environ is None else environ
    return _validate_github_token(env.get("GH_TOKEN") or env.get("GITHUB_TOKEN"), "GH_TOKEN or GITHUB_TOKEN")


def _immutable_releases_token(environ: dict[str, str] | None = None) -> str:
    env = os.environ if environ is None else environ
    return _validate_github_token(
        env.get("IMMUTABLE_RELEASES_TOKEN"),
        (
            "IMMUTABLE_RELEASES_TOKEN with owner identity and repository Administration:read, Contents:read, "
            "Environments:read, and Secrets:read"
        ),
    )


def _validate_github_asset_url(url: Any, *, label: str) -> urllib.parse.ParseResult:
    _require(
        isinstance(url, str)
        and url.isascii()
        and not any(character.isspace() or ord(character) < 0x20 or character == "\\" for character in url),
        f"unsafe {label}: {url!r}",
    )
    try:
        parsed = urllib.parse.urlparse(url)
        port = parsed.port
    except ValueError as exc:
        raise ReleaseError(f"unsafe {label}: {url!r}: {exc}") from exc
    _require(
        parsed.scheme == "https"
        and parsed.hostname
        in {"api.github.com", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
        and port in {None, 443}
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment,
        f"unsafe {label}: {url!r}",
    )
    return parsed


class _GitHubAssetRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        parsed = _validate_github_asset_url(newurl, label="GitHub release-asset redirect")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and parsed.hostname != "api.github.com":
            redirected.headers.pop("Authorization", None)
            redirected.unredirected_hdrs.pop("Authorization", None)
        return redirected


class _RejectGitHubAPIRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        raise ReleaseError(f"GitHub JSON API unexpectedly redirected with HTTP {code}")


def _github_api_json(path: str, allow_not_found: bool = False, *, token: str | None = None) -> Any | None:
    _require(isinstance(path, str), f"unsafe GitHub API path: {path!r}")
    prefix = f"/repos/{REPOSITORY}/"
    safe_user_path = path == "/user"
    release_list_match = re.fullmatch(rf"{re.escape(prefix)}releases\?per_page=100&page=([1-9][0-9]{{0,2}})", path)
    safe_release_list_query = (
        release_list_match is not None and int(release_list_match.group(1)) <= MAX_GITHUB_RELEASE_LIST_PAGES
    )
    _require(
        isinstance(path, str)
        and (path.startswith(prefix) or safe_user_path)
        and ".." not in path
        and "#" not in path
        and path.isascii()
        and not any(character.isspace() or ord(character) < 0x20 for character in path)
        and ("?" not in path or safe_release_list_query),
        f"unsafe GitHub API path: {path!r}",
    )
    auth_token = _github_token() if token is None else _validate_github_token(token, "GitHub API token")
    url = f"https://api.github.com{path}"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {auth_token}",
            "User-Agent": "compile-code-release/1",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        },
    )
    opener = urllib.request.build_opener(_RejectGitHubAPIRedirect())
    try:
        with opener.open(request, timeout=30) as response:
            _require(response.geturl() == url, "GitHub JSON API unexpectedly redirected")
            _require(response.getcode() == 200, f"GitHub JSON API returned HTTP {response.getcode()}")
            data = response.read(MAX_JSON_SIZE + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and allow_not_found:
            return None
        raise ReleaseError(f"GitHub API request failed for {path}: HTTP {exc.code}") from exc
    _require(len(data) <= MAX_JSON_SIZE, f"GitHub API response exceeds {MAX_JSON_SIZE} bytes")
    return _load_json_bytes(data, f"GitHub API {path}")


def _fetch_github_release_asset(asset_id: int, *, token: str, max_bytes: int) -> bytes:
    _require(type(asset_id) is int and asset_id > 0, "GitHub release asset ID must be a positive integer")
    token = _validate_github_token(token, "GitHub release asset token")
    url = f"https://api.github.com/repos/{REPOSITORY}/releases/assets/{asset_id}"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/octet-stream",
            "Authorization": f"Bearer {token}",
            "User-Agent": "compile-code-release/1",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        },
    )
    opener = urllib.request.build_opener(_GitHubAssetRedirect())
    with opener.open(request, timeout=30) as response:
        _validate_github_asset_url(response.geturl(), label="final GitHub release-asset URL")
        _require(response.getcode() == 200, f"GitHub release asset returned HTTP {response.getcode()}")
        data = response.read(max_bytes + 1)
    _require(len(data) <= max_bytes, f"GitHub release asset exceeds {max_bytes} bytes")
    return data


def _validate_workflow_artifact_metadata(
    document: Any,
    *,
    artifact_id: str,
    artifact_digest: str,
    source_sha: str,
    run_id: str,
) -> None:
    _require(isinstance(document, dict), "GitHub Actions artifact metadata must be an object")
    _require(re.fullmatch(r"[1-9][0-9]{0,19}", artifact_id) is not None, "artifact ID must be a positive integer")
    _require(HASH_RE.fullmatch(artifact_digest) is not None, "artifact digest must be lowercase SHA-256")
    _validate_sha(source_sha)
    _require(re.fullmatch(r"[1-9][0-9]{0,19}", run_id) is not None, "GITHUB_RUN_ID must be a positive integer")
    expected_id = int(artifact_id)
    _require(type(document.get("id")) is int and document["id"] == expected_id, "Actions artifact ID mismatch")
    _require(document.get("name") == GITHUB_WORKFLOW_ARTIFACT_NAME, "Actions artifact name mismatch")
    _require(document.get("expired") is False, "Actions artifact is expired")
    _require(document.get("digest") == f"sha256:{artifact_digest}", "Actions artifact digest mismatch")
    workflow_run = document.get("workflow_run")
    _require(isinstance(workflow_run, dict), "Actions artifact workflow binding is missing")
    _require(
        type(workflow_run.get("id")) is int and workflow_run["id"] == int(run_id),
        "Actions artifact workflow-run ID mismatch",
    )
    _require(workflow_run.get("head_sha") == source_sha, "Actions artifact source SHA mismatch")


def verify_github_workflow_artifact(
    *,
    artifact_id: str,
    artifact_digest: str,
    expected_source: dict[str, Any],
    environ: dict[str, str] | None = None,
    fetch_json: Callable[[str, bool], Any | None] | None = None,
) -> None:
    env = os.environ if environ is None else environ
    run_id = env.get("GITHUB_RUN_ID", "")
    token = _github_token(env)
    reader = fetch_json or (lambda path, missing: _github_api_json(path, missing, token=token))
    document = reader(f"/repos/{REPOSITORY}/actions/artifacts/{artifact_id}", False)
    _validate_workflow_artifact_metadata(
        document,
        artifact_id=artifact_id,
        artifact_digest=artifact_digest,
        source_sha=expected_source["sha"],
        run_id=run_id,
    )


def _validate_remote_annotated_tag(
    source: dict[str, Any],
    reader: Callable[[str, bool], Any | None],
) -> None:
    version = _validate_version(source["version"])
    tag = _validate_tag(source["tag"], version)
    source_sha = _validate_sha(source["sha"])
    tag_object_sha = _validate_sha(source["tag_object_sha"])
    ref = reader(f"/repos/{REPOSITORY}/git/ref/tags/{tag}", False)
    _require(isinstance(ref, dict) and ref.get("ref") == f"refs/tags/{tag}", "remote release tag ref mismatch")
    ref_object = ref.get("object")
    _require(isinstance(ref_object, dict), "remote release tag object is missing")
    _require(ref_object.get("type") == "tag", "remote release tag must remain annotated")
    _require(ref_object.get("sha") == tag_object_sha, "remote annotated tag object SHA mismatch")
    tag_object = reader(f"/repos/{REPOSITORY}/git/tags/{tag_object_sha}", False)
    _require(isinstance(tag_object, dict), "remote annotated tag record is missing")
    _require(tag_object.get("sha") == tag_object_sha, "remote annotated tag record SHA mismatch")
    _require(tag_object.get("tag") == tag, "remote annotated tag name mismatch")
    target = tag_object.get("object")
    _require(isinstance(target, dict), "remote annotated tag target is missing")
    _require(target.get("type") == "commit", "remote annotated tag target must be a commit")
    _require(target.get("sha") == source_sha, "remote annotated tag source SHA mismatch")


def _validate_release_guard_identity(reader: Callable[[str, bool], Any | None]) -> None:
    user = reader("/user", False)
    _require(isinstance(user, dict), "release guard identity response must be an object")
    _require(user.get("login") == OWNER, f"release guard token must belong to {OWNER}")
    _require(type(user.get("id")) is int and user["id"] > 0, "release guard identity ID is invalid")
    _require(user.get("type") == "User", "release guard identity must be a GitHub user")


def _validate_release_guard_environment(reader: Callable[[str, bool], Any | None]) -> None:
    base = f"/repos/{REPOSITORY}/environments/{RELEASE_GUARD_ENVIRONMENT}"
    document = reader(base, False)
    _require(isinstance(document, dict), "release-guard environment response must be an object")
    _require(document.get("name") == RELEASE_GUARD_ENVIRONMENT, "release-guard environment name mismatch")
    _require(type(document.get("can_admins_bypass")) is bool, "release-guard admin-bypass state is malformed")
    branch_policy = _exact_keys(
        document.get("deployment_branch_policy"),
        {"custom_branch_policies", "protected_branches"},
        "release-guard deployment branch policy",
    )
    _require(
        branch_policy == {"custom_branch_policies": True, "protected_branches": False},
        "release-guard must use custom deployment branch/tag policies only",
    )

    rules = document.get("protection_rules")
    _require(isinstance(rules, list), "release-guard protection rules must be an array")
    _require(all(isinstance(rule, dict) for rule in rules), "release-guard protection rule must be an object")
    required_reviewers = [rule for rule in rules if rule.get("type") == "required_reviewers"]
    branch_rules = [rule for rule in rules if rule.get("type") == "branch_policy"]
    _require(len(required_reviewers) == 1, "release-guard must have one required-reviewers rule")
    _require(len(branch_rules) == 1, "release-guard must have one branch-policy protection rule")
    reviewer_rule = required_reviewers[0]
    _require(
        reviewer_rule.get("prevent_self_review") is False,
        "release-guard prevent_self_review must remain false for the owner-reviewer contract",
    )
    reviewers = reviewer_rule.get("reviewers")
    _require(isinstance(reviewers, list) and len(reviewers) == 1, "release-guard must require only reviewer Cranot")
    reviewer_row = reviewers[0]
    _require(
        isinstance(reviewer_row, dict) and reviewer_row.get("type") == "User", "release-guard reviewer type mismatch"
    )
    reviewer = reviewer_row.get("reviewer")
    _require(isinstance(reviewer, dict), "release-guard reviewer record is missing")
    _require(reviewer.get("login") == OWNER, "release-guard required reviewer must be Cranot")
    _require(type(reviewer.get("id")) is int and reviewer["id"] > 0, "release-guard reviewer ID is invalid")
    _require(reviewer.get("type") == "User", "release-guard reviewer account type mismatch")

    policies = reader(f"{base}/deployment-branch-policies", False)
    _require(isinstance(policies, dict), "release-guard deployment policy response must be an object")
    rows = policies.get("branch_policies")
    _require(
        type(policies.get("total_count")) is int and policies["total_count"] == 1,
        "release-guard must have one deployment tag policy",
    )
    _require(
        isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict),
        "release-guard deployment tag policy is missing",
    )
    policy = rows[0]
    _require(policy.get("id") == RELEASE_GUARD_POLICY_ID, "release-guard deployment policy ID mismatch")
    _require(policy.get("name") == RELEASE_GUARD_TAG_PATTERN, "release-guard deployment tag pattern mismatch")
    _require(policy.get("type") == "tag", "release-guard deployment policy must target tags")


def _validate_release_guard_secret_scope(reader: Callable[[str, bool], Any | None]) -> None:
    """Prove the credential came from the protected environment, not fallback scope."""
    environment_path = f"/repos/{REPOSITORY}/environments/{RELEASE_GUARD_ENVIRONMENT}/secrets/{RELEASE_GUARD_SECRET}"
    environment_secret = reader(environment_path, False)
    _require(isinstance(environment_secret, dict), "release-guard environment secret metadata is missing")
    _require(
        environment_secret.get("name") == RELEASE_GUARD_SECRET,
        "release-guard environment secret name mismatch",
    )
    repository_secret = reader(f"/repos/{REPOSITORY}/actions/secrets/{RELEASE_GUARD_SECRET}", True)
    _require(
        repository_secret is None,
        "RELEASE_GUARD_READ_TOKEN must not exist at repository scope",
    )


def _github_release_inventory(reader: Callable[[str, bool], Any | None], *, tag: str) -> list[dict[str, Any]]:
    """Scan the bounded inventory while retaining only same-tag collision rows."""
    matching: list[dict[str, Any]] = []
    for page in range(1, MAX_GITHUB_RELEASE_LIST_PAGES + 1):
        rows = reader(f"/repos/{REPOSITORY}/releases?per_page=100&page={page}", False)
        _require(isinstance(rows, list), "GitHub release inventory page must be an array")
        _require(len(rows) <= 100, "GitHub release inventory page exceeds the requested bound")
        _require(all(isinstance(row, dict) for row in rows), "GitHub release inventory row must be an object")
        matching.extend(row for row in rows if row.get("tag_name") == tag)
        _require(len(matching) <= 1, "GitHub release inventory contains duplicate same-tag releases")
        if len(rows) < 100:
            return matching
    raise ReleaseError(
        f"GitHub release inventory exceeds the fail-closed {MAX_GITHUB_RELEASE_LIST_PAGES * 100}-release bound"
    )


def _reconcile_github_release(
    *,
    tag: str,
    release_by_tag: Any | None,
    inventory: list[dict[str, Any]],
) -> dict[str, Any] | None:
    matching = [row for row in inventory if row.get("tag_name") == tag]
    _require(len(matching) <= 1, "GitHub release inventory contains duplicate same-tag releases")
    if release_by_tag is None:
        if not matching:
            return None
        _require(matching[0].get("draft") is True, "GitHub release API views disagree for a published release")
        return matching[0]

    _require(isinstance(release_by_tag, dict), "GitHub release response must be an object")
    _require(len(matching) == 1, "GitHub release API views disagree for the release tag")
    release_id = release_by_tag.get("id")
    _require(
        type(release_id) is int and matching[0].get("id") == release_id,
        "GitHub release API views disagree for the release ID",
    )
    return release_by_tag


def _release_asset_payloads(bundle: Path, manifest: dict[str, Any]) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    for record in manifest["files"]:
        role = record["role"]
        limit = MAX_JSON_SIZE if role == "sbom" else MAX_ARCHIVE_SIZE
        payloads[record["filename"]] = _read_bounded_regular_file(
            bundle / record["filename"], label=f"GitHub release {role}", max_bytes=limit
        )
    payloads[MANIFEST_NAME] = _read_bounded_regular_file(
        bundle / MANIFEST_NAME, label="GitHub release manifest", max_bytes=MAX_JSON_SIZE
    )
    _require(len(payloads) == 4, "GitHub release asset set must contain exactly four files")
    return payloads


def _verify_build_attestations(bundle: Path, manifest: dict[str, Any]) -> None:
    payloads = _release_asset_payloads(bundle, manifest)
    for filename in sorted(payloads):
        _run_github_cli(
            [
                "attestation",
                "verify",
                str(bundle / filename),
                "--repo",
                REPOSITORY,
                "--signer-workflow",
                GITHUB_RELEASE_SIGNER_WORKFLOW,
                "--signer-digest",
                manifest["source"]["sha"],
                "--source-ref",
                f"refs/tags/{manifest['tag']}",
                "--source-digest",
                manifest["source"]["sha"],
                "--deny-self-hosted-runners",
            ],
            timeout=120,
        )


def _verify_immutable_release_attestation(bundle: Path, manifest: dict[str, Any]) -> None:
    _run_github_cli(["release", "verify", manifest["tag"], "--repo", REPOSITORY], timeout=120)
    for filename in sorted(_release_asset_payloads(bundle, manifest)):
        _run_github_cli(
            [
                "release",
                "verify-asset",
                manifest["tag"],
                str(bundle / filename),
                "--repo",
                REPOSITORY,
            ],
            timeout=120,
        )


def _remote_github_release_state(
    bundle: Path,
    *,
    expected_source: dict[str, Any],
    required_state: str = "recoverable",
    details: dict[str, int | str] | None = None,
    fetch_json: Callable[[str, bool], Any | None] | None = None,
    fetch_bytes: Callable[[str], bytes] | None = None,
    verify_build_attestations: Callable[[Path, dict[str, Any]], None] = _verify_build_attestations,
    verify_release_attestation: Callable[[Path, dict[str, Any]], None] = _verify_immutable_release_attestation,
    environ: dict[str, str] | None = None,
) -> str:
    _require(
        required_state in {"recoverable", "draft", "immutable"},
        "invalid required GitHub release state",
    )
    if details is not None:
        details.clear()
    manifest = verify_bundle(bundle, expected_source=expected_source)
    env = os.environ if environ is None else environ
    token = _github_token(env)
    reader = fetch_json or (lambda path, missing: _github_api_json(path, missing, token=token))

    # Bind the remote annotated tag before touching the Releases API.  The tag
    # object's SHA and its direct commit target are both part of the manifest.
    source = {**expected_source, "version": manifest["version"], "tag": manifest["tag"]}
    _validate_remote_annotated_tag(source, reader)
    release_guard_token: str | None = None
    if fetch_json is None:
        release_guard_token = _immutable_releases_token(env)

        def authenticated_release_reader(path: str, missing: bool) -> Any | None:
            return _github_api_json(path, missing, token=release_guard_token)

        release_reader = authenticated_release_reader
    else:
        release_reader = reader
    _validate_release_guard_identity(release_reader)
    _validate_release_guard_environment(release_reader)
    _validate_release_guard_secret_scope(release_reader)
    immutable_settings = release_reader(f"/repos/{REPOSITORY}/immutable-releases", True)
    _require(isinstance(immutable_settings, dict), "GitHub immutable releases are not enabled")
    _require(immutable_settings.get("enabled") is True, "GitHub immutable releases are not enabled")
    _require(
        type(immutable_settings.get("enforced_by_owner")) is bool,
        "GitHub immutable-release settings response is malformed",
    )
    verify_build_attestations(bundle, manifest)

    release_by_tag = release_reader(f"/repos/{REPOSITORY}/releases/tags/{manifest['tag']}", True)
    inventory = _github_release_inventory(release_reader, tag=manifest["tag"])
    release = _reconcile_github_release(
        tag=manifest["tag"],
        release_by_tag=release_by_tag,
        inventory=inventory,
    )
    if release is None:
        _require(required_state == "recoverable", "GitHub release is missing")
        return "missing"
    release_id = release.get("id")
    _require(
        type(release_id) is int and 0 < release_id <= MAX_GITHUB_EXPRESSION_INTEGER,
        "GitHub release ID is invalid",
    )
    if details is not None:
        details["release_id"] = release_id
    _require(release.get("tag_name") == manifest["tag"], "GitHub release tag mismatch")
    _require(release.get("name") == _release_name(manifest["version"]), "GitHub release name mismatch")
    _require(release.get("body") == _release_body(manifest["version"]), "GitHub release body mismatch")
    _require(release.get("prerelease") is False, "GitHub release must not be a prerelease")
    draft_state = release.get("draft")
    if draft_state is True:
        _require(required_state != "immutable", "GitHub release is not the expected immutable release")
        _require(release.get("immutable") is False, "draft GitHub release unexpectedly reports immutable state")
        _require(release.get("published_at") is None, "draft GitHub release already has a publication timestamp")
        result_state = "draft_exact"
    elif draft_state is False:
        _require(required_state != "draft", "GitHub release is not the expected draft")
        _require(release.get("immutable") is True, "existing GitHub release is mutable")
        _require(isinstance(release.get("published_at"), str) and release["published_at"], "release is not published")
        result_state = "exact"
    else:
        raise ReleaseError("GitHub release draft state is malformed")

    payloads = _release_asset_payloads(bundle, manifest)
    assets = release.get("assets")
    _require(isinstance(assets, list), "GitHub release asset inventory is missing")
    _require(all(isinstance(asset, dict) for asset in assets), "GitHub release asset row must be an object")
    names = [asset.get("name") for asset in assets]
    _require(
        all(isinstance(name, str) for name in names) and len(names) == len(set(names)) and set(names) == set(payloads),
        "GitHub release has missing, duplicate, or extra assets",
    )
    asset_ids: set[int] = set()
    roles_by_filename = {record["filename"]: record["role"] for record in manifest["files"]}
    roles_by_filename[MANIFEST_NAME] = "manifest"
    for asset in assets:
        filename = _safe_bundle_filename(asset["name"])
        payload = payloads[filename]
        asset_id = asset.get("id")
        _require(
            type(asset_id) is int and 0 < asset_id <= MAX_GITHUB_EXPRESSION_INTEGER and asset_id not in asset_ids,
            "GitHub release asset ID drift",
        )
        asset_ids.add(asset_id)
        _require(asset.get("state") == "uploaded", f"GitHub release asset is not uploaded: {filename}")
        _require(
            asset.get("content_type") == "application/octet-stream",
            f"GitHub release asset content type mismatch: {filename}",
        )
        _require(asset.get("size") == len(payload), f"GitHub release asset size mismatch: {filename}")
        asset_digest = f"sha256:{hashlib.sha256(payload).hexdigest()}"
        _require(
            asset.get("digest") == asset_digest,
            f"GitHub release asset digest mismatch: {filename}",
        )
        expected_url = f"{REPOSITORY_URL}/releases/download/{manifest['tag']}/{filename}"
        url = asset.get("browser_download_url")
        _require(url == expected_url, f"GitHub release asset URL mismatch: {filename}")
        api_url = asset.get("url")
        expected_api_url = f"https://api.github.com/repos/{REPOSITORY}/releases/assets/{asset_id}"
        _require(api_url == expected_api_url, f"GitHub release asset API URL mismatch: {filename}")
        if fetch_bytes is not None:
            remote = fetch_bytes(url)
        else:
            _require(release_guard_token is not None, "authenticated release asset reader is unavailable")
            remote = _fetch_github_release_asset(
                asset_id,
                token=release_guard_token,
                max_bytes=len(payload),
            )
        _require(isinstance(remote, bytes), f"GitHub release asset payload is not bytes: {filename}")
        _require(remote == payload, f"GitHub release exact-byte mismatch: {filename}")
        if details is not None:
            role = roles_by_filename[filename]
            details[f"{role}_asset_id"] = asset_id
            details[f"{role}_asset_digest"] = asset_digest
            details[f"{role}_asset_size"] = len(payload)
    if result_state == "exact":
        verify_release_attestation(bundle, manifest)
    return result_state


def github_release_state(
    bundle: Path,
    *,
    expected_source: dict[str, Any],
    require_exact: bool,
    require_draft_exact: bool,
    wait_seconds: int,
    details: dict[str, int | str] | None = None,
) -> str:
    _require(not (require_exact and require_draft_exact), "choose only one required GitHub release state")
    required_state = "draft" if require_draft_exact else "immutable" if require_exact else "recoverable"
    expected_result = "draft_exact" if require_draft_exact else "exact"
    deadline = time.monotonic() + wait_seconds
    last_error: ReleaseError | None = None
    while True:
        try:
            state = _remote_github_release_state(
                bundle,
                expected_source=expected_source,
                required_state=required_state,
                details=details,
            )
            if state == expected_result or not (require_exact or require_draft_exact):
                return state
            last_error = ReleaseError(f"GitHub release state is {state}; expected {expected_result}")
        except ReleaseError as exc:
            if not (require_exact or require_draft_exact):
                raise
            last_error = exc
        if time.monotonic() >= deadline:
            label = "byte-exact draft" if require_draft_exact else "byte-exact immutable release"
            raise ReleaseError(f"GitHub release did not become a {label}: {last_error}") from last_error
        time.sleep(min(10, max(1, int(deadline - time.monotonic()))))


def _write_github_artifact_output(
    artifact_id: str,
    artifact_digest: str,
    source: dict[str, Any],
) -> None:
    _append_github_output(
        [
            f"artifact_id={artifact_id}",
            f"artifact_digest={artifact_digest}",
            f"source_sha={source['sha']}",
            f"tag={source['tag']}",
            f"tag_object_sha={source['tag_object_sha']}",
        ]
    )


def _write_github_release_output(state: str, *, details: dict[str, int | str] | None = None) -> None:
    _require(state in {"missing", "draft_exact", "exact"}, "invalid GitHub release state")
    lines = [
        f"state={state}",
        f"release_required={'true' if state == 'missing' else 'false'}",
        f"publish_required={'true' if state == 'draft_exact' else 'false'}",
    ]
    if state == "draft_exact":
        _require(details is not None, "draft release details are missing")
        release_id = details.get("release_id")
        _require(
            type(release_id) is int and 0 < release_id <= MAX_GITHUB_EXPRESSION_INTEGER,
            "draft release ID is missing",
        )
        lines.append(f"release_id={release_id}")
        for role in ("wheel", "sdist", "sbom", "manifest"):
            asset_id = details.get(f"{role}_asset_id")
            asset_digest = details.get(f"{role}_asset_digest")
            asset_size = details.get(f"{role}_asset_size")
            _require(
                type(asset_id) is int and 0 < asset_id <= MAX_GITHUB_EXPRESSION_INTEGER,
                f"draft {role} asset ID is missing",
            )
            _require(
                isinstance(asset_digest, str)
                and asset_digest.startswith("sha256:")
                and HASH_RE.fullmatch(asset_digest.removeprefix("sha256:")) is not None,
                f"draft {role} asset digest is malformed",
            )
            _require(type(asset_size) is int and 0 < asset_size <= MAX_ARCHIVE_SIZE, f"draft {role} size is invalid")
            if role in {"sbom", "manifest"}:
                _require(asset_size <= MAX_JSON_SIZE, f"draft {role} exceeds the JSON size limit")
            lines.extend(
                (
                    f"{role}_asset_id={asset_id}",
                    f"{role}_asset_digest={asset_digest}",
                    f"{role}_asset_size={asset_size}",
                )
            )
    _append_github_output(lines)


def _venv_python(directory: Path) -> Path:
    return directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _smoke_environment() -> dict[str, str]:
    env = os.environ.copy()
    for name in tuple(env):
        normalized_name = name.upper()
        if normalized_name.startswith(("PIP_", "UV_")) or normalized_name in {
            "ALL_PROXY",
            "CURL_CA_BUNDLE",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "PYTHONHOME",
            "PYTHONPATH",
            "REQUESTS_CA_BUNDLE",
            "SSL_CERT_DIR",
            "SSL_CERT_FILE",
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


def _isolated_smoke_runtime_environment(smoke_root: Path, environment: dict[str, str]) -> dict[str, str]:
    """Bind user, config, cache, state, and temporary writes to one smoke root."""
    runtime_root = smoke_root / "isolated-runtime"
    home = runtime_root / "home"
    directories = {
        "home": home,
        "config": runtime_root / "config",
        "cache": runtime_root / "cache",
        "data": runtime_root / "data",
        "state": runtime_root / "state",
        "runtime": runtime_root / "run",
        # Rust's Windows known-folder implementation derives these beneath
        # USERPROFILE and requires the directories to exist. Keeping that
        # native layout makes parser caches isolated without breaking Roam.
        "appdata": home / "AppData" / "Roaming" if os.name == "nt" else runtime_root / "appdata",
        "local_appdata": home / "AppData" / "Local" if os.name == "nt" else runtime_root / "local-appdata",
        "temp": runtime_root / "temp",
    }
    for label, directory in directories.items():
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        _validated_real_directory(directory, label=f"smoke {label}")

    isolated = environment.copy()
    for name in tuple(isolated):
        normalized = name.upper()
        if normalized.startswith(("CLAUDE_", "CODEX_", "COMPILE_", "GIT_", "ROAM_", "XDG_")) or normalized in {
            "CONDA_PREFIX",
            "VIRTUAL_ENV",
        }:
            isolated.pop(name, None)
    isolated.update(
        {
            "APPDATA": str(directories["appdata"]),
            "CLAUDE_CONFIG_DIR": str(home / ".claude"),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "HOME": str(home),
            "LOCALAPPDATA": str(directories["local_appdata"]),
            "TEMP": str(directories["temp"]),
            "TMP": str(directories["temp"]),
            "TMPDIR": str(directories["temp"]),
            "USERPROFILE": str(home),
            "XDG_CACHE_HOME": str(directories["cache"]),
            "XDG_CONFIG_HOME": str(directories["config"]),
            "XDG_DATA_HOME": str(directories["data"]),
            "XDG_RUNTIME_DIR": str(directories["runtime"]),
            "XDG_STATE_HOME": str(directories["state"]),
        }
    )
    isolated.pop("HOMEDRIVE", None)
    isolated.pop("HOMEPATH", None)
    if os.name == "nt":
        home_drive, home_path = os.path.splitdrive(str(home))
        _require(bool(home_drive and home_path), "isolated Windows smoke HOME is not absolute")
        isolated["HOMEDRIVE"] = home_drive
        isolated["HOMEPATH"] = home_path
    return isolated


def _run_required_roam_protocol_smoke(
    compile_executable: Path,
    smoke_root: Path,
    environment: dict[str, str],
) -> None:
    """Exercise installed Roam hook production, readiness, and Verify protocol."""
    project = smoke_root / "roam-protocol-project"
    project.mkdir(mode=0o700)
    source = project / "protocol_smoke.py"
    source.write_text(
        "def protocol_smoke(value: int) -> int:\n    return value + 1\n",
        encoding="utf-8",
        newline="\n",
    )

    runtime_environment = _isolated_smoke_runtime_environment(smoke_root, environment)
    existing_path = runtime_environment.get("PATH", "")
    runtime_environment["PATH"] = str(compile_executable.parent)
    if existing_path:
        runtime_environment["PATH"] += os.pathsep + existing_path

    git_executable = shutil.which("git", path=runtime_environment["PATH"])
    _require(
        isinstance(git_executable, str) and Path(git_executable).is_absolute(),
        "resolved smoke requires an absolute Git executable",
    )
    _run(
        [git_executable, "-c", "init.defaultBranch=main", "init", "--quiet"],
        cwd=project,
        env=runtime_environment,
        timeout=60,
    )
    _run(
        [git_executable, "add", "--", source.name],
        cwd=project,
        env=runtime_environment,
        timeout=60,
    )
    _run(
        [str(compile_executable), "init"],
        cwd=project,
        env=runtime_environment,
        timeout=180,
    )
    wire_output = _run(
        [str(compile_executable), "wire", "claude"],
        cwd=project,
        env=runtime_environment,
        timeout=180,
    )
    _require(
        isinstance(wire_output, str) and "Traceback" not in wire_output,
        "resolved roam-code did not produce Claude hooks cleanly",
    )
    doctor_output = _run(
        [str(compile_executable), "doctor"],
        cwd=project,
        env=runtime_environment,
        timeout=60,
    )
    normalized_doctor = doctor_output.replace("\r\n", "\n") if isinstance(doctor_output, str) else ""
    _require(
        re.search(r"(?m)^claude\s+:\s+wired \(project\)\s*$", normalized_doctor) is not None
        and re.search(r"(?m)^VERDICT: ready\s*$", normalized_doctor) is not None
        and "Traceback" not in normalized_doctor,
        f"{REQUIRED_CLAUDE_HOOK_READINESS} failed",
    )
    output = _run(
        [
            str(compile_executable),
            "verify",
            "--threshold",
            "0",
            "--",
            source.name,
        ],
        cwd=project,
        env=runtime_environment,
        timeout=180,
    )
    _require(
        isinstance(output, str)
        and re.match(r"\AVERDICT: (?:PASS|WARN) \(score \d+/100\)", output) is not None
        and "Traceback" not in output,
        f"resolved roam-code did not complete {REQUIRED_ROAM_VERIFY_PROTOCOL}",
    )


def _run_install_smoke(artifact: Path, version: str, mode: str, temp_root: Path) -> None:
    environment = _smoke_environment()
    with tempfile.TemporaryDirectory(prefix=f"smoke-{artifact.suffix.lstrip('.')}-", dir=temp_root) as temporary:
        environment_root = Path(temporary) / "venv"
        venv.EnvBuilder(with_pip=True, clear=True, symlinks=False).create(environment_root)
        python = _venv_python(environment_root)
        common = [
            str(python),
            "-m",
            "pip",
            "install",
            "--isolated",
            "--disable-pip-version-check",
            "--index-url",
            "https://pypi.org/simple",
            "--no-cache-dir",
            "--no-compile",
        ]
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
        backend_assertion = (
            "import importlib.metadata as m; "
            "assert {n: m.version(n) for n in ('packaging', 'pip', 'setuptools', 'wheel')} == "
            "{'packaging': '26.2', 'pip': '26.1.2', 'setuptools': '83.0.0', 'wheel': '0.47.0'}"
        )
        _run([str(python), "-I", "-c", backend_assertion], cwd=temp_root, env=environment, timeout=60)
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
        if mode == "resolve":
            compile_executable = scripts / ("compile.exe" if os.name == "nt" else "compile")
            _run_required_roam_protocol_smoke(compile_executable, Path(temporary), environment)


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
    release_actions = re.findall(r"(?m)^\s+uses:\s*([^\s#]+)", release)
    action_inventory = {action: release_actions.count(action) for action in set(release_actions)}
    if action_inventory != RELEASE_ACTION_INVENTORY:
        problems.append(
            f"release.yml exact action inventory drift: expected {RELEASE_ACTION_INVENTORY}; got {action_inventory}"
        )
    required_fragments = (
        "github.repository == 'Cranot/compile-code'",
        "github.actor == 'Cranot'",
        "environment:",
        "name: pypi",
        "github.triggering_actor == 'Cranot'",
        "id-token: write",
        "attestations: write",
        "skip-existing: false",
        "attestations: true",
        "python scripts/release_artifacts.py source",
        "python scripts/release_artifacts.py audit-locks",
        "verify --bundle release-bundle --dist pypi-dist --github-source",
        "--github-source --wait-seconds 120 --github-output",
        "--github-source --require-exact",
        "github-artifact-state",
        "github-release-state",
        "needs: [build, prepublish, github_release_preflight]",
        "needs: [build, prepublish, github_release_preflight, github_release_draft_verify]",
        "needs: [github_release_preflight, github_release_draft_verify, postpublish]",
        "name: release-guard",
        "needs.github_release_preflight.outputs.bundle_artifact_id == needs.build.outputs.bundle_artifact_id",
        "needs.github_release_preflight.outputs.bundle_artifact_digest == needs.build.outputs.bundle_artifact_digest",
        "secrets.RELEASE_GUARD_READ_TOKEN",
        "octokit/request-action@b91aabaa861c777dcdb14e2387e30eddf04619ae",
        "route: GET /repos/{owner}/{repo}/git/tags/{tag_sha}",
        "ncipollo/release-action@339a81892b84b4eeb0f6e744e4574d79d0d9b8dd",
        'draft: "true"',
        'immutableCreate: "false"',
        "artifactContentType: application/octet-stream",
        'artifactErrorsFailBuild: "true"',
        'allowUpdates: "false"',
        'removeArtifacts: "false"',
        'replacesArtifacts: "false"',
        'skipIfReleaseExists: "true"',
        "install-github-cli --github-output",
        "COMPILE_GITHUB_CLI: ${{ steps.github_cli.outputs.github_cli_path }}",
        "--require-draft-exact --wait-seconds 120 --github-output",
        "route: PATCH /repos/{owner}/{repo}/releases/{release_id}",
        "--require-exact --wait-seconds 300",
    )
    for fragment in required_fragments:
        if fragment not in release:
            problems.append(f"release.yml missing hardened release fragment: {fragment}")
    if "workflow_dispatch:" in release or "inputs:" in release:
        problems.append("release.yml may not accept user-controlled release inputs")
    build_match = re.search(r"(?ms)^  build:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)", release)
    if not build_match:
        problems.append("release build job missing")
    else:
        build_job = build_match.group(1)
        if re.search(r"(?m)^    if:", build_job):
            problems.append("release build job may not silently skip an unauthorized tag event")
        source_guard = build_job.find("python scripts/release_artifacts.py source")
        lock_audit = build_job.find("python scripts/release_artifacts.py audit-locks")
        tool_install = build_job.find("python -m pip install")
        if source_guard < 0 or not (source_guard < lock_audit < tool_install):
            problems.append("release build must validate source before dependency audit and tool installation")
        if build_job.count("python scripts/release_artifacts.py source") != 1:
            problems.append("release build must run exactly one early source guard")
    if release.find("python scripts/release_artifacts.py audit-locks") > release.find("python -m pip install"):
        problems.append("release.yml must audit locked graphs before installing release tooling")
    secret_names = set(re.findall(r"secrets\.([A-Z0-9_]+)", release))
    if secret_names != {"RELEASE_GUARD_READ_TOKEN"}:
        problems.append("release.yml secret inventory must contain only the read-only owner release guard token")
    if release.count("secrets.RELEASE_GUARD_READ_TOKEN") != 3:
        problems.append("release.yml must pass the read-only owner token only to the three GitHub verifier steps")
    if release.count("name: release-guard") != 3:
        problems.append("release.yml must bind all three owner-token verifier jobs to release-guard")
    if release.count("install-github-cli --github-output") != 3:
        problems.append("release.yml must install the exact GitHub CLI in all three verifier jobs")
    if release.count("COMPILE_GITHUB_CLI: ${{ steps.github_cli.outputs.github_cli_path }}") != 3:
        problems.append("release.yml must pass only the controlled GitHub CLI path to all verifier commands")
    if "create-github-app-token" in release:
        problems.append("release.yml may not use an installation identity that can hide draft releases")
    if release.count("id-token: write") != 2 or release.count("attestations: write") != 1:
        problems.append("release.yml elevated permission inventory drift")
    if release.count("fetch-depth: 0") != 6:
        problems.append("release.yml must fetch annotated tag objects in all six source-verifying jobs")
    if release.count("contents: write") != 2:
        problems.append("release.yml must isolate draft staging from the exact-ID publication boundary")
    for forbidden_permission in ("actions: write", "packages: write", "write-all"):
        if forbidden_permission in release:
            problems.append(f"release.yml forbidden permission: {forbidden_permission}")
    if "continue-on-error:" in release:
        problems.append("release.yml may not suppress a release gate")
    publish_match = re.search(r"(?ms)^  publish:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)", release)
    if not publish_match or re.search(r"(?m)^\s+run:", publish_match.group(1)):
        problems.append("privileged publish job must contain no run steps")
    elif "actions/checkout@" in publish_match.group(1) or "actions/setup-python@" in publish_match.group(1):
        problems.append("privileged publish job may not check out or execute source")
    else:
        publish_job = publish_match.group(1)
        for binding in (
            "github.ref == 'refs/tags/v0.2.0'",
            "needs.prepublish.outputs.publish_required == 'true'",
            "needs.github_release_preflight.outputs.source_sha == github.sha",
            "needs.github_release_preflight.outputs.tag == 'v0.2.0'",
            "needs.github_release_preflight.outputs.release_state == 'exact'",
            "needs.github_release_draft_verify.outputs.state == 'draft_exact'",
            "needs.github_release_draft_verify.result == 'success'",
            "artifact-ids: ${{ needs.build.outputs.dist_artifact_id }}",
            "digest-mismatch: error",
            "skip-existing: false",
            "attestations: true",
        ):
            if binding not in publish_job:
                problems.append(f"PyPI publication binding drift: {binding}")
    privileged_jobs: dict[str, str] = {}
    for job_name in ("github_release_stage", "github_release_publish"):
        match = re.search(rf"(?ms)^  {job_name}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)", release)
        if not match:
            problems.append(f"privileged GitHub Release job missing: {job_name}")
            continue
        job = match.group(1)
        privileged_jobs[job_name] = job
        if re.search(r"(?m)^\s+run:", job):
            problems.append(f"{job_name} must contain no run steps")
        if "actions/checkout@" in job or "actions/setup-python@" in job:
            problems.append(f"{job_name} may not check out or execute source")
        if job.count("contents: write") != 1 or "id-token: write" in job:
            problems.append(f"{job_name} permission inventory drift")
        if "RELEASE_GUARD_READ_TOKEN" in job or "IMMUTABLE_RELEASES_TOKEN" in job:
            problems.append(f"{job_name} must not receive the release guard credential")
        if "name: release-guard" in job:
            problems.append(f"{job_name} must not cross the read-token release-guard environment")
        if job.count("route: GET /repos/{owner}/{repo}/git/tags/{tag_sha}") != 1:
            problems.append(f"{job_name} must URL-bind the annotated tag SHA as an API parameter")
        for binding in (
            "github.ref == 'refs/tags/v0.2.0'",
            "needs.github_release_preflight.outputs.source_sha == github.sha",
            "needs.github_release_preflight.outputs.tag == 'v0.2.0'",
            "fromJSON(steps.remote_tag_ref.outputs.data).object.type == 'tag'",
            "fromJSON(steps.remote_tag_ref.outputs.data).object.sha == needs.github_release_preflight.outputs.tag_object_sha",
            "fromJSON(steps.remote_tag_object.outputs.data).object.type == 'commit'",
            "fromJSON(steps.remote_tag_object.outputs.data).object.sha == github.sha",
        ):
            if binding not in job:
                problems.append(f"{job_name} tag binding drift: {binding}")

    for job_name in ("github_release_preflight", "github_release_draft_verify", "github_release_postverify"):
        match = re.search(rf"(?ms)^  {job_name}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)", release)
        if not match:
            problems.append(f"release-guard verifier job missing: {job_name}")
            continue
        job = match.group(1)
        if job.count("name: release-guard") != 1:
            problems.append(f"{job_name} must use exactly one release-guard environment")
        if job.count("secrets.RELEASE_GUARD_READ_TOKEN") != 1:
            problems.append(f"{job_name} must receive exactly one environment-scoped release guard secret")
        if job.count("install-github-cli --github-output") != 1:
            problems.append(f"{job_name} must install exactly one checksum-pinned GitHub CLI")
        if job.count("COMPILE_GITHUB_CLI: ${{ steps.github_cli.outputs.github_cli_path }}") != 1:
            problems.append(f"{job_name} must invoke gh only through its controlled absolute path")

    github_publish = privileged_jobs.get("github_release_publish", "")
    if github_publish:
        if github_publish.count("octokit/request-action@b91aabaa861c777dcdb14e2387e30eddf04619ae") != 8:
            problems.append("publication must perform seven exact reads and one exact-ID PATCH")
        mutation_routes = re.findall(r"(?m)^\s+route:\s+(POST|PATCH|PUT|DELETE)\b", github_publish)
        if mutation_routes != ["PATCH"]:
            problems.append("publication must perform exactly one PATCH and no create/delete request")
        for binding in (
            "route: GET /repos/{owner}/{repo}/releases/assets/{asset_id}",
            "fromJSON(steps.remote_wheel.outputs.data).id == fromJSON(needs.github_release_draft_verify.outputs.wheel_asset_id)",
            "fromJSON(steps.remote_sdist.outputs.data).id == fromJSON(needs.github_release_draft_verify.outputs.sdist_asset_id)",
            "fromJSON(steps.remote_sbom.outputs.data).id == fromJSON(needs.github_release_draft_verify.outputs.sbom_asset_id)",
            "fromJSON(steps.remote_manifest.outputs.data).id == fromJSON(needs.github_release_draft_verify.outputs.manifest_asset_id)",
            "fromJSON(steps.remote_draft.outputs.data).id == fromJSON(needs.github_release_draft_verify.outputs.release_id)",
            "fromJSON(steps.remote_draft.outputs.data).draft == true",
            "fromJSON(steps.remote_draft.outputs.data).immutable == false",
            "fromJSON(steps.remote_draft.outputs.data).published_at == null",
            "fromJSON(steps.remote_draft.outputs.data).assets[3] != null",
            "fromJSON(steps.remote_draft.outputs.data).assets[4] == null",
            "needs.postpublish.result == 'success'",
            "tag_name: v0.2.0",
            "name: compile-code v0.2.0",
            "prerelease: false",
        ):
            if binding not in github_publish:
                problems.append(f"publication draft binding drift: {binding}")
        if github_publish.count("route: GET /repos/{owner}/{repo}/releases/assets/{asset_id}") != 4:
            problems.append("publication must re-read each of the four byte-verified asset IDs")

    github_stage = privileged_jobs.get("github_release_stage", "")
    if github_stage:
        if "needs: [build, prepublish, github_release_preflight]" not in github_stage or "postpublish" in github_stage:
            problems.append("draft staging must depend on preflight and precede PyPI post-verification")
        if github_stage.count("octokit/request-action@b91aabaa861c777dcdb14e2387e30eddf04619ae") != 2:
            problems.append("draft staging must re-read exactly the tag ref and annotated tag object")
        if re.search(r"(?m)^\s+route:\s+(?:POST|PATCH|PUT|DELETE)\b", github_stage):
            problems.append("draft staging tag guard may perform only GET requests outside the pinned staging action")
        expected_assets = (
            "compile_code-0.2.0-py3-none-any.whl",
            "compile_code-0.2.0.tar.gz",
            "compile_code-0.2.0.cdx.json",
        )
        for asset in expected_assets:
            if github_stage.count(asset) != 1:
                problems.append(f"GitHub Release closed asset inventory drift: {asset}")
        if github_stage.count(MANIFEST_NAME) != 2:
            problems.append("GitHub Release manifest must appear once in the body and once in the closed asset set")

    postpublish_match = re.search(r"(?ms)^  postpublish:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)", release)
    if not postpublish_match:
        problems.append("PyPI post-verification job missing")
    else:
        postpublish_job = postpublish_match.group(1)
        for binding in (
            "needs: [build, prepublish, github_release_preflight, github_release_draft_verify, publish]",
            "needs.prepublish.outputs.publish_required == 'false'",
            "needs.github_release_draft_verify.outputs.state == 'draft_exact'",
        ):
            if binding not in postpublish_job:
                problems.append(f"PyPI post-verification ordering drift: {binding}")

    postverify_match = re.search(r"(?ms)^  github_release_postverify:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)", release)
    if not postverify_match:
        problems.append("terminal GitHub Release verifier job missing")
    else:
        postverify_job = postverify_match.group(1)
        for binding in (
            "always() && needs.build.result == 'success'",
            "needs.github_release_preflight.result == 'success'",
            "artifact-ids: ${{ needs.build.outputs.dist_artifact_id }}",
            "pypi-state --bundle release-bundle --dist pypi-dist",
            "--github-source --require-exact --wait-seconds 300",
            "--require-exact --wait-seconds 300",
        ):
            if binding not in postverify_job:
                problems.append(f"terminal GitHub Release verification drift: {binding}")
    return problems


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("assert-runner", help="Prove the builder has no root/OIDC/publication credentials.")

    github_cli = subparsers.add_parser(
        "install-github-cli",
        help="Install and verify the exact reviewed GitHub CLI under RUNNER_TEMP.",
    )
    github_cli.add_argument(
        "--github-output",
        action="store_true",
        help="Append the controlled absolute executable path to GITHUB_OUTPUT.",
    )

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

    subparsers.add_parser(
        "audit-locks",
        help="Audit the exact build, smoke, and tooling lock rows without resolving dependencies.",
    )

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

    artifact = subparsers.add_parser(
        "github-artifact-state", help="Bind one Actions artifact ID and digest to this release run and source."
    )
    artifact.add_argument("--artifact-id", required=True)
    artifact.add_argument("--artifact-digest", required=True)
    artifact.add_argument("--github-output", action="store_true")

    github_release = subparsers.add_parser(
        "github-release-state", help="Require missing, exact resumable-draft, or exact immutable release state."
    )
    github_release.add_argument("--bundle", type=Path, required=True)
    github_release.add_argument("--require-exact", action="store_true")
    github_release.add_argument("--require-draft-exact", action="store_true")
    github_release.add_argument("--wait-seconds", type=int, default=0)
    github_release.add_argument("--github-output", action="store_true")

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
        elif args.command == "install-github-cli":
            executable = install_github_cli()
            print(f"GitHub CLI: verified {GITHUB_CLI_VERSION} at {executable}")
            if args.github_output:
                _append_github_output([f"github_cli_path={executable}"])
        elif args.command == "source":
            context = source_context_from_github(ROOT)
            print(json.dumps(context, sort_keys=True))
            if args.github_output:
                _append_github_output(
                    [
                        f"{key}={context[key]}"
                        for key in ("version", "tag", "sha", "tag_object_sha", "source_date_epoch")
                    ]
                )
        elif args.command == "build":
            context = source_context_from_github(ROOT)
            manifest = build_release(
                ROOT,
                Path(os.path.abspath(args.bundle)),
                Path(os.path.abspath(args.dist)),
                context,
            )
            print(f"release build: deterministic {manifest['tag']} at {manifest['source']['sha']}")
        elif args.command == "verify":
            expected_source = source_context_from_github(ROOT, allow_untracked=True) if args.github_source else None
            manifest = verify_bundle(
                Path(os.path.abspath(args.bundle)),
                dist=Path(os.path.abspath(args.dist)) if args.dist else None,
                expected_source=expected_source,
            )
            print(f"release bundle: verified {manifest['tag']} at {manifest['source']['sha']}")
        elif args.command == "twine-check":
            twine_check(Path(os.path.abspath(args.bundle)))
            print("twine check: PASS")
        elif args.command == "audit-locks":
            audited = audit_locked_requirements(ROOT)
            print(f"locked dependency audit: PASS ({audited} exact package versions; no resolution)")
        elif args.command == "pypi-state":
            _require(0 <= args.wait_seconds <= 600, "wait-seconds must be between 0 and 600")
            expected_source = source_context_from_github(ROOT, allow_untracked=True) if args.github_source else None
            state = pypi_state(
                Path(os.path.abspath(args.bundle)),
                Path(os.path.abspath(args.dist)),
                require_exact=args.require_exact,
                wait_seconds=args.wait_seconds,
                expected_source=expected_source,
            )
            print(f"PyPI state: {state}")
            if args.github_output:
                _write_github_output(state)
        elif args.command == "github-artifact-state":
            context = source_context_from_github(ROOT)
            verify_github_workflow_artifact(
                artifact_id=args.artifact_id,
                artifact_digest=args.artifact_digest,
                expected_source=context,
            )
            print(f"GitHub Actions artifact: exact ID {args.artifact_id} and digest {args.artifact_digest}")
            if args.github_output:
                _write_github_artifact_output(args.artifact_id, args.artifact_digest, context)
        elif args.command == "github-release-state":
            _require(0 <= args.wait_seconds <= 600, "wait-seconds must be between 0 and 600")
            context = source_context_from_github(ROOT, allow_untracked=True)
            details: dict[str, int | str] = {}
            state = github_release_state(
                Path(os.path.abspath(args.bundle)),
                expected_source=context,
                require_exact=args.require_exact,
                require_draft_exact=args.require_draft_exact,
                wait_seconds=args.wait_seconds,
                details=details,
            )
            print(f"GitHub Release state: {state}")
            if args.github_output:
                _write_github_release_output(state, details=details)
        elif args.command == "install-smoke":
            install_smoke(
                Path(os.path.abspath(args.bundle)),
                args.mode,
                Path(os.path.abspath(args.temp_root)),
            )
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
