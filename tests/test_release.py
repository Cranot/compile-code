from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest
import yaml

from scripts import check as prepush_check
from scripts import release_artifacts as release


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.2.0"
EPOCH = 1_700_000_000
SOURCE_SHA = "1" * 40
TAG_OBJECT_SHA = "a" * 40


def _source(*, sha: str = SOURCE_SHA) -> dict[str, object]:
    return {
        "repository": release.REPOSITORY_URL,
        "sha": sha,
        "tag": f"v{VERSION}",
        "tag_object_sha": TAG_OBJECT_SHA,
        "source_date_epoch": EPOCH,
        "version": VERSION,
    }


def _metadata() -> bytes:
    return (
        "Metadata-Version: 2.4\n"
        "Name: compile-code\n"
        f"Version: {VERSION}\n"
        "Requires-Python: >=3.10\n"
        "License-Expression: Apache-2.0\n"
        "License-File: LICENSE\n"
        "Provides-Extra: dev\n"
        "Requires-Dist: roam-code<14,>=13.10.0\n"
        "Requires-Dist: click>=8.0\n"
        'Requires-Dist: pytest==9.1.1; extra == "dev"\n'
        'Requires-Dist: PyYAML==6.0.3; extra == "dev"\n'
        'Requires-Dist: ruff==0.15.22; extra == "dev"\n'
        'Requires-Dist: zizmor==1.27.0; extra == "dev"\n'
        "\n"
    ).encode()


def _raw_wheel(path: Path, *, extra: dict[str, bytes] | None = None, reverse: bool = False) -> None:
    dist_info = f"compile_code-{VERSION}.dist-info"
    files = {
        "compile_code/__init__.py": (ROOT / "src" / "compile_code" / "__init__.py").read_bytes(),
        "compile_code/cli.py": (ROOT / "src" / "compile_code" / "cli.py").read_bytes(),
        f"{dist_info}/METADATA": _metadata(),
        f"{dist_info}/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"{dist_info}/entry_points.txt": (
            b"[console_scripts]\n"
            b"cmpl = compile_code.cli:cli\n"
            b"compile = compile_code.cli:cli\n"
            b"compile-code = compile_code.cli:cli\n"
        ),
        f"{dist_info}/licenses/LICENSE": (ROOT / "LICENSE").read_bytes(),
        f"{dist_info}/RECORD": b"",
        f"{dist_info}/top_level.txt": b"compile_code\n",
    }
    files.update(extra or {})
    entries = list(files.items())
    if reverse:
        entries.reverse()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=(2025, 1, 2, 3, 4, 6))
            archive.writestr(info, data)


def _raw_sdist(
    path: Path,
    *,
    extra: dict[str, bytes] | None = None,
    pyproject: bytes | None = None,
    reverse: bool = False,
    symlink: tuple[str, str] | None = None,
) -> None:
    root = f"compile_code-{VERSION}"
    files = {
        f"{root}/LICENSE": (ROOT / "LICENSE").read_bytes(),
        f"{root}/PKG-INFO": _metadata(),
        f"{root}/README.md": (ROOT / "README.md").read_bytes(),
        f"{root}/pyproject.toml": pyproject or (ROOT / "pyproject.toml").read_bytes(),
        f"{root}/src/compile_code/__init__.py": (ROOT / "src" / "compile_code" / "__init__.py").read_bytes(),
        f"{root}/src/compile_code/cli.py": (ROOT / "src" / "compile_code" / "cli.py").read_bytes(),
    }
    files.update(extra or {})
    entries = list(files.items())
    if reverse:
        entries.reverse()
    with tarfile.open(path, "w:gz") as archive:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1_600_000_000
            info.mode = 0o777
            archive.addfile(info, io.BytesIO(data))
        if symlink is not None:
            info = tarfile.TarInfo(symlink[0])
            info.type = tarfile.SYMTYPE
            info.linkname = symlink[1]
            archive.addfile(info)


def _bundle(tmp_path: Path, *, source: dict[str, object] | None = None) -> tuple[Path, Path]:
    source = source or _source()
    raw = tmp_path / "raw"
    bundle = tmp_path / "bundle"
    dist = tmp_path / "dist"
    raw.mkdir(parents=True)
    bundle.mkdir()
    dist.mkdir()
    raw_wheel = raw / release._expected_wheel_name(VERSION)
    raw_sdist = raw / release._expected_sdist_name(VERSION)
    _raw_wheel(raw_wheel)
    _raw_sdist(raw_sdist)
    wheel = bundle / raw_wheel.name
    sdist = bundle / raw_sdist.name
    release.normalize_wheel(raw_wheel, wheel, source)
    release.normalize_sdist(raw_sdist, sdist, source)
    shutil.copyfile(wheel, dist / wheel.name)
    shutil.copyfile(sdist, dist / sdist.name)
    sbom = bundle / release._expected_sbom_name(VERSION)
    dependencies = release._read_pyproject(ROOT)["project"]["dependencies"]
    sbom.write_bytes(
        release._sbom_bytes(
            version=VERSION,
            source=source,
            dependencies=dependencies,
            distributions=[wheel, sdist],
        )
    )
    (bundle / release.MANIFEST_NAME).write_bytes(release._manifest_bytes(source, [wheel, sdist, sbom]))
    return bundle, dist


def _manifest(bundle: Path) -> dict[str, object]:
    return json.loads((bundle / release.MANIFEST_NAME).read_text(encoding="utf-8"))


def _write_manifest(bundle: Path, document: dict[str, object]) -> None:
    (bundle / release.MANIFEST_NAME).write_bytes(release._canonical_json(document))


def _pypi_provenance(filename: str, sha256: str) -> dict[str, object]:
    statement = release._canonical_json(
        {
            "_type": release.IN_TOTO_STATEMENT_TYPE,
            "predicate": None,
            "predicateType": release.PYPI_PUBLISH_ATTESTATION_TYPE,
            "subject": [{"digest": {"sha256": sha256}, "name": filename}],
        }
    )
    return {
        "attestation_bundles": [
            {
                "attestations": [
                    {
                        "envelope": {
                            "signature": base64.b64encode(b"signature").decode("ascii"),
                            "statement": base64.b64encode(statement).decode("ascii"),
                        },
                        "verification_material": {
                            "certificate": base64.b64encode(b"certificate").decode("ascii"),
                            "transparency_entries": [{}],
                        },
                        "version": 1,
                    }
                ],
                "publisher": {
                    "claims": None,
                    "environment": "pypi",
                    "kind": "GitHub",
                    "repository": release.REPOSITORY,
                    "workflow": "release.yml",
                },
            }
        ],
        "version": 1,
    }


def _remote_project(
    bundle: Path, dist: Path
) -> tuple[dict[str, object], dict[str, bytes], dict[str, dict[str, object]]]:
    manifest = _manifest(bundle)
    rows = []
    payloads = {}
    provenances = {}
    for record in manifest["files"]:
        if record["role"] not in {"wheel", "sdist"}:
            continue
        filename = record["filename"]
        url = f"https://files.pythonhosted.org/packages/test/{filename}"
        payloads[url] = (dist / filename).read_bytes()
        provenances[filename] = _pypi_provenance(filename, record["hashes"]["sha256"])
        rows.append(
            {
                "digests": {"sha256": record["hashes"]["sha256"]},
                "filename": filename,
                "packagetype": "bdist_wheel" if record["role"] == "wheel" else "sdist",
                "size": record["size"],
                "url": url,
                "yanked": False,
            }
        )
    project = {"info": {"name": "compile-code"}, "releases": {VERSION: rows}}
    return project, payloads, provenances


def _github_environment() -> dict[str, str]:
    return {
        "GH_TOKEN": "g" * 40,
        "GITHUB_RUN_ID": "123456",
        "IMMUTABLE_RELEASES_TOKEN": "i" * 40,
    }


def _copy_release_locks(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    release_dir = root / "release"
    release_dir.mkdir(parents=True)
    for input_name, lock_name in release.LOCK_GRAPHS:
        shutil.copyfile(ROOT / "release" / input_name, release_dir / input_name)
        shutil.copyfile(ROOT / "release" / lock_name, release_dir / lock_name)
    return root


def _remote_github(
    bundle: Path,
    *,
    include_release: bool = True,
) -> tuple[dict[str, object], dict[str, bytes]]:
    manifest = _manifest(bundle)
    source = manifest["source"]
    tag = manifest["tag"]
    documents: dict[str, object] = {
        "/user": {"id": 1, "login": release.OWNER, "type": "User"},
        f"/repos/{release.REPOSITORY}/git/ref/tags/{tag}": {
            "ref": f"refs/tags/{tag}",
            "object": {"sha": source["tag_object_sha"], "type": "tag"},
        },
        f"/repos/{release.REPOSITORY}/git/tags/{source['tag_object_sha']}": {
            "object": {"sha": source["sha"], "type": "commit"},
            "sha": source["tag_object_sha"],
            "tag": tag,
        },
        f"/repos/{release.REPOSITORY}/immutable-releases": {"enabled": True, "enforced_by_owner": False},
        f"/repos/{release.REPOSITORY}/environments/{release.RELEASE_GUARD_ENVIRONMENT}": {
            "can_admins_bypass": True,
            "deployment_branch_policy": {"custom_branch_policies": True, "protected_branches": False},
            "name": release.RELEASE_GUARD_ENVIRONMENT,
            "protection_rules": [
                {
                    "id": 60_306_496,
                    "prevent_self_review": False,
                    "reviewers": [
                        {
                            "reviewer": {"id": 44_682_693, "login": release.OWNER, "type": "User"},
                            "type": "User",
                        }
                    ],
                    "type": "required_reviewers",
                },
                {"id": 60_306_497, "type": "branch_policy"},
            ],
        },
        f"/repos/{release.REPOSITORY}/environments/{release.RELEASE_GUARD_ENVIRONMENT}/deployment-branch-policies": {
            "branch_policies": [
                {
                    "id": release.RELEASE_GUARD_POLICY_ID,
                    "name": release.RELEASE_GUARD_TAG_PATTERN,
                    "type": "tag",
                }
            ],
            "total_count": 1,
        },
        (
            f"/repos/{release.REPOSITORY}/environments/{release.RELEASE_GUARD_ENVIRONMENT}"
            f"/secrets/{release.RELEASE_GUARD_SECRET}"
        ): {"created_at": "2026-07-18T00:00:00Z", "name": release.RELEASE_GUARD_SECRET},
    }
    payloads = release._release_asset_payloads(bundle, manifest)
    remote_payloads: dict[str, bytes] = {}
    assets = []
    for index, (filename, payload) in enumerate(sorted(payloads.items()), 1):
        url = f"{release.REPOSITORY_URL}/releases/download/{tag}/{filename}"
        remote_payloads[url] = payload
        assets.append(
            {
                "browser_download_url": url,
                "content_type": "application/octet-stream",
                "digest": f"sha256:{hashlib.sha256(payload).hexdigest()}",
                "id": index,
                "name": filename,
                "size": len(payload),
                "state": "uploaded",
                "url": f"https://api.github.com/repos/{release.REPOSITORY}/releases/assets/{index}",
            }
        )
    if include_release:
        release_document = {
            "assets": assets,
            "body": release._release_body(VERSION),
            "draft": False,
            "id": 9,
            "immutable": True,
            "name": release._release_name(VERSION),
            "prerelease": False,
            "published_at": "2026-07-18T12:00:00Z",
            "tag_name": tag,
        }
        documents[f"/repos/{release.REPOSITORY}/releases/tags/{tag}"] = release_document
        documents[f"/repos/{release.REPOSITORY}/releases?per_page=100&page=1"] = [copy.deepcopy(release_document)]
    else:
        documents[f"/repos/{release.REPOSITORY}/releases?per_page=100&page=1"] = []
    return documents, remote_payloads


def _github_reader(documents: dict[str, object]):
    def read(path: str, allow_not_found: bool) -> object | None:
        if path in documents:
            return copy.deepcopy(documents[path])
        if allow_not_found:
            return None
        raise AssertionError(f"unexpected GitHub API path: {path}")

    return read


def _github_cli_test_archive(
    binary: bytes,
    *,
    extra_members: list[tuple[str, bytes]] | None = None,
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        target = tarfile.TarInfo(release.GITHUB_CLI_ARCHIVE_MEMBER)
        target.mode = 0o755
        target.size = len(binary)
        archive.addfile(target, io.BytesIO(binary))
        for name, payload in extra_members or []:
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    return output.getvalue()


def _pin_github_cli_test_archive(monkeypatch, archive: bytes, binary: bytes, *, entries: int = 1) -> None:
    monkeypatch.setattr(release, "GITHUB_CLI_ARCHIVE_SIZE", len(archive))
    monkeypatch.setattr(release, "GITHUB_CLI_ARCHIVE_SHA256", hashlib.sha256(archive).hexdigest())
    monkeypatch.setattr(release, "GITHUB_CLI_ARCHIVE_ENTRIES", entries)
    monkeypatch.setattr(release, "GITHUB_CLI_ARCHIVE_EXPANDED_SIZE", len(binary) + (entries - 1))
    monkeypatch.setattr(release, "GITHUB_CLI_BINARY_SIZE", len(binary))
    monkeypatch.setattr(release, "GITHUB_CLI_BINARY_SHA256", hashlib.sha256(binary).hexdigest())


def test_normalization_is_byte_reproducible_across_order_timestamp_and_compression(tmp_path: Path):
    source = _source()
    first_raw_wheel = tmp_path / "first" / release._expected_wheel_name(VERSION)
    second_raw_wheel = tmp_path / "second" / release._expected_wheel_name(VERSION)
    first_raw_wheel.parent.mkdir()
    second_raw_wheel.parent.mkdir()
    _raw_wheel(first_raw_wheel)
    _raw_wheel(second_raw_wheel, reverse=True)
    first_wheel = tmp_path / "first.whl"
    second_wheel = tmp_path / "second.whl"
    # The normalizer intentionally requires the canonical output filename.
    first_wheel = tmp_path / "out-a" / release._expected_wheel_name(VERSION)
    second_wheel = tmp_path / "out-b" / release._expected_wheel_name(VERSION)
    first_wheel.parent.mkdir()
    second_wheel.parent.mkdir()
    release.normalize_wheel(first_raw_wheel, first_wheel, source)
    release.normalize_wheel(second_raw_wheel, second_wheel, source)
    assert first_wheel.read_bytes() == second_wheel.read_bytes()

    first_raw_sdist = tmp_path / "third" / release._expected_sdist_name(VERSION)
    second_raw_sdist = tmp_path / "fourth" / release._expected_sdist_name(VERSION)
    first_raw_sdist.parent.mkdir()
    second_raw_sdist.parent.mkdir()
    _raw_sdist(first_raw_sdist)
    _raw_sdist(second_raw_sdist, reverse=True)
    first_sdist = tmp_path / "out-c" / release._expected_sdist_name(VERSION)
    second_sdist = tmp_path / "out-d" / release._expected_sdist_name(VERSION)
    first_sdist.parent.mkdir()
    second_sdist.parent.mkdir()
    release.normalize_sdist(first_raw_sdist, first_sdist, source)
    release.normalize_sdist(second_raw_sdist, second_sdist, source)
    assert first_sdist.read_bytes() == second_sdist.read_bytes()


def test_closed_bundle_verifies_and_binds_wheel_sdist_sbom_and_dist(tmp_path: Path):
    bundle, dist = _bundle(tmp_path)
    manifest = release.verify_bundle(bundle, dist=dist, expected_source=_source())
    assert manifest["tag"] == "v0.2.0"
    assert {record["role"] for record in manifest["files"]} == {"wheel", "sdist", "sbom"}
    assert all(set(record["hashes"]) == {"sha256", "sha512"} for record in manifest["files"])
    assert all(set(record["sri"]) == {"sha256", "sha512"} for record in manifest["files"])


def test_zip_and_tar_path_traversal_fail_closed(tmp_path: Path):
    raw_wheel = tmp_path / release._expected_wheel_name(VERSION)
    _raw_wheel(raw_wheel, extra={"../escape": b"payload"})
    with pytest.raises(release.ReleaseError, match="traversing archive path"):
        release.normalize_wheel(raw_wheel, tmp_path / "wheel-out", _source())

    raw_sdist = tmp_path / release._expected_sdist_name(VERSION)
    root = f"compile_code-{VERSION}"
    _raw_sdist(raw_sdist, extra={f"{root}/../escape": b"payload"})
    with pytest.raises(release.ReleaseError, match="traversing archive path"):
        release.normalize_sdist(raw_sdist, tmp_path / "sdist-out", _source())


def test_manifest_path_traversal_and_duplicate_keys_fail_closed(tmp_path: Path):
    bundle, _ = _bundle(tmp_path)
    document = _manifest(bundle)
    document["files"][0]["filename"] = "../substitute.whl"
    _write_manifest(bundle, document)
    with pytest.raises(release.ReleaseError, match="unsafe bundle filename"):
        release.verify_bundle(bundle)

    bundle, _ = _bundle(tmp_path / "duplicate")
    original = (bundle / release.MANIFEST_NAME).read_text(encoding="utf-8")
    duplicate = original.replace('"files":', '"version":"0.2.0","files":', 1)
    (bundle / release.MANIFEST_NAME).write_text(duplicate, encoding="utf-8")
    with pytest.raises(release.ReleaseError, match="duplicate JSON key"):
        release.verify_bundle(bundle)

    bundle, _ = _bundle(tmp_path / "unknown-key")
    document = _manifest(bundle)
    document["unexpected"] = "not in the closed schema"
    _write_manifest(bundle, document)
    with pytest.raises(release.ReleaseError, match="keys must be"):
        release.verify_bundle(bundle)


def test_manifest_and_sbom_reads_are_bounded_duplicate_strict_and_single_linked(tmp_path: Path):
    bundle, _ = _bundle(tmp_path)
    manifest_path = bundle / release.MANIFEST_NAME
    manifest_path.write_bytes(b" " * (release.MAX_JSON_SIZE + 1))
    with pytest.raises(release.ReleaseError, match="input limit"):
        release.verify_bundle(bundle)

    bundle, _ = _bundle(tmp_path / "hardlink")
    manifest_path = bundle / release.MANIFEST_NAME
    original = tmp_path / "manifest-copy.json"
    shutil.copyfile(manifest_path, original)
    manifest_path.unlink()
    try:
        os.link(original, manifest_path)
    except OSError as exc:  # pragma: no cover - unusual filesystems without hard links
        pytest.skip(f"hard links unavailable: {exc}")
    with pytest.raises(release.ReleaseError, match="hard-linked"):
        release.verify_bundle(bundle)

    bundle, _ = _bundle(tmp_path / "duplicate-sbom")
    sbom = next(bundle.glob("*.cdx.json"))
    duplicate = sbom.read_bytes().replace(b'{"bomFormat":', b'{"bomFormat":"CycloneDX","bomFormat":', 1)
    sbom.write_bytes(duplicate)
    document = _manifest(bundle)
    replacement = release._file_record(sbom, "sbom")
    document["files"] = [replacement if record["role"] == "sbom" else record for record in document["files"]]
    _write_manifest(bundle, document)
    with pytest.raises(release.ReleaseError, match="duplicate JSON key"):
        release.verify_bundle(bundle)

    for payload in (b'{"value":NaN}', b'{"value":Infinity}', b'{"value":1e10000}'):
        with pytest.raises(release.ReleaseError, match="invalid strict UTF-8 JSON"):
            release._load_json_bytes(payload, "non-finite document")
    with pytest.raises(release.ReleaseError, match="invalid strict UTF-8 JSON.*integer literal is oversized"):
        release._load_json_bytes(b'{"value":' + (b"1" * 129) + b"}", "oversized integer document")
    with pytest.raises(release.ReleaseError, match="JSON nesting exceeds"):
        release._load_json_bytes((b"[" * 2_000) + (b"]" * 2_000), "deep document")


def test_release_cli_preserves_bundle_symlink_identity(tmp_path: Path, capsys):
    bundle, _ = _bundle(tmp_path / "target")
    alias = tmp_path / "bundle-alias"
    try:
        alias.symlink_to(bundle, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - Windows often requires Developer Mode
        pytest.skip(f"directory symlinks unavailable: {exc}")

    assert release.main(["verify", "--bundle", str(alias)]) == 1
    assert "symlink or reparse point" in capsys.readouterr().err


def test_extra_missing_and_duplicate_artifact_inventory_fail_closed(tmp_path: Path):
    bundle, _ = _bundle(tmp_path)
    (bundle / "extra.txt").write_text("substitution", encoding="utf-8")
    with pytest.raises(release.ReleaseError, match="missing or extra"):
        release.verify_bundle(bundle)

    bundle, _ = _bundle(tmp_path / "duplicate")
    document = _manifest(bundle)
    document["files"][2]["filename"] = document["files"][0]["filename"]
    _write_manifest(bundle, document)
    with pytest.raises(release.ReleaseError, match="duplicate manifest filename"):
        release.verify_bundle(bundle)

    bundle, _ = _bundle(tmp_path / "role-order")
    document = _manifest(bundle)
    document["files"].reverse()
    _write_manifest(bundle, document)
    with pytest.raises(release.ReleaseError, match="canonical role order"):
        release.verify_bundle(bundle)


def test_hash_mismatch_and_source_bound_artifact_substitution_fail_closed(tmp_path: Path):
    bundle, _ = _bundle(tmp_path)
    wheel = next(bundle.glob("*.whl"))
    wheel.write_bytes(wheel.read_bytes() + b"substitute")
    with pytest.raises(release.ReleaseError, match="artifact (size|hash) mismatch"):
        release.verify_bundle(bundle)

    bundle, _ = _bundle(tmp_path / "bound")
    wheel = next(bundle.glob("*.whl"))
    raw = tmp_path / "bound-raw" / wheel.name
    raw.parent.mkdir()
    _raw_wheel(raw)
    release.normalize_wheel(raw, wheel, _source(sha="2" * 40))
    source = _source()
    sdist = next(bundle.glob("*.tar.gz"))
    sbom = next(bundle.glob("*.cdx.json"))
    (bundle / release.MANIFEST_NAME).write_bytes(release._manifest_bytes(source, [wheel, sdist, sbom]))
    with pytest.raises(release.ReleaseError, match="wheel source binding mismatch"):
        release.verify_bundle(bundle)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda doc: doc.update(tag="v0.2.1"), "tag must be exactly"),
        (lambda doc: doc.update(version="0.2.1"), "tag must be exactly"),
        (lambda doc: doc["source"].update(sha="f" * 40), "source binding mismatch"),
        (lambda doc: doc["source"].update(tag_object_sha=doc["source"]["sha"]), "must differ"),
        (lambda doc: doc["evidence"].update(build_attestation="unsigned"), "evidence policy mismatch"),
        (lambda doc: doc["evidence"].update(dependency_audit="skipped"), "evidence policy mismatch"),
        (lambda doc: doc["evidence"].update(pypi_publish_attestation="missing"), "evidence policy mismatch"),
        (lambda doc: doc["files"][0]["hashes"].update(sha256="0" * 64), "SRI mismatch"),
    ],
)
def test_wrong_tag_version_source_and_hash_fail_closed(tmp_path: Path, mutation, message: str):
    bundle, _ = _bundle(tmp_path)
    document = _manifest(bundle)
    mutation(document)
    _write_manifest(bundle, document)
    with pytest.raises(release.ReleaseError, match=message):
        release.verify_bundle(bundle)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda doc: doc.update(schema_version=True), "manifest schema mismatch"),
        (lambda doc: doc["files"][0].update(size=True), "invalid size"),
    ],
)
def test_boolean_values_cannot_impersonate_manifest_integers(tmp_path: Path, mutation, message: str):
    bundle, _ = _bundle(tmp_path)
    document = _manifest(bundle)
    mutation(document)
    _write_manifest(bundle, document)
    with pytest.raises(release.ReleaseError, match=message):
        release.verify_bundle(bundle)


def test_lifecycle_scripts_and_dynamic_metadata_fail_closed(tmp_path: Path):
    raw = tmp_path / release._expected_sdist_name(VERSION)
    root = f"compile_code-{VERSION}"
    _raw_sdist(raw, extra={f"{root}/setup.py": b"raise SystemExit('ran')"})
    with pytest.raises(release.ReleaseError, match="lifecycle script"):
        release.normalize_sdist(raw, tmp_path / "out.tar.gz", _source())

    raw = tmp_path / "malicious" / release._expected_sdist_name(VERSION)
    raw.parent.mkdir()
    _raw_sdist(raw, extra={f"{root}/setup.cfg": b"[metadata]\nversion = 99\n"})
    with pytest.raises(release.ReleaseError, match="inert generated egg_info"):
        release.normalize_sdist(raw, tmp_path / "blocked.tar.gz", _source())

    pyproject = (
        (ROOT / "pyproject.toml")
        .read_text(encoding="utf-8")
        .replace('version = "0.2.0"', 'version = "0.2.0"\ndynamic = ["description"]')
    )
    with pytest.raises(release.ReleaseError, match="dynamic metadata"):
        release._read_pyproject_bytes(pyproject.encode())

    backend_path = (
        (ROOT / "pyproject.toml")
        .read_text(encoding="utf-8")
        .replace(
            'build-backend = "setuptools.build_meta"',
            'build-backend = "setuptools.build_meta"\nbackend-path = ["."]',
        )
    )
    with pytest.raises(release.ReleaseError, match="build-system table must be closed"):
        release._read_pyproject_bytes(backend_path.encode())

    external_readme = (
        (ROOT / "pyproject.toml")
        .read_text(encoding="utf-8")
        .replace('readme = "README.md"', 'readme = "../../private.txt"')
    )
    with pytest.raises(release.ReleaseError, match="readme path must be exactly README.md"):
        release._read_pyproject_bytes(external_readme.encode())

    executable_tool_plugin = (ROOT / "pyproject.toml").read_text(encoding="utf-8") + "\n[tool.setuptools_scm]\n"
    with pytest.raises(release.ReleaseError, match="tool table must be closed"):
        release._read_pyproject_bytes(executable_tool_plugin.encode())

    unknown_root_table = (ROOT / "pyproject.toml").read_text(encoding="utf-8") + "\n[release-plugin]\nvalue = true\n"
    with pytest.raises(release.ReleaseError, match="root table must contain only"):
        release._read_pyproject_bytes(unknown_root_table.encode())


def test_lifecycle_inputs_are_rejected_before_the_build_backend_can_run(tmp_path: Path):
    source = tmp_path / "source"
    (source / "src" / "compile_code").mkdir(parents=True)
    for relative in ("LICENSE", "README.md", "pyproject.toml"):
        shutil.copyfile(ROOT / relative, source / relative)
    for relative in ("__init__.py", "cli.py"):
        shutil.copyfile(ROOT / "src" / "compile_code" / relative, source / "src" / "compile_code" / relative)
    (source / "setup.py").write_text("raise SystemExit('must never execute')\n", encoding="utf-8")

    with pytest.raises(release.ReleaseError, match="pre-build lifecycle input is forbidden: setup.py"):
        release._validate_source_tree_for_build(source, expected_version=VERSION)


def test_backend_output_inventory_rejects_non_artifacts_before_normalization(tmp_path: Path):
    expected = (release._expected_wheel_name(VERSION), release._expected_sdist_name(VERSION))

    raw = tmp_path / "directory-output"
    raw.mkdir()
    for name in expected:
        (raw / name).write_bytes(b"placeholder")
    (raw / "ignored-directory").mkdir()
    with pytest.raises(release.ReleaseError, match="only singly-linked regular artifacts"):
        release._normalize_build(raw, tmp_path / "normalized-directory", _source())
    assert not (tmp_path / "normalized-directory").exists()

    raw = tmp_path / "extra-output"
    raw.mkdir()
    for name in expected:
        (raw / name).write_bytes(b"placeholder")
    (raw / "unexpected.txt").write_bytes(b"unexpected")
    with pytest.raises(release.ReleaseError, match="backend artifact set mismatch"):
        release._normalize_build(raw, tmp_path / "normalized-extra", _source())
    assert not (tmp_path / "normalized-extra").exists()


def test_wheel_entry_point_inventory_rejects_empty_or_duplicate_sections():
    valid = (
        b"[console_scripts]\n"
        b"cmpl = compile_code.cli:cli\n"
        b"compile = compile_code.cli:cli\n"
        b"compile-code = compile_code.cli:cli\n"
    )
    release._validate_entry_points(valid)

    with pytest.raises(release.ReleaseError, match="unexpected wheel entry-point section"):
        release._validate_entry_points(valid + b"[unexpected-empty-section]\n")
    with pytest.raises(release.ReleaseError, match="duplicate wheel entry-point section"):
        release._validate_entry_points(valid + b"[console_scripts]\n")


def test_build_environment_is_closed_against_python_pip_and_setuptools_injection(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PIP_EXTRA_INDEX_URL", "https://attacker.invalid/simple")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "shadow"))
    monkeypatch.setenv("SETUPTOOLS_SCM_PRETEND_VERSION", "99.0.0")

    environment = release._closed_build_environment(EPOCH, tmp_path)

    assert "PIP_EXTRA_INDEX_URL" not in environment
    assert "PYTHONPATH" not in environment
    assert "SETUPTOOLS_SCM_PRETEND_VERSION" not in environment
    assert environment["PIP_NO_INDEX"] == "1"
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["PYTHONSAFEPATH"] == "1"

    monkeypatch.setenv("HTTPS_PROXY", "https://attacker.invalid")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "attacker-ca.pem"))
    smoke_environment = release._smoke_environment()
    assert "HTTPS_PROXY" not in smoke_environment
    assert "REQUESTS_CA_BUNDLE" not in smoke_environment
    assert smoke_environment["PIP_INDEX_URL"] == "https://pypi.org/simple"


def test_runtime_dependency_contract_is_closed_to_the_tested_roam_major():
    project = release._read_pyproject(ROOT)["project"]
    assert project["dependencies"] == ["roam-code<14,>=13.10.0", "click>=8.0"]
    assert release.RUNTIME_REQUIRES == project["dependencies"]

    docs = {name: (ROOT / name).read_text(encoding="utf-8") for name in ("README.md", "AGENTS.md")}
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert prepush_check._floor_drift(pyproject, docs) == []


@pytest.mark.parametrize(
    ("replacement", "expected"),
    [
        ("roam-code>=13.10.0", "inclusive floor and one exclusive ceiling"),
        ("roam-code<15,>=13.10.0", "compatibility interval drifted"),
        ("roam-code<14,>=13.9.0", "compatibility interval drifted"),
    ],
)
def test_compatibility_gate_rejects_open_or_drifted_roam_intervals(replacement: str, expected: str):
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    mutated = pyproject.replace("roam-code<14,>=13.10.0", replacement)
    docs = {name: (ROOT / name).read_text(encoding="utf-8") for name in ("README.md", "AGENTS.md")}

    assert any(expected in problem for problem in prepush_check._floor_drift(mutated, docs))


def test_resolver_protocol_smoke_runs_real_hook_contract_and_bound_verify(tmp_path: Path, monkeypatch):
    scripts = tmp_path / "venv" / ("Scripts" if os.name == "nt" else "bin")
    scripts.mkdir(parents=True)
    compile_executable = scripts / ("compile.exe" if os.name == "nt" else "compile")
    calls: list[tuple[list[str], Path, dict[str, str], int]] = []

    def run(argv, *, cwd, env=None, timeout=300, **_kwargs):
        calls.append((argv, cwd, env, timeout))
        if argv[1:] == ["doctor"]:
            return "toolchain : ok\nindex     : ok\nclaude    : wired (project)\nVERDICT: ready\n"
        if "verify" in argv:
            return "VERDICT: PASS (score 100/100) -- 0 issues in 1 changed file\n"
        return ""

    monkeypatch.setattr(release, "_run", run)
    git_executable = str(tmp_path / ("git.exe" if os.name == "nt" else "git"))
    monkeypatch.setattr(release.shutil, "which", lambda *_args, **_kwargs: git_executable)
    original_environment = {
        "CLAUDE_CONFIG_DIR": "user-claude-config",
        "GIT_DIR": "user-git-dir",
        "PATH": "trusted-system-path",
        "PYTHONSAFEPATH": "1",
        "ROAM_DB": "user-roam.db",
    }

    release._run_required_roam_protocol_smoke(compile_executable, tmp_path, original_environment)

    project = tmp_path / "roam-protocol-project"
    assert (project / "protocol_smoke.py").read_text(encoding="utf-8") == (
        "def protocol_smoke(value: int) -> int:\n    return value + 1\n"
    )
    assert [call[0] for call in calls] == [
        [git_executable, "-c", "init.defaultBranch=main", "init", "--quiet"],
        [git_executable, "add", "--", "protocol_smoke.py"],
        [str(compile_executable), "init"],
        [str(compile_executable), "wire", "claude"],
        [str(compile_executable), "doctor"],
        [str(compile_executable), "verify", "--threshold", "0", "--", "protocol_smoke.py"],
    ]
    assert all(call[1] == project for call in calls)
    assert [call[3] for call in calls] == [60, 60, 180, 180, 60, 180]
    assert all(call[2]["PATH"].split(os.pathsep, 1)[0] == str(scripts) for call in calls)
    isolated_home = tmp_path / "isolated-runtime" / "home"
    for _argv, _cwd, environment, _timeout in calls:
        assert environment["HOME"] == str(isolated_home)
        assert environment["USERPROFILE"] == str(isolated_home)
        assert environment["CLAUDE_CONFIG_DIR"] == str(isolated_home / ".claude")
        assert Path(environment["XDG_CONFIG_HOME"]).is_relative_to(tmp_path)
        assert Path(environment["APPDATA"]).is_relative_to(tmp_path)
        assert Path(environment["TEMP"]).is_relative_to(tmp_path)
        assert "GIT_DIR" not in environment
        assert "ROAM_DB" not in environment
    assert original_environment == {
        "CLAUDE_CONFIG_DIR": "user-claude-config",
        "GIT_DIR": "user-git-dir",
        "PATH": "trusted-system-path",
        "PYTHONSAFEPATH": "1",
        "ROAM_DB": "user-roam.db",
    }


def test_resolver_protocol_smoke_rejects_roam_hooks_that_compile_reports_unwired(tmp_path: Path, monkeypatch):
    scripts = tmp_path / "venv" / ("Scripts" if os.name == "nt" else "bin")
    scripts.mkdir(parents=True)
    compile_executable = scripts / ("compile.exe" if os.name == "nt" else "compile")
    calls: list[list[str]] = []

    def run(argv, **_kwargs):
        calls.append(argv)
        if argv[1:] == ["doctor"]:
            return (
                "toolchain : ok\n"
                "index     : ok\n"
                "claude    : not wired (run `compile wire claude`)\n"
                "VERDICT: install ok — finish setup above\n"
            )
        return ""

    monkeypatch.setattr(release, "_run", run)
    git_executable = str(tmp_path / ("git.exe" if os.name == "nt" else "git"))
    monkeypatch.setattr(release.shutil, "which", lambda *_args, **_kwargs: git_executable)

    with pytest.raises(release.ReleaseError, match=release.REQUIRED_CLAUDE_HOOK_READINESS):
        release._run_required_roam_protocol_smoke(compile_executable, tmp_path, {"PATH": "trusted"})

    assert calls == [
        [git_executable, "-c", "init.defaultBranch=main", "init", "--quiet"],
        [git_executable, "add", "--", "protocol_smoke.py"],
        [str(compile_executable), "init"],
        [str(compile_executable), "wire", "claude"],
        [str(compile_executable), "doctor"],
    ]


def test_resolver_protocol_smoke_rejects_non_protocol_output(tmp_path: Path, monkeypatch):
    scripts = tmp_path / "venv" / ("Scripts" if os.name == "nt" else "bin")
    scripts.mkdir(parents=True)
    compile_executable = scripts / ("compile.exe" if os.name == "nt" else "compile")
    git_executable = str(tmp_path / ("git.exe" if os.name == "nt" else "git"))
    monkeypatch.setattr(release.shutil, "which", lambda *_args, **_kwargs: git_executable)

    def run(argv, **_kwargs):
        if argv[1:] == ["doctor"]:
            return "claude    : wired (project)\nVERDICT: ready\n"
        return "Usage: compile verify\n" if "verify" in argv else ""

    monkeypatch.setattr(release, "_run", run)

    with pytest.raises(release.ReleaseError, match=release.REQUIRED_ROAM_VERIFY_PROTOCOL):
        release._run_required_roam_protocol_smoke(compile_executable, tmp_path, {"PATH": "trusted"})


def test_install_smoke_requires_protocol_transaction_only_for_resolved_dependencies(tmp_path: Path, monkeypatch):
    class Builder:
        def __init__(self, **_kwargs):
            pass

        def create(self, directory):
            scripts = Path(directory) / ("Scripts" if os.name == "nt" else "bin")
            scripts.mkdir(parents=True)

    def run(argv, **_kwargs):
        return "Usage: compile\n" if argv[-1] == "--help" else ""

    protocol_calls = []
    monkeypatch.setattr(release.venv, "EnvBuilder", Builder)
    monkeypatch.setattr(release, "_run", run)
    monkeypatch.setattr(
        release,
        "_run_required_roam_protocol_smoke",
        lambda executable, root, environment: protocol_calls.append((executable, root, environment)),
    )

    release._run_install_smoke(tmp_path / "compile.whl", VERSION, "package-only", tmp_path)
    assert protocol_calls == []

    release._run_install_smoke(tmp_path / "compile.whl", VERSION, "resolve", tmp_path)
    assert len(protocol_calls) == 1
    executable, smoke_root, environment = protocol_calls[0]
    assert executable.name == ("compile.exe" if os.name == "nt" else "compile")
    assert smoke_root.parent == tmp_path
    assert environment["PIP_INDEX_URL"] == "https://pypi.org/simple"


def test_normalized_archives_reject_trailing_bytes_and_noncanonical_encoding(tmp_path: Path):
    bundle, _ = _bundle(tmp_path)
    manifest = _manifest(bundle)
    wheel = next(bundle.glob("*.whl"))
    wheel.write_bytes(wheel.read_bytes() + b"trailing substitution")
    with pytest.raises(release.ReleaseError, match="trailing bytes"):
        release._inspect_wheel(wheel, manifest)

    bundle, _ = _bundle(tmp_path / "sdist")
    manifest = _manifest(bundle)
    sdist = next(bundle.glob("*.tar.gz"))
    sdist.write_bytes(sdist.read_bytes() + b"trailing substitution")
    with pytest.raises(release.ReleaseError, match="invalid sdist gzip stream"):
        release._inspect_sdist(sdist, manifest)


def test_archive_links_fail_closed(tmp_path: Path):
    raw_wheel = tmp_path / release._expected_wheel_name(VERSION)
    _raw_wheel(raw_wheel)
    with zipfile.ZipFile(raw_wheel, "a") as archive:
        link = zipfile.ZipInfo("compile_code/link.py")
        link.create_system = 3
        link.external_attr = (0o120777 << 16) | 0xA000
        archive.writestr(link, b"cli.py")
    with pytest.raises(release.ReleaseError, match="wheel symlink is forbidden"):
        release.normalize_wheel(raw_wheel, tmp_path / "linked.whl", _source())

    raw_sdist = tmp_path / "linked" / release._expected_sdist_name(VERSION)
    raw_sdist.parent.mkdir()
    _raw_sdist(raw_sdist, symlink=(f"compile_code-{VERSION}/src/compile_code/link.py", "cli.py"))
    with pytest.raises(release.ReleaseError, match="forbidden"):
        release.normalize_sdist(raw_sdist, tmp_path / "linked.tar.gz", _source())


def test_archive_entry_counts_are_bounded_before_unbounded_member_materialization(tmp_path: Path):
    wheel = tmp_path / "many.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for index in range(release.MAX_ARCHIVE_ENTRIES + 1):
            archive.writestr(f"entry-{index}.txt", b"")
    with pytest.raises(release.ReleaseError, match="too many entries"):
        release._read_zip_files(wheel)

    understated = bytearray(wheel.read_bytes())
    eocd = understated.rfind(b"PK\x05\x06")
    assert eocd >= 0
    __import__("struct").pack_into("<2H", understated, eocd + 8, 1, 1)
    with pytest.raises(release.ReleaseError, match="too many entries"):
        release._read_zip_files(wheel, archive_bytes=bytes(understated))

    sdist = tmp_path / "many.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        for index in range(release.MAX_ARCHIVE_ENTRIES + 1):
            info = tarfile.TarInfo(f"root/entry-{index}.txt")
            info.size = 0
            archive.addfile(info, io.BytesIO())
    with pytest.raises(release.ReleaseError, match="too many entries"):
        release._read_tar_files(sdist)


def test_sdist_total_decompressed_stream_is_bounded_before_tar_parsing(tmp_path: Path, monkeypatch):
    raw_sdist = tmp_path / release._expected_sdist_name(VERSION)
    _raw_sdist(raw_sdist)
    monkeypatch.setattr(release, "MAX_TAR_STREAM_SIZE", 1_024)
    with pytest.raises(release.ReleaseError, match="decompressed stream exceeds"):
        release._read_tar_files(raw_sdist)


def test_package_content_leaks_fail_and_private_nonpackage_files_are_pruned(tmp_path: Path):
    root = f"compile_code-{VERSION}"
    secret = b"gh" + b"p_" + b"A" * 24
    raw = tmp_path / release._expected_sdist_name(VERSION)
    _raw_sdist(raw, extra={f"{root}/src/compile_code/leak.py": secret})
    with pytest.raises(release.ReleaseError, match="package-content leak"):
        release.normalize_sdist(raw, tmp_path / "blocked.tar.gz", _source())

    raw = tmp_path / "prune" / release._expected_sdist_name(VERSION)
    raw.parent.mkdir()
    private_path = f"{root}/internal/" + "planning/session.txt"
    _raw_sdist(raw, extra={private_path: b"private"})
    output = tmp_path / "pruned" / release._expected_sdist_name(VERSION)
    output.parent.mkdir()
    release.normalize_sdist(raw, output, _source())
    _, files = release._read_tar_files(output)
    assert not any("internal/" in name for name in files)


def test_manifest_schema_closes_every_nested_manifest_object():
    schema = json.loads((ROOT / "release" / "manifest.schema.json").read_text(encoding="utf-8"))
    assert schema["additionalProperties"] is False
    assert schema["properties"]["evidence"]["additionalProperties"] is False
    assert schema["properties"]["evidence"]["properties"] == {
        "build_attestation": {"const": "github-build-provenance"},
        "dependency_audit": {"const": "osv-locked-graphs"},
        "pypi_publish_attestation": {"const": "pypi-integrity-api-pep740"},
        "release_attestation": {"const": "github-immutable-release"},
    }
    assert schema["properties"]["source"]["additionalProperties"] is False
    assert schema["properties"]["source"]["properties"]["tag_object_sha"]["pattern"] == "^[0-9a-f]{40}$"
    item = schema["properties"]["files"]["items"]
    assert item["additionalProperties"] is False
    assert item["properties"]["hashes"]["additionalProperties"] is False
    assert item["properties"]["sri"]["additionalProperties"] is False
    prefix_items = schema["properties"]["files"]["prefixItems"]
    assert all(prefix["allOf"][0] == {"$ref": "#/properties/files/items"} for prefix in prefix_items)
    assert [prefix["allOf"][1]["properties"]["role"]["const"] for prefix in prefix_items] == [
        "wheel",
        "sdist",
        "sbom",
    ]
    assert [prefix["allOf"][1]["properties"]["media_type"]["const"] for prefix in prefix_items] == [
        "application/zip",
        "application/gzip",
        "application/vnd.cyclonedx+json",
    ]
    assert item["allOf"][0]["if"]["properties"]["role"]["const"] == "sbom"
    assert item["allOf"][0]["then"]["properties"]["size"]["maximum"] == release.MAX_JSON_SIZE


def test_leak_scan_redacts_credential_text(tmp_path: Path, monkeypatch):
    token = "gh" + "p_" + "A" * 24
    tracked = tmp_path / "tracked.txt"
    tracked.write_text(token, encoding="utf-8")
    monkeypatch.setattr(prepush_check, "ROOT", tmp_path)

    hits = prepush_check._scan_file_for_leaks("tracked.txt")

    assert hits
    assert token not in "\n".join(hits)
    assert "redacted match" in hits[0]


def test_workflows_use_immutable_actions_and_keep_expressions_out_of_shell():
    for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
        assert isinstance(yaml.safe_load(workflow.read_text(encoding="utf-8")), dict)
    assert release.audit_repository(ROOT) == []
    malicious = """
jobs:
  bad:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - run: echo "${{ github.event.issue.title }}"
"""
    problems = release.audit_workflow_text(malicious, "malicious.yml")
    assert any("mutable or local action" in problem for problem in problems)
    assert any("expression embedded" in problem for problem in problems)
    assert any("ubuntu-latest" in problem for problem in problems)
    canonical_check = (ROOT / "scripts" / "check.py").read_text(encoding="utf-8")
    assert '"--persona", "auditor", "--no-ignores", "--min-severity", "medium"' in canonical_check


def test_release_workflow_is_inputless_least_privilege_owner_gated_and_publishers_have_no_run():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    jobs = yaml.safe_load(workflow)["jobs"]
    assert "workflow_dispatch:" not in workflow
    assert "inputs:" not in workflow
    assert set(__import__("re").findall(r"secrets\.([A-Z0-9_]+)", workflow)) == {"RELEASE_GUARD_READ_TOKEN"}
    assert workflow.count("secrets.RELEASE_GUARD_READ_TOKEN") == 3
    assert workflow.count("name: release-guard") == 3
    assert "create-github-app-token" not in workflow
    assert "github.repository == 'Cranot/compile-code'" in workflow
    assert "github.actor == 'Cranot'" in workflow
    assert "github.triggering_actor == 'Cranot'" in workflow
    assert "environment:\n      name: pypi" in workflow
    assert workflow.count("--github-source") == 4
    assert workflow.count("fetch-depth: 0") == 6
    build = workflow.split("\n  build:\n", 1)[1].split("\n  provenance:\n", 1)[0]
    assert "\n    if:" not in build
    assert build.count("python scripts/release_artifacts.py source") == 1
    assert (
        build.index("python scripts/release_artifacts.py source")
        < build.index("python scripts/release_artifacts.py audit-locks")
        < build.index("python -m pip install")
    )
    publish = workflow.split("\n  publish:\n", 1)[1].split("\n  postpublish:\n", 1)[0]
    assert "\n        run:" not in publish
    assert "id-token: write" in publish
    github_stage = workflow.split("\n  github_release_stage:\n", 1)[1].split("\n  github_release_draft_verify:\n", 1)[0]
    github_publish = workflow.split("\n  github_release_publish:\n", 1)[1].split("\n  github_release_postverify:\n", 1)[
        0
    ]
    for privileged in (github_stage, github_publish):
        assert "\n        run:" not in privileged
        assert "actions/checkout@" not in privileged
        assert "actions/setup-python@" not in privileged
        assert "id-token: write" not in privileged
        assert "RELEASE_GUARD_READ_TOKEN" not in privileged
        assert "IMMUTABLE_RELEASES_TOKEN" not in privileged
        assert "name: release-guard" not in privileged
        assert privileged.count("contents: write") == 1
        assert "github.ref == 'refs/tags/v0.2.0'" in privileged
        assert "needs.github_release_preflight.outputs.source_sha == github.sha" in privileged
        assert "needs.github_release_preflight.outputs.tag == 'v0.2.0'" in privileged
        assert "fromJSON(steps.remote_tag_ref.outputs.data).object.type == 'tag'" in privileged
        assert (
            "fromJSON(steps.remote_tag_ref.outputs.data).object.sha == "
            "needs.github_release_preflight.outputs.tag_object_sha"
        ) in privileged
        assert "fromJSON(steps.remote_tag_object.outputs.data).object.type == 'commit'" in privileged
        assert "fromJSON(steps.remote_tag_object.outputs.data).object.sha == github.sha" in privileged
        assert privileged.count("route: GET /repos/{owner}/{repo}/git/tags/{tag_sha}") == 1
        assert "tag_sha: ${{ needs.github_release_preflight.outputs.tag_object_sha }}" in privileged
    assert "softprops/action-gh-release@" not in github_stage + github_publish
    assert github_stage.count("octokit/request-action@b91aabaa861c777dcdb14e2387e30eddf04619ae") == 2
    assert "ncipollo/release-action@339a81892b84b4eeb0f6e744e4574d79d0d9b8dd" in github_stage
    assert (
        "needs.github_release_preflight.outputs.bundle_artifact_id == needs.build.outputs.bundle_artifact_id"
        in github_stage
    )
    assert "route: GET /repos/Cranot/compile-code/git/ref/tags/v0.2.0" in github_stage
    assert "route: PATCH " not in github_stage
    assert 'draft: "true"' in github_stage
    assert 'allowUpdates: "false"' in github_stage
    assert "artifactContentType: application/octet-stream" in github_stage
    assert 'artifactErrorsFailBuild: "true"' in github_stage
    assert 'immutableCreate: "false"' in github_stage
    assert 'removeArtifacts: "false"' in github_stage
    assert 'replacesArtifacts: "false"' in github_stage
    assert 'skipIfReleaseExists: "true"' in github_stage
    assert github_stage.count("compile_code-0.2.0-py3-none-any.whl") == 1
    assert github_stage.count("compile_code-0.2.0.tar.gz") == 1
    assert github_stage.count("compile_code-0.2.0.cdx.json") == 1
    assert github_stage.count("release-manifest.json") == 2  # body + exact file input
    assert github_publish.count("octokit/request-action@b91aabaa861c777dcdb14e2387e30eddf04619ae") == 8
    assert github_publish.count("route: GET /repos/{owner}/{repo}/releases/assets/{asset_id}") == 4
    assert github_publish.count("route: PATCH ") == 1
    assert "route: POST " not in github_publish
    assert "route: DELETE " not in github_publish
    assert "fromJSON(steps.remote_draft.outputs.data).draft == true" in github_publish
    assert "fromJSON(steps.remote_draft.outputs.data).immutable == false" in github_publish
    assert "fromJSON(steps.remote_draft.outputs.data).published_at == null" in github_publish
    assert "route: PATCH /repos/{owner}/{repo}/releases/{release_id}" in github_publish
    for role in ("wheel", "sdist", "sbom", "manifest"):
        assert (
            f"fromJSON(steps.remote_{role}.outputs.data).id == "
            f"fromJSON(needs.github_release_draft_verify.outputs.{role}_asset_id)"
        ) in github_publish
    assert "fromJSON(steps.remote_draft.outputs.data).assets[3] != null" in github_publish
    assert "fromJSON(steps.remote_draft.outputs.data).assets[4] == null" in github_publish
    assert "tag_name: v0.2.0" in github_publish
    assert "name: compile-code v0.2.0" in github_publish
    assert "prerelease: false" in github_publish
    assert jobs["github_release_stage"]["needs"] == ["build", "prepublish", "github_release_preflight"]
    assert jobs["github_release_draft_verify"]["needs"] == [
        "build",
        "github_release_preflight",
        "github_release_stage",
    ]
    assert jobs["publish"]["needs"] == [
        "build",
        "prepublish",
        "github_release_preflight",
        "github_release_draft_verify",
    ]
    assert jobs["postpublish"]["needs"] == [
        "build",
        "prepublish",
        "github_release_preflight",
        "github_release_draft_verify",
        "publish",
    ]
    assert jobs["github_release_publish"]["needs"] == [
        "github_release_preflight",
        "github_release_draft_verify",
        "postpublish",
    ]
    assert "needs.postpublish.result == 'success'" in jobs["github_release_publish"]["if"]
    assert "needs.github_release_draft_verify.outputs.state == 'draft_exact'" in jobs["publish"]["if"]
    assert "needs.github_release_preflight.outputs.release_state == 'exact'" in jobs["publish"]["if"]
    assert "needs.prepublish.outputs.publish_required == 'false'" in jobs["postpublish"]["if"]
    assert jobs["github_release_postverify"]["if"] == (
        "always() && needs.build.result == 'success' && needs.github_release_preflight.result == 'success'"
    )
    postverify = jobs["github_release_postverify"]
    assert any(
        step.get("with", {}).get("artifact-ids") == "${{ needs.build.outputs.dist_artifact_id }}"
        for step in postverify["steps"]
    )
    assert any(
        "pypi-state --bundle release-bundle --dist pypi-dist --github-source --require-exact --wait-seconds 300"
        in step.get("run", "")
        for step in postverify["steps"]
    )
    assert "github-artifact-state" in workflow
    assert "github-release-state" in workflow
    assert "digest-mismatch: error" in github_stage
    assert "--require-draft-exact --wait-seconds 120 --github-output" in workflow
    assert "--github-source --wait-seconds 120 --github-output" in workflow
    assert "skip-existing: false" in workflow
    assert "skip-existing: true" not in workflow
    assert "python scripts/release_artifacts.py audit-locks" in workflow
    assert workflow.index("python scripts/release_artifacts.py audit-locks") < workflow.index("python -m pip install")
    assert "pypa/gh-action-pip-audit@" not in workflow

    guard_jobs = ("github_release_preflight", "github_release_draft_verify", "github_release_postverify")
    for job_name in guard_jobs:
        job = workflow.split(f"\n  {job_name}:\n", 1)[1]
        job = __import__("re").split(r"\n  [a-zA-Z0-9_-]+:\n", job, maxsplit=1)[0]
        assert job.count("environment:\n      name: release-guard") == 1
        assert job.count("secrets.RELEASE_GUARD_READ_TOKEN") == 1
        assert job.count("install-github-cli --github-output") == 1
        assert job.count("COMPILE_GITHUB_CLI: ${{ steps.github_cli.outputs.github_cli_path }}") == 1
    assert workflow.count("install-github-cli --github-output") == 3
    assert workflow.count("COMPILE_GITHUB_CLI: ${{ steps.github_cli.outputs.github_cli_path }}") == 3
    release_source = (ROOT / "scripts" / "release_artifacts.py").read_text(encoding="utf-8")
    assert __import__("re").search(r"_run\(\s*\[\s*['\"]gh['\"]", release_source) is None


def test_release_workflow_audit_rejects_tag_guard_mutation_and_binding_loss(tmp_path: Path):
    root = tmp_path / "repository"
    shutil.copytree(ROOT / ".github", root / ".github")
    workflow = root / ".github" / "workflows" / "release.yml"
    original = workflow.read_text(encoding="utf-8")

    workflow.write_text(
        original.replace(
            "route: GET /repos/Cranot/compile-code/git/ref/tags/v0.2.0",
            "route: PATCH /repos/Cranot/compile-code/git/ref/tags/v0.2.0",
            1,
        ),
        encoding="utf-8",
    )
    assert any("tag guard may perform only GET" in problem for problem in release.audit_repository(root))

    workflow.write_text(
        original.replace("fromJSON(steps.remote_tag_ref.outputs.data).object.type == 'tag'", "true", 1),
        encoding="utf-8",
    )
    assert any("tag binding drift" in problem for problem in release.audit_repository(root))

    workflow.write_text(
        original.replace("environment:\n      name: release-guard", "environment:\n      name: unprotected", 1),
        encoding="utf-8",
    )
    assert any("release-guard" in problem for problem in release.audit_repository(root))

    workflow.write_text(
        original.replace("needs.github_release_preflight.outputs.source_sha == github.sha", "true", 1),
        encoding="utf-8",
    )
    assert any("PyPI publication binding drift" in problem for problem in release.audit_repository(root))

    workflow.write_text(original.replace("actions/checkout@9c091", "actions/checkout@00000", 1), encoding="utf-8")
    assert any("exact action inventory drift" in problem for problem in release.audit_repository(root))

    workflow.write_text(
        original.replace(
            "needs: [build, prepublish, github_release_preflight]",
            "needs: [build, postpublish, github_release_preflight]",
            1,
        ),
        encoding="utf-8",
    )
    assert any("draft staging must depend on preflight" in problem for problem in release.audit_repository(root))

    workflow.write_text(
        original.replace("install-github-cli --github-output", "install-runner-github-cli", 1),
        encoding="utf-8",
    )
    assert any("exact GitHub CLI" in problem for problem in release.audit_repository(root))

    workflow.write_text(
        original.replace(
            "COMPILE_GITHUB_CLI: ${{ steps.github_cli.outputs.github_cli_path }}",
            "COMPILE_GITHUB_CLI: /usr/bin/gh",
            1,
        ),
        encoding="utf-8",
    )
    assert any("controlled GitHub CLI path" in problem for problem in release.audit_repository(root))


def test_immutable_release_settings_token_is_mandatory_and_bounded():
    with pytest.raises(release.ReleaseError, match="Administration:read"):
        release._immutable_releases_token({})
    with pytest.raises(release.ReleaseError, match="Administration:read"):
        release._immutable_releases_token({"IMMUTABLE_RELEASES_TOKEN": "short"})
    assert release._immutable_releases_token({"IMMUTABLE_RELEASES_TOKEN": "g" * 40}) == "g" * 40


def test_github_json_api_redirects_fail_before_credentials_can_follow():
    with pytest.raises(release.ReleaseError, match="unexpectedly redirected"):
        release._RejectGitHubAPIRedirect().redirect_request(
            None,
            None,
            302,
            "Found",
            {},
            "https://attacker.invalid/capture",
        )


def test_github_cli_download_is_exact_bounded_and_credential_free(monkeypatch):
    payload = b"reviewed-gh-archive"
    monkeypatch.setattr(release, "GITHUB_CLI_ARCHIVE_SIZE", len(payload))
    monkeypatch.setattr(release, "GITHUB_CLI_ARCHIVE_SHA256", hashlib.sha256(payload).hexdigest())

    class Response:
        def __init__(self, body: bytes):
            self.body = body
            self.headers = {
                "Content-Disposition": f"attachment; filename={release.GITHUB_CLI_ARCHIVE_NAME}",
                "Content-Length": str(len(payload)),
                "Content-Type": "application/octet-stream",
            }

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return 200

        def geturl(self):
            return "https://release-assets.githubusercontent.com/github-production-release-asset/exact?sig=1"

        def read(self, limit: int):
            return self.body[:limit]

        def read1(self, _limit: int):
            return self.body

    class Opener:
        def __init__(self, body: bytes):
            self.body = body
            self.requests = []

        def open(self, request, *, timeout: int):
            self.requests.append((request, timeout))
            return Response(self.body)

    opener = Opener(payload)
    assert release._fetch_github_cli_archive(opener=opener) == payload
    request, timeout = opener.requests[0]
    assert request.full_url == release.GITHUB_CLI_ARCHIVE_URL
    assert request.get_header("Authorization") is None
    assert timeout == release.GITHUB_CLI_SOCKET_TIMEOUT_SECONDS

    with pytest.raises(release.ReleaseError, match="exact byte length"):
        release._fetch_github_cli_archive(opener=Opener(payload + b"x"))

    monkeypatch.setattr(release, "GITHUB_CLI_ARCHIVE_SHA256", "0" * 64)
    with pytest.raises(release.ReleaseError, match="SHA-256 mismatch"):
        release._fetch_github_cli_archive(opener=Opener(payload))

    monkeypatch.setattr(release, "GITHUB_CLI_ARCHIVE_SHA256", hashlib.sha256(payload).hexdigest())
    moments = iter((0.0, float(release.GITHUB_CLI_DOWNLOAD_TIMEOUT_SECONDS + 1)))
    monkeypatch.setattr(release.time, "monotonic", lambda: next(moments))
    with pytest.raises(release.ReleaseError, match="wall-clock deadline"):
        release._fetch_github_cli_archive(opener=Opener(payload))


def test_github_cli_pin_is_exact_and_above_the_security_floor():
    assert tuple(int(part) for part in release.GITHUB_CLI_VERSION.split(".")) >= (2, 93, 0)
    assert release.GITHUB_CLI_VERSION == "2.96.0"
    assert release.GITHUB_CLI_ARCHIVE_URL == (
        "https://github.com/cli/cli/releases/download/v2.96.0/gh_2.96.0_linux_amd64.tar.gz"
    )
    assert release.GITHUB_CLI_ARCHIVE_SIZE == 14_652_560
    assert release.GITHUB_CLI_ARCHIVE_SHA256 == ("83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60")
    assert release.GITHUB_CLI_BINARY_SIZE == 40_722_594
    assert release.GITHUB_CLI_BINARY_SHA256 == ("56b8bbbb27b066ecb33dbef9a256dc9d1314adaeff0908a752feba6c34053b40")


def test_github_cli_redirect_allows_only_one_official_release_asset_hop():
    request = release.urllib.request.Request(
        release.GITHUB_CLI_ARCHIVE_URL,
        headers={"Authorization": "Bearer must-not-follow"},
    )
    safe_url = "https://release-assets.githubusercontent.com/github-production-release-asset/exact?sig=1"
    handler = release._GitHubCliRedirect()
    redirected = handler.redirect_request(request, None, 302, "Found", {}, safe_url)
    assert redirected.full_url == safe_url
    assert redirected.get_header("Authorization") is None

    with pytest.raises(release.ReleaseError, match="more than once"):
        handler.redirect_request(request, None, 302, "Found", {}, safe_url)

    with pytest.raises(release.ReleaseError, match="unsafe GitHub CLI release-asset redirect"):
        release._GitHubCliRedirect().redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://attacker.invalid/capture",
        )


def test_github_cli_archive_extracts_only_exact_binary_and_rejects_archive_paths(monkeypatch):
    binary = b"fixture-gh"
    archive = _github_cli_test_archive(binary)
    _pin_github_cli_test_archive(monkeypatch, archive, binary)
    assert release._github_cli_binary_from_archive(archive) == binary

    malicious = _github_cli_test_archive(binary, extra_members=[("../escape", b"x")])
    _pin_github_cli_test_archive(monkeypatch, malicious, binary, entries=2)
    with pytest.raises(release.ReleaseError, match="traversing archive path"):
        release._github_cli_binary_from_archive(malicious)


def test_github_cli_install_is_exclusive_and_revalidates_hash_and_version(monkeypatch, tmp_path: Path):
    binary = b"fixture-gh"
    archive = _github_cli_test_archive(binary)
    _pin_github_cli_test_archive(monkeypatch, archive, binary)
    monkeypatch.setattr(release, "_require_github_cli_platform", lambda: None)
    invocations = []

    def exact_version(argv, *, cwd, env, timeout):
        invocations.append((argv, cwd, env, timeout))
        return (
            f"gh version {release.GITHUB_CLI_VERSION} (2026-07-16)\n"
            f"https://github.com/cli/cli/releases/tag/v{release.GITHUB_CLI_VERSION}\n"
        )

    env = {"RUNNER_TEMP": str(tmp_path)}
    executable = release.install_github_cli(
        environ=env,
        fetch_archive=lambda: archive,
        run_command=exact_version,
    )
    assert executable == tmp_path / release.GITHUB_CLI_INSTALL_DIRECTORY / "gh"
    assert executable.read_bytes() == binary
    assert invocations == [
        (
            [str(executable), "--version"],
            release.ROOT,
            {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "NO_COLOR": "1"},
            30,
        )
    ]

    with pytest.raises(release.ReleaseError, match="already exists"):
        release.install_github_cli(
            environ=env,
            fetch_archive=lambda: archive,
            run_command=exact_version,
        )

    os.chmod(executable.parent, 0o700)
    os.chmod(executable, 0o700)
    executable.write_bytes(b"tamper-gh!")
    os.chmod(executable, 0o500)
    os.chmod(executable.parent, 0o500)
    with pytest.raises(release.ReleaseError, match="SHA-256 mismatch"):
        release._validate_github_cli_executable(executable, run_command=exact_version)

    os.chmod(executable.parent, 0o700)
    os.chmod(executable, 0o700)
    executable.write_bytes(binary)
    os.chmod(executable, 0o500)
    os.chmod(executable.parent, 0o500)
    with pytest.raises(release.ReleaseError, match="exact version"):
        release._validate_github_cli_executable(
            executable,
            run_command=lambda *_args, **_kwargs: "gh version 2.92.0 (2026-01-01)\n",
        )
    os.chmod(executable.parent, 0o700)
    os.chmod(executable, 0o700)


def test_each_github_attestation_command_revalidates_the_controlled_cli(monkeypatch, tmp_path: Path):
    bundle, _ = _bundle(tmp_path)
    manifest = _manifest(bundle)
    validations: list[str] = []
    commands: list[list[str]] = []
    environments: list[dict[str, str]] = []

    def controlled_cli():
        validations.append("validated")
        return "/runner/_temp/compile-code-gh-2.96.0/gh"

    def run(argv, **kwargs):
        commands.append(argv)
        environments.append(kwargs["env"])
        return ""

    monkeypatch.setenv("GH_TOKEN", "g" * 40)
    monkeypatch.setattr(release, "_github_cli_executable", controlled_cli)
    monkeypatch.setattr(release, "_run", run)
    release._verify_build_attestations(bundle, manifest)
    release._verify_immutable_release_attestation(bundle, manifest)

    assert len(commands) == 9
    assert len(validations) == len(commands)
    assert all(command[0] == "/runner/_temp/compile-code-gh-2.96.0/gh" for command in commands)
    assert sum(command[1:3] == ["attestation", "verify"] for command in commands) == 4
    assert sum(command[1:3] == ["release", "verify-asset"] for command in commands) == 4
    assert sum(command[1:3] == ["release", "verify"] for command in commands) == 1
    expected_config_directory = str(Path("/runner/_temp/compile-code-gh-2.96.0/gh").parent)
    assert all(
        environment
        == {
            "GH_CONFIG_DIR": expected_config_directory,
            "GH_HOST": "github.com",
            "GH_NO_UPDATE_NOTIFIER": "1",
            "GH_PROMPT_DISABLED": "1",
            "GH_TOKEN": "g" * 40,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NO_COLOR": "1",
        }
        for environment in environments
    )


def test_release_apis_use_only_the_owner_scoped_read_token(tmp_path: Path, monkeypatch):
    bundle, _ = _bundle(tmp_path)
    documents, payloads = _remote_github(bundle)
    tokens: dict[str, str] = {}

    def api(path: str, allow_not_found: bool, *, token: str | None = None) -> object | None:
        assert token is not None
        tokens[path] = token
        return _github_reader(documents)(path, allow_not_found)

    monkeypatch.setattr(release, "_github_api_json", api)
    assert (
        release._remote_github_release_state(
            bundle,
            expected_source=_source(),
            fetch_bytes=lambda url: payloads[url],
            verify_build_attestations=lambda _bundle, _manifest: None,
            verify_release_attestation=lambda _bundle, _manifest: None,
            environ=_github_environment(),
        )
        == "exact"
    )
    settings_path = f"/repos/{release.REPOSITORY}/immutable-releases"
    release_paths = {
        "/user",
        settings_path,
        f"/repos/{release.REPOSITORY}/environments/{release.RELEASE_GUARD_ENVIRONMENT}",
        f"/repos/{release.REPOSITORY}/environments/{release.RELEASE_GUARD_ENVIRONMENT}/deployment-branch-policies",
        (
            f"/repos/{release.REPOSITORY}/environments/{release.RELEASE_GUARD_ENVIRONMENT}"
            f"/secrets/{release.RELEASE_GUARD_SECRET}"
        ),
        f"/repos/{release.REPOSITORY}/actions/secrets/{release.RELEASE_GUARD_SECRET}",
        f"/repos/{release.REPOSITORY}/releases/tags/v{VERSION}",
        f"/repos/{release.REPOSITORY}/releases?per_page=100&page=1",
    }
    assert release_paths <= tokens.keys()
    assert {tokens.pop(path) for path in release_paths} == {"i" * 40}
    assert tokens and set(tokens.values()) == {"g" * 40}


def test_release_guard_token_must_be_environment_scoped_without_repository_fallback(tmp_path: Path):
    bundle, _ = _bundle(tmp_path)
    documents, payloads = _remote_github(bundle)
    environment_secret_path = (
        f"/repos/{release.REPOSITORY}/environments/{release.RELEASE_GUARD_ENVIRONMENT}"
        f"/secrets/{release.RELEASE_GUARD_SECRET}"
    )
    repository_secret_path = f"/repos/{release.REPOSITORY}/actions/secrets/{release.RELEASE_GUARD_SECRET}"

    missing_environment_secret = copy.deepcopy(documents)
    missing_environment_secret[environment_secret_path] = None
    with pytest.raises(release.ReleaseError, match="environment secret metadata is missing"):
        release._remote_github_release_state(
            bundle,
            expected_source=_source(),
            fetch_json=_github_reader(missing_environment_secret),
            fetch_bytes=lambda url: payloads[url],
            verify_build_attestations=lambda _bundle, _manifest: None,
            verify_release_attestation=lambda _bundle, _manifest: None,
            environ=_github_environment(),
        )

    repository_collision = copy.deepcopy(documents)
    repository_collision[repository_secret_path] = {"name": release.RELEASE_GUARD_SECRET}
    with pytest.raises(release.ReleaseError, match="must not exist at repository scope"):
        release._remote_github_release_state(
            bundle,
            expected_source=_source(),
            fetch_json=_github_reader(repository_collision),
            fetch_bytes=lambda url: payloads[url],
            verify_build_attestations=lambda _bundle, _manifest: None,
            verify_release_attestation=lambda _bundle, _manifest: None,
            environ=_github_environment(),
        )


def test_hash_locked_requirements_have_only_exact_versions_and_sha256_hashes():
    for name in ("tooling-requirements.lock", "build-requirements.lock", "smoke-requirements.lock"):
        text = (ROOT / "release" / name).read_text(encoding="utf-8")
        assert "--index-url" not in text
        assert "--trusted-host" not in text
        assert "git+" not in text
        starts = list(__import__("re").finditer(r"(?m)^([a-z0-9][a-z0-9._-]*)==([^\s;\\]+).*$", text))
        assert starts, name
        for index, match in enumerate(starts):
            block_end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
            block = text[match.start() : block_end]
            assert release.VERSION_RE.fullmatch(match.group(2)) or __import__("re").fullmatch(
                r"(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){1,3}", match.group(2)
            )
            assert "--hash=sha256:" in block


def test_locked_graph_audit_is_stable_complete_and_never_resolves_roam_code():
    queries, provenance = release.locked_requirement_queries(ROOT)
    package_versions = [(query["package"]["name"], query["version"]) for query in queries]
    assert package_versions == sorted(package_versions)
    assert len(package_versions) == release.EXPECTED_LOCKED_VERSION_COUNT == 47
    assert len(package_versions) == len(set(package_versions))
    assert all(query["package"]["ecosystem"] == "PyPI" for query in queries)
    assert "roam-code" not in {name for name, _version in package_versions}
    assert set().union(*map(set, provenance.values())) == {
        "build-requirements.lock",
        "smoke-requirements.lock",
        "tooling-requirements.lock",
    }

    requests: list[bytes] = []

    def clean(payload: bytes) -> object:
        requests.append(payload)
        document = json.loads(payload)
        assert document == {"queries": queries}
        return {"results": [{} for _query in queries]}

    assert release.audit_locked_requirements(ROOT, fetch_json=clean) == len(queries)
    assert requests == [release._canonical_json({"queries": queries})]


def test_locked_graph_audit_reports_vulnerabilities_with_graph_provenance():
    queries, _ = release.locked_requirement_queries(ROOT)
    vulnerable_index = next(index for index, query in enumerate(queries) if query["package"]["name"] == "pip")

    def vulnerable(_payload: bytes) -> object:
        results = [{} for _query in queries]
        results[vulnerable_index] = {"vulns": [{"id": "GHSA-aaaa-bbbb-cccc", "modified": "2026-07-18T00:00:00Z"}]}
        return {"results": results}

    with pytest.raises(
        release.ReleaseError,
        match=r"pip==26\.1\.2:GHSA-aaaa-bbbb-cccc.*(?:build|tooling)-requirements\.lock",
    ):
        release.audit_locked_requirements(ROOT, fetch_json=vulnerable)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda results: results.pop(), "result count mismatch"),
        (lambda results: results[0].update(next_page_token="more"), "incomplete and paginated"),
        (lambda results: results[0].update(unexpected=True), "unknown fields"),
        (lambda results: results[0].update(vulns="not-an-array"), "vulnerabilities must be an array"),
    ],
)
def test_locked_graph_audit_rejects_incomplete_or_malformed_service_results(mutation, message: str):
    queries, _ = release.locked_requirement_queries(ROOT)
    results = [{} for _query in queries]
    mutation(results)
    with pytest.raises(release.ReleaseError, match=message):
        release.audit_locked_requirements(ROOT, fetch_json=lambda _payload: {"results": results})


def test_locked_graph_audit_fails_closed_when_osv_is_unavailable(monkeypatch):
    class UnavailableOpener:
        def open(self, _request, timeout: int):
            assert timeout == 30
            raise release.urllib.error.URLError("service unavailable")

    monkeypatch.setattr(release.urllib.request, "build_opener", lambda *_handlers: UnavailableOpener())
    with pytest.raises(release.ReleaseError, match="OSV audit request failed: service unavailable"):
        release._fetch_osv_batch(b'{"queries":[]}')


def test_locked_graph_exact_query_count_rejects_a_silent_transitive_omission(tmp_path: Path):
    root = _copy_release_locks(tmp_path)
    lock = root / "release" / "tooling-requirements.lock"
    text = lock.read_text(encoding="utf-8")
    mutated, substitutions = __import__("re").subn(
        r"(?ms)^zipp==4\.1\.0.*?(?=^[a-z0-9][a-z0-9._-]*==|\Z)",
        "",
        text,
        count=1,
    )
    assert substitutions == 1
    lock.write_text(mutated, encoding="utf-8")
    with pytest.raises(release.ReleaseError, match="query count must remain exactly 47; got 46"):
        release.locked_requirement_queries(root)


@pytest.mark.parametrize(
    ("filename", "mutation", "message"),
    [
        (
            "build-requirements.in",
            lambda text: text.replace("packaging==26.2", "packaging==26.1", 1),
            "is stale for root packaging==26.1",
        ),
        (
            "build-requirements.lock",
            lambda text: text.replace("packaging==26.2", "packaging>=26.2", 1),
            "unexpected or unpinned requirement syntax",
        ),
        (
            "build-requirements.lock",
            lambda text: text.replace("--hash=sha256:", "--hash=sha512:", 1),
            "unexpected or unpinned requirement syntax",
        ),
        (
            "build-requirements.in",
            lambda text: text + "\nroam-code==13.10.0\n",
            "must not resolve the unpublished roam-code dependency",
        ),
        (
            "build-requirements.lock",
            lambda text: text + "\nroam-code==13.10.0 \\\n    --hash=sha256:" + "0" * 64 + "\n",
            "must not resolve the unpublished roam-code dependency",
        ),
    ],
)
def test_locked_graph_parser_fails_closed_on_stale_unpinned_unhashed_or_roam_inputs(
    tmp_path: Path, filename: str, mutation, message: str
):
    root = _copy_release_locks(tmp_path)
    path = root / "release" / filename
    path.write_text(mutation(path.read_text(encoding="utf-8")), encoding="utf-8")
    with pytest.raises(release.ReleaseError, match=message):
        release.locked_requirement_queries(root)


def test_pypi_state_is_missing_or_exact_and_never_blindly_skips(tmp_path: Path):
    bundle, dist = _bundle(tmp_path)
    assert release._remote_release_state(bundle, dist, fetch_project=lambda: None) == "missing"
    wrong_source = dict(_source(), sha="f" * 40)
    with pytest.raises(release.ReleaseError, match="manifest SHA differs"):
        release._remote_release_state(
            bundle,
            dist,
            expected_source=wrong_source,
            fetch_project=lambda: None,
        )
    project, payloads, provenances = _remote_project(bundle, dist)
    assert (
        release._remote_release_state(
            bundle,
            dist,
            fetch_project=lambda: project,
            fetch_bytes=lambda url: payloads[url],
            fetch_provenance=lambda _version, filename: provenances[filename],
        )
        == "exact"
    )

    assert (
        release._remote_release_state(
            bundle,
            dist,
            fetch_project=lambda: project,
            fetch_bytes=lambda url: payloads[url],
            fetch_provenance=lambda _version, _filename: None,
        )
        == "attestation_pending"
    )

    wrong = copy.deepcopy(payloads)
    first_url = next(iter(wrong))
    wrong[first_url] += b"substitution"
    with pytest.raises(release.ReleaseError, match="exact-byte mismatch"):
        release._remote_release_state(
            bundle,
            dist,
            fetch_project=lambda: project,
            fetch_bytes=lambda url: wrong[url],
            fetch_provenance=lambda _version, filename: provenances[filename],
        )

    extra_project = copy.deepcopy(project)
    extra_project["releases"][VERSION].append(
        {
            "digests": {"sha256": "0" * 64},
            "filename": "compile_code-0.2.0.zip",
            "packagetype": "sdist",
            "size": 1,
            "url": "https://files.pythonhosted.org/packages/test/extra",
            "yanked": False,
        }
    )
    with pytest.raises(release.ReleaseError, match="missing, duplicate, or extra"):
        release._remote_release_state(
            bundle,
            dist,
            fetch_project=lambda: extra_project,
            fetch_provenance=lambda _version, filename: provenances[filename],
        )

    malformed_project = copy.deepcopy(project)
    malformed_project["releases"][VERSION][0]["filename"] = ["not", "a", "filename"]
    with pytest.raises(release.ReleaseError, match="bundle filename must be a string"):
        release._remote_release_state(
            bundle,
            dist,
            fetch_project=lambda: malformed_project,
            fetch_provenance=lambda _version, filename: provenances[filename],
        )

    unsafe_project = copy.deepcopy(project)
    unsafe_project["releases"][VERSION][0]["url"] = "https://attacker.invalid/substitution"
    with pytest.raises(release.ReleaseError, match="unsafe registry URL"):
        release._remote_release_state(
            bundle,
            dist,
            fetch_project=lambda: unsafe_project,
            fetch_bytes=lambda url: payloads[url],
            fetch_provenance=lambda _version, filename: provenances[filename],
        )
    with pytest.raises(release.ReleaseError, match="unsafe registry URL"):
        release._fetch_url("http://files.pythonhosted.org/substitution", max_bytes=1)

    for unsafe_url in (
        "https://pypi.org/path\nheader",
        "https://pypi.org/path\\tail",
        "https://pypi.org/non-ascii-\N{LATIN SMALL LETTER E WITH ACUTE}",
    ):
        with pytest.raises(release.ReleaseError, match="unsafe registry URL"):
            release._validate_registry_url(unsafe_url)


def test_release_asset_urls_and_attestation_base64_are_canonical():
    for unsafe_url in (
        "https://release-assets.githubusercontent.com/path#fragment",
        "https://release-assets.githubusercontent.com/path\nheader",
        "https://release-assets.githubusercontent.com/path\\tail",
        "https://release-assets.githubusercontent.com/non-ascii-\N{LATIN SMALL LETTER E WITH ACUTE}",
    ):
        with pytest.raises(release.ReleaseError, match="unsafe GitHub release-asset URL"):
            release._validate_github_asset_url(unsafe_url, label="GitHub release-asset URL")

    assert release._decode_bounded_base64("YQ==", label="canonical", max_bytes=1) == b"a"
    with pytest.raises(release.ReleaseError, match="not canonical base64"):
        release._decode_bounded_base64("YR==", label="noncanonical", max_bytes=1)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda doc: doc["attestation_bundles"][0]["publisher"].update(repository="attacker/project"),
            "lacks the expected",
        ),
        (
            lambda doc: doc["attestation_bundles"][0]["publisher"].update(workflow="other.yml"),
            "lacks the expected",
        ),
        (
            lambda doc: doc["attestation_bundles"][0]["publisher"].update(environment="other"),
            "lacks the expected",
        ),
        (
            lambda doc: doc["attestation_bundles"][0]["attestations"][0]["verification_material"].update(
                transparency_entries=[]
            ),
            "transparency log evidence is missing",
        ),
        (
            lambda doc: doc["attestation_bundles"][0]["attestations"][0]["envelope"].update(signature="***"),
            "not canonical base64",
        ),
    ],
)
def test_pypi_publish_provenance_identity_and_structure_fail_closed(tmp_path: Path, mutation, message: str):
    bundle, dist = _bundle(tmp_path)
    project, payloads, provenances = _remote_project(bundle, dist)
    candidate = copy.deepcopy(provenances)
    mutation(next(iter(candidate.values())))
    with pytest.raises(release.ReleaseError, match=message):
        release._remote_release_state(
            bundle,
            dist,
            fetch_project=lambda: project,
            fetch_bytes=lambda url: payloads[url],
            fetch_provenance=lambda _version, filename: candidate[filename],
        )


def test_pypi_publish_provenance_binds_each_exact_filename_and_digest(tmp_path: Path):
    bundle, dist = _bundle(tmp_path)
    project, payloads, provenances = _remote_project(bundle, dist)
    filename = next(iter(provenances))
    candidate = copy.deepcopy(provenances)
    attestation = candidate[filename]["attestation_bundles"][0]["attestations"][0]
    statement = json.loads(base64.b64decode(attestation["envelope"]["statement"]))

    for replacement, message in (
        ("substitute.whl", "subject filename mismatch"),
        (filename, "subject SHA-256 mismatch"),
    ):
        mutated = copy.deepcopy(candidate)
        row = mutated[filename]["attestation_bundles"][0]["attestations"][0]
        changed_statement = copy.deepcopy(statement)
        if message.startswith("subject filename"):
            changed_statement["subject"][0]["name"] = replacement
        else:
            changed_statement["subject"][0]["digest"]["sha256"] = "0" * 64
        row["envelope"]["statement"] = base64.b64encode(release._canonical_json(changed_statement)).decode("ascii")
        with pytest.raises(release.ReleaseError, match=message):
            release._remote_release_state(
                bundle,
                dist,
                fetch_project=lambda: project,
                fetch_bytes=lambda url: payloads[url],
                fetch_provenance=lambda _version, name, docs=mutated: docs[name],
            )


def test_pypi_partial_release_and_attestation_pending_states_block(monkeypatch, tmp_path: Path):
    bundle, dist = _bundle(tmp_path)
    project, payloads, provenances = _remote_project(bundle, dist)
    partial = copy.deepcopy(project)
    partial["releases"][VERSION].pop()
    with pytest.raises(release.ReleaseError, match="missing, duplicate, or extra files"):
        release._remote_release_state(
            bundle,
            dist,
            fetch_project=lambda: partial,
            fetch_bytes=lambda url: payloads[url],
            fetch_provenance=lambda _version, filename: provenances[filename],
        )

    monkeypatch.setattr(release, "_remote_release_state", lambda *_args, **_kwargs: "attestation_pending")
    with pytest.raises(release.ReleaseError, match="publish attestations are not yet available"):
        release.pypi_state(bundle, dist, require_exact=False, wait_seconds=0)


def test_actions_artifact_metadata_binds_exact_id_digest_run_and_source():
    digest = "b" * 64
    document = {
        "digest": f"sha256:{digest}",
        "expired": False,
        "id": 42,
        "name": release.GITHUB_WORKFLOW_ARTIFACT_NAME,
        "workflow_run": {"head_sha": SOURCE_SHA, "id": 123456},
    }
    paths: list[str] = []

    def read(path: str, allow_not_found: bool) -> object:
        assert allow_not_found is False
        paths.append(path)
        return copy.deepcopy(document)

    release.verify_github_workflow_artifact(
        artifact_id="42",
        artifact_digest=digest,
        expected_source=_source(),
        environ=_github_environment(),
        fetch_json=read,
    )
    assert paths == [f"/repos/{release.REPOSITORY}/actions/artifacts/42"]

    mutations = (
        (lambda value: value.update(id=43), "ID mismatch"),
        (lambda value: value.update(name="substitution"), "name mismatch"),
        (lambda value: value.update(digest=f"sha256:{'c' * 64}"), "digest mismatch"),
        (lambda value: value.update(expired=True), "expired"),
        (lambda value: value["workflow_run"].update(id=7), "workflow-run ID mismatch"),
        (lambda value: value["workflow_run"].update(head_sha="f" * 40), "source SHA mismatch"),
    )
    for mutation, message in mutations:
        candidate = copy.deepcopy(document)
        mutation(candidate)
        with pytest.raises(release.ReleaseError, match=message):
            release.verify_github_workflow_artifact(
                artifact_id="42",
                artifact_digest=digest,
                expected_source=_source(),
                environ=_github_environment(),
                fetch_json=lambda _path, _missing, value=candidate: value,
            )

    for artifact_id, artifact_digest, message in (
        ("042", digest, "positive integer"),
        ("42;echo", digest, "positive integer"),
        ("42", "B" * 64, "lowercase SHA-256"),
    ):
        with pytest.raises(release.ReleaseError, match=message):
            release.verify_github_workflow_artifact(
                artifact_id=artifact_id,
                artifact_digest=artifact_digest,
                expected_source=_source(),
                environ=_github_environment(),
                fetch_json=read,
            )


def test_github_release_state_is_missing_draft_or_exact_and_verifies_required_attestations(tmp_path: Path):
    bundle, _ = _bundle(tmp_path)
    missing_documents, missing_payloads = _remote_github(bundle, include_release=False)
    calls: list[str] = []
    assert (
        release._remote_github_release_state(
            bundle,
            expected_source=_source(),
            fetch_json=_github_reader(missing_documents),
            fetch_bytes=lambda url: missing_payloads[url],
            verify_build_attestations=lambda _bundle, _manifest: calls.append("build"),
            verify_release_attestation=lambda _bundle, _manifest: calls.append("release"),
            environ=_github_environment(),
        )
        == "missing"
    )
    assert calls == ["build"]

    documents, payloads = _remote_github(bundle)
    manifest = _manifest(bundle)
    release_path = f"/repos/{release.REPOSITORY}/releases/tags/{manifest['tag']}"
    inventory_path = f"/repos/{release.REPOSITORY}/releases?per_page=100&page=1"
    for document in (documents[release_path], documents[inventory_path][0]):
        document.update(draft=True, immutable=False, published_at=None)
    calls.clear()
    assert (
        release._remote_github_release_state(
            bundle,
            expected_source=_source(),
            fetch_json=_github_reader(documents),
            fetch_bytes=lambda url: payloads[url],
            verify_build_attestations=lambda _bundle, _manifest: calls.append("build"),
            verify_release_attestation=lambda _bundle, _manifest: calls.append("release"),
            environ=_github_environment(),
        )
        == "draft_exact"
    )
    assert calls == ["build"]

    documents, payloads = _remote_github(bundle)
    calls.clear()
    assert (
        release._remote_github_release_state(
            bundle,
            expected_source=_source(),
            fetch_json=_github_reader(documents),
            fetch_bytes=lambda url: payloads[url],
            verify_build_attestations=lambda _bundle, _manifest: calls.append("build"),
            verify_release_attestation=lambda _bundle, _manifest: calls.append("release"),
            environ=_github_environment(),
        )
        == "exact"
    )
    assert calls == ["build", "release"]


def test_github_release_draft_is_byte_verified_before_publication(tmp_path: Path):
    bundle, _ = _bundle(tmp_path)
    documents, payloads = _remote_github(bundle)
    manifest = _manifest(bundle)
    release_path = f"/repos/{release.REPOSITORY}/releases/tags/{manifest['tag']}"
    inventory_path = f"/repos/{release.REPOSITORY}/releases?per_page=100&page=1"
    for document in (documents[release_path], documents[inventory_path][0]):
        document.update(draft=True, immutable=False, published_at=None)
    calls: list[str] = []
    details: dict[str, int | str] = {}
    assert (
        release._remote_github_release_state(
            bundle,
            expected_source=_source(),
            required_state="draft",
            details=details,
            fetch_json=_github_reader(documents),
            fetch_bytes=lambda url: payloads[url],
            verify_build_attestations=lambda _bundle, _manifest: calls.append("build"),
            verify_release_attestation=lambda _bundle, _manifest: calls.append("release"),
            environ=_github_environment(),
        )
        == "draft_exact"
    )
    expected_details: dict[str, int | str] = {"release_id": 9}
    roles = {record["filename"]: record["role"] for record in manifest["files"]}
    roles[release.MANIFEST_NAME] = "manifest"
    for asset in documents[release_path]["assets"]:
        role = roles[asset["name"]]
        expected_details[f"{role}_asset_id"] = asset["id"]
        expected_details[f"{role}_asset_digest"] = asset["digest"]
        expected_details[f"{role}_asset_size"] = asset["size"]
    assert details == expected_details
    assert calls == ["build"]


def test_github_draft_outputs_carry_each_exact_asset_id_digest_and_size(tmp_path: Path, monkeypatch):
    bundle, _ = _bundle(tmp_path)
    documents, payloads = _remote_github(bundle)
    manifest = _manifest(bundle)
    release_path = f"/repos/{release.REPOSITORY}/releases/tags/{manifest['tag']}"
    inventory_path = f"/repos/{release.REPOSITORY}/releases?per_page=100&page=1"
    for document in (documents[release_path], documents[inventory_path][0]):
        document.update(draft=True, immutable=False, published_at=None)
    details: dict[str, int | str] = {}
    assert (
        release._remote_github_release_state(
            bundle,
            expected_source=_source(),
            required_state="draft",
            details=details,
            fetch_json=_github_reader(documents),
            fetch_bytes=lambda url: payloads[url],
            verify_build_attestations=lambda _bundle, _manifest: None,
            verify_release_attestation=lambda _bundle, _manifest: None,
            environ=_github_environment(),
        )
        == "draft_exact"
    )
    output = tmp_path / "github-output"
    output.write_bytes(b"")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    release._write_github_release_output("draft_exact", details=details)
    lines = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
    assert lines["release_id"] == "9"
    assert lines["publish_required"] == "true"
    assert set(lines) == {
        "state",
        "release_required",
        "publish_required",
        "release_id",
        *(
            f"{role}_asset_{field}"
            for role in ("wheel", "sdist", "sbom", "manifest")
            for field in ("id", "digest", "size")
        ),
    }


def test_github_release_hidden_exact_draft_recovers_but_mismatch_and_duplicate_fail_closed(tmp_path: Path):
    bundle, _ = _bundle(tmp_path)
    manifest = _manifest(bundle)
    release_path = f"/repos/{release.REPOSITORY}/releases/tags/{manifest['tag']}"
    inventory_path = f"/repos/{release.REPOSITORY}/releases?per_page=100&page=1"

    documents, payloads = _remote_github(bundle)
    draft = copy.deepcopy(documents[release_path])
    assert isinstance(draft, dict)
    draft.update(draft=True, immutable=False, published_at=None)
    del documents[release_path]
    documents[inventory_path] = [draft]
    assert (
        release._remote_github_release_state(
            bundle,
            expected_source=_source(),
            fetch_json=_github_reader(documents),
            fetch_bytes=lambda url: payloads[url],
            verify_build_attestations=lambda _bundle, _manifest: None,
            verify_release_attestation=lambda _bundle, _manifest: None,
            environ=_github_environment(),
        )
        == "draft_exact"
    )

    documents[inventory_path][0]["body"] = "substituted draft"
    with pytest.raises(release.ReleaseError, match="body mismatch"):
        release._remote_github_release_state(
            bundle,
            expected_source=_source(),
            fetch_json=_github_reader(documents),
            fetch_bytes=lambda url: payloads[url],
            verify_build_attestations=lambda _bundle, _manifest: None,
            verify_release_attestation=lambda _bundle, _manifest: None,
            environ=_github_environment(),
        )

    documents, payloads = _remote_github(bundle)
    duplicate = copy.deepcopy(documents[release_path])
    assert isinstance(duplicate, dict)
    duplicate["id"] = 10
    inventory = documents[inventory_path]
    assert isinstance(inventory, list)
    inventory.append(duplicate)
    with pytest.raises(release.ReleaseError, match="duplicate same-tag"):
        release._remote_github_release_state(
            bundle,
            expected_source=_source(),
            fetch_json=_github_reader(documents),
            fetch_bytes=lambda url: payloads[url],
            verify_build_attestations=lambda _bundle, _manifest: None,
            verify_release_attestation=lambda _bundle, _manifest: None,
            environ=_github_environment(),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda docs, manifest: docs["/user"].update(login="attacker"),
            "must belong to Cranot",
        ),
        (
            lambda docs, manifest: docs[f"/repos/{release.REPOSITORY}/immutable-releases"].update(enabled=False),
            "not enabled",
        ),
        (
            lambda docs, manifest: docs[
                f"/repos/{release.REPOSITORY}/environments/{release.RELEASE_GUARD_ENVIRONMENT}"
            ].update(name="substitution"),
            "environment name mismatch",
        ),
        (
            lambda docs, manifest: docs[
                f"/repos/{release.REPOSITORY}/environments/{release.RELEASE_GUARD_ENVIRONMENT}"
            ].update(can_admins_bypass="unknown"),
            "admin-bypass state is malformed",
        ),
        (
            lambda docs, manifest: docs[
                f"/repos/{release.REPOSITORY}/environments/{release.RELEASE_GUARD_ENVIRONMENT}"
            ]["protection_rules"][0].update(prevent_self_review=True),
            "prevent_self_review must remain false",
        ),
        (
            lambda docs, manifest: docs[
                f"/repos/{release.REPOSITORY}/environments/{release.RELEASE_GUARD_ENVIRONMENT}"
            ]["protection_rules"][0]["reviewers"][0]["reviewer"].update(login="attacker"),
            "required reviewer must be Cranot",
        ),
        (
            lambda docs, manifest: docs[
                f"/repos/{release.REPOSITORY}/environments/{release.RELEASE_GUARD_ENVIRONMENT}/deployment-branch-policies"
            ]["branch_policies"][0].update(id=1),
            "policy ID mismatch",
        ),
        (
            lambda docs, manifest: docs[
                f"/repos/{release.REPOSITORY}/environments/{release.RELEASE_GUARD_ENVIRONMENT}/deployment-branch-policies"
            ]["branch_policies"][0].update(name="v0.2.0"),
            "tag pattern mismatch",
        ),
        (
            lambda docs, manifest: docs[
                f"/repos/{release.REPOSITORY}/environments/{release.RELEASE_GUARD_ENVIRONMENT}/deployment-branch-policies"
            ]["branch_policies"][0].update(type="branch"),
            "must target tags",
        ),
        (
            lambda docs, manifest: docs[f"/repos/{release.REPOSITORY}/git/ref/tags/{manifest['tag']}"]["object"].update(
                type="commit"
            ),
            "remain annotated",
        ),
        (
            lambda docs, manifest: docs[f"/repos/{release.REPOSITORY}/git/tags/{manifest['source']['tag_object_sha']}"][
                "object"
            ].update(sha="f" * 40),
            "source SHA mismatch",
        ),
        (
            lambda docs, manifest: docs[f"/repos/{release.REPOSITORY}/releases/tags/{manifest['tag']}"].update(
                draft=True
            ),
            "unexpectedly reports immutable state",
        ),
        (
            lambda docs, manifest: docs[f"/repos/{release.REPOSITORY}/releases/tags/{manifest['tag']}"].update(
                immutable=False
            ),
            "release is mutable",
        ),
        (
            lambda docs, manifest: docs[f"/repos/{release.REPOSITORY}/releases/tags/{manifest['tag']}"][
                "assets"
            ].append(
                {
                    "browser_download_url": f"{release.REPOSITORY_URL}/releases/download/{manifest['tag']}/extra.txt",
                    "digest": f"sha256:{'0' * 64}",
                    "id": 99,
                    "name": "extra.txt",
                    "size": 1,
                    "state": "uploaded",
                }
            ),
            "missing, duplicate, or extra assets",
        ),
        (
            lambda docs, manifest: docs[f"/repos/{release.REPOSITORY}/releases/tags/{manifest['tag']}"]["assets"][
                0
            ].update(digest=f"sha256:{'0' * 64}"),
            "asset digest mismatch",
        ),
        (
            lambda docs, manifest: docs[f"/repos/{release.REPOSITORY}/releases/tags/{manifest['tag']}"]["assets"][
                0
            ].update(state="starter"),
            "not uploaded",
        ),
        (
            lambda docs, manifest: docs[f"/repos/{release.REPOSITORY}/releases/tags/{manifest['tag']}"]["assets"][
                0
            ].update(content_type="text/plain"),
            "content type mismatch",
        ),
        (
            lambda docs, manifest: docs[f"/repos/{release.REPOSITORY}/releases/tags/{manifest['tag']}"]["assets"][
                0
            ].update(size=0),
            "size mismatch",
        ),
        (
            lambda docs, manifest: docs[f"/repos/{release.REPOSITORY}/releases/tags/{manifest['tag']}"]["assets"][
                0
            ].update(browser_download_url="https://attacker.invalid/substitution"),
            "asset URL mismatch",
        ),
        (
            lambda docs, manifest: docs[f"/repos/{release.REPOSITORY}/releases/tags/{manifest['tag']}"]["assets"][
                0
            ].update(url="https://attacker.invalid/substitution"),
            "asset API URL mismatch",
        ),
        (
            lambda docs, manifest: docs[f"/repos/{release.REPOSITORY}/releases/tags/{manifest['tag']}"]["assets"][
                1
            ].update(id=docs[f"/repos/{release.REPOSITORY}/releases/tags/{manifest['tag']}"]["assets"][0]["id"]),
            "asset ID drift",
        ),
        (
            lambda docs, manifest: docs[f"/repos/{release.REPOSITORY}/releases/tags/{manifest['tag']}"]["assets"][
                0
            ].update(id=release.MAX_GITHUB_EXPRESSION_INTEGER + 1),
            "asset ID drift",
        ),
    ],
)
def test_github_release_tag_setting_and_asset_drift_fail_closed(tmp_path: Path, mutation, message: str):
    bundle, _ = _bundle(tmp_path)
    documents, payloads = _remote_github(bundle)
    manifest = _manifest(bundle)
    mutation(documents, manifest)
    with pytest.raises(release.ReleaseError, match=message):
        release._remote_github_release_state(
            bundle,
            expected_source=_source(),
            fetch_json=_github_reader(documents),
            fetch_bytes=lambda url: payloads[url],
            verify_build_attestations=lambda _bundle, _manifest: None,
            verify_release_attestation=lambda _bundle, _manifest: None,
            environ=_github_environment(),
        )


def test_github_release_downloaded_bytes_and_signed_evidence_fail_closed(tmp_path: Path):
    bundle, _ = _bundle(tmp_path)
    documents, payloads = _remote_github(bundle)
    wrong_payloads = copy.deepcopy(payloads)
    first_url = next(iter(wrong_payloads))
    wrong_payloads[first_url] += b"substitution"
    with pytest.raises(release.ReleaseError, match="exact-byte mismatch"):
        release._remote_github_release_state(
            bundle,
            expected_source=_source(),
            fetch_json=_github_reader(documents),
            fetch_bytes=lambda url: wrong_payloads[url],
            verify_build_attestations=lambda _bundle, _manifest: None,
            verify_release_attestation=lambda _bundle, _manifest: None,
            environ=_github_environment(),
        )

    def fail_build(_bundle: Path, _manifest: dict[str, object]) -> None:
        raise release.ReleaseError("build provenance rejected")

    with pytest.raises(release.ReleaseError, match="build provenance rejected"):
        release._remote_github_release_state(
            bundle,
            expected_source=_source(),
            fetch_json=_github_reader(documents),
            fetch_bytes=lambda url: payloads[url],
            verify_build_attestations=fail_build,
            verify_release_attestation=lambda _bundle, _manifest: None,
            environ=_github_environment(),
        )

    def fail_release(_bundle: Path, _manifest: dict[str, object]) -> None:
        raise release.ReleaseError("immutable release attestation rejected")

    with pytest.raises(release.ReleaseError, match="immutable release attestation rejected"):
        release._remote_github_release_state(
            bundle,
            expected_source=_source(),
            fetch_json=_github_reader(documents),
            fetch_bytes=lambda url: payloads[url],
            verify_build_attestations=lambda _bundle, _manifest: None,
            verify_release_attestation=fail_release,
            environ=_github_environment(),
        )

    with pytest.raises(release.ReleaseError, match="positive integer"):
        release._fetch_github_release_asset("not-an-id", token="g" * 40, max_bytes=1)


def test_source_context_binds_annotated_tag_event_sha_and_clean_head(tmp_path: Path):
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "pyproject.toml").write_bytes((ROOT / "pyproject.toml").read_bytes())
    (repository / "source.txt").write_text("source", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(["git", "add", "."], cwd=repository, check=True)
    identity = ["-c", "user.name=Release Test", "-c", "user.email=release@example.invalid"]
    subprocess.run(["git", *identity, "commit", "-qm", "release source"], cwd=repository, check=True)
    subprocess.run(["git", *identity, "tag", "-am", "v0.2.0", "v0.2.0"], cwd=repository, check=True)
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repository, check=True, capture_output=True, text=True
    ).stdout.strip()
    env = {
        "GITHUB_ACTOR": "Cranot",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF": "refs/tags/v0.2.0",
        "GITHUB_REPOSITORY": "Cranot/compile-code",
        "GITHUB_REPOSITORY_OWNER": "Cranot",
        "GITHUB_SHA": sha,
        "GITHUB_TRIGGERING_ACTOR": "Cranot",
    }
    context = release.source_context_from_github(repository, env)
    assert context["sha"] == sha
    assert context["tag"] == "v0.2.0"
    tag_object_sha = subprocess.run(
        ["git", "rev-parse", "refs/tags/v0.2.0^{tag}"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert context["tag_object_sha"] == tag_object_sha
    assert context["tag_object_sha"] != context["sha"]

    injected = dict(env, GITHUB_REF="refs/tags/v0.2.0;echo injected")
    with pytest.raises(release.ReleaseError, match="event ref must be"):
        release.source_context_from_github(repository, injected)

    rerun_by_other_actor = dict(env, GITHUB_TRIGGERING_ACTOR="other-maintainer")
    with pytest.raises(release.ReleaseError, match="triggering actor"):
        release.source_context_from_github(repository, rerun_by_other_actor)

    (repository / "untracked.txt").write_text("dirty", encoding="utf-8")
    with pytest.raises(release.ReleaseError, match="checkout must be clean"):
        release.source_context_from_github(repository, env)
    assert release.source_context_from_github(repository, env, allow_untracked=True)["sha"] == sha

    (repository / "source.txt").write_text("tracked mutation", encoding="utf-8")
    with pytest.raises(release.ReleaseError, match="checkout must be clean"):
        release.source_context_from_github(repository, env, allow_untracked=True)

    subprocess.run(["git", "tag", "-d", "v0.2.0"], cwd=repository, check=True, capture_output=True)
    subprocess.run(["git", "tag", "v0.2.0"], cwd=repository, check=True)
    with pytest.raises(release.ReleaseError, match="annotated tag object"):
        release.source_context_from_github(repository, env, allow_untracked=True)


def test_builder_rejects_publication_credentials():
    with pytest.raises(release.ReleaseError, match="TWINE_PASSWORD"):
        release.assert_unprivileged_runner({"TWINE_PASSWORD": "not-a-real-secret"})
