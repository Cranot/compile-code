from __future__ import annotations

import copy
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

from scripts import release_artifacts as release


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.2.0"
EPOCH = 1_700_000_000
SOURCE_SHA = "1" * 40


def _source(*, sha: str = SOURCE_SHA) -> dict[str, object]:
    return {
        "repository": release.REPOSITORY_URL,
        "sha": sha,
        "tag": f"v{VERSION}",
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
        "Requires-Dist: roam-code>=13.10.0\n"
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


def _remote_project(bundle: Path, dist: Path) -> tuple[dict[str, object], dict[str, bytes]]:
    manifest = _manifest(bundle)
    rows = []
    payloads = {}
    for record in manifest["files"]:
        if record["role"] not in {"wheel", "sdist"}:
            continue
        filename = record["filename"]
        url = f"https://files.pythonhosted.org/packages/test/{filename}"
        payloads[url] = (dist / filename).read_bytes()
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
    return project, payloads


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
    duplicate = original.replace('{"files":', '{"version":"0.2.0","files":', 1)
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


def test_normalized_archives_reject_trailing_bytes_and_noncanonical_encoding(tmp_path: Path):
    bundle, _ = _bundle(tmp_path)
    manifest = _manifest(bundle)
    wheel = next(bundle.glob("*.whl"))
    wheel.write_bytes(wheel.read_bytes() + b"trailing substitution")
    with pytest.raises(release.ReleaseError, match="wheel byte encoding is not canonical"):
        release._inspect_wheel(wheel, manifest)

    bundle, _ = _bundle(tmp_path / "sdist")
    manifest = _manifest(bundle)
    sdist = next(bundle.glob("*.tar.gz"))
    sdist.write_bytes(sdist.read_bytes() + b"trailing substitution")
    with pytest.raises(release.ReleaseError, match="sdist byte encoding is not canonical"):
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
    assert schema["properties"]["source"]["additionalProperties"] is False
    item = schema["properties"]["files"]["items"]
    assert item["additionalProperties"] is False
    assert item["properties"]["hashes"]["additionalProperties"] is False
    assert item["properties"]["sri"]["additionalProperties"] is False
    assert [item["properties"]["role"]["const"] for item in schema["properties"]["files"]["prefixItems"]] == [
        "wheel",
        "sdist",
        "sbom",
    ]
    assert item["allOf"][0]["if"]["properties"]["role"]["const"] == "sbom"
    assert item["allOf"][0]["then"]["properties"]["size"]["maximum"] == release.MAX_JSON_SIZE


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


def test_release_workflow_is_inputless_tokenless_owner_gated_and_publisher_has_no_run():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" not in workflow
    assert "inputs:" not in workflow
    assert "secrets." not in workflow
    assert "github.repository == 'Cranot/compile-code'" in workflow
    assert "github.actor == 'Cranot'" in workflow
    assert "github.triggering_actor == 'Cranot'" in workflow
    assert "environment:\n      name: pypi" in workflow
    assert workflow.count("--github-source") == 3
    assert workflow.count("fetch-depth: 0") == 3
    publish = workflow.split("\n  publish:\n", 1)[1].split("\n  postpublish:\n", 1)[0]
    assert "\n        run:" not in publish
    assert "id-token: write" in publish


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
    project, payloads = _remote_project(bundle, dist)
    assert (
        release._remote_release_state(
            bundle,
            dist,
            fetch_project=lambda: project,
            fetch_bytes=lambda url: payloads[url],
        )
        == "exact"
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
        release._remote_release_state(bundle, dist, fetch_project=lambda: extra_project)

    malformed_project = copy.deepcopy(project)
    malformed_project["releases"][VERSION][0]["filename"] = ["not", "a", "filename"]
    with pytest.raises(release.ReleaseError, match="bundle filename must be a string"):
        release._remote_release_state(bundle, dist, fetch_project=lambda: malformed_project)

    unsafe_project = copy.deepcopy(project)
    unsafe_project["releases"][VERSION][0]["url"] = "https://attacker.invalid/substitution"
    with pytest.raises(release.ReleaseError, match="unsafe registry URL"):
        release._remote_release_state(
            bundle,
            dist,
            fetch_project=lambda: unsafe_project,
            fetch_bytes=lambda url: payloads[url],
        )
    with pytest.raises(release.ReleaseError, match="unsafe registry URL"):
        release._fetch_url("http://files.pythonhosted.org/substitution", max_bytes=1)


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


def test_builder_rejects_publication_credentials():
    with pytest.raises(release.ReleaseError, match="TWINE_PASSWORD"):
        release.assert_unprivileged_runner({"TWINE_PASSWORD": "not-a-real-secret"})
