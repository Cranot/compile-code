# Gate environment contract

The gates distinguish an unmet runner assumption from a product or repository
failure. `scripts/check.py` performs its complete precondition check before it
starts any quality gate. Release commands perform the narrower checks needed by
that command. GitHub Actions is the supported environment for release-only
network, attestation, and publication jobs.

| Gate | Assumption | Checked before/after |
|---|---|---|
| `scripts/check.py` and the pytest suite | Non-root UID; the suite deliberately tests the product's root refusal. | Checked before pytest; direct pytest exits with an environment-precondition message. |
| `scripts/check.py` | UTF-8 locale, finite wall clock, monotonic deadline clock, writable system temporary directory. | Checked before every quality gate. |
| `scripts/check.py` | `git`, locked Ruff/Pytest versions, locked `pypi-attestations`/`sigstore`, and verified locked `zizmor`. | Git and test tooling are checked before the suite; Zizmor identity is checked before its two audits. CI job: `check`. |
| `scripts/check.py` dependency audit | HTTPS reachability to OSV querybatch. | Checked before the audit; the audit still validates the POST response. CI job: `check`. |
| `scripts/secret_scan.py` and `scripts/prepush_leak_scan.py` | A real Git checkout and readable tracked objects. | Git inventory/range resolution checks after startup and fails closed if unavailable or empty. |
| `release_artifacts.py source` | Git, UTF-8 locale, and a usable clock for the annotated-tag/source binding. | Checked before command work. CI job: `release.build`. |
| `release_artifacts.py build` | Non-root release builder, Git, writable `RUNNER_TEMP`/temporary path and output parents, UTF-8-compatible deterministic environment, and a usable clock. | Checked before command work. CI job: `release.build`. |
| `release_artifacts.py audit-locks` | HTTPS reachability to OSV. | Checked before the audit. CI job: `release.build`. |
| `release_artifacts.py install-smoke` | Writable `--temp-root`, PyPI reachability, and Git for `resolve` mode. | Checked before virtual-environment creation. CI job: `release.build`. |
| `release_artifacts.py pypi-state` | PyPI/GitHub reachability, exact `pypi-attestations` and `sigstore` Python packages, Git when `--github-source` is used, and a usable clock. | Checked before remote-state and Sigstore verification. CI job: `release.prepublish`/`release.postpublish`, which installs the attestation lock. |
| `dev/pin_github_actions.sh --check` | Bash and either a Git checkout or a readable source tree; check mode does not need network or `gh` authentication. | The script resolves the checkout and enumerates files before scanning; CI job: `action-pins`. |
| Release workflow GitHub CLI and shell steps | Linux amd64, writable runner temp, network, `gh`, `jq`, and GitHub Actions-provided identity/permissions. | Script checks platform/temp/network and the pinned `gh`; workflow job supplies and exercises `gh`/`jq`/OIDC. CI jobs: `release.github_release_preflight` and publication jobs. |
| `cosign` | No repository gate invokes this binary. | NO INSTANCES: searched `src`, `scripts`, `tests`, workflows, hooks, README, and packaging metadata with `rg`; no precondition is invented. |
| Clock accuracy and locale beyond the checks above | Sigstore's certificate validity depends on synchronized runner time; the repository cannot prove synchronization offline. | Clock API sanity is checked; synchronization accuracy remains an explicit CI/runner responsibility. Locale is required to resolve to UTF-8. |
