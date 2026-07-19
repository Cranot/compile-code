# Changelog

## 0.2.0 - 2026-07-18

- Binds `compile verify` to one canonical Roam JSON transaction with a fresh nonce, sorted target scope, exact file-byte digest, and closed Verify receipt-v3 validation; duplicate, trailing, skipped, incomplete, contradictory, or oversized evidence fails closed.
- Verifies concrete workspace-external `roam` and Claude executables selected by PATH and requires roam-code 13.10.0 or newer.
- Makes `compile claude` re-prove readiness immediately before launch by structurally validating both hook events, exact commands/files, current hook protocol markers, and the exact Roam producer's canonical-body attestation; degraded launch requires `--allow-unwired` and is disclosed.
- Keeps Roam-owned hook bodies immutable from the Compile layer, rejects symlinked or escaped `.claude`/`.roam` trees, and uses bounded compare-and-swap writes for settings, guidance, and launch markers so repository links cannot redirect mutations.
- Resolves every Roam/Git maintenance subprocess to a concrete workspace-external executable and strips interpreter/Git redirection variables before launch.
- Reports executable and Python metadata versions separately in `compile doctor`.
- Pins and hashes the PEP 517 backend, `pip`, and release toolchain exactly, adopts PEP 639 license metadata, and removes mutable GitHub Action references.
- Adds a source-SHA/tag-bound, owner- and environment-gated PyPI Trusted Publishing workflow with an unprivileged builder and a publisher that checks out no source and contains no repository-controlled run steps.
- Builds wheel and sdist twice, normalizes timestamps and archive metadata, and requires byte-for-byte reproducibility before either artifact can cross jobs.
- Ships a closed release manifest with SHA-256, SHA-512, and SRI values, plus a deterministic CycloneDX SBOM and GitHub/PyPI provenance attestations.
- Adds adversarial artifact/workflow gates for traversal, duplicate keys, substitution, mutable refs, shell expression injection, extra files, lifecycle scripts, and source/version/hash drift.
- Rejects legacy lifecycle inputs before PEP 517 can execute, removes the source checkout from the build tool's initial import path, and builds under a scrubbed environment with package-index access disabled.
- Reads manifests, SBOMs, archives, transported distributions, and control-plane outputs through bounded no-follow single-link checks; requires canonical archive bytes and identical package, license, and core-metadata payloads across wheel and sdist.
- Makes `scripts/check.py` bind pytest to this checkout and fail closed when Git cannot provide the exact tracked inventory, so a clean locked environment cannot accidentally test an older installed wheel or skip privacy/package scans.
- Rebinds transported artifacts to the annotated tag and source SHA before and after publication, makes reruns idempotent only when every remote PyPI distribution is byte-identical and has its expected registry-hosted PEP 740 publish attestation, disables `skip-existing` at the write boundary, and keeps release blocked until clean dependency resolution can install `roam-code>=13.10.0`.
- Adds a pre-PyPI GitHub Release transaction that binds the annotated tag object and exact Actions artifact ID/digest, stages a closed four-asset draft from a source-free `contents: write` job, and byte/API/build-attestation-verifies it before PyPI can publish.
- Safely resumes an exact hidden draft after interruption, rejects partial or mismatched drafts, duplicate same-tag releases, mutable published releases, API-view disagreement, and missing, duplicate, extra, or substituted assets; exact immutable reruns skip finalization.
- Uses a repository-scoped owner token with `Administration: read`, `Contents: read`, `Environments: read`, and metadata-only `Secrets: read` in verifier jobs, proving its `/user` identity, requiring the `release-guard` environment secret, and rejecting a same-name repository secret fallback without exposing values; every consumer is gated by `release-guard` and verifies reviewer `Cranot`, `prevent_self_review=false`, and exact tag policy `55007746` / `v*` / `tag` through the read-only API.
- Audits exactly 47 distinct versions in the universal build, smoke, and tooling locks directly against OSV before tool installation and in the canonical check; stale, omitted, unhashed, malformed, vulnerable, incomplete, or unavailable results fail closed without invoking a resolver or touching the unpublished `roam-code` requirement.
- Rechecks the exact remote annotated tag ref and peeled source commit inside both source-free write jobs, proves the exact resumable draft before the first PyPI write, requires exact PyPI bytes plus PEP 740 evidence, then re-reads every exact asset ID/digest/size and the final four-item inventory before publishing once by exact release ID with no create fallback.
- Replaces runner-managed GitHub CLI use with official v2.96.0 release bytes pinned by independently checked archive and executable SHA-256 values, a one-hop byte/time-bounded credential-free downloader, exclusive runner-temp installation, a minimal fixed command environment, and hash/version/path revalidation before every affected command.
- Makes exact PyPI and immutable GitHub post-verification a terminal fail-closed job after every successful build and release preflight, so an unexpected skipped write step cannot turn a missing registry publication or still-draft release into a green workflow.
- Rejects non-finite or over-nested JSON, preflights ZIP central-directory counts before allocation, streams TAR entry bounds, validates archive member sizes, and restricts PyPI URLs and redirects to HTTPS default-port registry identities without userinfo or fragments.

## 0.1.0 - 2026-07-03

- Initial public release of `compile-code`.
- Adds the CLI wrapper for initializing, wiring, launching, and checking the roam-code toolchain.
- Ships local and cloud polish gates via `scripts/check.py`.
