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
- Rejects legacy lifecycle inputs before PEP 517 can execute, removes the source checkout from the build tool's initial import path, and builds under a closed, networkless environment.
- Reads manifests, SBOMs, archives, transported distributions, and control-plane outputs through bounded no-follow single-link checks; requires canonical archive bytes and identical package, license, and core-metadata payloads across wheel and sdist.
- Makes `scripts/check.py` bind pytest to this checkout and fail closed when Git cannot provide the exact tracked inventory, so a clean locked environment cannot accidentally test an older installed wheel or skip privacy/package scans.
- Rebinds transported artifacts to the annotated tag and source SHA before and after publication, makes reruns idempotent only when every remote PyPI distribution is byte-identical, and keeps release blocked until clean dependency resolution can install `roam-code>=13.10.0`.

## 0.1.0 - 2026-07-03

- Initial public release of `compile-code`.
- Adds the CLI wrapper for initializing, wiring, launching, and checking the roam-code toolchain.
- Ships local and cloud polish gates via `scripts/check.py`.
