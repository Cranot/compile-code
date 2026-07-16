# Changelog

## 0.2.0 - 2026-07-17

- Makes `compile verify` delegate the canonical complete worktree scope and reject empty, malformed, skipped, or stale verifier protocols.
- Verifies the exact `roam` executable selected by PATH and requires roam-code 13.10.0 or newer.
- Makes `compile claude` fail closed when hook wiring cannot be proven; degraded launch requires `--allow-unwired`.
- Reports executable and Python metadata versions separately in `compile doctor`.

## 0.1.0 - 2026-07-03

- Initial public release of `compile-code`.
- Adds the CLI wrapper for initializing, wiring, launching, and checking the roam-code toolchain.
- Ships local and cloud polish gates via `scripts/check.py`.
