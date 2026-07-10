# AGENTS.md — compile-code development guide

compile-code is the product CLI over the roam-code compile/verify kernel
(`compile claude` = index + wire + launch). Small by design: the kernel
lives in the `roam-code` dependency; this repo owns the product surface.

## The pipeline — every commit ships polished

`python3 scripts/check.py` is the gate: ruff check, ruff format --check,
the full test suite, a leak scan (credentials, VPS paths, private memo
references), and README sanity (the install command must stay true).
It runs automatically on push via `.githooks/pre-push` — enable hooks once
per clone:

```bash
git config core.hooksPath .githooks
```

`.githooks/commit-msg` rejects attribution/assistant references in commit
messages. Bypass any hook only deliberately (`git push --no-verify`) and
say why in the commit body.

## History policy

Normal, well-scoped commits — no squashing, no history rewrites. The
repo's first day used a single squashed commit while the surface settled;
that period is over. Each commit message explains the why, not just the
what.

## Conventions

- Python 3.10+, `from __future__ import annotations`, ruff (line length 120).
- The CLI must never traceback at the product surface: every toolchain
  failure becomes a one-line `VERDICT:` with a copy-paste fix. Exit codes:
  0 ok, 1 user-fixable, 2 toolchain missing, 124 timeout, 130 interrupted.
- Tests are CliRunner-based with the toolchain stubbed (`_roam`
  monkeypatched); failure paths are first-class test subjects.
- README numbers come from the roam-code eval ledger — update them when the
  kernel re-measures, never invent.

## Releases

GitHub is the source of truth. PyPI publish is owner-gated (no token on the
dev box). The roam-code dependency floor (`>=13.7.0`) only moves when the CLI
actually requires a newer kernel feature.
