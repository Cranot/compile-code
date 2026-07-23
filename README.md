<div align="center">

# compile-code

**A compiler for AI coding tasks.**

Pre-resolves the mechanical work — who calls this, what changed recently, what breaks if I touch it, where the bug-site code is — *before* your coding agent's first model token, then verifies the change after it edits. Your agent spends its turns thinking, not grepping.

[![CI](https://github.com/Cranot/compile-code/actions/workflows/ci.yml/badge.svg)](https://github.com/Cranot/compile-code/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub stars](https://img.shields.io/github/stars/Cranot/compile-code?style=flat-square)](https://github.com/Cranot/compile-code/stargazers)

<sub>Works with Claude Code · one command · zero config · local compiler and verifier · zero model calls</sub>

<sub>A thin CLI over the [roam-code](https://github.com/Cranot/roam-code) engine (installed automatically) · 23 intent procedures · 28 languages · zero model calls</sub>

</div>

---

```text
          your prompt
               │
               ▼
   ┌───────────────────────┐   deterministic · <0.5 s · zero model calls
   │       COMPILE         │   callers · git log · blast radius · bug-site source
   └───────────────────────┘
               │   facts injected before the agent's first token
               ▼
   ┌───────────────────────┐
   │      YOUR AGENT       │   edits with the facts already in context
   └───────────────────────┘
               │   after it edits
               ▼
   ┌───────────────────────┐   scoped review over exactly the changed lines
   │        VERIFY         │   returns a fix-or-suppress list before it stops
   └───────────────────────┘
```

## Install and use in 60 seconds

Release `0.2.0` is deliberately dependency-gated. Install it only after
`roam-code 13.10.0` is available on PyPI; the installer resolves that real
dependency in the tested `>=13.10.0,<14` compatibility interval and fails
instead of silently substituting an older or future-major kernel.

```bash
python -m pip install "compile-code==0.2.0"                    # owner-gated PyPI release
# or, after the same tag is published:
python -m pip install "compile-code @ git+https://github.com/Cranot/compile-code.git@v0.2.0"
cd your-repo
compile claude          # index + wire + launch Claude Code, all-in-one
```

The install resolves the `compile` CLI and its roam-code engine together. The
closed compatibility interval makes the command auditable, admits compatible
13.x fixes, and prevents an untested future major from entering the immutable
0.2.0 release.

That's it. From then on, every prompt you type gets compiled facts injected
before the model sees it, and every edit gets a scoped verification after.
Prefer your native workflow? Wire once, then keep typing `claude` like always:

```bash
compile init
compile wire claude     # persistent; `compile unwire claude` to undo
```

Requirements: Python 3.10+, a git repository, and Claude Code for the wired
flow (`compile run` works standalone). The indexer reads 28 languages.

For a one-off navigation prompt, preflight the facts before your agent starts
with broad grep/read setup:

```bash
compile run "who calls handleSave?"
```

That prints the compiled answer envelope up front: callers, file:line citations,
and the answer contract the agent can use instead of re-deriving the basics.

## Why

Coding agents burn most of their turns and tokens *gathering context*:
grepping for the symbol, reading the file, running `git log`, re-deriving
the call graph. All of that is deterministic — a compiler can do it in
well under a second from a local index, with zero model calls, and hand
the agent the answers up front.

## Results

All numbers are head-to-head A/B runs — the identical prompt and repo, with
and without the compiled envelope — on a 300+ KLOC production Python
codebase, June 2026. Medians over repeated runs; negative cells published
alongside the wins.

**Headline (Claude Fable 5, 41-cell A/B, n=2/cell — controlled benchmark, June 2026, roam v13.4):**

| Metric | vanilla | compiled | delta |
|---|---|---|---|
| Agent turns (nav/comprehension, median) | 6 | 1 | **−83%** |
| Input tokens (median/task) | 271K | 53K | **−80%** |
| Cost (median/task) | $1.30 | $0.48 | **−63%** |
| Wall time | — | — | **−50%** |
| Compile overhead per prompt | — | p50 92 ms | — |

A second run on Claude Opus showed the same direction at smaller magnitude
(−33% turns overall on that run; the best single cell reached −88%, but no
aggregate supports more than −33%). Other model tiers (Sonnet, Haiku,
non-Claude agents) have not been
measured on this A/B — the deltas above are measured on the frontier tier and
should not be assumed to transfer. On a ground-truth bug bench (a failing test
must transition to passing — not LLM-judged), the compiled arm fixed **10/10,
as did vanilla, at −13% cost**. Read that honestly: **10/10 vs 10/10 does not
establish quality parity** — at n=10 the 95% interval on the true resolve rate
runs [72%, 100%], and a compiled arm that had genuinely dropped to 90% would
still have shown 10/10 about a third of the time. It means **no quality
difference was detected at a sample size with little power to detect one.**

<details>
<summary><strong>Full benchmark breakdown</strong> — per-task gallery (incl. the published losses), the bug bench, and routing stats</summary>

### Per-task gallery (same bench, median per cell)

| Task | turns | input tokens | cost |
|---|---|---|---|
| "where is `open_db` defined?" | 3 → **1** | 156K → 51K | $0.67 → $0.28 |
| "which files depend on `cli.py`?" | 6 → **1** | 252K → 51K | $1.15 → $0.30 |
| "where is the `ROAM_GREP_ENGINE` env var configured?" | 9 → **1** | 497K → 53K | $1.40 → $0.31 |
| "what are the layers of this codebase?" | 5 → **1** | 271K → 50K | $1.42 → $0.41 |
| "what changed in `cli.py` recently?" | 4 → **2** | 186K → 104K | $0.62 → $0.40 |
| "explain the compiler module's architecture" | 13 → **6** | 618K → 240K | $1.85 → $1.01 |
| "trace how a command becomes an MCP tool" | 12 → **8** | 464K → 303K | $1.25 → $1.01 |
| security-hook comprehension (hard, multi-file) | 6 → **2** | 267K → 117K | $1.15 → $0.56 |
| "what are the biggest cycles in this codebase?" (re-measured 06-11) | 6 → **1** | — | $0.65 → **$0.07** |
| "where is the CLI entry point?" (trivial, re-measured Jun 11) | 1 → 1 | 48K → 50K | $0.21 → $0.22 |
| "write a pytest for X" (generation, re-measured Jun 11) | 5 → 7 | 275K → 396K | $0.61 → **$0.45** |

The last two rows were the honest losses — published as losses, then fixed.
Generation-shaped prompts now get a ~0.6 KB lean envelope (or none), and the
trivial entry-point prompt routes to a pre-answered envelope. Re-measured at
n=3 medians on the same model: generation flipped to a −26% cost / −18% wall
win (expensive output tokens −29%, across more-but-cheaper turns), and the
trivial cell is a tie within noise. The big wins remain comprehension,
navigation, debugging, and review-shaped work.

### Bug-fixing (ground-truth graded)

20-cell bench: planted bugs with real tracebacks, graded by a
failing-test-transitions-to-passing oracle — not LLM-judged.

- **10/10 fixed in both arms — but this is NOT a parity result.** n=10 gives a 95%
  interval of [72%, 100%] on the true resolve rate; a real drop to 90% would still
  show 10/10 roughly a third of the time. Pooling all three graded bug benches we
  have run (28 instances): compiled **23/28 (82%, CI [64%, 92%])** vs vanilla
  **22/28 (79%, CI [61%, 90%])** — the intervals overlap almost entirely.
  **No quality difference has been detected; the data cannot rule out a meaningful
  difference in either direction.** If quality parity matters to your decision, say
  so and we will run a bench large enough to actually test it.
- Compiled arm cost **$5.55 vs $6.41** total (−13%) — the envelope ships the
  bug-site source slice (±12 lines around the cited `path:line`), so the
  typical fix landed within 2 turns instead of a grep-and-read walk.

### Routing, measured on a frozen corpus

Replayed against **723 real prompts** captured from live agent sessions
(re-measured on the June 11 2026 kernel):

- **57% of envelopes ship pre-executed answers** (L1 probes) — the caller
  list, the git history, the env-var location, the blast radius — so the
  agent's first token can be the answer. A further ~33% ship structured
  facts (relevant context, not the literal answer), and the rest are
  freeform tasks that get a skeleton-plus-search envelope instead. (The
  engine repo ships a regression guard for this rate —
  [`tests/test_l1_rate_floor.py`](https://github.com/Cranot/roam-code/blob/main/tests/test_l1_rate_floor.py)
  replays a deterministic 60-prompt subsample of the corpus and fails
  below a 45% L1 floor; it recorded 56.7% at introduction and skips on
  public CI, where the private corpus and index are absent. An earlier
  "91%" wording here counted the facts envelopes as answers, which they
  are not.)
- Compile latency: **p50 0.45 s** cold on the replay harness, **p50 92 ms**
  in live sessions (warm cache). Zero model calls, fully local.
- **Continuously re-checked (latest 2026-07-11, roam 13.7.1):** a daily dogfood
  harness re-measures the envelope on the live codebases — most recent rolling
  cold-compile median = **410 ms** (a separate live-traffic population, not
  the 0.45 s replay-harness figure above). The headline A/B table is the
  June-2026 controlled benchmark.

### The numbers move with the kernel

compile-code 0.2.0 supports `roam-code >= 13.10.0,<14` and picks up compatible
13.x kernel releases — so the published losses above are not static marketing:
each one was attacked in a kernel release and re-measured. The trivial-prompt cell
(+80% cost on v13.4) is a tie on v13.6; the generation cell (+17%) flipped
to a −26% win; the cycles cell went from +56% to **−89%** ($0.65 → $0.07).
The full version-keyed eval history, with raw cells and methodology, lives
in the [roam-code README](https://github.com/Cranot/roam-code#the-compiler--your-agents-first-token-already-knows-the-answer)
and its benchmarks directory — this page keeps only the current,
reproducible numbers.

</details>

## See one

A real envelope, compiled from this repo (`compile run "who calls
_require_index?"`, trimmed):

```text
VERDICT: l1_probe_envelope for structural_callers
procedure:       structural_callers
classifier_conf: 0.85
named_paths:     ['src/compile_code/cli.py', 'tests/test_cli.py']

PREFETCHED ANSWERS (do not re-run the tools that produced these):
  callers: (2 items)
    - {'name': 'claude',  'location': 'src/compile_code/cli.py:131', 'edge': 'call',
       'call_line': 'if not _require_index():',  'call_location': 'src/compile_code/cli.py:145'}
    - {'name': 'doctor',  'location': 'src/compile_code/cli.py:182', 'edge': 'call',
       'call_line': 'indexed = _require_index()', 'call_location': 'src/compile_code/cli.py:190'}
  callers_definition: Callers of `_require_index`. Each entry includes
    `call_line` — the actual calling source line — so you do NOT need to
    re-grep the symbol.
```

The agent receives this *before* its first token. The answer to "who calls
`_require_index`?" is already in its context, with file:line citations and an
answer contract — no grep, no file reads, no tool-call round-trips.

## What gets injected

The compiler classifies your prompt into one of 23 intent procedures
(deterministic regex + a local code graph — no model calls) and pre-executes
the matching probes:

- *"who calls `handleSave`?"* → the caller list, with file:line
- *"what changed in api.py last week?"* → the git log, already filtered
- *"fix the bug in cli.py:45"* → the source around line 45, gutter-numbered
- *"what breaks if I refactor X?"* → blast radius + affected tests
- *"where is the entry point?"* → the `[project.scripts]` console script
- *"compare X vs Y"*, *"top 5 most-imported files"*, *"why is the CLI slow?"*
  → the comparison, the ranking, the hot path — already computed
- unknown/freeform → file skeleton + targeted search, budget-capped
- generation-shaped ("write a test for X") → lean envelope or nothing —
  measured as a loss, so the compiler stays out of the way

Everything arrives as a compact envelope (typically ~10 KB) with an answer contract,
so the agent answers from facts instead of re-deriving them. If a file you
named carries known open findings (complexity, N+1 shapes), the envelope
says so — the agent fixes debt opportunistically instead of re-deriving it.

## After the agent edits

The other half of the loop: when your agent finishes editing, a scoped
review runs over exactly the lines it changed — and comes back as a
fix-or-suppress list the agent resolves before it stops. You see clean
turns; the agent quietly cleans up after itself.

What it catches, in practice:

- a function name that breaks *your* codebase's own convention (learned
  from your production code, not a style guide — test fixtures never vote)
- an import that resolves to nothing — not your code, not the standard
  library (Python stdlib / Node builtins), not anything declared in
  pyproject or package.json. That is the signature of a hallucinated
  dependency, and it FAILs the check with did-you-mean candidates when a
  near-miss exists
- swallowed exceptions, broken syntax, complexity spikes, copy-paste
  duplicates — each disclosed honestly when a sub-check could not run
- a credential-shaped string about to be committed (cloud keys, tokens,
  PEM blocks), plus any pattern your repo declares must never ship
- quadratic loop shapes the algo catalog knows (N+1 queries, re-sorted
  accumulators, `JSON.parse(JSON.stringify(...))` clones) — advisory,
  with a concrete fix sketch

Suppressions are keyed to the symbol, not the line, so they survive
refactors. Prompt optimization remains fail-open, but the launcher refuses to
claim the compile/Verify loop is active unless its hooks are proven wired.
`compile claude --allow-unwired` is the explicit degraded-mode escape hatch;
`compile wire claude --no-verify` is the deliberate persistent opt-out.

These checks are themselves eval-gated: a planted-issues corpus proves
every category catches its canonical positives, and false-positive locks
are dogfooded across three real repos (a Python package, a production
Vue 3 app, a Node/TS server) — no false positives across that corpus,
planted hallucinations caught in both languages.

## Commands

| Command | What it does |
|---|---|
| `compile claude [...]` | Index + prove wiring + launch Claude Code (args pass through; `--allow-unwired` explicitly accepts degraded mode) |
| `compile init` | Index the repo (incremental afterwards; `--force` rebuilds) |
| `compile wire claude` | Persistent wiring; `--user` for all repos, `--no-verify` to skip the post-edit check |
| `compile unwire claude` | Remove the hooks (`--user` for the user-global install) |
| `compile run "task"` | Headless: print the compiled envelope (`--json` for scripts/CI) |
| `compile verify [files...]` | Scoped review of the changed files (`--new-only`, `--diff-only`, `--threshold`); names the next local action on failure |
| `compile baseline [dirs...]` | Snapshot accepted debt for a clean whole-repo tree (refuses a dirty tree) |
| `compile report` | Persist a whole-repo verify report without gating |
| `compile stats` | Routing/latency/cache telemetry for this repo |
| `compile commands` | Print a deterministic inventory of all CLI verbs (for scripts/CI) |
| `compile doctor` | Check toolchain, index, and wiring (project + user-global) |

`compile-code` and `cmpl` are aliases for `compile` if another tool owns
that name on your system.

With no explicit files, `compile verify` discovers the complete worktree scope
itself (staged, unstaged, untracked, renamed, and deleted paths), canonicalizes
that set, and passes explicit root-bound targets to `roam verify`. Only when
discovery yields no bound targets does it use `roam verify --changed` as the
path-free recovery fallback.

## Beyond Claude Code — Codex, MCP, and CI

One-command wiring (`compile wire claude`) targets Claude Code's hook system
today. The compiler itself is **agent-agnostic** — the compiled envelope is
just text, so any agent can consume it right now:

- **Any agent, headless.** `compile run "who calls handleSave?"` prints the
  envelope to stdout. Pipe it into Codex, paste it into a chat, or feed it to
  a CI step — no Claude required. `--json` gives a machine-readable envelope.
- **Codex and other MCP clients.** The kernel ships an MCP server (`roam mcp`,
  from the roam-code dependency). Point Codex — or any MCP-capable client — at
  it and the same graph facts (callers, blast radius, history) are exposed as
  live tools.
- **Roadmap.** A one-command `compile wire codex` (MCP-first) is planned, so
  Codex gets the same before-the-first-token injection Claude has today.

Compile's indexing, prompt precomputation, verification, and local telemetry use
no model API or Compile-managed cloud service. When you launch or feed an
external coding agent, that agent's own client, provider, and privacy policy
govern its network traffic; Compile does not make that traffic local.

## Troubleshooting

`compile doctor` diagnoses the three states that matter: toolchain on PATH,
index present, hooks wired (at either level). Every failure surfaces as a
one-line `VERDICT:` with the fix — never a traceback. Exit codes: `0` ok,
`1` user-fixable state, `2` toolchain missing, `124` timeout.

The supported package interval is `roam-code >= 13.10.0,<14`. Doctor resolves
the exact `roam` executable selected by PATH and reports that executable's path
and version separately from Python package metadata, because a stale
console-script shim can disagree with the installed distribution.

Prompt compilation remains fail-open so an unavailable optimizer never blocks
work. Post-edit verification is fail-closed for edited turns: malformed,
incomplete, or unavailable verifier evidence cannot be reported as a pass.
Uninstall completely with `compile unwire claude && pip uninstall
compile-code roam-code`.

## Release integrity

Releases originate only from an annotated `vX.Y.Z` tag whose target is the
checked-out source SHA and whose version equals `pyproject.toml`. The GitHub
workflow has read-only build permissions, uses full commit pins for every
action, and runs an early source guard that makes wrong-repository,
wrong-owner, unauthorized-rerun, lightweight-tag, version, or checked-out-SHA
drift fail the workflow instead of silently skipping it. It then audits every
exact row in the universal build, smoke, and tooling locks before installing
them, installs a hash-locked toolchain (including `pip`),
builds wheel and sdist twice from `git archive`, normalizes both under
`SOURCE_DATE_EPOCH`, and requires byte-for-byte equality. The release bundle
contains SHA-256 and SHA-512 hashes, matching SRI values, a closed manifest,
and a deterministic CycloneDX SBOM. GitHub build provenance and immutable-release
attestations bind GitHub's files to the tag workflow. For each PyPI distribution,
post-verification also requires the registry's PEP 740 Integrity API to expose a
publish statement for the exact filename and SHA-256 under the
`Cranot/compile-code` / `release.yml` / `pypi` Trusted Publisher identity.

The lock audit is the reproducible, non-resolving equivalent of a `pip-audit`
gate: it parses only the three checked-in uv graphs, requires exact versions,
SHA-256 hashes, matching root inputs, and the canonical universal-generation
command, then submits a sorted package/version query set directly to OSV. It
requires exactly 47 distinct package/version queries and audits every marker
branch without invoking `pip` and without resolving `roam-code`. A vulnerability, stale
or malformed lock, changed query count, unavailable service,
pagination, malformed response, or ignored/incomplete result blocks both
`scripts/check.py` and the release workflow. This avoids the official wrapper's
runtime installation of an open `pip-audit ~=2.0` tool graph.

Before PEP 517 runs, the builder rejects legacy `setup.py`, `setup.cfg`, and
`MANIFEST.in` inputs, validates a closed static `pyproject.toml`, removes the
source tree from the tool launch path, and uses a scrubbed build environment
with package-index access disabled. After the backend returns, only the exact
singly-linked regular wheel and sdist outputs are accepted; directories, links,
and extra files block normalization. Transport verification uses bounded,
no-follow, single-link reads; wheel and sdist must have canonical bytes,
closed entry-point sections, and identical package, Apache-2.0 license, and
core-metadata payloads.

PyPI publication is tokenless and isolated from the builder. OIDC is confined
to GitHub build provenance and PyPI Trusted Publishing; the GitHub Release
publisher receives only `contents: write`. Before tagging, maintainers must
create the `pypi` GitHub Environment, add the owner as its required reviewer,
configure the matching PyPI Trusted Publisher, and enable immutable releases
for the repository. The workflow cannot create those external protections.
PyPI preflight distinguishes a missing release from partial, mismatched, or
attestation-pending state. Exact bytes plus both registry-hosted publish
attestations make reruns idempotent; any partial or conflicting state blocks.
The publisher keeps `skip-existing` disabled so an upload race fails at the
write boundary instead of being silently accepted.

GitHub's immutable-release settings API requires repository
`Administration: read`, which is not available to the built-in workflow token.
Its release-list API also returns drafts only to a user with push access. The
expected external contract is the dedicated `release-guard` GitHub Environment
with one required reviewer, `Cranot`, and `prevent_self_review=false`. It uses
custom deployment policies only (`protected_branches=false` and
`custom_branch_policies=true`) and contains exactly policy ID `55007746`, name
pattern `v*`, type `tag`. This is deliberately an owner-approved gate rather
than a two-person review gate; the workflow separately requires both the tag
actor and rerun actor to be `Cranot` and hard-binds this release to `v0.2.0`.
Administrator bypass is currently enabled; it is not pinned by the contract,
so disabling bypass later is accepted as monotonic hardening.
Store `RELEASE_GUARD_READ_TOKEN` as an environment secret there, with no
repository-level copy. The fine-grained token must belong to the repository
owner, be scoped only to this repository with exactly `Administration: read`
and `Contents: read`, plus `Environments: read` and `Secrets: read` for secret
metadata only, and have an explicit expiration. The three read-only jobs that
consume it are all bound to `release-guard`; each validates the environment
reviewer and exact tag-policy contract through the versioned read-only API,
proves the token's `/user` identity, requires the named environment secret to
exist, and rejects a repository-scoped secret of the same name. Secret values
are never read. The token cannot mutate repository state and never reaches
either publication job.
Those verifier jobs do not trust the GitHub-hosted runner's preinstalled `gh`.
They fetch only the official Linux amd64 GitHub CLI v2.96.0 archive through one
bounded, credential-free GitHub-to-release-CDN redirect, require its exact
14,652,560-byte length and independently checked SHA-256
`83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60`,
and extract only the reviewed `gh` member. The contained executable is separately
bound to SHA-256
`56b8bbbb27b066ecb33dbef9a256dc9d1314adaeff0908a752feba6c34053b40`,
installed at an exclusive absolute path under `RUNNER_TEMP`, and kept outside
`PATH`. Immediately before every attestation or release-verification command,
the verifier rechecks the stable single-link file, size, hash, executable mode,
controlled path, and exact v2.96.0 version output. Any redirect, header, archive,
platform, path, hash, version, 60-second wall-clock deadline, or safe-version
floor drift blocks the release. Network commands receive a minimal fixed `gh`
environment containing only the bounded token, `github.com` host, read-only
config path, noninteractive flags, locale, and color setting; inherited proxy,
host, config, update, and credential-selection variables do not cross the boundary.
The canonical check also runs Zizmor's auditor persona with ignores disabled at
medium severity and above, so an inline suppression cannot silently remove this
environment boundary.

Before the first PyPI publication, an unprivileged gate binds the downloaded
bundle to its exact Actions artifact ID, artifact digest, workflow run, source
SHA, and annotated tag object. It verifies the immutable-release setting and
build attestations, rejects duplicate same-tag releases and any partial or
mismatched draft, and accepts only `missing`, byte-exact resumable `draft_exact`,
or byte-exact immutable `exact` state. For `missing`, the source-free publisher
re-reads the remote tag ref and exact annotated tag object, requires their object
IDs and peeled source commit to match preflight, creates one draft, and attaches
exactly the wheel, sdist, SBOM, and manifest. For `draft_exact`, staging is
skipped so an interrupted run resumes the same release and asset IDs. A separate
read-only job then revalidates the tag, build attestations, every remote asset's
bytes, digest, size and API identity, and the closed four-item draft inventory.
That successful draft proof (or a pre-existing immutable exact release) is a
hard dependency of the PyPI publisher.

PyPI Trusted Publishing runs next. A separate job requires both exact registry
bytes and the registry-hosted PEP 740 statements before GitHub finalization can
start. Only then does the second source-free GitHub job recheck the tag, every
exact asset ID, digest, size, release metadata, and the final four-item draft
inventory before issuing one
exact-ID draft-to-published API transition; it has no create fallback. GitHub's
release PATCH has no conditional-write primitive, so repository permissions
must also exclude concurrent release writers during this final read-to-PATCH
window. Final verification independently requires exact PyPI bytes and publish
attestations, then repeats the GitHub byte checks against immutable state and
verifies the release attestation. A rerun safely resumes an exact draft or skips
an exact immutable release; contradictory, partial, mismatched, duplicate, or
extra state fails closed. This terminal verifier runs after every successful build
and GitHub preflight even when an intermediate publication job failed or was
skipped, so a missing PyPI publication or missing/still-draft GitHub release cannot
produce a green workflow.

Maintainer sequence: publish a compatible `roam-code>=13.10.0,<14` release, run
`python scripts/check.py`, verify the protected `pypi` environment and Trusted
Publisher, immutable releases, and the protected `release-guard` environment
with its read-only owner token;
create the annotated version tag, push that tag, and approve the environment
deployment. Do not create the tag while the dependency-resolving wheel and
sdist smokes are blocked.

For a clean local release checkout, create and activate a virtual environment,
then install the reviewed quality tools from the checked-in hash lock before
running the gate:

```bash
python -m pip install --isolated --no-cache-dir --no-compile --require-hashes --only-binary=:all: -r release/tooling-requirements.lock
python scripts/check.py
```

If the environment already has every other tool, `python scripts/check.py
--bootstrap-zizmor` installs only the exact hash-locked `zizmor==1.27.0` wheel.
The gate resolves zizmor from the active interpreter's configured scripts
directory and verifies its executable against a semantic-digest-pinned trust
manifest derived from every exact lock-listed wheel. It independently checks
the installed wheel RECORD SHA-256 and size, single-link file identity, and
exact reported version before and after both mandatory workflow audits. Paired
executable plus mutable RECORD tampering therefore cannot satisfy the offline
gate. It does not search PATH, accept another version, or downgrade either
audit to an advisory check.

## How it relates to roam-code

The kernel (indexer, code graph, classifier, probes, verify) is the
[roam-code](https://github.com/Cranot/roam-code) toolchain, installed
automatically as a dependency. compile-code is the product surface for the
compile loop — the same relationship as a compiler driver over its toolchain
libraries. Those compiler and verifier operations are local and make zero model
calls; any agent you launch retains its own provider/network boundary.

## License

Apache-2.0 — see [LICENSE](LICENSE). The kernel ([roam-code](https://github.com/Cranot/roam-code)) is Apache-2.0 too.
