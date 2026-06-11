# compile-code

**A compiler for AI coding tasks.** It pre-resolves the mechanical work —
who calls this, what changed recently, what breaks if I touch it, where the
bug-site code is — *before* your coding agent's first model token, and
verifies the change after it edits. Your agent spends its turns thinking,
not grepping.

Works with Claude Code today. One command, zero configuration, 100% local —
nothing leaves your machine, no API keys.

## Install and use in 60 seconds

```bash
pip install git+https://github.com/Cranot/compile-code
cd your-repo
compile claude          # index + wire + launch Claude Code, all-in-one
```

(`pip install compile-code` once the PyPI release lands.)

That's it. From then on, every prompt you type gets compiled facts injected
before the model sees it, and every edit gets a scoped verification after.
Prefer your native workflow? Wire once, then keep typing `claude` like always:

```bash
compile init
compile wire claude     # persistent; `compile unwire claude` to undo
```

Requirements: Python 3.10+, a git repository, and Claude Code for the wired
flow (`compile run` works standalone). The indexer reads 28 languages.

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

### Headline (Claude, 41-cell A/B)

| Metric | vanilla | compiled | delta |
|---|---|---|---|
| Agent turns (nav/comprehension, median) | 6 | 1 | **−83%** |
| Input tokens (median/task) | 271K | 53K | **−80%** |
| Cost (median/task) | $1.30 | $0.48 | **−63%** |
| Wall time | — | — | **−50%** |
| Compile overhead per prompt | — | p50 92 ms | — |

The same shape reproduces on Opus (−86% turns on navigation tasks).

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

- **Quality parity: 10/10 fixed in both arms.**
- Compiled arm cost **$5.55 vs $6.41** total (−13%) — the envelope ships the
  bug-site source slice (±12 lines around the cited `path:line`), so the
  typical fix landed within 2 turns instead of a grep-and-read walk.

### Routing, measured on a frozen corpus

Replayed against **723 real prompts** captured from live agent sessions
(re-measured on the June 11 2026 kernel):

- **91% of envelopes ship pre-executed answers** (L1 probes) — the caller
  list, the git history, the env-var location, the blast radius — so the
  agent's first token can be the answer. The other 9% are freeform tasks
  that get a skeleton-plus-search envelope instead.
- Compile latency: **p50 0.45 s** cold on the replay harness, **p50 92 ms**
  in live sessions (warm cache). Zero model calls, fully local.

### The numbers move with the kernel

compile-code pins `roam-code >= 13.5` and picks up every kernel release —
so the published losses above are not static marketing: each one was
attacked in a kernel release and re-measured. The trivial-prompt cell
(+80% cost on v13.4) is a tie on v13.6; the generation cell (+17%) flipped
to a −26% win; the cycles cell went from +56% to **−89%** ($0.65 → $0.07).
The full version-keyed eval history, with raw cells and methodology, lives
in the [roam-code README](https://github.com/Cranot/roam-code#the-compiler--your-agents-first-token-already-knows-the-answer)
and its benchmarks directory — this page keeps only the current,
reproducible numbers.

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
refactors. The whole loop is fail-open: if anything in it breaks, your
agent runs as if compile-code were not installed. `--no-verify` skips it.

These checks are themselves eval-gated: a planted-issues corpus proves
every category catches its canonical positives, and false-positive locks
are dogfooded across three real repos (a Python package, a production
Vue 3 app, a Node/TS server) — zero false positives, planted
hallucinations caught in both languages.

## Commands

| Command | What it does |
|---|---|
| `compile claude [...]` | Index + wire + launch Claude Code (args pass through) |
| `compile init` | Index the repo (incremental afterwards; `--force` rebuilds) |
| `compile wire claude` | Persistent wiring; `--user` for all repos, `--no-verify` to skip the post-edit check |
| `compile unwire claude` | Remove the hooks (`--user` for the user-global install) |
| `compile run "task"` | Headless: print the compiled envelope (`--json` for scripts/CI) |
| `compile stats` | Routing/latency/cache telemetry for this repo |
| `compile doctor` | Check toolchain, index, and wiring (project + user-global) |

`compile-code` and `cmpl` are aliases for `compile` if another tool owns
that name on your system.

## Troubleshooting

`compile doctor` diagnoses the three states that matter: toolchain on PATH,
index present, hooks wired (at either level). Every failure surfaces as a
one-line `VERDICT:` with the fix — never a traceback. Exit codes: `0` ok,
`1` user-fixable state, `2` toolchain missing, `124` timeout.

The hooks are fail-open end to end: if the compiler or verifier ever
breaks, your agent runs exactly as if compile-code weren't installed.
Uninstall completely with `compile unwire claude && pip uninstall
compile-code roam-code`.

## How it relates to roam-code

The kernel (indexer, code graph, classifier, probes, verify) is the
[roam-code](https://github.com/Cranot/roam-code) toolchain, installed
automatically as a dependency. compile-code is the product surface for the
compile loop — the same relationship as a compiler driver over its
toolchain libraries. 100% local, no API keys, nothing leaves your machine.

## License

Apache-2.0
