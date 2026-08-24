#!/usr/bin/env python3
"""Build the source-derived Roam wiring coverage denominator.

The command inventory and the four channel sets come from the resolved
``roam-code`` sources.  The one deliberately human-owned part is
``COMMAND_CLASSIFICATION_ROWS``: whether a command matters while changing code
and which failure classes it addresses are judgment calls.  Completeness is
fail-closed so a new Roam command cannot silently disappear from the report.

Run ``python scripts/build_wiring_coverage.py --write`` to regenerate the
document, or pass ``--check`` to check the checked-in copy.
"""

from __future__ import annotations

import argparse
import ast
import importlib.metadata as importlib_metadata
import inspect
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "WIRING_COVERAGE.md"
CHANNEL_ORDER = ("CONTEXT", "VERIFY", "HOOK", "MCP")


class CoverageError(RuntimeError):
    """A source registry or declared classification is incomplete."""


@dataclass(frozen=True)
class FailureClass:
    title: str
    impact: int
    description: str


@dataclass(frozen=True)
class CommandClassification:
    edit_relevant: bool
    failure_classes: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class CoverageReport:
    roam_version: str
    inventory: frozenset[str]
    channels: dict[str, frozenset[str]]
    classifications: dict[str, CommandClassification]


# The failure taxonomy is inherited from the July denominator so state changes
# remain comparable. Impact is 1 (localized) through 5 (can ship a broken,
# unsafe, or irrecoverable change).
FAILURE_CLASSES: dict[str, FailureClass] = {
    "F1": FailureClass("Hallucinated API", 5, "A call or import names a symbol that does not exist."),
    "F2": FailureClass("Broke an importer or caller", 5, "A signature or public contract changes incompatibly."),
    "F3": FailureClass("Silent behavioral regression", 5, "Static checks pass while runtime behavior regresses."),
    "F4": FailureClass("Local convention violation", 3, "The edit violates repository-specific conventions."),
    "F5": FailureClass("Missed coupled code", 4, "Related code that needed a companion edit is missed."),
    "F6": FailureClass("Security regression", 5, "The change weakens authorization, secrecy, or data-flow safety."),
    "F7": FailureClass(
        "Performance regression", 4, "The edit introduces N+1, indexing, fetching, or algorithmic cost."
    ),
    "F8": FailureClass("Deleted but still referenced", 5, "A delete or rename leaves live dangling references."),
    "F9": FailureClass("Missing or insufficient test", 5, "Changed behavior lacks an observing test."),
    "F10": FailureClass(
        "Non-idempotent or transaction-unsafe operation", 5, "Retries or partial failure corrupt state."
    ),
    "F11": FailureClass("Duplicated existing code", 4, "A clone is introduced instead of reusing existing code."),
    "F12": FailureClass("Documentation or contract drift", 3, "Documentation or declared contracts diverge from code."),
    "F13": FailureClass("Magic numbers", 3, "Hardcoded constants obscure or duplicate policy."),
    "F14": FailureClass(
        "Import-time side effects or orphan imports", 5, "Imports fail or trigger unintended behavior."
    ),
    "F15": FailureClass(
        "Cycle or layering violation", 4, "The edit creates a cycle or crosses an architecture boundary."
    ),
    "F16": FailureClass("Complexity growth", 3, "A component becomes structurally difficult to reason about."),
    "F17": FailureClass("Dead code introduced", 3, "The edit leaves unreachable or unused implementation behind."),
    "F18": FailureClass("Fragile-file edit", 4, "A high-risk or low-ownership file is changed carelessly."),
    "F19": FailureClass("Blast-radius unawareness", 5, "The edit proceeds without understanding downstream impact."),
    "F20": FailureClass("Syntax error introduced", 5, "Changed source no longer parses."),
    "F21": FailureClass("Error-handling anti-pattern", 4, "Errors are swallowed or handled too broadly."),
    "F22": FailureClass(
        "LLM-integration anti-pattern", 4, "LLM-facing code uses unsafe or brittle integration patterns."
    ),
    "F23": FailureClass("AI rot or vibe", 3, "Generated-code quality decay survives review."),
    "F24": FailureClass(
        "Governance or custom-rule violation", 5, "Repository rules or architecture budgets are violated."
    ),
    "F25": FailureClass("Test hermeticity", 4, "A test depends on time, network, randomness, or ambient state."),
    "F26": FailureClass("Broken invariant", 5, "An implicit contract relied on by callers is broken."),
    "F27": FailureClass("Type-annotation regression", 4, "Type surface or annotation coverage regresses."),
}


def _c(edit_relevant: bool, failure_classes: str, reason: str) -> CommandClassification:
    return CommandClassification(edit_relevant, tuple(failure_classes.split()) if failure_classes else (), reason)


# Every built-in Roam command is named exactly once.  Repeated reasons are
# intentional where commands are aliases or members of the same operational
# family; the command remains an explicit review unit rather than inheriting a
# wildcard classification.
COMMAND_CLASSIFICATION_ROWS = (
    ("adrs", _c(False, "", "Excluded from the edit denominator: ADR discovery/linking (governance docs).")),
    ("adversarial", _c(True, "F19", "Challenges a change for architectural and security failure modes.")),
    (
        "affected",
        _c(False, "", "Excluded from the edit denominator: diff->affected files; subsumed by impact (wired)."),
    ),
    ("affected-tests", _c(True, "F3", "Selects tests capable of observing the edited target.")),
    ("agent-context", _c(False, "", "Excluded from the edit denominator: agent collaboration state.")),
    ("agent-export", _c(False, "", "Excluded from the edit denominator: AI agent context-file gen.")),
    ("agent-opt", _c(False, "", "Excluded from the edit denominator: agent-contract surface optimizer (meta).")),
    ("agent-plan", _c(False, "", "Excluded from the edit denominator: work decomposition.")),
    ("agent-score", _c(False, "", "Excluded from the edit denominator: agent run scoring.")),
    ("agents-md", _c(False, "", "Excluded from the edit denominator: AGENTS.md generator.")),
    ("ai-ratio", _c(False, "", "Excluded from the edit denominator: estimate %% AI code (reporting).")),
    ("ai-readiness", _c(False, "", "Excluded from the edit denominator: AI-readiness reporting.")),
    ("alerts", _c(False, "", "Excluded from the edit denominator: health-degradation trends.")),
    ("algo", _c(True, "F7", "Finds algorithmic anti-patterns and inefficient implementations.")),
    ("annotate", _c(False, "", "Excluded from the edit denominator: persistent note write.")),
    ("annotations", _c(False, "", "Excluded from the edit denominator: note list.")),
    ("api", _c(True, "F2", "Maps public API consumers and compatibility-sensitive surface.")),
    (
        "api-changes",
        _c(False, "", "Excluded from the edit denominator: API change report; subsumed by breaking (wired)."),
    ),
    ("api-drift", _c(True, "F12", "Detects drift between documented and implemented API surface.")),
    ("architecture-drift", _c(False, "", "Excluded from the edit denominator: trend report.")),
    ("article-12-check", _c(False, "", "Excluded from the edit denominator: EU AI Act compliance.")),
    ("ask", _c(False, "", "Excluded from the edit denominator: free-form recipe dispatch (meta).")),
    ("at", _c(False, "", "Excluded from the edit denominator: navigation: code at file:line (subsumed by envelope).")),
    ("attest", _c(False, "", "Excluded from the edit denominator: PR attestation (compliance).")),
    ("audit", _c(False, "", "Excluded from the edit denominator: one-shot architecture audit (reporting).")),
    ("audit-trail-conformance-check", _c(False, "", "Excluded from the edit denominator: compliance.")),
    ("audit-trail-export", _c(False, "", "Excluded from the edit denominator: compliance.")),
    ("audit-trail-verify", _c(False, "", "Excluded from the edit denominator: compliance.")),
    ("auth-gaps", _c(True, "F6", "Finds routes or handlers missing expected authorization checks.")),
    ("batch-search", _c(False, "", "Excluded from the edit denominator: navigation/search (subsumed by grep wired).")),
    ("bench-compile", _c(False, "", "Excluded from the edit denominator: A/B benchmark harness.")),
    ("bisect", _c(False, "", "Excluded from the edit denominator: degradation bisect (reporting).")),
    ("blame-reviewers", _c(False, "", "Identifies knowledgeable reviewers for a fragile edit area.")),
    ("boundary", _c(True, "F15", "Finds forbidden dependency direction and accidental public surface.")),
    ("breaking", _c(True, "F2 F12", "Detects signature and exported-surface breakage.")),
    ("brief", _c(False, "", "Excluded from the edit denominator: agent briefing (comprehension).")),
    ("budget", _c(True, "F24", "Checks whether a change exceeds declared resource or risk budgets.")),
    ("bus-factor", _c(True, "F18", "Surfaces ownership concentration before a risky edit.")),
    ("calc-golden", _c(True, "F3 F26", "Checks calculation output against golden semantic cases.")),
    ("calc-inventory", _c(True, "F26", "Inventories calculations whose semantics an edit must preserve.")),
    ("calc-probe", _c(True, "F3 F26", "Executes calculation probes to catch semantic divergence.")),
    ("capabilities", _c(False, "", "Excluded from the edit denominator: capability registry (meta).")),
    ("capsule", _c(False, "", "Excluded from the edit denominator: graph export.")),
    ("causal-graph", _c(True, "F6", "Maps causal dependencies and effects that an edit may disturb.")),
    ("cga", _c(False, "", "Excluded from the edit denominator: code graph attestation (compliance).")),
    ("changelog", _c(False, "", "Excluded from the edit denominator: commit list.")),
    ("check-rules", _c(True, "F24", "Evaluates repository rules and invariants against the edit.")),
    ("churn", _c(False, "", "Excluded from the edit denominator: deprecated->weather (reporting).")),
    ("ci-setup", _c(False, "", "Excluded from the edit denominator: CI config gen.")),
    ("clean", _c(False, "", "Excluded from the edit denominator: index maintenance.")),
    ("clones", _c(True, "F11", "Finds clone siblings that may require the same edit.")),
    ("closure", _c(False, "", "Excluded from the edit denominator: transitive closure (graph navigation).")),
    ("clusters", _c(False, "", "Excluded from the edit denominator: graph clustering (reporting).")),
    ("codeowners", _c(False, "", "Excluded from the edit denominator: ownership coverage.")),
    ("commands", _c(False, "", "Excluded from the edit denominator: list repo runnable commands (meta).")),
    ("compare", _c(False, "", "Excluded from the edit denominator: cross-index structural diff (reporting).")),
    ("compatibility", _c(True, "F2", "Checks version and consumer compatibility across a change.")),
    ("compile", _c(False, "", "Excluded from the edit denominator: the compile entrypoint itself (the consumer).")),
    ("compile-cache", _c(False, "", "Excluded from the edit denominator: cache mgmt.")),
    ("compile-daemon", _c(False, "", "Runs compiler infrastructure rather than validating code changes.")),
    ("compile-stats", _c(False, "", "Excluded from the edit denominator: telemetry.")),
    ("compiler-corpus", _c(False, "", "Excluded from the edit denominator: eval harness.")),
    ("compiler-health", _c(False, "", "Excluded from the edit denominator: telemetry.")),
    ("complete", _c(False, "", "Excluded from the edit denominator: shell completion (meta).")),
    ("complexity", _c(True, "F16", "Detects complexity growth in edited code.")),
    ("config", _c(False, "", "Excluded from the edit denominator: config mgmt.")),
    ("congestion", _c(False, "", "Excluded from the edit denominator: developer congestion (PM).")),
    ("constitution", _c(False, "", "Excluded from the edit denominator: agent constitution (governance meta).")),
    (
        "context",
        _c(
            False,
            "",
            "Excluded from the edit denominator: roam context; the core primitive the compile envelope productizes.",
        ),
    ),
    ("conventions", _c(True, "F4", "Derives local naming and implementation conventions.")),
    ("coupling", _c(True, "F5", "Finds temporal and structural partners an edit may need to update.")),
    ("coverage-gaps", _c(True, "F6", "Finds production code lacking executable coverage.")),
    ("critique", _c(True, "F2", "Reviews a patch for missed clone siblings and high blast radius.")),
    ("cut", _c(True, "F15", "Finds architectural cut points for a contained refactor.")),
    ("cycle-break", _c(True, "F15", "Plans changes that remove dependency cycles safely.")),
    ("cycles", _c(True, "F15", "Detects dependency cycles introduced or worsened by an edit.")),
    ("dark-matter", _c(False, "", "Excluded from the edit denominator: dark/untested code report (reporting).")),
    ("dashboard", _c(False, "", "Excluded from the edit denominator: status dashboard (reporting).")),
    ("db-check", _c(False, "", "Excluded from the edit denominator: index integrity.")),
    ("dead", _c(True, "F17", "Finds dead exports and code orphaned by an edit.")),
    ("debt", _c(True, "F18", "Surfaces debt hotspots that increase edit risk.")),
    ("delete-check", _c(True, "F8", "Blocks deletions that retain live references.")),
    ("deps", _c(True, "F5", "Maps dependencies affected by code or package changes.")),
    ("describe", _c(False, "", "Excluded from the edit denominator: project description gen.")),
    ("dev-profile", _c(False, "", "Excluded from the edit denominator: developer metrics (PM).")),
    ("diagnose", _c(True, "F3", "Finds likely root causes for a reported failure.")),
    ("dict-consistency", _c(True, "F26", "Detects inconsistent parallel dictionary or mapping definitions.")),
    (
        "diff",
        _c(False, "", "Excluded from the edit denominator: diff blast radius; subsumed by impact/edit_blast (wired)."),
    ),
    ("digest", _c(False, "", "Excluded from the edit denominator: deprecated->trends.")),
    ("disambiguate", _c(False, "", "Excluded from the edit denominator: navigation.")),
    ("dispatch-trace", _c(False, "", "Excluded from the edit denominator: classifier debug (meta).")),
    ("doc-staleness", _c(True, "F12", "Finds documentation made stale by a code change.")),
    ("docs-coverage", _c(True, "F12", "Finds public code surface without matching documentation.")),
    ("docs-index", _c(False, "", "Excluded from the edit denominator: orphaned-memo finder (docs).")),
    ("doctor", _c(False, "", "Excluded from the edit denominator: env diagnosis.")),
    ("dogfood", _c(False, "", "Excluded from the edit denominator: eval.")),
    ("dogfood-aggregate", _c(False, "", "Excluded from the edit denominator: eval.")),
    ("drift", _c(False, "", "Excluded from the edit denominator: ownership drift (PM).")),
    ("duplicates", _c(True, "F11", "Detects duplicate implementations introduced or left inconsistent.")),
    ("effects", _c(True, "F21", "Traces downstream effects of a changed symbol.")),
    (
        "endpoints",
        _c(False, "", "Excluded from the edit denominator: endpoint listing (comprehension; feeds auth-gaps gap)."),
    ),
    ("entry-points", _c(True, "F19", "Finds executable entry paths that can reach changed code.")),
    ("envelope-diff", _c(False, "", "Excluded from the edit denominator: compile envelope debug (meta).")),
    ("eval-retrieve", _c(False, "", "Excluded from the edit denominator: retrieval eval harness.")),
    ("evidence-diff", _c(False, "", "Excluded from the edit denominator: compliance.")),
    ("evidence-doctor", _c(False, "", "Excluded from the edit denominator: compliance.")),
    ("evidence-oscal", _c(False, "", "Excluded from the edit denominator: compliance.")),
    ("exit-codes", _c(False, "", "Excluded from the edit denominator: meta.")),
    ("explain-command", _c(False, "", "Excluded from the edit denominator: meta.")),
    (
        "fan",
        _c(False, "", "Excluded from the edit denominator: fan-in/out connectivity (reporting; subsumed by impact)."),
    ),
    ("file", _c(False, "", "Excluded from the edit denominator: navigation (subsumed by envelope).")),
    (
        "findings",
        _c(
            False,
            "",
            "Excluded from the edit denominator: findings registry view (consumed indirectly by known_findings probe).",
        ),
    ),
    ("fingerprint", _c(False, "", "Excluded from the edit denominator: cross-repo topology.")),
    ("fitness", _c(True, "F24", "Evaluates declared architectural fitness rules.")),
    ("flag-dead", _c(True, "F17", "Marks dead code that may be safely removed after review.")),
    ("fleet", _c(False, "", "Excluded from the edit denominator: parallel-work planning.")),
    ("fn-coupling", _c(True, "F5", "Finds function-level coupling partners for an edit.")),
    ("forecast", _c(False, "", "Excluded from the edit denominator: trend prediction.")),
    ("graph-diff", _c(False, "", "Excluded from the edit denominator: snapshot graph diff.")),
    ("graph-export", _c(False, "", "Excluded from the edit denominator: export.")),
    ("graph-stats", _c(False, "", "Excluded from the edit denominator: graph stats (reporting).")),
    ("grep", _c(True, "F1", "Finds literal references and configuration mentions relevant to an edit.")),
    ("guard", _c(True, "F2", "Combines callers, tests, and risk before a symbol edit.")),
    ("guard-clean", _c(False, "", "Excluded from the edit denominator: guard infra.")),
    ("guard-diff", _c(False, "", "Excluded from the edit denominator: guard infra.")),
    ("guard-doctor", _c(False, "", "Excluded from the edit denominator: guard infra.")),
    ("guard-history", _c(False, "", "Excluded from the edit denominator: guard infra.")),
    ("guard-init", _c(False, "", "Excluded from the edit denominator: guard infra.")),
    (
        "guard-pr",
        _c(
            False,
            "",
            "Excluded from the edit denominator: full guard pipeline (aggregate of critique+verify; see critique gap).",
        ),
    ),
    ("guard-rules", _c(False, "", "Excluded from the edit denominator: rule-pack mgmt.")),
    ("health", _c(False, "", "Excluded from the edit denominator: reporting.")),
    ("help-search", _c(False, "", "Excluded from the edit denominator: meta.")),
    ("history-grep", _c(True, "F12", "Finds when and why a relevant symbol or behavior changed.")),
    ("hooks", _c(False, "", "Excluded from the edit denominator: the hooks installer itself (the channel).")),
    (
        "hotspots",
        _c(False, "", "Excluded from the edit denominator: static-vs-runtime hotspots; subsumed by why_slow (wired)."),
    ),
    ("hover", _c(False, "", "Excluded from the edit denominator: navigation.")),
    ("idempotency", _c(True, "F10", "Classifies whether retrying edited behavior can duplicate effects.")),
    ("ignore-drift", _c(True, "F12", "Detects ignore-policy drift that can hide files from checks.")),
    ("impact", _c(True, "F19", "Measures the blast radius of a proposed or completed change.")),
    ("index", _c(False, "", "Excluded from the edit denominator: infra.")),
    ("index-export", _c(False, "", "Excluded from the edit denominator: infra.")),
    ("index-import", _c(False, "", "Excluded from the edit denominator: infra.")),
    ("index-stats", _c(False, "", "Excluded from the edit denominator: infra.")),
    ("ingest-trace", _c(False, "", "Excluded from the edit denominator: runtime trace ingest (infra).")),
    ("init", _c(False, "", "Excluded from the edit denominator: infra.")),
    ("intent", _c(True, "F12", "Links declared intent to implementation so drift can be detected.")),
    ("intent-check", _c(False, "", "Excluded from the edit denominator: mode permission check.")),
    ("invariants", _c(True, "F26", "Surfaces implicit contracts depended on by callers.")),
    ("laws", _c(False, "", "Excluded from the edit denominator: constitution installer.")),
    ("layers", _c(True, "F15", "Maps layer boundaries that an edit must respect.")),
    ("lease", _c(False, "", "Excluded from the edit denominator: work coordination.")),
    ("llm-smells", _c(True, "F22", "Detects unsafe and fragile language-model API patterns.")),
    ("lsp", _c(False, "", "Excluded from the edit denominator: language-server infra.")),
    ("magic-numbers", _c(True, "F13", "Detects unexplained constants introduced by edits.")),
    ("map", _c(False, "", "Excluded from the edit denominator: skeleton (comprehension).")),
    ("math", _c(False, "", "Excluded from the edit denominator: deprecated->algo.")),
    ("mcp", _c(False, "", "Excluded from the edit denominator: MCP server (the channel).")),
    ("mcp-setup", _c(False, "", "Excluded from the edit denominator: MCP setup (channel).")),
    ("mcp-status", _c(False, "", "Excluded from the edit denominator: MCP status.")),
    ("memory", _c(False, "", "Excluded from the edit denominator: agent memory infra.")),
    ("metrics", _c(False, "", "Excluded from the edit denominator: metrics view.")),
    ("metrics-push", _c(False, "", "Excluded from the edit denominator: telemetry push.")),
    ("migration-plan", _c(True, "F10", "Plans ordered data and schema changes before implementation.")),
    ("migration-safety", _c(True, "F10", "Detects unsafe or irreversible migration operations.")),
    ("minimap", _c(False, "", "Excluded from the edit denominator: CLAUDE.md minimap.")),
    ("missing-index", _c(True, "F7", "Finds missing database indexes that can make an edit regress performance.")),
    ("mode", _c(False, "", "Excluded from the edit denominator: mode mgmt.")),
    ("module", _c(False, "", "Excluded from the edit denominator: navigation.")),
    ("mutate", _c(False, "", "Excluded from the edit denominator: agentic edit ACTION (not a detector).")),
    ("n1", _c(True, "F7", "Detects N+1 data-access patterns introduced or exposed by edits.")),
    ("next", _c(False, "", "Excluded from the edit denominator: suggest-next-command (meta).")),
    ("observability-opt", _c(True, "F21", "Finds missing or inefficient observability around changed behavior.")),
    ("onboard", _c(False, "", "Excluded from the edit denominator: deprecated->understand.")),
    ("oracle", _c(False, "", "Excluded from the edit denominator: boolean oracles container (meta).")),
    ("orchestrate", _c(False, "", "Excluded from the edit denominator: workflow coordination.")),
    ("orphan-imports", _c(True, "F14", "Finds imports orphaned by moves or deletions.")),
    ("orphan-routes", _c(True, "F12", "Finds routes disconnected from handlers or authorization paths.")),
    ("over-fetch", _c(True, "F7", "Detects endpoints retrieving or exposing more data than needed.")),
    ("owner", _c(True, "F18", "Identifies the owner and review context for an edit target.")),
    ("partition", _c(False, "", "Excluded from the edit denominator: work partitioning.")),
    ("path-coverage", _c(True, "F9", "Finds untested call paths to sensitive effects.")),
    ("patterns", _c(True, "F16", "Detects implementation patterns and local idiom violations.")),
    ("permit", _c(False, "", "Excluded from the edit denominator: permission facade.")),
    ("plan", _c(False, "", "Excluded from the edit denominator: execution-plan gen (comprehension/action).")),
    ("plan-refactor", _c(False, "", "Excluded from the edit denominator: refactor-plan gen (action).")),
    ("plugins", _c(False, "", "Excluded from the edit denominator: plugin inspect.")),
    ("postmortem", _c(False, "", "Excluded from the edit denominator: replay detectors on past commits (reporting).")),
    ("pr-analyze", _c(False, "", "Excluded from the edit denominator: PR analysis aggregate.")),
    ("pr-bundle", _c(False, "", "Excluded from the edit denominator: proof-carrying PR bundle (aggregate).")),
    ("pr-comment-render", _c(False, "", "Excluded from the edit denominator: render PR comment.")),
    ("pr-diff", _c(False, "", "Excluded from the edit denominator: pending structural impact; subsumed by impact.")),
    ("pr-prep", _c(False, "", "Excluded from the edit denominator: pre-PR aggregate.")),
    ("pr-replay", _c(False, "", "Excluded from the edit denominator: PR replay report.")),
    ("pr-risk", _c(True, "F19", "Scores combined blast, hotspot, ownership, and coupling risk.")),
    ("pre-commit", _c(False, "", "Excluded from the edit denominator: pre-commit hook installer.")),
    (
        "preflight",
        _c(
            False,
            "",
            "Excluded from the edit denominator: pre-change checklist aggregate; subsumed by risk_context+edit_blast.",
        ),
    ),
    ("profile-import", _c(False, "", "Imports runtime profiles; profile consumers provide the edit checks.")),
    ("proof-bundle", _c(False, "", "Excluded from the edit denominator: compliance.")),
    ("py-modern", _c(True, "F27", "Finds unsafe or outdated Python constructs during modernization.")),
    ("py-types", _c(True, "F27", "Checks Python type surface and contract consistency.")),
    ("pytest-fixtures", _c(True, "F9", "Maps test fixtures that an edit may need to preserve or update.")),
    ("reachability-triage", _c(True, "F6 F19", "Triages whether vulnerable or sensitive code is actually reachable.")),
    ("recipes", _c(False, "", "Excluded from the edit denominator: meta.")),
    ("recommend", _c(False, "", "Excluded from the edit denominator: related-symbol recommend (comprehension).")),
    ("refs", _c(True, "F2", "Deprecated reference lookup alias that still finds live consumers.")),
    ("refs-text", _c(True, "F12", "Finds textual references that can make a rename or deletion unsafe.")),
    ("relate", _c(False, "", "Excluded from the edit denominator: navigation.")),
    ("replay", _c(False, "", "Excluded from the edit denominator: re-narrate run.")),
    ("report", _c(False, "", "Excluded from the edit denominator: compound report preset (reporting).")),
    ("reset", _c(False, "", "Excluded from the edit denominator: infra.")),
    (
        "retrieve",
        _c(False, "", "Excluded from the edit denominator: ranked spans; subsumed by search-semantic (wired)."),
    ),
    ("review-accept", _c(False, "", "Records a review decision rather than deriving code evidence.")),
    ("review-request", _c(False, "", "Requests review and does not inspect the implementation.")),
    ("review-verify", _c(False, "", "Verifies review workflow state rather than changed-code behavior.")),
    ("risk", _c(True, "F18", "Summarizes risk factors around a proposed edit.")),
    ("rules", _c(True, "F24", "Evaluates repository rules constraining implementation changes.")),
    ("rules-suggest", _c(False, "", "Suggests future rules and does not validate the current edit.")),
    ("rules-validate", _c(False, "", "Excluded from the edit denominator: lint rules file.")),
    ("runs", _c(False, "", "Excluded from the edit denominator: event ledger.")),
    ("safe-delete", _c(True, "F8", "Plans and validates dependency-aware deletion.")),
    ("safe-zones", _c(True, "F18", "Identifies low-risk areas and architecture constraints for edits.")),
    ("savings", _c(False, "", "Reports optimization savings rather than code correctness.")),
    ("savings-backfill", _c(False, "", "Backfills metrics and does not validate code edits.")),
    ("sbom", _c(False, "", "Excluded from the edit denominator: compliance.")),
    ("schema", _c(False, "", "Excluded from the edit denominator: meta.")),
    ("search", _c(False, "", "Excluded from the edit denominator: navigation (subsumed).")),
    ("search-semantic", _c(True, "F5", "Finds conceptually related code missed by literal lookup.")),
    ("secrets", _c(True, "F6", "Detects credential material in changed files.")),
    ("semantic-diff", _c(True, "F12", "Compares behavioral surface rather than text alone.")),
    ("service-report", _c(False, "", "Maps a service's entry points, dependencies, and operational risks.")),
    ("side-effects", _c(True, "F21", "Classifies observable effects an edit must preserve.")),
    ("simulate", _c(False, "", "Excluded from the edit denominator: simulation (meta).")),
    ("simulate-departure", _c(False, "", "Excluded from the edit denominator: PM.")),
    ("sketch", _c(False, "", "Excluded from the edit denominator: skeleton (comprehension).")),
    ("skill-generate", _c(False, "", "Excluded from the edit denominator: skill manifest gen.")),
    ("smells", _c(True, "F16", "Detects maintainability and generated-code smell patterns.")),
    ("snapshot", _c(False, "", "Excluded from the edit denominator: deprecated->trends.")),
    ("spectral", _c(False, "", "Excluded from the edit denominator: spectral partition (reporting).")),
    ("split", _c(True, "F16", "Finds safe boundaries for splitting a module or change.")),
    ("stale-refs", _c(True, "F12", "Finds references made stale by moves, renames, or deletions.")),
    ("stats", _c(False, "", "Excluded from the edit denominator: aggregate metrics (reporting).")),
    ("suggest-refactoring", _c(False, "", "Excluded from the edit denominator: refactor ranking (comprehension).")),
    ("suggest-reviewers", _c(False, "", "Excluded from the edit denominator: PM.")),
    ("supply-chain", _c(False, "", "Excluded from the edit denominator: dependency-risk compliance.")),
    ("suppress", _c(False, "", "Excluded from the edit denominator: suppression mgmt.")),
    ("surface", _c(False, "", "Excluded from the edit denominator: capability surface (meta).")),
    ("surface-gaps", _c(True, "F2 F12", "Finds missing or undocumented public-surface coverage.")),
    ("symbol", _c(False, "", "Excluded from the edit denominator: navigation.")),
    ("syntax-check", _c(True, "F20", "Checks changed source for parse and syntax failures.")),
    ("taint", _c(True, "F6", "Traces untrusted data to sensitive sinks.")),
    ("telemetry", _c(False, "", "Excluded from the edit denominator: telemetry.")),
    ("test-gaps", _c(True, "F9", "Finds missing tests for changed or risky production code.")),
    ("test-hermeticity", _c(True, "F25", "Detects tests coupled to time, network, randomness, or environment.")),
    ("test-impact", _c(True, "F3", "Maps changed code to the tests that exercise it.")),
    (
        "test-map",
        _c(False, "", "Excluded from the edit denominator: symbol->test map; subsumed by test-impact (wired)."),
    ),
    ("test-pyramid", _c(True, "F9", "Detects imbalance in the repository's executable test layers.")),
    ("test-scaffold", _c(True, "F9", "Generates tests but does not prove the generated tests are sufficient.")),
    ("timeline", _c(False, "", "Excluded from the edit denominator: commit history (comprehension).")),
    ("tour", _c(False, "", "Excluded from the edit denominator: guided walkthrough (meta).")),
    ("trace", _c(True, "F19", "Traces execution paths and effects through edited code.")),
    ("trend", _c(False, "", "Excluded from the edit denominator: deprecated->trends.")),
    ("trends", _c(False, "", "Excluded from the edit denominator: health trends (reporting).")),
    ("triage", _c(False, "", "Excluded from the edit denominator: suppression mgmt.")),
    ("tx-boundaries", _c(True, "F10", "Finds unsafe or unmatched transaction boundaries.")),
    ("understand", _c(False, "", "Excluded from the edit denominator: comprehension.")),
    ("uses", _c(True, "F2", "Finds graph-resolved callers and references that an edit can break.")),
    ("verdict", _c(False, "", "Excluded from the edit denominator: proof-bundle verdict (compliance).")),
    ("verification-contract", _c(True, "F9 F20", "Derives the exact checks required for a changed file.")),
    ("verify", _c(True, "F3 F21", "Runs the post-edit selected-check gate.")),
    ("verify-imports", _c(True, "F1 F14", "Detects unresolved imports introduced by an edit.")),
    ("version", _c(False, "", "Excluded from the edit denominator: meta.")),
    ("vibe-check", _c(True, "F23", "Detects broad generated-code and maintainability decay.")),
    ("visualize", _c(False, "", "Excluded from the edit denominator: diagram gen.")),
    ("vue-emits", _c(True, "F2 F26", "Checks Vue emitted-event contracts against consumers.")),
    ("vuln-map", _c(False, "", "Excluded from the edit denominator: compliance/security ingest.")),
    ("vuln-reach", _c(False, "", "Excluded from the edit denominator: compliance/security ingest.")),
    (
        "vulns",
        _c(False, "", "Excluded from the edit denominator: vuln inventory mgmt (scanner-based, not edit-detector)."),
    ),
    ("watch", _c(False, "", "Excluded from the edit denominator: auto-reindex infra.")),
    ("weather", _c(False, "", "Excluded from the edit denominator: churn x complexity reporting (debt wired).")),
    ("why", _c(False, "", "Excluded from the edit denominator: symbol importance (comprehension).")),
    ("why-fail", _c(True, "F3", "Ranks changed symbols likely to explain a failing test.")),
    ("why-slow", _c(True, "F7", "Finds runtime hotspots and their likely source causes.")),
    ("workflow", _c(False, "", "Excluded from the edit denominator: recipe DAG (meta).")),
    ("ws", _c(False, "", "Excluded from the edit denominator: multi-repo workspace.")),
    ("x-lang", _c(True, "F5", "Checks cross-language bindings and consumer contracts.")),
)


def _classification_table() -> dict[str, CommandClassification]:
    table: dict[str, CommandClassification] = {}
    duplicates: list[str] = []
    for command, classification in COMMAND_CLASSIFICATION_ROWS:
        if command in table:
            duplicates.append(command)
        table[command] = classification
    if duplicates:
        raise CoverageError(f"duplicate declared command classifications: {', '.join(sorted(duplicates))}")
    return table


COMMAND_CLASSIFICATION = _classification_table()


def roam_command_inventory() -> frozenset[str]:
    """Return Roam's built-in, plugin-invariant CLI registry."""
    from roam import cli as roam_cli

    commands = frozenset(roam_cli._COMMANDS)
    if not commands or any(not isinstance(command, str) or not command for command in commands):
        raise CoverageError("roam.cli._COMMANDS is empty or contains a non-command key")
    return commands


def _module_tree(module: ModuleType) -> ast.Module:
    source_path = inspect.getsourcefile(module)
    if not source_path:
        raise CoverageError(f"cannot locate source for {module.__name__}")
    try:
        return ast.parse(Path(source_path).read_text(encoding="utf-8"), filename=source_path)
    except (OSError, SyntaxError) as exc:
        raise CoverageError(f"cannot parse source for {module.__name__}: {exc}") from exc


def _assignment(tree: ast.Module, name: str) -> ast.expr:
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            return node.value
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
            and node.value
        ):
            return node.value
    raise CoverageError(f"source registry {name} was not found")


def _functions(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _call_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _local_assignments(node: ast.AST) -> dict[str, ast.expr]:
    assignments: dict[str, ast.expr] = {}
    for child in ast.walk(node):
        if isinstance(child, ast.Assign) and len(child.targets) == 1 and isinstance(child.targets[0], ast.Name):
            assignments[child.targets[0].id] = child.value
        elif isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name) and child.value:
            assignments[child.target.id] = child.value
    return assignments


def _first_string(expr: ast.expr, assignments: dict[str, ast.expr]) -> str | None:
    if isinstance(expr, ast.Name) and expr.id in assignments:
        return _first_string(assignments[expr.id], assignments)
    if isinstance(expr, (ast.List, ast.Tuple)) and expr.elts:
        first = expr.elts[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
    return None


def _commands_reachable_from(
    roots: set[str],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    *,
    runner_prefix: str = "_run_roam",
) -> tuple[set[str], list[str], set[str]]:
    commands: set[str] = set()
    unresolved: list[str] = []
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visited or name not in functions:
            return
        visited.add(name)
        node = functions[name]
        assignments = _local_assignments(node)
        for call in (child for child in ast.walk(node) if isinstance(child, ast.Call)):
            called = _call_name(call)
            if called and called.startswith(runner_prefix) and call.args:
                command = _first_string(call.args[0], assignments)
                if command is None:
                    unresolved.append(f"{name}:{call.lineno}: {ast.unparse(call.args[0])}")
                else:
                    commands.add(command)
                continue
            if called in functions:
                visit(called)

    for root in roots:
        visit(root)
    return commands, unresolved, visited


def context_commands(inventory: frozenset[str]) -> frozenset[str]:
    """Commands reachable from the plan compiler's always-on probe registry."""
    from roam.plan import compiler

    tree = _module_tree(compiler)
    registry = _assignment(tree, "_L1_ALWAYS_ON_PROBES")
    if not isinstance(registry, (ast.Tuple, ast.List)):
        raise CoverageError("_L1_ALWAYS_ON_PROBES is no longer a literal sequence")
    labels: list[str] = []
    roots: set[str] = set()
    for row in registry.elts:
        if not isinstance(row, (ast.Tuple, ast.List)) or len(row.elts) != 2:
            raise CoverageError("_L1_ALWAYS_ON_PROBES contains a non-(label, callable) row")
        label, callback = row.elts
        if not isinstance(label, ast.Constant) or not isinstance(label.value, str):
            raise CoverageError("_L1_ALWAYS_ON_PROBES contains a non-literal label")
        labels.append(label.value)
        roots.update(
            call.func.id
            for call in ast.walk(callback)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
        )
    runtime_labels = [label for label, _callback in compiler._L1_ALWAYS_ON_PROBES]
    if labels != runtime_labels:
        raise CoverageError("_L1_ALWAYS_ON_PROBES source and runtime labels disagree")
    functions = _functions(tree)
    roots &= functions.keys()
    commands, unresolved, _visited = _commands_reachable_from(roots, functions)
    if unresolved:
        raise CoverageError("CONTEXT has unresolved Roam command expressions: " + "; ".join(unresolved))
    # Some probes implement a command's analysis inline rather than spawning
    # the CLI. An exact normalized registry label is still a source-owned
    # binding; fuzzy or hand-maintained aliases are deliberately excluded.
    commands.update({label.replace("_", "-") for label in labels} & inventory)
    return frozenset(commands)


def _verify_auto_checks(module: ModuleType) -> tuple[str, ...]:
    source = inspect.getsource(module.auto_select_checks)
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise CoverageError(f"cannot parse auto_select_checks: {exc}") from exc
    flags = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith("ROAM_VERIFY_")
    }
    targets = [
        "src/module.py",
        "tests/test_module.py",
        "docs/README.md",
        "migrations/0001_change.php",
        "src/calculation.ts",
    ]
    with patch.dict(os.environ, {flag: "1" for flag in flags}):
        selected = tuple(module.auto_select_checks(targets))
    if not selected:
        raise CoverageError("auto_select_checks returned no checks for the coverage fixture")
    return selected


def _verify_handler_name(check: str, functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]) -> str | None:
    aliases = {"delete_check": "_check_delete_safety"}
    candidate = aliases.get(check, f"_check_{check}")
    return candidate if candidate in functions else None


def _imported_command_modules(root: str, functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]) -> set[str]:
    commands: set[str] = set()
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visited or name not in functions:
            return
        visited.add(name)
        for node in ast.walk(functions[name]):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("roam.commands.cmd_"):
                commands.add(node.module.rsplit("cmd_", 1)[1].replace("_", "-"))
            elif isinstance(node, ast.Call):
                called = _call_name(node)
                if called in functions:
                    visit(called)

    visit(root)
    return commands


def verify_commands(inventory: frozenset[str]) -> frozenset[str]:
    """Commands represented by checks that ``verify --auto`` can select."""
    from roam.commands import cmd_verify

    selected = _verify_auto_checks(cmd_verify)
    tree = _module_tree(cmd_verify)
    functions = _functions(tree)
    commands: set[str] = set()
    for check in selected:
        normalized = check.replace("_", "-")
        # ``syntax`` is exposed as ``syntax-check``; accepting the mechanical
        # suffix keeps this derived without a semantic alias table.
        commands.update({normalized, f"{normalized}-check"} & inventory)
    missing_handlers: list[str] = []
    for check in selected:
        handler = _verify_handler_name(check, functions)
        if handler is None:
            missing_handlers.append(check)
            continue
        commands.update(_imported_command_modules(handler, functions) & inventory)
    if missing_handlers:
        raise CoverageError("VERIFY auto checks have no source handler: " + ", ".join(sorted(missing_handlers)))
    return frozenset(commands)


def hook_commands() -> frozenset[str]:
    """Commands called by the canonical Claude Stop-hook script."""
    from roam.commands import cmd_hooks

    try:
        tree = ast.parse(cmd_hooks._CLAUDE_STOP_HOOK_SCRIPT)
    except SyntaxError as exc:
        raise CoverageError(f"cannot parse _CLAUDE_STOP_HOOK_SCRIPT: {exc}") from exc
    functions = _functions(tree)
    roots = {"main"} if "main" in functions else set(functions)
    commands, unresolved, _visited = _commands_reachable_from(roots, functions)
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call) and _call_name(node) == "Popen"):
        if not call.args or not isinstance(call.args[0], (ast.List, ast.Tuple)):
            continue
        words = [
            element.value
            for element in call.args[0].elts
            if isinstance(element, ast.Constant) and isinstance(element.value, str)
        ]
        if "roam" not in words:
            continue
        after_roam = words[words.index("roam") + 1 :]
        command = next((word for word in after_roam if not word.startswith("-")), None)
        if command:
            commands.add(command)
    if unresolved:
        raise CoverageError("HOOK has unresolved Roam command expressions: " + "; ".join(unresolved))
    return frozenset(commands)


def _decorated_tool_name(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        for keyword in decorator.keywords:
            if (
                keyword.arg == "name"
                and isinstance(keyword.value, ast.Constant)
                and isinstance(keyword.value.value, str)
            ):
                return keyword.value.value
    return None


def mcp_commands(inventory: frozenset[str]) -> frozenset[str]:
    """CLI commands represented by Roam's compile-curated MCP preset."""
    import roam.mcp_server as mcp_server

    curated = frozenset(mcp_server._PRESETS["compile-curated"])
    tree = _module_tree(mcp_server)
    functions = _functions(tree)
    handlers = {
        tool_name: node.name for node in functions.values() if (tool_name := _decorated_tool_name(node)) in curated
    }
    missing = curated - handlers.keys()
    if missing:
        raise CoverageError("MCP curated tools have no decorated handler: " + ", ".join(sorted(missing)))
    commands: set[str] = set()
    unresolved: list[str] = []
    for tool, handler in handlers.items():
        found, unresolved_handler, _visited = _commands_reachable_from({handler}, functions)
        found.update(_imported_command_modules(handler, functions))
        normalized = tool.removeprefix("roam_").replace("_", "-")
        if normalized in inventory:
            found.add(normalized)
        commands.update(found & inventory)
        unresolved.extend(f"{tool}: {item}" for item in unresolved_handler)
    if unresolved:
        raise CoverageError("MCP has unresolved Roam command expressions: " + "; ".join(unresolved))
    return frozenset(commands)


def validate_classifications(inventory: frozenset[str], classifications: dict[str, CommandClassification]) -> None:
    missing = inventory - classifications.keys()
    extra = classifications.keys() - inventory
    problems: list[str] = []
    if missing:
        problems.append("unclassified Roam command(s): " + ", ".join(sorted(missing)))
    if extra:
        problems.append("classifications for commands absent from Roam: " + ", ".join(sorted(extra)))
    for command in sorted(inventory & classifications.keys()):
        classification = classifications[command]
        if not classification.reason.strip() or "\n" in classification.reason:
            problems.append(f"{command}: reason must be one non-empty line")
        if classification.edit_relevant and not classification.failure_classes:
            problems.append(f"{command}: edit-relevant command has no failure class")
        if not classification.edit_relevant and classification.failure_classes:
            problems.append(f"{command}: non-edit command carries failure classes")
        unknown = set(classification.failure_classes) - FAILURE_CLASSES.keys()
        if unknown:
            problems.append(f"{command}: unknown failure classes {', '.join(sorted(unknown))}")
    if problems:
        raise CoverageError("; ".join(problems))


def validate_channels(inventory: frozenset[str], channels: dict[str, frozenset[str]]) -> None:
    if tuple(channels) != CHANNEL_ORDER:
        raise CoverageError(f"channel order/names must be {', '.join(CHANNEL_ORDER)}")
    problems = []
    for channel, commands in channels.items():
        outside = commands - inventory
        if outside:
            problems.append(f"{channel} references commands outside the Roam inventory: {', '.join(sorted(outside))}")
        if not commands:
            problems.append(f"{channel} derived an empty command set")
    if problems:
        raise CoverageError("; ".join(problems))


def build_report() -> CoverageReport:
    inventory = roam_command_inventory()
    channels = {
        "CONTEXT": context_commands(inventory),
        "VERIFY": verify_commands(inventory),
        "HOOK": hook_commands(),
        "MCP": mcp_commands(inventory),
    }
    validate_classifications(inventory, COMMAND_CLASSIFICATION)
    validate_channels(inventory, channels)
    return CoverageReport(
        roam_version=importlib_metadata.version("roam-code"),
        inventory=inventory,
        channels=channels,
        classifications=COMMAND_CLASSIFICATION,
    )


def _wired(report: CoverageReport) -> frozenset[str]:
    return frozenset().union(*report.channels.values())


def _failure_channels(report: CoverageReport, failure_class: str) -> dict[str, frozenset[str]]:
    relevant = {
        command
        for command, classification in report.classifications.items()
        if failure_class in classification.failure_classes
    }
    return {channel: frozenset(commands & relevant) for channel, commands in report.channels.items()}


def _failure_state(report: CoverageReport, failure_class: str) -> tuple[str, int, int]:
    mapped = {
        command
        for command, classification in report.classifications.items()
        if failure_class in classification.failure_classes
    }
    wired = mapped & _wired(report)
    if not wired:
        state = "uncovered"
    elif wired == mapped:
        state = "covered"
    else:
        state = "partial"
    return state, len(wired), len(mapped)


def ranked_gaps(report: CoverageReport) -> list[tuple[int, int, str, CommandClassification]]:
    wired = _wired(report)
    fully_uncovered = {
        failure_class for failure_class in FAILURE_CLASSES if not any(_failure_channels(report, failure_class).values())
    }
    gaps: list[tuple[int, int, str, CommandClassification]] = []
    for command, classification in report.classifications.items():
        if not classification.edit_relevant or command in wired:
            continue
        impact = sum(FAILURE_CLASSES[failure_class].impact for failure_class in classification.failure_classes)
        uncovered = sum(1 for failure_class in classification.failure_classes if failure_class in fully_uncovered)
        score = impact + 100 * uncovered
        gaps.append((score, uncovered, command, classification))
    return sorted(gaps, key=lambda row: (-row[0], -row[1], row[2]))


def _command_list(commands: set[str] | frozenset[str]) -> str:
    return ", ".join(f"`{command}`" for command in sorted(commands)) or "—"


def render_markdown(report: CoverageReport) -> str:
    validate_classifications(report.inventory, report.classifications)
    wired = _wired(report)
    edit_relevant = {
        command for command, classification in report.classifications.items() if classification.edit_relevant
    }
    wired_relevant = wired & edit_relevant
    failure_state_counts = {state: 0 for state in ("covered", "partial", "uncovered")}
    for failure_class in FAILURE_CLASSES:
        failure_state_counts[_failure_state(report, failure_class)[0]] += 1
    lines = [
        "<!-- Generated by scripts/build_wiring_coverage.py; do not edit. -->",
        "# Roam → compile-code wiring coverage denominator",
        "",
        (
            f"Source: resolved Roam {report.roam_version}. The {len(report.inventory)}-command inventory and channel "
            "sets are read from source; edit relevance, failure classes, and their one-line reasons are the declared "
            "review table in `scripts/build_wiring_coverage.py`."
        ),
        "",
        "## Summary",
        "",
        f"**{len(wired_relevant)} of {len(edit_relevant)} edit-relevant commands are wired** "
        f"({len(wired)} distinct commands across all channels; {len(report.inventory)} commands total).",
        "",
        (
            f"Failure classes: {failure_state_counts['covered']} fully covered, "
            f"{failure_state_counts['partial']} partial, and "
            f"{failure_state_counts['uncovered']} fully uncovered."
        ),
        "",
        "| Channel | Wired commands | Edit-relevant wired | Inventory share |",
        "|---|---:|---:|---:|",
    ]
    for channel in CHANNEL_ORDER:
        commands = report.channels[channel]
        lines.append(
            f"| {channel} | {len(commands)} | {len(commands & edit_relevant)} | "
            f"{len(commands) / len(report.inventory):.1%} |"
        )
    lines.extend(
        [
            f"| **Union** | **{len(wired)}** | **{len(wired_relevant)}** | **{len(wired) / len(report.inventory):.1%}** |",
            "",
            "## Derived channel sets",
            "",
        ]
    )
    for channel in CHANNEL_ORDER:
        lines.extend([f"### {channel}", "", _command_list(report.channels[channel]), ""])

    lines.extend(
        [
            "## Failure-class coverage",
            "",
            (
                "A class is **covered** when every mapped command is wired, **partial** when some are wired, and "
                "**uncovered** when none are wired."
            ),
            "",
            "| Class | Failure | Impact | CONTEXT | VERIFY | HOOK | MCP | Wired / mapped | State |",
            "|---|---|---:|---:|---:|---:|---:|---:|---|",
        ]
    )
    for failure_class, metadata in FAILURE_CLASSES.items():
        by_channel = _failure_channels(report, failure_class)
        state, wired_count, mapped_count = _failure_state(report, failure_class)
        rendered_state = "**UNCOVERED**" if state == "uncovered" else state
        lines.append(
            f"| {failure_class} | {metadata.title} | {metadata.impact} | "
            f"{len(by_channel['CONTEXT'])} | {len(by_channel['VERIFY'])} | {len(by_channel['HOOK'])} | "
            f"{len(by_channel['MCP'])} | {wired_count} / {mapped_count} | {rendered_state} |"
        )

    lines.extend(
        [
            "",
            "## Ranked gap list",
            "",
            (
                "Rank score is the sum of mapped failure-class impacts plus 100 for each still-fully-uncovered class. "
                "That makes closing a denominator hole outrank adding redundancy to an already covered class."
            ),
            "",
            "| Rank | Command | Score | Failure classes | Reason |",
            "|---:|---|---:|---|---|",
        ]
    )
    for rank, (score, _uncovered, command, classification) in enumerate(ranked_gaps(report), 1):
        lines.append(
            f"| {rank} | `{command}` | {score} | {', '.join(classification.failure_classes)} | "
            f"{classification.reason} |"
        )

    lines.extend(
        [
            "",
            "## Full command classification",
            "",
            "| Command | Edit-relevant | Failure classes | Reason | Wired by |",
            "|---|---|---|---|---|",
        ]
    )
    for command in sorted(report.inventory):
        classification = report.classifications[command]
        channels = [channel for channel in CHANNEL_ORDER if command in report.channels[channel]]
        lines.append(
            f"| `{command}` | {'yes' if classification.edit_relevant else 'no'} | "
            f"{', '.join(classification.failure_classes) or '—'} | {classification.reason} | "
            f"{', '.join(channels) or '—'} |"
        )
    return "\n".join(lines) + "\n"


def _check_or_write(rendered: str, *, write: bool) -> int:
    if write:
        OUTPUT.write_text(rendered, encoding="utf-8")
        print(f"wiring coverage: wrote {OUTPUT.name}")
        return 0
    try:
        current = OUTPUT.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"wiring coverage: FAIL — {OUTPUT.name} is missing", file=sys.stderr)
        print(f"  fix: {sys.executable} scripts/build_wiring_coverage.py --write", file=sys.stderr)
        return 1
    if current != rendered:
        print(f"wiring coverage: FAIL — {OUTPUT.name} is stale", file=sys.stderr)
        print(f"  fix: {sys.executable} scripts/build_wiring_coverage.py --write", file=sys.stderr)
        return 1
    print(f"wiring coverage: PASS — {OUTPUT.name} matches resolved Roam source")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help=f"check that {OUTPUT.name} matches source (default)")
    mode.add_argument("--write", action="store_true", help=f"rewrite {OUTPUT.name} instead of checking it")
    args = parser.parse_args(argv)
    try:
        rendered = render_markdown(build_report())
    except (CoverageError, ImportError, importlib_metadata.PackageNotFoundError) as exc:
        print(f"wiring coverage: FAIL — {exc}", file=sys.stderr)
        return 1
    return _check_or_write(rendered, write=args.write)


if __name__ == "__main__":
    raise SystemExit(main())
