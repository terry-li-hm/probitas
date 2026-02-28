---
title: "feat: Guardrail Regression Testing CLI"
type: feat
status: active
date: 2026-02-28
---

# Guardrail Regression Testing CLI — probitas

## Overview

Build a CLI tool that tests whether LLM agent guardrails actually work. Runs deterministic policy rules against test cases in CI/CD, reports pass/fail and a "guardrail coverage" percentage. Think "pytest for guardrails."

Companion to [frenum](https://github.com/terry-li-hm/frenum) (the guardrail enforcement engine). probitas tests the bridle; frenum is the bridle.

## Problem Statement

- No standard for testing that guardrails work correctly before shipping
- No "guardrail test coverage" metric (analogous to code coverage)
- Model updates, new tools, new data sources require re-validation — no automated pipeline
- O'Reilly Radar: governance stays at "policy level" while engineers work at "pipeline level" — they don't meet
- 40% of agentic AI projects will be cancelled by 2027 (Gartner) — governance gap as primary cause

## Proposed Solution

A Python CLI (`probitas run --config policy.yaml --tests tests/`) that:

1. Loads a policy YAML declaring guardrail rules (same schema as frenum)
2. Loads test cases (YAML files with tool call inputs + expected verdicts)
3. Executes deterministic rules against test inputs (no LLM, fast)
4. Reports pass/fail per test case
5. Computes **guardrail coverage**: `rules_exercised / total_deterministic_rules`
6. Generates an HTML evidence report with SHA-256 hash for tamper-evidence
7. Exits non-zero on failures (CI-friendly)

## Technical Approach

### Architecture

```
policy.yaml ─────┐
                  ├──→ probitas run ──→ Results + Coverage + HTML Report
tests/*.yaml ────┘

policy.yaml declares rules (same schema as frenum):
  - Each rule tagged: deterministic | semantic
  - deterministic rules: tested automatically
  - semantic rules: listed as "manual validation required"

tests/*.yaml declares test cases:
  - tool_call: {name, args, metadata}
  - expected: allow | block
  - expected_rule: (optional) which rule should trigger
  - description: human-readable label
```

### Package Structure

```
~/code/probitas/
├── pyproject.toml
├── README.md
├── LICENSE
├── src/probitas/
│   ├── __init__.py          # Public API re-exports (~15 lines)
│   ├── _types.py            # Dataclasses: TestCase, TestResult, CoverageReport, PolicyConfig (~60 lines)
│   ├── loader.py            # Load policy YAML + test case YAML files (~80 lines)
│   ├── engine.py            # Rule engine — evaluate rules, collect results (~150 lines)
│   ├── coverage.py          # Coverage calculator — rules_exercised / total (~60 lines)
│   ├── report.py            # HTML report generator with Jinja2 template (~80 lines)
│   ├── cli.py               # argparse CLI: `probitas run` (~60 lines)
│   └── templates/
│       └── report.html      # Jinja2 HTML template (~80 lines)
├── tests/
│   ├── conftest.py
│   ├── test_engine.py
│   ├── test_loader.py
│   ├── test_coverage.py
│   ├── test_report.py
│   └── test_cli.py
└── examples/
    ├── policy.yaml           # Sample policy with all rule types
    └── tests/
        ├── test_sql_injection.yaml
        ├── test_pii_detection.yaml
        └── test_entitlements.yaml
```

### Implementation Phases

#### Phase 1: Core Types + Rule Engine (~250 lines)

**`_types.py`** — Core data types:

```python
@dataclass(frozen=True)
class ToolCall:
    name: str
    args: dict
    metadata: dict = field(default_factory=dict)

class Decision(Enum):
    ALLOW = "allow"
    BLOCK = "block"

class RuleKind(Enum):
    DETERMINISTIC = "deterministic"
    SEMANTIC = "semantic"

@dataclass(frozen=True)
class RuleConfig:
    name: str
    rule_type: str          # regex_block, regex_require, pii_detect, entitlement, budget, tool_allowlist
    params: dict
    applies_to: list[str]
    kind: RuleKind = RuleKind.DETERMINISTIC

@dataclass(frozen=True)
class TestCase:
    description: str
    tool_call: ToolCall
    expected: Decision
    expected_rule: str | None = None  # optional: which rule should trigger

@dataclass
class TestResult:
    test_case: TestCase
    actual: Decision
    actual_rule: str | None
    passed: bool
    reason: str

@dataclass
class CoverageReport:
    total_deterministic_rules: int
    rules_exercised: list[str]
    rules_not_exercised: list[str]
    semantic_rules: list[str]     # listed as "manual validation required"
    coverage_pct: float
```

**`engine.py`** — Rule evaluation engine:

- Reuse frenum's rule evaluation patterns (registry + handlers)
- 6 rule types:
  1. `regex_block` — block if field matches pattern
  2. `regex_require` — block if required field missing/invalid
  3. `pii_detect` — scan args for PII patterns
  4. `entitlement` — role-based tool access
  5. `budget` — block if `metadata["estimated_cost"]` exceeds threshold
  6. `tool_allowlist` — block if tool name not in allowed list
- Short-circuit on first BLOCK (frenum semantics)
- Track which rules were evaluated and which triggered

**`loader.py`** — YAML loading:

- `load_policy(path) -> list[RuleConfig]` — parse policy YAML
- `load_tests(path) -> list[TestCase]` — parse test YAML files (single file or directory)
- Validation: unknown rule types, missing required fields, type mismatches
- Optional pyyaml import (same pattern as frenum)

#### Phase 2: Coverage Calculator + Test Runner (~120 lines)

**`coverage.py`** — Coverage calculation:

```python
def calculate_coverage(
    rules: list[RuleConfig],
    results: list[TestResult],
) -> CoverageReport:
    deterministic = [r for r in rules if r.kind == RuleKind.DETERMINISTIC]
    semantic = [r for r in rules if r.kind == RuleKind.SEMANTIC]
    exercised = {r.actual_rule for r in results if r.actual_rule}
    det_names = {r.name for r in deterministic}
    covered = exercised & det_names
    not_covered = det_names - covered
    pct = (len(covered) / len(det_names) * 100) if det_names else 100.0
    return CoverageReport(
        total_deterministic_rules=len(det_names),
        rules_exercised=sorted(covered),
        rules_not_exercised=sorted(not_covered),
        semantic_rules=[r.name for r in semantic],
        coverage_pct=round(pct, 1),
    )
```

**Test runner** (in `engine.py` or separate `runner.py`):

```python
def run_tests(rules, test_cases) -> list[TestResult]:
    results = []
    for tc in test_cases:
        eval_result = evaluate(rules, tc.tool_call)
        passed = eval_result.decision == tc.expected
        if tc.expected_rule and passed:
            passed = eval_result.blocking_rule == tc.expected_rule
        results.append(TestResult(...))
    return results
```

#### Phase 3: HTML Report + CLI (~200 lines)

**`report.py`** — HTML evidence report:

- Policy hash (SHA-256 of policy YAML content)
- Test run timestamp
- Pass/fail matrix (table: test description | expected | actual | rule | status)
- Coverage percentage + rules exercised/not-exercised lists
- Semantic rules listed as "manual validation required"
- Evidence bundle hash: SHA-256 of (policy_hash + all test results serialized)
- Uses Jinja2 template from `templates/report.html`
- Also outputs JSON for machine consumption

**`cli.py`** — CLI entry point:

```
probitas run --config policy.yaml --tests tests/ [--format html|json|text] [--output report.html]
probitas run --config policy.yaml --tests tests/ --live  # opt-in semantic testing (future)
```

- argparse (no click dependency — keep zero deps)
- Exit code 0 = all pass, 1 = failures, 2 = config error
- Default format: text (terminal-friendly summary)
- `--format html` generates the evidence report
- `--format json` for CI pipeline consumption

### Key Design Decisions

1. **Zero core dependencies.** argparse (stdlib) for CLI, string.Template or inline HTML for reports if Jinja2 not installed. Jinja2 as optional dep for pretty reports.
2. **No LLM calls by default.** All rule evaluation is deterministic regex/dict/threshold checks. `--live` flag reserved for future semantic testing.
3. **Frenum-compatible policy schema.** Same YAML structure as frenum's config. Users can test their frenum policies with probitas without changes.
4. **Coverage scoped to deterministic rules.** Semantic rules explicitly listed as "not covered — manual validation required." This is honest and mirrors how code coverage handles untestable code.
5. **SHA-256 for tamper-evidence.** Single hash of the evidence bundle. Not Merkle trees — 90% of the "tamper-evident" story at 1% of the complexity.
6. **Exit codes for CI.** 0/1/2 pattern standard for CI tools.

## Acceptance Criteria

- [ ] `probitas run --config policy.yaml --tests tests/` executes test cases and reports pass/fail
- [ ] Coverage percentage computed correctly: `rules_exercised / total_deterministic_rules`
- [ ] Semantic rules listed as "manual validation required" in output
- [ ] HTML report generated with `--format html` (policy hash, coverage %, pass/fail matrix, bundle hash)
- [ ] JSON output with `--format json`
- [ ] Text output as default (terminal-friendly)
- [ ] Exit code 0 on all pass, 1 on failures, 2 on config errors
- [ ] Works with frenum's policy YAML schema unchanged
- [ ] 6 rule types: regex_block, regex_require, pii_detect, entitlement, budget, tool_allowlist
- [ ] All tests pass (`uv run pytest`)
- [ ] Ruff clean (`uv run ruff check src/`)
- [ ] Zero core dependencies (pyyaml and jinja2 optional)
- [ ] `pip install probitas[yaml]` works
- [ ] Example policy + test suite included

## Test Plan

Follow frenum's test patterns (class-based organization, conftest fixtures, tmp_path for files):

| File | Tests | Focus |
|------|-------|-------|
| `test_loader.py` | ~6 | YAML parsing, validation, error handling, directory loading |
| `test_engine.py` | ~10 | Each rule type + short-circuit + coverage tracking |
| `test_coverage.py` | ~6 | Coverage math, edge cases (0 rules, all semantic, partial) |
| `test_report.py` | ~6 | HTML generation, JSON output, SHA-256 hashing, text format |
| `test_cli.py` | ~6 | Exit codes, argument parsing, end-to-end with fixtures |

Target: ~34 tests, <1 second, fully deterministic.

## Sources & References

### Internal
- `/Users/terry/code/frenum/` — companion guardrail engine (rule types, policy schema, test patterns)
- `/Users/terry/notes/Councils/LLM Council - Which Guardrails Gap to Build - 2026-02-28.md` — council deliberation on gap selection
- `/Users/terry/notes/Capco/Agentic AI Guardrails - Gap Research.md` — 10 confirmed gaps with evidence
- `/Users/terry/docs/solutions/patterns/critical-patterns.md` — use hashlib.sha256, not hash()

### External
- O'Reilly Radar: "AI Agents Need Guardrails" — governance theatre vs engineering
- Gartner: 40% of agentic AI projects cancelled by 2027
- avidoai.com: guardrail testing gaps in financial services
