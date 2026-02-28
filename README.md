# probitas

> Guardrail regression testing for LLM agent tool calls.
> pytest for guardrails — runs deterministic policy rules against test cases, reports pass/fail and guardrail coverage.

Named after the Latin word for *proved quality* or *integrity*. Companion to [frenum](https://github.com/terry-li-hm/frenum) (the guardrail enforcement engine). Probitas tests the bridle; frenum is the bridle.

## Why

You have guardrail rules — SQL injection blocks, PII detection, role-based entitlements, cost limits. But how do you know they actually work? Model updates, new tools, and config changes can silently break enforcement. There's no `pytest` for guardrails, and no "guardrail coverage" metric.

Probitas fills that gap:

- **Deterministic testing** — no LLM calls, runs in CI, sub-second execution
- **Guardrail coverage** — `rules_exercised / total_deterministic_rules`, like code coverage for your policy
- **Evidence reports** — HTML/JSON/text with SHA-256 tamper-evidence hashing
- **Frenum-compatible** — same YAML policy schema, test your frenum rules without changes
- **Zero dependencies** — stdlib only; pyyaml and jinja2 are optional

## Quick Start

```bash
pip install probitas[yaml]
```

Write a policy (`policy.yaml`):

```yaml
rules:
  - name: block_sql_injection
    type: regex_block
    applies_to: ["execute_sql"]
    params:
      fields: ["query"]
      patterns:
        - "(?i)(DROP|DELETE|TRUNCATE)\\s+TABLE"

  - name: detect_pii
    type: pii_detect
    applies_to: ["*"]
    params:
      detectors: [email, credit_card]
      action: block
```

Write test cases (`tests/test_sql.yaml`):

```yaml
tests:
  - description: "Safe SELECT should be allowed"
    tool_call:
      name: execute_sql
      args:
        query: "SELECT * FROM accounts"
    expected: allow

  - description: "DROP TABLE should be blocked"
    tool_call:
      name: execute_sql
      args:
        query: "DROP TABLE users"
    expected: block
    expected_rule: block_sql_injection
```

Run:

```bash
probitas run --config policy.yaml --tests tests/
```

```
probitas — guardrail regression test report
==================================================
Results: 2/2 passed, 0 failed

  [PASS] Safe SELECT should be allowed
  [PASS] DROP TABLE should be blocked

Coverage: 50.0% (1/2 deterministic rules)
  Not exercised: detect_pii

Evidence hash: 7a3f9c1e2b4d...
```

## CLI

```bash
# Text output (default, terminal-friendly)
probitas run --config policy.yaml --tests tests/

# JSON for CI pipelines
probitas run --config policy.yaml --tests tests/ --format json

# HTML evidence report
probitas run --config policy.yaml --tests tests/ --format html --output report.html
```

Exit codes: `0` = all pass, `1` = failures, `2` = config error.

## Rule Types

| Type | Purpose | Key Params |
|---|---|---|
| `regex_block` | Block if field matches pattern | `fields`, `patterns` |
| `regex_require` | Block if required field missing/invalid | `fields`, `pattern` |
| `pii_detect` | Scan args for PII (email, phone, HKID, etc.) | `detectors`, `action` |
| `entitlement` | Role-based tool access control | `roles`, `default` |
| `budget` | Block if estimated cost exceeds threshold | `max_cost`, `cost_field` |
| `tool_allowlist` | Block if tool not in approved list | `allowed_tools` |

## Guardrail Coverage

Coverage tracks which deterministic rules were exercised by your test suite:

```
Coverage: 83.3% (5/6 deterministic rules)
  Not exercised: require_confirmation
  Semantic (manual validation required): response_tone_check
```

Rules tagged `kind: semantic` are excluded from coverage and listed separately — honest about what can't be tested deterministically.

## Test Case Schema

```yaml
tests:
  - description: "Human-readable label"
    tool_call:
      name: tool_name
      args:
        key: value
      metadata:
        role: analyst
        estimated_cost: 0.50
    expected: allow | block
    expected_rule: rule_name  # optional: verify which rule triggers
```

## Policy Schema

Same as [frenum](https://github.com/terry-li-hm/frenum). Each rule can be tagged `kind: deterministic` (default) or `kind: semantic`:

```yaml
rules:
  - name: block_sql_injection
    type: regex_block
    kind: deterministic  # tested automatically (default)
    applies_to: ["execute_sql"]
    params:
      fields: ["query"]
      patterns: ["(?i)DROP\\s+TABLE"]

  - name: response_tone_check
    kind: semantic  # listed as "manual validation required"
    type: regex_block
    applies_to: ["*"]
    params:
      fields: []
      patterns: []
```

## Programmatic Use

```python
from probitas import evaluate, run_tests, calculate_coverage
from probitas import RuleConfig, TestCase, ToolCall, Decision

rules = [
    RuleConfig(
        name="cost_limit",
        rule_type="budget",
        params={"max_cost": 1.00},
        applies_to=["*"],
    ),
]

result = evaluate(rules, ToolCall(name="gpt4", args={}, metadata={"estimated_cost": 5.0}))
assert result.decision == Decision.BLOCK
```

## HTML Report

The HTML report includes:

- Policy hash (SHA-256)
- Pass/fail matrix with colour-coded status
- Coverage percentage with progress bar
- Rules not exercised
- Semantic rules flagged for manual validation
- Evidence bundle hash (SHA-256 of policy + results)

Generate with `--format html --output report.html`, or programmatically:

```python
from probitas.report import generate_html
html = generate_html(results, coverage, policy_content)
```

## Design Philosophy

- **Deterministic by default.** No LLM calls in CI. Fast, reproducible, cacheable.
- **Coverage is honest.** Semantic rules are explicitly excluded — no inflated numbers.
- **SHA-256 for tamper-evidence.** Single hash of the evidence bundle. 90% of the tamper-evident story at 1% of the complexity.
- **Zero core deps.** pyyaml for config loading, jinja2 for pretty HTML — both optional.
- **CI-native.** Exit codes, JSON output, sub-second execution.

## License

MIT
