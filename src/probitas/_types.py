"""Core types for probitas — guardrail regression testing for LLM agent tool calls."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Decision(Enum):
    ALLOW = "allow"
    BLOCK = "block"


class RuleKind(Enum):
    DETERMINISTIC = "deterministic"
    SEMANTIC = "semantic"


@dataclass(frozen=True)
class ToolCall:
    """A tool call to evaluate against policy rules."""

    name: str
    args: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuleConfig:
    """A single rule from the policy config."""

    name: str
    rule_type: str  # regex_block, regex_require, pii_detect, entitlement, budget, tool_allowlist
    params: dict[str, Any]
    applies_to: list[str]  # tool name patterns, ["*"] = all
    kind: RuleKind = RuleKind.DETERMINISTIC


@dataclass(frozen=True)
class TestCase:
    """A single test case: tool call + expected verdict."""

    description: str
    tool_call: ToolCall
    expected: Decision
    expected_rule: str | None = None


@dataclass
class RuleResult:
    """Result of evaluating a single rule."""

    rule_name: str
    decision: Decision
    reason: str


@dataclass
class EvalResult:
    """Aggregate result of evaluating all rules against a tool call."""

    decision: Decision
    rules_evaluated: list[str]
    blocking_rule: str | None = None
    reason: str = ""


@dataclass
class TestResult:
    """Result of running one test case."""

    test_case: TestCase
    actual: Decision
    actual_rule: str | None
    passed: bool
    reason: str
    rules_evaluated: list[str] = field(default_factory=list)


@dataclass
class CoverageReport:
    """Guardrail coverage: how many deterministic rules were exercised."""

    total_deterministic_rules: int
    rules_exercised: list[str]
    rules_not_exercised: list[str]
    semantic_rules: list[str]
    coverage_pct: float
