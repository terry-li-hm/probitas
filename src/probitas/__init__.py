"""probitas — Guardrail regression testing for LLM agent tool calls."""

__version__ = "0.1.0"

from probitas._types import (
    CoverageReport,
    Decision,
    EvalResult,
    RuleConfig,
    RuleKind,
    RuleResult,
    TestCase,
    TestResult,
    ToolCall,
)
from probitas.coverage import calculate_coverage
from probitas.engine import evaluate, run_tests

__all__ = [
    "CoverageReport",
    "Decision",
    "EvalResult",
    "RuleConfig",
    "RuleKind",
    "RuleResult",
    "TestCase",
    "TestResult",
    "ToolCall",
    "calculate_coverage",
    "evaluate",
    "run_tests",
]
