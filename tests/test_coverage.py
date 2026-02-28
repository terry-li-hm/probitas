"""Tests for coverage calculator."""

from __future__ import annotations

from probitas._types import (
    Decision,
    RuleConfig,
    RuleKind,
    TestCase,
    TestResult,
    ToolCall,
)
from probitas.coverage import calculate_coverage


def _make_result(
    actual_rule: str | None,
    passed: bool = True,
    rules_evaluated: list[str] | None = None,
) -> TestResult:
    return TestResult(
        test_case=TestCase(
            description="test",
            tool_call=ToolCall(name="x", args={}),
            expected=Decision.BLOCK,
        ),
        actual=Decision.BLOCK,
        actual_rule=actual_rule,
        passed=passed,
        reason="",
        rules_evaluated=(
            rules_evaluated if rules_evaluated is not None
            else ([actual_rule] if actual_rule else [])
        ),
    )


class TestCoverageCalculation:
    def test_full_coverage(self):
        rules = [
            RuleConfig(name="r1", rule_type="regex_block", params={}, applies_to=["*"]),
            RuleConfig(name="r2", rule_type="pii_detect", params={}, applies_to=["*"]),
        ]
        results = [_make_result("r1"), _make_result("r2")]
        cov = calculate_coverage(rules, results)
        assert cov.coverage_pct == 100.0
        assert cov.total_deterministic_rules == 2
        assert sorted(cov.rules_exercised) == ["r1", "r2"]
        assert cov.rules_not_exercised == []

    def test_partial_coverage(self):
        rules = [
            RuleConfig(name="r1", rule_type="regex_block", params={}, applies_to=["*"]),
            RuleConfig(name="r2", rule_type="pii_detect", params={}, applies_to=["*"]),
        ]
        results = [_make_result("r1")]
        cov = calculate_coverage(rules, results)
        assert cov.coverage_pct == 50.0
        assert cov.rules_not_exercised == ["r2"]

    def test_zero_rules_is_100_pct(self):
        cov = calculate_coverage([], [])
        assert cov.coverage_pct == 100.0
        assert cov.total_deterministic_rules == 0

    def test_semantic_rules_excluded_from_coverage(self):
        rules = [
            RuleConfig(name="det", rule_type="regex_block", params={}, applies_to=["*"]),
            RuleConfig(
                name="sem", rule_type="regex_block", params={},
                applies_to=["*"], kind=RuleKind.SEMANTIC
            ),
        ]
        results = [_make_result("det")]
        cov = calculate_coverage(rules, results)
        assert cov.coverage_pct == 100.0
        assert cov.semantic_rules == ["sem"]
        assert cov.total_deterministic_rules == 1

    def test_all_semantic_rules(self):
        rules = [
            RuleConfig(
                name="s1", rule_type="regex_block", params={},
                applies_to=["*"], kind=RuleKind.SEMANTIC
            ),
        ]
        cov = calculate_coverage(rules, [])
        assert cov.coverage_pct == 100.0
        assert cov.total_deterministic_rules == 0
        assert cov.semantic_rules == ["s1"]

    def test_allow_result_still_counts_as_exercised(self):
        rules = [
            RuleConfig(name="r1", rule_type="regex_block", params={}, applies_to=["*"]),
        ]
        # Rule evaluated but ALLOWed — should still count as exercised
        results = [_make_result(None, rules_evaluated=["r1"])]
        cov = calculate_coverage(rules, results)
        assert cov.coverage_pct == 100.0
        assert cov.rules_exercised == ["r1"]

    def test_no_rules_evaluated(self):
        rules = [
            RuleConfig(name="r1", rule_type="regex_block", params={}, applies_to=["*"]),
        ]
        results = [_make_result(None, rules_evaluated=[])]
        cov = calculate_coverage(rules, results)
        assert cov.coverage_pct == 0.0
        assert cov.rules_not_exercised == ["r1"]
