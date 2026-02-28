"""Coverage calculator — rules_exercised / total_deterministic_rules."""

from __future__ import annotations

from probitas._types import CoverageReport, RuleConfig, RuleKind, TestResult


def calculate_coverage(
    rules: list[RuleConfig],
    results: list[TestResult],
) -> CoverageReport:
    """Calculate guardrail coverage from test results."""
    deterministic = [r for r in rules if r.kind == RuleKind.DETERMINISTIC]
    semantic = [r for r in rules if r.kind == RuleKind.SEMANTIC]
    det_names = {r.name for r in deterministic}
    exercised = {r.actual_rule for r in results if r.actual_rule}
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
