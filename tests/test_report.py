"""Tests for report generators."""

from __future__ import annotations

import json

from probitas._types import CoverageReport, Decision, TestCase, TestResult, ToolCall
from probitas.report import generate_html, generate_json, generate_text


def _sample_results() -> tuple[list[TestResult], CoverageReport]:
    tc_pass = TestCase(
        description="Safe query allowed",
        tool_call=ToolCall(name="execute_sql", args={"query": "SELECT 1"}),
        expected=Decision.ALLOW,
    )
    tc_fail = TestCase(
        description="Should block injection",
        tool_call=ToolCall(name="execute_sql", args={"query": "DROP TABLE"}),
        expected=Decision.BLOCK,
    )
    results = [
        TestResult(test_case=tc_pass, actual=Decision.ALLOW, actual_rule=None, passed=True, reason="All rules passed"),
        TestResult(
            test_case=tc_fail, actual=Decision.ALLOW, actual_rule=None, passed=False,
            reason="Expected block, got allow",
        ),
    ]
    coverage = CoverageReport(
        total_deterministic_rules=2,
        rules_exercised=["block_sql"],
        rules_not_exercised=["detect_pii"],
        semantic_rules=["tone_check"],
        coverage_pct=50.0,
    )
    return results, coverage


class TestTextReport:
    def test_contains_key_elements(self):
        results, coverage = _sample_results()
        text = generate_text(results, coverage, "policy content")
        assert "probitas" in text
        assert "1/2 passed" in text
        assert "PASS" in text
        assert "FAIL" in text
        assert "50.0%" in text
        assert "tone_check" in text
        assert "Evidence hash" in text

    def test_policy_hash_present(self):
        results, coverage = _sample_results()
        text = generate_text(results, coverage, "some policy")
        assert "Policy hash" in text


class TestJsonReport:
    def test_valid_json(self):
        results, coverage = _sample_results()
        output = generate_json(results, coverage, "policy")
        data = json.loads(output)
        assert data["summary"]["total"] == 2
        assert data["summary"]["passed"] == 1
        assert data["summary"]["failed"] == 1
        assert data["coverage"]["coverage_pct"] == 50.0
        assert "evidence_hash" in data
        assert len(data["evidence_hash"]) == 64  # SHA-256 hex

    def test_policy_hash_is_sha256(self):
        results, coverage = _sample_results()
        output = generate_json(results, coverage, "test")
        data = json.loads(output)
        assert len(data["policy_hash"]) == 64


class TestHtmlReport:
    def test_contains_html_structure(self):
        results, coverage = _sample_results()
        html = generate_html(results, coverage, "policy")
        assert "<!DOCTYPE html>" in html
        assert "probitas" in html
        assert "Safe query allowed" in html
        assert "50.0%" in html or "50.0" in html

    def test_sha256_present(self):
        results, coverage = _sample_results()
        html = generate_html(results, coverage, "policy")
        assert "Evidence hash" in html or "evidence_hash" in html
