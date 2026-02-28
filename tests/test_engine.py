"""Tests for the rule evaluation engine."""

from __future__ import annotations

from probitas._types import Decision, RuleConfig, ToolCall
from probitas.engine import evaluate, run_tests


class TestRegexBlock:
    def test_blocks_dangerous_pattern(self, regex_block_rule, dangerous_query):
        result = evaluate([regex_block_rule], dangerous_query)
        assert result.decision == Decision.BLOCK
        assert result.blocking_rule == "block_sql_injection"

    def test_allows_safe_query(self, regex_block_rule, safe_query):
        result = evaluate([regex_block_rule], safe_query)
        assert result.decision == Decision.ALLOW
        assert result.blocking_rule is None

    def test_only_applies_to_matching_tools(self, regex_block_rule):
        call = ToolCall(name="unrelated_tool", args={"query": "DROP TABLE users"})
        result = evaluate([regex_block_rule], call)
        assert result.decision == Decision.ALLOW


class TestRegexRequire:
    def test_blocks_missing_field(self):
        rule = RuleConfig(
            name="require_confirm",
            rule_type="regex_require",
            params={"fields": ["confirmation_id"], "pattern": r"^CONF-[A-Z0-9]{8}$"},
            applies_to=["transfer_funds"],
        )
        call = ToolCall(name="transfer_funds", args={"amount": 1000})
        result = evaluate([rule], call)
        assert result.decision == Decision.BLOCK

    def test_blocks_invalid_pattern(self):
        rule = RuleConfig(
            name="require_confirm",
            rule_type="regex_require",
            params={"fields": ["confirmation_id"], "pattern": r"^CONF-[A-Z0-9]{8}$"},
            applies_to=["transfer_funds"],
        )
        call = ToolCall(name="transfer_funds", args={"confirmation_id": "bad-id"})
        result = evaluate([rule], call)
        assert result.decision == Decision.BLOCK

    def test_allows_valid_pattern(self):
        rule = RuleConfig(
            name="require_confirm",
            rule_type="regex_require",
            params={"fields": ["confirmation_id"], "pattern": r"^CONF-[A-Z0-9]{8}$"},
            applies_to=["transfer_funds"],
        )
        call = ToolCall(name="transfer_funds", args={"confirmation_id": "CONF-AB12CD34"})
        result = evaluate([rule], call)
        assert result.decision == Decision.ALLOW


class TestPiiDetect:
    def test_blocks_email(self, pii_rule, pii_call):
        result = evaluate([pii_rule], pii_call)
        assert result.decision == Decision.BLOCK
        assert result.blocking_rule == "detect_pii"

    def test_allows_clean_text(self, pii_rule):
        call = ToolCall(name="send_email", args={"body": "Hello, how are you?"})
        result = evaluate([pii_rule], call)
        assert result.decision == Decision.ALLOW


class TestEntitlement:
    def test_analyst_allowed_for_search(self, entitlement_rule, analyst_call):
        result = evaluate([entitlement_rule], analyst_call)
        assert result.decision == Decision.ALLOW

    def test_analyst_blocked_for_delete(self, entitlement_rule):
        call = ToolCall(name="delete_user", args={}, metadata={"role": "analyst"})
        result = evaluate([entitlement_rule], call)
        assert result.decision == Decision.BLOCK

    def test_admin_allowed_for_anything(self, entitlement_rule, admin_call):
        result = evaluate([entitlement_rule], admin_call)
        assert result.decision == Decision.ALLOW

    def test_unknown_role_default_block(self, entitlement_rule):
        call = ToolCall(name="search", args={}, metadata={"role": "intern"})
        result = evaluate([entitlement_rule], call)
        assert result.decision == Decision.BLOCK


class TestBudget:
    def test_blocks_expensive_call(self, budget_rule, expensive_call):
        result = evaluate([budget_rule], expensive_call)
        assert result.decision == Decision.BLOCK
        assert "exceeds" in result.reason

    def test_allows_cheap_call(self, budget_rule, cheap_call):
        result = evaluate([budget_rule], cheap_call)
        assert result.decision == Decision.ALLOW

    def test_missing_cost_defaults_allow(self, budget_rule):
        call = ToolCall(name="gpt4_query", args={"prompt": "Hi"})
        result = evaluate([budget_rule], call)
        assert result.decision == Decision.ALLOW


class TestToolAllowlist:
    def test_blocks_unlisted_tool(self, allowlist_rule):
        call = ToolCall(name="delete_database", args={})
        result = evaluate([allowlist_rule], call)
        assert result.decision == Decision.BLOCK

    def test_allows_listed_tool(self, allowlist_rule):
        call = ToolCall(name="search", args={"q": "test"})
        result = evaluate([allowlist_rule], call)
        assert result.decision == Decision.ALLOW


class TestShortCircuit:
    def test_first_block_wins(self, regex_block_rule, pii_rule, dangerous_query):
        result = evaluate([regex_block_rule, pii_rule], dangerous_query)
        assert result.decision == Decision.BLOCK
        assert result.blocking_rule == "block_sql_injection"
        assert len(result.rules_evaluated) == 1


class TestRunTests:
    def test_all_pass(self, regex_block_rule, sample_test_case):
        results = run_tests([regex_block_rule], [sample_test_case])
        assert len(results) == 1
        assert results[0].passed

    def test_detects_failure(self, regex_block_rule, safe_query):
        wrong_case = __import__("probitas._types", fromlist=["TestCase"]).TestCase(
            description="Should block but actually allows",
            tool_call=safe_query,
            expected=Decision.BLOCK,
        )
        results = run_tests([regex_block_rule], [wrong_case])
        assert len(results) == 1
        assert not results[0].passed

    def test_expected_rule_match(self, regex_block_rule, blocking_test_case):
        results = run_tests([regex_block_rule], [blocking_test_case])
        assert results[0].passed
        assert results[0].actual_rule == "block_sql_injection"

    def test_expected_rule_mismatch(self, regex_block_rule, dangerous_query):
        from probitas._types import TestCase

        case = TestCase(
            description="Wrong rule expected",
            tool_call=dangerous_query,
            expected=Decision.BLOCK,
            expected_rule="wrong_rule_name",
        )
        results = run_tests([regex_block_rule], [case])
        assert not results[0].passed
