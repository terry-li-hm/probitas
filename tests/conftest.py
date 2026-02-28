"""Shared fixtures for probitas tests."""

from __future__ import annotations

import pytest

from probitas._types import Decision, RuleConfig, RuleKind, TestCase, ToolCall

# ---------------------------------------------------------------------------
# Tool calls
# ---------------------------------------------------------------------------


@pytest.fixture
def safe_query():
    return ToolCall(name="execute_sql", args={"query": "SELECT * FROM users"})


@pytest.fixture
def dangerous_query():
    return ToolCall(name="execute_sql", args={"query": "DROP TABLE users"})


@pytest.fixture
def pii_call():
    return ToolCall(
        name="send_email",
        args={"body": "Contact john@example.com or call +852 9123 4567"},
    )


@pytest.fixture
def analyst_call():
    return ToolCall(name="search", args={"q": "revenue"}, metadata={"role": "analyst"})


@pytest.fixture
def admin_call():
    return ToolCall(name="delete_user", args={"id": "123"}, metadata={"role": "admin"})


@pytest.fixture
def expensive_call():
    return ToolCall(
        name="gpt4_query",
        args={"prompt": "Summarize"},
        metadata={"estimated_cost": 5.50},
    )


@pytest.fixture
def cheap_call():
    return ToolCall(name="gpt4_query", args={"prompt": "Hi"}, metadata={"estimated_cost": 0.01})


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


@pytest.fixture
def regex_block_rule():
    return RuleConfig(
        name="block_sql_injection",
        rule_type="regex_block",
        params={"fields": ["query"], "patterns": [r"(?i)(DROP|DELETE|TRUNCATE)\s+TABLE"]},
        applies_to=["execute_sql"],
    )


@pytest.fixture
def pii_rule():
    return RuleConfig(
        name="detect_pii",
        rule_type="pii_detect",
        params={"detectors": ["email", "phone_intl"], "action": "block"},
        applies_to=["*"],
    )


@pytest.fixture
def entitlement_rule():
    return RuleConfig(
        name="tool_entitlement",
        rule_type="entitlement",
        params={"roles": {"analyst": ["search", "get_data"], "admin": ["*"]}, "default": "block"},
        applies_to=["*"],
    )


@pytest.fixture
def budget_rule():
    return RuleConfig(
        name="cost_limit",
        rule_type="budget",
        params={"max_cost": 1.00},
        applies_to=["*"],
    )


@pytest.fixture
def allowlist_rule():
    return RuleConfig(
        name="tool_allowlist",
        rule_type="tool_allowlist",
        params={"allowed_tools": ["search", "get_data", "summarize"]},
        applies_to=["*"],
    )


@pytest.fixture
def semantic_rule():
    return RuleConfig(
        name="tone_check",
        rule_type="regex_block",
        params={"fields": [], "patterns": []},
        applies_to=["*"],
        kind=RuleKind.SEMANTIC,
    )


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_test_case(safe_query):
    return TestCase(
        description="Safe SQL query should be allowed",
        tool_call=safe_query,
        expected=Decision.ALLOW,
    )


@pytest.fixture
def blocking_test_case(dangerous_query):
    return TestCase(
        description="DROP TABLE should be blocked",
        tool_call=dangerous_query,
        expected=Decision.BLOCK,
        expected_rule="block_sql_injection",
    )


# ---------------------------------------------------------------------------
# Policy config dict (for loader tests)
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_policy_dict():
    return {
        "version": "1.0",
        "policy_version": "1.0.0",
        "rules": [
            {
                "name": "block_sql_injection",
                "type": "regex_block",
                "applies_to": ["execute_sql"],
                "params": {
                    "fields": ["query"],
                    "patterns": [r"(?i)(DROP|DELETE|TRUNCATE)\s+TABLE"],
                },
            },
            {
                "name": "detect_pii",
                "type": "pii_detect",
                "applies_to": ["*"],
                "params": {"detectors": ["email", "phone_intl"], "action": "block"},
            },
            {
                "name": "cost_limit",
                "type": "budget",
                "applies_to": ["*"],
                "params": {"max_cost": 1.00},
            },
        ],
    }
