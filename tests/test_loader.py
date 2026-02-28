"""Tests for policy and test case loaders."""

from __future__ import annotations

import pytest

from probitas._types import Decision, RuleKind
from probitas.loader import load_policy, load_policy_dict, load_tests


class TestLoadPolicyDict:
    def test_loads_rules(self, sample_policy_dict):
        rules = load_policy_dict(sample_policy_dict)
        assert len(rules) == 3
        assert rules[0].name == "block_sql_injection"
        assert rules[0].rule_type == "regex_block"

    def test_default_kind_is_deterministic(self, sample_policy_dict):
        rules = load_policy_dict(sample_policy_dict)
        assert all(r.kind == RuleKind.DETERMINISTIC for r in rules)

    def test_unknown_type_raises(self):
        config = {"rules": [{"name": "bad", "type": "nonexistent", "applies_to": ["*"]}]}
        with pytest.raises(ValueError, match="unknown type"):
            load_policy_dict(config)

    def test_missing_name_raises(self):
        config = {"rules": [{"type": "regex_block"}]}
        with pytest.raises(ValueError, match="missing 'name'"):
            load_policy_dict(config)

    def test_missing_type_raises(self):
        config = {"rules": [{"name": "foo"}]}
        with pytest.raises(ValueError, match="missing 'type'"):
            load_policy_dict(config)


class TestLoadPolicyYAML:
    def test_loads_yaml_file(self, tmp_path):
        policy = tmp_path / "policy.yaml"
        policy.write_text(
            "rules:\n"
            "  - name: test_rule\n"
            "    type: regex_block\n"
            "    applies_to: ['*']\n"
            "    params:\n"
            "      fields: [query]\n"
            "      patterns: ['DROP']\n"
        )
        rules = load_policy(policy)
        assert len(rules) == 1
        assert rules[0].name == "test_rule"


class TestLoadTests:
    def test_loads_single_file(self, tmp_path):
        test_file = tmp_path / "test.yaml"
        test_file.write_text(
            "tests:\n"
            "  - description: allow safe query\n"
            "    tool_call:\n"
            "      name: execute_sql\n"
            "      args:\n"
            "        query: SELECT 1\n"
            "    expected: allow\n"
        )
        cases = load_tests(test_file)
        assert len(cases) == 1
        assert cases[0].expected == Decision.ALLOW
        assert cases[0].tool_call.name == "execute_sql"

    def test_loads_directory(self, tmp_path):
        for name in ["a.yaml", "b.yaml"]:
            (tmp_path / name).write_text(
                "tests:\n"
                "  - description: test\n"
                "    tool_call:\n"
                "      name: search\n"
                "      args: {}\n"
                "    expected: allow\n"
            )
        cases = load_tests(tmp_path)
        assert len(cases) == 2

    def test_invalid_expected_raises(self, tmp_path):
        test_file = tmp_path / "test.yaml"
        test_file.write_text(
            "tests:\n"
            "  - description: bad\n"
            "    tool_call:\n"
            "      name: x\n"
            "      args: {}\n"
            "    expected: maybe\n"
        )
        with pytest.raises(ValueError, match="must be 'allow' or 'block'"):
            load_tests(test_file)

    def test_missing_tool_call_raises(self, tmp_path):
        test_file = tmp_path / "test.yaml"
        test_file.write_text(
            "tests:\n"
            "  - description: bad\n"
            "    expected: allow\n"
        )
        with pytest.raises(ValueError, match="missing 'tool_call'"):
            load_tests(test_file)

    def test_empty_tests_raises(self, tmp_path):
        test_file = tmp_path / "test.yaml"
        test_file.write_text("tests: []\n")
        with pytest.raises(ValueError, match="empty"):
            load_tests(test_file)
