"""Tests for CLI entry point."""

from __future__ import annotations

from pathlib import Path

from probitas.cli import main


POLICY_YAML = """\
rules:
  - name: block_sql_injection
    type: regex_block
    applies_to: [execute_sql]
    params:
      fields: [query]
      patterns:
        - "(?i)(DROP|DELETE|TRUNCATE)\\\\s+TABLE"
  - name: detect_pii
    type: pii_detect
    applies_to: ["*"]
    params:
      detectors: [email]
      action: block
"""

TESTS_YAML = """\
tests:
  - description: Safe query allowed
    tool_call:
      name: execute_sql
      args:
        query: SELECT 1
    expected: allow
  - description: DROP TABLE blocked
    tool_call:
      name: execute_sql
      args:
        query: DROP TABLE users
    expected: block
    expected_rule: block_sql_injection
"""


def _write_fixtures(tmp_path: Path) -> tuple[Path, Path]:
    policy = tmp_path / "policy.yaml"
    policy.write_text(POLICY_YAML)
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_sql.yaml").write_text(TESTS_YAML)
    return policy, tests_dir


class TestCliRun:
    def test_all_pass_returns_zero(self, tmp_path):
        policy, tests_dir = _write_fixtures(tmp_path)
        code = main(["run", "--config", str(policy), "--tests", str(tests_dir)])
        assert code == 0

    def test_failure_returns_one(self, tmp_path):
        policy = tmp_path / "policy.yaml"
        policy.write_text("rules: []\n")
        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        (tests_dir / "t.yaml").write_text(
            "tests:\n"
            "  - description: expect block but no rules\n"
            "    tool_call:\n"
            "      name: x\n"
            "      args: {}\n"
            "    expected: block\n"
        )
        code = main(["run", "--config", str(policy), "--tests", str(tests_dir)])
        assert code == 1

    def test_missing_config_returns_two(self, tmp_path):
        code = main(["run", "--config", str(tmp_path / "nope.yaml"), "--tests", str(tmp_path)])
        assert code == 2

    def test_json_format(self, tmp_path, capsys):
        policy, tests_dir = _write_fixtures(tmp_path)
        code = main(["run", "--config", str(policy), "--tests", str(tests_dir), "--format", "json"])
        assert code == 0
        import json
        data = json.loads(capsys.readouterr().out)
        assert "summary" in data

    def test_output_to_file(self, tmp_path):
        policy, tests_dir = _write_fixtures(tmp_path)
        out_file = tmp_path / "report.txt"
        code = main(["run", "--config", str(policy), "--tests", str(tests_dir), "--output", str(out_file)])
        assert code == 0
        assert out_file.exists()
        assert "probitas" in out_file.read_text()

    def test_no_command_returns_two(self):
        code = main([])
        assert code == 2
