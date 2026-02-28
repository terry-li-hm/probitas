"""YAML loaders for policy config and test case files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from probitas._types import Decision, RuleConfig, RuleKind, TestCase, ToolCall
from probitas.engine import _RULE_REGISTRY


def _require_yaml() -> Any:
    try:
        import yaml
    except ImportError:
        raise ImportError(
            "pyyaml is required for loading YAML files. Install it with: pip install probitas[yaml]"
        ) from None
    return yaml


def load_policy(path: str | Path) -> list[RuleConfig]:
    """Load policy rules from a YAML file."""
    yaml = _require_yaml()
    path = Path(path)
    with path.open() as f:
        config = yaml.safe_load(f)
    if not isinstance(config, dict):
        raise ValueError(f"Policy file must be a YAML mapping, got {type(config).__name__}")
    return _parse_rules(config)


def load_policy_dict(config: dict[str, Any]) -> list[RuleConfig]:
    """Load policy rules from a Python dict (same schema as YAML)."""
    return _parse_rules(config)


def _parse_rules(config: dict[str, Any]) -> list[RuleConfig]:
    rules: list[RuleConfig] = []
    for i, rule_data in enumerate(config.get("rules", [])):
        name = rule_data.get("name")
        if not name:
            raise ValueError(f"Rule at index {i} missing 'name'")
        rule_type = rule_data.get("type")
        if not rule_type:
            raise ValueError(f"Rule '{name}' missing 'type'")
        if rule_type not in _RULE_REGISTRY:
            raise ValueError(
                f"Rule '{name}' has unknown type '{rule_type}'. Valid: {sorted(_RULE_REGISTRY)}"
            )
        kind_str = rule_data.get("kind", "deterministic")
        try:
            kind = RuleKind(kind_str)
        except ValueError:
            raise ValueError(
                f"Rule '{name}' has invalid kind '{kind_str}'. Valid: {[k.value for k in RuleKind]}"
            ) from None
        rules.append(
            RuleConfig(
                name=name,
                rule_type=rule_type,
                params=rule_data.get("params", {}),
                applies_to=rule_data.get("applies_to", ["*"]),
                kind=kind,
            )
        )
    return rules


def load_tests(path: str | Path) -> list[TestCase]:
    """Load test cases from a YAML file or directory of YAML files."""
    path = Path(path)
    if path.is_dir():
        cases: list[TestCase] = []
        for p in sorted(path.glob("*.yaml")):
            cases.extend(_load_test_file(p))
        for p in sorted(path.glob("*.yml")):
            cases.extend(_load_test_file(p))
        return cases
    return _load_test_file(path)


def _load_test_file(path: Path) -> list[TestCase]:
    yaml = _require_yaml()
    with path.open() as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Test file {path.name} must be a YAML mapping")
    raw_cases = data.get("tests", [])
    if not raw_cases:
        raise ValueError(f"Test file {path.name} has no 'tests' key or it is empty")
    cases: list[TestCase] = []
    for i, tc in enumerate(raw_cases):
        description = tc.get("description", f"test_{i}")
        tool_call_data = tc.get("tool_call")
        if not tool_call_data:
            raise ValueError(f"Test '{description}' in {path.name} missing 'tool_call'")
        expected_str = tc.get("expected")
        if expected_str not in ("allow", "block"):
            raise ValueError(
                f"Test '{description}' in {path.name}: expected must be 'allow' or 'block'"
            )
        tool_call = ToolCall(
            name=tool_call_data.get("name", ""),
            args=tool_call_data.get("args", {}),
            metadata=tool_call_data.get("metadata", {}),
        )
        cases.append(
            TestCase(
                description=description,
                tool_call=tool_call,
                expected=Decision(expected_str),
                expected_rule=tc.get("expected_rule"),
            )
        )
    return cases
