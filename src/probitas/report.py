"""Report generators: text, JSON, HTML with SHA-256 tamper-evidence."""

from __future__ import annotations

import hashlib
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from probitas._types import CoverageReport, TestResult


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_string(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Shared data builder
# ---------------------------------------------------------------------------


def _build_report_data(
    results: list[TestResult],
    coverage: CoverageReport,
    policy_content: str = "",
) -> dict[str, Any]:
    """Build the canonical report data dict."""
    policy_hash = _hash_string(policy_content) if policy_content else ""
    test_rows = []
    for r in results:
        test_rows.append(
            {
                "description": r.test_case.description,
                "tool": r.test_case.tool_call.name,
                "expected": r.test_case.expected.value,
                "actual": r.actual.value,
                "rule": r.actual_rule or "",
                "passed": r.passed,
                "reason": r.reason,
            }
        )

    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed

    data: dict[str, Any] = {
        "timestamp": _now_iso(),
        "policy_hash": policy_hash,
        "summary": {
            "total": len(results),
            "passed": passed,
            "failed": failed,
        },
        "coverage": {
            "total_deterministic_rules": coverage.total_deterministic_rules,
            "rules_exercised": coverage.rules_exercised,
            "rules_not_exercised": coverage.rules_not_exercised,
            "semantic_rules": coverage.semantic_rules,
            "coverage_pct": coverage.coverage_pct,
        },
        "tests": test_rows,
    }

    # Evidence bundle hash: SHA-256 of (policy_hash + serialised results)
    bundle_str = policy_hash + json.dumps(test_rows, sort_keys=True)
    data["evidence_hash"] = _hash_string(bundle_str)

    return data


# ---------------------------------------------------------------------------
# Text report
# ---------------------------------------------------------------------------


def generate_text(
    results: list[TestResult],
    coverage: CoverageReport,
    policy_content: str = "",
) -> str:
    """Generate a terminal-friendly text report."""
    data = _build_report_data(results, coverage, policy_content)
    lines: list[str] = []
    lines.append("probitas — guardrail regression test report")
    lines.append("=" * 50)
    lines.append(f"Timestamp: {data['timestamp']}")
    if data["policy_hash"]:
        lines.append(f"Policy hash: {data['policy_hash'][:16]}...")
    lines.append("")

    s = data["summary"]
    lines.append(f"Results: {s['passed']}/{s['total']} passed, {s['failed']} failed")
    lines.append("")

    for t in data["tests"]:
        status = "PASS" if t["passed"] else "FAIL"
        lines.append(f"  [{status}] {t['description']}")
        if not t["passed"]:
            lines.append(
                f"         expected={t['expected']}, actual={t['actual']}, reason={t['reason']}"
            )
    lines.append("")

    c = data["coverage"]
    exercised = len(c["rules_exercised"])
    total = c["total_deterministic_rules"]
    lines.append(f"Coverage: {c['coverage_pct']}% ({exercised}/{total} deterministic rules)")
    if c["rules_not_exercised"]:
        lines.append(f"  Not exercised: {', '.join(c['rules_not_exercised'])}")
    if c["semantic_rules"]:
        lines.append(f"  Semantic (manual validation required): {', '.join(c['semantic_rules'])}")
    lines.append("")
    lines.append(f"Evidence hash: {data['evidence_hash'][:16]}...")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------


def generate_json(
    results: list[TestResult],
    coverage: CoverageReport,
    policy_content: str = "",
) -> str:
    """Generate a JSON report for CI pipeline consumption."""
    data = _build_report_data(results, coverage, policy_content)
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------


def generate_html(
    results: list[TestResult],
    coverage: CoverageReport,
    policy_content: str = "",
) -> str:
    """Generate an HTML evidence report. Uses Jinja2 if available, else string.Template."""
    data = _build_report_data(results, coverage, policy_content)

    try:
        return _render_jinja2(data)
    except ImportError:
        return _render_stdlib(data)


def _render_jinja2(data: dict[str, Any]) -> str:
    from jinja2 import Environment, FileSystemLoader

    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
    template = env.get_template("report.html")
    return template.render(**data)


def _render_stdlib(data: dict[str, Any]) -> str:
    """Minimal HTML fallback without Jinja2."""
    e = html.escape
    rows = ""
    for t in data["tests"]:
        status = "PASS" if t["passed"] else "FAIL"
        color = "#22c55e" if t["passed"] else "#ef4444"
        rows += (
            f"<tr><td>{e(t['description'])}</td><td>{e(t['expected'])}</td>"
            f"<td>{e(t['actual'])}</td><td>{e(t['rule'])}</td>"
            f'<td style="color:{color};font-weight:bold">{status}</td></tr>\n'
        )

    s = data["summary"]
    c = data["coverage"]
    semantic = e(", ".join(c["semantic_rules"])) if c["semantic_rules"] else "none"
    not_exercised = e(", ".join(c["rules_not_exercised"])) if c["rules_not_exercised"] else "none"

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>probitas report</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid #d1d5db; padding: 0.5rem; text-align: left; }}
th {{ background: #f3f4f6; }}
.meta {{ color: #6b7280; font-size: 0.875rem; }}
</style></head>
<body>
<h1>probitas — guardrail regression test report</h1>
<p class="meta">Timestamp: {data["timestamp"]}<br>
Policy hash: {data["policy_hash"][:16]}...<br>
Evidence hash: {data["evidence_hash"][:16]}...</p>

<h2>Results: {s["passed"]}/{s["total"]} passed, {s["failed"]} failed</h2>
<table>
<tr><th>Test</th><th>Expected</th><th>Actual</th><th>Rule</th><th>Status</th></tr>
{rows}</table>

<h2>Coverage: {c["coverage_pct"]}%</h2>
<p>{len(c["rules_exercised"])}/{c["total_deterministic_rules"]} deterministic rules exercised</p>
<p>Not exercised: {not_exercised}</p>
<p>Semantic (manual validation required): {semantic}</p>
</body></html>"""
