"""CLI entry point: probitas run."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="probitas", description="Guardrail regression testing CLI"
    )
    sub = parser.add_subparsers(dest="command")

    run_parser = sub.add_parser("run", help="Run guardrail tests against a policy")
    run_parser.add_argument("--config", required=True, help="Path to policy YAML file")
    run_parser.add_argument("--tests", required=True, help="Path to test YAML file or directory")
    run_parser.add_argument(
        "--format", choices=["text", "json", "html"], default="text", help="Output format"
    )
    run_parser.add_argument("--output", help="Write report to file (default: stdout)")

    args = parser.parse_args(argv)

    if args.command != "run":
        parser.print_help()
        return 2

    return _cmd_run(args)


def _cmd_run(args: argparse.Namespace) -> int:
    from probitas import report
    from probitas.coverage import calculate_coverage
    from probitas.engine import run_tests
    from probitas.loader import load_policy, load_tests

    config_path = Path(args.config)
    tests_path = Path(args.tests)

    if not config_path.exists():
        print(f"Error: config file not found: {config_path}", file=sys.stderr)
        return 2
    if not tests_path.exists():
        print(f"Error: tests path not found: {tests_path}", file=sys.stderr)
        return 2

    try:
        rules = load_policy(config_path)
    except Exception as e:
        print(f"Error loading policy: {e}", file=sys.stderr)
        return 2

    try:
        test_cases = load_tests(tests_path)
    except Exception as e:
        print(f"Error loading tests: {e}", file=sys.stderr)
        return 2

    # Read policy content for hashing
    policy_content = config_path.read_text()

    results = run_tests(rules, test_cases)
    coverage = calculate_coverage(rules, results)

    if args.format == "json":
        output = report.generate_json(results, coverage, policy_content)
    elif args.format == "html":
        output = report.generate_html(results, coverage, policy_content)
    else:
        output = report.generate_text(results, coverage, policy_content)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    # Exit code: 0 = all pass, 1 = failures
    has_failures = any(not r.passed for r in results)
    return 1 if has_failures else 0


if __name__ == "__main__":
    sys.exit(main())
