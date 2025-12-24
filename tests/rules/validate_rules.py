#!/usr/bin/env python3
"""
CLI script to validate Sigma detection rules.

Usage:
    python validate_rules.py /path/to/rules/
    python validate_rules.py /rules/sigma/okta/itdr/
    python validate_rules.py /rules/sigma/ --verbose
    python validate_rules.py /rules/sigma/ --output report.json
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

from rule_test_runner import RuleTestRunner, print_test_report


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Validate Sigma detection rules against test data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python validate_rules.py /rules/sigma/okta/itdr/
    python validate_rules.py /rules/sigma/ --verbose
    python validate_rules.py /rules/sigma/ --output report.json
    python validate_rules.py /rules/sigma/ --fail-on-error
        """,
    )

    parser.add_argument(
        "rules_path",
        type=str,
        help="Path to directory containing Sigma rules",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show verbose output including all test results",
    )

    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output file for JSON report",
    )

    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help="Exit with non-zero status if any tests fail",
    )

    parser.add_argument(
        "--min-success-rate",
        type=float,
        default=0.0,
        help="Minimum success rate required (0-100)",
    )

    parser.add_argument(
        "--rule-types",
        type=str,
        nargs="+",
        choices=[
            "brute_force",
            "password_spray",
            "mfa_fatigue",
            "impossible_travel",
            "privilege_escalation",
            "credential_stuffing",
        ],
        help="Only test specific rule types",
    )

    return parser.parse_args()


def validate_path(path: str) -> Path:
    """Validate and return path."""
    p = Path(path)
    if not p.exists():
        print(f"Error: Path does not exist: {path}", file=sys.stderr)
        sys.exit(1)
    if not p.is_dir():
        print(f"Error: Path is not a directory: {path}", file=sys.stderr)
        sys.exit(1)
    return p


def print_verbose_results(report):
    """Print detailed results for each test."""
    print("\nDetailed Test Results:")
    print("-" * 60)

    current_rule = None
    for result in report.results:
        if result.rule_id != current_rule:
            current_rule = result.rule_id
            print(f"\n{result.rule_title} ({result.rule_id})")

        status = "✓ PASS" if result.passed else "✗ FAIL"
        print(f"  {status}: {result.test_case}")
        if result.error:
            print(f"         Error: {result.error}")
        if not result.passed:
            print(f"         Expected: {'match' if result.expected_match else 'no match'}")
            print(f"         Actual: {'match' if result.actual_match else 'no match'}")


def main():
    """Main entry point."""
    args = parse_args()

    # Validate path
    rules_path = validate_path(args.rules_path)

    print(f"Validating rules in: {rules_path}")
    print("=" * 60)

    # Run validation
    runner = RuleTestRunner()
    report = runner.run_all_tests(str(rules_path))

    # Print report
    print_test_report(report)

    # Print verbose output if requested
    if args.verbose:
        print_verbose_results(report)

    # Save JSON report if requested
    if args.output:
        output_path = Path(args.output)
        with open(output_path, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"\nReport saved to: {output_path}")

    # Check success criteria
    exit_code = 0

    if args.fail_on_error and report.failed_tests > 0:
        print(f"\nFailed: {report.failed_tests} test(s) failed", file=sys.stderr)
        exit_code = 1

    if args.min_success_rate > 0 and report.success_rate < args.min_success_rate:
        print(
            f"\nFailed: Success rate {report.success_rate:.1f}% "
            f"below minimum {args.min_success_rate}%",
            file=sys.stderr,
        )
        exit_code = 1

    # Print summary
    if exit_code == 0:
        print("\n✓ Validation passed")
    else:
        print("\n✗ Validation failed", file=sys.stderr)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
