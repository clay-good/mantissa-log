#!/usr/bin/env python3
"""Test SQL conversion for all Sigma rules."""

import sys
from pathlib import Path
from typing import List, Tuple

import yaml

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.shared.detection.sigma_converter import (
    SigmaRuleConverter,
    SIGMA_AVAILABLE,
    SigmaConversionError
)


def test_rule_conversion(rule_path: Path, converter: SigmaRuleConverter) -> Tuple[bool, List[str]]:
    """Test that a rule can be converted to SQL."""
    try:
        sql = converter.convert_rule_to_sql(str(rule_path), use_cache=False)

        if not sql or len(sql) == 0:
            return False, ["No SQL generated"]

        # Basic SQL validation
        sql_upper = sql.upper()
        if "SELECT" not in sql_upper:
            return False, ["Generated SQL does not contain SELECT statement"]

        return True, []

    except SigmaConversionError as e:
        return False, [f"Conversion error: {str(e)}"]
    except Exception as e:
        return False, [f"Unexpected error: {str(e)}"]


def main():
    """Main test script."""
    repo_root = Path(__file__).parent.parent
    rules_dir = repo_root / "rules" / "sigma"

    if not rules_dir.exists():
        print(f"Error: Rules directory not found: {rules_dir}")
        sys.exit(1)

    # Find all Sigma rules
    rule_files = list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))

    if len(rule_files) == 0:
        print("No Sigma rules found")
        sys.exit(0)

    print(f"Testing {len(rule_files)} Sigma rules for SQL conversion\n")

    # Initialize converter
    if not SIGMA_AVAILABLE:
        print("Error: pySigma not installed")
        print("Run: pip install pysigma pysigma-backend-athena")
        sys.exit(1)

    try:
        converter = SigmaRuleConverter(backend_type="athena")
        print("Sigma converter initialized (Athena backend)\n")
    except ImportError as e:
        print(f"Error: Could not initialize Sigma converter: {e}")
        sys.exit(1)

    # Test all rules
    passed = 0
    failed_rules = []

    for rule_file in sorted(rule_files):
        relative_path = rule_file.relative_to(rules_dir)

        is_valid, errors = test_rule_conversion(rule_file, converter)

        if is_valid:
            passed += 1
            print(f"✓ {relative_path}")
        else:
            failed_rules.append((relative_path, errors))
            print(f"✗ {relative_path}")
            for error in errors:
                print(f"  {error}")

    # Summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Total rules: {len(rule_files)}")
    print(f"Passed: {passed}/{len(rule_files)} ({100*passed//len(rule_files)}%)")
    print(f"Failed: {len(failed_rules)}/{len(rule_files)}")

    if failed_rules:
        print(f"\nFailed rules:")
        for rule_path, errors in failed_rules:
            print(f"  {rule_path}")

        sys.exit(1)
    else:
        print("\n✓ All rules converted successfully")
        sys.exit(0)


if __name__ == "__main__":
    main()
