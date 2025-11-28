#!/usr/bin/env python3
"""Validate all Sigma rules against the Sigma schema and test SQL conversion."""

import sys
import json
from pathlib import Path
from typing import List, Tuple

import yaml
from jsonschema import validate, ValidationError

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.shared.detection.sigma_converter import (
    SigmaRuleConverter,
    SIGMA_AVAILABLE,
    SigmaConversionError
)


def load_schema(schema_path: Path) -> dict:
    """Load JSON schema."""
    with open(schema_path) as f:
        return json.load(f)


def validate_rule_schema(rule_path: Path, schema: dict) -> Tuple[bool, List[str]]:
    """Validate a rule against the JSON schema."""
    errors = []

    try:
        with open(rule_path) as f:
            rule_dict = yaml.safe_load(f)

        validate(instance=rule_dict, schema=schema)
        return True, []

    except ValidationError as e:
        errors.append(f"Schema validation error: {e.message}")
        return False, errors
    except Exception as e:
        errors.append(f"Error loading rule: {str(e)}")
        return False, errors


def validate_rule_conversion(rule_path: Path, converter: SigmaRuleConverter) -> Tuple[bool, List[str]]:
    """Validate that a rule can be converted to SQL."""
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
    """Main validation script."""
    # Find rules directory
    repo_root = Path(__file__).parent.parent
    rules_dir = repo_root / "rules" / "sigma"
    schema_path = repo_root / "rules" / "sigma-schema.json"

    if not rules_dir.exists():
        print(f"Error: Rules directory not found: {rules_dir}")
        sys.exit(1)

    if not schema_path.exists():
        print(f"Error: Schema file not found: {schema_path}")
        sys.exit(1)

    # Load schema
    print(f"Loading schema from {schema_path}")
    schema = load_schema(schema_path)

    # Find all Sigma rules
    rule_files = list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))

    if len(rule_files) == 0:
        print("No Sigma rules found")
        sys.exit(0)

    print(f"Found {len(rule_files)} Sigma rules\n")

    # Initialize converter if available
    converter = None
    if SIGMA_AVAILABLE:
        try:
            converter = SigmaRuleConverter(backend_type="athena")
            print("Sigma converter initialized (Athena backend)\n")
        except ImportError as e:
            print(f"Warning: Could not initialize Sigma converter: {e}")
            print("Skipping SQL conversion validation\n")
    else:
        print("Warning: pySigma not installed")
        print("Skipping SQL conversion validation\n")

    # Validate all rules
    schema_valid_count = 0
    conversion_valid_count = 0
    failed_rules = []

    for rule_file in sorted(rule_files):
        relative_path = rule_file.relative_to(rules_dir)

        # Schema validation
        is_valid_schema, schema_errors = validate_rule_schema(rule_file, schema)

        # Conversion validation
        is_valid_conversion = False
        conversion_errors = []

        if converter:
            is_valid_conversion, conversion_errors = validate_rule_conversion(
                rule_file, converter
            )

        # Track results
        if is_valid_schema:
            schema_valid_count += 1

        if is_valid_conversion:
            conversion_valid_count += 1

        # Report issues
        all_errors = []
        if not is_valid_schema:
            all_errors.extend([f"Schema: {e}" for e in schema_errors])
        if converter and not is_valid_conversion:
            all_errors.extend([f"Conversion: {e}" for e in conversion_errors])

        if all_errors:
            failed_rules.append((relative_path, all_errors))
            print(f"❌ {relative_path}")
            for error in all_errors:
                print(f"   {error}")
        else:
            status = "✓" if is_valid_schema else "?"
            print(f"{status}  {relative_path}")

    # Summary
    print(f"\n{'='*60}")
    print("VALIDATION SUMMARY")
    print(f"{'='*60}")
    print(f"Total rules: {len(rule_files)}")
    print(f"Schema validation: {schema_valid_count}/{len(rule_files)} passed")

    if converter:
        print(f"SQL conversion: {conversion_valid_count}/{len(rule_files)} passed")

    if failed_rules:
        print(f"\n{len(failed_rules)} rules failed validation:")
        for rule_path, errors in failed_rules:
            print(f"\n  {rule_path}:")
            for error in errors:
                print(f"    - {error}")

        sys.exit(1)
    else:
        print("\n✓ All rules passed validation")
        sys.exit(0)


if __name__ == "__main__":
    main()
