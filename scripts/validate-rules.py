#!/usr/bin/env python3
"""
Mantissa Log - Detection Rule Validator

Validates detection rule YAML files for:
- Schema compliance
- SQL syntax
- Best practices
- Duplicate detection
"""

import sys
import os
import yaml
import re
from pathlib import Path
from typing import Dict, List, Tuple
import sqlparse

# Rule schema validation
REQUIRED_FIELDS = ['name', 'description', 'enabled', 'severity', 'category', 'query', 'threshold']
SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'info']
CATEGORY_OPTIONS = ['authentication', 'network', 'cloud', 'data', 'compliance', 'threat']

# Known tables in the system
KNOWN_TABLES = ['cloudtrail', 'vpc_flow_logs', 'guardduty_findings']

class RuleValidator:
    def __init__(self, rules_dir: str = 'rules'):
        self.rules_dir = Path(rules_dir)
        self.errors = []
        self.warnings = []
        self.rules = {}

    def validate_all(self) -> bool:
        """Validate all rule files in the rules directory"""
        print(f"Validating rules in {self.rules_dir}")
        print("=" * 80)

        rule_files = list(self.rules_dir.rglob('*.yaml'))
        if not rule_files:
            self.errors.append("No rule files found")
            return False

        for rule_file in rule_files:
            self.validate_file(rule_file)

        self.check_duplicates()
        self.print_summary()

        return len(self.errors) == 0

    def validate_file(self, file_path: Path):
        """Validate a single rule file"""
        print(f"\nValidating: {file_path.relative_to(self.rules_dir.parent)}")

        try:
            with open(file_path, 'r') as f:
                rule = yaml.safe_load(f)
        except yaml.YAMLError as e:
            self.errors.append(f"{file_path}: YAML parse error - {e}")
            return
        except Exception as e:
            self.errors.append(f"{file_path}: Failed to read file - {e}")
            return

        if not rule:
            self.errors.append(f"{file_path}: Empty rule file")
            return

        # Schema validation
        self.validate_schema(file_path, rule)

        # SQL validation
        if 'query' in rule:
            self.validate_sql(file_path, rule['query'])

        # Best practices
        self.check_best_practices(file_path, rule)

        # Store for duplicate checking
        rule_id = file_path.stem
        self.rules[rule_id] = (file_path, rule)

    def validate_schema(self, file_path: Path, rule: Dict):
        """Validate rule schema"""
        # Check required fields
        for field in REQUIRED_FIELDS:
            if field not in rule:
                self.errors.append(f"{file_path}: Missing required field '{field}'")

        # Validate severity
        if 'severity' in rule and rule['severity'] not in SEVERITY_OPTIONS:
            self.errors.append(
                f"{file_path}: Invalid severity '{rule['severity']}'. "
                f"Must be one of: {', '.join(SEVERITY_OPTIONS)}"
            )

        # Validate category
        if 'category' in rule and rule['category'] not in CATEGORY_OPTIONS:
            self.errors.append(
                f"{file_path}: Invalid category '{rule['category']}'. "
                f"Must be one of: {', '.join(CATEGORY_OPTIONS)}"
            )

        # Validate threshold
        if 'threshold' in rule:
            threshold = rule['threshold']
            if not isinstance(threshold, dict):
                self.errors.append(f"{file_path}: threshold must be an object")
            else:
                if 'count' not in threshold:
                    self.errors.append(f"{file_path}: threshold.count is required")
                if 'window' not in threshold:
                    self.errors.append(f"{file_path}: threshold.window is required")

        # Validate metadata
        if 'metadata' in rule:
            metadata = rule['metadata']
            if 'mitre_attack' in metadata and not isinstance(metadata['mitre_attack'], list):
                self.errors.append(f"{file_path}: metadata.mitre_attack must be a list")
            if 'tags' in metadata and not isinstance(metadata['tags'], list):
                self.errors.append(f"{file_path}: metadata.tags must be a list")

    def validate_sql(self, file_path: Path, sql: str):
        """Validate SQL query"""
        if not sql or not sql.strip():
            self.errors.append(f"{file_path}: Empty SQL query")
            return

        # Parse SQL
        try:
            parsed = sqlparse.parse(sql)
            if not parsed:
                self.errors.append(f"{file_path}: Failed to parse SQL")
                return
        except Exception as e:
            self.errors.append(f"{file_path}: SQL syntax error - {e}")
            return

        sql_upper = sql.upper()

        # Check for SELECT statement
        if not sql_upper.strip().startswith('SELECT') and not sql_upper.strip().startswith('WITH'):
            self.errors.append(f"{file_path}: Query must be a SELECT statement")

        # Check for table references
        tables_found = []
        for table in KNOWN_TABLES:
            if re.search(rf'\bFROM\s+{table}\b', sql, re.IGNORECASE):
                tables_found.append(table)
            if re.search(rf'\bJOIN\s+{table}\b', sql, re.IGNORECASE):
                tables_found.append(table)

        if not tables_found:
            self.warnings.append(
                f"{file_path}: No known table references found. "
                f"Expected one of: {', '.join(KNOWN_TABLES)}"
            )

        # Check for time filter
        time_keywords = ['eventtime', 'start_time', 'timestamp', 'CURRENT_TIMESTAMP', 'INTERVAL']
        has_time_filter = any(keyword in sql for keyword in time_keywords)
        if not has_time_filter:
            self.warnings.append(
                f"{file_path}: No time filter detected. "
                "Queries should filter by time to avoid scanning all data"
            )

    def check_best_practices(self, file_path: Path, rule: Dict):
        """Check for best practices"""
        sql = rule.get('query', '')

        # Warn about SELECT *
        if re.search(r'SELECT\s+\*', sql, re.IGNORECASE):
            self.warnings.append(
                f"{file_path}: Using SELECT * - consider selecting specific columns"
            )

        # Warn if no LIMIT
        if 'LIMIT' not in sql.upper() and 'GROUP BY' not in sql.upper():
            self.warnings.append(
                f"{file_path}: No LIMIT clause - query may return too many rows"
            )

        # Check for documentation
        if 'metadata' in rule:
            metadata = rule['metadata']

            if not metadata.get('tags'):
                self.warnings.append(f"{file_path}: No tags defined in metadata")

            if not metadata.get('mitre_attack'):
                self.warnings.append(f"{file_path}: No MITRE ATT&CK mappings defined")

            if not metadata.get('response_actions'):
                self.warnings.append(f"{file_path}: No response actions documented")
        else:
            self.warnings.append(f"{file_path}: No metadata section")

    def check_duplicates(self):
        """Check for duplicate rules"""
        # Check for duplicate names
        names = {}
        for rule_id, (file_path, rule) in self.rules.items():
            name = rule.get('name')
            if name in names:
                self.warnings.append(
                    f"Duplicate rule name '{name}' in {file_path} and {names[name]}"
                )
            else:
                names[name] = file_path

        # Check for very similar SQL (simple similarity check)
        queries = {}
        for rule_id, (file_path, rule) in self.rules.items():
            query = rule.get('query', '').strip()
            # Normalize query for comparison
            normalized = re.sub(r'\s+', ' ', query).lower()

            if normalized in queries:
                self.warnings.append(
                    f"Very similar queries in {file_path} and {queries[normalized]}"
                )
            else:
                queries[normalized] = file_path

    def print_summary(self):
        """Print validation summary"""
        print("\n" + "=" * 80)
        print("VALIDATION SUMMARY")
        print("=" * 80)

        print(f"\nRules validated: {len(self.rules)}")
        print(f"Errors: {len(self.errors)}")
        print(f"Warnings: {len(self.warnings)}")

        if self.errors:
            print("\n" + "=" * 80)
            print("ERRORS:")
            print("=" * 80)
            for error in self.errors:
                print(f"  ERROR: {error}", file=sys.stderr)

        if self.warnings:
            print("\n" + "=" * 80)
            print("WARNINGS:")
            print("=" * 80)
            for warning in self.warnings:
                print(f"  WARNING: {warning}")

        if not self.errors and not self.warnings:
            print("\nAll rules passed validation!")

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Validate Mantissa Log detection rules')
    parser.add_argument(
        '--rules-dir',
        default='rules',
        help='Directory containing rule files (default: rules)'
    )

    args = parser.parse_args()

    validator = RuleValidator(args.rules_dir)
    success = validator.validate_all()

    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
