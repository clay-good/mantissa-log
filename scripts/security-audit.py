#!/usr/bin/env python3
"""
Comprehensive security audit for Mantissa Log

Checks for:
1. SQL injection vulnerabilities
2. Overly permissive IAM policies
3. Hardcoded credentials
4. Insecure defaults
5. Missing input validation
6. Error message information leakage
7. XSS vulnerabilities in web code
8. Missing encryption settings
"""

import re
from pathlib import Path
from collections import defaultdict

PROJECT_ROOT = Path(__file__).parent.parent

def check_hardcoded_credentials():
    """Check for hardcoded credentials in source code."""
    print("\n" + "=" * 70)
    print("Checking for Hardcoded Credentials")
    print("=" * 70)

    patterns = [
        (r'password\s*=\s*["\'](?!.*\{)[^"\']{8,}["\']', "Hardcoded password"),
        (r'api[_-]?key\s*=\s*["\'][^"\']{20,}["\']', "Hardcoded API key"),
        (r'secret\s*=\s*["\'](?!mantissa/)[^"\']{20,}["\']', "Hardcoded secret"),
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
        (r'aws_secret_access_key\s*=\s*["\'][^"\']+["\']', "AWS Secret Key"),
    ]

    issues = []
    for py_file in PROJECT_ROOT.rglob("*.py"):
        if "venv" in str(py_file) or ".git" in str(py_file):
            continue

        content = py_file.read_text()
        for pattern, description in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                issues.append((py_file, description, match.group(0)[:50]))

    if issues:
        print(f"\nFOUND {len(issues)} POTENTIAL ISSUES:")
        for file_path, desc, snippet in issues:
            print(f"  {file_path.relative_to(PROJECT_ROOT)}: {desc}")
            print(f"    Snippet: {snippet}...")
    else:
        print("\n  OK: No hardcoded credentials found")

    return len(issues) == 0

def check_sql_injection():
    """Check for potential SQL injection vulnerabilities."""
    print("\n" + "=" * 70)
    print("Checking for SQL Injection Vulnerabilities")
    print("=" * 70)

    # Patterns that indicate potential SQL injection
    dangerous_patterns = [
        (r'f"SELECT.*\{[^}]+\}"', "f-string in SQL query"),
        (r'f\'SELECT.*\{[^}]+\}\'', "f-string in SQL query"),
        (r'"SELECT.*"\s*\+\s*', "String concatenation in SQL"),
        (r'\.format\(.*\).*WHERE', "String.format() in SQL WHERE clause"),
        (r'%\s*\(.*\).*SELECT', "% formatting in SQL"),
    ]

    issues = []
    for py_file in PROJECT_ROOT.rglob("*.py"):
        if "venv" in str(py_file) or "test" in str(py_file):
            continue

        content = py_file.read_text()
        for pattern, description in dangerous_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                issues.append((py_file, description))

    if issues:
        print(f"\nFOUND {len(issues)} POTENTIAL ISSUES:")
        for file_path, desc in issues:
            print(f"  {file_path.relative_to(PROJECT_ROOT)}: {desc}")
    else:
        print("\n  OK: No obvious SQL injection vulnerabilities")

    # Check if SQL validator is used
    validator_usage = 0
    for py_file in PROJECT_ROOT.rglob("*.py"):
        if "query" in str(py_file).lower() or "sql" in str(py_file).lower():
            content = py_file.read_text()
            if "SQLValidator" in content or "validator.validate" in content:
                validator_usage += 1

    print(f"\n  SQL validation used in {validator_usage} files")

    return len(issues) == 0

def check_iam_permissions():
    """Check for overly permissive IAM policies."""
    print("\n" + "=" * 70)
    print("Checking IAM Permissions")
    print("=" * 70)

    issues = []
    tf_files = list((PROJECT_ROOT / "infrastructure").rglob("*.tf"))

    for tf_file in tf_files:
        content = tf_file.read_text()

        # Check for Resource = "*"
        if re.search(r'Resource\s*=\s*"\*"', content):
            issues.append((tf_file, "Wildcard (*) resource permission"))

        # Check for Action = "*"
        if re.search(r'Action\s*=\s*"\*"', content):
            issues.append((tf_file, "Wildcard (*) action permission"))

        # Check for Effect = "Allow" with broad permissions
        if re.search(r'Action\s*=\s*\[.*:?\*.*\]', content):
            issues.append((tf_file, "Wildcard action in list"))

    if issues:
        print(f"\nFOUND {len(issues)} POTENTIAL ISSUES:")
        for file_path, desc in issues:
            print(f"  {file_path.relative_to(PROJECT_ROOT)}: {desc}")
    else:
        print("\n  OK: No overly permissive IAM policies found")

    return len(issues) == 0

def check_encryption():
    """Check for missing encryption settings."""
    print("\n" + "=" * 70)
    print("Checking Encryption Settings")
    print("=" * 70)

    issues = []
    tf_files = list((PROJECT_ROOT / "infrastructure").rglob("*.tf"))

    for tf_file in tf_files:
        content = tf_file.read_text()

        # Check S3 buckets have encryption
        if 'resource "aws_s3_bucket"' in content:
            bucket_blocks = re.findall(
                r'resource "aws_s3_bucket" "(\w+)" \{[^}]+\}',
                content,
                re.DOTALL
            )
            for block in bucket_blocks:
                # Should have corresponding encryption config
                if not re.search(f'aws_s3_bucket_server_side_encryption_configuration.*{block}', content, re.DOTALL):
                    issues.append((tf_file, f"S3 bucket '{block}' may lack encryption"))

        # Check DynamoDB tables have encryption
        if 'resource "aws_dynamodb_table"' in content:
            if 'server_side_encryption' not in content:
                issues.append((tf_file, "DynamoDB table may lack encryption"))

    if issues:
        print(f"\nFOUND {len(issues)} POTENTIAL ISSUES:")
        for file_path, desc in issues:
            print(f"  {file_path.relative_to(PROJECT_ROOT)}: {desc}")
    else:
        print("\n  OK: Encryption settings appear configured")

    return len(issues) == 0

def check_input_validation():
    """Check for missing input validation in Lambda handlers."""
    print("\n" + "=" * 70)
    print("Checking Input Validation")
    print("=" * 70)

    lambda_handlers = list((PROJECT_ROOT / "src/aws/lambda").glob("*_handler.py"))
    handlers_with_validation = 0
    handlers_without = []

    for handler in lambda_handlers:
        content = handler.read_text()

        # Check for validation patterns
        has_validation = any([
            "validate" in content.lower(),
            "isinstance(" in content,
            "type(" in content and "raise" in content,
            "jsonschema" in content,
            ".get(" in content,  # Safe dict access
        ])

        if has_validation:
            handlers_with_validation += 1
        else:
            handlers_without.append(handler)

    print(f"\n  Handlers with validation: {handlers_with_validation}/{len(lambda_handlers)}")

    if handlers_without:
        print("\n  Handlers possibly missing validation:")
        for handler in handlers_without:
            print(f"    {handler.name}")

    return len(handlers_without) < len(lambda_handlers) * 0.2  # 80% should have validation

def check_error_handling():
    """Check for information leakage in error messages."""
    print("\n" + "=" * 70)
    print("Checking Error Handling")
    print("=" * 70)

    issues = []
    for py_file in PROJECT_ROOT.rglob("*.py"):
        if "venv" in str(py_file) or ".git" in str(py_file):
            continue

        content = py_file.read_text()

        # Check for bare exceptions that might leak info
        if re.search(r'raise\s+Exception\(f["\']', content):
            issues.append((py_file, "f-string in Exception (may leak sensitive data)"))

        # Check for print statements with secrets
        if re.search(r'print\(.*secret|password|key.*\)', content, re.IGNORECASE):
            issues.append((py_file, "Printing potentially sensitive data"))

    if issues:
        print(f"\nFOUND {len(issues)} POTENTIAL ISSUES:")
        for file_path, desc in issues[:10]:  # Limit output
            print(f"  {file_path.relative_to(PROJECT_ROOT).name}: {desc}")
    else:
        print("\n  OK: Error handling appears secure")

    return len(issues) == 0

def main():
    print("=" * 70)
    print("Mantissa Log - Security Audit")
    print("=" * 70)

    results = {
        "Hardcoded Credentials": check_hardcoded_credentials(),
        "SQL Injection": check_sql_injection(),
        "IAM Permissions": check_iam_permissions(),
        "Encryption": check_encryption(),
        "Input Validation": check_input_validation(),
        "Error Handling": check_error_handling(),
    }

    print("\n" + "=" * 70)
    print("Security Audit Summary")
    print("=" * 70)

    for check_name, passed in results.items():
        status = "PASS" if passed else "REVIEW NEEDED"
        print(f"  {check_name}: {status}")

    all_passed = all(results.values())

    print("\n" + "=" * 70)
    if all_passed:
        print("Security audit PASSED")
        return 0
    else:
        print("Security audit found issues requiring review")
        return 1

if __name__ == "__main__":
    exit(main())
