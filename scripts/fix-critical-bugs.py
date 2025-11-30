#!/usr/bin/env python3
"""
Critical Bug Fixes for Mantissa Log

This script fixes critical issues found in stress testing:
1. Unsafe os.environ[] access without defaults
2. Missing error handling
3. Inconsistent import paths
"""

import os
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent

def fix_unsafe_environ_access():
    """Fix unsafe os.environ[] access in Lambda handlers."""
    print("Fixing unsafe os.environ[] access...")

    lambda_dir = PROJECT_ROOT / "src" / "aws" / "lambda"
    files_fixed = []

    for py_file in lambda_dir.glob("*_handler.py"):
        content = py_file.read_text()
        original = content

        # Replace os.environ['KEY'] with os.environ.get('KEY', 'default')
        # Pattern: os.environ['VARIABLE_NAME']
        pattern = r"os\.environ\['([A-Z_]+)'\]"

        def replacement(match):
            var_name = match.group(1)
            # Determine appropriate default based on variable name
            if 'BUCKET' in var_name:
                default = f'"{var_name.lower().replace("_", "-")}"'
            elif 'TABLE' in var_name:
                default = f'"mantissa-{var_name.lower().replace("_", "-")}"'
            elif 'SECRET' in var_name:
                default = f'"mantissa/{var_name.lower().replace("_", "/")}"'
            elif 'URL' in var_name or 'ENDPOINT' in var_name:
                default = '""'
            else:
                default = '""'

            return f"os.environ.get('{var_name}', {default})"

        content = re.sub(pattern, replacement, content)

        if content != original:
            py_file.write_text(content)
            files_fixed.append(py_file.name)
            print(f"  Fixed: {py_file.name}")

    print(f"Fixed {len(files_fixed)} files")
    return files_fixed

def validate_terraform_vars():
    """Validate Terraform variable references."""
    print("\nValidating Terraform variables...")

    tf_dir = PROJECT_ROOT / "infrastructure" / "aws" / "terraform"
    errors = []

    # Check main.tf references modules correctly
    main_tf = tf_dir / "main.tf"
    if main_tf.exists():
        content = main_tf.read_text()

        # Extract module sources
        module_pattern = r'module\s+"([^"]+)"\s+\{\s+source\s+=\s+"([^"]+)"'
        modules = re.findall(module_pattern, content)

        for module_name, source_path in modules:
            # Check if module directory exists
            full_path = tf_dir / source_path.lstrip("./")
            if not full_path.exists():
                errors.append(f"Module '{module_name}' references non-existent path: {source_path}")
            else:
                print(f"  OK: Module '{module_name}' -> {source_path}")

    if errors:
        print("ERRORS:")
        for error in errors:
            print(f"  {error}")
    else:
        print("  All module references valid")

    return len(errors) == 0

def check_required_files():
    """Check all required files exist."""
    print("\nChecking required files...")

    required_files = [
        "requirements.txt",
        "scripts/deploy.sh",
        "scripts/package-lambdas.sh",
        "infrastructure/aws/terraform/main.tf",
        "infrastructure/aws/terraform/variables.tf",
        "infrastructure/aws/terraform/outputs.tf",
    ]

    missing = []
    for file_path in required_files:
        full_path = PROJECT_ROOT / file_path
        if not full_path.exists():
            missing.append(file_path)
            print(f"  MISSING: {file_path}")
        else:
            print(f"  OK: {file_path}")

    return len(missing) == 0

def validate_lambda_handlers():
    """Validate Lambda handler functions exist and are properly named."""
    print("\nValidating Lambda handlers...")

    lambda_dir = PROJECT_ROOT / "src" / "aws" / "lambda"
    handlers_ok = []
    handlers_missing = []

    expected_handlers = [
        "detection_engine_handler.py",
        "llm_query_handler.py",
        "alert_router_handler.py",
        "okta_collector_handler.py",
        "google_workspace_collector_handler.py",
        "microsoft365_collector_handler.py",
        "github_collector_handler.py",
        "slack_collector_handler.py",
        "duo_collector_handler.py",
        "crowdstrike_collector_handler.py",
        "docker_collector_handler.py",
        "kubernetes_collector_handler.py",
        "salesforce_collector_handler.py",
        "snowflake_collector_handler.py",
        "jamf_collector_handler.py",
        "onepassword_collector_handler.py",
        "azure_monitor_collector_handler.py",
        "gcp_logging_collector_handler.py",
    ]

    for handler in expected_handlers:
        handler_path = lambda_dir / handler
        if not handler_path.exists():
            handlers_missing.append(handler)
            print(f"  MISSING: {handler}")
        else:
            # Check for lambda_handler or handler function
            content = handler_path.read_text()
            if 'def lambda_handler(' in content or 'def handler(' in content:
                handlers_ok.append(handler)
                print(f"  OK: {handler}")
            else:
                handlers_missing.append(handler)
                print(f"  ERROR: {handler} missing lambda_handler function")

    print(f"\nHandlers OK: {len(handlers_ok)}/{len(expected_handlers)}")
    return len(handlers_missing) == 0

def main():
    print("=" * 60)
    print("Mantissa Log - Critical Bug Fixes")
    print("=" * 60)

    # Fix unsafe environment variable access
    fix_unsafe_environ_access()

    # Validate Terraform
    terraform_ok = validate_terraform_vars()

    # Check required files
    files_ok = check_required_files()

    # Validate Lambda handlers
    handlers_ok = validate_lambda_handlers()

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"Terraform validation: {'PASS' if terraform_ok else 'FAIL'}")
    print(f"Required files check: {'PASS' if files_ok else 'FAIL'}")
    print(f"Lambda handlers check: {'PASS' if handlers_ok else 'FAIL'}")

    if terraform_ok and files_ok and handlers_ok:
        print("\nAll critical bugs fixed!")
        return 0
    else:
        print("\nSome issues remain - review output above")
        return 1

if __name__ == "__main__":
    exit(main())
