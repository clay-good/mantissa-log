#!/usr/bin/env python3
"""Check for environment variable mismatches between Terraform and Lambda handlers."""

import re
from pathlib import Path
from collections import defaultdict

PROJECT_ROOT = Path(__file__).parent.parent

def extract_terraform_env_vars():
    """Extract environment variables from Terraform Lambda definitions."""
    tf_file = PROJECT_ROOT / "infrastructure/aws/terraform/modules/collectors/main.tf"

    if not tf_file.exists():
        print(f"ERROR: {tf_file} not found")
        return {}

    content = tf_file.read_text()

    # Pattern to find Lambda function environment blocks
    # This is complex because of nested braces
    terraform_envs = {}

    # Split by Lambda function resources
    functions = re.split(r'resource "aws_lambda_function"', content)

    for func_block in functions[1:]:  # Skip first empty split
        # Extract function name
        name_match = re.search(r'"(\w+_collector)"', func_block)
        if not name_match:
            continue

        func_name = name_match.group(1)

        # Extract environment variables
        env_match = re.search(r'environment\s*\{.*?variables\s*=\s*merge\([^{]*\{([^}]+)\}', func_block, re.DOTALL)
        if env_match:
            env_block = env_match.group(1)
            # Find all KEY = "value" pairs
            vars_dict = {}
            for var_match in re.finditer(r'(\w+)\s*=\s*"([^"]*)"', env_block):
                vars_dict[var_match.group(1)] = var_match.group(2)

            terraform_envs[func_name] = vars_dict

    return terraform_envs

def extract_handler_env_vars():
    """Extract environment variables from Lambda handler code."""
    lambda_dir = PROJECT_ROOT / "src/aws/lambda"
    handler_envs = {}

    for handler_file in lambda_dir.glob("*_collector_handler.py"):
        collector_name = handler_file.stem  # e.g., "okta_collector_handler"
        content = handler_file.read_text()

        # Find all os.environ.get() calls
        env_vars = set()
        for match in re.finditer(r'os\.environ\.get\([\'"]([A-Z_]+)[\'"]', content):
            env_vars.add(match.group(1))

        # Also check for os.environ[] access
        for match in re.finditer(r'os\.environ\[[\'"]([A-Z_]+)[\'"]\]', content):
            env_vars.add(match.group(1))

        handler_envs[collector_name] = env_vars

    return handler_envs

def main():
    print("=" * 70)
    print("Environment Variable Mismatch Detection")
    print("=" * 70)

    terraform_envs = extract_terraform_env_vars()
    handler_envs = extract_handler_env_vars()

    print(f"\nFound {len(terraform_envs)} Terraform Lambda configs")
    print(f"Found {len(handler_envs)} Lambda handler files")

    # Common environment variables provided by common_environment
    common_vars = {'S3_BUCKET', 'CHECKPOINT_TABLE', 'LOG_LEVEL', 'ENVIRONMENT'}

    issues_found = []

    for handler_name, handler_vars in handler_envs.items():
        # Match handler to Terraform config
        # handler_name is like "okta_collector_handler"
        # terraform key is like "okta_collector"
        tf_key = handler_name.replace("_handler", "")

        if tf_key not in terraform_envs:
            print(f"\nWARNING: No Terraform config found for {handler_name}")
            continue

        tf_vars = set(terraform_envs[tf_key].keys())

        # Check what handler expects but Terraform doesn't provide
        missing_in_tf = handler_vars - tf_vars - common_vars
        # Check what Terraform provides but handler doesn't use
        unused_in_handler = tf_vars - handler_vars - common_vars

        if missing_in_tf or unused_in_handler:
            print(f"\n{handler_name}:")
            if missing_in_tf:
                print(f"  ERROR: Handler expects but Terraform missing: {missing_in_tf}")
                issues_found.append((handler_name, "missing", missing_in_tf))
            if unused_in_handler:
                print(f"  WARNING: Terraform provides but handler doesn't use: {unused_in_handler}")
        else:
            print(f"\n{handler_name}: OK")

    print("\n" + "=" * 70)
    if issues_found:
        print(f"Found {len(issues_found)} environment variable issues")
        return 1
    else:
        print("All environment variables match!")
        return 0

if __name__ == "__main__":
    exit(main())
