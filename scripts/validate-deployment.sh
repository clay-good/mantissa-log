#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=========================================="
echo "Mantissa Log Deployment Validation"
echo "=========================================="
echo ""

ERRORS=0
WARNINGS=0

error() {
    echo "ERROR: $1"
    ((ERRORS++))
}

warn() {
    echo "WARNING: $1"
    ((WARNINGS++))
}

ok() {
    echo "OK: $1"
}

section() {
    echo ""
    echo "=== $1 ==="
}

section "Checking Project Structure"

for dir in src infrastructure rules docs tests scripts web; do
    if [ -d "$PROJECT_ROOT/$dir" ]; then
        ok "Directory exists: $dir"
    else
        error "Missing directory: $dir"
    fi
done

section "Validating Source Code"

PARSERS=(cloudtrail vpc_flow guardduty okta google_workspace crowdstrike kubernetes slack microsoft365 github duo docker salesforce snowflake jamf onepassword azure_monitor gcp_logging)

echo "Checking parsers..."
for parser in "${PARSERS[@]}"; do
    if [ -f "$PROJECT_ROOT/src/shared/parsers/${parser}.py" ]; then
        ok "Parser exists: $parser"
    else
        error "Missing parser: $parser"
    fi
done

COLLECTORS=(okta google_workspace microsoft365 github slack duo crowdstrike salesforce snowflake docker kubernetes jamf onepassword azure_monitor gcp_logging)

echo ""
echo "Checking collector handlers..."
for collector in "${COLLECTORS[@]}"; do
    if [ -f "$PROJECT_ROOT/src/aws/lambda/${collector}_collector_handler.py" ]; then
        ok "Collector exists: $collector"
    else
        error "Missing collector: $collector"
    fi
done

section "Validating Infrastructure"

TERRAFORM_MODULES=(storage catalog compute scheduling api auth secrets monitoring state collectors web)

echo "Checking Terraform modules..."
for module in "${TERRAFORM_MODULES[@]}"; do
    if [ -d "$PROJECT_ROOT/infrastructure/aws/terraform/modules/$module" ]; then
        ok "Terraform module exists: $module"

        TF_COUNT=$(find "$PROJECT_ROOT/infrastructure/aws/terraform/modules/$module" -name "*.tf" | wc -l)
        if [ "$TF_COUNT" -gt 0 ]; then
            ok "  Contains $TF_COUNT .tf files"
        else
            error "  No .tf files found in $module"
        fi

        if [ -f "$PROJECT_ROOT/infrastructure/aws/terraform/modules/$module/variables.tf" ]; then
            ok "  variables.tf present"
        else
            warn "  Missing variables.tf in $module"
        fi

        if [ -f "$PROJECT_ROOT/infrastructure/aws/terraform/modules/$module/outputs.tf" ]; then
            ok "  outputs.tf present"
        else
            warn "  Missing outputs.tf in $module"
        fi
    else
        error "Missing Terraform module: $module"
    fi
done

section "Validating Glue Tables"

GLUE_TABLES=(okta google_workspace microsoft365 github slack duo crowdstrike salesforce snowflake docker kubernetes jamf onepassword azure_monitor gcp_logging)

echo "Checking Glue table definitions..."
for table in "${GLUE_TABLES[@]}"; do
    if [ -f "$PROJECT_ROOT/infrastructure/aws/terraform/modules/catalog/${table}_table.tf" ]; then
        ok "Glue table exists: $table"
    else
        error "Missing Glue table: $table"
    fi
done

section "Validating Detection Rules"

SIGMA_COUNT=$(find "$PROJECT_ROOT/rules/sigma" -name "*.yml" -o -name "*.yaml" 2>/dev/null | wc -l)
echo "Total Sigma rules: $SIGMA_COUNT"

if [ "$SIGMA_COUNT" -lt 500 ]; then
    warn "Only $SIGMA_COUNT Sigma rules found (expected 590+)"
elif [ "$SIGMA_COUNT" -lt 100 ]; then
    error "Only $SIGMA_COUNT Sigma rules found (expected 590+)"
else
    ok "Sigma rules count: $SIGMA_COUNT"
fi

RULE_DIRS=(aws/cloudtrail aws/vpc_flow aws/guardduty okta google_workspace microsoft365 github slack duo crowdstrike salesforce snowflake docker kubernetes jamf onepassword azure_monitor gcp_logging)

echo ""
echo "Checking Sigma rule directories..."
for dir in "${RULE_DIRS[@]}"; do
    if [ -d "$PROJECT_ROOT/rules/sigma/$dir" ]; then
        COUNT=$(find "$PROJECT_ROOT/rules/sigma/$dir" -name "*.yml" -o -name "*.yaml" 2>/dev/null | wc -l)
        ok "Rules for $dir: $COUNT files"
    else
        warn "Missing Sigma rule directory: $dir"
    fi
done

section "Validating Dependencies"

if [ -f "$PROJECT_ROOT/requirements.txt" ]; then
    ok "requirements.txt exists"

    REQUIRED_PACKAGES=(boto3 pyyaml anthropic openai pysigma requests google-api-python-client msal snowflake-connector-python docker kubernetes PyGithub duo-client azure-identity google-cloud-logging)

    echo ""
    echo "Checking required Python packages..."
    for package in "${REQUIRED_PACKAGES[@]}"; do
        if grep -q "$package" "$PROJECT_ROOT/requirements.txt"; then
            ok "Package listed: $package"
        else
            error "Missing package in requirements.txt: $package"
        fi
    done
else
    error "requirements.txt not found"
fi

section "Validating Deployment Scripts"

SCRIPTS=(deploy.sh package-lambdas.sh deploy-web.sh smoke-test.sh validate-rules.py)

echo "Checking deployment scripts..."
for script in "${SCRIPTS[@]}"; do
    if [ -f "$PROJECT_ROOT/scripts/$script" ]; then
        ok "Script exists: $script"

        if [[ "$script" == *.sh ]]; then
            if [ -x "$PROJECT_ROOT/scripts/$script" ]; then
                ok "  Script is executable"
            else
                warn "  Script is not executable: $script"
            fi
        fi
    else
        error "Missing script: $script"
    fi
done

section "Validating Documentation"

DOCS=(README.md CHANGELOG.md CONTRIBUTING.md docs/getting-started.md docs/deployment/aws-deployment.md docs/architecture/architecture.md)

echo "Checking documentation files..."
for doc in "${DOCS[@]}"; do
    if [ -f "$PROJECT_ROOT/$doc" ]; then
        ok "Documentation exists: $doc"
    else
        warn "Missing documentation: $doc"
    fi
done

section "Validating Web Interface"

WEB_FILES=(package.json vite.config.js tailwind.config.js postcss.config.js src/App.jsx src/main.jsx)

echo "Checking web interface files..."
for file in "${WEB_FILES[@]}"; do
    if [ -f "$PROJECT_ROOT/web/$file" ]; then
        ok "Web file exists: $file"
    else
        error "Missing web file: $file"
    fi
done

section "Validation Summary"

echo ""
if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo "=========================================="
    echo "SUCCESS: All validation checks passed!"
    echo "=========================================="
    echo ""
    echo "The project is ready for deployment."
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo "=========================================="
    echo "PASSED with warnings"
    echo "=========================================="
    echo ""
    echo "Errors: $ERRORS"
    echo "Warnings: $WARNINGS"
    echo ""
    echo "The project can be deployed but you should review the warnings."
    exit 0
else
    echo "=========================================="
    echo "FAILED: Validation errors found"
    echo "=========================================="
    echo ""
    echo "Errors: $ERRORS"
    echo "Warnings: $WARNINGS"
    echo ""
    echo "Please fix the errors before deploying."
    exit 1
fi
