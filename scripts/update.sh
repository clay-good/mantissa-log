#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=========================================="
echo "Mantissa Log Update Script"
echo "=========================================="
echo ""

check_git_status() {
    echo "Checking Git status..."

    cd "$PROJECT_ROOT"

    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        echo "  Warning: Not a Git repository"
        return
    fi

    if [ -n "$(git status --porcelain)" ]; then
        echo "  Warning: You have uncommitted changes"
        read -p "  Continue with update? (y/n): " CONTINUE
        if [ "$CONTINUE" != "y" ]; then
            exit 0
        fi
    fi

    echo "  Git status OK"
    echo ""
}

pull_latest_code() {
    echo "Pulling latest code..."

    cd "$PROJECT_ROOT"

    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        echo "  Skipping Git pull (not a repository)"
        echo ""
        return
    fi

    CURRENT_BRANCH=$(git branch --show-current)
    echo "  Current branch: $CURRENT_BRANCH"

    git fetch origin
    git pull origin "$CURRENT_BRANCH"

    echo "  Code updated"
    echo ""
}

check_breaking_changes() {
    echo "Checking for breaking changes..."

    if [ -f "$PROJECT_ROOT/CHANGELOG.md" ]; then
        echo "  Recent changelog entries:"
        head -20 "$PROJECT_ROOT/CHANGELOG.md"
        echo ""

        read -p "Review changelog above. Continue with update? (y/n): " CONTINUE
        if [ "$CONTINUE" != "y" ]; then
            exit 0
        fi
    fi

    echo ""
}

package_lambda_functions() {
    echo "Packaging updated Lambda functions..."

    cd "$PROJECT_ROOT"
    bash "$SCRIPT_DIR/package-lambdas.sh"

    echo ""
}

update_infrastructure() {
    echo "Updating infrastructure..."

    cd "$PROJECT_ROOT/infrastructure/aws/terraform"

    if [ ! -d ".terraform" ]; then
        echo "  Terraform not initialized. Run deploy.sh first."
        exit 1
    fi

    echo "  Running terraform init to update providers..."
    terraform init -upgrade

    echo ""
    echo "  Creating Terraform plan..."
    terraform plan -out=tfplan

    echo ""
    read -p "Apply these changes? (y/n): " APPLY_CONFIRM
    if [ "$APPLY_CONFIRM" != "y" ]; then
        echo "Update cancelled"
        exit 0
    fi

    echo "  Applying Terraform changes..."
    terraform apply tfplan

    echo ""
    echo "  Extracting outputs..."
    terraform output -json > "$PROJECT_ROOT/terraform-outputs.json"

    echo "  Infrastructure updated"
    echo ""
}

update_lambda_code() {
    echo "Updating Lambda function code..."

    DETECTION_ENGINE=$(grep -o '"detection_engine_function_name[^:]*:[^"]*"[^"]*"' "$PROJECT_ROOT/terraform-outputs.json" | cut -d'"' -f4 || echo "")
    LLM_QUERY=$(grep -o '"llm_query_function_name[^:]*:[^"]*"[^"]*"' "$PROJECT_ROOT/terraform-outputs.json" | cut -d'"' -f4 || echo "")
    ALERT_ROUTER=$(grep -o '"alert_router_function_name[^:]*:[^"]*"[^"]*"' "$PROJECT_ROOT/terraform-outputs.json" | cut -d'"' -f4 || echo "")

    if [ -n "$DETECTION_ENGINE" ] && [ -f "$PROJECT_ROOT/build/lambda/detection-engine.zip" ]; then
        echo "  Updating detection engine..."
        aws lambda update-function-code \
            --function-name "$DETECTION_ENGINE" \
            --zip-file "fileb://$PROJECT_ROOT/build/lambda/detection-engine.zip" \
            > /dev/null
        echo "    Detection engine updated"
    fi

    if [ -n "$LLM_QUERY" ] && [ -f "$PROJECT_ROOT/build/lambda/llm-query.zip" ]; then
        echo "  Updating LLM query handler..."
        aws lambda update-function-code \
            --function-name "$LLM_QUERY" \
            --zip-file "fileb://$PROJECT_ROOT/build/lambda/llm-query.zip" \
            > /dev/null
        echo "    LLM query handler updated"
    fi

    if [ -n "$ALERT_ROUTER" ] && [ -f "$PROJECT_ROOT/build/lambda/alert-router.zip" ]; then
        echo "  Updating alert router..."
        aws lambda update-function-code \
            --function-name "$ALERT_ROUTER" \
            --zip-file "fileb://$PROJECT_ROOT/build/lambda/alert-router.zip" \
            > /dev/null
        echo "    Alert router updated"
    fi

    echo ""
}

update_detection_rules() {
    echo "Updating detection rules..."

    RULES_BUCKET=$(grep -o '"rules_bucket[^:]*:[^"]*"[^"]*"' "$PROJECT_ROOT/terraform-outputs.json" | cut -d'"' -f4 || echo "")

    if [ -z "$RULES_BUCKET" ]; then
        echo "  Warning: Rules bucket not found in outputs"
        return
    fi

    read -p "Upload detection rules? (y/n) [y]: " UPLOAD_RULES
    UPLOAD_RULES=${UPLOAD_RULES:-y}

    if [ "$UPLOAD_RULES" == "y" ]; then
        aws s3 sync "$PROJECT_ROOT/rules/" "s3://$RULES_BUCKET/rules/" \
            --exclude "*.md" \
            --exclude "README*" \
            --delete

        echo "  Detection rules updated"
    else
        echo "  Skipping rule upload"
    fi

    echo ""
}

run_smoke_tests() {
    echo "Running smoke tests..."

    bash "$SCRIPT_DIR/smoke-test.sh" "$PROJECT_ROOT/terraform-outputs.json"

    echo ""
}

print_update_summary() {
    echo "=========================================="
    echo "Update Complete"
    echo "=========================================="
    echo ""
    echo "Mantissa Log has been updated to the latest version."
    echo ""
    echo "Changes applied:"
    echo "  - Code pulled from repository"
    echo "  - Lambda functions updated"
    echo "  - Infrastructure updated (if changes detected)"
    echo "  - Detection rules updated"
    echo ""
    echo "Please review the smoke test results above."
    echo ""
}

main() {
    check_git_status
    pull_latest_code
    check_breaking_changes
    package_lambda_functions
    update_infrastructure
    update_lambda_code
    update_detection_rules
    run_smoke_tests
    print_update_summary
}

main
