#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Packaging Lambda functions for deployment..."
echo ""

BUILD_DIR="$PROJECT_ROOT/build/lambda"
mkdir -p "$BUILD_DIR"

package_python_lambda() {
    local FUNCTION_NAME=$1
    local HANDLER_FILE=$2
    local DESCRIPTION=$3

    echo "Packaging $DESCRIPTION ($FUNCTION_NAME)..."

    local PACKAGE_DIR="$BUILD_DIR/$FUNCTION_NAME"
    rm -rf "$PACKAGE_DIR"
    mkdir -p "$PACKAGE_DIR"

    echo "  Installing dependencies..."
    pip install -q -r "$PROJECT_ROOT/requirements.txt" -t "$PACKAGE_DIR" --upgrade

    echo "  Copying source code..."
    cp -r "$PROJECT_ROOT/src/shared" "$PACKAGE_DIR/"
    cp -r "$PROJECT_ROOT/src/aws" "$PACKAGE_DIR/" 2>/dev/null || true

    if [ -f "$PROJECT_ROOT/$HANDLER_FILE" ]; then
        cp "$PROJECT_ROOT/$HANDLER_FILE" "$PACKAGE_DIR/"
    fi

    echo "  Creating deployment package..."
    cd "$PACKAGE_DIR"
    zip -q -r "../${FUNCTION_NAME}.zip" . -x "*.pyc" -x "**/__pycache__/*" -x "*.dist-info/*"
    cd "$PROJECT_ROOT"

    echo "  Package created: build/lambda/${FUNCTION_NAME}.zip"
    local SIZE=$(du -h "$BUILD_DIR/${FUNCTION_NAME}.zip" | cut -f1)
    echo "  Size: $SIZE"
    echo ""
}

package_detection_engine() {
    package_python_lambda \
        "detection-engine" \
        "src/aws/lambda/detection_engine_handler.py" \
        "Detection Engine"
}

package_llm_query() {
    package_python_lambda \
        "llm-query" \
        "src/aws/lambda/llm_query_handler.py" \
        "LLM Query Handler"
}

package_alert_router() {
    package_python_lambda \
        "alert-router" \
        "src/aws/lambda/alert_router_handler.py" \
        "Alert Router"
}

package_collectors() {
    package_python_lambda \
        "okta-collector" \
        "src/aws/lambda/okta_collector_handler.py" \
        "Okta Collector"

    package_python_lambda \
        "google-workspace-collector" \
        "src/aws/lambda/google_workspace_collector_handler.py" \
        "Google Workspace Collector"

    package_python_lambda \
        "microsoft365-collector" \
        "src/aws/lambda/microsoft365_collector_handler.py" \
        "Microsoft 365 Collector"

    package_python_lambda \
        "github-collector" \
        "src/aws/lambda/github_collector_handler.py" \
        "GitHub Collector"

    package_python_lambda \
        "slack-collector" \
        "src/aws/lambda/slack_collector_handler.py" \
        "Slack Collector"

    package_python_lambda \
        "duo-collector" \
        "src/aws/lambda/duo_collector_handler.py" \
        "Duo Security Collector"

    package_python_lambda \
        "crowdstrike-collector" \
        "src/aws/lambda/crowdstrike_collector_handler.py" \
        "CrowdStrike Collector"

    package_python_lambda \
        "salesforce-collector" \
        "src/aws/lambda/salesforce_collector_handler.py" \
        "Salesforce Collector"

    package_python_lambda \
        "snowflake-collector" \
        "src/aws/lambda/snowflake_collector_handler.py" \
        "Snowflake Collector"

    package_python_lambda \
        "docker-collector" \
        "src/aws/lambda/docker_collector_handler.py" \
        "Docker Collector"

    package_python_lambda \
        "kubernetes-collector" \
        "src/aws/lambda/kubernetes_collector_handler.py" \
        "Kubernetes Collector"

    package_python_lambda \
        "jamf-collector" \
        "src/aws/lambda/jamf_collector_handler.py" \
        "Jamf Pro Collector"

    package_python_lambda \
        "onepassword-collector" \
        "src/aws/lambda/onepassword_collector_handler.py" \
        "1Password Collector"

    package_python_lambda \
        "azure-monitor-collector" \
        "src/aws/lambda/azure_monitor_collector_handler.py" \
        "Azure Monitor Collector"

    package_python_lambda \
        "gcp-logging-collector" \
        "src/aws/lambda/gcp_logging_collector_handler.py" \
        "GCP Cloud Logging Collector"
}

create_lambda_layer() {
    echo "Creating shared Lambda layer..."

    local LAYER_DIR="$BUILD_DIR/layer/python"
    rm -rf "$BUILD_DIR/layer"
    mkdir -p "$LAYER_DIR"

    echo "  Installing shared dependencies..."
    pip install -q -r "$PROJECT_ROOT/requirements.txt" -t "$LAYER_DIR" --upgrade

    echo "  Copying shared modules..."
    cp -r "$PROJECT_ROOT/src/shared" "$LAYER_DIR/"

    echo "  Creating layer package..."
    cd "$BUILD_DIR/layer"
    zip -q -r "../mantissa-log-layer.zip" . -x "*.pyc" -x "**/__pycache__/*" -x "*.dist-info/*"
    cd "$PROJECT_ROOT"

    echo "  Layer created: build/lambda/mantissa-log-layer.zip"
    local SIZE=$(du -h "$BUILD_DIR/mantissa-log-layer.zip" | cut -f1)
    echo "  Size: $SIZE"
    echo ""
}

validate_packages() {
    echo "Validating packages..."

    for PACKAGE in "$BUILD_DIR"/*.zip; do
        if [ -f "$PACKAGE" ]; then
            local NAME=$(basename "$PACKAGE")
            local SIZE=$(stat -f%z "$PACKAGE" 2>/dev/null || stat -c%s "$PACKAGE" 2>/dev/null)

            if [ "$SIZE" -gt 262144000 ]; then
                echo "  WARNING: $NAME is larger than 250MB uncompressed Lambda limit"
            fi

            if [ "$SIZE" -gt 52428800 ]; then
                echo "  WARNING: $NAME is larger than 50MB direct upload limit"
                echo "           You will need to upload to S3 first"
            fi
        fi
    done

    echo "  Validation complete"
    echo ""
}

clean_build() {
    echo "Cleaning previous builds..."
    rm -rf "$BUILD_DIR"
    echo "  Build directory cleaned"
    echo ""
}

main() {
    clean_build

    create_lambda_layer

    package_detection_engine
    package_llm_query
    package_alert_router
    package_collectors

    validate_packages

    echo "Lambda packaging complete!"
    echo "Packages location: $BUILD_DIR"
    echo ""
    echo "To deploy these packages:"
    echo "1. Upload to S3 if larger than 50MB"
    echo "2. Update Terraform lambda function configurations"
    echo "3. Run terraform apply"
    echo ""
}

main
