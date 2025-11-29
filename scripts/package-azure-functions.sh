#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Packaging Azure Function Apps for deployment..."
echo ""

BUILD_DIR="$PROJECT_ROOT/build/azure-functions"
mkdir -p "$BUILD_DIR"

package_azure_function() {
    local FUNCTION_NAME=$1
    local HANDLER_FILE=$2
    local DESCRIPTION=$3

    echo "Packaging $DESCRIPTION ($FUNCTION_NAME)..."

    local PACKAGE_DIR="$BUILD_DIR/$FUNCTION_NAME"
    rm -rf "$PACKAGE_DIR"
    mkdir -p "$PACKAGE_DIR"

    echo "  Installing dependencies..."
    pip install -q -r "$PROJECT_ROOT/requirements.txt" -t "$PACKAGE_DIR/.python_packages/lib/site-packages" --upgrade

    echo "  Copying source code..."
    cp -r "$PROJECT_ROOT/src/shared" "$PACKAGE_DIR/"
    cp -r "$PROJECT_ROOT/src/azure" "$PACKAGE_DIR/" 2>/dev/null || true

    if [ -f "$PROJECT_ROOT/$HANDLER_FILE" ]; then
        cp "$PROJECT_ROOT/$HANDLER_FILE" "$PACKAGE_DIR/"
    fi

    echo "  Creating function.json..."
    cat > "$PACKAGE_DIR/function.json" <<EOF
{
  "scriptFile": "$(basename "$HANDLER_FILE")",
  "bindings": [
    {
      "name": "timer",
      "type": "timerTrigger",
      "direction": "in",
      "schedule": "%COLLECTION_SCHEDULE%"
    }
  ]
}
EOF

    echo "  Creating host.json..."
    cat > "$PACKAGE_DIR/../host.json" <<EOF
{
  "version": "2.0",
  "logging": {
    "applicationInsights": {
      "samplingSettings": {
        "isEnabled": true,
        "maxTelemetryItemsPerSecond": 20
      }
    }
  },
  "extensionBundle": {
    "id": "Microsoft.Azure.Functions.ExtensionBundle",
    "version": "[4.*, 5.0.0)"
  }
}
EOF

    echo "  Creating requirements.txt..."
    cp "$PROJECT_ROOT/requirements.txt" "$PACKAGE_DIR/../requirements.txt"

    echo "  Creating deployment package..."
    cd "$PACKAGE_DIR/.."
    zip -q -r "${FUNCTION_NAME}.zip" . -x "*.pyc" -x "**/__pycache__/*" -x "*.dist-info/*"
    cd "$PROJECT_ROOT"

    echo "  Package created: build/azure-functions/${FUNCTION_NAME}.zip"
    local SIZE=$(du -h "$BUILD_DIR/${FUNCTION_NAME}.zip" | cut -f1)
    echo "  Size: $SIZE"
    echo ""
}

package_collectors() {
    package_azure_function \
        "okta-collector" \
        "src/azure/functions/okta_collector_handler.py" \
        "Okta Collector"

    package_azure_function \
        "google-workspace-collector" \
        "src/azure/functions/google_workspace_collector_handler.py" \
        "Google Workspace Collector"

    package_azure_function \
        "microsoft365-collector" \
        "src/azure/functions/microsoft365_collector_handler.py" \
        "Microsoft 365 Collector"

    package_azure_function \
        "github-collector" \
        "src/azure/functions/github_collector_handler.py" \
        "GitHub Collector"

    package_azure_function \
        "slack-collector" \
        "src/azure/functions/slack_collector_handler.py" \
        "Slack Collector"

    package_azure_function \
        "duo-collector" \
        "src/azure/functions/duo_collector_handler.py" \
        "Duo Security Collector"

    package_azure_function \
        "crowdstrike-collector" \
        "src/azure/functions/crowdstrike_collector_handler.py" \
        "CrowdStrike Collector"

    package_azure_function \
        "salesforce-collector" \
        "src/azure/functions/salesforce_collector_handler.py" \
        "Salesforce Collector"

    package_azure_function \
        "snowflake-collector" \
        "src/azure/functions/snowflake_collector_handler.py" \
        "Snowflake Collector"

    package_azure_function \
        "docker-collector" \
        "src/azure/functions/docker_collector_handler.py" \
        "Docker Collector"

    package_azure_function \
        "kubernetes-collector" \
        "src/azure/functions/kubernetes_collector_handler.py" \
        "Kubernetes Collector"

    package_azure_function \
        "jamf-collector" \
        "src/azure/functions/jamf_collector_handler.py" \
        "Jamf Pro Collector"

    package_azure_function \
        "onepassword-collector" \
        "src/azure/functions/onepassword_collector_handler.py" \
        "1Password Collector"

    package_azure_function \
        "azure-monitor-collector" \
        "src/azure/functions/azure_monitor_collector_handler.py" \
        "Azure Monitor Collector"

    package_azure_function \
        "gcp-logging-collector" \
        "src/azure/functions/gcp_logging_collector_handler.py" \
        "GCP Cloud Logging Collector"
}

validate_packages() {
    echo "Validating packages..."

    for PACKAGE in "$BUILD_DIR"/*.zip; do
        if [ -f "$PACKAGE" ]; then
            local NAME=$(basename "$PACKAGE")
            local SIZE=$(stat -f%z "$PACKAGE" 2>/dev/null || stat -c%s "$PACKAGE" 2>/dev/null)

            if [ "$SIZE" -gt 1572864000 ]; then
                echo "  WARNING: $NAME is larger than 1.5GB Azure Function App limit"
            fi

            if [ "$SIZE" -gt 104857600 ]; then
                echo "  WARNING: $NAME is larger than 100MB direct deployment limit"
                echo "           You will need to use external package deployment"
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

    package_collectors

    validate_packages

    echo "Azure Function App packaging complete!"
    echo "Packages location: $BUILD_DIR"
    echo ""
    echo "To deploy these packages:"
    echo "1. Upload to Azure Storage if larger than 100MB"
    echo "2. Use Azure CLI or Portal to deploy to Function Apps"
    echo "3. Configure app settings in Azure Portal or via Terraform"
    echo ""
}

main
