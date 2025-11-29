#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Packaging Azure Function Apps for deployment..."
echo ""

BUILD_DIR="$PROJECT_ROOT/build/azure-functions"
mkdir -p "$BUILD_DIR"

package_azure_function_app() {
    echo "Packaging Azure Function App with all collectors..."

    local APP_DIR="$BUILD_DIR/collectors-app"
    rm -rf "$APP_DIR"
    mkdir -p "$APP_DIR"

    echo "  Installing dependencies..."
    pip install -q -r "$PROJECT_ROOT/requirements.txt" -t "$APP_DIR/.python_packages/lib/site-packages" --upgrade
    pip install -q -r "$PROJECT_ROOT/src/azure/functions/requirements.txt" -t "$APP_DIR/.python_packages/lib/site-packages" --upgrade

    echo "  Copying source code..."
    cp -r "$PROJECT_ROOT/src/shared" "$APP_DIR/"
    cp "$PROJECT_ROOT/src/azure/functions/__init__.py" "$APP_DIR/"
    cp "$PROJECT_ROOT/src/azure/functions/host.json" "$APP_DIR/"
    cp "$PROJECT_ROOT/src/azure/functions/requirements.txt" "$APP_DIR/"

    echo "  Creating deployment package..."
    cd "$APP_DIR"
    zip -q -r "../collectors-app.zip" . -x "*.pyc" -x "**/__pycache__/*" -x "*.dist-info/*"
    cd "$PROJECT_ROOT"

    echo "  Package created: build/azure-functions/collectors-app.zip"
    local SIZE=$(du -h "$BUILD_DIR/collectors-app.zip" | cut -f1)
    echo "  Size: $SIZE"
    echo ""
}

package_collectors() {
    package_azure_function_app
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
