#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WEB_DIR="$PROJECT_ROOT/web"

echo "=========================================="
echo "Mantissa Log Web Deployment Script"
echo "=========================================="
echo ""

check_prerequisites() {
    echo "Checking prerequisites..."

    if ! command -v node &> /dev/null; then
        echo "ERROR: Node.js not found. Please install Node.js >= 18"
        exit 1
    fi

    NODE_VERSION=$(node --version)
    echo "  Node.js version: $NODE_VERSION"

    if ! command -v npm &> /dev/null; then
        echo "ERROR: npm not found. Please install npm"
        exit 1
    fi

    NPM_VERSION=$(npm --version)
    echo "  npm version: $NPM_VERSION"

    if ! command -v aws &> /dev/null; then
        echo "ERROR: AWS CLI not found. Please install AWS CLI v2"
        exit 1
    fi

    AWS_VERSION=$(aws --version 2>&1 | cut -d' ' -f1)
    echo "  $AWS_VERSION"

    if ! aws sts get-caller-identity &> /dev/null; then
        echo "ERROR: AWS credentials not configured or invalid"
        exit 1
    fi

    AWS_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
    echo "  AWS Account: $AWS_ACCOUNT"

    echo "  Prerequisites check passed!"
    echo ""
}

load_terraform_outputs() {
    echo "Loading Terraform outputs..."

    if [ ! -f "$PROJECT_ROOT/terraform-outputs.json" ]; then
        echo "ERROR: terraform-outputs.json not found"
        echo "Please run ./scripts/deploy.sh first to deploy infrastructure"
        exit 1
    fi

    WEB_BUCKET_NAME=$(cat "$PROJECT_ROOT/terraform-outputs.json" | python3 -c "import sys, json; print(json.load(sys.stdin).get('web_bucket_name', {}).get('value', ''))")
    CLOUDFRONT_DISTRIBUTION_ID=$(cat "$PROJECT_ROOT/terraform-outputs.json" | python3 -c "import sys, json; print(json.load(sys.stdin).get('cloudfront_distribution_id', {}).get('value', ''))")
    API_ENDPOINT=$(cat "$PROJECT_ROOT/terraform-outputs.json" | python3 -c "import sys, json; print(json.load(sys.stdin).get('api_endpoint', {}).get('value', ''))")
    USER_POOL_ID=$(cat "$PROJECT_ROOT/terraform-outputs.json" | python3 -c "import sys, json; print(json.load(sys.stdin).get('cognito_user_pool_id', {}).get('value', ''))")
    USER_POOL_CLIENT_ID=$(cat "$PROJECT_ROOT/terraform-outputs.json" | python3 -c "import sys, json; print(json.load(sys.stdin).get('cognito_user_pool_client_id', {}).get('value', ''))")
    AWS_REGION=$(cat "$PROJECT_ROOT/terraform-outputs.json" | python3 -c "import sys, json; outputs = json.load(sys.stdin); print(list(outputs.values())[0].get('value', '').split(':')[3] if outputs else 'us-east-1')" 2>/dev/null || echo "us-east-1")

    if [ -z "$WEB_BUCKET_NAME" ]; then
        echo "ERROR: Web bucket name not found in terraform-outputs.json"
        echo "Please ensure the web module is deployed"
        exit 1
    fi

    if [ -z "$CLOUDFRONT_DISTRIBUTION_ID" ]; then
        echo "ERROR: CloudFront distribution ID not found in terraform-outputs.json"
        exit 1
    fi

    if [ -z "$API_ENDPOINT" ]; then
        echo "ERROR: API endpoint not found in terraform-outputs.json"
        exit 1
    fi

    echo "  Web Bucket: $WEB_BUCKET_NAME"
    echo "  CloudFront Distribution: $CLOUDFRONT_DISTRIBUTION_ID"
    echo "  API Endpoint: $API_ENDPOINT"
    echo "  User Pool ID: $USER_POOL_ID"
    echo "  User Pool Client ID: $USER_POOL_CLIENT_ID"
    echo "  AWS Region: $AWS_REGION"
    echo ""
}

create_env_file() {
    echo "Creating environment configuration..."

    cat > "$WEB_DIR/.env.production" <<EOF
VITE_API_ENDPOINT=$API_ENDPOINT
VITE_AWS_REGION=$AWS_REGION
VITE_USER_POOL_ID=$USER_POOL_ID
VITE_USER_POOL_CLIENT_ID=$USER_POOL_CLIENT_ID
EOF

    echo "  Created .env.production with API configuration"
    echo ""
}

install_dependencies() {
    echo "Installing dependencies..."

    cd "$WEB_DIR"

    if [ ! -d "node_modules" ]; then
        echo "  Running npm install..."
        npm install
    else
        echo "  Dependencies already installed"
    fi

    echo ""
}

build_web_app() {
    echo "Building web application..."

    cd "$WEB_DIR"

    echo "  Running Vite build..."
    npm run build

    if [ ! -d "dist" ]; then
        echo "ERROR: Build failed - dist directory not created"
        exit 1
    fi

    echo "  Build completed successfully"
    echo ""
}

deploy_to_s3() {
    echo "Deploying to S3..."

    cd "$WEB_DIR"

    echo "  Syncing files to s3://$WEB_BUCKET_NAME/"
    aws s3 sync dist/ "s3://$WEB_BUCKET_NAME/" \
        --delete \
        --cache-control "public, max-age=31536000, immutable" \
        --exclude "index.html"

    echo "  Uploading index.html with no-cache policy..."
    aws s3 cp dist/index.html "s3://$WEB_BUCKET_NAME/index.html" \
        --cache-control "no-cache, no-store, must-revalidate" \
        --content-type "text/html"

    echo "  Files deployed to S3"
    echo ""
}

invalidate_cloudfront() {
    echo "Invalidating CloudFront cache..."

    INVALIDATION_ID=$(aws cloudfront create-invalidation \
        --distribution-id "$CLOUDFRONT_DISTRIBUTION_ID" \
        --paths "/*" \
        --query 'Invalidation.Id' \
        --output text)

    echo "  Invalidation created: $INVALIDATION_ID"
    echo "  Waiting for invalidation to complete (this may take 1-2 minutes)..."

    aws cloudfront wait invalidation-completed \
        --distribution-id "$CLOUDFRONT_DISTRIBUTION_ID" \
        --id "$INVALIDATION_ID"

    echo "  CloudFront cache invalidated"
    echo ""
}

print_deployment_summary() {
    WEB_URL=$(cat "$PROJECT_ROOT/terraform-outputs.json" | python3 -c "import sys, json; print(json.load(sys.stdin).get('web_url', {}).get('value', ''))")

    echo "=========================================="
    echo "Web Deployment Complete!"
    echo "=========================================="
    echo ""
    echo "Application URL: $WEB_URL"
    echo ""
    echo "Configuration:"
    echo "  API Endpoint: $API_ENDPOINT"
    echo "  User Pool ID: $USER_POOL_ID"
    echo "  Region: $AWS_REGION"
    echo ""
    echo "Next steps:"
    echo "1. Open the application URL in your browser"
    echo "2. Log in with your Cognito credentials"
    echo "3. Configure LLM settings in Settings > LLM Configuration"
    echo "4. Set up alert integrations in Settings > Integrations"
    echo ""
    echo "Note: It may take a few minutes for CloudFront to serve the updated content globally"
    echo ""
}

main() {
    check_prerequisites
    load_terraform_outputs
    create_env_file
    install_dependencies
    build_web_app
    deploy_to_s3
    invalidate_cloudfront
    print_deployment_summary
}

main
