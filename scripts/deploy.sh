#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=========================================="
echo "Mantissa Log Deployment Script"
echo "=========================================="
echo ""

check_prerequisites() {
    echo "Checking prerequisites..."

    if ! command -v terraform &> /dev/null; then
        echo "ERROR: Terraform not found. Please install Terraform >= 1.5"
        exit 1
    fi

    TF_VERSION=$(terraform version -json | grep -o '"terraform_version":"[^"]*' | cut -d'"' -f4)
    echo "  Terraform version: $TF_VERSION"

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

    if ! command -v python3 &> /dev/null; then
        echo "ERROR: Python 3 not found"
        exit 1
    fi

    PYTHON_VERSION=$(python3 --version)
    echo "  $PYTHON_VERSION"

    echo "  Prerequisites check passed!"
    echo ""
}

collect_configuration() {
    echo "Configuration:"
    echo ""

    read -p "Environment name (dev/staging/prod) [dev]: " ENVIRONMENT
    ENVIRONMENT=${ENVIRONMENT:-dev}

    read -p "AWS Region [us-east-1]: " AWS_REGION
    AWS_REGION=${AWS_REGION:-us-east-1}

    read -p "Project prefix [mantissa-log]: " PROJECT_PREFIX
    PROJECT_PREFIX=${PROJECT_PREFIX:-mantissa-log}

    read -p "S3 bucket for Terraform state (will create if not exists) [${PROJECT_PREFIX}-terraform-state]: " STATE_BUCKET
    STATE_BUCKET=${STATE_BUCKET:-${PROJECT_PREFIX}-terraform-state}

    read -p "Enable VPC Flow Logs ingestion? (y/n) [y]: " ENABLE_VPC_FLOW
    ENABLE_VPC_FLOW=${ENABLE_VPC_FLOW:-y}

    read -p "Enable GuardDuty integration? (y/n) [y]: " ENABLE_GUARDDUTY
    ENABLE_GUARDDUTY=${ENABLE_GUARDDUTY:-y}

    read -p "LLM Provider (bedrock/anthropic/openai) [bedrock]: " LLM_PROVIDER
    LLM_PROVIDER=${LLM_PROVIDER:-bedrock}

    echo ""
    echo "Configuration Summary:"
    echo "  Environment: $ENVIRONMENT"
    echo "  Region: $AWS_REGION"
    echo "  Project Prefix: $PROJECT_PREFIX"
    echo "  State Bucket: $STATE_BUCKET"
    echo "  VPC Flow Logs: $ENABLE_VPC_FLOW"
    echo "  GuardDuty: $ENABLE_GUARDDUTY"
    echo "  LLM Provider: $LLM_PROVIDER"
    echo ""

    read -p "Proceed with deployment? (y/n): " CONFIRM
    if [ "$CONFIRM" != "y" ]; then
        echo "Deployment cancelled"
        exit 0
    fi
}

create_state_bucket() {
    echo "Checking Terraform state bucket..."

    if aws s3 ls "s3://$STATE_BUCKET" 2>&1 | grep -q 'NoSuchBucket'; then
        echo "  Creating state bucket: $STATE_BUCKET"

        if [ "$AWS_REGION" == "us-east-1" ]; then
            aws s3api create-bucket --bucket "$STATE_BUCKET" --region "$AWS_REGION"
        else
            aws s3api create-bucket --bucket "$STATE_BUCKET" --region "$AWS_REGION" \
                --create-bucket-configuration LocationConstraint="$AWS_REGION"
        fi

        aws s3api put-bucket-versioning --bucket "$STATE_BUCKET" \
            --versioning-configuration Status=Enabled

        aws s3api put-bucket-encryption --bucket "$STATE_BUCKET" \
            --server-side-encryption-configuration '{
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }]
            }'

        aws s3api put-public-access-block --bucket "$STATE_BUCKET" \
            --public-access-block-configuration \
            "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

        echo "  State bucket created successfully"
    else
        echo "  State bucket already exists"
    fi
    echo ""
}

create_backend_config() {
    echo "Creating Terraform backend configuration..."

    cat > "$PROJECT_ROOT/infrastructure/aws/terraform/backend.tf" <<EOF
terraform {
  backend "s3" {
    bucket         = "$STATE_BUCKET"
    key            = "$ENVIRONMENT/terraform.tfstate"
    region         = "$AWS_REGION"
    encrypt        = true
    dynamodb_table = "${PROJECT_PREFIX}-terraform-locks"
  }
}
EOF

    if ! aws dynamodb describe-table --table-name "${PROJECT_PREFIX}-terraform-locks" --region "$AWS_REGION" &> /dev/null; then
        echo "  Creating DynamoDB table for state locking..."
        aws dynamodb create-table \
            --table-name "${PROJECT_PREFIX}-terraform-locks" \
            --attribute-definitions AttributeName=LockID,AttributeType=S \
            --key-schema AttributeName=LockID,KeyType=HASH \
            --billing-mode PAY_PER_REQUEST \
            --region "$AWS_REGION" > /dev/null

        echo "  Waiting for table to be active..."
        aws dynamodb wait table-exists --table-name "${PROJECT_PREFIX}-terraform-locks" --region "$AWS_REGION"
    fi

    echo "  Backend configuration created"
    echo ""
}

package_lambda_functions() {
    echo "Packaging Lambda functions..."

    cd "$PROJECT_ROOT"

    bash "$SCRIPT_DIR/package-lambdas.sh"

    echo "  Lambda functions packaged"
    echo ""
}

deploy_infrastructure() {
    echo "Deploying infrastructure with Terraform..."

    cd "$PROJECT_ROOT/infrastructure/aws/terraform"

    echo "  Initializing Terraform..."
    terraform init

    echo ""
    echo "  Creating Terraform plan..."
    terraform plan \
        -var="environment=$ENVIRONMENT" \
        -var="aws_region=$AWS_REGION" \
        -var="project_prefix=$PROJECT_PREFIX" \
        -var="llm_provider=$LLM_PROVIDER" \
        -var-file="environments/$ENVIRONMENT.tfvars" \
        -out=tfplan

    echo ""
    read -p "Apply this plan? (y/n): " APPLY_CONFIRM
    if [ "$APPLY_CONFIRM" != "y" ]; then
        echo "Deployment cancelled"
        exit 0
    fi

    echo "  Applying Terraform configuration..."
    terraform apply tfplan

    echo ""
    echo "  Extracting outputs..."
    terraform output -json > "$PROJECT_ROOT/terraform-outputs.json"

    echo "  Infrastructure deployment complete"
    echo ""
}

upload_detection_rules() {
    echo "Uploading detection rules..."

    RULES_BUCKET=$(cat "$PROJECT_ROOT/terraform-outputs.json" | grep -o '"rules_bucket[^:]*:[^"]*"[^"]*"' | cut -d'"' -f4 || echo "")

    if [ -z "$RULES_BUCKET" ]; then
        echo "  Warning: Rules bucket not found in outputs, skipping rule upload"
        return
    fi

    aws s3 sync "$PROJECT_ROOT/rules/" "s3://$RULES_BUCKET/rules/" \
        --exclude "*.md" \
        --exclude "README*"

    echo "  Detection rules uploaded to s3://$RULES_BUCKET/rules/"
    echo ""
}

configure_cloudtrail() {
    echo "Checking CloudTrail configuration..."

    LOGS_BUCKET=$(cat "$PROJECT_ROOT/terraform-outputs.json" | grep -o '"logs_bucket[^:]*:[^"]*"[^"]*"' | cut -d'"' -f4 || echo "")

    if [ -z "$LOGS_BUCKET" ]; then
        echo "  Warning: Logs bucket not found in outputs"
        return
    fi

    TRAIL_NAME="${PROJECT_PREFIX}-trail"

    if ! aws cloudtrail get-trail --name "$TRAIL_NAME" --region "$AWS_REGION" &> /dev/null; then
        echo "  Creating CloudTrail trail: $TRAIL_NAME"

        aws cloudtrail create-trail \
            --name "$TRAIL_NAME" \
            --s3-bucket-name "$LOGS_BUCKET" \
            --s3-key-prefix "cloudtrail/" \
            --is-multi-region-trail \
            --enable-log-file-validation \
            --region "$AWS_REGION" > /dev/null

        aws cloudtrail start-logging --name "$TRAIL_NAME" --region "$AWS_REGION"

        echo "  CloudTrail configured and started"
    else
        echo "  CloudTrail trail already exists"
    fi
    echo ""
}

create_admin_user() {
    echo "Setting up Cognito admin user..."

    USER_POOL_ID=$(cat "$PROJECT_ROOT/terraform-outputs.json" | grep -o '"user_pool_id[^:]*:[^"]*"[^"]*"' | cut -d'"' -f4 || echo "")

    if [ -z "$USER_POOL_ID" ]; then
        echo "  Warning: User pool ID not found in outputs, skipping user creation"
        return
    fi

    read -p "Create admin user? (y/n) [y]: " CREATE_USER
    CREATE_USER=${CREATE_USER:-y}

    if [ "$CREATE_USER" == "y" ]; then
        read -p "Admin email address: " ADMIN_EMAIL
        read -s -p "Admin password (min 8 chars, upper, lower, number, special): " ADMIN_PASSWORD
        echo ""

        aws cognito-idp admin-create-user \
            --user-pool-id "$USER_POOL_ID" \
            --username "$ADMIN_EMAIL" \
            --user-attributes Name=email,Value="$ADMIN_EMAIL" Name=email_verified,Value=true \
            --temporary-password "$ADMIN_PASSWORD" \
            --message-action SUPPRESS \
            --region "$AWS_REGION" > /dev/null 2>&1 || echo "  User may already exist"

        aws cognito-idp admin-set-user-password \
            --user-pool-id "$USER_POOL_ID" \
            --username "$ADMIN_EMAIL" \
            --password "$ADMIN_PASSWORD" \
            --permanent \
            --region "$AWS_REGION" > /dev/null

        echo "  Admin user created: $ADMIN_EMAIL"
    fi
    echo ""
}

run_smoke_tests() {
    echo "Running smoke tests..."

    bash "$SCRIPT_DIR/smoke-test.sh" "$PROJECT_ROOT/terraform-outputs.json"

    echo ""
}

deploy_web_application() {
    echo "Web application deployment..."
    echo ""

    read -p "Deploy web application to CloudFront? (y/n) [y]: " DEPLOY_WEB
    DEPLOY_WEB=${DEPLOY_WEB:-y}

    if [ "$DEPLOY_WEB" == "y" ]; then
        bash "$SCRIPT_DIR/deploy-web.sh"
    else
        echo "  Skipping web deployment"
        echo "  You can deploy the web app later by running: ./scripts/deploy-web.sh"
        echo ""
    fi
}

print_deployment_summary() {
    echo "=========================================="
    echo "Deployment Complete!"
    echo "=========================================="
    echo ""

    API_URL=$(cat "$PROJECT_ROOT/terraform-outputs.json" | grep -o '"api_endpoint[^:]*:[^"]*"[^"]*"' | cut -d'"' -f4 || echo "")
    USER_POOL_ID=$(cat "$PROJECT_ROOT/terraform-outputs.json" | grep -o '"user_pool_id[^:]*:[^"]*"[^"]*"' | cut -d'"' -f4 || echo "")
    USER_POOL_CLIENT_ID=$(cat "$PROJECT_ROOT/terraform-outputs.json" | grep -o '"user_pool_client_id[^:]*:[^"]*"[^"]*"' | cut -d'"' -f4 || echo "")
    WEB_URL=$(cat "$PROJECT_ROOT/terraform-outputs.json" | python3 -c "import sys, json; print(json.load(sys.stdin).get('web_url', {}).get('value', ''))" 2>/dev/null || echo "")

    echo "Environment: $ENVIRONMENT"
    echo "Region: $AWS_REGION"
    echo ""

    if [ -n "$API_URL" ]; then
        echo "API Endpoint: $API_URL"
    fi

    if [ -n "$WEB_URL" ]; then
        echo "Web Application: $WEB_URL"
    fi

    if [ -n "$USER_POOL_ID" ]; then
        echo "Cognito User Pool ID: $USER_POOL_ID"
    fi

    if [ -n "$USER_POOL_CLIENT_ID" ]; then
        echo "Cognito Client ID: $USER_POOL_CLIENT_ID"
    fi

    echo ""
    echo "Next steps:"
    echo "1. Configure alert destinations in AWS Secrets Manager"
    echo "2. Review and enable detection rules"
    echo "3. Configure log sources (CloudTrail, VPC Flow Logs, etc.)"
    if [ -z "$WEB_URL" ] || [ "$DEPLOY_WEB" != "y" ]; then
        echo "4. Deploy the web interface: ./scripts/deploy-web.sh"
    else
        echo "4. Access the web interface at: $WEB_URL"
    fi
    echo ""
    echo "For more information, see docs/deployment/aws-deployment.md"
    echo ""
}

main() {
    check_prerequisites
    collect_configuration
    create_state_bucket
    create_backend_config
    package_lambda_functions
    deploy_infrastructure
    upload_detection_rules
    configure_cloudtrail
    create_admin_user
    run_smoke_tests
    deploy_web_application
    print_deployment_summary
}

main
