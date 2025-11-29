#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=========================================="
echo "Mantissa Log GCP Deployment Script"
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

    if ! command -v gcloud &> /dev/null; then
        echo "ERROR: gcloud CLI not found. Please install Google Cloud SDK"
        exit 1
    fi

    GCLOUD_VERSION=$(gcloud version --format='value(version)' 2>/dev/null | head -n1)
    echo "  gcloud version: $GCLOUD_VERSION"

    if ! gcloud auth application-default print-access-token &> /dev/null; then
        echo "ERROR: GCP credentials not configured. Run: gcloud auth application-default login"
        exit 1
    fi

    PROJECT_ID=$(gcloud config get-value project 2>/dev/null || echo "")
    if [ -z "$PROJECT_ID" ]; then
        echo "ERROR: No GCP project configured. Run: gcloud config set project PROJECT_ID"
        exit 1
    fi
    echo "  GCP Project: $PROJECT_ID"

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

    PROJECT_ID=$(gcloud config get-value project 2>/dev/null)

    read -p "Environment name (dev/staging/prod) [dev]: " ENVIRONMENT
    ENVIRONMENT=${ENVIRONMENT:-dev}

    read -p "GCP Region [us-central1]: " GCP_REGION
    GCP_REGION=${GCP_REGION:-us-central1}

    read -p "GCP Project ID [$PROJECT_ID]: " INPUT_PROJECT_ID
    PROJECT_ID=${INPUT_PROJECT_ID:-$PROJECT_ID}

    read -p "Project prefix [mantissa-log]: " PROJECT_PREFIX
    PROJECT_PREFIX=${PROJECT_PREFIX:-mantissa-log}

    read -p "GCS bucket for Terraform state (will create if not exists) [${PROJECT_PREFIX}-terraform-state]: " STATE_BUCKET
    STATE_BUCKET=${STATE_BUCKET:-${PROJECT_PREFIX}-terraform-state}

    read -p "Enable Vertex AI integration? (y/n) [y]: " ENABLE_VERTEX_AI
    ENABLE_VERTEX_AI=${ENABLE_VERTEX_AI:-y}

    read -p "LLM Provider (vertex/anthropic/openai) [vertex]: " LLM_PROVIDER
    LLM_PROVIDER=${LLM_PROVIDER:-vertex}

    echo ""
    echo "Configuration Summary:"
    echo "  Environment: $ENVIRONMENT"
    echo "  Region: $GCP_REGION"
    echo "  Project ID: $PROJECT_ID"
    echo "  Project Prefix: $PROJECT_PREFIX"
    echo "  State Bucket: $STATE_BUCKET"
    echo "  Vertex AI: $ENABLE_VERTEX_AI"
    echo "  LLM Provider: $LLM_PROVIDER"
    echo ""

    read -p "Proceed with deployment? (y/n): " CONFIRM
    if [ "$CONFIRM" != "y" ]; then
        echo "Deployment cancelled"
        exit 0
    fi
}

enable_apis() {
    echo "Enabling required GCP APIs..."

    REQUIRED_APIS=(
        "cloudfunctions.googleapis.com"
        "cloudbuild.googleapis.com"
        "cloudscheduler.googleapis.com"
        "storage.googleapis.com"
        "firestore.googleapis.com"
        "logging.googleapis.com"
        "secretmanager.googleapis.com"
        "cloudresourcemanager.googleapis.com"
        "iam.googleapis.com"
        "compute.googleapis.com"
    )

    if [ "$ENABLE_VERTEX_AI" == "y" ]; then
        REQUIRED_APIS+=("aiplatform.googleapis.com")
    fi

    for api in "${REQUIRED_APIS[@]}"; do
        echo "  Enabling $api..."
        gcloud services enable "$api" --project="$PROJECT_ID" 2>/dev/null || true
    done

    echo "  API enablement complete"
    echo ""
}

create_state_bucket() {
    echo "Checking Terraform state bucket..."

    if ! gsutil ls -b "gs://$STATE_BUCKET" &> /dev/null; then
        echo "  Creating state bucket: $STATE_BUCKET"

        gsutil mb -p "$PROJECT_ID" -l "$GCP_REGION" "gs://$STATE_BUCKET"

        gsutil versioning set on "gs://$STATE_BUCKET"

        gsutil uniformbucketlevelaccess set on "gs://$STATE_BUCKET"

        echo "  State bucket created successfully"
    else
        echo "  State bucket already exists"
    fi
    echo ""
}

create_backend_config() {
    echo "Creating Terraform backend configuration..."

    cat > "$PROJECT_ROOT/infrastructure/gcp/terraform/backend.tf" <<EOF
terraform {
  backend "gcs" {
    bucket  = "$STATE_BUCKET"
    prefix  = "$ENVIRONMENT/state"
  }
}
EOF

    echo "  Backend configuration created"
    echo ""
}

package_cloud_functions() {
    echo "Packaging Cloud Functions..."

    FUNCTIONS_SOURCE_DIR="$PROJECT_ROOT/src/gcp/functions/collector"
    BUILD_DIR="$PROJECT_ROOT/build/gcp"

    mkdir -p "$BUILD_DIR/collector"

    echo "  Copying collector source..."
    cp "$FUNCTIONS_SOURCE_DIR/main.py" "$BUILD_DIR/collector/"
    cp "$FUNCTIONS_SOURCE_DIR/requirements.txt" "$BUILD_DIR/collector/"

    echo "  Copying shared modules..."
    cp -r "$PROJECT_ROOT/src/shared" "$BUILD_DIR/collector/" 2>/dev/null || true

    echo "  Cloud Functions source prepared at $BUILD_DIR/collector"
    echo ""
}

deploy_infrastructure() {
    echo "Deploying infrastructure with Terraform..."

    cd "$PROJECT_ROOT/infrastructure/gcp/terraform"

    echo "  Initializing Terraform..."
    terraform init

    echo ""
    echo "  Creating Terraform plan..."
    terraform plan \
        -var="environment=$ENVIRONMENT" \
        -var="project_id=$PROJECT_ID" \
        -var="region=$GCP_REGION" \
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
    terraform output -json > "$PROJECT_ROOT/terraform-outputs-gcp.json"

    echo "  Infrastructure deployment complete"
    echo ""
}

upload_detection_rules() {
    echo "Uploading detection rules..."

    RULES_BUCKET=$(python3 -c "import sys, json; print(json.load(open('$PROJECT_ROOT/terraform-outputs-gcp.json')).get('rules_bucket', {}).get('value', ''))" 2>/dev/null || echo "")

    if [ -z "$RULES_BUCKET" ]; then
        echo "  Warning: Rules bucket not found in outputs, skipping rule upload"
        return
    fi

    gsutil -m rsync -r -x '.*\.md$|README.*' "$PROJECT_ROOT/rules/" "gs://$RULES_BUCKET/rules/"

    echo "  Detection rules uploaded to gs://$RULES_BUCKET/rules/"
    echo ""
}

configure_audit_logs() {
    echo "Checking Cloud Audit Logs configuration..."

    echo "  Configuring audit log sinks..."

    LOGS_BUCKET=$(python3 -c "import sys, json; print(json.load(open('$PROJECT_ROOT/terraform-outputs-gcp.json')).get('logs_bucket', {}).get('value', ''))" 2>/dev/null || echo "")

    if [ -z "$LOGS_BUCKET" ]; then
        echo "  Warning: Logs bucket not found in outputs"
        return
    fi

    SINK_NAME="${PROJECT_PREFIX}-audit-logs-sink"

    if ! gcloud logging sinks describe "$SINK_NAME" --project="$PROJECT_ID" &> /dev/null; then
        echo "  Creating audit log sink: $SINK_NAME"

        gcloud logging sinks create "$SINK_NAME" \
            "storage.googleapis.com/$LOGS_BUCKET" \
            --log-filter='logName:"cloudaudit.googleapis.com"' \
            --project="$PROJECT_ID" > /dev/null

        echo "  Cloud Audit Logs sink configured"
    else
        echo "  Audit log sink already exists"
    fi
    echo ""
}

configure_secrets() {
    echo "Configuring secrets..."
    echo ""

    read -p "Configure SaaS API credentials in Secret Manager? (y/n) [n]: " CONFIGURE_SECRETS
    CONFIGURE_SECRETS=${CONFIGURE_SECRETS:-n}

    if [ "$CONFIGURE_SECRETS" == "y" ]; then
        echo "  Visit the GCP Console to add secrets:"
        echo "  https://console.cloud.google.com/security/secret-manager?project=$PROJECT_ID"
        echo ""
        echo "  Required secrets for each enabled collector:"
        echo "    - okta-domain, okta-token"
        echo "    - google-workspace-credentials"
        echo "    - microsoft365-tenant-id, microsoft365-client-id, microsoft365-client-secret"
        echo "    - github-token"
        echo "    - slack-token"
        echo "    - duo-api-hostname, duo-integration-key, duo-secret-key"
        echo "    - crowdstrike-client-id, crowdstrike-client-secret"
        echo "    - salesforce-instance-url, salesforce-client-id, salesforce-client-secret"
        echo "    - snowflake-account, snowflake-user, snowflake-private-key"
        echo "    - docker-api-url"
        echo "    - kubernetes-config"
        echo "    - jamf-url, jamf-client-id, jamf-client-secret"
        echo "    - onepassword-token"
        echo "    - azure-tenant-id, azure-client-id, azure-client-secret"
        echo ""
    else
        echo "  Skipping secret configuration"
        echo "  Configure secrets later in Secret Manager before enabling collectors"
        echo ""
    fi
}

run_smoke_tests() {
    echo "Running smoke tests..."

    if [ -f "$SCRIPT_DIR/smoke-test.sh" ]; then
        bash "$SCRIPT_DIR/smoke-test.sh" "$PROJECT_ROOT/terraform-outputs-gcp.json"
    else
        echo "  Smoke test script not found, skipping"
    fi

    echo ""
}

print_deployment_summary() {
    echo "=========================================="
    echo "Deployment Complete!"
    echo "=========================================="
    echo ""

    OUTPUTS_FILE="$PROJECT_ROOT/terraform-outputs-gcp.json"

    LOGS_BUCKET=$(python3 -c "import sys, json; print(json.load(open('$OUTPUTS_FILE')).get('logs_bucket', {}).get('value', ''))" 2>/dev/null || echo "")
    RULES_BUCKET=$(python3 -c "import sys, json; print(json.load(open('$OUTPUTS_FILE')).get('rules_bucket', {}).get('value', ''))" 2>/dev/null || echo "")

    echo "Environment: $ENVIRONMENT"
    echo "Region: $GCP_REGION"
    echo "Project: $PROJECT_ID"
    echo ""

    if [ -n "$LOGS_BUCKET" ]; then
        echo "Logs Bucket: gs://$LOGS_BUCKET"
    fi

    if [ -n "$RULES_BUCKET" ]; then
        echo "Rules Bucket: gs://$RULES_BUCKET"
    fi

    echo ""
    echo "Next steps:"
    echo "1. Configure SaaS API credentials in Secret Manager"
    echo "2. Review and enable detection rules in gs://$RULES_BUCKET"
    echo "3. Enable specific collectors by updating terraform variables"
    echo "4. Monitor collector execution in Cloud Logging"
    echo ""
    echo "View Cloud Functions:"
    echo "  gcloud functions list --project=$PROJECT_ID --region=$GCP_REGION"
    echo ""
    echo "View logs:"
    echo "  gcloud logging read 'resource.type=cloud_function' --project=$PROJECT_ID --limit=50"
    echo ""
}

main() {
    check_prerequisites
    collect_configuration
    enable_apis
    create_state_bucket
    create_backend_config
    package_cloud_functions
    deploy_infrastructure
    upload_detection_rules
    configure_audit_logs
    configure_secrets
    run_smoke_tests
    print_deployment_summary
}

main
