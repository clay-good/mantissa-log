#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=========================================="
echo "Mantissa Log Azure Deployment Script"
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

    if ! command -v az &> /dev/null; then
        echo "ERROR: Azure CLI not found. Please install Azure CLI"
        exit 1
    fi

    AZ_VERSION=$(az version --output tsv --query '"azure-cli"' 2>/dev/null || az version | grep -o 'azure-cli[^,]*' | cut -d' ' -f2)
    echo "  Azure CLI version: $AZ_VERSION"

    if ! az account show &> /dev/null; then
        echo "ERROR: Not logged in to Azure. Run: az login"
        exit 1
    fi

    SUBSCRIPTION_ID=$(az account show --query id -o tsv)
    SUBSCRIPTION_NAME=$(az account show --query name -o tsv)
    echo "  Azure Subscription: $SUBSCRIPTION_NAME ($SUBSCRIPTION_ID)"

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

    SUBSCRIPTION_ID=$(az account show --query id -o tsv)

    read -p "Environment name (dev/staging/prod) [dev]: " ENVIRONMENT
    ENVIRONMENT=${ENVIRONMENT:-dev}

    read -p "Azure Region [eastus]: " AZURE_REGION
    AZURE_REGION=${AZURE_REGION:-eastus}

    read -p "Azure Subscription ID [$SUBSCRIPTION_ID]: " INPUT_SUBSCRIPTION_ID
    SUBSCRIPTION_ID=${INPUT_SUBSCRIPTION_ID:-$SUBSCRIPTION_ID}

    read -p "Project prefix [mantissa-log]: " PROJECT_PREFIX
    PROJECT_PREFIX=${PROJECT_PREFIX:-mantissa-log}

    read -p "Storage account for Terraform state (will create if not exists) [${PROJECT_PREFIX}tfstate]: " STATE_STORAGE_ACCOUNT
    STATE_STORAGE_ACCOUNT=${STATE_STORAGE_ACCOUNT:-${PROJECT_PREFIX}tfstate}
    STATE_STORAGE_ACCOUNT=$(echo "$STATE_STORAGE_ACCOUNT" | tr -d '-' | cut -c1-24)

    read -p "Resource group for Terraform state [${PROJECT_PREFIX}-terraform-state]: " STATE_RESOURCE_GROUP
    STATE_RESOURCE_GROUP=${STATE_RESOURCE_GROUP:-${PROJECT_PREFIX}-terraform-state}

    read -p "Enable Azure OpenAI integration? (y/n) [y]: " ENABLE_OPENAI
    ENABLE_OPENAI=${ENABLE_OPENAI:-y}

    read -p "LLM Provider (azure-openai/anthropic/openai) [azure-openai]: " LLM_PROVIDER
    LLM_PROVIDER=${LLM_PROVIDER:-azure-openai}

    echo ""
    echo "Configuration Summary:"
    echo "  Environment: $ENVIRONMENT"
    echo "  Region: $AZURE_REGION"
    echo "  Subscription ID: $SUBSCRIPTION_ID"
    echo "  Project Prefix: $PROJECT_PREFIX"
    echo "  State Storage Account: $STATE_STORAGE_ACCOUNT"
    echo "  State Resource Group: $STATE_RESOURCE_GROUP"
    echo "  Azure OpenAI: $ENABLE_OPENAI"
    echo "  LLM Provider: $LLM_PROVIDER"
    echo ""

    read -p "Proceed with deployment? (y/n): " CONFIRM
    if [ "$CONFIRM" != "y" ]; then
        echo "Deployment cancelled"
        exit 0
    fi
}

create_state_storage() {
    echo "Checking Terraform state storage..."

    if ! az group show --name "$STATE_RESOURCE_GROUP" &> /dev/null; then
        echo "  Creating resource group: $STATE_RESOURCE_GROUP"
        az group create --name "$STATE_RESOURCE_GROUP" --location "$AZURE_REGION" --output none
    else
        echo "  Resource group already exists"
    fi

    if ! az storage account show --name "$STATE_STORAGE_ACCOUNT" --resource-group "$STATE_RESOURCE_GROUP" &> /dev/null; then
        echo "  Creating storage account: $STATE_STORAGE_ACCOUNT"

        az storage account create \
            --name "$STATE_STORAGE_ACCOUNT" \
            --resource-group "$STATE_RESOURCE_GROUP" \
            --location "$AZURE_REGION" \
            --sku Standard_LRS \
            --encryption-services blob \
            --https-only true \
            --min-tls-version TLS1_2 \
            --allow-blob-public-access false \
            --output none

        STORAGE_KEY=$(az storage account keys list --account-name "$STATE_STORAGE_ACCOUNT" --resource-group "$STATE_RESOURCE_GROUP" --query '[0].value' -o tsv)

        az storage container create \
            --name tfstate \
            --account-name "$STATE_STORAGE_ACCOUNT" \
            --account-key "$STORAGE_KEY" \
            --output none

        echo "  State storage created successfully"
    else
        echo "  Storage account already exists"
    fi
    echo ""
}

create_backend_config() {
    echo "Creating Terraform backend configuration..."

    cat > "$PROJECT_ROOT/infrastructure/azure/terraform/backend.tf" <<EOF
terraform {
  backend "azurerm" {
    resource_group_name  = "$STATE_RESOURCE_GROUP"
    storage_account_name = "$STATE_STORAGE_ACCOUNT"
    container_name       = "tfstate"
    key                  = "$ENVIRONMENT.terraform.tfstate"
  }
}
EOF

    echo "  Backend configuration created"
    echo ""
}

package_function_apps() {
    echo "Packaging Azure Function Apps..."

    cd "$PROJECT_ROOT"

    bash "$SCRIPT_DIR/package-azure-functions.sh"

    echo "  Function Apps packaged"
    echo ""
}

deploy_infrastructure() {
    echo "Deploying infrastructure with Terraform..."

    cd "$PROJECT_ROOT/infrastructure/azure/terraform"

    echo "  Initializing Terraform..."
    terraform init

    echo ""
    echo "  Creating Terraform plan..."
    terraform plan \
        -var="environment=$ENVIRONMENT" \
        -var="location=$AZURE_REGION" \
        -var="subscription_id=$SUBSCRIPTION_ID" \
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
    terraform output -json > "$PROJECT_ROOT/terraform-outputs-azure.json"

    echo "  Infrastructure deployment complete"
    echo ""
}

upload_function_code() {
    echo "Uploading Function App code..."

    RESOURCE_GROUP=$(python3 -c "import sys, json; print(json.load(open('$PROJECT_ROOT/terraform-outputs-azure.json')).get('resource_group_name', {}).get('value', ''))" 2>/dev/null || echo "")

    # Deploy Collectors Function App
    COLLECTOR_APP=$(python3 -c "import sys, json; print(json.load(open('$PROJECT_ROOT/terraform-outputs-azure.json')).get('collector_function_app_name', {}).get('value', ''))" 2>/dev/null || echo "")
    if [ -n "$COLLECTOR_APP" ] && [ -f "$PROJECT_ROOT/build/azure/collectors-app.zip" ]; then
        echo "  Deploying Collectors Function App: $COLLECTOR_APP"
        az functionapp deployment source config-zip \
            --resource-group "$RESOURCE_GROUP" \
            --name "$COLLECTOR_APP" \
            --src "$PROJECT_ROOT/build/azure/collectors-app.zip" \
            --output none
        echo "  Collectors Function App deployed"
    fi

    # Deploy LLM Query Function App
    LLM_QUERY_APP=$(python3 -c "import sys, json; print(json.load(open('$PROJECT_ROOT/terraform-outputs-azure.json')).get('llm_query_function_app_name', {}).get('value', ''))" 2>/dev/null || echo "")
    if [ -n "$LLM_QUERY_APP" ] && [ -f "$PROJECT_ROOT/build/azure/llm-query-app.zip" ]; then
        echo "  Deploying LLM Query Function App: $LLM_QUERY_APP"
        az functionapp deployment source config-zip \
            --resource-group "$RESOURCE_GROUP" \
            --name "$LLM_QUERY_APP" \
            --src "$PROJECT_ROOT/build/azure/llm-query-app.zip" \
            --output none
        echo "  LLM Query Function App deployed"
    fi

    # Deploy Detection Engine Function App
    DETECTION_APP=$(python3 -c "import sys, json; print(json.load(open('$PROJECT_ROOT/terraform-outputs-azure.json')).get('detection_function_app_name', {}).get('value', ''))" 2>/dev/null || echo "")
    if [ -n "$DETECTION_APP" ] && [ -f "$PROJECT_ROOT/build/azure/detection-app.zip" ]; then
        echo "  Deploying Detection Engine Function App: $DETECTION_APP"
        az functionapp deployment source config-zip \
            --resource-group "$RESOURCE_GROUP" \
            --name "$DETECTION_APP" \
            --src "$PROJECT_ROOT/build/azure/detection-app.zip" \
            --output none
        echo "  Detection Engine Function App deployed"
    fi

    # Deploy Alert Router Function App
    ALERT_ROUTER_APP=$(python3 -c "import sys, json; print(json.load(open('$PROJECT_ROOT/terraform-outputs-azure.json')).get('alert_router_function_app_name', {}).get('value', ''))" 2>/dev/null || echo "")
    if [ -n "$ALERT_ROUTER_APP" ] && [ -f "$PROJECT_ROOT/build/azure/alert-router-app.zip" ]; then
        echo "  Deploying Alert Router Function App: $ALERT_ROUTER_APP"
        az functionapp deployment source config-zip \
            --resource-group "$RESOURCE_GROUP" \
            --name "$ALERT_ROUTER_APP" \
            --src "$PROJECT_ROOT/build/azure/alert-router-app.zip" \
            --output none
        echo "  Alert Router Function App deployed"
    fi

    echo ""
}

upload_detection_rules() {
    echo "Uploading detection rules..."

    RULES_CONTAINER=$(python3 -c "import sys, json; print(json.load(open('$PROJECT_ROOT/terraform-outputs-azure.json')).get('rules_storage_container', {}).get('value', ''))" 2>/dev/null || echo "")
    STORAGE_ACCOUNT_NAME=$(python3 -c "import sys, json; print(json.load(open('$PROJECT_ROOT/terraform-outputs-azure.json')).get('storage_account_name', {}).get('value', ''))" 2>/dev/null || echo "")

    if [ -z "$RULES_CONTAINER" ] || [ -z "$STORAGE_ACCOUNT_NAME" ]; then
        echo "  Warning: Rules storage not found in outputs, skipping rule upload"
        return
    fi

    STORAGE_KEY=$(az storage account keys list --account-name "$STORAGE_ACCOUNT_NAME" --query '[0].value' -o tsv)

    find "$PROJECT_ROOT/rules" -type f \( -name "*.json" -o -name "*.yml" -o -name "*.yaml" \) | while read -r rule_file; do
        BLOB_NAME=$(echo "$rule_file" | sed "s|$PROJECT_ROOT/rules/||")
        az storage blob upload \
            --account-name "$STORAGE_ACCOUNT_NAME" \
            --account-key "$STORAGE_KEY" \
            --container-name "$RULES_CONTAINER" \
            --name "$BLOB_NAME" \
            --file "$rule_file" \
            --overwrite \
            --output none 2>/dev/null || true
    done

    echo "  Detection rules uploaded to $STORAGE_ACCOUNT_NAME/$RULES_CONTAINER"
    echo ""
}

configure_activity_logs() {
    echo "Checking Azure Activity Logs configuration..."

    LOGS_STORAGE=$(python3 -c "import sys, json; print(json.load(open('$PROJECT_ROOT/terraform-outputs-azure.json')).get('storage_account_name', {}).get('value', ''))" 2>/dev/null || echo "")

    if [ -z "$LOGS_STORAGE" ]; then
        echo "  Warning: Logs storage not found in outputs"
        return
    fi

    DIAGNOSTIC_SETTING_NAME="${PROJECT_PREFIX}-activity-logs"

    if ! az monitor diagnostic-settings subscription show --name "$DIAGNOSTIC_SETTING_NAME" &> /dev/null; then
        echo "  Creating Activity Logs diagnostic setting: $DIAGNOSTIC_SETTING_NAME"

        STORAGE_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$(az storage account show --name "$LOGS_STORAGE" --query resourceGroup -o tsv)/providers/Microsoft.Storage/storageAccounts/$LOGS_STORAGE"

        az monitor diagnostic-settings subscription create \
            --name "$DIAGNOSTIC_SETTING_NAME" \
            --location "$AZURE_REGION" \
            --storage-account "$STORAGE_ID" \
            --logs '[
                {
                    "category": "Administrative",
                    "enabled": true
                },
                {
                    "category": "Security",
                    "enabled": true
                },
                {
                    "category": "Alert",
                    "enabled": true
                },
                {
                    "category": "Policy",
                    "enabled": true
                }
            ]' \
            --output none 2>/dev/null || echo "  Diagnostic setting may already exist or require different configuration"

        echo "  Activity Logs configured"
    else
        echo "  Activity Logs diagnostic setting already exists"
    fi
    echo ""
}

configure_secrets() {
    echo "Configuring secrets..."
    echo ""

    read -p "Configure SaaS API credentials in Key Vault? (y/n) [n]: " CONFIGURE_SECRETS
    CONFIGURE_SECRETS=${CONFIGURE_SECRETS:-n}

    if [ "$CONFIGURE_SECRETS" == "y" ]; then
        KEY_VAULT_NAME=$(python3 -c "import sys, json; print(json.load(open('$PROJECT_ROOT/terraform-outputs-azure.json')).get('key_vault_name', {}).get('value', ''))" 2>/dev/null || echo "")

        if [ -n "$KEY_VAULT_NAME" ]; then
            echo "  Visit the Azure Portal to add secrets:"
            echo "  https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.KeyVault%2Fvaults"
            echo ""
            echo "  Key Vault: $KEY_VAULT_NAME"
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
        fi
    else
        echo "  Skipping secret configuration"
        echo "  Configure secrets later in Key Vault before enabling collectors"
        echo ""
    fi
}

run_smoke_tests() {
    echo "Running smoke tests..."

    if [ -f "$SCRIPT_DIR/smoke-test.sh" ]; then
        bash "$SCRIPT_DIR/smoke-test.sh" "$PROJECT_ROOT/terraform-outputs-azure.json"
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

    OUTPUTS_FILE="$PROJECT_ROOT/terraform-outputs-azure.json"

    RESOURCE_GROUP=$(python3 -c "import sys, json; print(json.load(open('$OUTPUTS_FILE')).get('resource_group_name', {}).get('value', ''))" 2>/dev/null || echo "")
    STORAGE_ACCOUNT=$(python3 -c "import sys, json; print(json.load(open('$OUTPUTS_FILE')).get('storage_account_name', {}).get('value', ''))" 2>/dev/null || echo "")
    COLLECTOR_APP=$(python3 -c "import sys, json; print(json.load(open('$OUTPUTS_FILE')).get('collector_function_app_name', {}).get('value', ''))" 2>/dev/null || echo "")
    LLM_QUERY_APP=$(python3 -c "import sys, json; print(json.load(open('$OUTPUTS_FILE')).get('llm_query_function_app_name', {}).get('value', ''))" 2>/dev/null || echo "")
    DETECTION_APP=$(python3 -c "import sys, json; print(json.load(open('$OUTPUTS_FILE')).get('detection_function_app_name', {}).get('value', ''))" 2>/dev/null || echo "")
    ALERT_ROUTER_APP=$(python3 -c "import sys, json; print(json.load(open('$OUTPUTS_FILE')).get('alert_router_function_app_name', {}).get('value', ''))" 2>/dev/null || echo "")
    STATIC_WEB_APP=$(python3 -c "import sys, json; print(json.load(open('$OUTPUTS_FILE')).get('static_web_app_url', {}).get('value', ''))" 2>/dev/null || echo "")
    KEY_VAULT=$(python3 -c "import sys, json; print(json.load(open('$OUTPUTS_FILE')).get('key_vault_name', {}).get('value', ''))" 2>/dev/null || echo "")

    echo "Environment: $ENVIRONMENT"
    echo "Region: $AZURE_REGION"
    echo "Subscription: $SUBSCRIPTION_ID"
    echo ""

    echo "Resources Deployed:"
    [ -n "$RESOURCE_GROUP" ] && echo "  Resource Group: $RESOURCE_GROUP"
    [ -n "$STORAGE_ACCOUNT" ] && echo "  Storage Account: $STORAGE_ACCOUNT"
    [ -n "$KEY_VAULT" ] && echo "  Key Vault: $KEY_VAULT"
    echo ""

    echo "Function Apps:"
    [ -n "$COLLECTOR_APP" ] && echo "  Collectors: $COLLECTOR_APP"
    [ -n "$LLM_QUERY_APP" ] && echo "  LLM Query: $LLM_QUERY_APP"
    [ -n "$DETECTION_APP" ] && echo "  Detection Engine: $DETECTION_APP"
    [ -n "$ALERT_ROUTER_APP" ] && echo "  Alert Router: $ALERT_ROUTER_APP"
    echo ""

    if [ -n "$STATIC_WEB_APP" ]; then
        echo "Frontend:"
        echo "  Static Web App URL: $STATIC_WEB_APP"
        echo ""
    fi

    echo "Next steps:"
    echo "1. Configure SaaS API credentials in Key Vault: $KEY_VAULT"
    echo "2. Deploy frontend code to Static Web App"
    echo "3. Review and enable detection rules in storage"
    echo "4. Enable specific collectors by updating terraform variables"
    echo "5. Monitor execution in Application Insights"
    echo ""
    echo "View Function Apps:"
    echo "  az functionapp list --resource-group $RESOURCE_GROUP --output table"
    echo ""
    echo "View logs:"
    echo "  az monitor app-insights query --app $COLLECTOR_APP --analytics-query 'traces | limit 50'"
    echo ""
}

main() {
    check_prerequisites
    collect_configuration
    create_state_storage
    create_backend_config
    package_function_apps
    deploy_infrastructure
    upload_function_code
    upload_detection_rules
    configure_activity_logs
    configure_secrets
    run_smoke_tests
    print_deployment_summary
}

main
