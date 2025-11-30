#!/bin/bash

# Fix environment variable name mismatches between Lambda handlers and Terraform

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Fixing environment variable name mismatches..."
echo ""

# Fix Slack collector
echo "Fixing slack_collector_handler.py..."
sed -i.bak \
    -e "s/LOGS_BUCKET = os.environ.get('LOGS_BUCKET'/LOGS_BUCKET = os.environ.get('S3_BUCKET'/g" \
    -e "s/API_TOKEN_SECRET = os.environ.get('API_TOKEN_SECRET'/API_TOKEN_SECRET = os.environ.get('SLACK_TOKEN_SECRET'/g" \
    "$PROJECT_ROOT/src/aws/lambda/slack_collector_handler.py"

# Fix Microsoft 365 collector
echo "Fixing microsoft365_collector_handler.py..."
sed -i.bak \
    -e "s/LOGS_BUCKET = os.environ.get('LOGS_BUCKET'/LOGS_BUCKET = os.environ.get('S3_BUCKET'/g" \
    -e "s/CREDENTIALS_SECRET = os.environ.get('CREDENTIALS_SECRET'/M365_CLIENT_ID_SECRET = os.environ.get('M365_CLIENT_ID_SECRET'/g" \
    -e "/^TENANT_ID = os.environ.get('TENANT_ID'/c\\
M365_TENANT_ID_SECRET = os.environ.get('M365_TENANT_ID_SECRET', 'mantissa/microsoft365/tenant_id')\\
M365_CLIENT_SECRET_SECRET = os.environ.get('M365_CLIENT_SECRET_SECRET', 'mantissa/microsoft365/client_secret')" \
    "$PROJECT_ROOT/src/aws/lambda/microsoft365_collector_handler.py"

# Fix CrowdStrike collector
echo "Fixing crowdstrike_collector_handler.py..."
sed -i.bak \
    -e "s/LOGS_BUCKET = os.environ.get('LOGS_BUCKET'/LOGS_BUCKET = os.environ.get('S3_BUCKET'/g" \
    -e "s/API_CREDENTIALS_SECRET = os.environ.get('API_CREDENTIALS_SECRET'/CROWDSTRIKE_CLIENT_ID_SECRET = os.environ.get('CROWDSTRIKE_CLIENT_ID_SECRET'/g" \
    -e "/^FALCON_CLOUD/d" \
    "$PROJECT_ROOT/src/aws/lambda/crowdstrike_collector_handler.py"

# Fix GitHub collector
echo "Fixing github_collector_handler.py..."
sed -i.bak \
    -e "s/LOGS_BUCKET = os.environ.get('LOGS_BUCKET'/LOGS_BUCKET = os.environ.get('S3_BUCKET'/g" \
    -e "s/API_TOKEN_SECRET = os.environ.get('API_TOKEN_SECRET'/API_TOKEN_SECRET = os.environ.get('GITHUB_TOKEN_SECRET'/g" \
    -e "/^GITHUB_ORG = os.environ.get/c\\
GITHUB_ORG_SECRET = os.environ.get('GITHUB_ORG_SECRET', 'mantissa/github/org')" \
    -e "/^GITHUB_ENTERPRISE/d" \
    -e "/^GITHUB_API_BASE/d" \
    "$PROJECT_ROOT/src/aws/lambda/github_collector_handler.py"

# Fix Google Workspace collector
echo "Fixing google_workspace_collector_handler.py..."
sed -i.bak \
    -e "s/LOGS_BUCKET = os.environ.get('LOGS_BUCKET'/LOGS_BUCKET = os.environ.get('S3_BUCKET'/g" \
    -e "s/SERVICE_ACCOUNT_SECRET = os.environ.get('SERVICE_ACCOUNT_SECRET'/GOOGLE_CREDENTIALS_SECRET = os.environ.get('GOOGLE_CREDENTIALS_SECRET'/g" \
    -e "/^DELEGATED_ADMIN_EMAIL = os.environ.get/c\\
GOOGLE_DELEGATED_ADMIN_SECRET = os.environ.get('GOOGLE_DELEGATED_ADMIN_SECRET', 'mantissa/google-workspace/admin_email')\\
GOOGLE_CUSTOMER_ID_SECRET = os.environ.get('GOOGLE_CUSTOMER_ID_SECRET', 'mantissa/google-workspace/customer_id')" \
    "$PROJECT_ROOT/src/aws/lambda/google_workspace_collector_handler.py"

# Fix Okta collector
echo "Fixing okta_collector_handler.py..."
sed -i.bak \
    -e "/org_url = os.environ.get('OKTA_ORG_URL'/c\\
    okta_domain_secret = os.environ.get('OKTA_DOMAIN_SECRET', 'mantissa/okta/domain')\\
    # Retrieve Okta domain from Secrets Manager\\
    try:\\
        domain_response = secrets_client.get_secret_value(SecretId=okta_domain_secret)\\
        domain_data = json.loads(domain_response['SecretString'])\\
        org_url = domain_data.get('domain', '')" \
    "$PROJECT_ROOT/src/aws/lambda/okta_collector_handler.py"

echo ""
echo "Removing backup files..."
find "$PROJECT_ROOT/src/aws/lambda" -name "*.bak" -delete

echo "Done! Environment variable names fixed."
echo ""
echo "Next steps:"
echo "1. Review the changes with: git diff src/aws/lambda/*_collector_handler.py"
echo "2. Update collector __init__ methods to fetch secrets from Secrets Manager"
echo "3. Test Lambda handlers locally"
