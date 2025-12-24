# Mantissa Log Quick Start

Get Mantissa Log running in 15 minutes.

---

## Quick Start: SIEM Only

Minimal deployment with log aggregation, querying, detection, and alerting.

### Step 1: Clone and Configure

```bash
git clone https://github.com/your-org/mantissa-log.git
cd mantissa-log

# Copy example configuration
cp infrastructure/aws/terraform/terraform.tfvars.example \
   infrastructure/aws/terraform/terraform.tfvars
```

### Step 2: Edit Configuration

Edit `infrastructure/aws/terraform/terraform.tfvars`:

```hcl
# Required settings
environment    = "dev"
aws_region     = "us-east-1"
project_name   = "mantissa-log"

# Module flags - SIEM only
enable_siem = true
enable_apm  = false
enable_soar = false

# LLM provider (choose one)
llm_provider = "bedrock"  # Uses AWS Bedrock (recommended)
# llm_provider = "anthropic"
# anthropic_api_key = "sk-..."

# Alert destination (at least one)
slack_webhook_url = "https://hooks.slack.com/services/..."
```

### Step 3: Deploy Infrastructure

```bash
cd infrastructure/aws/terraform

# Initialize Terraform
terraform init

# Preview changes
terraform plan

# Deploy (takes ~5 minutes)
terraform apply
```

### Step 4: Deploy Lambda Functions

```bash
cd ../../..
pip install -r requirements.txt
bash scripts/deploy.sh
```

### Step 5: Deploy Frontend

```bash
cd web
npm install
npm run build

# Get the frontend bucket name from Terraform output
BUCKET=$(cd ../infrastructure/aws/terraform && terraform output -raw frontend_bucket)
aws s3 sync dist/ s3://$BUCKET/
```

### Step 6: Access the UI

Get the CloudFront URL:
```bash
cd infrastructure/aws/terraform
terraform output frontend_url
```

Open the URL in your browser.

### Step 7: Configure Your First Collector

Navigate to **Settings → Collectors → Add Collector**

For Okta:
1. Select "Okta" from source type
2. Enter your Okta domain (e.g., `your-org.okta.com`)
3. Enter API token (create in Okta Admin → Security → API → Tokens)
4. Click "Test Connection"
5. Click "Save"

### Step 8: Try a Query

Navigate to **Query** and try:

```
Show me all events from the last hour
```

---

## Quick Start: Add Observability

Add APM capabilities to an existing SIEM deployment.

### Step 1: Update Configuration

Edit `infrastructure/aws/terraform/terraform.tfvars`:

```hcl
# Change this line
enable_apm = true
```

### Step 2: Apply Changes

```bash
cd infrastructure/aws/terraform
terraform apply
```

### Step 3: Deploy Updated Functions

```bash
cd ../../..
bash scripts/deploy.sh --include-apm
```

### Step 4: Get OTLP Endpoint

```bash
cd infrastructure/aws/terraform
terraform output otlp_endpoint
```

Example output:
```
https://abc123.execute-api.us-east-1.amazonaws.com/prod
```

### Step 5: Configure Your Application

**Python with OpenTelemetry:**

```bash
pip install opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp-proto-http
```

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

# Configure
trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)

exporter = OTLPSpanExporter(
    endpoint="https://abc123.execute-api.us-east-1.amazonaws.com/prod/v1/traces"
)
trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(exporter))

# Use
with tracer.start_as_current_span("my-operation"):
    # Your code here
    pass
```

**Node.js with OpenTelemetry:**

```bash
npm install @opentelemetry/api @opentelemetry/sdk-trace-node @opentelemetry/exporter-trace-otlp-http
```

```javascript
const { NodeTracerProvider } = require('@opentelemetry/sdk-trace-node');
const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-http');
const { BatchSpanProcessor } = require('@opentelemetry/sdk-trace-base');

const provider = new NodeTracerProvider();

const exporter = new OTLPTraceExporter({
  url: 'https://abc123.execute-api.us-east-1.amazonaws.com/prod/v1/traces',
});

provider.addSpanProcessor(new BatchSpanProcessor(exporter));
provider.register();
```

### Step 6: Verify Data Flow

Generate some traffic in your application, then:

1. Navigate to **APM → Service Map**
2. You should see your service(s) appear
3. Click a service to view traces
4. Try query: "Show me traces with errors"

---

## Quick Start: Add SOAR

Add automated response capabilities.

### Step 1: Update Configuration

Edit `infrastructure/aws/terraform/terraform.tfvars`:

```hcl
# Change this line
enable_soar = true
```

### Step 2: Apply Changes

```bash
cd infrastructure/aws/terraform
terraform apply
```

### Step 3: Deploy Updated Functions

```bash
cd ../../..
bash scripts/deploy.sh --include-soar
```

### Step 4: Create Your First Playbook

Navigate to **Playbooks → Create**

**Option A: Generate from Description**

Enter:
```
When a critical alert is triggered:
1. Send notification to #security-incidents Slack channel
2. Create a Jira ticket in project SEC
```

Click "Generate Playbook"

**Option B: Use a Template**

Select "Credential Compromise Response" template

**Option C: Write YAML**

```yaml
name: Simple Alert Response
version: "1.0.0"
status: active

trigger:
  type: alert
  conditions:
    severity:
      - critical

steps:
  - id: notify
    name: Notify Security Team
    action_type: send_notification
    parameters:
      channel: "#security-incidents"
      message: |
        Alert: {{alert.rule_name}}
        Severity: {{alert.severity}}
        Time: {{alert.timestamp}}

  - id: create-ticket
    name: Create Incident Ticket
    action_type: create_ticket
    parameters:
      system: jira
      project: SEC
      title: "Security Alert: {{alert.rule_name}}"
    depends_on:
      - notify
```

### Step 5: Test the Playbook

1. Click "Test Run"
2. Enter sample alert data or select an existing alert
3. Review execution results
4. Check Slack and Jira for created items

### Step 6: Enable for Production

Toggle playbook status to "Active"

Now when a matching alert is created, the playbook will automatically execute.

---

## Verification Checklist

### SIEM

- [ ] Can access web UI
- [ ] Query page loads
- [ ] "Show me all events" returns results
- [ ] Detection rules visible in Detections page
- [ ] Test alert sent to Slack

### Observability (if enabled)

- [ ] Service Map page loads
- [ ] Services appear after sending traces
- [ ] Can click service to view traces
- [ ] APM queries work

### SOAR (if enabled)

- [ ] Playbooks page loads
- [ ] Can create new playbook
- [ ] Test execution completes
- [ ] Notifications/tickets created

---

## Common Issues

### "No data found" in queries

- Check collector is enabled and running
- Verify API credentials are correct
- Wait 5-10 minutes for initial data sync

### Service Map is empty

- Verify OTLP endpoint URL is correct
- Check application is sending traces
- Look at CloudWatch Logs for errors

### Playbook execution fails

- Check step parameters are valid
- Verify provider credentials (Jira, Slack)
- Review execution logs for specific error

---

## Next Steps

- [Full Deployment Guide](DEPLOYMENT_GUIDE.md) - Detailed configuration
- [Module Reference](MODULE_REFERENCE.md) - Technical details
- [Detection Rules](configuration/detection-rules.md) - Custom Sigma rules
- [Alert Routing](configuration/alert-routing.md) - Configure destinations
