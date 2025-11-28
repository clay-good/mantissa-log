# Getting Started with Mantissa Log

## What is Mantissa Log?

Mantissa Log is an AI-powered security log analysis platform that transforms how you monitor and investigate security events in your cloud infrastructure.

**Key Features:**

- **Natural Language Queries**: Ask questions about your logs in plain English instead of writing complex SQL queries
- **Intelligent Detection**: AI-powered detection rules that adapt and learn from your environment
- **Multi-Source Integration**: Unified view across CloudTrail, VPC Flow Logs, GuardDuty, and custom application logs
- **Smart Alerting**: Context-aware alerts with automatic enrichment and intelligent routing
- **Serverless Architecture**: Fully serverless deployment on AWS with automatic scaling
- **Cost Effective**: Pay only for what you use with optimized query execution

**Who is it for?**

- Security teams needing faster log analysis and threat detection
- DevOps teams monitoring cloud infrastructure
- Compliance teams requiring audit trail analysis
- Organizations wanting to reduce SIEM costs
- Teams looking to leverage AI for security operations

## Quick Start

### Prerequisites

Before you begin, ensure you have:

- AWS account with administrative access
- Terraform >= 1.5.0
- AWS CLI >= 2.0
- Python >= 3.11
- Git

See [Prerequisites Guide](deployment/prerequisites.md) for detailed requirements.

### One-Command Deployment

Clone the repository and run the deployment script:

```bash
git clone <repository-url>
cd mantissa-log-dev
bash scripts/deploy.sh
```

The interactive deployment wizard will guide you through configuration:

```
Environment name (dev/staging/prod) [dev]: dev
AWS Region [us-east-1]: us-east-1
LLM Provider (bedrock/anthropic/openai) [bedrock]: bedrock
Enable VPC Flow Logs ingestion? (y/n) [y]: y
Enable GuardDuty integration? (y/n) [y]: y
```

Deployment typically takes 5-10 minutes.

### Your First Query

After deployment, you can query your logs using natural language:

**Using the API:**

```bash
# Get your API endpoint from deployment outputs
API_ENDPOINT=$(cat terraform-outputs.json | jq -r '.api_endpoint.value')

# Authenticate (using Cognito credentials)
TOKEN="your-jwt-token"

# Ask a question
curl -X POST "$API_ENDPOINT/query" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Show me failed login attempts in the last 24 hours",
    "execute": true
  }'
```

**Example Queries:**

- "Show me all root account activity this week"
- "What are the most common API errors in the last hour?"
- "List all S3 bucket deletions from the past month"
- "Show me failed authentication attempts by source IP"
- "Which IAM users created new access keys recently?"

### Your First Detection Rule

Detection rules automatically scan your logs for security issues.

**1. Create a rule file:**

```bash
cat > rules/custom/suspicious-logins.yaml <<EOF
name: "Suspicious Login Pattern"
description: "Multiple failed logins followed by success"
enabled: true
severity: "high"
category: "access"

query: |
  WITH failed_attempts AS (
    SELECT
      useridentity.principalid as user,
      sourceipaddress as ip,
      COUNT(*) as failures
    FROM cloudtrail
    WHERE eventname = 'ConsoleLogin'
      AND errorcode IS NOT NULL
      AND eventtime > CURRENT_TIMESTAMP - INTERVAL '1' HOUR
    GROUP BY useridentity.principalid, sourceipaddress
    HAVING COUNT(*) >= 3
  ),
  successful_logins AS (
    SELECT
      useridentity.principalid as user,
      sourceipaddress as ip
    FROM cloudtrail
    WHERE eventname = 'ConsoleLogin'
      AND errorcode IS NULL
      AND eventtime > CURRENT_TIMESTAMP - INTERVAL '1' HOUR
  )
  SELECT
    f.user,
    f.ip,
    f.failures,
    'Multiple failed login attempts followed by success' as reason
  FROM failed_attempts f
  INNER JOIN successful_logins s
    ON f.user = s.user AND f.ip = s.ip

threshold:
  count: 1
  window: "1h"

metadata:
  mitre_attack:
    - "T1110"  # Brute Force
  tags:
    - "authentication"
    - "brute-force"
EOF
```

**2. Upload the rule:**

```bash
RULES_BUCKET=$(cat terraform-outputs.json | jq -r '.rules_bucket.value')
aws s3 cp rules/custom/suspicious-logins.yaml s3://$RULES_BUCKET/rules/custom/
```

**3. Rule executes automatically:**

The detection engine runs every 5 minutes and will automatically:
- Execute your rule against recent logs
- Generate alerts if matches are found
- Route alerts to configured destinations (Slack, PagerDuty, email)

**4. Monitor rule execution:**

```bash
# Check detection engine logs
aws logs tail /aws/lambda/mantissa-log-detection-engine --follow
```

## Key Concepts

### Log Sources

Mantissa Log ingests and analyzes logs from multiple sources:

**AWS Native Sources:**
- **CloudTrail**: AWS API activity and account events
- **VPC Flow Logs**: Network traffic metadata
- **GuardDuty**: AWS threat detection findings
- **CloudWatch Logs**: Application and service logs

**Custom Sources:**
- Application logs in JSON format
- Third-party security tools
- Custom event streams

All logs are stored in S3, cataloged in AWS Glue, and queried via Amazon Athena.

**How it works:**

1. Logs written to S3 bucket (organized by source type and date)
2. Glue crawler discovers schema and creates tables
3. Detection rules query tables using Athena
4. Natural language queries translate to SQL and execute

See [Log Sources Guide](configuration/log-sources.md) for setup details.

### Detection Rules

Detection rules are YAML files that define what to look for in your logs:

```yaml
name: "Rule Name"
description: "What this rule detects"
enabled: true
severity: "critical|high|medium|low|info"
category: "access|network|data|compliance|threat"

query: |
  SELECT ... FROM ... WHERE ...

threshold:
  count: 1          # How many matches trigger an alert
  window: "5m"      # Time window to evaluate

metadata:
  mitre_attack: ["TA0001"]
  tags: ["aws", "security"]
```

**Rule Lifecycle:**

1. Write rule YAML file
2. Upload to S3 rules bucket
3. Detection engine loads rules every cycle
4. Rule queries execute against log tables
5. Matches generate alerts
6. Alerts route to destinations

**Built-in Rules:**

Mantissa Log includes detection rules for:
- Root account usage
- IAM policy changes
- S3 bucket exposure
- Security group modifications
- Unusual API activity
- Failed authentication patterns
- Data exfiltration indicators

See [Detection Rules Guide](configuration/detection-rules.md) for creating custom rules.

### Alerts

When detection rules find matches, they generate alerts with:

**Alert Structure:**
- **Title**: Brief description of the issue
- **Severity**: critical, high, medium, low, info
- **Description**: Detailed explanation
- **Evidence**: Query results that triggered the alert
- **Context**: Enriched data (IP geolocation, related events)
- **Metadata**: Rule information, MITRE ATT&CK mappings

**Alert Enrichment:**

Alerts are automatically enriched with:
- IP geolocation data
- Threat intelligence lookups
- Related alerts from same source
- Historical context

**Alert Lifecycle:**

1. Detection rule matches log entries
2. Alert generated with details
3. Alert enriched with context
4. Alert routed to destinations
5. Alert stored in DynamoDB
6. Alert can be acknowledged/resolved via API

See [Alert Routing Guide](configuration/alert-routing.md) for configuration.

### Natural Language Queries

Instead of writing SQL, ask questions in plain English:

**How it works:**

1. You ask a question: "Show me failed logins"
2. LLM translates to SQL using your schema
3. SQL is validated for safety
4. Query executes in Athena
5. Results returned in structured format

**Session Support:**

Queries can be conversational:

```
You: "Show me CloudTrail events from the last hour"
System: [Returns SQL and results]

You: "Filter to just S3 events"
System: [Refines previous query]

You: "Group by user"
System: [Further refines query]
```

**Safety Features:**

- SQL validation prevents destructive operations
- Only SELECT queries allowed
- Table access controls enforced
- Query cost limits applied

**Supported Questions:**

- Time-based queries: "last hour", "yesterday", "this week"
- Filtering: "only errors", "from IP 1.2.3.4", "by user admin"
- Aggregations: "count by user", "top 10", "group by hour"
- Joins: "correlate with VPC flow logs"

See [LLM Configuration Guide](configuration/llm-configuration.md) for provider setup.

## Next Steps

Now that you have Mantissa Log deployed:

**1. Configure Log Sources**

Enable additional AWS log sources:
- [Configure VPC Flow Logs](configuration/log-sources.md#vpc-flow-logs)
- [Enable GuardDuty Export](configuration/log-sources.md#guardduty)
- [Add Custom Application Logs](configuration/log-sources.md#custom-logs)

**2. Set Up Alerts**

Configure where alerts should go:
- [Slack Integration](configuration/alert-routing.md#slack)
- [PagerDuty Integration](configuration/alert-routing.md#pagerduty)
- [Email Notifications](configuration/alert-routing.md#email)

**3. Customize Detection**

Review and customize detection rules:
- Browse [Built-in Rules](../rules/)
- Create [Custom Rules](configuration/detection-rules.md)
- Tune [Rule Thresholds](configuration/detection-rules.md#tuning)

**4. Explore Your Data**

Start querying your logs:
- Try [Example Queries](api/api-reference.md#example-queries)
- Use [Query Patterns](operations/runbook.md#common-queries)
- Build [Custom Dashboards](operations/runbook.md#dashboards)

**5. Operational Excellence**

Establish operational practices:
- Follow the [Operations Runbook](operations/runbook.md)
- Set up [Monitoring](operations/runbook.md#monitoring)
- Plan for [Scaling](operations/scaling.md)

## Getting Help

**Documentation:**
- [Configuration Guides](configuration/)
- [Operations Runbook](operations/runbook.md)
- [Troubleshooting Guide](deployment/troubleshooting.md)
- [API Reference](api/api-reference.md)

**Common Issues:**
- [Deployment Problems](deployment/troubleshooting.md#deployment-issues)
- [Query Errors](deployment/troubleshooting.md#runtime-issues)
- [Alert Issues](deployment/troubleshooting.md#alerts-not-being-sent)

**Support:**
- Check GitHub Issues
- Review CloudWatch Logs
- Run diagnostic commands from troubleshooting guide

## Architecture Overview

Understanding the components:

**Data Flow:**

```
Log Sources (CloudTrail, VPC Flow, etc.)
    |
    v
S3 Buckets (Organized by source/date)
    |
    v
Glue Catalog (Schema discovery)
    |
    v
Athena (SQL query engine)
    ^         ^
    |         |
Detection    Natural Language
Engine       Query Handler
    |              |
    v              v
Alerts        Results
    |
    v
Alert Router
    |
    v
Destinations (Slack, PagerDuty, Email)
```

**Components:**

- **Detection Engine Lambda**: Executes detection rules every 5 minutes
- **LLM Query Lambda**: Translates natural language to SQL
- **Alert Router Lambda**: Routes alerts to configured destinations
- **S3 Buckets**: Store logs, rules, and query results
- **DynamoDB**: Track detection state and query sessions
- **Glue Catalog**: Metadata for log tables
- **Athena**: Query execution engine
- **EventBridge**: Schedule detection cycles
- **Cognito**: User authentication
- **API Gateway**: REST API endpoints

All components are serverless and scale automatically based on load.

## Cost Management

Typical monthly costs for different scales:

**Small** (< 1M events/month): $40-105
**Medium** (1M-10M events/month): $105-360
**Large** (10M+ events/month): $360-1,600

Primary cost drivers:
- Athena: $5 per TB scanned
- S3 storage: $0.023 per GB
- Lambda executions: $0.20 per 1M requests
- DynamoDB: $1.25 per million writes

**Cost optimization tips:**

1. Use partitioning in Glue tables
2. Convert logs to Parquet format
3. Set S3 lifecycle policies
4. Tune detection frequency
5. Use Athena query result reuse
6. Monitor with CloudWatch billing alarms

See [Prerequisites Guide](deployment/prerequisites.md#cost-estimates) for detailed estimates.

## Security Considerations

Mantissa Log is designed with security in mind:

**Data Protection:**
- All S3 buckets encrypted at rest (AES-256)
- TLS 1.2+ for all API communication
- Secrets stored in AWS Secrets Manager with KMS encryption

**Access Control:**
- IAM roles for all service-to-service communication
- Cognito for user authentication
- API Gateway with JWT validation
- Least privilege Lambda execution roles

**Compliance:**
- All data stays in your AWS account
- No data sent to external services (except LLM APIs if configured)
- CloudTrail audit logs for all access
- VPC deployment option available

**Best Practices:**
- Enable MFA for Cognito users
- Rotate API keys regularly
- Review IAM policies quarterly
- Monitor CloudTrail for admin actions
- Use VPC endpoints for sensitive environments

## Frequently Asked Questions

**Q: Can I use my own LLM API key?**
A: Yes, Mantissa Log supports AWS Bedrock (no API key needed), Anthropic API, and OpenAI API. See [LLM Configuration](configuration/llm-configuration.md).

**Q: How much does this cost to run?**
A: For typical usage (< 1M events/month), expect $40-105/month. See [Cost Estimates](deployment/prerequisites.md#cost-estimates).

**Q: Can I add my own application logs?**
A: Yes, write JSON logs to S3, create a Glue table, and write detection rules. See [Custom Logs](configuration/log-sources.md#custom-logs).

**Q: How do I create custom detection rules?**
A: Write YAML files following the rule schema and upload to S3. See [Detection Rules Guide](configuration/detection-rules.md).

**Q: Is my data secure?**
A: Yes, all data stays in your AWS account with encryption at rest and in transit. See [Security Considerations](#security-considerations).

**Q: Can I deploy to multiple AWS accounts?**
A: Yes, deploy independently to each account or use cross-account log aggregation. See [Scaling Guide](operations/scaling.md#multi-account).

**Q: How do I update to the latest version?**
A: Run `bash scripts/update.sh` to pull updates and redeploy. See [Update Guide](deployment/aws-deployment.md#updating-the-deployment).

**Q: What if I want to delete everything?**
A: Run `bash scripts/destroy.sh` for complete cleanup. See [Destroy Guide](deployment/aws-deployment.md#destroying-the-deployment).
