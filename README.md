# Mantissa Log

**"Ask Questions. Get Answers. Detect Threats."**

Open-source log aggregator with a natural language query interface. Query petabytes of logs using plain English. Free forever.

## What is Mantissa Log?

Mantissa Log is a **cloud-native log aggregation platform with an AI-powered natural language query interface**. Instead of learning complex query languages or wrestling with SIEM dashboards, you simply ask questions in plain English:

- *"When was the last time root was used?"*
- *"Show me all failed logins from outside the US this week"*
- *"List all S3 buckets created in the last 24 hours"*
- *"Find abnormal API calls in CloudTrail today"*

The system translates your questions into optimized SQL, executes them across your cloud data lake, and returns results instantly. It understands follow-up questions, maintains conversation context, and shows you the exact cost of each query before running it.

**Built for any log aggregation use case, currently focused on security detections.**

### Why Mantissa Log Exists

Modern SIEM vendors charge $150,000+ annually for systems built on primitives that cloud providers offer at commodity prices: S3 storage ($0.023/GB), Athena queries ($5/TB scanned), and serverless compute (pennies per execution).

The missing piece isn't infrastructure—it's the **interface**. Writing SQL is tedious. Learning vendor query languages is painful. Dashboards go stale.

**Natural language solves this.** Ask questions the way you think. Get answers in seconds. See exactly what it costs.

While Mantissa Log excels at security monitoring (with 90+ pre-built threat detection rules), the natural language query interface works for **any log aggregation scenario**: application logs, business analytics, compliance auditing, DevOps troubleshooting, or custom data exploration.

## Cost Comparison

**Traditional SIEM (Splunk/Datadog/Sumo Logic):**
- Base platform fee: $50,000/year
- Ingestion: 1 TB/day × $150/GB = $150,000/year
- Users (5 users): $10,000/year
- **Total: ~$210,000/year**

**Mantissa Log on AWS (1 TB/day ingestion):**
- S3 storage (1 TB/day × 365 days × $0.023/GB): $8,395/year
- Athena queries (500 queries/day, avg 10GB scan × $5/TB): $9,125/year
- Lambda execution: $2,400/year
- DynamoDB: $600/year
- LLM API calls (Claude/GPT): $3,000/year
- **Total: ~$23,500/year**

**Savings: $186,500/year (89% reduction)**

## What Makes Mantissa Log Unique

### 1. Natural Language Query Interface (The Core Innovation)

The LLM isn't just a feature—it's the entire interface. Four primary use cases:

#### **Adhoc Searches**
Ask one-off questions to investigate issues, audit activity, or satisfy curiosity:

**Example queries:**
- *"When was the last time root was used?"*
- *"Show me all EC2 instances launched in prod this month"*
- *"Find all Okta logins from new devices"*
- *"List CloudTrail events with errors in the last hour"*

The system:
1. Loads your data catalog schema (Glue/BigQuery/Synapse tables)
2. Generates optimized SQL using your chosen LLM (Claude, GPT-4, Gemini, or Bedrock)
3. Validates the query is read-only and safe
4. Shows estimated cost **before execution**
5. Runs the query and returns results
6. Remembers context for follow-up questions

**Cost visibility:** Before clicking "Run", you see:
```
Estimated cost: $0.04 (scans 8.2 GB)
Monthly cost if run daily: $1.20

Optimization tip: Add date filter to reduce cost by 85%
```

#### **Routine Detections**
Convert natural language into scheduled detection rules:

**Example:**
- *"Alert me anytime someone disables CloudTrail logging"*
- *"Notify me when root account is used"*
- *"Detect failed login attempts from >5 different IPs for the same user"*

The system:
1. Generates SQL from your natural language description
2. Shows projected **monthly cost** based on query frequency and historical data scanned
3. Creates a scheduled rule (EventBridge/Cloud Scheduler) to run every N minutes
4. Routes alerts to Slack/PagerDuty/Email/Jira when threshold is met
5. Uses deduplication to prevent alert spam

**Cost projection example:**
```
Detection: "Alert on abnormal API calls in CloudTrail"
Schedule: Every 15 minutes
Estimated monthly cost: $23.50
  - Athena queries: $18.20 (364 queries/month, ~50GB avg scan)
  - Lambda execution: $4.30
  - DynamoDB writes: $1.00

Reduce cost by 70%: Add partition filters for last 15 min
```

#### **Routine Detections with Context Enrichment**
Every alert sent to Slack/Jira/PagerDuty is enriched with **LLM-generated context**:

**Example alert (Slack):**
```
Detection: Abnormal CloudTrail API Calls

WHO: arn:aws:iam::123456789012:user/john.doe
WHAT: 47 API calls to sensitive IAM actions in 5 minutes
WHEN: 2024-01-15 14:23:17 UTC
WHERE: us-east-1 from IP 203.0.113.45 (external)
WHY: Potential privilege escalation or reconnaissance activity
HOW: User called iam:PutUserPolicy, iam:CreateAccessKey, iam:AttachUserPolicy

Behavioral Context:
- This user typically makes 2-3 IAM API calls per day
- This is 15x higher than their 30-day baseline
- External IP address has never been seen before
- API calls occurred outside normal working hours (2 AM local time)

MITRE ATT&CK: T1098 (Account Manipulation)

🔍 Recommended Actions:
1. Contact user John Doe to verify this activity
2. Review created access keys in IAM console
3. Check for new policies attached to user/roles
4. Audit CloudTrail for associated API calls from same IP
5. Consider rotating user credentials if unauthorized

Raw events: [View in Athena](https://console.aws.amazon.com/athena/...)
```

The **5W1H summary**, behavioral analysis, and recommended actions are all LLM-generated based on the raw event data and 30-day historical baseline.

**This enrichment happens automatically for every detection.** You don't write prompts or configure it—just enable the detection rule.

#### **Detection Engineering Automation** (Coming Soon)
The system runs weekly analysis of all enabled Sigma rules and suggests tuning improvements:

- Analyzes historical false positives vs true positives
- Identifies noisy rules that need refinement
- Suggests threshold adjustments or additional filters
- Creates Jira tickets with HIGH CONFIDENCE tuning recommendations
- Learns from ticket resolution (accept/reject) to improve future suggestions

**Example Jira ticket:**
```
Title: [Detection Tuning] Reduce FPs for "AWS CloudTrail Disabled"

Analysis Period: Last 7 days
False Positives: 23
True Positives: 0

Recommendation: Add exclusion for service account "terraform-deployer"

Suggested SQL change:
+ WHERE user_identity_principalid NOT LIKE '%terraform-deployer%'

Confidence: HIGH
Expected FP reduction: 95%
```

### 2. True Multi-Cloud Support

Write detection rules **once** using Sigma format. They auto-convert to work on:
- **AWS**: Athena SQL for S3 data lakes
- **GCP**: BigQuery SQL for Cloud Storage
- **Azure**: Synapse T-SQL for Blob Storage

**Same rule, three clouds:**
```yaml
title: Root Account Usage
detection:
  selection:
    userIdentity.type: Root
  condition: selection
```

Mantissa Log automatically converts this to the correct SQL dialect for your chosen cloud provider.

### 3. Comprehensive Log Source Support

While focused on **security detections**, Mantissa Log ingests logs from any JSON/CSV source:

| Category | Sources |
|----------|---------|
| **Cloud Providers** | AWS CloudTrail, VPC Flow Logs, GuardDuty, GCP Audit Logs, Azure Activity Logs |
| **Identity** | Okta, Google Workspace, Microsoft 365 / Azure AD, Duo Security |
| **Endpoints** | CrowdStrike Falcon, Jamf Pro |
| **Collaboration** | Slack Audit Logs, Microsoft Teams |
| **SaaS Data** | Snowflake, Salesforce |
| **DevOps** | GitHub Enterprise, GitLab, Kubernetes Audit Logs |
| **Containers** | Docker, containerd |

**Custom parsers:** Add your own log sources by creating a simple Python parser class.

### 4. Cost Transparency

Most SIEMs hide costs behind opaque per-GB ingestion pricing. Mantissa Log shows **exactly** what you'll pay:

**Query cost calculation:**
```
Cost = (Data Scanned in GB / 1000) × $5.00

Example:
- Query scans 8.2 GB
- Cost = (8.2 / 1000) × $5 = $0.041
```

**Detection cost projection:**
```
Monthly Cost = (Avg GB per execution) × (Executions per month) × $0.005
             + Lambda execution cost
             + DynamoDB write cost

Example: "Alert on failed logins" (runs every 15 min)
- Avg data scanned: 0.5 GB
- Executions per month: 2,880 (4 per hour × 24 × 30)
- Query cost: 0.5 × 2,880 × $0.005 = $7.20/month
- Lambda cost: $2.30/month
- DynamoDB cost: $0.50/month
- Total: ~$10/month
```

The system shows these projections **before you create the detection**, with optimization suggestions to reduce costs by 70-90%.

## Quick Demo: Ingest Logs and Ask Questions

The fastest way to see Mantissa Log in action:

### Step 1: Deploy Infrastructure (10 minutes)

```bash
git clone https://github.com/your-org/mantissa-log.git
cd mantissa-log
bash scripts/deploy.sh
```

This deploys:
- S3 bucket for log storage (partitioned by date/hour)
- Glue Data Catalog for schema metadata
- Athena for SQL queries
- Lambda functions for API and detections
- DynamoDB for state management
- CloudFront + S3 for web interface

### Step 2: Ingest Sample Logs

**Option A: Enable CloudTrail (automatic)**
The deployment script configures CloudTrail to send logs to your Mantissa Log S3 bucket. You'll have queryable data within 15 minutes.

**Option B: Ingest existing logs from other sources**

**Okta logs:**
```bash
# Configure Okta API token in Secrets Manager
aws secretsmanager put-secret-value \
  --secret-id mantissa-log/okta-token \
  --secret-string "your-okta-api-token"

# Run the Okta collector Lambda
aws lambda invoke \
  --function-name mantissa-log-okta-collector \
  --payload '{"start_date": "2024-01-01", "end_date": "2024-01-31"}' \
  response.json
```

**Google Workspace logs:**
```bash
# Configure Google service account in Secrets Manager
aws secretsmanager put-secret-value \
  --secret-id mantissa-log/google-workspace-creds \
  --secret-string file://service-account.json

# Run the Google Workspace collector
aws lambda invoke \
  --function-name mantissa-log-google-workspace-collector \
  --payload '{"days_back": 7}' \
  response.json
```

**CloudTrail (if you have existing logs in S3):**
```bash
# Copy existing CloudTrail logs to Mantissa Log bucket
aws s3 sync \
  s3://your-cloudtrail-bucket/AWSLogs/123456789012/CloudTrail/us-east-1/ \
  s3://mantissa-log-your-deployment/cloudtrail/ \
  --exclude "*" --include "*.json.gz"

# Update Glue catalog to recognize new partitions
aws glue start-crawler --name mantissa-log-cloudtrail-crawler
```

### Step 3: Configure LLM Provider

Open the web interface (CloudFront URL from deployment output) and configure your LLM:

**Settings > LLM Configuration**

Choose one:
- **AWS Bedrock** (no API key needed—uses IAM role)
  - Model: `anthropic.claude-3-5-sonnet-20241022-v2:0`
- **Anthropic Claude** (requires API key)
  - Model: `claude-3-5-sonnet-20241022`
  - API Key: `sk-ant-...`
- **OpenAI GPT** (requires API key)
  - Model: `gpt-4-turbo`
  - API Key: `sk-...`
- **Google Gemini** (requires API key)
  - Model: `gemini-1.5-pro`
  - API Key: `AIza...`

### Step 4: Ask Questions

**Query Interface > New Query**

Try these example queries:

**Example 1: "When was the last time root was used?"**
```
🔍 Generated SQL:
SELECT
  eventtime,
  useridentity_principalid,
  eventname,
  sourceipaddress,
  awsregion
FROM cloudtrail
WHERE useridentity_type = 'Root'
ORDER BY eventtime DESC
LIMIT 10

Estimated cost: $0.03 (scans 6.1 GB)

▶ Run Query
```

Click "Run Query" to see results:
```
| Event Time           | Principal ID | Event Name      | Source IP      | Region    |
|---------------------|--------------|-----------------|----------------|-----------|
| 2024-01-15 14:23:17 | root         | ConsoleLogin    | 203.0.113.45   | us-east-1 |
```

**Example 2: "Show me all failed logins in the last 24 hours"**

The system understands context from previous queries and can access multiple log sources (CloudTrail, Okta, Google Workspace, etc.):

```
Generated SQL:
SELECT
  event_time,
  user_identity_username,
  source_ip,
  user_agent,
  failure_reason
FROM (
  SELECT eventtime as event_time,
         useridentity_username,
         sourceipaddress as source_ip,
         useragent as user_agent,
         errormessage as failure_reason
  FROM cloudtrail
  WHERE errorcode IS NOT NULL
    AND eventname IN ('ConsoleLogin', 'GetSigninToken')
    AND eventtime >= current_timestamp - interval '24' hour
  UNION ALL
  SELECT published as event_time,
         actor_alternate_id as user_identity_username,
         client_ip as source_ip,
         client_user_agent as user_agent,
         outcome_reason as failure_reason
  FROM okta_logs
  WHERE outcome_result = 'FAILURE'
    AND event_type LIKE '%authentication%'
    AND published >= current_timestamp - interval '24' hour
)
ORDER BY event_time DESC
LIMIT 100

Estimated cost: $0.08 (scans 16.4 GB)

Optimization: Add partition filter to reduce cost by 82%:
   WHERE year = 2024 AND month = 1 AND day = 15

▶ Run Query
```

**Example 3: Follow-up question: "How many were from outside the US?"**

Mantissa Log remembers your conversation context:
```
🔍 Generated SQL (using previous query as subquery):
SELECT COUNT(*) as failed_login_count
FROM (
  [previous query]
)
WHERE source_ip NOT IN (
  SELECT ip_address FROM ip_geolocation WHERE country_code = 'US'
)

Estimated cost: $0.09 (scans 18.1 GB + geolocation table)

▶ Run Query
```

### Step 5: Create a Detection Rule

**Rules > Create Detection**

**Natural language input:**
*"Alert me anytime there are abnormal API calls in CloudTrail"*

System response:
```
Generated Detection SQL:
WITH baseline AS (
  SELECT
    useridentity_principalid,
    COUNT(*) as avg_daily_calls
  FROM cloudtrail
  WHERE eventtime >= current_timestamp - interval '30' day
  GROUP BY useridentity_principalid
),
recent_activity AS (
  SELECT
    useridentity_principalid,
    COUNT(*) as recent_calls
  FROM cloudtrail
  WHERE eventtime >= current_timestamp - interval '1' hour
  GROUP BY useridentity_principalid
)
SELECT
  r.useridentity_principalid,
  r.recent_calls,
  b.avg_daily_calls / 24 as avg_hourly_calls,
  r.recent_calls / (b.avg_daily_calls / 24) as deviation_ratio
FROM recent_activity r
JOIN baseline b ON r.useridentity_principalid = b.useridentity_principalid
WHERE r.recent_calls > (b.avg_daily_calls / 24) * 5  -- 5x deviation
ORDER BY deviation_ratio DESC

Projected Monthly Cost (runs every 15 minutes):
- Athena queries: $24.30 (2,880 queries × ~8.4 GB avg scan)
- Lambda execution: $5.20
- DynamoDB writes: $1.50
- Total: ~$31/month

Optimization suggestions:
1. Add partition filter for last 1 hour: Saves $17/month (70% reduction)
2. Reduce query frequency to 30 min: Saves $12/month (50% reduction)
3. Use incremental baseline (weekly vs daily): Saves $6/month (25% reduction)

Recommended optimized cost: ~$8/month

Schedule: Every 15 minutes
Alert threshold: Any match (deviation_ratio > 5)
Route to: Slack #security-alerts
Enable context enrichment: ✓ Yes (adds $2/month for LLM API calls)

Save Detection
```

When this detection fires, the alert sent to Slack includes:
- **5W1H summary** (who, what, when, where, why, how)
- **Behavioral context** (comparison to 30-day baseline)
- **MITRE ATT&CK mapping** (if applicable)
- **Recommended investigation steps**

All generated by the LLM automatically.

## Architecture

```
                    +------------------+
                    |   Web Interface  |
                    |   (React + Vite) |
                    +--------+---------+
                             |
                    +--------v---------+
                    |   API Gateway    |
                    +--------+---------+
                             |
         +-------------------+-------------------+
         |                   |                   |
+--------v--------+ +--------v--------+ +--------v--------+
|  LLM Query      | |  Detection      | |  Alert Router   |
|  Handler        | |  Engine         | |  + Enrichment   |
|                 | |                 | |                 |
| - NL to SQL     | | - Sigma Rules   | | - LLM Enricher  |
| - Conversation  | | - Multi-Cloud   | | - PII Redaction |
| - Cost Estimate | | - Scheduling    | | - Integrations  |
| - SQL Validator | | - Deduplication | | - 5W1H Context  |
+-----------------+ +-----------------+ +-----------------+
         |                   |                   |
         +-------------------+-------------------+
                             |
              +--------------v--------------+
              |        Query Executor       |
              |  (Athena / BigQuery / Synapse)
              +--------------+--------------+
                             |
              +--------------v--------------+
              |     Data Lake (S3 / GCS)    |
              |   Partitioned by date/hour  |
              |      Parquet/JSON.gz        |
              +-----------------------------+
```

### How Natural Language Queries Work

1. **User asks question** in web interface
2. **Schema context loaded**: System fetches Glue Data Catalog (or BigQuery/Synapse metadata) to understand available tables, columns, and data types
3. **Prompt built**: Question + schema context + conversation history (last 10 messages) sent to LLM
4. **LLM generates SQL**: Returns optimized query with JOINs, aggregations, filters
5. **SQL validation**:
   - Blocks unsafe operations (INSERT, UPDATE, DELETE, DROP, etc.)
   - Auto-applies LIMIT clause (max 10,000 rows)
   - Validates table names against allowlist
   - Checks max subquery depth (3 levels)
6. **Cost estimation**: Calculates data scanned based on partition filters and historical query stats
7. **User reviews**: Sees generated SQL, estimated cost, and optimization suggestions
8. **Query execution**: Athena/BigQuery/Synapse runs the query (120s timeout)
9. **Results cached**: Stored for 24 hours to avoid redundant LLM calls
10. **Conversation stored**: DynamoDB saves session for follow-up questions

**Retry logic:** If SQL validation fails, error message is sent back to LLM with request to fix (up to 3 retry attempts).

## Detection Rule Coverage

Mantissa Log includes **90+ pre-built Sigma rules** covering MITRE ATT&CK techniques:

| MITRE Tactic | Example Rules |
|--------------|---------------|
| **Initial Access** | Brute force login attempts, SSO abuse, SAML token manipulation |
| **Execution** | Lambda function invoked with untrusted code, container exec into pod |
| **Persistence** | IAM user created with console access, login profile added to role |
| **Privilege Escalation** | AssumeRole to admin role, IAM policy modified to grant wildcards |
| **Defense Evasion** | CloudTrail logging disabled, GuardDuty detector deleted, Config recorder stopped |
| **Credential Access** | IAM access key created, credentials exposed in CloudTrail errors |
| **Discovery** | S3 bucket enumeration, Secrets Manager list secrets, VPC describe calls |
| **Lateral Movement** | Cross-account AssumeRole, VPN tunnel created to untrusted network |
| **Collection** | S3 GetObject on sensitive buckets, RDS snapshot exported |
| **Exfiltration** | Large S3 data transfer to external IP, unusual outbound VPC traffic |
| **Impact** | S3 bucket encryption disabled, RDS instance deleted, ransomware file extensions |

**All rules are customizable** and can be tuned via the web interface.

## What Mantissa Log Is NOT

Mantissa Log is intentionally focused on log aggregation and natural language queries. It does **NOT** include:

- **Dashboards or Visualizations**: Use adhoc NL queries to answer questions on-demand instead of building stale dashboards
- **Case Management**: Alerts create tickets in Jira/ServiceNow; manage investigations there
- **SOAR/Automated Remediation**: No automated blocking, policy changes, or infrastructure modifications (use dedicated SOAR tools if needed)
- **Threat Intelligence Platform**: Integrate with existing TI feeds via log ingestion, but Mantissa Log doesn't maintain its own threat intel database
- **On-Prem Log Collection**: Focus is exclusively on cloud-native and SaaS log sources

## Target Users

- **Security teams at startups/mid-size companies** who can't afford $150k+ annual SIEM contracts
- **Detection engineers** who want to prototype rules without worrying about per-GB ingestion costs
- **Security practitioners** who value transparency and want to understand their security tools
- **DevOps/SRE teams** who need queryable log aggregation for troubleshooting and auditing
- **Compliance teams** who need to demonstrate log retention and analysis capabilities
- **Anyone aggregating logs** who wants a natural language interface instead of learning complex query languages

## Deployment Options

### AWS (Recommended)
- **Storage**: S3 (partitioned by date/hour)
- **Query Engine**: Athena
- **Compute**: Lambda
- **Metadata**: Glue Data Catalog
- **Scheduling**: EventBridge
- **State**: DynamoDB
- **Web Hosting**: CloudFront + S3

**Deployment time:** 10-15 minutes

```bash
git clone https://github.com/your-org/mantissa-log.git
cd mantissa-log
bash scripts/deploy.sh
```

See [AWS Deployment Guide](docs/deployment/aws-deployment.md)

### GCP
- **Storage**: Cloud Storage
- **Query Engine**: BigQuery
- **Compute**: Cloud Functions
- **Scheduling**: Cloud Scheduler
- **State**: Firestore
- **Web Hosting**: Cloud Run

See [GCP Deployment Guide](docs/deployment/gcp-deployment.md)

### Azure
- **Storage**: Blob Storage
- **Query Engine**: Synapse Analytics
- **Compute**: Azure Functions
- **Scheduling**: Logic Apps
- **State**: Cosmos DB
- **Web Hosting**: Static Web Apps

See [Azure Deployment Guide](docs/deployment/azure-deployment.md)

## Documentation

- [Getting Started Guide](docs/getting-started.md)
- [AWS Deployment](docs/deployment/aws-deployment.md)
- [GCP Deployment](docs/deployment/gcp-deployment.md)
- [Azure Deployment](docs/deployment/azure-deployment.md)
- [Writing Sigma Rules](docs/configuration/sigma-rules.md)
- [Natural Language Query Examples](docs/tutorials/query-examples.md)
- [Alert Routing Configuration](docs/configuration/alert-routing.md)
- [LLM Provider Setup](docs/configuration/llm-configuration.md)
- [API Reference](docs/api/api-reference.md)
- [Cost Optimization](docs/operations/cost-optimization.md)
- [Contributing Guide](docs/development/contributing.md)
