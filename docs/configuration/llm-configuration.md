# LLM Configuration Guide

This guide covers configuring LLM providers for natural language query capabilities.

## Overview

Mantissa Log uses Large Language Models (LLMs) to translate natural language questions into SQL queries. Three providers are supported:

- **AWS Bedrock** (recommended): No API key needed, pay-per-use
- **Anthropic API**: Claude models via Anthropic's API
- **OpenAI API**: GPT models via OpenAI's API

## Choosing an LLM Provider

### AWS Bedrock

**Advantages:**
- No API keys to manage
- Integrated with AWS IAM
- Data stays within AWS
- Competitive pricing
- Lower latency (same region)

**Requirements:**
- Bedrock available in deployment region
- Model access enabled

**Best for:**
- AWS-native deployments
- Security-conscious organizations
- Simplified credential management

**Cost:** $0.003 per 1K input tokens, $0.015 per 1K output tokens (Claude 3 Haiku)

### Anthropic API

**Advantages:**
- Latest Claude models
- Higher rate limits
- More model options

**Requirements:**
- Anthropic API account
- API key

**Best for:**
- Latest model features
- High query volumes
- Multi-cloud deployments

**Cost:** $0.25 per 1M input tokens, $1.25 per 1M output tokens (Claude 3 Haiku)

### OpenAI API

**Advantages:**
- GPT-4 Turbo available
- Large context windows
- Familiar API

**Requirements:**
- OpenAI API account
- API key

**Best for:**
- Existing OpenAI integrations
- GPT-4 requirements

**Cost:** $0.01 per 1K input tokens, $0.03 per 1K output tokens (GPT-3.5 Turbo)

## Cost Comparison

Assuming 1,000 queries per month, average 500 input tokens + 200 output tokens per query:

**AWS Bedrock (Claude 3 Haiku):**
- Input: 500K tokens × $0.003/1K = $1.50
- Output: 200K tokens × $0.015/1K = $3.00
- **Total: $4.50/month**

**Anthropic API (Claude 3 Haiku):**
- Input: 500K tokens × $0.25/1M = $0.13
- Output: 200K tokens × $1.25/1M = $0.25
- **Total: $0.38/month**

**OpenAI (GPT-3.5 Turbo):**
- Input: 500K tokens × $0.01/1K = $5.00
- Output: 200K tokens × $0.03/1K = $6.00
- **Total: $11.00/month**

## AWS Bedrock Configuration

### Enable Bedrock

1. Navigate to AWS Bedrock console
2. Go to "Model access"
3. Click "Manage model access"
4. Enable models:
   - Anthropic Claude 3 Haiku (recommended)
   - Anthropic Claude 3 Sonnet (higher quality)
5. Submit request

**Access is usually granted instantly.**

### Verify Model Access

```bash
aws bedrock list-foundation-models --region us-east-1 \
  --query 'modelSummaries[?contains(modelId, `claude`)].modelId'
```

Expected output:
```json
[
    "anthropic.claude-3-haiku-20240307-v1:0",
    "anthropic.claude-3-sonnet-20240229-v1:0"
]
```

### Configure in Terraform

Edit `infrastructure/aws/terraform/environments/prod.tfvars`:

```hcl
llm_provider = "bedrock"
llm_model = "anthropic.claude-3-haiku-20240307-v1:0"
llm_region = "us-east-1"  # Same as deployment region
```

### Update Deployment

```bash
cd infrastructure/aws/terraform
terraform apply -var-file=environments/prod.tfvars
```

### IAM Permissions

The Lambda execution role needs Bedrock permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": [
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"
      ]
    }
  ]
}
```

This is automatically configured by Terraform.

### Test Bedrock

```bash
aws bedrock-runtime invoke-model \
  --model-id anthropic.claude-3-haiku-20240307-v1:0 \
  --body '{
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 100,
    "messages": [{
      "role": "user",
      "content": "Write SQL to select all from cloudtrail"
    }]
  }' \
  --region us-east-1 \
  output.json

cat output.json
```

## Anthropic API Configuration

### Get API Key

1. Sign up at https://console.anthropic.com
2. Go to API Keys section
3. Click "Create Key"
4. Copy the API key

### Store API Key

```bash
aws secretsmanager create-secret \
  --name mantissa-log/llm/anthropic-api-key \
  --secret-string '{
    "api_key": "sk-ant-api03-your-api-key-here"
  }' \
  --region us-east-1
```

### Configure in Terraform

Edit `infrastructure/aws/terraform/environments/prod.tfvars`:

```hcl
llm_provider = "anthropic"
llm_model = "claude-3-haiku-20240307"
llm_api_key_secret = "mantissa-log/llm/anthropic-api-key"
```

### Update Deployment

```bash
cd infrastructure/aws/terraform
terraform apply -var-file=environments/prod.tfvars
```

### Test Anthropic API

```bash
API_KEY=$(aws secretsmanager get-secret-value \
  --secret-id mantissa-log/llm/anthropic-api-key \
  --query SecretString --output text | jq -r '.api_key')

curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{
    "model": "claude-3-haiku-20240307",
    "max_tokens": 100,
    "messages": [{
      "role": "user",
      "content": "Write SQL to select all from cloudtrail"
    }]
  }'
```

## OpenAI API Configuration

### Get API Key

1. Sign up at https://platform.openai.com
2. Go to API keys
3. Click "Create new secret key"
4. Copy the key

### Store API Key

```bash
aws secretsmanager create-secret \
  --name mantissa-log/llm/openai-api-key \
  --secret-string '{
    "api_key": "sk-your-openai-api-key-here"
  }' \
  --region us-east-1
```

### Configure in Terraform

Edit `infrastructure/aws/terraform/environments/prod.tfvars`:

```hcl
llm_provider = "openai"
llm_model = "gpt-3.5-turbo"
llm_api_key_secret = "mantissa-log/llm/openai-api-key"
```

### Update Deployment

```bash
cd infrastructure/aws/terraform
terraform apply -var-file=environments/prod.tfvars
```

### Test OpenAI API

```bash
API_KEY=$(aws secretsmanager get-secret-value \
  --secret-id mantissa-log/llm/openai-api-key \
  --query SecretString --output text | jq -r '.api_key')

curl https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [{
      "role": "user",
      "content": "Write SQL to select all from cloudtrail"
    }],
    "max_tokens": 100
  }'
```

## Model Selection

### Recommended Models

**For most use cases:**
- Bedrock: `anthropic.claude-3-haiku-20240307-v1:0`
- Anthropic: `claude-3-haiku-20240307`
- OpenAI: `gpt-3.5-turbo`

**For complex queries:**
- Bedrock: `anthropic.claude-3-sonnet-20240229-v1:0`
- Anthropic: `claude-3-sonnet-20240229`
- OpenAI: `gpt-4-turbo-preview`

**For highest accuracy:**
- Bedrock: `anthropic.claude-3-opus-20240229-v1:0`
- Anthropic: `claude-3-opus-20240229`
- OpenAI: `gpt-4`

### Model Comparison

| Model | Speed | Quality | Cost | Context Window |
|-------|-------|---------|------|----------------|
| Claude 3 Haiku | Fast | Good | Low | 200K |
| Claude 3 Sonnet | Medium | Better | Medium | 200K |
| Claude 3 Opus | Slow | Best | High | 200K |
| GPT-3.5 Turbo | Fast | Good | Medium | 16K |
| GPT-4 Turbo | Medium | Better | High | 128K |

## Advanced Configuration

### Query Generation Parameters

Configure LLM query generation in Lambda environment:

```bash
aws lambda update-function-configuration \
  --function-name mantissa-log-llm-query \
  --environment Variables='{
    "LLM_PROVIDER": "bedrock",
    "LLM_MODEL": "anthropic.claude-3-haiku-20240307-v1:0",
    "MAX_TOKENS": "1000",
    "TEMPERATURE": "0.0",
    "MAX_RETRIES": "3",
    "ENABLE_QUERY_VALIDATION": "true",
    "ENABLE_SQL_EXPLANATION": "true"
  }'
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| LLM_PROVIDER | bedrock, anthropic, or openai | bedrock |
| LLM_MODEL | Model identifier | (provider default) |
| MAX_TOKENS | Maximum output tokens | 1000 |
| TEMPERATURE | LLM temperature (0.0-1.0) | 0.0 |
| MAX_RETRIES | Query generation retries | 3 |
| ENABLE_QUERY_VALIDATION | Validate SQL safety | true |
| ENABLE_SQL_EXPLANATION | Generate query explanations | true |

### Temperature Settings

- **0.0**: Deterministic, same query every time (recommended)
- **0.3**: Slight variation, still consistent
- **0.7**: More creative, less consistent
- **1.0**: Maximum creativity, unpredictable

For SQL generation, use **0.0** for consistency.

### Context Window Management

Large schemas may exceed context limits. Configure schema context:

```python
# In src/shared/llm/schema_context.py
schema_context = SchemaContext(
    glue_client=glue,
    database_name=database,
    max_tables=10,  # Limit tables in context
    max_columns_per_table=20,  # Limit columns per table
    include_sample_data=False  # Exclude samples to save tokens
)
```

## Monitoring LLM Usage

### Track API Calls

```bash
# CloudWatch metrics for LLM query Lambda
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=mantissa-log-llm-query \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 86400 \
  --statistics Sum
```

### Monitor Costs

**Bedrock:**
```bash
# Cost Explorer API
aws ce get-cost-and-usage \
  --time-period Start=2024-01-01,End=2024-01-31 \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --filter '{"Dimensions":{"Key":"SERVICE","Values":["Amazon Bedrock"]}}'
```

**External APIs:**
- Check provider dashboard (Anthropic Console, OpenAI Usage)
- Set up billing alerts
- Monitor API key usage

### Query Performance

```bash
# Check query latency
aws logs filter-log-events \
  --log-group-name /aws/lambda/mantissa-log-llm-query \
  --filter-pattern "[time, request_id, level, latency, ...]" \
  --start-time $(($(date +%s) - 3600))000 \
  | jq '.events[].message' | grep "latency"
```

## Cost Optimization

### Use Haiku Models

Claude 3 Haiku is 10x cheaper than Sonnet with good quality:

```hcl
llm_model = "anthropic.claude-3-haiku-20240307-v1:0"
```

### Enable Query Caching

Cache common queries to avoid LLM calls:

```python
# In Lambda function
from functools import lru_cache

@lru_cache(maxsize=100)
def generate_query_cached(question):
    return query_generator.generate_query(question)
```

### Limit Context Size

Reduce tokens sent to LLM:

```python
schema_context = SchemaContext(
    max_tables=5,  # Only most relevant tables
    max_columns_per_table=10,
    include_sample_data=False
)
```

### Set Token Limits

```bash
MAX_TOKENS="500"  # Reduce from 1000
```

### Use Streaming for Long Responses

For real-time feedback without waiting for full response:

```python
# Stream responses to reduce perceived latency
response_stream = bedrock.invoke_model_with_response_stream(
    modelId=model_id,
    body=json.dumps(request_body)
)
```

## Troubleshooting

### Bedrock Access Denied

**Error:** "AccessDeniedException"

**Solution:**
1. Check model access is enabled
2. Verify IAM permissions
3. Ensure correct region

```bash
# Check model access
aws bedrock list-foundation-models --region us-east-1

# Check Lambda role
aws iam get-role-policy \
  --role-name mantissa-log-llm-query-role \
  --policy-name BedrockAccess
```

### API Key Invalid

**Error:** "Invalid API key"

**Solution:**
1. Verify secret exists
2. Check key format
3. Test key manually

```bash
# Check secret
aws secretsmanager get-secret-value \
  --secret-id mantissa-log/llm/anthropic-api-key

# Test key
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: YOUR_KEY" \
  -H "anthropic-version: 2023-06-01" \
  --data '{"model":"claude-3-haiku-20240307","max_tokens":10,"messages":[{"role":"user","content":"test"}]}'
```

### Rate Limiting

**Error:** "Rate limit exceeded"

**Solution:**
1. Implement backoff/retry
2. Upgrade API plan
3. Reduce query frequency

```python
# Add exponential backoff
import time
from anthropic import RateLimitError

max_retries = 3
for attempt in range(max_retries):
    try:
        response = client.generate(...)
        break
    except RateLimitError:
        if attempt < max_retries - 1:
            time.sleep(2 ** attempt)
        else:
            raise
```

### High Latency

**Symptoms:** Queries taking > 10 seconds

**Solutions:**
1. Use faster model (Haiku instead of Sonnet)
2. Reduce context size
3. Use same region as deployment
4. Enable streaming responses

```bash
# Check latency
aws logs tail /aws/lambda/mantissa-log-llm-query --since 10m \
  | grep "generation_time"
```

### Poor Query Quality

**Symptoms:** Generated SQL is incorrect or doesn't match intent

**Solutions:**
1. Improve schema documentation
2. Add example queries to context
3. Use higher quality model (Sonnet/Opus)
4. Enable query explanations

```python
# Add examples to schema context
schema_context = SchemaContext(
    glue_client=glue,
    database_name=database,
    example_queries=[
        {
            "question": "Show failed logins",
            "sql": "SELECT * FROM cloudtrail WHERE eventname='ConsoleLogin' AND errorcode IS NOT NULL"
        }
    ]
)
```

## Security Considerations

### API Key Protection

- Store in Secrets Manager with encryption
- Rotate keys regularly
- Use IAM policies to restrict access
- Enable CloudTrail logging for secret access

### Data Privacy

**Bedrock:**
- Data stays in AWS
- No training on your data
- Encrypted in transit and at rest

**External APIs:**
- Data sent to third-party
- Check provider data retention policies
- Consider data sensitivity

### Network Security

**For Bedrock:**
- Uses VPC endpoints (optional)
- No internet access required

**For external APIs:**
- Requires internet access
- Use NAT Gateway or VPC endpoints
- Monitor outbound traffic

### Compliance

- GDPR: Check provider compliance
- HIPAA: Bedrock is HIPAA eligible
- PCI DSS: Evaluate data flows
- SOC 2: Review provider certifications
