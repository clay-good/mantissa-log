# AWS Terraform Deployment

Terraform configuration for deploying Mantissa Log to AWS.

## Prerequisites

- AWS CLI v2 configured with appropriate credentials
- Terraform 1.5 or higher
- Sufficient AWS permissions to create resources
- S3 bucket for Terraform state (recommended for production)

## Quick Start

```bash
# Initialize Terraform
terraform init

# Review the deployment plan
terraform plan -var-file=environments/dev.tfvars

# Deploy infrastructure
terraform apply -var-file=environments/dev.tfvars

# Destroy infrastructure (when needed)
terraform destroy -var-file=environments/dev.tfvars
```

## Architecture

The Terraform configuration is organized into modules:

- **storage**: S3 buckets for log storage with lifecycle policies
- **ingestion**: Log routing from AWS services to S3
- **catalog**: Glue Data Catalog for schema management
- **compute**: Lambda functions for detection and API
- **scheduling**: EventBridge rules for triggering detection
- **api**: API Gateway for web interface
- **auth**: Cognito for user authentication
- **secrets**: Secrets Manager for credentials
- **monitoring**: CloudWatch for logs and metrics

## Configuration

### Environment Files

- **environments/dev.tfvars**: Development environment settings
- **environments/prod.tfvars.example**: Production template (copy and customize)

### Key Variables

```hcl
aws_region          = "us-east-1"
environment         = "dev"
project_prefix      = "mantissa-log"
log_retention_days  = 365
enable_guardduty    = true
enable_cloudtrail   = true
```

See `variables.tf` for all available configuration options.

### Backend Configuration

For production, use S3 backend for state management:

```bash
# Copy example backend config
cp backend.tf.example backend.tf

# Edit with your bucket name
vim backend.tf
```

Example backend.tf:
```hcl
terraform {
  backend "s3" {
    bucket         = "your-terraform-state-bucket"
    key            = "mantissa-log/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}
```

## Modules

Each module is self-contained with:

- **main.tf**: Resource definitions
- **variables.tf**: Input variables
- **outputs.tf**: Output values
- **README.md**: Module documentation

### Storage Module

Creates:
- S3 bucket for raw logs (partitioned by date)
- Lifecycle policies (hot/warm/cold tiers)
- Bucket encryption and access logging
- S3 bucket for Athena query results

### Compute Module

Creates:
- Lambda functions for detection engine
- Lambda functions for LLM query processing
- Lambda functions for alert routing
- Lambda function for API endpoints
- IAM roles with least-privilege permissions

### Catalog Module

Creates:
- Glue database
- Glue tables for each log source
- Glue views for normalized data
- Glue crawlers (optional)

## Deployment Process

### 1. Initial Setup

```bash
# Clone repository
git clone https://github.com/clay-good/mantissa-log.git
cd mantissa-log/infrastructure/aws/terraform

# Initialize Terraform
terraform init
```

### 2. Customize Configuration

```bash
# Copy environment template
cp environments/dev.tfvars my-environment.tfvars

# Edit configuration
vim my-environment.tfvars
```

### 3. Review Plan

```bash
# Generate and review execution plan
terraform plan -var-file=my-environment.tfvars -out=tfplan

# Review planned changes carefully
```

### 4. Deploy

```bash
# Apply the plan
terraform apply tfplan
```

### 5. Verify Deployment

```bash
# Check outputs
terraform output

# Test API endpoint
curl $(terraform output -raw api_endpoint)/health

# Check S3 bucket
aws s3 ls $(terraform output -raw log_bucket_name)
```

## Outputs

After deployment, Terraform outputs:

- S3 bucket names
- API Gateway endpoint URL
- Cognito user pool ID and client ID
- Lambda function ARNs
- Athena workgroup name

Save these values for configuring the web interface and detection rules.

## Cost Optimization

To minimize costs:

1. Adjust `log_retention_days` based on requirements
2. Use S3 Intelligent-Tiering for automatic cost optimization
3. Set appropriate EventBridge schedule for detection rules
4. Monitor Lambda concurrency and memory settings
5. Use Athena query result caching

Estimated costs for 100GB/day of logs:
- S3 Storage: ~$2.30/month
- Athena Queries: ~$5/month (moderate usage)
- Lambda: ~$1/month
- Other Services: ~$2/month
- **Total: ~$10-15/month**

## Troubleshooting

### Terraform Init Fails

- Check AWS credentials: `aws sts get-caller-identity`
- Verify Terraform version: `terraform version`
- Check network connectivity

### Insufficient Permissions

Ensure your AWS user/role has:
- IAM permissions to create roles and policies
- S3 permissions to create buckets
- Lambda permissions to create functions
- Glue permissions to create databases and tables
- API Gateway permissions
- Cognito permissions

### State Lock Error

If using DynamoDB for state locking and getting lock errors:

```bash
# Force unlock (use carefully)
terraform force-unlock <lock-id>
```

## Maintenance

### Updating Infrastructure

```bash
# Pull latest changes
git pull

# Review changes
terraform plan -var-file=my-environment.tfvars

# Apply updates
terraform apply -var-file=my-environment.tfvars
```

### Destroying Infrastructure

```bash
# Review what will be destroyed
terraform plan -destroy -var-file=my-environment.tfvars

# Destroy all resources
terraform destroy -var-file=my-environment.tfvars
```

**Warning**: This will delete all data. Ensure you have backups of important logs and rules.

## Advanced Configuration

### Multi-Region Deployment

Deploy to multiple regions for redundancy:

```bash
# Deploy primary region
terraform apply -var-file=environments/prod-us-east-1.tfvars

# Deploy secondary region
terraform apply -var-file=environments/prod-us-west-2.tfvars
```

### Custom Log Sources

Add custom log sources by extending the ingestion module. See module documentation for details.

## Support

For deployment issues:
- Check [docs/deployment/troubleshooting.md](../../../docs/deployment/troubleshooting.md)
- Open a GitHub issue
- Review AWS CloudWatch logs for Lambda errors
