# Infrastructure as Code

Terraform modules for deploying Mantissa Log to AWS, GCP, and Azure.

## Directory Structure

```
infrastructure/
├── aws/
│   ├── terraform/           # AWS Terraform modules (14 modules)
│   │   ├── modules/
│   │   │   ├── collectors/  # Lambda collectors for log sources
│   │   │   ├── state/       # DynamoDB state tables
│   │   │   └── ...          # Networking, IAM, S3, Athena, etc.
│   │   ├── environments/    # Per-environment tfvars
│   │   └── backend.tf       # Remote state configuration
│   └── README.md
├── gcp/
│   ├── terraform/           # GCP Terraform configuration
│   └── README.md
└── azure/
    ├── terraform/           # Azure Terraform configuration
    └── README.md
```

## Cloud Provider Support

### AWS

Full deployment support using Terraform:
- S3 for log storage (partitioned by source/date/hour)
- Athena for serverless SQL queries
- Lambda for all compute (collectors, detection, API handlers)
- DynamoDB for state management
- Glue for table schemas and crawlers
- EventBridge for scheduled detection execution
- API Gateway + Cognito for authenticated API access
- CloudFront + S3 for web frontend hosting

See [aws/terraform/README.md](aws/terraform/README.md) for deployment instructions.

### GCP

Deployment support using Terraform:
- Cloud Storage for log data
- BigQuery for serverless SQL queries
- Cloud Functions for compute
- Firestore for state management
- Cloud Scheduler for scheduled detection

See [gcp/README.md](gcp/README.md) for details.

### Azure

Deployment support using Terraform:
- Blob Storage for log data
- Synapse Analytics for SQL queries
- Azure Functions for compute
- Cosmos DB for state management
- Timer Triggers for scheduled detection

See [azure/README.md](azure/README.md) for details.

## Getting Started

1. Choose your cloud provider
2. Follow the deployment guide in the provider's directory
3. Customize variables for your environment
4. Deploy using the provided scripts or manual Terraform commands

```bash
# AWS example
cd infrastructure/aws/terraform
cp backend.tf.example backend.tf
cp environments/dev.tfvars.example environments/dev.tfvars
terraform init
terraform plan -var-file=environments/dev.tfvars
terraform apply -var-file=environments/dev.tfvars
```

## Design Principles

- **Serverless-first**: No servers or clusters to manage
- **Cost-efficient**: Pay-per-use pricing on all compute and storage
- **Auto-scaling**: Scales with log volume automatically
- **Least-privilege IAM**: Minimal permissions for each component
- **Modular deployment**: Enable/disable APM and SOAR modules via Terraform flags
