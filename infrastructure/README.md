# Infrastructure as Code

This directory contains all Infrastructure as Code (IaC) for deploying Mantissa Log across different cloud providers.

## Directory Structure

- **aws/**: AWS deployment using Terraform and CloudFormation
- **gcp/**: Google Cloud Platform deployment (planned for future release)
- **azure/**: Microsoft Azure deployment (planned for future release)

## Cloud Provider Support

### AWS (Current)

Full support for AWS deployment using:
- Terraform modules for infrastructure provisioning
- CloudFormation templates as an alternative option
- Serverless architecture with Lambda, S3, Athena, and Glue

See [aws/terraform/README.md](aws/terraform/README.md) for AWS deployment instructions.

### GCP (Planned)

Future release will include:
- Cloud Storage for log data
- BigQuery for analytics
- Cloud Functions for serverless compute
- Cloud Dataflow for streaming ingestion

### Azure (Planned)

Future release will include:
- Blob Storage for log data
- Synapse Analytics for querying
- Azure Functions for serverless compute
- Event Hubs for streaming ingestion

## Getting Started

1. Choose your cloud provider (currently AWS only)
2. Follow the deployment guide in the provider's directory
3. Customize variables for your environment
4. Deploy using provided scripts or manual commands

## Architecture Philosophy

The infrastructure is designed to:
- Minimize costs through serverless and managed services
- Scale automatically with log volume
- Maintain security through least-privilege IAM
- Support multi-cloud through abstraction layers
