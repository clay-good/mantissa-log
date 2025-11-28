# Mantissa Log Source Code

This directory contains all application source code for Mantissa Log.

## Directory Structure

- **shared/**: Cloud-agnostic shared code (parsers, detection, LLM, alerting)
- **aws/**: AWS-specific implementations (Lambda handlers, Glue schemas, Athena wrappers)
- **gcp/**: Google Cloud specific implementations (future)
- **azure/**: Azure-specific implementations (future)

## Architecture Philosophy

The codebase is split into two layers:

### 1. Shared Layer (70% of code)

Cloud-agnostic components that work across all platforms:

- **parsers/**: Log parsing and normalization
- **detection/**: Detection engine core logic
- **llm/**: LLM query generation and validation
- **alerting/**: Alert routing and enrichment
- **utils/**: Common utilities

These components have no cloud-specific dependencies and can be reused across AWS, GCP, and Azure.

### 2. Cloud-Specific Layer (30% of code)

Platform-specific adapters and implementations:

- **aws/lambdas/**: AWS Lambda function handlers
- **aws/glue/**: Glue table schemas and crawler configs
- **aws/athena/**: Athena query execution wrappers

These components wrap cloud services and call the shared layer for business logic.

## Development Guidelines

When adding new features:

1. Implement business logic in `shared/` if cloud-agnostic
2. Create cloud-specific adapters in provider directories
3. Ensure shared code has no cloud SDK dependencies
4. Write tests for both shared and cloud-specific code
5. Document interfaces between layers

## Language Standards

- **Python 3.11+**: All backend code
- **Type hints**: Required for function signatures
- **Docstrings**: Google-style docstrings for public functions
- **Testing**: pytest for unit and integration tests

## Import Structure

Shared code should only import from:
- Python standard library
- Third-party libraries with no cloud dependencies
- Other shared modules

Cloud-specific code can import:
- Shared modules
- Cloud provider SDKs (boto3 for AWS, etc.)
- Cloud-specific third-party libraries
