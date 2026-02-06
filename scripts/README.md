# Scripts

Deployment, testing, and utility scripts for Mantissa Log.

## Deployment

| Script | Description |
|--------|-------------|
| `deploy.sh` | Deploy AWS infrastructure and Lambda functions |
| `deploy-gcp.sh` | Deploy GCP infrastructure and Cloud Functions |
| `deploy-azure.sh` | Deploy Azure infrastructure and Functions |
| `deploy-web.sh` | Build and deploy the React frontend |
| `destroy.sh` | Tear down deployed infrastructure |
| `update.sh` | Update an existing deployment |
| `package-lambdas.sh` | Package Lambda functions for deployment |
| `package-azure-functions.sh` | Package Azure Functions for deployment |

## Testing and Validation

| Script | Description |
|--------|-------------|
| `run-tests.sh` | Run the full test suite |
| `test-rule.py` | Test a single detection rule (dry-run, test, backtest) |
| `test-sigma-rules.py` | Run Sigma rule test suite |
| `validate-rules.py` | Validate detection rule schemas |
| `validate-sigma-rules.py` | Validate Sigma rule format |
| `validate-deployment.sh` | Verify a deployment is working correctly |
| `smoke-test.sh` | Quick smoke test against a live deployment |

## Development and Setup

| Script | Description |
|--------|-------------|
| `setup-dev.sh` | Set up local development environment |
| `generate-sample-data.py` | Generate sample log data for testing |
| `check-env-vars.py` | Verify required environment variables are set |
| `fix-env-var-names.sh` | Standardize environment variable naming |

## Utilities

| Script | Description |
|--------|-------------|
| `security-audit.py` | Run security audit against the codebase |
| `map-sigmahq-rules.py` | Map SigmaHQ community rules to Mantissa sources |
| `standardize-collector-secrets.py` | Standardize collector credential configuration |

## Usage Examples

```bash
# Deploy to AWS (dev environment)
./scripts/deploy.sh --environment dev

# Deploy to GCP
./scripts/deploy-gcp.sh

# Generate test data
python scripts/generate-sample-data.py --type cloudtrail --count 1000

# Test a detection rule
python scripts/test-rule.py rules/sigma/okta/brute_force_login.yml --mode dry-run

# Validate all rules
python scripts/validate-rules.py

# Run smoke tests against a live deployment
./scripts/smoke-test.sh

# Security audit
python scripts/security-audit.py
```

## Adding New Scripts

1. Add executable permissions: `chmod +x scripts/your-script.sh`
2. Include `--help` flag for usage documentation
3. Update this README
