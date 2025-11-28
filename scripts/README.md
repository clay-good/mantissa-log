# Utility Scripts

This directory contains utility scripts for development, deployment, and maintenance.

## Available Scripts

### Development

- **setup-dev.sh**: Set up local development environment
- **generate-sample-data.py**: Generate sample log data for testing
- **validate-rules.py**: Validate detection rule syntax

### Deployment

- **deploy.sh**: Main deployment script for AWS infrastructure

### Maintenance

- **cost-estimator.py**: Estimate AWS costs based on log volume

## Script Usage

### setup-dev.sh

Sets up local development environment:

```bash
./scripts/setup-dev.sh
```

This script:
- Checks for required tools (Python, Node.js, Terraform, AWS CLI)
- Creates Python virtual environment
- Installs Python dependencies
- Installs Node.js dependencies
- Sets up pre-commit hooks
- Provides next steps

### generate-sample-data.py

Generate sample log data for testing:

```bash
python scripts/generate-sample-data.py --help

# Generate CloudTrail logs
python scripts/generate-sample-data.py --type cloudtrail --count 1000 --output tests/fixtures/sample_logs/

# Generate VPC Flow logs
python scripts/generate-sample-data.py --type vpc-flow --count 5000 --output tests/fixtures/sample_logs/
```

### validate-rules.py

Validate detection rule syntax:

```bash
python scripts/validate-rules.py --help

# Validate single rule
python scripts/validate-rules.py rules/authentication/brute_force_login.yaml

# Validate all rules
python scripts/validate-rules.py rules/

# Validate with SQL syntax checking
python scripts/validate-rules.py rules/ --check-sql
```

### deploy.sh

Deploy Mantissa Log infrastructure to AWS:

```bash
./scripts/deploy.sh --help

# Deploy to dev environment
./scripts/deploy.sh --environment dev

# Deploy to prod environment
./scripts/deploy.sh --environment prod --auto-approve
```

### cost-estimator.py

Estimate AWS costs:

```bash
python scripts/cost-estimator.py --help

# Estimate costs for 100GB/day
python scripts/cost-estimator.py --log-volume 100 --retention-days 365

# Compare with Datadog pricing
python scripts/cost-estimator.py --log-volume 100 --retention-days 365 --compare
```

## Adding New Scripts

When adding new scripts:

1. Add executable permissions: `chmod +x scripts/your-script.sh`
2. Include usage documentation in script comments
3. Add help text (--help flag)
4. Update this README
5. Add tests if applicable
