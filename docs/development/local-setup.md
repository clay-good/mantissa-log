# Local Development Setup

This guide walks you through setting up a local development environment for Mantissa Log.

## Prerequisites

### Required Tools

- **Python 3.11+**: Backend code and CLI tools
- **Node.js 18+**: Web interface development
- **Git**: Version control

### Optional Tools

- **Terraform 1.5+**: Infrastructure deployment
- **AWS CLI v2**: AWS resource management
- **Docker**: Local testing of Lambda functions

### Verifying Prerequisites

Check that you have the required tools installed:

```bash
python3 --version  # Should be 3.11 or higher
node --version     # Should be 18.x or higher
git --version
```

Optional tools:

```bash
terraform --version  # 1.5 or higher
aws --version        # v2
docker --version
```

## Quick Setup

The fastest way to get started is using the automated setup script:

```bash
# Clone the repository
git clone https://github.com/clay-good/mantissa-log.git
cd mantissa-log

# Run the setup script
./scripts/setup-dev.sh

# Activate the virtual environment
source venv/bin/activate
```

The script will:
1. Verify required tools are installed
2. Create a Python virtual environment
3. Install Python dependencies
4. Install Node.js dependencies for the web interface
5. Set up pre-commit hooks
6. Create configuration files

## Manual Setup

If you prefer to set up manually or need to troubleshoot:

### 1. Python Environment

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Python Dependencies

Install development dependencies:

```bash
pip install --upgrade pip
pip install -r requirements-dev.txt
```

This installs:
- Production dependencies from `requirements.txt`
- Testing tools (pytest, coverage)
- Code formatters (black, isort)
- Linters (flake8, mypy, pylint)
- Security scanners (bandit, safety)
- Pre-commit hooks

### 3. Web Interface Setup

Install Node.js dependencies:

```bash
cd web
npm install
cd ..
```

### 4. Pre-commit Hooks

Install pre-commit hooks to run linting and formatting before commits:

```bash
pre-commit install
```

This sets up hooks for:
- Code formatting (black, isort)
- Linting (flake8)
- Security scanning (bandit, detect-secrets)
- Terraform formatting
- YAML/JSON validation

### 5. Create Configuration Files

Create a secrets baseline for detect-secrets:

```bash
detect-secrets scan > .secrets.baseline
```

Create `.yamllint.yaml`:

```yaml
extends: default

rules:
  line-length:
    max: 120
    level: warning
  indentation:
    spaces: 2
  comments:
    min-spaces-from-content: 1
```

## Verifying Installation

### Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src
```

### Check Code Quality

```bash
# Run pre-commit hooks manually
pre-commit run --all-files

# Run linters individually
black --check src/
isort --check src/
flake8 src/
mypy src/
bandit -r src/
```

### Start Web Interface (Development)

```bash
cd web
npm run dev
```

The development server should start on http://localhost:5173

## Project Structure

```
mantissa-log/
├── src/                  # Python source code
│   ├── shared/          # Cloud-agnostic code
│   └── aws/             # AWS-specific code
├── web/                 # React web interface
├── rules/               # Detection rules (YAML)
├── infrastructure/      # Terraform/CloudFormation
├── tests/               # Test suite
├── scripts/             # Utility scripts
└── docs/                # Documentation
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Changes

Edit code, add tests, update documentation.

### 3. Run Tests and Linters

```bash
# Run tests
pytest

# Run linters
pre-commit run --all-files
```

### 4. Commit Changes

```bash
git add .
git commit -m "feat: add new feature"
```

Pre-commit hooks will run automatically. If they fail, fix the issues and commit again.

### 5. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub.

## Common Development Tasks

### Running Tests

```bash
# All tests
pytest

# Specific test file
pytest tests/unit/parsers/test_cloudtrail.py

# Tests matching pattern
pytest -k "test_parser"

# With coverage
pytest --cov=src --cov-report=html
open htmlcov/index.html

# In parallel
pytest -n auto
```

### Code Formatting

```bash
# Format all Python code
black src/ tests/

# Sort imports
isort src/ tests/

# Format Terraform
terraform fmt -recursive infrastructure/
```

### Linting

```bash
# Flake8
flake8 src/

# MyPy type checking
mypy src/

# Pylint
pylint src/

# Bandit security scan
bandit -r src/
```

### Adding Dependencies

```bash
# Add production dependency
echo "new-package>=1.0.0" >> requirements.txt
pip install -r requirements.txt

# Add development dependency
echo "new-dev-package>=1.0.0" >> requirements-dev.txt
pip install -r requirements-dev.txt
```

### Working with Detection Rules

```bash
# Validate rule syntax
python scripts/validate-rules.py rules/authentication/brute_force_login.yaml

# Validate all rules
python scripts/validate-rules.py rules/

# Test a specific rule
pytest tests/unit/detection/test_rules.py -k brute_force
```

### Generating Sample Data

```bash
# Generate CloudTrail logs
python scripts/generate-sample-data.py --type cloudtrail --count 1000

# Generate VPC Flow logs
python scripts/generate-sample-data.py --type vpc-flow --count 5000
```

## Troubleshooting

### Virtual Environment Issues

If the virtual environment has issues:

```bash
# Remove and recreate
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
```

### Pre-commit Hook Failures

If pre-commit hooks fail:

```bash
# Run hooks manually to see detailed errors
pre-commit run --all-files

# Update hooks to latest versions
pre-commit autoupdate

# Skip hooks temporarily (not recommended)
git commit --no-verify
```

### Import Errors

If you get import errors when running tests:

```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements-dev.txt

# Set PYTHONPATH if needed
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

### AWS Credentials for Testing

For tests that interact with AWS (using moto for mocking):

```bash
# Set fake credentials for moto
export AWS_ACCESS_KEY_ID=testing
export AWS_SECRET_ACCESS_KEY=testing
export AWS_SECURITY_TOKEN=testing
export AWS_SESSION_TOKEN=testing
export AWS_DEFAULT_REGION=us-east-1
```

## Editor Configuration

### VS Code

Recommended extensions:
- Python
- Pylance
- ESLint
- Prettier
- Terraform
- YAML

Recommended settings (.vscode/settings.json):

```json
{
  "python.linting.enabled": true,
  "python.linting.flake8Enabled": true,
  "python.linting.mypyEnabled": true,
  "python.formatting.provider": "black",
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": true
  }
}
```

### PyCharm

1. Set Python interpreter to `venv/bin/python`
2. Enable black as formatter
3. Enable isort for import sorting
4. Configure pytest as test runner

## Next Steps

- Read [CONTRIBUTING.md](../../CONTRIBUTING.md) for contribution guidelines
- Review [Architecture Overview](../architecture.md)
- Explore example detection rules in `rules/`
- Check out open issues on GitHub

## Getting Help

- GitHub Issues: Bug reports and feature requests
- GitHub Discussions: Questions and community support
- Documentation: Browse the `docs/` directory
