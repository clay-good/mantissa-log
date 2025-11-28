# Contributing to Mantissa Log

Thank you for your interest in contributing to Mantissa Log! This guide will help you get started with development, testing, and submitting contributions.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Standards](#code-standards)
- [Testing Requirements](#testing-requirements)
- [Submitting Changes](#submitting-changes)
- [Documentation](#documentation)
- [Community Guidelines](#community-guidelines)

## Getting Started

### Prerequisites

**Required:**
- Python 3.11 or higher
- Git
- AWS CLI (for AWS deployments)
- Terraform 1.6.0 or higher

**Optional (for multi-cloud):**
- Google Cloud SDK (for GCP)
- Azure CLI (for Azure)

### Initial Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/mantissa-log.git
   cd mantissa-log
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

4. **Install pre-commit hooks:**
   ```bash
   pre-commit install
   ```

5. **Verify installation:**
   ```bash
   make test-quick
   ```

## Development Workflow

### Branching Strategy

We use a feature branch workflow:

```
main (protected)
  ↓
feature/add-new-detector
feature/fix-athena-bug
feature/update-docs
```

**Branch naming conventions:**
- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation updates
- `test/description` - Test improvements
- `refactor/description` - Code refactoring

### Creating a Feature Branch

```bash
# Update main branch
git checkout main
git pull origin main

# Create feature branch
git checkout -b feature/add-new-detector

# Make changes and commit
git add .
git commit -m "feat: add new detector for privilege escalation"

# Push to your fork
git push origin feature/add-new-detector
```

### Development Process

1. **Create an issue** describing the feature or bug
2. **Assign yourself** to the issue
3. **Create a feature branch** from main
4. **Implement your changes** following code standards
5. **Write tests** for new functionality
6. **Update documentation** as needed
7. **Run full test suite** to ensure nothing breaks
8. **Submit a pull request** with detailed description
9. **Address review feedback** promptly
10. **Celebrate** when merged!

## Code Standards

### Python Style Guide

We follow PEP 8 with some modifications:

**Line length:** 100 characters (not 79)

**Import order:**
```python
# Standard library
import os
import sys
from typing import Dict, List

# Third-party
import boto3
from pysigma.conversion.base import Backend

# Local application
from src.shared.detection.executors.base import QueryExecutor
from src.shared.detection.rule import DetectionRule
```

**Type hints:**
```python
def execute_query(
    self,
    query: str,
    timeout_seconds: int = 300
) -> QueryResult:
    """Execute a query and return results."""
    pass
```

**Docstrings:**
```python
def process_detection_results(
    results: List[Dict[str, Any]],
    severity_threshold: str = "medium"
) -> List[Alert]:
    """
    Process detection results and create alerts.

    Args:
        results: List of query results from detection engine
        severity_threshold: Minimum severity level to alert on

    Returns:
        List of Alert objects for findings above threshold

    Raises:
        ValidationError: If results format is invalid
    """
    pass
```

### Code Quality Tools

**Black** for formatting:
```bash
black src/ tests/ --line-length 100
```

**isort** for import sorting:
```bash
isort src/ tests/ --profile black --line-length 100
```

**flake8** for linting:
```bash
flake8 src/ tests/ --max-line-length 100
```

**mypy** for type checking:
```bash
mypy src/ --strict
```

**Run all checks:**
```bash
make lint
```

**Auto-fix formatting:**
```bash
make format
```

### Pre-commit Hooks

Pre-commit hooks automatically run before each commit:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/psf/black
    rev: 24.1.0
    hooks:
      - id: black
        args: [--line-length=100]

  - repo: https://github.com/pycqa/isort
    rev: 5.13.0
    hooks:
      - id: isort
        args: [--profile=black, --line-length=100]

  - repo: https://github.com/pycqa/flake8
    rev: 7.0.0
    hooks:
      - id: flake8
        args: [--max-line-length=100]

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.8.0
    hooks:
      - id: mypy
        args: [--strict]
```

Skip hooks only when necessary:
```bash
git commit --no-verify -m "WIP: work in progress"
```

## Testing Requirements

### Test Coverage Requirements

All contributions must meet these coverage thresholds:

- **Overall coverage:** >80%
- **Critical modules** (executors, engine, rule): >90%
- **New features:** 100% coverage required

### Running Tests

**Quick validation:**
```bash
make test-quick
```

**Full test suite:**
```bash
make test
```

**Specific test suites:**
```bash
make test-unit          # Unit tests only
make test-integration   # Integration tests
make test-executors     # Query executor tests
make test-sigma         # Sigma conversion tests
```

**With coverage:**
```bash
make test-coverage
open htmlcov/index.html
```

### Writing Tests

**Unit test structure:**
```python
# tests/unit/detection/test_new_feature.py

import pytest
from src.shared.detection.new_feature import NewFeature

class TestNewFeature:
    """Tests for NewFeature class."""

    def test_basic_functionality(self):
        """Test basic functionality works as expected."""
        # Arrange
        feature = NewFeature(config={'enabled': True})

        # Act
        result = feature.process('test input')

        # Assert
        assert result is not None
        assert result.status == 'success'

    def test_error_handling(self):
        """Test error handling for invalid input."""
        feature = NewFeature(config={'enabled': True})

        with pytest.raises(ValueError, match="Invalid input"):
            feature.process(None)

    @pytest.mark.parametrize("input_value,expected", [
        ("test1", "result1"),
        ("test2", "result2"),
        ("test3", "result3"),
    ])
    def test_multiple_inputs(self, input_value, expected):
        """Test multiple input scenarios."""
        feature = NewFeature(config={'enabled': True})
        result = feature.process(input_value)
        assert result == expected
```

**Integration test structure:**
```python
# tests/integration/test_new_integration.py

import pytest
from unittest.mock import Mock, patch

pytestmark = pytest.mark.integration

class TestNewIntegration:
    """Integration tests for new feature."""

    @patch('boto3.client')
    def test_aws_integration(self, mock_boto_client):
        """Test integration with AWS services."""
        # Setup mocks
        mock_client = Mock()
        mock_boto_client.return_value = mock_client

        mock_client.some_method.return_value = {'Status': 'Success'}

        # Test integration
        # ...
```

### Test Fixtures

Use shared fixtures from `tests/conftest.py`:

```python
def test_with_sample_logs(sample_cloudtrail_logs):
    """Test using sample CloudTrail logs fixture."""
    assert len(sample_cloudtrail_logs) > 0
```

Add new fixtures to conftest.py when needed:

```python
@pytest.fixture
def sample_new_data():
    """Provide sample data for new feature testing."""
    return {
        'field1': 'value1',
        'field2': 'value2'
    }
```

## Submitting Changes

### Commit Message Format

We follow Conventional Commits:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Test additions or changes
- `refactor:` - Code refactoring
- `perf:` - Performance improvements
- `chore:` - Build process or tooling changes
- `ci:` - CI/CD configuration changes

**Examples:**
```bash
feat(executors): add support for Azure Synapse Analytics

Add SynapseExecutor class implementing QueryExecutor interface.
Supports both managed identity and SQL authentication.

Closes #123

---

fix(athena): correct cost estimation for partitioned queries

Previously, cost estimation included all partitions. Now correctly
estimates based on query partition filters.

Fixes #456

---

docs(deployment): add multi-cloud deployment guide

Add comprehensive guide covering AWS, GCP, and Azure deployments
with configuration examples and troubleshooting tips.

---

test(executors): add comprehensive BigQuery executor tests

Add unit tests for BigQuery executor covering:
- Query execution
- Cost estimation
- Schema retrieval
- Error handling
```

### Pull Request Process

1. **Create pull request** from your feature branch to `main`

2. **Fill out PR template** with:
   - Description of changes
   - Related issue numbers
   - Testing performed
   - Screenshots (if UI changes)
   - Checklist completion

3. **PR checklist:**
   - [ ] Code follows style guidelines
   - [ ] Tests added for new functionality
   - [ ] All tests pass
   - [ ] Documentation updated
   - [ ] No merge conflicts
   - [ ] Commit messages follow convention
   - [ ] Pre-commit hooks pass

4. **Wait for CI checks** to pass:
   - Unit tests
   - Integration tests
   - Linting
   - Type checking
   - Coverage threshold

5. **Respond to review feedback**:
   - Address all comments
   - Push updates to same branch
   - Request re-review when ready

6. **Squash and merge** when approved

### PR Description Template

```markdown
## Description
Brief description of what this PR does.

## Related Issues
Closes #123
Related to #456

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Documentation update

## Testing
Describe the tests you ran:
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing performed

## Screenshots (if applicable)
[Add screenshots here]

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests added that prove fix/feature works
- [ ] All tests pass locally
- [ ] Dependent changes merged
```

## Documentation

### Documentation Requirements

All contributions should include appropriate documentation:

**Code documentation:**
- Docstrings for all public functions/classes
- Type hints for function signatures
- Inline comments for complex logic

**User documentation:**
- Update relevant docs/ files
- Add examples for new features
- Update configuration guides

**API documentation:**
- Document new API endpoints
- Update API examples
- Add request/response schemas

### Documentation Structure

```
docs/
├── getting-started.md          # Quick start guide
├── architecture.md             # System architecture
├── features/                   # Feature documentation
│   ├── sigma-rules.md
│   ├── llm-queries.md
│   └── alerting.md
├── deployment/                 # Deployment guides
│   ├── aws.md
│   ├── multi-cloud.md
│   └── automation.md
├── development/                # Development guides
│   ├── contributing.md
│   ├── testing.md
│   └── architecture.md
├── operations/                 # Operations guides
│   ├── monitoring.md
│   └── troubleshooting.md
├── configuration/              # Configuration references
│   ├── detection-rules.md
│   └── alerting.md
└── api/                        # API documentation
    ├── rest-api.md
    └── llm-queries.md
```

### Writing Good Documentation

**Be clear and concise:**
```markdown
# Good
Configure the detection engine schedule using the `detection_engine_schedule` variable:

```hcl
detection_engine_schedule = "rate(5 minutes)"
```

# Bad
You can configure how often the detection engine runs by setting a value for the schedule.
```

**Include examples:**
```markdown
## Querying with Natural Language

Ask questions about your security logs:

```python
query = "Show me all failed login attempts in the last hour"
results = llm_query_handler.execute(query)
```

This will automatically:
1. Convert natural language to SQL
2. Execute against your log data
3. Return formatted results
```

**Add troubleshooting sections:**
```markdown
## Troubleshooting

### Query Timeout Errors

If you see "Query execution timeout" errors:

1. Check query complexity
2. Verify partition pruning is working
3. Increase timeout setting:
   ```python
   executor.execute_query(query, timeout_seconds=600)
   ```
```

## Community Guidelines

### Code of Conduct

We are committed to providing a welcoming and inclusive environment:

1. **Be respectful** - Treat everyone with respect
2. **Be collaborative** - Help others learn and grow
3. **Be patient** - Remember everyone was new once
4. **Be constructive** - Provide helpful feedback
5. **Be inclusive** - Welcome diverse perspectives

### Communication Channels

**GitHub Issues:**
- Bug reports
- Feature requests
- Technical discussions

**Pull Requests:**
- Code review
- Design discussions
- Implementation feedback

**GitHub Discussions:**
- General questions
- Architecture discussions
- Community announcements

### Getting Help

**Before asking for help:**
1. Check existing documentation
2. Search GitHub issues
3. Review closed pull requests
4. Try minimal reproduction

**When asking for help:**
1. Describe what you're trying to do
2. Show what you've tried
3. Include error messages
4. Provide minimal reproduction
5. Specify your environment

**Example issue:**
```markdown
## Description
I'm trying to deploy Mantissa Log to AWS but getting a Terraform error.

## Steps to Reproduce
1. Run `./scripts/deploy.sh`
2. Select environment: dev
3. Select region: us-east-1

## Expected Behavior
Deployment should complete successfully.

## Actual Behavior
Terraform fails with error:
```
Error: Error creating S3 bucket: BucketAlreadyExists
```

## Environment
- OS: macOS 14.0
- Terraform: 1.6.0
- AWS CLI: 2.13.0
- Python: 3.11.0

## What I've Tried
- Changed bucket name prefix
- Verified AWS credentials
- Checked S3 bucket doesn't exist in console
```

### Recognition

We appreciate all contributions! Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Credited in relevant documentation

Significant contributions may also be recognized with:
- Maintainer status
- Special mentions in project updates
- Community spotlight features

## Development Best Practices

### Query Executor Development

When adding support for new query backends:

```python
from src.shared.detection.executors.base import QueryExecutor

class NewBackendExecutor(QueryExecutor):
    """Query executor for NewBackend."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize executor with configuration."""
        self.config = config
        # Initialize client connection

    def execute_query(
        self,
        query: str,
        timeout_seconds: int = 300
    ) -> QueryResult:
        """Execute query and return results."""
        # 1. Validate query
        if not self.validate_query(query):
            raise QueryValidationError("Invalid query")

        # 2. Execute query
        # 3. Parse results
        # 4. Return QueryResult

    def validate_query(self, query: str) -> bool:
        """Validate query is safe to execute."""
        # Implement validation logic
        pass

    def get_query_cost_estimate(self, query: str) -> float:
        """Estimate query cost in USD."""
        # Implement cost estimation
        pass
```

### Sigma Rule Development

When creating new Sigma rules:

```yaml
title: Descriptive Title
id: unique-uuid-here
status: experimental  # or test, stable
description: Detailed description of what this rule detects
author: Your Name
date: 2025-01-28
modified: 2025-01-28
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName:
      - CreateUser
      - AttachUserPolicy
    errorCode: null
  condition: selection
fields:
  - userIdentity.principalId
  - sourceIPAddress
  - eventTime
falsepositives:
  - Legitimate IAM administration
level: medium
tags:
  - attack.persistence
  - attack.privilege_escalation
```

Test the rule:
```bash
python scripts/test-rule.py rules/sigma/aws/cloudtrail/new_rule.yml
```

### Infrastructure Changes

When modifying Terraform infrastructure:

1. **Test in dev first:**
   ```bash
   cd infrastructure/aws/terraform
   terraform plan -var-file=environments/dev.tfvars
   ```

2. **Document variables:**
   ```hcl
   variable "new_feature_enabled" {
     description = "Enable new feature functionality"
     type        = bool
     default     = false
   }
   ```

3. **Update all environments:**
   - dev.tfvars
   - staging.tfvars
   - prod.tfvars.example

4. **Test deployment:**
   ```bash
   ./scripts/deploy.sh
   ```

### Performance Considerations

**Query optimization:**
- Use partition pruning
- Limit time ranges
- Index frequently queried fields
- Test query cost before deploying

**Lambda optimization:**
- Minimize cold starts
- Use Lambda layers for shared dependencies
- Set appropriate memory/timeout
- Implement proper error handling

**Cost optimization:**
- Use lifecycle policies for old logs
- Enable S3 Intelligent-Tiering
- Implement query result caching
- Monitor and alert on costs

## Release Process

### Versioning

We follow Semantic Versioning (SemVer):

- **MAJOR:** Breaking changes (2.0.0)
- **MINOR:** New features, backward compatible (1.1.0)
- **PATCH:** Bug fixes, backward compatible (1.0.1)

### Creating a Release

1. **Update version numbers:**
   - setup.py
   - package.json (if web component changed)
   - Documentation references

2. **Update CHANGELOG.md:**
   ```markdown
   ## [1.2.0] - 2025-01-28

   ### Added
   - Support for Azure Synapse Analytics
   - Multi-cloud cost estimation

   ### Changed
   - Improved Sigma rule conversion performance

   ### Fixed
   - Athena partition pruning for date ranges
   ```

3. **Create git tag:**
   ```bash
   git tag -a v1.2.0 -m "Release version 1.2.0"
   git push origin v1.2.0
   ```

4. **GitHub Actions will:**
   - Run full test suite
   - Build Lambda packages
   - Create GitHub release
   - Deploy to production

5. **Announce release:**
   - GitHub Discussions
   - Update documentation
   - Send notifications

## Resources

- [Python Type Hints](https://docs.python.org/3/library/typing.html)
- [pytest Documentation](https://docs.pytest.org/)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Semantic Versioning](https://semver.org/)
- [AWS Lambda Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [Terraform Best Practices](https://www.terraform.io/docs/cloud/guides/recommended-practices/index.html)
- [Sigma Rule Specification](https://github.com/SigmaHQ/sigma/wiki/Specification)

## Questions?

If you have questions not covered in this guide:

1. Check the [documentation](../../README.md)
2. Search [GitHub Issues](https://github.com/clay-good/mantissa-log/issues)
3. Ask in [GitHub Discussions](https://github.com/clay-good/mantissa-log/discussions)
4. Review [architecture documentation](architecture.md)

Thank you for contributing to Mantissa Log!
