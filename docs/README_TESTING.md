# Mantissa Log - Testing Guide

This document describes the testing framework and how to run tests for the Mantissa Log project.

## Test Structure

```
tests/
├── unit/                           # Unit tests (fast, isolated)
│   ├── detection/
│   │   ├── executors/             # Query executor tests
│   │   │   ├── test_base.py       # Base executor tests
│   │   │   ├── test_athena.py     # AWS Athena executor
│   │   │   ├── test_bigquery.py   # GCP BigQuery executor
│   │   │   ├── test_synapse.py    # Azure Synapse executor
│   │   │   └── test_config.py     # Cloud provider config
│   │   ├── test_rule.py           # Detection rule tests
│   │   └── test_engine.py         # Detection engine tests
│   ├── llm/
│   │   └── test_query_generator.py
│   └── alerting/
│       └── test_router.py
├── integration/                    # Integration tests
│   ├── detection/
│   │   ├── test_multi_cloud_execution.py       # Multi-cloud query execution
│   │   ├── test_sigma_multi_cloud.py           # Sigma multi-cloud conversion
│   │   └── test_detection_engine_multi_cloud.py # Detection engine integration
│   ├── test_sigma_conversion.py   # Sigma rule conversion
│   └── aws/
│       ├── test_athena_queries.py
│       ├── test_glue_catalog.py
│       └── test_s3_operations.py
├── fixtures/                       # Test data
│   ├── sample_logs/               # Sample log files
│   ├── sample_configs/            # Sample configurations
│   ├── sample_sigma_rules/        # Sample Sigma rules for testing
│   └── sample_query_results/      # Expected query results
└── conftest.py                    # Shared fixtures
```

## Running Tests

### Prerequisites

Install development dependencies:

```bash
pip install -r requirements-dev.txt
```

### Quick Start

Run all tests:

```bash
make test
```

Or using pytest directly:

```bash
pytest
```

### Test Suites

**Unit Tests** (fast, isolated tests):

```bash
make test-unit
# or
pytest tests/unit -v
```

**Integration Tests** (tests with mocked services):

```bash
make test-integration
# or
pytest tests/integration -v
```

**Query Executor Tests** (AWS Athena, GCP BigQuery, Azure Synapse):

```bash
make test-executors
# or
pytest tests/unit/detection/executors/ -v
```

**Sigma Conversion Tests** (Sigma rule to SQL conversion):

```bash
make test-sigma
# or
pytest tests/unit/test_sigma_converter.py tests/integration/test_sigma_conversion.py -v
```

**Multi-Cloud Tests** (cross-cloud compatibility):

```bash
make test-multi-cloud
# or
pytest tests/integration/detection/test_multi_cloud_*.py -v
```

**Coverage Report**:

```bash
make test-coverage
# or
pytest --cov=src --cov=lambda_functions --cov-report=html --cov-report=term-missing
```

View coverage report in browser:

```bash
open htmlcov/index.html
```

**Quick Smoke Tests** (fast tests for rapid feedback):

```bash
make test-quick
# or
pytest -x -k "not slow" --tb=short
```

## Test Markers

Tests are categorized using pytest markers:

- `@pytest.mark.unit` - Unit tests (fast, isolated)
- `@pytest.mark.integration` - Integration tests (slower, may use mocks)
- `@pytest.mark.aws` - Tests that interact with AWS services
- `@pytest.mark.slow` - Slow-running tests

Run specific markers:

```bash
pytest -m unit              # Run only unit tests
pytest -m integration       # Run only integration tests
pytest -m "not slow"        # Skip slow tests
```

## Writing Tests

### Unit Test Example

```python
import pytest
from src.shared.detection.executors.athena import AthenaQueryExecutor

class TestAthenaQueryExecutor:
    def test_validate_select_query(self):
        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://bucket/results/'
        )

        assert executor.validate_query("SELECT * FROM cloudtrail") is True
        assert executor.validate_query("DROP TABLE cloudtrail") is False
```

### Integration Test Example

```python
import pytest
from unittest.mock import Mock, patch

pytestmark = pytest.mark.integration

@patch('boto3.client')
def test_athena_query_execution(mock_boto_client):
    mock_client = Mock()
    mock_boto_client.return_value = mock_client

    # Setup mocks...

    executor = AthenaQueryExecutor(
        database='test_db',
        output_location='s3://bucket/results/'
    )

    result = executor.execute_query("SELECT * FROM cloudtrail")

    assert result.row_count > 0
```

### Using Fixtures

```python
def test_with_fixtures(sample_executor_configs, sample_query_results):
    """Test using shared fixtures from conftest.py"""
    aws_config = sample_executor_configs['aws']
    results = sample_query_results['brute_force']

    assert aws_config['provider'] == 'aws'
    assert len(results) > 0
```

## Continuous Integration

Tests run automatically on GitHub Actions for:

- Pull requests to main/develop branches
- Pushes to main/develop branches

The CI pipeline runs:

1. Unit tests with coverage
2. Integration tests
3. Code linting (black, flake8)
4. Type checking (mypy)

## Debugging Tests

**Run specific test:**

```bash
pytest tests/unit/detection/executors/test_athena.py::TestAthenaQueryExecutor::test_validate_select_query -v
```

**Run with detailed output:**

```bash
pytest -vv -s --tb=long
```

**Drop into debugger on failure:**

```bash
pytest --pdb
```

**Run last failed tests:**

```bash
pytest --lf
```

## Code Quality

**Format code:**

```bash
make format
# or
black src/ lambda_functions/ tests/ --line-length=100
```

**Lint code:**

```bash
make lint
# or
flake8 src/ lambda_functions/ tests/ --max-line-length=120
```

**Type checking:**

```bash
make type-check
# or
mypy src/ lambda_functions/ --ignore-missing-imports
```

## Test Coverage Goals

- Overall coverage: >80%
- Critical modules (detection engine, executors): >90%
- Unit tests should be fast (<1s each)
- Integration tests should complete in <5s each

## Adding New Tests

When adding new functionality:

1. Write unit tests for individual components
2. Write integration tests for multi-component interactions
3. Add test fixtures to `tests/fixtures/` for reusable test data
4. Update this documentation if adding new test suites

## Common Issues

**Import errors:**

```bash
# Ensure src is in PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:${PWD}/src"
```

**AWS credential errors:**

Tests use moto for AWS mocking. No real AWS credentials needed.

**pySigma not installed:**

Sigma-related tests will be skipped if pySigma is not installed:

```bash
pip install pysigma pysigma-backend-athena
```

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [pytest-cov documentation](https://pytest-cov.readthedocs.io/)
- [moto documentation](http://docs.getmoto.org/)
- [pySigma documentation](https://sigmahq-pysigma.readthedocs.io/)
