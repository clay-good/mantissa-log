# Testing Guide

Comprehensive testing framework for Mantissa Log, including unit tests, integration tests, and multi-cloud compatibility tests.

## Overview

The testing framework ensures:
- Detection engine correctness across AWS, GCP, and Azure
- Sigma rule conversion accuracy for all backends
- Query executor functionality for all cloud providers
- Integration between components
- Code quality and security

## Test Structure

```
tests/
├── unit/                           # Unit tests (fast, isolated)
│   ├── detection/
│   │   ├── executors/             # Query executor tests
│   │   │   ├── test_base.py       # Base executor abstraction
│   │   │   ├── test_athena.py     # AWS Athena executor
│   │   │   ├── test_bigquery.py   # GCP BigQuery executor
│   │   │   ├── test_synapse.py    # Azure Synapse executor
│   │   │   └── test_config.py     # Cloud provider config
│   │   ├── test_rule.py           # Detection rule tests
│   │   ├── test_engine.py         # Detection engine tests
│   │   └── test_sigma_converter.py # Sigma conversion tests
│   ├── llm/
│   │   └── test_query_generator.py
│   └── alerting/
│       └── test_router.py
├── integration/                    # Integration tests
│   ├── detection/
│   │   ├── test_multi_cloud_execution.py       # Multi-cloud query tests
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
│   ├── sample_sigma_rules/        # Sample Sigma rules
│   └── sample_query_results/      # Expected query results
└── conftest.py                    # Shared fixtures
```

## Running Tests

### Quick Start

Run all tests:
```bash
make test
# or
pytest
```

### Test Suites

**Unit Tests** (fast, < 1s each):
```bash
make test-unit
# or
pytest tests/unit/ -v
```

**Integration Tests** (slower, with mocks):
```bash
make test-integration
# or
pytest tests/integration/ -v
```

**Query Executor Tests**:
```bash
make test-executors
# or
pytest tests/unit/detection/executors/ -v
```

**Sigma Conversion Tests**:
```bash
make test-sigma
# or
pytest tests/unit/test_sigma_converter.py tests/integration/test_sigma_conversion.py -v
```

**Multi-Cloud Tests**:
```bash
make test-multi-cloud
# or
pytest tests/integration/detection/test_multi_cloud_*.py -v
```

**Coverage Report**:
```bash
make test-coverage
# or
pytest --cov=src --cov=lambda_functions --cov-report=html
open htmlcov/index.html
```

**Quick Smoke Tests**:
```bash
make test-quick
# or
pytest -x -k "not slow" --tb=short
```

## Test Markers

Categorize tests using pytest markers:

```python
import pytest

@pytest.mark.unit
def test_fast_operation():
    """Fast, isolated unit test"""
    pass

@pytest.mark.integration
def test_component_integration():
    """Integration test with mocked services"""
    pass

@pytest.mark.slow
def test_expensive_operation():
    """Slow-running test"""
    pass

@pytest.mark.aws
def test_aws_specific():
    """Test specific to AWS"""
    pass
```

Run specific markers:
```bash
pytest -m unit              # Only unit tests
pytest -m integration       # Only integration tests
pytest -m "not slow"        # Skip slow tests
pytest -m "aws and unit"    # AWS unit tests
```

## Writing Tests

### Unit Test Example

Test a single component in isolation:

```python
# tests/unit/detection/executors/test_athena.py

import pytest
from src.shared.detection.executors.athena import AthenaQueryExecutor
from src.shared.detection.executors.base import QueryValidationError

class TestAthenaValidation:
    def test_validate_select_query(self):
        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://bucket/results/'
        )

        # Valid SELECT query
        assert executor.validate_query("SELECT * FROM cloudtrail") is True

    def test_reject_dangerous_query(self):
        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://bucket/results/'
        )

        # Dangerous DROP query should be rejected
        assert executor.validate_query("DROP TABLE cloudtrail") is False

    def test_execute_query_validation_error(self):
        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://bucket/results/'
        )

        # Should raise validation error
        with pytest.raises(QueryValidationError):
            executor.execute_query("DROP TABLE cloudtrail")
```

### Integration Test Example

Test multiple components working together:

```python
# tests/integration/detection/test_multi_cloud_execution.py

import pytest
from unittest.mock import Mock, patch
from src.shared.detection.executors.athena import AthenaQueryExecutor
from src.shared.detection.executors.bigquery import BigQueryExecutor

pytestmark = pytest.mark.integration

class TestMultiCloudExecution:
    @patch('boto3.client')
    def test_athena_query_execution(self, mock_boto_client):
        """Test query execution on AWS Athena"""
        # Setup mock
        mock_client = Mock()
        mock_boto_client.return_value = mock_client

        mock_client.start_query_execution.return_value = {
            'QueryExecutionId': 'query-123'
        }

        mock_client.get_query_execution.return_value = {
            'QueryExecution': {
                'Status': {'State': 'SUCCEEDED'},
                'Statistics': {'DataScannedInBytes': 1024}
            }
        }

        # Execute test
        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://bucket/results/'
        )

        result = executor.execute_query("SELECT * FROM cloudtrail")

        assert result.row_count >= 0
        assert result.bytes_scanned == 1024
```

### Sigma Rule Conversion Test

Test Sigma rule conversion across clouds:

```python
# tests/integration/detection/test_sigma_multi_cloud.py

import pytest
from pathlib import Path
from src.shared.detection.sigma_converter import SigmaRuleConverter, SIGMA_AVAILABLE

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not SIGMA_AVAILABLE, reason="pySigma not installed")
]

class TestSigmaMultiCloudConversion:
    @pytest.fixture
    def sample_rule_path(self):
        return Path("rules/sigma/aws/cloudtrail/root_account_usage.yml")

    def test_convert_to_all_backends(self, sample_rule_path):
        """Test same rule converts to all backends"""
        backends = ["athena", "bigquery", "synapse"]
        results = {}

        for backend in backends:
            converter = SigmaRuleConverter(backend_type=backend)
            sql = converter.convert_rule_to_sql(str(sample_rule_path))

            # All should produce valid SQL
            assert sql is not None
            assert len(sql) > 0
            assert "SELECT" in sql.upper()

            results[backend] = sql

        # Verify we got results for all backends
        assert len(results) == 3
```

## Using Fixtures

Shared fixtures are defined in `tests/conftest.py`:

```python
def test_with_executor_configs(sample_executor_configs):
    """Use pre-configured executor configs"""
    aws_config = sample_executor_configs['aws']
    assert aws_config['provider'] == 'aws'

def test_with_query_results(sample_query_results):
    """Use sample query result data"""
    brute_force_results = sample_query_results['brute_force']
    assert len(brute_force_results) > 0

def test_with_sigma_rules(sample_sigma_rules_path):
    """Use sample Sigma rules"""
    rule_path = sample_sigma_rules_path / 'test_console_login.yml'
    assert rule_path.exists()
```

## Mocking

### Mocking AWS Services

Use moto for AWS mocking:

```python
from moto import mock_s3, mock_athena
import boto3

@mock_s3
def test_s3_operations():
    # Create mock S3 client
    s3 = boto3.client('s3', region_name='us-east-1')

    # Operations work against mock
    s3.create_bucket(Bucket='test-bucket')
    s3.put_object(Bucket='test-bucket', Key='test.txt', Body=b'data')

    # Assertions
    response = s3.list_objects_v2(Bucket='test-bucket')
    assert len(response['Contents']) == 1
```

### Mocking Cloud Clients

Mock cloud-specific clients:

```python
from unittest.mock import Mock, patch

@patch('boto3.client')
def test_athena_with_mock(mock_boto_client):
    mock_client = Mock()
    mock_boto_client.return_value = mock_client

    # Configure mock behavior
    mock_client.start_query_execution.return_value = {
        'QueryExecutionId': 'test-id'
    }

    # Test code using mock
    executor = AthenaQueryExecutor(
        database='test',
        output_location='s3://bucket/'
    )
    # ... test logic
```

## Test Data

### Sample Logs

Located in `tests/fixtures/sample_logs/`:

```
tests/fixtures/sample_logs/
├── cloudtrail/
│   ├── console_login_success.json
│   ├── console_login_failure.json
│   └── api_call.json
├── vpc_flow/
│   ├── accept_record.txt
│   └── reject_record.txt
└── guardduty/
    └── high_severity.json
```

### Sample Configurations

Located in `tests/fixtures/sample_configs/`:

```
tests/fixtures/sample_configs/
├── aws_executor_config.json
├── gcp_executor_config.json
└── azure_executor_config.json
```

### Sample Sigma Rules

Located in `tests/fixtures/sample_sigma_rules/`:

```
tests/fixtures/sample_sigma_rules/
├── test_console_login.yml
├── test_iam_policy_change.yml
└── test_s3_bucket_exposure.yml
```

## Continuous Integration

Tests run automatically on GitHub Actions:

```yaml
# .github/workflows/test.yml
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.11', '3.12']

    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Run unit tests
        run: pytest tests/unit/ -v --cov=src --cov-report=xml

      - name: Run integration tests
        run: pytest tests/integration/ -v

      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## Code Coverage

### Coverage Goals

- **Overall:** >80%
- **Critical modules (executors, engine):** >90%
- **Utility modules:** >70%

### Generating Reports

```bash
# Terminal report
pytest --cov=src --cov-report=term-missing

# HTML report
pytest --cov=src --cov-report=html
open htmlcov/index.html

# XML report (for CI)
pytest --cov=src --cov-report=xml
```

### Coverage Configuration

Configured in `pytest.ini`:

```ini
[pytest]
addopts =
    --cov=src
    --cov=lambda_functions
    --cov-report=term-missing
    --cov-report=html

[coverage:report]
exclude_lines =
    pragma: no cover
    def __repr__
    raise NotImplementedError
    if __name__ == .__main__.:
    @abstractmethod
```

## Debugging Tests

### Run Specific Test

```bash
pytest tests/unit/detection/executors/test_athena.py::TestAthenaValidation::test_validate_select_query -v
```

### Detailed Output

```bash
pytest -vv -s --tb=long
```

### Drop into Debugger on Failure

```bash
pytest --pdb
```

### Run Last Failed Tests

```bash
pytest --lf
```

### Show Print Statements

```bash
pytest -s
```

## Performance Testing

### Benchmarking

```python
import pytest

@pytest.mark.benchmark
def test_query_conversion_performance(benchmark):
    """Benchmark Sigma to SQL conversion"""
    converter = SigmaRuleConverter(backend_type="athena")

    result = benchmark(
        converter.convert_rule_to_sql,
        "rules/sigma/aws/cloudtrail/brute_force_login.yml"
    )

    assert result is not None
```

### Profiling

```bash
# Profile test execution
pytest --profile

# Profile with profiling data
pytest --profile-svg
```

## Best Practices

1. **Test one thing per test** - Each test should verify one specific behavior
2. **Use descriptive names** - Test names should describe what they test
3. **Arrange-Act-Assert** - Structure tests clearly:
   ```python
   def test_example():
       # Arrange
       executor = create_executor()

       # Act
       result = executor.execute_query("SELECT 1")

       # Assert
       assert result.row_count == 1
   ```

4. **Mock external dependencies** - Don't call real AWS/GCP/Azure services
5. **Use fixtures for common setup** - Share setup code via fixtures
6. **Test edge cases** - Empty results, errors, timeouts, etc.
7. **Keep tests fast** - Unit tests should run in <1s
8. **Maintain test independence** - Tests should not depend on each other
9. **Clean up resources** - Use fixtures with cleanup or context managers
10. **Document complex tests** - Add docstrings explaining what's being tested

## Troubleshooting

### Import Errors

Ensure src is in PYTHONPATH:
```bash
export PYTHONPATH="${PYTHONPATH}:${PWD}/src"
```

### AWS Credential Errors

Tests use moto for mocking - no real credentials needed.

### pySigma Not Available

Install Sigma dependencies:
```bash
pip install pysigma pysigma-backend-athena
```

Sigma tests will be skipped if not installed.

### Slow Tests

Run only fast tests:
```bash
pytest -m "not slow"
```

### Debugging Failed Tests

```bash
# Show full traceback
pytest --tb=long

# Show local variables
pytest --showlocals

# Drop into debugger
pytest --pdb

# Run specific failing test
pytest tests/path/to/test.py::test_name -vv
```

## Resources

- [pytest Documentation](https://docs.pytest.org/)
- [pytest-cov Documentation](https://pytest-cov.readthedocs.io/)
- [moto Documentation](http://docs.getmoto.org/)
- [unittest.mock Guide](https://docs.python.org/3/library/unittest.mock.html)
- [README_TESTING.md](../../README_TESTING.md) - Comprehensive testing guide
