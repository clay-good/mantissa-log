# Test Suite

Comprehensive test suite for Mantissa Log.

## Test Structure

- **unit/**: Unit tests for individual components
- **integration/**: Integration tests for component interactions
- **e2e/**: End-to-end tests for complete workflows
- **fixtures/**: Test data and expected outputs

## Running Tests

```bash
# Run all tests
pytest

# Run specific test directory
pytest tests/unit/

# Run specific test file
pytest tests/unit/parsers/test_cloudtrail.py

# Run tests matching pattern
pytest -k "test_parser"

# Run with coverage
pytest --cov=src --cov-report=html

# Run with verbose output
pytest -v

# Run in parallel (requires pytest-xdist)
pytest -n auto
```

## Test Categories

### Unit Tests

Test individual functions and classes in isolation:

- **parsers/**: Log parser tests
- **detection/**: Detection engine component tests
- **llm/**: LLM query generation tests
- **alerting/**: Alert routing tests

### Integration Tests

Test component interactions:

- **aws/**: AWS service integration tests (requires AWS credentials)
- **detection_pipeline/**: Full detection pipeline tests

### End-to-End Tests

Test complete user workflows:

- **full_pipeline/**: Complete log ingestion to alert delivery

## Test Fixtures

The `fixtures/` directory contains:

- **sample_logs/**: Example log entries for different sources
- **expected_outputs/**: Expected parsed results and alert outputs

## Writing Tests

### Unit Test Example

```python
import pytest
from src.shared.parsers.cloudtrail import CloudTrailParser

def test_cloudtrail_parser_success():
    """Test CloudTrail parser with valid event."""
    parser = CloudTrailParser()
    raw_event = {
        "eventTime": "2025-01-27T12:00:00Z",
        "userIdentity": {"userName": "test-user"},
        "eventName": "GetObject",
        "sourceIPAddress": "192.168.1.1"
    }

    result = parser.parse(raw_event)

    assert result.timestamp == "2025-01-27T12:00:00Z"
    assert result.user == "test-user"
    assert result.action == "GetObject"
    assert result.source_ip == "192.168.1.1"

def test_cloudtrail_parser_missing_field():
    """Test parser handles missing fields gracefully."""
    parser = CloudTrailParser()
    raw_event = {"eventTime": "2025-01-27T12:00:00Z"}

    result = parser.parse(raw_event)

    assert result.timestamp == "2025-01-27T12:00:00Z"
    assert result.user is None
```

### Integration Test Example

```python
import pytest
import boto3
from moto import mock_s3, mock_athena

@mock_s3
@mock_athena
def test_detection_engine_with_athena():
    """Test detection engine executes queries against Athena."""
    # Setup mocked AWS services
    s3 = boto3.client('s3', region_name='us-east-1')
    s3.create_bucket(Bucket='test-logs')

    # Run detection engine
    # ... test implementation
```

## Test Configuration

Test configuration is in `conftest.py`:

- Pytest fixtures
- Mock AWS credentials
- Test database setup
- Common test utilities

## Mocking

Use these libraries for mocking:

- **moto**: Mock AWS services
- **unittest.mock**: Mock Python objects
- **responses**: Mock HTTP requests

## Coverage Requirements

Aim for:

- 80%+ overall coverage
- 90%+ for shared/parsers and shared/detection
- 70%+ for AWS-specific code
- 60%+ for integration tests

View coverage report:

```bash
pytest --cov=src --cov-report=html
open htmlcov/index.html
```

## Continuous Integration

Tests run automatically on:

- Every pull request
- Commits to main branch
- Nightly builds

CI runs:

- All unit tests
- Integration tests (with mocked AWS)
- Linting and security scans
- Coverage reporting

## Performance Tests

For performance-critical code:

```python
import pytest

def test_parser_performance(benchmark):
    """Test parser performance."""
    parser = CloudTrailParser()
    event = {...}

    result = benchmark(parser.parse, event)

    assert benchmark.stats.stats.mean < 0.001  # < 1ms
```

## Test Data

Generate test data:

```bash
python scripts/generate-sample-data.py --output tests/fixtures/sample_logs/
```

## Debugging Tests

```bash
# Drop into debugger on failure
pytest --pdb

# Drop into debugger on first failure
pytest -x --pdb

# Show print statements
pytest -s
```
