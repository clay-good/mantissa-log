# Test Suite

Comprehensive test suite for Mantissa Log (83 test files).

## Structure

```
tests/
├── unit/                    # Unit tests (49 files)
│   ├── parsers/             # Log parser tests
│   ├── detection/           # Detection engine tests
│   ├── identity/            # ITDR behavioral analysis tests
│   ├── llm/                 # LLM query generation tests
│   ├── alerting/            # Alert routing tests
│   └── ...
├── integration/             # Integration tests (13 files)
│   ├── aws/                 # AWS service integration
│   └── detection_pipeline/  # Full detection pipeline
├── fixtures/                # Test data
│   ├── sample_logs/         # Example log entries per source
│   ├── expected_outputs/    # Expected parsed results
│   └── sample_ir_plans/     # Sample IR plan documents
└── rules/                   # Detection rule validation tests
```

## Running Tests

```bash
# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run all tests
PYTHONPATH=. pytest tests/ -v

# Run by category
pytest tests/unit/ -v                    # Unit tests
pytest tests/integration/ -v             # Integration tests
pytest tests/unit/identity/ -v           # ITDR tests
pytest tests/rules/ -v                   # Rule validation

# Run specific file or pattern
pytest tests/unit/parsers/test_cloudtrail.py -v
pytest -k "test_parser" -v

# Run with coverage
pytest --cov=src --cov-report=html
open htmlcov/index.html

# Run in parallel (requires pytest-xdist)
pytest -n auto
```

## Test Configuration

Configuration is in `pyproject.toml` under `[tool.pytest.ini_options]`:
- Test paths: `tests/`
- Markers: `unit`, `integration`, `e2e`, `slow`, `aws`
- Coverage: automatic `--cov=src` reporting

## Mocking

- **moto**: Mock AWS services (S3, DynamoDB, Athena, Lambda)
- **unittest.mock**: Mock Python objects and modules
- **responses**: Mock HTTP requests to external APIs

## Writing Tests

```python
import pytest
from src.shared.parsers.cloudtrail import CloudTrailParser

def test_cloudtrail_parser_success():
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
```

## Debugging

```bash
# Drop into debugger on failure
pytest --pdb

# Show print output
pytest -s

# Stop on first failure
pytest -x
```
