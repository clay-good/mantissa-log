#!/bin/bash
# Mantissa Log - Test Runner Script
# Run test suites with different configurations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Mantissa Log - Test Runner"
echo "=========================="
echo ""

# Check if pytest is installed
if ! command -v pytest &> /dev/null; then
    echo -e "${RED}Error: pytest is not installed${NC}"
    echo "Install with: pip install pytest pytest-cov"
    exit 1
fi

# Function to run tests with specific marker
run_test_suite() {
    local suite_name=$1
    local marker=$2
    local description=$3

    echo -e "${YELLOW}Running ${suite_name}...${NC}"
    echo "${description}"
    echo ""

    if pytest -v -m "${marker}" --tb=short; then
        echo -e "${GREEN}${suite_name} passed${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}${suite_name} failed${NC}"
        echo ""
        return 1
    fi
}

# Default: run all tests
TEST_SUITE=${1:-all}

case $TEST_SUITE in
    unit)
        echo "Running unit tests only..."
        run_test_suite "Unit Tests" "unit" "Fast, isolated tests"
        ;;

    integration)
        echo "Running integration tests only..."
        run_test_suite "Integration Tests" "integration" "Integration tests with mocked services"
        ;;

    executors)
        echo "Running executor tests..."
        pytest tests/unit/detection/executors/ -v --tb=short
        ;;

    sigma)
        echo "Running Sigma conversion tests..."
        pytest tests/unit/test_sigma_converter.py tests/integration/test_sigma_conversion.py -v --tb=short
        ;;

    multi-cloud)
        echo "Running multi-cloud tests..."
        pytest tests/integration/detection/test_multi_cloud_execution.py \
               tests/integration/detection/test_sigma_multi_cloud.py \
               tests/integration/detection/test_detection_engine_multi_cloud.py \
               -v --tb=short
        ;;

    coverage)
        echo "Running tests with coverage report..."
        pytest --cov=src --cov=lambda_functions \
               --cov-report=term-missing \
               --cov-report=html \
               --cov-report=xml \
               -v
        echo ""
        echo -e "${GREEN}Coverage report generated${NC}"
        echo "HTML report: htmlcov/index.html"
        ;;

    quick)
        echo "Running quick smoke tests..."
        pytest -v --tb=short -x -k "not slow"
        ;;

    all)
        echo "Running all tests..."
        pytest -v --tb=short
        ;;

    *)
        echo -e "${RED}Unknown test suite: ${TEST_SUITE}${NC}"
        echo ""
        echo "Usage: $0 [suite]"
        echo ""
        echo "Available test suites:"
        echo "  unit         - Run unit tests only"
        echo "  integration  - Run integration tests only"
        echo "  executors    - Run query executor tests"
        echo "  sigma        - Run Sigma conversion tests"
        echo "  multi-cloud  - Run multi-cloud tests"
        echo "  coverage     - Run tests with coverage report"
        echo "  quick        - Run quick smoke tests"
        echo "  all          - Run all tests (default)"
        exit 1
        ;;
esac

exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}Some tests failed${NC}"
fi

exit $exit_code
