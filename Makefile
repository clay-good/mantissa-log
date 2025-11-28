.PHONY: help test test-unit test-integration test-coverage test-quick clean install lint format

help:
	@echo "Mantissa Log - Development Commands"
	@echo "===================================="
	@echo ""
	@echo "Testing:"
	@echo "  make test              - Run all tests"
	@echo "  make test-unit         - Run unit tests only"
	@echo "  make test-integration  - Run integration tests only"
	@echo "  make test-executors    - Run query executor tests"
	@echo "  make test-sigma        - Run Sigma conversion tests"
	@echo "  make test-multi-cloud  - Run multi-cloud tests"
	@echo "  make test-coverage     - Run tests with coverage report"
	@echo "  make test-quick        - Run quick smoke tests"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint              - Run linters (flake8, pylint)"
	@echo "  make format            - Format code with black"
	@echo "  make type-check        - Run mypy type checking"
	@echo ""
	@echo "Setup:"
	@echo "  make install           - Install dependencies"
	@echo "  make clean             - Clean build artifacts"

test:
	@./scripts/run-tests.sh all

test-unit:
	@./scripts/run-tests.sh unit

test-integration:
	@./scripts/run-tests.sh integration

test-executors:
	@./scripts/run-tests.sh executors

test-sigma:
	@./scripts/run-tests.sh sigma

test-multi-cloud:
	@./scripts/run-tests.sh multi-cloud

test-coverage:
	@./scripts/run-tests.sh coverage

test-quick:
	@./scripts/run-tests.sh quick

lint:
	@echo "Running flake8..."
	@flake8 src/ lambda_functions/ tests/ --max-line-length=120 --exclude=node_modules,venv,.venv || true
	@echo ""
	@echo "Running pylint..."
	@pylint src/ lambda_functions/ --max-line-length=120 --disable=C0111 || true

format:
	@echo "Formatting code with black..."
	@black src/ lambda_functions/ tests/ --line-length=100

type-check:
	@echo "Running mypy type checking..."
	@mypy src/ lambda_functions/ --ignore-missing-imports || true

install:
	@echo "Installing Python dependencies..."
	@pip install -r requirements.txt
	@pip install -r requirements-dev.txt
	@echo ""
	@echo "Installing web dependencies..."
	@cd web && npm install

clean:
	@echo "Cleaning build artifacts..."
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@rm -rf .pytest_cache
	@rm -rf htmlcov
	@rm -rf .coverage
	@rm -rf dist
	@rm -rf build
	@echo "Clean complete"
