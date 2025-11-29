.PHONY: help test test-unit test-integration test-coverage test-quick clean install lint format
.PHONY: deploy-aws deploy-gcp deploy-azure package-aws package-gcp package-azure
.PHONY: destroy-aws destroy-gcp destroy-azure

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
	@echo "Deployment:"
	@echo "  make deploy-aws        - Deploy to AWS"
	@echo "  make deploy-gcp        - Deploy to GCP"
	@echo "  make deploy-azure      - Deploy to Azure"
	@echo "  make package-aws       - Package AWS Lambda functions"
	@echo "  make package-gcp       - Package GCP Cloud Functions"
	@echo "  make package-azure     - Package Azure Function Apps"
	@echo "  make destroy-aws       - Destroy AWS infrastructure"
	@echo "  make destroy-gcp       - Destroy GCP infrastructure"
	@echo "  make destroy-azure     - Destroy Azure infrastructure"
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
	@flake8 src/ tests/ --max-line-length=120 --exclude=node_modules,venv,.venv || true
	@echo ""
	@echo "Running pylint..."
	@pylint src/ --max-line-length=120 --disable=C0111 || true

format:
	@echo "Formatting code with black..."
	@black src/ tests/ --line-length=100

type-check:
	@echo "Running mypy type checking..."
	@mypy src/ --ignore-missing-imports || true

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

# AWS Deployment
deploy-aws:
	@echo "Deploying to AWS..."
	@./scripts/deploy.sh

package-aws:
	@echo "Packaging AWS Lambda functions..."
	@./scripts/package-lambdas.sh

destroy-aws:
	@echo "Destroying AWS infrastructure..."
	@./scripts/destroy.sh aws

# GCP Deployment
deploy-gcp:
	@echo "Deploying to GCP..."
	@./scripts/deploy-gcp.sh

package-gcp:
	@echo "Packaging GCP Cloud Functions..."
	@echo "GCP uses direct source upload - no packaging needed"

destroy-gcp:
	@echo "Destroying GCP infrastructure..."
	@./scripts/destroy.sh gcp

# Azure Deployment
deploy-azure:
	@echo "Deploying to Azure..."
	@./scripts/deploy-azure.sh

package-azure:
	@echo "Packaging Azure Function Apps..."
	@./scripts/package-azure-functions.sh

destroy-azure:
	@echo "Destroying Azure infrastructure..."
	@./scripts/destroy.sh azure
