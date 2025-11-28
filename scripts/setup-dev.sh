#!/bin/bash
set -e

echo "=========================================="
echo "Mantissa Log - Development Setup"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print colored output
print_status() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check for required tools
echo "Checking for required tools..."
echo ""

MISSING_TOOLS=0

# Python 3.11+
if command_exists python3; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
    REQUIRED_VERSION="3.11"
    if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" = "$REQUIRED_VERSION" ]; then
        print_status "Python $PYTHON_VERSION found"
    else
        print_error "Python $PYTHON_VERSION found, but 3.11+ is required"
        MISSING_TOOLS=1
    fi
else
    print_error "Python 3 not found. Please install Python 3.11 or higher."
    MISSING_TOOLS=1
fi

# Node.js 18+
if command_exists node; then
    NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_VERSION" -ge 18 ]; then
        print_status "Node.js $(node --version) found"
    else
        print_error "Node.js $(node --version) found, but v18+ is required"
        MISSING_TOOLS=1
    fi
else
    print_error "Node.js not found. Please install Node.js 18 or higher."
    MISSING_TOOLS=1
fi

# Terraform
if command_exists terraform; then
    print_status "Terraform $(terraform version -json | grep -o '"terraform_version":"[^"]*' | cut -d'"' -f4) found"
else
    print_warning "Terraform not found. Install if you plan to deploy infrastructure."
fi

# AWS CLI
if command_exists aws; then
    print_status "AWS CLI $(aws --version | cut -d' ' -f1 | cut -d'/' -f2) found"
else
    print_warning "AWS CLI not found. Install if you plan to deploy to AWS."
fi

echo ""

if [ $MISSING_TOOLS -eq 1 ]; then
    print_error "Missing required tools. Please install them and run this script again."
    exit 1
fi

# Create Python virtual environment
echo "Setting up Python environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    print_status "Created Python virtual environment"
else
    print_status "Python virtual environment already exists"
fi

# Activate virtual environment
source venv/bin/activate
print_status "Activated virtual environment"

# Upgrade pip
python -m pip install --upgrade pip > /dev/null 2>&1
print_status "Upgraded pip"

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
pip install -r requirements-dev.txt > /dev/null 2>&1
print_status "Installed Python dependencies"

# Install Node.js dependencies (web interface)
if [ -f "web/package.json" ]; then
    echo ""
    echo "Installing Node.js dependencies for web interface..."
    cd web
    npm install > /dev/null 2>&1
    cd ..
    print_status "Installed Node.js dependencies"
fi

# Set up pre-commit hooks
echo ""
echo "Setting up pre-commit hooks..."
pre-commit install > /dev/null 2>&1
print_status "Installed pre-commit hooks"

# Create initial secrets baseline for detect-secrets
if [ ! -f ".secrets.baseline" ]; then
    detect-secrets scan > .secrets.baseline 2>/dev/null
    print_status "Created secrets detection baseline"
fi

# Create .yamllint.yaml if it doesn't exist
if [ ! -f ".yamllint.yaml" ]; then
    cat > .yamllint.yaml << 'EOF'
extends: default

rules:
  line-length:
    max: 120
    level: warning
  indentation:
    spaces: 2
  comments:
    min-spaces-from-content: 1
EOF
    print_status "Created .yamllint.yaml configuration"
fi

# Summary
echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Activate the virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo "2. Run tests to verify setup:"
echo "   pytest tests/"
echo ""
echo "3. Start developing!"
echo "   - Source code: src/"
echo "   - Detection rules: rules/"
echo "   - Infrastructure: infrastructure/aws/terraform/"
echo "   - Web interface: web/"
echo ""
echo "4. Before committing, pre-commit hooks will run automatically."
echo "   To run manually: pre-commit run --all-files"
echo ""
echo "For more information, see docs/development/local-setup.md"
echo ""
