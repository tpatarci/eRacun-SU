#!/bin/bash
# Setup Pre-Commit Hooks for eRacun Project
# Ensures code quality and prevents common mistakes

set -e

echo "===================="
echo "Pre-Commit Hook Setup"
echo "===================="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    echo "Install Python 3 and try again"
    exit 1
fi

echo "✓ Python 3 found"

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is required but not installed"
    echo "Install pip3 and try again"
    exit 1
fi

echo "✓ pip3 found"

# Install pre-commit
echo ""
echo "Installing pre-commit..."
pip3 install pre-commit

# Verify installation
if ! command -v pre-commit &> /dev/null; then
    echo "❌ pre-commit installation failed"
    exit 1
fi

echo "✓ pre-commit installed"

# Install pre-commit hooks
echo ""
echo "Installing pre-commit hooks..."
pre-commit install

# Install commit-msg hook (optional)
pre-commit install --hook-type commit-msg

echo "✓ Pre-commit hooks installed"

# Initialize secrets baseline (if not exists)
if [ ! -f .secrets.baseline ]; then
    echo ""
    echo "Initializing secrets baseline..."
    detect-secrets scan > .secrets.baseline 2>/dev/null || echo "{}" > .secrets.baseline
    echo "✓ Secrets baseline initialized"
fi

# Run pre-commit on all files (optional, can be slow)
read -p "Run pre-commit on all files now? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Running pre-commit on all files..."
    pre-commit run --all-files || true
    echo ""
    echo "⚠️  Some checks may have failed - this is normal for first run"
    echo "   Pre-commit will auto-fix many issues on your next commit"
fi

echo ""
echo "=============================="
echo "✅ Pre-Commit Setup Complete!"
echo "=============================="
echo ""
echo "Pre-commit hooks will now run automatically before each commit."
echo ""
echo "To manually run hooks:"
echo "  pre-commit run --all-files       # Run on all files"
echo "  pre-commit run <hook-id>         # Run specific hook"
echo ""
echo "To bypass hooks (use sparingly):"
echo "  git commit --no-verify"
echo ""
echo "To update hooks:"
echo "  pre-commit autoupdate"
echo ""
