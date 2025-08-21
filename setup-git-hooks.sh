#!/bin/bash
# Setup script to install Git hooks for automatic formatting

set -e

echo "Setting up Git hooks for rust-security project..."

# Set Git hooks directory
git config core.hooksPath .githooks

# Make hooks executable
chmod +x .githooks/*

echo "✅ Git hooks installed successfully!"
echo ""
echo "The following pre-commit checks are now active:"
echo "  - cargo fmt (automatic formatting)"
echo "  - cargo clippy (linting)" 
echo "  - cargo check (compilation)"
echo ""
echo "To bypass hooks for emergency commits, use:"
echo "  git commit --no-verify"
echo ""
echo "To manually run formatting anytime:"
echo "  cargo fmt --all"