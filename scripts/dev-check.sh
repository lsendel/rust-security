#!/bin/bash
# Quick development check script

set -euo pipefail

echo "🦀 Running quick development checks..."

echo "📎 Running clippy..."
cargo clippy --workspace --all-features

echo "🎨 Checking formatting..."
cargo fmt --all -- --check

echo "🧪 Running tests..."
cargo test --workspace --all-features

echo "✅ All checks passed!"
