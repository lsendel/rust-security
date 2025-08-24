#!/bin/bash
# Generate code metrics report

set -euo pipefail

echo "📊 Generating code metrics..."

if command -v tokei >/dev/null 2>&1; then
    echo "Lines of code:"
    tokei --exclude target
else
    echo "Install tokei for detailed metrics: cargo install tokei"
fi

echo -e "\nWorkspace structure:"
find . -name "Cargo.toml" -not -path "./target/*" | head -10

echo -e "\nLarge files (>500 lines):"
find . -name "*.rs" -not -path "./target/*" -exec wc -l {} + | awk '$1 > 500 {print $2 ": " $1 " lines"}' | head -10

echo -e "\nTest coverage (if tarpaulin is installed):"
if command -v cargo-tarpaulin >/dev/null 2>&1; then
    cargo tarpaulin --workspace --all-features --skip-clean --out Stdout | tail -1
else
    echo "Install cargo-tarpaulin for coverage: cargo install cargo-tarpaulin"
fi
