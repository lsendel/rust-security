#!/bin/bash

echo "🧹 Cleaning up unused dependencies and imports..."

# Function to remove unused dependencies from a Cargo.toml
cleanup_cargo_toml() {
    local cargo_file="$1"
    echo "📝 Processing $cargo_file..."
    
    # Create backup
    cp "$cargo_file" "${cargo_file}.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Get unused dependencies for this package
    local package_dir=$(dirname "$cargo_file")
    local unused_deps=$(cargo machete --with-metadata "$package_dir" 2>/dev/null | grep "unused" | cut -d':' -f2 | tr -d ' ')
    
    if [ -n "$unused_deps" ]; then
        echo "  Found unused dependencies: $unused_deps"
        # Note: Manual removal needed as cargo machete doesn't auto-remove
    fi
}

# Clean up workspace members
for cargo_file in */Cargo.toml; do
    if [ -f "$cargo_file" ]; then
        cleanup_cargo_toml "$cargo_file"
    fi
done

# Apply cargo fix for unused imports
echo "🔧 Applying automatic fixes for unused imports..."
cargo fix --allow-dirty --allow-staged --all-targets --all-features 2>/dev/null || true

# Format code
echo "🎨 Formatting code..."
cargo fmt --all

echo "✅ Cleanup completed!"
