#!/bin/bash
#
# Build interactive documentation using mdbook

set -e

echo "📚 Building interactive documentation..."

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check if mdbook is installed
if ! command -v mdbook &> /dev/null; then
    echo -e "${YELLOW}⚠️  mdbook not found. Installing...${NC}"
    
    if command -v cargo &> /dev/null; then
        cargo install mdbook
        echo -e "${GREEN}✅ mdbook installed${NC}"
    else
        echo -e "${RED}❌ Cargo not found. Please install Rust first.${NC}"
        exit 1
    fi
fi

# Install useful mdbook plugins
echo "🔧 Installing mdbook plugins..."

if ! mdbook --help | grep -q "test"; then
    echo "  📋 Installing mdbook-test..."
    cargo install mdbook-test || echo "⚠️  mdbook-test installation failed (optional)"
fi

if ! mdbook --help | grep -q "linkcheck"; then
    echo "  🔗 Installing mdbook-linkcheck..."
    cargo install mdbook-linkcheck || echo "⚠️  mdbook-linkcheck installation failed (optional)"
fi

# Create missing directories
echo "📁 Creating directory structure..."
mkdir -p docs/interactive
mkdir -p docs/styles  
mkdir -p docs/scripts

# Validate book configuration
echo "🔍 Validating book configuration..."
if [ ! -f "book.toml" ]; then
    echo -e "${RED}❌ book.toml not found${NC}"
    exit 1
fi

if [ ! -f "docs/SUMMARY.md" ]; then
    echo -e "${RED}❌ docs/SUMMARY.md not found${NC}"
    exit 1
fi

# Test that all links in SUMMARY.md exist
echo "🔗 Checking documentation links..."
while read -r line; do
    if [[ $line =~ \[(.*)\]\((.*)\) ]]; then
        link="${BASH_REMATCH[2]}"
        # Skip external links and anchors
        if [[ $link != http* && $link != "#"* && $link != "mailto:"* ]]; then
            full_path="docs/${link}"
            if [ ! -f "$full_path" ]; then
                echo -e "${YELLOW}⚠️  Missing file: $full_path${NC}"
            fi
        fi
    fi
done < docs/SUMMARY.md

# Build the documentation
echo "🏗️  Building documentation..."
mdbook build

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Documentation built successfully${NC}"
    
    # Show build information
    echo
    echo "📊 Build Summary:"
    echo "  📖 Output directory: book/"
    echo "  🌐 Main file: book/index.html"
    
    # Count pages
    PAGE_COUNT=$(find book/ -name "*.html" | wc -l)
    echo "  📄 Total pages: $PAGE_COUNT"
    
    # Show size
    BOOK_SIZE=$(du -sh book/ | cut -f1)
    echo "  💾 Total size: $BOOK_SIZE"
    
    echo
    echo "🚀 To serve the documentation locally:"
    echo "  mdbook serve --open"
    echo
    echo "🌍 Or open directly in browser:"
    echo "  open book/index.html"
    
else
    echo -e "${RED}❌ Documentation build failed${NC}"
    exit 1
fi

# Optional: Test the documentation
if command -v mdbook-test &> /dev/null; then
    echo
    echo "🧪 Testing documentation examples..."
    if mdbook test; then
        echo -e "${GREEN}✅ All documentation examples passed${NC}"
    else
        echo -e "${YELLOW}⚠️  Some documentation examples failed${NC}"
        echo "This is expected if examples require external dependencies"
    fi
fi

# Optional: Check links
if command -v mdbook-linkcheck &> /dev/null; then
    echo
    echo "🔗 Checking documentation links..."
    if mdbook-linkcheck; then
        echo -e "${GREEN}✅ All links are valid${NC}"
    else
        echo -e "${YELLOW}⚠️  Some links may be broken${NC}"
    fi
fi

echo
echo -e "${GREEN}📚 Interactive documentation is ready!${NC}"