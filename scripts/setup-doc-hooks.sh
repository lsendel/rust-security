#!/bin/bash
#
# Script to set up documentation validation hooks

set -e

echo "🔧 Setting up documentation validation hooks..."

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Install the documentation validation hook
if [ -f ".githooks/pre-commit-docs" ]; then
    echo "📋 Installing documentation pre-commit hook..."
    
    # Copy to git hooks directory
    cp .githooks/pre-commit-docs .git/hooks/pre-commit-docs
    chmod +x .git/hooks/pre-commit-docs
    
    echo -e "${GREEN}✅ Documentation validation hook installed${NC}"
    echo "  - Location: .git/hooks/pre-commit-docs"
    echo "  - Run manually: .git/hooks/pre-commit-docs"
    
    # Add to existing pre-commit hook or create chained hook
    if [ -f ".git/hooks/pre-commit" ]; then
        echo -e "${YELLOW}⚠️  Existing pre-commit hook found${NC}"
        echo "Consider adding this line to your existing hook:"
        echo "  .git/hooks/pre-commit-docs"
    else
        # Create a simple chaining pre-commit hook
        cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Combined pre-commit hook

set -e

# Run documentation validation
if [ -f ".git/hooks/pre-commit-docs" ]; then
    .git/hooks/pre-commit-docs
fi

# Run other existing hooks if they exist
if [ -f ".githooks/pre-commit" ]; then
    .githooks/pre-commit
fi
EOF
        chmod +x .git/hooks/pre-commit
        echo -e "${GREEN}✅ Combined pre-commit hook created${NC}"
    fi
else
    echo "❌ Documentation hook file not found: .githooks/pre-commit-docs"
    exit 1
fi

echo
echo "🎯 Documentation validation is now active!"
echo
echo "What happens now:"
echo "  • Every commit will validate documentation examples"
echo "  • Rust code blocks in markdown will be checked"
echo "  • Documentation tests will be run"
echo "  • Quality issues will be reported as warnings"
echo
echo "To test the hook manually:"
echo "  .git/hooks/pre-commit-docs"
echo
echo "To bypass the hook (not recommended):"
echo "  git commit --no-verify"