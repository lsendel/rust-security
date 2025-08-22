#!/bin/bash
# Workflow Status Dashboard
# Shows the status of all GitHub Actions workflows

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "🚀 Rust Security Platform - Workflow Status Dashboard"
echo "====================================================="
echo ""

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "❌ Not in a git repository"
    exit 1
fi

# Function to check workflow file validity
check_workflow_file() {
    local file="$1"
    local filename=$(basename "$file")
    
    echo "📋 Checking: $filename"
    
    # Check if file is disabled
    if [[ "$filename" == *.disabled ]]; then
        echo "   ⏸️  Status: DISABLED"
        return 0
    fi
    
    # Check for basic YAML syntax
    if ! python3 -c "import yaml; yaml.safe_load(open('$file'))" 2>/dev/null; then
        echo "   ❌ Status: INVALID YAML"
        return 1
    fi
    
    # Check for required fields
    if ! grep -q "^name:" "$file"; then
        echo "   ❌ Status: MISSING NAME"
        return 1
    fi
    
    if ! grep -q "^on:" "$file"; then
        echo "   ❌ Status: MISSING TRIGGERS"
        return 1
    fi
    
    if ! grep -q "^jobs:" "$file"; then
        echo "   ❌ Status: MISSING JOBS"
        return 1
    fi
    
    # Check for timeout specifications
    if ! grep -q "timeout-minutes:" "$file"; then
        echo "   ⚠️  Status: VALID (missing timeouts)"
        return 0
    fi
    
    echo "   ✅ Status: VALID"
    return 0
}

# Function to analyze workflow triggers
analyze_triggers() {
    local file="$1"
    local filename=$(basename "$file")
    
    echo "   🔄 Triggers:"
    
    if grep -q "push:" "$file"; then
        local branches=$(grep -A 5 "push:" "$file" | grep "branches:" | head -1 || echo "")
        if [[ -n "$branches" ]]; then
            echo "      • Push to: $(echo "$branches" | sed 's/.*branches: *\[//' | sed 's/\].*//')"
        else
            echo "      • Push to: all branches"
        fi
    fi
    
    if grep -q "pull_request:" "$file"; then
        echo "      • Pull requests"
    fi
    
    if grep -q "schedule:" "$file"; then
        echo "      • Scheduled"
    fi
    
    if grep -q "workflow_dispatch:" "$file"; then
        echo "      • Manual trigger"
    fi
}

# Function to check for potential conflicts
check_conflicts() {
    echo "🔍 Checking for potential workflow conflicts..."
    echo ""
    
    # Check for workflows that might run on the same triggers
    local main_triggers=$(find "$PROJECT_ROOT/.github/workflows" -name "*.yml" -not -name "*.disabled" -exec grep -l "push:" {} \; | wc -l)
    local pr_triggers=$(find "$PROJECT_ROOT/.github/workflows" -name "*.yml" -not -name "*.disabled" -exec grep -l "pull_request:" {} \; | wc -l)
    
    echo "   📊 Trigger Analysis:"
    echo "      • Workflows with push triggers: $main_triggers"
    echo "      • Workflows with PR triggers: $pr_triggers"
    
    if [[ $main_triggers -gt 3 ]]; then
        echo "   ⚠️  Warning: Many workflows trigger on push - may cause resource conflicts"
    fi
    
    if [[ $pr_triggers -gt 2 ]]; then
        echo "   ⚠️  Warning: Many workflows trigger on PRs - may slow down PR checks"
    fi
    
    echo ""
}

# Function to show workflow recommendations
show_recommendations() {
    echo "💡 Workflow Optimization Recommendations"
    echo "======================================="
    echo ""
    
    local workflow_count=$(find "$PROJECT_ROOT/.github/workflows" -name "*.yml" -not -name "*.disabled" | wc -l)
    
    echo "📈 Current Status:"
    echo "   • Active workflows: $workflow_count"
    echo "   • Disabled workflows: $(find "$PROJECT_ROOT/.github/workflows" -name "*.disabled" | wc -l)"
    echo ""
    
    if [[ $workflow_count -gt 5 ]]; then
        echo "🎯 Recommendations:"
        echo "   • Consider consolidating similar workflows"
        echo "   • Use path filters to reduce unnecessary runs"
        echo "   • Implement workflow dependencies to avoid parallel resource usage"
        echo "   • Use matrix strategies for multi-platform builds"
        echo ""
    fi
    
    echo "🔧 Best Practices:"
    echo "   • Always specify timeout-minutes for jobs"
    echo "   • Use specific action versions (not @main or @master)"
    echo "   • Cache dependencies to speed up builds"
    echo "   • Use fail-fast: false for matrix builds when appropriate"
    echo "   • Implement proper error handling and cleanup"
    echo ""
}

# Main execution
echo "📁 Workflow Directory: $PROJECT_ROOT/.github/workflows"
echo ""

# Check if workflows directory exists
if [[ ! -d "$PROJECT_ROOT/.github/workflows" ]]; then
    echo "❌ No workflows directory found"
    exit 1
fi

# Count workflows
active_count=0
disabled_count=0
invalid_count=0

echo "📋 Workflow Analysis:"
echo "===================="
echo ""

# Analyze each workflow file
for workflow_file in "$PROJECT_ROOT/.github/workflows"/*.yml "$PROJECT_ROOT/.github/workflows"/*.yaml "$PROJECT_ROOT/.github/workflows"/*.disabled; do
    if [[ -f "$workflow_file" ]]; then
        if check_workflow_file "$workflow_file"; then
            if [[ "$(basename "$workflow_file")" == *.disabled ]]; then
                ((disabled_count++))
            else
                ((active_count++))
                analyze_triggers "$workflow_file"
            fi
        else
            ((invalid_count++))
        fi
        echo ""
    fi
done

echo "📊 Summary:"
echo "==========="
echo "   ✅ Active workflows: $active_count"
echo "   ⏸️  Disabled workflows: $disabled_count"
echo "   ❌ Invalid workflows: $invalid_count"
echo ""

# Check for conflicts
check_conflicts

# Show recommendations
show_recommendations

# Exit with appropriate code
if [[ $invalid_count -gt 0 ]]; then
    echo "❌ Some workflows have issues that need to be fixed"
    exit 1
else
    echo "✅ All workflows are valid and ready to run"
    exit 0
fi
