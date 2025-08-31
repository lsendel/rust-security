#!/bin/bash

# Automated Refactoring Tools - Smart code improvements and clean code enforcement
# Detects and fixes common code quality issues automatically

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REFACTOR_CONFIG="$PROJECT_ROOT/.auto-refactor.conf"
BACKUP_DIR="$PROJECT_ROOT/target/refactor-backups"

# Default settings
MAX_FUNCTION_LINES=50
MAX_COMPLEXITY=10
MIN_TEST_COVERAGE=90
DRY_RUN=false
BACKUP_ENABLED=true
VERBOSE=false

# Load configuration
if [ -f "$REFACTOR_CONFIG" ]; then
    source "$REFACTOR_CONFIG"
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔧 Automated Refactoring Tools - Smart Code Improvements${NC}"
echo "=========================================================="

# Function to create backup
create_backup() {
    local file="$1"

    if [ "$BACKUP_ENABLED" = true ]; then
        local backup_file="$BACKUP_DIR/$(basename "$file")-$(date +%Y%m%d-%H%M%S).bak"
        mkdir -p "$BACKUP_DIR"
        cp "$file" "$backup_file"

        if [ "$VERBOSE" = true ]; then
            echo "💾 Backup created: $backup_file"
        fi
    fi
}

# Function to log refactoring action
log_refactor() {
    local action="$1"
    local file="$2"
    local details="$3"
    local timestamp=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

    mkdir -p "$PROJECT_ROOT/quality-monitoring"
    echo "$timestamp [$action] $file: $details" >> "$PROJECT_ROOT/quality-monitoring/refactor.log"

    if [ "$VERBOSE" = true ]; then
        echo -e "${GREEN}✨ $action: $file - $details${NC}"
    fi
}

# Function to fix naming conventions
fix_naming_conventions() {
    echo "🏷️  Fixing naming conventions..."

    find "$PROJECT_ROOT" -name "*.rs" -not -path "*/target/*" | while read -r file; do
        local changed=false

        # Check if file needs backup
        if grep -q "type_\|Type_\|_type\s*:" "$file" 2>/dev/null; then
            create_backup "$file"
        fi

        # Fix common naming violations with serde attributes
        if sed -i.tmp 's/pub type_:/pub email_type:/g; s/Type_:/EmailType:/g' "$file" 2>/dev/null; then
            if ! cmp -s "$file" "$file.tmp"; then
                rm -f "$file.tmp"
                log_refactor "NAMING" "$file" "Fixed type_ field naming violations"
                changed=true
            else
                rm -f "$file.tmp"
            fi
        fi

        # Fix snake_case violations in struct fields
        if perl -i -pe 's/pub\s+([a-z]+[A-Z][a-zA-Z]*)\s*:/pub \L$1:/g' "$file" 2>/dev/null; then
            log_refactor "NAMING" "$file" "Fixed camelCase to snake_case conversions"
            changed=true
        fi

        # Fix function naming
        if perl -i -pe 's/fn\s+([a-z]+[A-Z][a-zA-Z]*)\s*\(/fn \L$1(/g' "$file" 2>/dev/null; then
            log_refactor "NAMING" "$file" "Fixed function naming to snake_case"
            changed=true
        fi

        if [ "$changed" = true ]; then
            echo "  📝 Updated naming conventions in $(basename "$file")"
        fi
    done
}

# Function to fix error handling patterns
fix_error_handling() {
    echo "🚨 Fixing error handling patterns..."

    find "$PROJECT_ROOT" -name "*.rs" -not -path "*/target/*" | while read -r file; do
        local changed=false

        # Check for panic usage in production code
        if grep -q "panic!\|unwrap()\|expect(" "$file" 2>/dev/null; then
            create_backup "$file"

            # Replace unwrap() with proper error handling
            if sed -i.tmp 's/\.unwrap()/.map_err(|e| format!("Unexpected error: {}", e))?/g' "$file" 2>/dev/null; then
                if ! cmp -s "$file" "$file.tmp"; then
                    rm -f "$file.tmp"
                    log_refactor "ERROR_HANDLING" "$file" "Replaced unwrap() with proper error handling"
                    changed=true
                else
                    rm -f "$file.tmp"
                fi
            fi

            # Replace expect() with proper error handling
            if sed -i.tmp 's/\.expect(\([^)]*\))/.map_err(|e| format!("Error: {}: {}", \1, e))?/g' "$file" 2>/dev/null; then
                if ! cmp -s "$file" "$file.tmp"; then
                    rm -f "$file.tmp"
                    log_refactor "ERROR_HANDLING" "$file" "Replaced expect() with proper error handling"
                    changed=true
                else
                    rm -f "$file.tmp"
                fi
            fi

            # Flag panic! for manual review (don't auto-replace as it needs context)
            if grep -n "panic!" "$file" >/dev/null 2>&1; then
                echo "  ⚠️  Manual review needed for panic! calls in $(basename "$file")"
                grep -n "panic!" "$file" | head -3
            fi
        fi

        if [ "$changed" = true ]; then
            echo "  🛡️  Improved error handling in $(basename "$file")"
        fi
    done
}

# Function to optimize performance patterns
optimize_performance() {
    echo "⚡ Optimizing performance patterns..."

    find "$PROJECT_ROOT" -name "*.rs" -not -path "*/target/*" | while read -r file; do
        local changed=false

        # Check for optimization opportunities
        if grep -q "clone()\|to_owned()\|to_string()" "$file" 2>/dev/null; then
            create_backup "$file"

            # Optimize unnecessary clones in return statements
            if sed -i.tmp 's/return\s\+\([^.]*\)\.clone();/return \1;/g' "$file" 2>/dev/null; then
                if ! cmp -s "$file" "$file.tmp"; then
                    rm -f "$file.tmp"
                    log_refactor "PERFORMANCE" "$file" "Removed unnecessary clone() in return statements"
                    changed=true
                else
                    rm -f "$file.tmp"
                fi
            fi

            # Optimize string conversions
            if sed -i.tmp 's/\.to_string()\(\s*==\s*\)"\([^"]*\)"/\1"\2"/g' "$file" 2>/dev/null; then
                if ! cmp -s "$file" "$file.tmp"; then
                    rm -f "$file.tmp"
                    log_refactor "PERFORMANCE" "$file" "Optimized string comparisons"
                    changed=true
                else
                    rm -f "$file.tmp"
                fi
            fi
        fi

        # Check for lock optimization opportunities
        if grep -q "\.lock()\|\.read()\|\.write()" "$file" 2>/dev/null; then
            # Flag for manual review (automatic lock optimization is risky)
            echo "  🔒 Manual review suggested for lock usage in $(basename "$file")"
            echo "      Consider early drop patterns to reduce lock contention"
        fi

        if [ "$changed" = true ]; then
            echo "  ⚡ Performance optimizations applied to $(basename "$file")"
        fi
    done
}

# Function to improve code documentation
improve_documentation() {
    echo "📚 Improving code documentation..."

    find "$PROJECT_ROOT" -name "*.rs" -not -path "*/target/*" | while read -r file; do
        local changed=false

        # Check for missing error documentation
        if grep -q "pub fn\|pub async fn" "$file" 2>/dev/null; then
            create_backup "$file"

            # Add skeleton error documentation where missing
            python3 << EOF
import re
import sys

def add_error_docs(file_path):
    with open(file_path, 'r') as f:
        content = f.read()

    # Find public functions that return Result but lack # Errors documentation
    pattern = r'(pub (?:async )?fn [^{]+-> Result<[^{]+\{)'
    functions = re.findall(pattern, content)

    if functions:
        # Add placeholder error docs (user should customize)
        for func in functions:
            if '# Errors' not in content[:content.find(func)]:
                # Insert error documentation before function
                content = content.replace(func, '    /// # Errors\n    /// Returns error if operation fails\n    ' + func)

    with open(file_path, 'w') as f:
        f.write(content)

add_error_docs("$file")
EOF

            if [ $? -eq 0 ]; then
                log_refactor "DOCUMENTATION" "$file" "Added skeleton error documentation"
                changed=true
            fi
        fi

        if [ "$changed" = true ]; then
            echo "  📖 Documentation improved in $(basename "$file")"
        fi
    done
}

# Function to apply clippy fixes automatically
apply_clippy_fixes() {
    echo "🔍 Applying automatic clippy fixes..."

    # Run clippy with automatic fixes (safe ones only)
    if cargo clippy --fix --allow-dirty --allow-staged -- \
        -A clippy::needless_return \
        -A clippy::redundant_field_names \
        -A clippy::redundant_closure \
        -A clippy::redundant_pattern_matching \
        -A clippy::unnecessary_mut_passed \
        >/dev/null 2>&1; then

        echo "  ✨ Applied automatic clippy fixes"
        log_refactor "CLIPPY" "multiple files" "Applied safe automatic clippy fixes"
    else
        echo "  ⚠️  Some clippy fixes require manual review"
    fi
}

# Function to format code consistently
format_code() {
    echo "🎨 Formatting code consistently..."

    if cargo fmt --all >/dev/null 2>&1; then
        echo "  ✅ Code formatted successfully"
        log_refactor "FORMATTING" "all files" "Applied consistent code formatting"
    else
        echo "  ❌ Code formatting failed"
        return 1
    fi
}

# Function to detect and suggest refactoring opportunities
detect_refactoring_opportunities() {
    echo "🔎 Detecting refactoring opportunities..."

    local opportunities_file="$PROJECT_ROOT/quality-monitoring/refactor-opportunities.md"

    cat > "$opportunities_file" << 'EOF'
# Refactoring Opportunities

*Generated automatically - Review and apply as appropriate*

## Function Length Analysis
EOF

    # Find long functions
    find "$PROJECT_ROOT" -name "*.rs" -not -path "*/target/*" | while read -r file; do
        awk "
        /fn [^;]*\{/ && !/\/\// {
            start = NR;
            func_line = \$0;
            gsub(/^[[:space:]]*/, \"\", func_line);
            brace_count = gsub(/\{/, \"&\", \$0) - gsub(/\}/, \"&\", \$0);
        }
        brace_count > 0 {
            brace_count += gsub(/\{/, \"&\", \$0) - gsub(/\}/, \"&\", \$0);
        }
        brace_count == 0 && start {
            length = NR - start + 1;
            if (length > $MAX_FUNCTION_LINES) {
                print \"### ⚠️  Long Function: \" FILENAME \":\" start \" (\" length \" lines)\";
                print \"\\\`\\\`\\\`rust\";
                print func_line;
                print \"\\\`\\\`\\\`\";
                print \"**Suggestion**: Break into smaller, focused functions\";
                print \"\";
            }
            start = 0;
        }
        " "$file" >> "$opportunities_file"
    done

    # Find code duplication opportunities
    echo "## Code Duplication Analysis" >> "$opportunities_file"

    # Simple function name duplication detection
    find "$PROJECT_ROOT" -name "*.rs" -not -path "*/target/*" -exec grep -Hn "fn [a-zA-Z_]" {} \; | \
    sed 's/.*fn \([a-zA-Z_][a-zA-Z0-9_]*\).*/\1/' | \
    sort | uniq -c | awk '$1 > 1 {print "### 🔄 Potential duplicate function name: **" $2 "** (found " $1 " times)"}' >> "$opportunities_file"

    # Add improvement suggestions
    cat >> "$opportunities_file" << 'EOF'

## Suggested Improvements

### Error Handling
- Replace `.unwrap()` with proper error handling using `?` operator
- Add meaningful error context with `.map_err()`
- Document all possible errors with `# Errors` sections

### Performance
- Use `&str` instead of `String` for read-only parameters
- Consider `Cow<str>` for conditional ownership
- Implement early drop patterns for locks
- Use `const fn` where possible

### Code Organization
- Extract large functions into smaller, focused ones
- Use traits for common behavior patterns
- Consider builder patterns for complex constructors
- Group related functionality into modules

### Testing
- Add property-based tests for validation functions
- Implement integration tests for critical workflows
- Use test fixtures for complex test data
- Add benchmark tests for performance-critical code
EOF

    echo "  📋 Refactoring opportunities documented in $opportunities_file"
}

# Function to run comprehensive refactoring
run_comprehensive_refactoring() {
    local start_time=$(date +%s)

    echo -e "${GREEN}🚀 Starting comprehensive refactoring process...${NC}"

    # Ensure we're in a Rust project
    if [ ! -f "$PROJECT_ROOT/Cargo.toml" ]; then
        echo -e "${RED}❌ Not a Rust project. Please run from project root.${NC}"
        return 1
    fi

    # Create backup directory
    mkdir -p "$BACKUP_DIR"

    # Run initial compilation check
    echo "🔧 Running initial compilation check..."
    if ! cargo check --all-targets --all-features >/dev/null 2>&1; then
        echo -e "${RED}❌ Project has compilation errors. Fix these first.${NC}"
        return 1
    fi

    # Apply refactoring steps
    if [ "$DRY_RUN" = false ]; then
        fix_naming_conventions
        fix_error_handling
        optimize_performance
        improve_documentation
        apply_clippy_fixes
        format_code
    else
        echo "🔍 DRY RUN MODE - No files will be modified"
    fi

    # Always detect opportunities
    detect_refactoring_opportunities

    # Run final validation
    echo "✅ Running final validation..."
    if cargo check --all-targets --all-features >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Refactoring completed successfully${NC}"

        # Run tests to ensure nothing broke
        if cargo test --lib >/dev/null 2>&1; then
            echo -e "${GREEN}✅ All tests still passing${NC}"
        else
            echo -e "${YELLOW}⚠️  Some tests are failing - review changes${NC}"
        fi
    else
        echo -e "${RED}❌ Refactoring introduced compilation errors${NC}"
        echo "📋 Check the refactor log and review recent changes"
        return 1
    fi

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    echo -e "\n${BLUE}📊 Refactoring Summary:${NC}"
    echo "⏱️  Duration: ${duration}s"
    echo "💾 Backups: $BACKUP_DIR"
    echo "📋 Log: $PROJECT_ROOT/quality-monitoring/refactor.log"
    echo "🔍 Opportunities: $PROJECT_ROOT/quality-monitoring/refactor-opportunities.md"
}

# Function to setup configuration
setup_configuration() {
    echo "🔧 Setting up refactoring configuration..."

    cat > "$REFACTOR_CONFIG" << 'EOF'
# Automated Refactoring Configuration

# Function length threshold (lines)
MAX_FUNCTION_LINES=50

# Cyclomatic complexity threshold
MAX_COMPLEXITY=10

# Minimum test coverage percentage
MIN_TEST_COVERAGE=90

# Safety settings
DRY_RUN=false              # Set to true to preview changes without applying
BACKUP_ENABLED=true        # Always create backups before refactoring
VERBOSE=false              # Show detailed refactoring actions

# Refactoring rules (true/false)
FIX_NAMING=true           # Fix naming convention violations
FIX_ERROR_HANDLING=true   # Improve error handling patterns
OPTIMIZE_PERFORMANCE=true # Apply performance optimizations
IMPROVE_DOCS=true         # Add missing documentation
APPLY_CLIPPY=true         # Apply safe clippy fixes
FORMAT_CODE=true          # Apply consistent formatting

# Advanced settings
PRESERVE_COMMENTS=true    # Preserve existing comments during refactoring
CHECK_TESTS_AFTER=true    # Run tests after refactoring
REQUIRE_MANUAL_REVIEW=true # Flag certain changes for manual review
EOF

    echo "✅ Configuration created at $REFACTOR_CONFIG"
    echo "📝 Edit this file to customize refactoring behavior"
}

# Function to restore from backup
restore_from_backup() {
    local backup_time="$1"

    if [ -z "$backup_time" ]; then
        echo "Available backups:"
        ls -la "$BACKUP_DIR" 2>/dev/null || echo "No backups found"
        return 1
    fi

    echo "🔄 Restoring from backup timestamp: $backup_time"

    find "$BACKUP_DIR" -name "*-$backup_time.bak" | while read -r backup_file; do
        local original_file=$(basename "$backup_file" | sed "s/-$backup_time\.bak$//")
        local target_path=$(find "$PROJECT_ROOT" -name "$original_file" -not -path "*/target/*" | head -1)

        if [ -n "$target_path" ]; then
            cp "$backup_file" "$target_path"
            echo "  📋 Restored $original_file"
        fi
    done

    echo "✅ Backup restoration completed"
}

# Main execution
main() {
    case "${1:-refactor}" in
        "refactor"|"run"|"auto")
            run_comprehensive_refactoring
            ;;
        "naming")
            fix_naming_conventions
            ;;
        "errors")
            fix_error_handling
            ;;
        "performance"|"perf")
            optimize_performance
            ;;
        "docs"|"documentation")
            improve_documentation
            ;;
        "clippy")
            apply_clippy_fixes
            ;;
        "format")
            format_code
            ;;
        "opportunities"|"detect")
            detect_refactoring_opportunities
            ;;
        "setup"|"config")
            setup_configuration
            ;;
        "restore")
            restore_from_backup "$2"
            ;;
        "dry-run"|"preview")
            DRY_RUN=true
            VERBOSE=true
            run_comprehensive_refactoring
            ;;
        "help"|"-h"|"--help")
            cat << EOF
Automated Refactoring Tools - Usage

Commands:
  refactor, run, auto     Run comprehensive refactoring
  naming                  Fix naming convention issues
  errors                  Improve error handling patterns
  performance, perf       Apply performance optimizations
  docs, documentation     Improve code documentation
  clippy                  Apply clippy fixes
  format                  Format code consistently
  opportunities, detect   Find refactoring opportunities
  setup, config           Create configuration file
  restore <timestamp>     Restore from backup
  dry-run, preview        Preview changes without applying
  help                    Show this help

Configuration:
  Edit $REFACTOR_CONFIG to customize behavior

Examples:
  $0 refactor                    # Run full refactoring
  $0 naming                      # Fix only naming issues
  $0 dry-run                     # Preview all changes
  $0 restore 20240831-143022     # Restore from backup
EOF
            ;;
        *)
            echo "❌ Unknown command: $1"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
