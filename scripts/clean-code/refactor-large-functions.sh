#!/bin/bash
# Clean Code: Function Size Optimization
# Identifies and helps refactor large functions

set -euo pipefail

echo "🔧 Function Size Optimization"
echo "============================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
MAX_FUNCTION_SIZE=50
TARGET_SIZE=30
SCAN_DIRS=("auth-service/src" "common/src" "mvp-tools/src")

# Function to count lines in a function
count_function_lines() {
    local file="$1"
    local start_line="$2"
    
    # Count lines until matching closing brace
    awk -v start="$start_line" '
        NR >= start {
            if ($0 ~ /^\s*fn.*\{/ && NR == start) {
                brace_count = 1
                line_count = 1
                next
            }
            if (brace_count > 0) {
                line_count++
                # Count opening braces
                gsub(/[^{]/, "", temp1); gsub(/./, "x", temp1)
                brace_count += length(temp1)
                # Count closing braces  
                gsub(/[^}]/, "", temp2); gsub(/./, "x", temp2)
                brace_count -= length(temp2)
                
                if (brace_count == 0) {
                    print line_count
                    exit
                }
            }
        }
    ' "$file"
}

# Find large functions
find_large_functions() {
    echo -e "${YELLOW}🔍 Scanning for functions larger than $MAX_FUNCTION_SIZE lines...${NC}"
    
    local large_functions=()
    
    for dir in "${SCAN_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            while IFS= read -r -d '' file; do
                # Find function definitions
                grep -n "^\s*\(pub \)\?fn " "$file" | while IFS=: read -r line_num line_content; do
                    if [[ "$line_content" =~ \{ ]]; then
                        local func_lines
                        func_lines=$(count_function_lines "$file" "$line_num")
                        
                        if [[ "$func_lines" -gt "$MAX_FUNCTION_SIZE" ]]; then
                            echo -e "${RED}📏 Large function found:${NC}"
                            echo "   File: $file:$line_num"
                            echo "   Size: $func_lines lines"
                            echo "   Function: $(echo "$line_content" | sed 's/^\s*//')"
                            echo ""
                            
                            large_functions+=("$file:$line_num:$func_lines")
                        fi
                    fi
                done
            done < <(find "$dir" -name "*.rs" -type f -print0)
        fi
    done
    
    if [[ ${#large_functions[@]} -eq 0 ]]; then
        echo -e "${GREEN}✅ No functions larger than $MAX_FUNCTION_SIZE lines found!${NC}"
        return 0
    fi
    
    echo -e "${YELLOW}📊 Summary: ${#large_functions[@]} large functions found${NC}"
    return 1
}

# Generate refactoring suggestions
generate_suggestions() {
    local file="$1"
    local line_num="$2"
    local func_lines="$3"
    
    echo -e "${YELLOW}💡 Refactoring suggestions for $file:$line_num${NC}"
    
    # Extract function content
    local func_content
    func_content=$(sed -n "${line_num},$((line_num + func_lines - 1))p" "$file")
    
    # Analyze function for refactoring opportunities
    echo "   Suggested improvements:"
    
    # Check for multiple responsibilities
    if echo "$func_content" | grep -q "// TODO\|// FIXME\|// NOTE"; then
        echo "   - Address TODO/FIXME comments"
    fi
    
    # Check for nested conditions
    local nesting_level
    nesting_level=$(echo "$func_content" | grep -c "^\s\{8,\}if\|^\s\{8,\}match\|^\s\{8,\}for\|^\s\{8,\}while" || true)
    if [[ "$nesting_level" -gt 3 ]]; then
        echo "   - Extract nested logic into helper functions (nesting level: $nesting_level)"
    fi
    
    # Check for repeated patterns
    if echo "$func_content" | grep -q "\.await\?.*\.await\?.*\.await\?"; then
        echo "   - Consider extracting async operation chains"
    fi
    
    # Check for error handling patterns
    if echo "$func_content" | grep -c "\?" | awk '{if($1>5) print "yes"}' | grep -q "yes"; then
        echo "   - Extract error-prone operations into separate functions"
    fi
    
    echo ""
}

# Create refactoring template
create_refactoring_template() {
    local file="$1"
    local line_num="$2"
    
    local template_file="${file%.rs}_refactor_template.rs"
    
    echo -e "${YELLOW}📝 Creating refactoring template: $template_file${NC}"
    
    cat > "$template_file" << 'EOF'
// Refactoring Template
// Original function was too large - break into smaller, focused functions

// Main function - orchestrates the workflow
pub async fn original_function_name(&self, input: InputType) -> Result<OutputType, ErrorType> {
    let validated_input = self.validate_input(input)?;
    let processed_data = self.process_core_logic(validated_input).await?;
    let result = self.build_result(processed_data)?;
    Ok(result)
}

// Helper function 1 - Single responsibility: Input validation
fn validate_input(&self, input: InputType) -> Result<ValidatedInput, ErrorType> {
    // Move validation logic here
    todo!("Implement validation logic")
}

// Helper function 2 - Single responsibility: Core processing
async fn process_core_logic(&self, input: ValidatedInput) -> Result<ProcessedData, ErrorType> {
    // Move main processing logic here
    todo!("Implement core processing")
}

// Helper function 3 - Single responsibility: Result building
fn build_result(&self, data: ProcessedData) -> Result<OutputType, ErrorType> {
    // Move result construction here
    todo!("Implement result building")
}

// Additional helper functions as needed...
EOF
    
    echo "   Template created with suggested function structure"
    echo ""
}

# Main execution
main() {
    echo "Starting function size analysis..."
    echo ""
    
    if find_large_functions; then
        echo -e "${GREEN}🎉 All functions are within size limits!${NC}"
        exit 0
    fi
    
    echo ""
    echo -e "${YELLOW}🛠️  Refactoring recommendations:${NC}"
    echo ""
    echo "1. Break large functions into smaller, focused functions"
    echo "2. Each function should have a single responsibility"
    echo "3. Extract complex logic into helper functions"
    echo "4. Use descriptive function names that explain purpose"
    echo "5. Keep functions under $TARGET_SIZE lines when possible"
    echo ""
    
    # Offer to create templates
    read -p "Create refactoring templates for large functions? (y/n): " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Creating refactoring templates..."
        # This would need to be implemented based on specific large functions found
        echo "Templates would be created here for each large function"
    fi
    
    echo ""
    echo -e "${GREEN}✅ Function analysis complete${NC}"
    echo "Next steps:"
    echo "1. Review identified large functions"
    echo "2. Apply refactoring suggestions"
    echo "3. Test refactored code thoroughly"
    echo "4. Run this script again to verify improvements"
}

# Run main function
main "$@"
