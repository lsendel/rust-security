#!/bin/bash

echo "🔍 Verifying E2E Test Screenshots..."
echo "=================================="

EVIDENCE_DIR="evidence"
TOTAL_IMAGES=0
VALID_IMAGES=0

# Check if evidence directory exists
if [ ! -d "$EVIDENCE_DIR" ]; then
    echo "❌ Evidence directory not found: $EVIDENCE_DIR"
    exit 1
fi

echo "📂 Scanning evidence directory..."

# Find all PNG files
for img in $(find $EVIDENCE_DIR -name "*.png" -type f); do
    TOTAL_IMAGES=$((TOTAL_IMAGES + 1))
    
    # Check if file exists and is readable
    if [ -r "$img" ]; then
        # Get file size
        SIZE=$(stat -f%z "$img" 2>/dev/null || stat -c%s "$img" 2>/dev/null)
        
        # Check if it's a valid PNG
        if file "$img" | grep -q "PNG image data"; then
            VALID_IMAGES=$((VALID_IMAGES + 1))
            echo "✅ $img (${SIZE} bytes)"
        else
            echo "❌ $img - Invalid PNG format"
        fi
    else
        echo "❌ $img - File not readable"
    fi
done

echo ""
echo "📊 Summary:"
echo "  Total images found: $TOTAL_IMAGES"
echo "  Valid PNG files: $VALID_IMAGES"
echo "  Success rate: $(( VALID_IMAGES * 100 / TOTAL_IMAGES ))%" 2>/dev/null || echo "  Success rate: N/A"

if [ $VALID_IMAGES -gt 0 ]; then
    echo ""
    echo "🎯 Latest screenshots:"
    ls -lht $EVIDENCE_DIR/*/example-*.png 2>/dev/null | head -3
    ls -lht $EVIDENCE_DIR/*/local-*.png 2>/dev/null | head -3
    
    echo ""
    echo "🚀 To view images:"
    echo "  • Open Finder: open $EVIDENCE_DIR"
    echo "  • View in browser: open evidence-viewer.html"
    echo "  • Command line: open $EVIDENCE_DIR/screenshot-validation/*.png"
fi

echo ""
if [ $VALID_IMAGES -eq $TOTAL_IMAGES ] && [ $TOTAL_IMAGES -gt 0 ]; then
    echo "🎉 All screenshots are valid and viewable!"
else
    echo "⚠️  Some issues found with screenshot generation"
fi
