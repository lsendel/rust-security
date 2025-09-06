#!/bin/bash

# E2E Test Execution Script
# Runs complete test suite with reporting

set -e

echo "🚀 Starting E2E Test Suite..."

# Ensure directories exist
mkdir -p reports evidence config

# Check if services are running
echo "🔍 Checking service availability..."
if ! curl -s http://localhost:8080/health > /dev/null; then
    echo "❌ Auth service not available at http://localhost:8080"
    echo "Please start the services first:"
    echo "  docker-compose up -d"
    exit 1
fi

echo "✅ Services are running"

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
fi

# Run URL validation first
echo "🔗 Running URL validation..."
node utils/url-validator.js

# Run Playwright tests
echo "🎭 Running Playwright tests..."
npx playwright test --reporter=html,json,junit

# Run integrated test suite
echo "🧪 Running integrated test suite..."
npx ts-node run-tests.ts

# Generate final report
echo "📊 Generating final report..."
timestamp=$(date +"%Y%m%d_%H%M%S")
report_dir="reports/e2e_${timestamp}"
mkdir -p "$report_dir"

# Copy all reports to timestamped directory
cp -r reports/* "$report_dir/" 2>/dev/null || true
cp -r evidence/* "$report_dir/" 2>/dev/null || true

echo "✅ E2E tests completed!"
echo "📁 Reports available in: $report_dir"

# Check if any tests failed
if [ -f "reports/quality-gates.json" ]; then
    failed_gates=$(jq -r '.[] | select(.passed == false) | .name' reports/quality-gates.json 2>/dev/null || echo "")
    if [ -n "$failed_gates" ]; then
        echo "❌ Quality gates failed: $failed_gates"
        exit 1
    fi
fi

echo "🎉 All tests passed!"
