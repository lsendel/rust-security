# 🔄 Regression Testing Guide

## Quick Start

### Run Regression Tests
```bash
# Quick regression (2-3 minutes)
make test-regression-quick

# Full regression suite (10-15 minutes)
make test-regression-full

# Security-only regression
make test-regression-security

# Performance regression with baselines
make test-regression-performance
```

### Manual Execution
```bash
# Direct script execution
./scripts/run_regression_tests.sh

# Monitor results
./scripts/monitor_regression.sh

# Compare with baselines
./scripts/compare_baselines.sh
```

## Test Categories

### 1. Authentication Regression
- OAuth 2.0 token flows
- JWT validation
- Password hashing
- Session management
- MFA workflows

### 2. Security Regression  
- Rate limiting
- Input validation
- CSRF protection
- XSS prevention
- SQL injection blocking

### 3. Performance Regression
- Response time baselines
- Memory usage tracking
- Concurrent request handling
- Database query performance

### 4. Database Regression
- Connection pooling
- Transaction handling
- Migration execution
- Data integrity

### 5. API Regression
- Endpoint availability
- Response formats
- Error handling
- Status codes

## Baseline Management

### View Current Baselines
```bash
ls -la tests/baseline/
cat tests/baseline/auth_latency_ms_baseline.txt
```

### Update Baselines (After Verified Improvements)
```bash
# Interactive update
make regression-baseline-update

# Manual update
echo "45" > tests/baseline/auth_latency_ms_baseline.txt
```

## CI/CD Integration

### GitHub Actions
- **Pull Requests**: Quick regression tests
- **Main Branch**: Full regression suite
- **Scheduled**: Daily comprehensive testing

### Local Development
```bash
# Pre-commit hook
git add . && make test-regression-quick && git commit

# Pre-push validation
make test-regression-full
```

## Failure Investigation

### Check Reports
```bash
# Latest regression report
ls -t regression_reports/regression_summary_*.md | head -1

# View specific test logs
cat regression_reports/security_scan_*.log
```

### Common Issues
1. **Performance Regression**: Check baseline comparison
2. **Security Failures**: Review vulnerability scan results
3. **Test Failures**: Check individual test logs
4. **E2E Failures**: Verify service availability

## Monitoring & Alerts

### Success Rate Monitoring
- **Threshold**: 80% minimum success rate
- **Alerts**: Slack notifications for failures
- **Escalation**: Automatic issue creation

### Performance Monitoring
- **Threshold**: 10% performance degradation
- **Baselines**: Updated quarterly or after improvements
- **Tracking**: Historical trend analysis

## Best Practices

### Before Code Changes
1. Run `make test-regression-quick`
2. Ensure all tests pass
3. Check performance impact

### Before Releases
1. Run `make test-regression-full`
2. Review baseline comparisons
3. Update documentation if needed

### After Deployments
1. Monitor regression test results
2. Check for performance degradation
3. Update baselines if improvements verified
