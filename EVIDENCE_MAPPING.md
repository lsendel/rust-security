# 📁 Evidence Collection - Local Disk Mapping

## ✅ **Current Volume Mappings**

### Docker Compose Volumes
```yaml
e2e-tests:
  volumes:
    - ./reports:/app/reports      # Test reports
    - ./evidence:/app/evidence    # Screenshots & evidence
    - ./tests:/app/tests:ro       # Test files (read-only)
```

### Test Results Viewer
```yaml
test-viewer:
  volumes:
    - ./reports:/usr/share/nginx/html:ro    # Web-accessible reports
```

## 📂 **Local Directory Structure**

```
/Users/lsendel/IdeaProjects/rust-security/e2e-testing/
├── evidence/                    # 🎯 EVIDENCE COLLECTION
│   ├── working-e2e/            # Test suite evidence
│   │   ├── *.png              # Screenshots
│   │   └── *.json             # Test results
│   └── api-results/            # API test evidence
├── reports/                     # 📊 TEST REPORTS
│   ├── validation/             # URL validation reports
│   │   ├── url-validation-report.json
│   │   └── url-validation-report.html
│   └── coverage/               # Coverage reports
└── test-results/               # 🎭 PLAYWRIGHT REPORTS
    └── *.html                  # Interactive test reports
```

## 🔍 **Current Evidence Files**

### Screenshots
- `evidence/working-e2e/example-page-2025-09-05T18-04-23-346Z.png`
- `evidence/working-e2e/example-page-2025-09-05T18-02-22-562Z.png`

### Test Results
- `evidence/working-e2e/result-2025-09-05T18-04-23-416Z.json`
- `evidence/working-e2e/result-2025-09-05T18-02-22-638Z.json`

### Reports
- `reports/validation/url-validation-report.html` (35,113 bytes)
- `reports/validation/url-validation-report.json` (9,596 bytes)

## 🚀 **Access Methods**

### 1. Direct File Access
```bash
# View evidence directory
ls -la e2e-testing/evidence/

# View screenshots
open e2e-testing/evidence/working-e2e/*.png

# View test results
cat e2e-testing/evidence/working-e2e/*.json
```

### 2. Web Viewer (Optional)
```bash
# Start web viewer for reports
docker-compose --profile viewer up test-viewer

# Access at: http://localhost:8082
```

### 3. Playwright Reports
```bash
# Generate and view Playwright HTML report
cd e2e-testing && npx playwright show-report
```

## 📊 **Evidence Collection Commands**

### Generate Evidence
```bash
# Run tests with evidence collection
make test-e2e-smoke

# Run with screenshots
cd e2e-testing && npx playwright test --reporter=html

# Generate coverage reports
make test-coverage
```

### View Evidence
```bash
# Open evidence directory
open e2e-testing/evidence/

# View latest screenshots
open e2e-testing/evidence/working-e2e/*.png

# View HTML reports
open e2e-testing/reports/validation/url-validation-report.html
```

## 🎯 **Evidence Types Collected**

1. **Screenshots**: Full-page captures during test execution
2. **Test Results**: JSON files with test outcomes and timing
3. **Network Logs**: API request/response data (when available)
4. **Coverage Reports**: HTML and JSON coverage data
5. **URL Validation**: Endpoint accessibility reports
6. **Performance Metrics**: Response times and benchmarks

## ✅ **Verification**

Evidence collection is **WORKING** and mapped to your local disk at:
`/Users/lsendel/IdeaProjects/rust-security/e2e-testing/evidence/`

All test artifacts are automatically saved and accessible locally! 🎉
