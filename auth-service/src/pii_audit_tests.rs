#[cfg(test)]
use crate::shared::error::AppError;
/// Automated tests to ensure no secrets or tokens are logged at any level
/// This module provides comprehensive testing for PII/SPI redaction compliance
use crate::pii_protection::{DataClassification, PiiSpiRedactor, SensitiveDataType};
#[cfg(test)]
use crate::security_logging::{SecurityEvent, SecurityEventType, SecuritySeverity};

/// Test data samples that should be redacted
pub struct SensitiveTestData {
    pub emails: Vec<&'static str>,
    pub phone_numbers: Vec<&'static str>,
    pub jwt_tokens: Vec<&'static str>,
    pub api_keys: Vec<&'static str>,
    pub ssns: Vec<&'static str>,
    pub credit_cards: Vec<&'static str>,
    pub ip_addresses: Vec<&'static str>,
    pub uuids: Vec<&'static str>,
}

impl SensitiveTestData {
    pub fn new() -> Self {
        Self {
            emails: vec![
                "user@example.com",
                "admin@company.org",
                "test.email+tag@domain.co.uk",
            ],
            phone_numbers: vec![
                "555-123-4567",
                "1-800-555-1234",
                "(555) 987-6543",
            ],
            jwt_tokens: vec![
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJURVNUIiwibmFtZSI6IkZBS0UiLCJpYXQiOjB9.TEST_SIGNATURE_NOT_REAL",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJURVNUIiwic3ViIjoiRkFLRSJ9.MOCK_SIGNATURE_FOR_TESTING",
            ],
            api_keys: vec![
                "sk_test_FAKE_KEY_FOR_TESTING_ONLY_NOT_REAL",
                "pk_live_MOCK_KEY_FOR_REDACTION_TESTS_ONLY",
                "api_key_TEST_DATA_NOT_A_REAL_SECRET_KEY",
            ],
            ssns: vec![
                "123-45-6789",
                "987654321",
                "555-12-3456",
            ],
            credit_cards: vec![
                "4111-1111-1111-1111",
                "5555 5555 5555 4444",
                "378282246310005",
            ],
            ip_addresses: vec![
                "192.168.1.1",
                "10.0.0.1",
                "172.16.254.1",
                "2001:db8:85a3::8a2e:370:7334",
            ],
            uuids: vec![
                "123e4567-e89b-12d3-a456-426614174000",
                "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
                "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            ],
        }
    }

    /// Get all sensitive data as a single vector for testing
    pub fn all_sensitive_data(&self) -> Vec<&'static str> {
        let mut all_data = Vec::new();
        all_data.extend(&self.emails);
        all_data.extend(&self.phone_numbers);
        all_data.extend(&self.jwt_tokens);
        all_data.extend(&self.api_keys);
        all_data.extend(&self.ssns);
        all_data.extend(&self.credit_cards);
        all_data.extend(&self.ip_addresses);
        all_data.extend(&self.uuids);
        all_data
    }
}

/// Audit trail for redaction events
#[derive(Debug, Clone)]
pub struct RedactionAudit {
    pub original_content: String,
    pub redacted_content: String,
    pub sensitive_types_found: Vec<SensitiveDataType>,
    pub redaction_count: usize,
    pub classification_level: DataClassification,
}

impl RedactionAudit {
    pub fn new(original: &str, redacted: &str, redactor: &PiiSpiRedactor) -> Self {
        let sensitive_types = redactor.contains_sensitive_data(original);
        let redaction_count = if original != redacted { 1 } else { 0 };

        // Determine the highest classification level found
        let classification_level = sensitive_types
            .iter()
            .map(|t| t.classification())
            .max()
            .unwrap_or(DataClassification::Public);

        Self {
            original_content: original.to_string(),
            redacted_content: redacted.to_string(),
            sensitive_types_found: sensitive_types,
            redaction_count,
            classification_level,
        }
    }

    /// Check if redaction was applied when it should have been
    pub fn is_compliant(&self) -> bool {
        if self.sensitive_types_found.is_empty() {
            // No sensitive data found, so no redaction expected
            self.original_content == self.redacted_content
        } else {
            // Sensitive data found, redaction should have occurred
            self.original_content != self.redacted_content
                && !self.contains_original_sensitive_data()
        }
    }

    /// Check if the redacted content still contains original sensitive data
    pub fn contains_original_sensitive_data(&self) -> bool {
        let redactor = PiiSpiRedactor::new();
        !redactor
            .contains_sensitive_data(&self.redacted_content)
            .is_empty()
    }

    /// Get compliance score (0.0 to 1.0)
    pub fn compliance_score(&self) -> f64 {
        if self.is_compliant() {
            1.0
        } else {
            let remaining_sensitive = redactor().contains_sensitive_data(&self.redacted_content);
            let original_sensitive = &self.sensitive_types_found;

            if original_sensitive.is_empty() {
                1.0 // No sensitive data, fully compliant
            } else {
                let redacted_count = original_sensitive.len() - remaining_sensitive.len();
                redacted_count as f64 / original_sensitive.len() as f64
            }
        }
    }
}

fn redactor() -> PiiSpiRedactor {
    PiiSpiRedactor::new()
}

/// Comprehensive PII/SPI redaction compliance tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_message_redaction_compliance() {
        let test_data = SensitiveTestData::new();
        let mut audit_results = Vec::new();

        for sensitive_item in test_data.all_sensitive_data() {
            let error_message = format!("Authentication failed for user: {}", sensitive_item);
            let error = crate::shared::error::AppError::InvalidRequest {
                reason: error_message.clone(),
            };

            // Convert error to string representation (this would be logged)
            let error_string = format!("{}", error);

            let redactor = PiiSpiRedactor::new();
            let redacted = redactor.redact_error_message(&error_string);

            let audit = RedactionAudit::new(&error_string, &redacted, &redactor);
            audit_results.push(audit);
        }

        // Check compliance for all audit results
        let mut failed_audits = Vec::new();
        for audit in &audit_results {
            if !audit.is_compliant() {
                failed_audits.push(audit);
            }
        }

        if !failed_audits.is_empty() {
            println!("\n=== PII REDACTION COMPLIANCE FAILURES ===");
            for failure in &failed_audits {
                println!("FAILED: {:?}", failure.sensitive_types_found);
                println!("Original: {}", failure.original_content);
                println!("Redacted: {}", failure.redacted_content);
                println!("Compliance Score: {:.2}", failure.compliance_score());
                println!("---");
            }
        }

        assert!(
            failed_audits.is_empty(),
            "{} error messages failed PII redaction compliance",
            failed_audits.len()
        );
    }

    #[test]
    fn test_security_event_redaction_compliance() {
        let test_data = SensitiveTestData::new();
        let mut audit_results = Vec::new();

        for sensitive_item in test_data.all_sensitive_data() {
            let mut event = SecurityEvent::new(
                SecurityEventType::AuthenticationFailure,
                SecuritySeverity::Medium,
                "auth-service".to_string(),
                format!("Login attempt with data: {}", sensitive_item),
            );

            // Apply PII protection (this simulates what SecurityLogger does)
            event.apply_pii_protection();

            // Serialize to JSON (this is what gets logged)
            let event_json = serde_json::to_string(&event).unwrap();

            let redactor = PiiSpiRedactor::new();
            let original = format!("Login attempt with data: {}", sensitive_item);

            let audit = RedactionAudit::new(&original, &event.description, &redactor);
            audit_results.push(audit);
        }

        // Check compliance
        let failed_count = audit_results
            .iter()
            .filter(|audit| !audit.is_compliant())
            .count();

        assert_eq!(
            failed_count, 0,
            "{} security events failed PII redaction compliance",
            failed_count
        );
    }

    #[test]
    fn test_log_message_redaction_compliance() {
        let test_data = SensitiveTestData::new();

        for sensitive_item in test_data.all_sensitive_data() {
            let log_message = format!("Processing request for {}", sensitive_item);
            let redacted = crate::pii_protection::redact_log(&log_message);

            let redactor = PiiSpiRedactor::new();
            let audit = RedactionAudit::new(&log_message, &redacted, &redactor);

            assert!(
                audit.is_compliant(),
                "Log message redaction failed for: {} -> {}",
                log_message,
                redacted
            );
        }
    }

    #[test]
    fn test_no_false_positives_in_redaction() {
        let safe_content = vec![
            "normal log message",
            "user logged in successfully",
            "processing payment for order 12345",
            "database connection established",
            "API endpoint /users/profile accessed",
        ];

        let redactor = PiiSpiRedactor::new();

        for content in safe_content {
            let redacted = redactor.redact_log_message(content);
            assert_eq!(
                content, redacted,
                "False positive: safe content was incorrectly redacted: {} -> {}",
                content, redacted
            );
        }
    }

    #[test]
    fn test_mixed_content_redaction() {
        let mixed_content = vec![
            "User john.doe@company.com called 555-1234 about order #12345",
            "Payment failed for card 4111-1111-1111-1111 at IP 192.168.1.100",
            "JWT token eyJhbGciOiJIUzI1NiJ9.payload.signature expired for session abc123",
        ];

        let redactor = PiiSpiRedactor::new();

        for content in mixed_content {
            let redacted = redactor.redact_error_message(content);
            let audit = RedactionAudit::new(content, &redacted, &redactor);

            assert!(
                audit.is_compliant(),
                "Mixed content redaction failed:\nOriginal: {}\nRedacted: {}\nScore: {:.2}",
                content,
                redacted,
                audit.compliance_score()
            );

            // Ensure redaction occurred if sensitive data was present
            if !audit.sensitive_types_found.is_empty() {
                assert_ne!(
                    content, redacted,
                    "No redaction occurred despite sensitive data: {}",
                    content
                );
            }
        }
    }

    #[test]
    fn test_classification_levels() {
        let test_cases = vec![
            ("user@test.com", DataClassification::Pii),
            ("123-45-6789", DataClassification::Spi),
            (
                "eyJhbGciOiJIUzI1NiJ9.payload.sig",
                DataClassification::Confidential,
            ),
            ("normal text", DataClassification::Public),
        ];

        let redactor = PiiSpiRedactor::new();

        for (content, expected_classification) in test_cases {
            let redacted = redactor.redact_text(content, expected_classification.clone());
            let audit = RedactionAudit::new(content, &redacted, &redactor);

            if expected_classification != DataClassification::Public {
                assert!(
                    audit.classification_level as u8 >= expected_classification as u8,
                    "Classification level mismatch for: {}",
                    content
                );
            }
        }
    }

    #[test]
    fn test_comprehensive_pattern_coverage() {
        let redactor = PiiSpiRedactor::new();
        let test_data = SensitiveTestData::new();

        // Test each category of sensitive data
        let categories = vec![
            ("emails", test_data.emails),
            ("phones", test_data.phone_numbers),
            ("jwt_tokens", test_data.jwt_tokens),
            ("api_keys", test_data.api_keys),
            ("ssns", test_data.ssns),
            ("credit_cards", test_data.credit_cards),
            ("ip_addresses", test_data.ip_addresses),
            ("uuids", test_data.uuids),
        ];

        for (category_name, test_items) in categories {
            for item in test_items {
                let sensitive_types = redactor.contains_sensitive_data(item);
                assert!(
                    !sensitive_types.is_empty(),
                    "Failed to detect sensitive data in category '{}': {}",
                    category_name,
                    item
                );

                let redacted = redactor.redact_error_message(item);
                assert_ne!(
                    item, redacted,
                    "Failed to redact sensitive data in category '{}': {}",
                    category_name, item
                );
            }
        }
    }

    /// Generate a comprehensive compliance report
    #[test]
    fn test_generate_compliance_report() {
        let test_data = SensitiveTestData::new();
        let redactor = PiiSpiRedactor::new();
        let mut report = ComplianceReport::new();

        // Test all sensitive data types
        for item in test_data.all_sensitive_data() {
            let redacted_error = redactor.redact_error_message(item);
            let redacted_log = redactor.redact_log_message(item);

            report.add_test_result(item, &redacted_error, &redacted_log, &redactor);
        }

        // Print report for visibility
        println!("\n{}", report.generate_report());

        // Ensure overall compliance
        assert!(
            report.overall_compliance() >= 0.95,
            "Overall PII/SPI compliance below 95%: {:.2}%",
            report.overall_compliance() * 100.0
        );
    }
}

/// Compliance reporting structure
pub struct ComplianceReport {
    pub test_results: Vec<ComplianceTestResult>,
}

pub struct ComplianceTestResult {
    pub test_input: String,
    pub error_redaction: RedactionAudit,
    pub log_redaction: RedactionAudit,
    pub overall_compliance: f64,
}

impl ComplianceReport {
    pub fn new() -> Self {
        Self {
            test_results: Vec::new(),
        }
    }

    pub fn add_test_result(
        &mut self,
        input: &str,
        error_redacted: &str,
        log_redacted: &str,
        redactor: &PiiSpiRedactor,
    ) {
        let error_audit = RedactionAudit::new(input, error_redacted, redactor);
        let log_audit = RedactionAudit::new(input, log_redacted, redactor);

        let overall_compliance =
            (error_audit.compliance_score() + log_audit.compliance_score()) / 2.0;

        self.test_results.push(ComplianceTestResult {
            test_input: input.to_string(),
            error_redaction: error_audit,
            log_redaction: log_audit,
            overall_compliance,
        });
    }

    pub fn overall_compliance(&self) -> f64 {
        if self.test_results.is_empty() {
            return 1.0;
        }

        let total_compliance: f64 = self.test_results.iter().map(|r| r.overall_compliance).sum();

        total_compliance / self.test_results.len() as f64
    }

    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str("=== PII/SPI REDACTION COMPLIANCE REPORT ===\n\n");
        report.push_str(&format!("Total Tests: {}\n", self.test_results.len()));
        report.push_str(&format!(
            "Overall Compliance: {:.2}%\n\n",
            self.overall_compliance() * 100.0
        ));

        let failed_tests: Vec<_> = self
            .test_results
            .iter()
            .filter(|r| r.overall_compliance < 1.0)
            .collect();

        if !failed_tests.is_empty() {
            report.push_str("FAILED TESTS:\n");
            for test in failed_tests {
                report.push_str(&format!(
                    "- Input: {} (Compliance: {:.2}%)\n",
                    test.test_input,
                    test.overall_compliance * 100.0
                ));
            }
            report.push_str("\n");
        } else {
            report.push_str("✅ ALL TESTS PASSED - 100% COMPLIANCE\n\n");
        }

        // Classification breakdown
        let mut classification_counts = std::collections::HashMap::new();
        for result in &self.test_results {
            for data_type in &operation_result.error_redaction.sensitive_types_found {
                let classification = data_type.classification();
                *classification_counts.entry(classification).or_insert(0) += 1;
            }
        }

        report.push_str("DATA CLASSIFICATION BREAKDOWN:\n");
        for (classification, count) in classification_counts {
            report.push_str(&format!("- {:?}: {} items\n", classification, count));
        }

        report
    }
}
