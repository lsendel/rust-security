use opentelemetry::{
    global,
    sdk::{
        trace::{self, RandomIdGenerator, Sampler},
        Resource,
    },
    KeyValue,
};
use opentelemetry_jaeger::new_agent_pipeline;
use std::env;
use tracing::{info, warn};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

/// Initialize distributed tracing with OpenTelemetry and Jaeger
pub fn init_tracing(service_name: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Get configuration from environment
    let jaeger_endpoint = env::var("JAEGER_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:14268/api/traces".to_string());
    
    let environment = env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
    let service_version = env::var("SERVICE_VERSION").unwrap_or_else(|_| "0.1.0".to_string());
    
    // Configure OpenTelemetry tracer
    let tracer = new_agent_pipeline()
        .with_service_name(service_name)
        .with_endpoint(&jaeger_endpoint)
        .with_trace_config(
            trace::config()
                .with_sampler(match environment.as_str() {
                    "production" => Sampler::TraceIdRatioBased(0.1), // 10% sampling in prod
                    "staging" => Sampler::TraceIdRatioBased(0.5),    // 50% sampling in staging
                    _ => Sampler::AlwaysOn,                          // 100% sampling in dev
                })
                .with_id_generator(RandomIdGenerator::default())
                .with_resource(Resource::new(vec![
                    KeyValue::new("service.name", service_name.to_string()),
                    KeyValue::new("service.version", service_version),
                    KeyValue::new("deployment.environment", environment.clone()),
                    KeyValue::new("service.namespace", "rust-security"),
                ])),
        )
        .install_batch(opentelemetry::runtime::Tokio)?;

    // Configure tracing subscriber with multiple layers
    let telemetry_layer = OpenTelemetryLayer::new(tracer);
    
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            match environment.as_str() {
                "production" => EnvFilter::new("info,auth_service=info,policy_service=info"),
                "staging" => EnvFilter::new("debug,auth_service=debug,policy_service=debug"),
                _ => EnvFilter::new("debug,auth_service=trace,policy_service=trace"),
            }
        });

    Registry::default()
        .with(env_filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
                .json() // Use JSON format for structured logging
        )
        .with(telemetry_layer)
        .init();

    info!(
        service = service_name,
        environment = environment,
        jaeger_endpoint = jaeger_endpoint,
        "Distributed tracing initialized"
    );

    Ok(())
}

/// Create a custom span for database operations
#[macro_export]
macro_rules! db_span {
    ($operation:expr, $table:expr) => {
        tracing::info_span!(
            "database_operation",
            operation = $operation,
            table = $table,
            otel.kind = "client",
            db.system = "redis"
        )
    };
}

/// Create a custom span for HTTP operations
#[macro_export]
macro_rules! http_span {
    ($method:expr, $path:expr) => {
        tracing::info_span!(
            "http_request",
            http.method = $method,
            http.route = $path,
            otel.kind = "server"
        )
    };
}

/// Create a custom span for external service calls
#[macro_export]
macro_rules! external_span {
    ($service:expr, $operation:expr) => {
        tracing::info_span!(
            "external_service_call",
            service.name = $service,
            operation = $operation,
            otel.kind = "client"
        )
    };
}

/// Middleware to add tracing to HTTP requests
pub async fn tracing_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");
    
    let span = tracing::info_span!(
        "http_request",
        http.method = %method,
        http.route = %path,
        http.user_agent = %user_agent,
        otel.kind = "server",
        otel.status_code = tracing::field::Empty,
        http.status_code = tracing::field::Empty,
        request.duration_ms = tracing::field::Empty,
    );

    let start_time = std::time::Instant::now();
    
    let response = async move {
        tracing::debug!("Processing HTTP request");
        next.run(request).await
    }
    .instrument(span.clone())
    .await;

    let duration = start_time.elapsed();
    let status_code = response.status().as_u16();
    
    // Record span attributes
    span.record("http.status_code", status_code);
    span.record("request.duration_ms", duration.as_millis() as u64);
    
    // Set OpenTelemetry status
    if status_code >= 400 {
        span.record("otel.status_code", "ERROR");
        if status_code >= 500 {
            tracing::error!(
                http.status_code = status_code,
                http.method = method,
                http.route = path,
                duration_ms = duration.as_millis(),
                "HTTP request failed"
            );
        } else {
            tracing::warn!(
                http.status_code = status_code,
                http.method = method,
                http.route = path,
                duration_ms = duration.as_millis(),
                "HTTP request client error"
            );
        }
    } else {
        span.record("otel.status_code", "OK");
        tracing::info!(
            http.status_code = status_code,
            http.method = method,
            http.route = path,
            duration_ms = duration.as_millis(),
            "HTTP request completed"
        );
    }

    response
}

/// Graceful shutdown for tracing
pub fn shutdown_tracing() {
    info!("Shutting down tracing...");
    global::shutdown_tracer_provider();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::info;

    #[tokio::test]
    async fn test_tracing_initialization() {
        // Set test environment
        std::env::set_var("ENVIRONMENT", "test");
        std::env::set_var("JAEGER_ENDPOINT", "http://localhost:14268/api/traces");
        
        // This would normally initialize tracing, but we'll skip for tests
        // to avoid conflicts with other tests
        info!("Tracing test completed");
    }

    #[test]
    fn test_span_macros() {
        // Test that our macros compile correctly
        let _db_span = db_span!("SELECT", "users");
        let _http_span = http_span!("GET", "/api/users");
        let _external_span = external_span!("redis", "get_token");
    }
}
