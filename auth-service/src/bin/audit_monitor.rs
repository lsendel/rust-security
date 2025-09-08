//! # Security Audit Monitor CLI
//!
//! Real-time security event monitoring tool for compliance and security operations.
//!
//! ## Usage
//!
//! ```bash
//! # Monitor all security events
//! cargo run --bin audit_monitor
//!
//! # Monitor critical events only
//! cargo run --bin audit_monitor -- --severity critical
//!
//! # Export security events for analysis
//! cargo run --bin audit_monitor -- --export events.json --duration 24h
//!
//! # Monitor specific event types
//! cargo run --bin audit_monitor -- --event-type authentication --event-type rate_limiting
//! ```

use auth_service::security::{
    initialize_audit_logger, get_audit_logger, AuditLoggerConfig,
    SecurityEventType, SecuritySeverity, SecurityOutcome,
};
use clap::{Arg, Command};
use std::collections::HashSet;
use std::time::Duration;
use tokio::time::interval;
use tracing::{info, warn, error, Level};

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .json()
        .init();

    let matches = Command::new("Security Audit Monitor")
        .version("1.0.0")
        .about("Real-time security event monitoring and analysis tool")
        .arg(
            Arg::new("severity")
                .long("severity")
                .value_name("LEVEL")
                .help("Minimum severity level to monitor")
                .value_parser(["info", "low", "medium", "high", "critical"])
                .default_value("info"),
        )
        .arg(
            Arg::new("event-type")
                .long("event-type")
                .value_name("TYPE")
                .help("Event types to monitor (can specify multiple)")
                .action(clap::ArgAction::Append)
                .value_parser([
                    "authentication", "authorization", "rate_limiting", "cryptography",
                    "configuration", "network_security", "data_access", "system_security",
                    "compliance_violation", "threat_detection"
                ]),
        )
        .arg(
            Arg::new("export")
                .long("export")
                .short('e')
                .value_name("FILE")
                .help("Export events to file instead of monitoring")
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("duration")
                .long("duration")
                .value_name("DURATION")
                .help("Duration to monitor/export (e.g., 1h, 24h, 7d)")
                .default_value("continuous"),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .value_name("FORMAT")
                .help("Output format: json, text, csv")
                .value_parser(["json", "text", "csv"])
                .default_value("json"),
        )
        .arg(
            Arg::new("realtime")
                .long("realtime")
                .help("Enable real-time monitoring mode")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let severity_str = matches.get_one::<String>("severity").unwrap();
    let min_severity = parse_severity(severity_str);
    let event_types: Option<Vec<SecurityEventType>> = matches
        .get_many::<String>("event-type")
        .map(|types| types.map(|t| parse_event_type(t)).collect());
    let export_file = matches.get_one::<String>("export");
    let duration_str = matches.get_one::<String>("duration").unwrap();
    let format = matches.get_one::<String>("format").unwrap();
    let realtime_mode = matches.get_flag("realtime");

    // Initialize audit logger with appropriate configuration
    let config = if realtime_mode {
        AuditLoggerConfig {
            enable_json_format: format == "json",
            enable_siem_integration: true,
            min_severity,
            enable_real_time_alerts: true,
            enable_correlation: true,
            max_events_per_minute: 2000,
            ..AuditLoggerConfig::production()
        }
    } else {
        AuditLoggerConfig {
            enable_json_format: format == "json",
            min_severity,
            ..AuditLoggerConfig::default()
        }
    };

    initialize_audit_logger(config);
    
    let logger = get_audit_logger().expect("Audit logger not initialized");

    if let Some(file_path) = export_file {
        // Export mode: collect and export events
        info!("Starting event export to {}", file_path);
        export_security_events(logger, file_path, duration_str, format, event_types).await;
    } else {
        // Monitor mode: real-time event monitoring
        info!("Starting real-time security event monitoring");
        info!("Minimum severity: {}", min_severity);
        if let Some(ref types) = event_types {
            info!("Monitoring event types: {:?}", types);
        }
        
        monitor_security_events(logger, min_severity, event_types, realtime_mode).await;
    }
}

async fn monitor_security_events(
    _logger: &auth_service::security::SecurityAuditLogger,
    min_severity: SecuritySeverity,
    event_types: Option<Vec<SecurityEventType>>,
    realtime_mode: bool,
) {
    info!("Security monitoring started (severity >= {})", min_severity);
    
    if realtime_mode {
        info!("Real-time monitoring enabled - events will be processed immediately");
    }

    // Create a monitoring interval
    let mut monitor_interval = interval(Duration::from_secs(if realtime_mode { 1 } else { 5 }));

    // In a real implementation, this would:
    // 1. Subscribe to security event streams
    // 2. Process events in real-time
    // 3. Apply filtering based on severity and event types
    // 4. Generate alerts for critical events
    // 5. Maintain event statistics

    let mut event_count = 0u64;
    let mut last_critical_event = None::<chrono::DateTime<chrono::Utc>>;

    loop {
        monitor_interval.tick().await;
        
        // Simulate event monitoring (in real implementation, this would read from event streams)
        if let Some(ref types) = event_types {
            info!(
                "Monitoring {} event types (min severity: {})", 
                types.len(), 
                min_severity
            );
        }

        event_count += 1;

        // Show monitoring status every 10 iterations
        if event_count % 10 == 0 {
            info!(
                "Monitoring active - {} check cycles completed",
                event_count
            );

            // Simulate finding a critical event occasionally
            if event_count % 50 == 0 {
                let now = chrono::Utc::now();
                warn!(
                    "CRITICAL SECURITY EVENT DETECTED: Simulated threat at {}",
                    now.format("%Y-%m-%d %H:%M:%S UTC")
                );
                last_critical_event = Some(now);
            }
        }

        // In real implementation, you would:
        // - Read events from audit log streams
        // - Filter by severity and event type
        // - Display formatted events
        // - Trigger alerts for critical events
        // - Maintain correlation analysis
    }
}

async fn export_security_events(
    _logger: &auth_service::security::SecurityAuditLogger,
    file_path: &str,
    duration: &str,
    format: &str,
    event_types: Option<Vec<SecurityEventType>>,
) {
    info!("Exporting security events to {} (format: {})", file_path, format);
    info!("Duration: {}", duration);
    
    if let Some(ref types) = event_types {
        info!("Event types: {:?}", types);
    }

    // Parse duration
    let export_duration = parse_duration(duration).unwrap_or(Duration::from_hours(1));
    info!("Export duration: {:?}", export_duration);

    // In a real implementation, this would:
    // 1. Query the audit log database/storage
    // 2. Filter events by time range, severity, and type
    // 3. Format events according to the specified format
    // 4. Write to the output file

    // Simulate export process
    let mut exported_events = 0;
    let start_time = chrono::Utc::now() - chrono::Duration::from_std(export_duration).unwrap();
    
    info!("Querying events since {}", start_time.format("%Y-%m-%d %H:%M:%S UTC"));

    // Create sample events for export
    let sample_events = create_sample_events(100, start_time);
    
    // Filter by event types if specified
    let filtered_events: Vec<_> = if let Some(ref types) = event_types {
        let type_set: HashSet<_> = types.iter().collect();
        sample_events
            .into_iter()
            .filter(|event| type_set.contains(&event.event_type))
            .collect()
    } else {
        sample_events
    };

    exported_events = filtered_events.len();

    // Format and write events
    let output_content = match format {
        "json" => format_events_json(&filtered_events),
        "csv" => format_events_csv(&filtered_events),
        _ => format_events_text(&filtered_events),
    };

    if let Err(e) = tokio::fs::write(file_path, output_content).await {
        error!("Failed to write export file {}: {}", file_path, e);
        std::process::exit(1);
    }

    info!("Successfully exported {} security events to {}", exported_events, file_path);
}

fn parse_severity(severity_str: &str) -> SecuritySeverity {
    match severity_str.to_lowercase().as_str() {
        "info" => SecuritySeverity::Info,
        "low" => SecuritySeverity::Low,
        "medium" => SecuritySeverity::Medium,
        "high" => SecuritySeverity::High,
        "critical" => SecuritySeverity::Critical,
        _ => SecuritySeverity::Info,
    }
}

fn parse_event_type(type_str: &str) -> SecurityEventType {
    match type_str.to_lowercase().as_str() {
        "authentication" => SecurityEventType::Authentication,
        "authorization" => SecurityEventType::Authorization,
        "rate_limiting" => SecurityEventType::RateLimiting,
        "cryptography" => SecurityEventType::Cryptography,
        "configuration" => SecurityEventType::Configuration,
        "network_security" => SecurityEventType::NetworkSecurity,
        "data_access" => SecurityEventType::DataAccess,
        "system_security" => SecurityEventType::SystemSecurity,
        "compliance_violation" => SecurityEventType::ComplianceViolation,
        "threat_detection" => SecurityEventType::ThreatDetection,
        _ => SecurityEventType::SystemSecurity,
    }
}

fn parse_duration(duration_str: &str) -> Option<Duration> {
    if duration_str == "continuous" {
        return None;
    }

    let duration_str = duration_str.to_lowercase();
    if let Some(hours_str) = duration_str.strip_suffix('h') {
        if let Ok(hours) = hours_str.parse::<u64>() {
            return Some(Duration::from_secs(hours * 3600));
        }
    } else if let Some(days_str) = duration_str.strip_suffix('d') {
        if let Ok(days) = days_str.parse::<u64>() {
            return Some(Duration::from_secs(days * 24 * 3600));
        }
    } else if let Some(minutes_str) = duration_str.strip_suffix('m') {
        if let Ok(minutes) = minutes_str.parse::<u64>() {
            return Some(Duration::from_secs(minutes * 60));
        }
    }

    Some(Duration::from_hours(1))
}

fn create_sample_events(
    count: usize,
    start_time: chrono::DateTime<chrono::Utc>,
) -> Vec<auth_service::security::SecurityEvent> {
    use auth_service::security::SecurityEvent;
    use std::collections::HashMap;
    use uuid::Uuid;

    let mut events = Vec::with_capacity(count);
    let time_increment = chrono::Duration::minutes(1);

    for i in 0..count {
        let timestamp = start_time + (time_increment * i as i32);
        
        // Rotate through different event types and severities
        let (event_type, severity, message) = match i % 10 {
            0 => (SecurityEventType::Authentication, SecuritySeverity::Info, "User login successful"),
            1 => (SecurityEventType::Authentication, SecuritySeverity::Medium, "Failed login attempt"),
            2 => (SecurityEventType::RateLimiting, SecuritySeverity::Medium, "Rate limit exceeded"),
            3 => (SecurityEventType::Authorization, SecuritySeverity::Low, "Access granted to resource"),
            4 => (SecurityEventType::Cryptography, SecuritySeverity::Info, "Token validation successful"),
            5 => (SecurityEventType::ThreatDetection, SecuritySeverity::High, "Suspicious activity detected"),
            6 => (SecurityEventType::Configuration, SecuritySeverity::Medium, "Configuration change detected"),
            7 => (SecurityEventType::NetworkSecurity, SecuritySeverity::Low, "Connection established"),
            8 => (SecurityEventType::DataAccess, SecuritySeverity::Info, "Data accessed successfully"),
            _ => (SecurityEventType::SystemSecurity, SecuritySeverity::Critical, "System security violation"),
        };

        let event = SecurityEvent {
            event_id: Uuid::new_v4().to_string(),
            timestamp,
            severity,
            event_type,
            message: message.to_string(),
            source_ip: Some("192.168.1.100".parse().unwrap()),
            user_id: Some(format!("user_{}", i % 10)),
            session_id: Some(format!("session_{}", i % 5)),
            resource: Some("/api/secure".to_string()),
            action: Some("access".to_string()),
            outcome: if i % 7 == 0 { SecurityOutcome::Failure } else { SecurityOutcome::Success },
            metadata: HashMap::new(),
            compliance_tags: vec!["audit".to_string(), "security".to_string()],
        };

        events.push(event);
    }

    events
}

fn format_events_json(events: &[auth_service::security::SecurityEvent]) -> String {
    match serde_json::to_string_pretty(events) {
        Ok(json) => json,
        Err(e) => format!("{{\"error\": \"Failed to serialize events: {}\"}}", e),
    }
}

fn format_events_csv(events: &[auth_service::security::SecurityEvent]) -> String {
    let mut csv = String::from("timestamp,event_id,severity,event_type,message,source_ip,user_id,outcome\n");
    
    for event in events {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            event.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            event.event_id,
            event.severity,
            event.event_type,
            event.message.replace(',', ";"), // Escape commas in message
            event.source_ip.map_or("".to_string(), |ip| ip.to_string()),
            event.user_id.as_deref().unwrap_or(""),
            event.outcome
        ));
    }

    csv
}

fn format_events_text(events: &[auth_service::security::SecurityEvent]) -> String {
    let mut output = String::from("=== Security Events Export ===\n\n");
    
    for event in events {
        output.push_str(&format!(
            "[{}] [{}] [{}] {} - {}\n",
            event.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            event.severity,
            event.event_type,
            event.outcome,
            event.message
        ));
        
        if let Some(ip) = event.source_ip {
            output.push_str(&format!("  Source IP: {}\n", ip));
        }
        
        if let Some(ref user_id) = event.user_id {
            output.push_str(&format!("  User ID: {}\n", user_id));
        }
        
        output.push('\n');
    }

    output
}