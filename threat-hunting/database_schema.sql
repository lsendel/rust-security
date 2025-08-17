-- Comprehensive Database Schema for Threat Hunting Toolkit
-- PostgreSQL 13+ compatible

-- Drop existing tables if they exist (for development/testing)
-- Uncomment the following lines if you need to recreate the schema
-- DROP TABLE IF EXISTS response_plans CASCADE;
-- DROP TABLE IF EXISTS attack_sequences CASCADE;
-- DROP TABLE IF EXISTS threat_signatures CASCADE;
-- DROP TABLE IF EXISTS threat_indicators CASCADE;
-- DROP TABLE IF EXISTS threat_enrichments CASCADE;
-- DROP TABLE IF EXISTS user_risk_assessments CASCADE;
-- DROP TABLE IF EXISTS attack_pattern_rules CASCADE;
-- DROP TABLE IF EXISTS threat_whitelist CASCADE;
-- DROP TABLE IF EXISTS security_events CASCADE;

-- Main security events table
CREATE TABLE IF NOT EXISTS security_events (
    event_id VARCHAR(255) PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical', 'warning')),
    source VARCHAR(100) NOT NULL,
    client_id VARCHAR(255),
    user_id VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    request_id VARCHAR(255),
    session_id VARCHAR(255),
    description TEXT NOT NULL,
    details JSONB DEFAULT '{}',
    outcome VARCHAR(50) NOT NULL,
    resource VARCHAR(255),
    action VARCHAR(100),
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    location VARCHAR(255),
    device_fingerprint VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Threat intelligence indicators
CREATE TABLE IF NOT EXISTS threat_indicators (
    indicator VARCHAR(255) PRIMARY KEY,
    indicator_type VARCHAR(50) NOT NULL CHECK (indicator_type IN ('ip', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256')),
    threat_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    confidence FLOAT NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    source VARCHAR(100) NOT NULL,
    description TEXT,
    tags JSONB DEFAULT '[]',
    ttl INTEGER NOT NULL DEFAULT 604800, -- 7 days in seconds
    false_positive_probability FLOAT DEFAULT 0.1 CHECK (false_positive_probability >= 0 AND false_positive_probability <= 1),
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Detected threat signatures
CREATE TABLE IF NOT EXISTS threat_signatures (
    threat_id VARCHAR(255) PRIMARY KEY,
    threat_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    confidence FLOAT NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    indicators JSONB DEFAULT '[]',
    affected_entities JSONB DEFAULT '[]',
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    mitigation_actions JSONB DEFAULT '[]',
    related_events JSONB DEFAULT '[]',
    status VARCHAR(50) DEFAULT 'active' CHECK (status IN ('active', 'investigating', 'resolved', 'false_positive')),
    assigned_to VARCHAR(255),
    resolution_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Attack sequences and patterns
CREATE TABLE IF NOT EXISTS attack_sequences (
    sequence_id VARCHAR(255) PRIMARY KEY,
    attack_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    confidence FLOAT NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL,
    affected_entities JSONB DEFAULT '[]',
    source_ips JSONB DEFAULT '[]',
    pattern_signature TEXT,
    complexity_score INTEGER CHECK (complexity_score >= 1 AND complexity_score <= 10),
    mitigation_priority VARCHAR(50) CHECK (mitigation_priority IN ('low', 'medium', 'high', 'urgent', 'immediate')),
    recommended_actions JSONB DEFAULT '[]',
    step_count INTEGER DEFAULT 0,
    status VARCHAR(50) DEFAULT 'active' CHECK (status IN ('active', 'investigating', 'resolved', 'false_positive')),
    analyst_notes TEXT,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User risk assessments
CREATE TABLE IF NOT EXISTS user_risk_assessments (
    assessment_id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    risk_score FLOAT NOT NULL CHECK (risk_score >= 0 AND risk_score <= 1),
    risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('minimal', 'low', 'medium', 'high', 'critical', 'unknown')),
    confidence FLOAT NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    contributing_factors JSONB DEFAULT '[]',
    anomaly_indicators JSONB DEFAULT '[]',
    recommended_actions JSONB DEFAULT '[]',
    model_predictions JSONB DEFAULT '{}',
    assessment_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    baseline_deviation FLOAT,
    behavioral_score FLOAT,
    threat_intel_score FLOAT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Threat enrichments for events
CREATE TABLE IF NOT EXISTS threat_enrichments (
    enrichment_id SERIAL PRIMARY KEY,
    event_id VARCHAR(255) NOT NULL REFERENCES security_events(event_id),
    enrichment_data JSONB NOT NULL DEFAULT '{}',
    risk_enhancement INTEGER DEFAULT 0,
    threat_matches JSONB DEFAULT '[]',
    intelligence_sources JSONB DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(event_id)
);

-- Attack pattern detection rules
CREATE TABLE IF NOT EXISTS attack_pattern_rules (
    rule_id VARCHAR(255) PRIMARY KEY,
    rule_name VARCHAR(255) NOT NULL,
    pattern_type VARCHAR(100) NOT NULL,
    sequence_conditions JSONB NOT NULL,
    time_window_seconds INTEGER NOT NULL DEFAULT 3600,
    minimum_steps INTEGER NOT NULL DEFAULT 2,
    confidence_threshold FLOAT NOT NULL DEFAULT 0.7 CHECK (confidence_threshold >= 0 AND confidence_threshold <= 1),
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    enabled BOOLEAN DEFAULT TRUE,
    false_positive_rate FLOAT DEFAULT 0.1 CHECK (false_positive_rate >= 0 AND false_positive_rate <= 1),
    description TEXT,
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Automated response plans
CREATE TABLE IF NOT EXISTS response_plans (
    plan_id VARCHAR(255) PRIMARY KEY,
    threat_id VARCHAR(255) NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status VARCHAR(50) NOT NULL DEFAULT 'created' CHECK (status IN ('created', 'executing', 'completed', 'failed', 'partially_completed', 'cancelled')),
    escalation_level VARCHAR(20) NOT NULL CHECK (escalation_level IN ('none', 'low', 'medium', 'high', 'critical')),
    executed_actions INTEGER DEFAULT 0,
    failed_actions INTEGER DEFAULT 0,
    total_actions INTEGER DEFAULT 0,
    approval_required BOOLEAN DEFAULT FALSE,
    approved_by VARCHAR(255),
    approved_at TIMESTAMP WITH TIME ZONE,
    plan_data JSONB NOT NULL DEFAULT '{}',
    execution_log JSONB DEFAULT '[]',
    estimated_duration INTEGER, -- in seconds
    actual_duration INTEGER, -- in seconds
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Response actions within plans
CREATE TABLE IF NOT EXISTS response_actions (
    action_id VARCHAR(255) PRIMARY KEY,
    plan_id VARCHAR(255) NOT NULL REFERENCES response_plans(plan_id),
    action_type VARCHAR(100) NOT NULL,
    priority INTEGER NOT NULL DEFAULT 5,
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'failed', 'cancelled', 'requires_approval')),
    parameters JSONB DEFAULT '{}',
    result JSONB DEFAULT '{}',
    error_message TEXT,
    requires_approval BOOLEAN DEFAULT FALSE,
    approved_by VARCHAR(255),
    approved_at TIMESTAMP WITH TIME ZONE,
    timeout_seconds INTEGER DEFAULT 300,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Threat intelligence whitelist
CREATE TABLE IF NOT EXISTS threat_whitelist (
    whitelist_id SERIAL PRIMARY KEY,
    indicator VARCHAR(255) NOT NULL,
    indicator_type VARCHAR(50) NOT NULL,
    reason TEXT NOT NULL,
    added_by VARCHAR(255),
    active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(indicator)
);

-- ML model metadata and performance tracking
CREATE TABLE IF NOT EXISTS ml_models (
    model_id VARCHAR(255) PRIMARY KEY,
    model_name VARCHAR(255) NOT NULL,
    model_type VARCHAR(100) NOT NULL, -- isolation_forest, lstm_behavioral, risk_classifier
    version VARCHAR(50) NOT NULL,
    accuracy FLOAT,
    precision_score FLOAT,
    recall FLOAT,
    f1_score FLOAT,
    training_data_size INTEGER,
    training_date TIMESTAMP WITH TIME ZONE,
    model_path VARCHAR(500),
    hyperparameters JSONB DEFAULT '{}',
    feature_importance JSONB DEFAULT '{}',
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User behavioral baselines
CREATE TABLE IF NOT EXISTS user_baselines (
    baseline_id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    baseline_type VARCHAR(100) NOT NULL, -- timing, location, device, etc.
    baseline_data JSONB NOT NULL,
    confidence FLOAT DEFAULT 0.5,
    sample_size INTEGER,
    last_updated TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, baseline_type)
);

-- Audit log for all threat hunting activities
CREATE TABLE IF NOT EXISTS threat_hunting_audit (
    audit_id SERIAL PRIMARY KEY,
    action_type VARCHAR(100) NOT NULL,
    component VARCHAR(100) NOT NULL,
    user_id VARCHAR(255),
    ip_address INET,
    details JSONB DEFAULT '{}',
    success BOOLEAN NOT NULL,
    error_message TEXT,
    duration_ms INTEGER,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- System configuration and settings
CREATE TABLE IF NOT EXISTS system_configuration (
    config_id VARCHAR(255) PRIMARY KEY,
    component VARCHAR(100) NOT NULL,
    configuration JSONB NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    active BOOLEAN DEFAULT TRUE,
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================
-- INDEXES FOR PERFORMANCE OPTIMIZATION
-- ============================================

-- Security events indexes
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_ip_address ON security_events(ip_address);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_client_id ON security_events(client_id);
CREATE INDEX IF NOT EXISTS idx_security_events_session_id ON security_events(session_id);
CREATE INDEX IF NOT EXISTS idx_security_events_outcome ON security_events(outcome);
CREATE INDEX IF NOT EXISTS idx_security_events_risk_score ON security_events(risk_score);

-- Composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_security_events_user_time ON security_events(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_ip_time ON security_events(ip_address, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_type_time ON security_events(event_type, timestamp DESC);

-- Threat indicators indexes
CREATE INDEX IF NOT EXISTS idx_threat_indicators_type ON threat_indicators(indicator_type);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_source ON threat_indicators(source);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_severity ON threat_indicators(severity);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_active ON threat_indicators(active);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_last_seen ON threat_indicators(last_seen DESC);

-- Attack sequences indexes
CREATE INDEX IF NOT EXISTS idx_attack_sequences_type ON attack_sequences(attack_type);
CREATE INDEX IF NOT EXISTS idx_attack_sequences_severity ON attack_sequences(severity);
CREATE INDEX IF NOT EXISTS idx_attack_sequences_start_time ON attack_sequences(start_time DESC);
CREATE INDEX IF NOT EXISTS idx_attack_sequences_status ON attack_sequences(status);

-- Response plans indexes
CREATE INDEX IF NOT EXISTS idx_response_plans_status ON response_plans(status);
CREATE INDEX IF NOT EXISTS idx_response_plans_threat_type ON response_plans(threat_type);
CREATE INDEX IF NOT EXISTS idx_response_plans_created_at ON response_plans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_response_plans_threat_id ON response_plans(threat_id);

-- User risk assessments indexes
CREATE INDEX IF NOT EXISTS idx_user_risk_user_id ON user_risk_assessments(user_id);
CREATE INDEX IF NOT EXISTS idx_user_risk_level ON user_risk_assessments(risk_level);
CREATE INDEX IF NOT EXISTS idx_user_risk_timestamp ON user_risk_assessments(assessment_timestamp DESC);

-- Response actions indexes
CREATE INDEX IF NOT EXISTS idx_response_actions_plan_id ON response_actions(plan_id);
CREATE INDEX IF NOT EXISTS idx_response_actions_status ON response_actions(status);
CREATE INDEX IF NOT EXISTS idx_response_actions_type ON response_actions(action_type);

-- Audit log indexes
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON threat_hunting_audit(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_component ON threat_hunting_audit(component);
CREATE INDEX IF NOT EXISTS idx_audit_action_type ON threat_hunting_audit(action_type);

-- User baselines indexes
CREATE INDEX IF NOT EXISTS idx_baselines_user_id ON user_baselines(user_id);
CREATE INDEX IF NOT EXISTS idx_baselines_type ON user_baselines(baseline_type);
CREATE INDEX IF NOT EXISTS idx_baselines_updated ON user_baselines(last_updated DESC);

-- ============================================
-- FUNCTIONS AND TRIGGERS
-- ============================================

-- Function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for automatic timestamp updates
CREATE TRIGGER update_security_events_updated_at 
    BEFORE UPDATE ON security_events 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_threat_indicators_updated_at 
    BEFORE UPDATE ON threat_indicators 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_threat_signatures_updated_at 
    BEFORE UPDATE ON threat_signatures 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_attack_sequences_updated_at 
    BEFORE UPDATE ON attack_sequences 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_response_plans_updated_at 
    BEFORE UPDATE ON response_plans 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_threat_enrichments_updated_at 
    BEFORE UPDATE ON threat_enrichments 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_threat_whitelist_updated_at 
    BEFORE UPDATE ON threat_whitelist 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_system_configuration_updated_at 
    BEFORE UPDATE ON system_configuration 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to automatically set completed_at timestamp
CREATE OR REPLACE FUNCTION set_completion_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status IN ('completed', 'failed', 'cancelled') AND OLD.status NOT IN ('completed', 'failed', 'cancelled') THEN
        NEW.completed_at = NOW();
        
        -- Calculate actual duration for response plans
        IF TG_TABLE_NAME = 'response_plans' THEN
            NEW.actual_duration = EXTRACT(EPOCH FROM (NOW() - NEW.created_at))::INTEGER;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for completion timestamps
CREATE TRIGGER set_response_plan_completion 
    BEFORE UPDATE ON response_plans 
    FOR EACH ROW EXECUTE FUNCTION set_completion_timestamp();

CREATE TRIGGER set_response_action_completion 
    BEFORE UPDATE ON response_actions 
    FOR EACH ROW EXECUTE FUNCTION set_completion_timestamp();

-- ============================================
-- VIEWS FOR COMMON QUERIES
-- ============================================

-- View for recent high-risk events
CREATE OR REPLACE VIEW recent_high_risk_events AS
SELECT 
    se.*,
    te.risk_enhancement,
    te.threat_matches
FROM security_events se
LEFT JOIN threat_enrichments te ON se.event_id = te.event_id
WHERE 
    se.timestamp >= NOW() - INTERVAL '24 hours'
    AND (se.risk_score >= 70 OR te.risk_enhancement >= 70)
ORDER BY se.timestamp DESC;

-- View for active threats summary
CREATE OR REPLACE VIEW active_threats_summary AS
SELECT 
    threat_type,
    severity,
    COUNT(*) as count,
    AVG(confidence) as avg_confidence,
    MAX(last_seen) as latest_detection
FROM threat_signatures 
WHERE status = 'active'
GROUP BY threat_type, severity
ORDER BY 
    CASE severity 
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
    END,
    count DESC;

-- View for user risk summary
CREATE OR REPLACE VIEW user_risk_summary AS
SELECT 
    user_id,
    risk_level,
    risk_score,
    confidence,
    assessment_timestamp,
    ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY assessment_timestamp DESC) as rn
FROM user_risk_assessments
WHERE assessment_timestamp >= NOW() - INTERVAL '7 days';

-- View for response plan effectiveness
CREATE OR REPLACE VIEW response_plan_metrics AS
SELECT 
    threat_type,
    status,
    COUNT(*) as plan_count,
    AVG(executed_actions::FLOAT / NULLIF(total_actions, 0)) as success_rate,
    AVG(actual_duration) as avg_duration,
    AVG(CASE WHEN failed_actions > 0 THEN 1 ELSE 0 END) as failure_rate
FROM response_plans 
WHERE created_at >= NOW() - INTERVAL '30 days'
GROUP BY threat_type, status
ORDER BY threat_type, status;

-- ============================================
-- SAMPLE DATA INSERTION (for testing)
-- ============================================

-- Insert sample attack pattern rules
INSERT INTO attack_pattern_rules (rule_id, rule_name, pattern_type, sequence_conditions, time_window_seconds, minimum_steps, confidence_threshold, severity, description) VALUES
('rule_001', 'Credential Stuffing Detection', 'credential_stuffing', 
 '[{"event_type": "authentication_failure", "min_count": 10}, {"unique_users": {"min": 10}}, {"failure_rate": {"min": 0.8}}]',
 300, 3, 0.8, 'high', 'Detects credential stuffing campaigns'),
('rule_002', 'Account Takeover Pattern', 'account_takeover', 
 '[{"event_type": "authentication_failure", "min_count": 5}, {"event_type": "authentication_success", "min_count": 1}, {"location_anomaly": true}]',
 3600, 3, 0.75, 'high', 'Detects potential account takeover sequences'),
('rule_003', 'Brute Force Attack', 'brute_force', 
 '[{"event_type": "authentication_failure", "min_count": 15}, {"time_concentration": true}]',
 900, 2, 0.8, 'medium', 'Detects brute force password attacks')
ON CONFLICT (rule_id) DO NOTHING;

-- Insert sample system configuration
INSERT INTO system_configuration (config_id, component, configuration) VALUES
('behavioral_thresholds', 'behavioral_analyzer', 
 '{"credential_stuffing": {"failed_logins_per_minute": 10, "unique_usernames_per_ip": 20}, "account_takeover": {"location_anomaly_threshold": 1000}}'),
('ml_model_config', 'user_profiler', 
 '{"isolation_forest": {"contamination": 0.1, "n_estimators": 100}, "lstm_behavioral": {"sequence_length": 30, "features": 20}}'),
('threat_feeds', 'threat_intelligence', 
 '{"misp": {"enabled": true, "refresh_interval": 3600}, "virustotal": {"enabled": true, "refresh_interval": 7200}}')
ON CONFLICT (config_id) DO NOTHING;

-- Create a function to cleanup old data
CREATE OR REPLACE FUNCTION cleanup_old_data()
RETURNS void AS $$
BEGIN
    -- Delete security events older than 90 days
    DELETE FROM security_events WHERE timestamp < NOW() - INTERVAL '90 days';
    
    -- Delete expired threat indicators
    DELETE FROM threat_indicators WHERE first_seen + INTERVAL '1 second' * ttl < NOW();
    
    -- Delete resolved threat signatures older than 30 days
    DELETE FROM threat_signatures WHERE status = 'resolved' AND updated_at < NOW() - INTERVAL '30 days';
    
    -- Delete completed response plans older than 60 days
    DELETE FROM response_plans WHERE status IN ('completed', 'failed') AND created_at < NOW() - INTERVAL '60 days';
    
    -- Delete old audit logs (keep 1 year)
    DELETE FROM threat_hunting_audit WHERE timestamp < NOW() - INTERVAL '1 year';
    
    -- Delete old user risk assessments (keep 6 months)
    DELETE FROM user_risk_assessments WHERE assessment_timestamp < NOW() - INTERVAL '6 months';
    
    RAISE NOTICE 'Old data cleanup completed';
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- SECURITY AND PERMISSIONS
-- ============================================

-- Create roles for different access levels
DO $$
BEGIN
    -- Threat hunting analyst role
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'threat_analyst') THEN
        CREATE ROLE threat_analyst;
    END IF;
    
    -- Security administrator role
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'security_admin') THEN
        CREATE ROLE security_admin;
    END IF;
    
    -- Read-only analyst role
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'security_readonly') THEN
        CREATE ROLE security_readonly;
    END IF;
END
$$;

-- Grant appropriate permissions
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO threat_analyst;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO security_readonly;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO security_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO threat_analyst, security_admin;

-- Restrict sensitive operations
REVOKE DELETE ON threat_indicators, attack_pattern_rules FROM threat_analyst;

COMMENT ON TABLE security_events IS 'Central table for all security events from the Rust authentication service';
COMMENT ON TABLE threat_indicators IS 'Threat intelligence indicators from various feeds';
COMMENT ON TABLE attack_sequences IS 'Detected attack patterns and sequences';
COMMENT ON TABLE response_plans IS 'Automated response plans for detected threats';
COMMENT ON TABLE user_risk_assessments IS 'ML-based user risk assessments and behavioral analysis';

-- Success message
DO $$
BEGIN
    RAISE NOTICE 'Threat hunting database schema created successfully!';
    RAISE NOTICE 'Tables created: %, Views created: %, Functions created: %', 
        (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'),
        (SELECT COUNT(*) FROM information_schema.views WHERE table_schema = 'public'),
        (SELECT COUNT(*) FROM information_schema.routines WHERE routine_schema = 'public');
END
$$;