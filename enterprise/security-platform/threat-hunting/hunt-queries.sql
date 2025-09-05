-- Threat Hunting Query Collection
-- Advanced SQL queries for proactive threat detection and investigation

-- =============================================================================
-- LATERAL MOVEMENT DETECTION
-- =============================================================================

-- Detect potential lateral movement through administrative shares
SELECT 
    timestamp,
    source_ip,
    destination_ip,
    user_name,
    share_name,
    COUNT(*) OVER (PARTITION BY source_ip, user_name ORDER BY timestamp 
                   RANGE BETWEEN INTERVAL '1 hour' PRECEDING AND CURRENT ROW) as connection_count
FROM network_connections 
WHERE share_name IN ('ADMIN$', 'C$', 'IPC$')
    AND timestamp >= NOW() - INTERVAL '24 hours'
    AND connection_count > 5
ORDER BY timestamp DESC;

-- Detect unusual process creation patterns (potential living-off-the-land attacks)
WITH process_baseline AS (
    SELECT 
        process_name,
        parent_process,
        AVG(execution_count) as avg_executions,
        STDDEV(execution_count) as stddev_executions
    FROM (
        SELECT 
            process_name,
            parent_process,
            DATE(timestamp) as day,
            COUNT(*) as execution_count
        FROM process_events
        WHERE timestamp >= NOW() - INTERVAL '30 days'
        GROUP BY process_name, parent_process, DATE(timestamp)
    ) daily_counts
    GROUP BY process_name, parent_process
)
SELECT 
    pe.timestamp,
    pe.hostname,
    pe.process_name,
    pe.parent_process,
    pe.command_line,
    pe.user_name,
    daily_count,
    pb.avg_executions,
    (daily_count - pb.avg_executions) / NULLIF(pb.stddev_executions, 0) as z_score
FROM (
    SELECT 
        timestamp,
        hostname,
        process_name,
        parent_process,
        command_line,
        user_name,
        COUNT(*) OVER (PARTITION BY process_name, parent_process, DATE(timestamp)) as daily_count
    FROM process_events
    WHERE timestamp >= NOW() - INTERVAL '7 days'
) pe
JOIN process_baseline pb ON pe.process_name = pb.process_name 
                         AND pe.parent_process = pb.parent_process
WHERE ABS((daily_count - pb.avg_executions) / NULLIF(pb.stddev_executions, 0)) > 3
ORDER BY z_score DESC;

-- =============================================================================
-- PRIVILEGE ESCALATION HUNTING
-- =============================================================================

-- Detect potential privilege escalation through service creation
SELECT 
    timestamp,
    hostname,
    user_name,
    service_name,
    service_path,
    service_account,
    LAG(user_name) OVER (PARTITION BY hostname ORDER BY timestamp) as previous_user,
    CASE 
        WHEN service_account = 'SYSTEM' OR service_account = 'LocalSystem' THEN 'HIGH'
        WHEN service_account LIKE '%Administrator%' THEN 'MEDIUM'
        ELSE 'LOW'
    END as privilege_level
FROM service_events
WHERE event_type = 'service_created'
    AND timestamp >= NOW() - INTERVAL '24 hours'
    AND (service_account = 'SYSTEM' 
         OR service_account LIKE '%Administrator%'
         OR service_path NOT LIKE 'C:\Windows\%')
ORDER BY timestamp DESC;

-- Hunt for unusual sudo/su usage patterns
WITH sudo_baseline AS (
    SELECT 
        user_name,
        target_user,
        command,
        AVG(daily_usage) as avg_daily_usage,
        STDDEV(daily_usage) as stddev_daily_usage
    FROM (
        SELECT 
            user_name,
            target_user,
            command,
            DATE(timestamp) as day,
            COUNT(*) as daily_usage
        FROM authentication_events
        WHERE event_type IN ('sudo', 'su')
            AND timestamp >= NOW() - INTERVAL '90 days'
        GROUP BY user_name, target_user, command, DATE(timestamp)
    ) daily_sudo
    GROUP BY user_name, target_user, command
)
SELECT 
    ae.timestamp,
    ae.hostname,
    ae.user_name,
    ae.target_user,
    ae.command,
    ae.source_ip,
    daily_count,
    sb.avg_daily_usage,
    CASE 
        WHEN sb.stddev_daily_usage = 0 THEN 999
        ELSE (daily_count - sb.avg_daily_usage) / sb.stddev_daily_usage
    END as anomaly_score
FROM (
    SELECT 
        timestamp,
        hostname,
        user_name,
        target_user,
        command,
        source_ip,
        COUNT(*) OVER (PARTITION BY user_name, target_user, command, DATE(timestamp)) as daily_count
    FROM authentication_events
    WHERE event_type IN ('sudo', 'su')
        AND timestamp >= NOW() - INTERVAL '7 days'
) ae
LEFT JOIN sudo_baseline sb ON ae.user_name = sb.user_name 
                            AND ae.target_user = sb.target_user
                            AND ae.command = sb.command
WHERE (sb.avg_daily_usage IS NULL -- New usage pattern
       OR ABS((daily_count - sb.avg_daily_usage) / NULLIF(sb.stddev_daily_usage, 0)) > 2)
ORDER BY anomaly_score DESC;

-- =============================================================================
-- PERSISTENCE MECHANISM DETECTION
-- =============================================================================

-- Hunt for suspicious scheduled tasks/cron jobs
SELECT 
    timestamp,
    hostname,
    task_name,
    task_command,
    task_schedule,
    created_by,
    run_as_user,
    CASE 
        WHEN task_command LIKE '%powershell%' AND task_command LIKE '%downloadstring%' THEN 'HIGH'
        WHEN task_command LIKE '%certutil%' AND task_command LIKE '%-decode%' THEN 'HIGH'
        WHEN task_command LIKE '%bitsadmin%' THEN 'MEDIUM'
        WHEN task_command LIKE '%wmic%' THEN 'MEDIUM'
        WHEN run_as_user = 'SYSTEM' OR run_as_user = 'root' THEN 'MEDIUM'
        ELSE 'LOW'
    END as suspicion_level
FROM scheduled_tasks
WHERE timestamp >= NOW() - INTERVAL '24 hours'
    AND (task_command LIKE '%powershell%'
         OR task_command LIKE '%cmd.exe%'
         OR task_command LIKE '%bash%'
         OR task_command LIKE '%sh %'
         OR task_command LIKE '%certutil%'
         OR task_command LIKE '%bitsadmin%'
         OR task_command LIKE '%wmic%'
         OR run_as_user IN ('SYSTEM', 'root', 'Administrator'))
ORDER BY 
    CASE suspicion_level 
        WHEN 'HIGH' THEN 1 
        WHEN 'MEDIUM' THEN 2 
        ELSE 3 
    END,
    timestamp DESC;

-- Detect unusual registry modifications (Windows persistence)
SELECT 
    timestamp,
    hostname,
    user_name,
    registry_key,
    registry_value,
    new_data,
    operation_type,
    process_name
FROM registry_events
WHERE timestamp >= NOW() - INTERVAL '24 hours'
    AND (
        -- Run/RunOnce keys
        registry_key LIKE '%\Run%' 
        -- Services
        OR registry_key LIKE '%\Services\%'
        -- Winlogon
        OR registry_key LIKE '%\Winlogon\%'
        -- Image File Execution Options
        OR registry_key LIKE '%\Image File Execution Options\%'
        -- App Init DLLs
        OR registry_key LIKE '%\AppInit_DLLs%'
        -- LSA Authentication Packages
        OR registry_key LIKE '%\Authentication Packages%'
        -- Security Providers
        OR registry_key LIKE '%\Security Providers%'
    )
    AND operation_type IN ('SetValue', 'CreateKey')
ORDER BY timestamp DESC;

-- =============================================================================
-- DATA EXFILTRATION DETECTION
-- =============================================================================

-- Detect unusual file access patterns
WITH file_access_baseline AS (
    SELECT 
        user_name,
        file_path,
        AVG(daily_accesses) as avg_daily_accesses,
        STDDEV(daily_accesses) as stddev_daily_accesses,
        MAX(daily_accesses) as max_daily_accesses
    FROM (
        SELECT 
            user_name,
            file_path,
            DATE(timestamp) as day,
            COUNT(*) as daily_accesses
        FROM file_events
        WHERE timestamp >= NOW() - INTERVAL '90 days'
            AND operation_type = 'FileRead'
        GROUP BY user_name, file_path, DATE(timestamp)
    ) daily_access
    GROUP BY user_name, file_path
)
SELECT 
    fe.timestamp,
    fe.hostname,
    fe.user_name,
    fe.file_path,
    fe.process_name,
    daily_count,
    fab.avg_daily_accesses,
    fab.max_daily_accesses,
    CASE 
        WHEN fab.stddev_daily_accesses = 0 THEN 999
        ELSE (daily_count - fab.avg_daily_accesses) / fab.stddev_daily_accesses
    END as access_anomaly_score,
    CASE 
        WHEN file_path LIKE '%.zip' OR file_path LIKE '%.rar' OR file_path LIKE '%.7z' THEN 'Archive'
        WHEN file_path LIKE '%.doc%' OR file_path LIKE '%.xls%' OR file_path LIKE '%.pdf' THEN 'Document'
        WHEN file_path LIKE '%.sql' OR file_path LIKE '%.db' OR file_path LIKE '%.mdb' THEN 'Database'
        WHEN file_path LIKE '%.key' OR file_path LIKE '%.pem' OR file_path LIKE '%.crt' THEN 'Certificate'
        ELSE 'Other'
    END as file_type
FROM (
    SELECT 
        timestamp,
        hostname,
        user_name,
        file_path,
        process_name,
        COUNT(*) OVER (PARTITION BY user_name, file_path, DATE(timestamp)) as daily_count
    FROM file_events
    WHERE timestamp >= NOW() - INTERVAL '7 days'
        AND operation_type = 'FileRead'
) fe
LEFT JOIN file_access_baseline fab ON fe.user_name = fab.user_name 
                                   AND fe.file_path = fab.file_path
WHERE daily_count > COALESCE(fab.max_daily_accesses, 0) * 2
    OR (fab.avg_daily_accesses IS NULL AND daily_count > 10)
ORDER BY access_anomaly_score DESC;

-- Hunt for large data transfers
SELECT 
    timestamp,
    source_ip,
    destination_ip,
    destination_port,
    protocol,
    bytes_sent,
    bytes_received,
    connection_duration,
    bytes_sent / NULLIF(connection_duration, 0) as transfer_rate_out,
    bytes_received / NULLIF(connection_duration, 0) as transfer_rate_in
FROM network_connections
WHERE timestamp >= NOW() - INTERVAL '24 hours'
    AND (bytes_sent > 100000000  -- 100MB+
         OR bytes_received > 100000000
         OR (connection_duration > 0 AND bytes_sent / connection_duration > 10000000)) -- 10MB/s+
    AND destination_ip NOT IN (
        SELECT ip_address FROM internal_networks
    )
ORDER BY bytes_sent DESC;

-- =============================================================================
-- COMMAND AND CONTROL (C2) DETECTION
-- =============================================================================

-- Detect potential beaconing behavior
WITH connection_intervals AS (
    SELECT 
        source_ip,
        destination_ip,
        destination_port,
        timestamp,
        LAG(timestamp) OVER (PARTITION BY source_ip, destination_ip, destination_port ORDER BY timestamp) as prev_timestamp,
        EXTRACT(EPOCH FROM (timestamp - LAG(timestamp) OVER (PARTITION BY source_ip, destination_ip, destination_port ORDER BY timestamp))) as interval_seconds
    FROM network_connections
    WHERE timestamp >= NOW() - INTERVAL '24 hours'
        AND connection_state = 'established'
)
SELECT 
    source_ip,
    destination_ip,
    destination_port,
    COUNT(*) as connection_count,
    AVG(interval_seconds) as avg_interval,
    STDDEV(interval_seconds) as stddev_interval,
    MIN(interval_seconds) as min_interval,
    MAX(interval_seconds) as max_interval,
    AVG(interval_seconds) / NULLIF(STDDEV(interval_seconds), 0) as regularity_score
FROM connection_intervals
WHERE interval_seconds IS NOT NULL
    AND interval_seconds > 0
GROUP BY source_ip, destination_ip, destination_port
HAVING COUNT(*) >= 10  -- At least 10 connections
    AND STDDEV(interval_seconds) / NULLIF(AVG(interval_seconds), 0) < 0.3  -- Low variance (regular intervals)
    AND AVG(interval_seconds) BETWEEN 30 AND 3600  -- Between 30 seconds and 1 hour
ORDER BY regularity_score DESC;

-- Hunt for DNS tunneling
SELECT 
    timestamp,
    source_ip,
    query_name,
    query_type,
    response_size,
    LENGTH(query_name) as query_length,
    (LENGTH(query_name) - LENGTH(REPLACE(query_name, '.', ''))) as subdomain_count
FROM dns_queries
WHERE timestamp >= NOW() - INTERVAL '24 hours'
    AND (
        LENGTH(query_name) > 50  -- Unusually long domain names
        OR response_size > 1000  -- Large responses
        OR query_type IN ('TXT', 'NULL')  -- Suspicious record types
        OR (LENGTH(query_name) - LENGTH(REPLACE(query_name, '.', ''))) > 5  -- Many subdomains
    )
    AND query_name NOT LIKE '%.in-addr.arpa'  -- Exclude reverse DNS
ORDER BY query_length DESC, response_size DESC;

-- =============================================================================
-- INSIDER THREAT DETECTION
-- =============================================================================

-- Detect after-hours access anomalies
WITH user_access_patterns AS (
    SELECT 
        user_name,
        EXTRACT(HOUR FROM timestamp) as access_hour,
        EXTRACT(DOW FROM timestamp) as day_of_week,
        COUNT(*) as access_count
    FROM authentication_events
    WHERE timestamp >= NOW() - INTERVAL '90 days'
        AND event_type = 'login_success'
    GROUP BY user_name, EXTRACT(HOUR FROM timestamp), EXTRACT(DOW FROM timestamp)
),
typical_hours AS (
    SELECT 
        user_name,
        day_of_week,
        MIN(access_hour) as earliest_hour,
        MAX(access_hour) as latest_hour,
        AVG(access_count) as avg_access_count
    FROM user_access_patterns
    WHERE access_count >= 5  -- Only consider patterns with sufficient data
    GROUP BY user_name, day_of_week
)
SELECT 
    ae.timestamp,
    ae.hostname,
    ae.user_name,
    ae.source_ip,
    EXTRACT(HOUR FROM ae.timestamp) as access_hour,
    EXTRACT(DOW FROM ae.timestamp) as day_of_week,
    th.earliest_hour,
    th.latest_hour,
    CASE 
        WHEN EXTRACT(DOW FROM ae.timestamp) IN (0, 6) THEN 'Weekend'
        WHEN EXTRACT(HOUR FROM ae.timestamp) < 6 OR EXTRACT(HOUR FROM ae.timestamp) > 22 THEN 'After Hours'
        WHEN th.earliest_hour IS NULL THEN 'New Pattern'
        WHEN EXTRACT(HOUR FROM ae.timestamp) < th.earliest_hour - 2 THEN 'Earlier Than Usual'
        WHEN EXTRACT(HOUR FROM ae.timestamp) > th.latest_hour + 2 THEN 'Later Than Usual'
        ELSE 'Normal'
    END as access_classification
FROM authentication_events ae
LEFT JOIN typical_hours th ON ae.user_name = th.user_name 
                           AND EXTRACT(DOW FROM ae.timestamp) = th.day_of_week
WHERE ae.timestamp >= NOW() - INTERVAL '7 days'
    AND ae.event_type = 'login_success'
    AND (
        EXTRACT(DOW FROM ae.timestamp) IN (0, 6)  -- Weekends
        OR EXTRACT(HOUR FROM ae.timestamp) < 6     -- Very early
        OR EXTRACT(HOUR FROM ae.timestamp) > 22    -- Very late
        OR th.earliest_hour IS NULL                -- New pattern
        OR EXTRACT(HOUR FROM ae.timestamp) < th.earliest_hour - 2
        OR EXTRACT(HOUR FROM ae.timestamp) > th.latest_hour + 2
    )
ORDER BY ae.timestamp DESC;

-- Hunt for mass file access (potential data harvesting)
SELECT 
    timestamp,
    hostname,
    user_name,
    process_name,
    COUNT(DISTINCT file_path) as unique_files_accessed,
    COUNT(*) as total_file_operations,
    MIN(timestamp) as first_access,
    MAX(timestamp) as last_access,
    EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp))) as operation_duration_seconds
FROM file_events
WHERE timestamp >= NOW() - INTERVAL '24 hours'
    AND operation_type IN ('FileRead', 'FileCopy')
GROUP BY 
    DATE_TRUNC('hour', timestamp),
    hostname,
    user_name,
    process_name
HAVING COUNT(DISTINCT file_path) > 100  -- Accessed many unique files
    OR COUNT(*) > 1000                   -- High volume of operations
ORDER BY unique_files_accessed DESC, total_file_operations DESC;

-- =============================================================================
-- ADVANCED PERSISTENT THREAT (APT) INDICATORS
-- =============================================================================

-- Hunt for living-off-the-land binaries (LOLBins) abuse
SELECT 
    timestamp,
    hostname,
    process_name,
    parent_process,
    command_line,
    user_name,
    CASE 
        WHEN process_name = 'powershell.exe' AND command_line LIKE '%downloadstring%' THEN 'Download via PowerShell'
        WHEN process_name = 'certutil.exe' AND command_line LIKE '%-decode%' THEN 'Certutil Decode'
        WHEN process_name = 'bitsadmin.exe' AND command_line LIKE '%transfer%' THEN 'BITS Transfer'
        WHEN process_name = 'wmic.exe' AND command_line LIKE '%process%call%create%' THEN 'WMIC Process Creation'
        WHEN process_name = 'rundll32.exe' AND command_line LIKE '%javascript%' THEN 'Rundll32 JavaScript'
        WHEN process_name = 'mshta.exe' AND command_line LIKE '%http%' THEN 'MSHTA Remote Execution'
        WHEN process_name = 'regsvr32.exe' AND command_line LIKE '%/s%/i%http%' THEN 'Regsvr32 Remote'
        ELSE 'Other Suspicious Activity'
    END as technique
FROM process_events
WHERE timestamp >= NOW() - INTERVAL '24 hours'
    AND (
        (process_name = 'powershell.exe' AND (command_line LIKE '%downloadstring%' OR command_line LIKE '%invoke-expression%' OR command_line LIKE '%iex%'))
        OR (process_name = 'certutil.exe' AND (command_line LIKE '%-decode%' OR command_line LIKE '%-urlcache%'))
        OR (process_name = 'bitsadmin.exe' AND command_line LIKE '%transfer%')
        OR (process_name = 'wmic.exe' AND command_line LIKE '%process%call%create%')
        OR (process_name = 'rundll32.exe' AND (command_line LIKE '%javascript%' OR command_line LIKE '%vbscript%'))
        OR (process_name = 'mshta.exe' AND command_line LIKE '%http%')
        OR (process_name = 'regsvr32.exe' AND command_line LIKE '%/s%/i%http%')
    )
ORDER BY timestamp DESC;

-- Detect potential watering hole attacks
WITH domain_reputation AS (
    SELECT 
        domain,
        COUNT(DISTINCT source_ip) as unique_visitors,
        COUNT(*) as total_requests,
        AVG(response_size) as avg_response_size
    FROM web_requests
    WHERE timestamp >= NOW() - INTERVAL '7 days'
    GROUP BY domain
),
suspicious_domains AS (
    SELECT domain
    FROM domain_reputation
    WHERE unique_visitors < 10  -- Low legitimate traffic
        AND avg_response_size > 50000  -- Large responses (potential payload)
)
SELECT 
    wr.timestamp,
    wr.source_ip,
    wr.domain,
    wr.url_path,
    wr.user_agent,
    wr.response_code,
    wr.response_size,
    dr.unique_visitors,
    dr.avg_response_size
FROM web_requests wr
JOIN suspicious_domains sd ON wr.domain = sd.domain
JOIN domain_reputation dr ON wr.domain = dr.domain
WHERE wr.timestamp >= NOW() - INTERVAL '24 hours'
    AND wr.response_code = 200
ORDER BY wr.timestamp DESC;

-- Hunt for process hollowing indicators
SELECT 
    pe1.timestamp,
    pe1.hostname,
    pe1.process_name as parent_process,
    pe1.process_id as parent_pid,
    pe1.command_line as parent_cmdline,
    pe2.process_name as child_process,
    pe2.process_id as child_pid,
    pe2.command_line as child_cmdline,
    pe2.image_path,
    CASE 
        WHEN pe2.image_path != pe2.process_name THEN 'Image/Process Name Mismatch'
        WHEN pe1.process_name IN ('explorer.exe', 'winlogon.exe', 'services.exe') 
             AND pe2.process_name NOT IN ('notepad.exe', 'calc.exe', 'taskmgr.exe') THEN 'Suspicious Parent'
        ELSE 'Potential Hollowing'
    END as indicator
FROM process_events pe1
JOIN process_events pe2 ON pe1.process_id = pe2.parent_process_id
    AND pe1.hostname = pe2.hostname
    AND pe2.timestamp BETWEEN pe1.timestamp AND pe1.timestamp + INTERVAL '5 minutes'
WHERE pe1.timestamp >= NOW() - INTERVAL '24 hours'
    AND (
        pe2.image_path != pe2.process_name  -- Image path doesn't match process name
        OR (pe1.process_name IN ('explorer.exe', 'winlogon.exe', 'services.exe') 
            AND pe2.process_name NOT IN (
                'notepad.exe', 'calc.exe', 'taskmgr.exe', 'cmd.exe', 'powershell.exe'
            ))
    )
ORDER BY pe1.timestamp DESC;