-- Databricks notebook source
-- MAGIC %md
-- MAGIC # Failed Login Detection Rule (System Tables)
-- MAGIC 
-- MAGIC **Rule ID**: AUTH-001  
-- MAGIC **Author**: Security Team  
-- MAGIC **Version**: 2.0.0  
-- MAGIC **Last Updated**: 2024-01-15  
-- MAGIC 
-- MAGIC ## Overview
-- MAGIC This detection rule identifies potential brute force attacks by monitoring for multiple failed login attempts from the same source IP or targeting the same user account within a specified time window using Databricks system tables.
-- MAGIC 
-- MAGIC ## Detection Logic
-- MAGIC - Monitors system.access.audit for authentication events
-- MAGIC - Groups by source IP and target user
-- MAGIC - Triggers when threshold exceeded within time window
-- MAGIC - Correlates with user behavior baselines
-- MAGIC - Uses system.query.history for additional context
-- MAGIC 
-- MAGIC ## MITRE ATT&CK Mapping
-- MAGIC - **Tactic**: TA0006 (Credential Access)
-- MAGIC - **Technique**: T1110 (Brute Force)
-- MAGIC 
-- MAGIC ## Data Sources
-- MAGIC - system.access.audit (Primary)
-- MAGIC - system.query.history (Context)

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Configuration Parameters

-- COMMAND ----------

-- Load rule configuration from central configuration table
use catalog identifier(:catalog);
use schema identifier(:schema);

CREATE OR REPLACE TEMP VIEW rule_config AS
SELECT 
    rule_id,
    rule_name,
    environment,
    time_window_hours,
    severity,
    confidence_threshold,
    failed_attempts_threshold
FROM current_rule_config
WHERE rule_id = 'AUTH-001' 
  AND environment = '${environment}';

-- Validate rule configuration is loaded
SELECT 
    CASE 
        WHEN COUNT(*) = 0 THEN RAISE_ERROR('No rule configuration found for AUTH-001 in environment ${environment}')
        ELSE 'Rule configuration loaded successfully'
    END as config_status
FROM rule_config;

-- MAGIC %md
-- MAGIC ## Time Window Configuration

-- COMMAND ----------

-- Define time window variables for the analysis
DECLARE OR REPLACE VARIABLE end_time = CURRENT_TIMESTAMP();
DECLARE OR REPLACE VARIABLE start_time TIMESTAMP;
SET VARIABLE start_time = (SELECT CURRENT_TIMESTAMP() - INTERVAL 1 hour * COALESCE((SELECT time_window_hours FROM rule_config), 1) HOURS);

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Data Preparation from System Tables

-- COMMAND ----------

-- Create view for authentication events from system.access.audit
CREATE OR REPLACE TEMP VIEW auth_events AS
SELECT 
    event_time as timestamp,
    user_identity.email as username,
    user_identity.subject_name as user_id,
    source_ip_address as source_ip,
    user_agent,
    action_name as event_type,
    response.result as authentication_result,
    session_id,
    -- Calculate risk score based on various factors
    CASE 
        WHEN response.result = 'FAILED' THEN 1.0
        WHEN source_ip_address LIKE '192.168.%' THEN 0.3
        WHEN source_ip_address LIKE '10.%' THEN 0.3
        WHEN source_ip_address NOT LIKE '%.%.%.%' THEN 0.7  -- Non-standard IP format
        ELSE 0.5
    END as risk_score
FROM system.access.audit
WHERE event_time >= '${start_time}'
  AND event_time <= '${end_time}'
  AND action_name IN ('login', 'loginFailed', 'authentication', 'logout')
  AND user_identity.email IS NOT NULL;

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Failed Login Analysis

-- COMMAND ----------

-- Analyze failed login patterns by source IP
CREATE OR REPLACE TEMP VIEW failed_logins_by_ip AS
SELECT 
    source_ip,
    COUNT(*) as failed_attempts,
    COUNT(DISTINCT user_id) as unique_users_targeted,
    MIN(timestamp) as first_attempt,
    MAX(timestamp) as last_attempt,
    COLLECT_LIST(DISTINCT username) as targeted_usernames,
    COLLECT_LIST(DISTINCT user_agent) as user_agents,
    AVG(risk_score) as avg_risk_score,
    -- Calculate time span of attacks
    (UNIX_TIMESTAMP(MAX(timestamp)) - UNIX_TIMESTAMP(MIN(timestamp))) / 60 as attack_duration_minutes
FROM auth_events 
WHERE authentication_result = 'FAILED'
  AND source_ip IS NOT NULL
GROUP BY source_ip
HAVING COUNT(*) >= (SELECT CAST(failed_attempts_threshold AS INT) FROM rule_config);

-- COMMAND ----------

-- Analyze failed login patterns by user
CREATE OR REPLACE TEMP VIEW failed_logins_by_user AS
SELECT 
    user_id,
    username,
    COUNT(*) as failed_attempts,
    COUNT(DISTINCT source_ip) as unique_source_ips,
    MIN(timestamp) as first_attempt,
    MAX(timestamp) as last_attempt,
    COLLECT_LIST(DISTINCT source_ip) as source_ips,
    COLLECT_LIST(DISTINCT user_agent) as user_agents,
    AVG(risk_score) as avg_risk_score,
    -- Calculate time span of attacks
    (UNIX_TIMESTAMP(MAX(timestamp)) - UNIX_TIMESTAMP(MIN(timestamp))) / 60 as attack_duration_minutes
FROM auth_events 
WHERE authentication_result = 'FAILED'
  AND user_id IS NOT NULL
GROUP BY user_id, username
HAVING COUNT(*) >= (SELECT CAST(failed_attempts_threshold AS INT) FROM rule_config);

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Additional Context from Query History

-- COMMAND ----------

-- Get additional context from query history for suspicious users
CREATE OR REPLACE TEMP VIEW suspicious_user_queries AS
SELECT 
    qh.executed_by,
    COUNT(*) as query_count,
    AVG(qh.total_duration_ms) as avg_execution_time,
    MAX(qh.total_duration_ms) as max_execution_time,
    SUM(qh.produced_rows) as total_rows_produced,
    MIN(qh.start_time) as first_query,
    MAX(qh.end_time) as last_query
FROM system.query.history qh
INNER JOIN failed_logins_by_user fl ON qh.executed_by = fl.username
WHERE qh.start_time >= '${start_time}'
  AND qh.end_time <= '${end_time}'
GROUP BY qh.executed_by;

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Detection Results

-- COMMAND ----------

-- Combine detection results
CREATE OR REPLACE TEMP VIEW detection_results AS
SELECT 
    rc.rule_id,
    rc.rule_name,
    rc.severity,
    
    -- IP-based detections
    CASE 
        WHEN ip.failed_attempts >= 10 THEN 0.9
        WHEN ip.failed_attempts >= 7 THEN 0.8
        WHEN ip.failed_attempts >= 5 THEN 0.7
        ELSE 0.6
    END as confidence,
    
    'IP_BASED' as detection_type,
    ip.source_ip as entity_id,
    ip.source_ip as entity_name,
    'source_ip' as entity_type,
    
    -- Additional context
    ip.failed_attempts as failed_attempts,
    ip.unique_users_targeted as unique_users_targeted,
    ip.attack_duration_minutes as attack_duration_minutes,
    ip.targeted_usernames as targeted_usernames,
    ip.user_agents as user_agents,
    ip.avg_risk_score as risk_score,
    
    -- Timestamps
    ip.first_attempt as first_attempt,
    ip.last_attempt as last_attempt,
    current_timestamp() as detection_timestamp,
    
    -- Additional metadata
    'system.access.audit' as data_source,
    'Databricks System Tables' as platform
    
FROM failed_logins_by_ip ip
CROSS JOIN rule_config rc

UNION ALL

-- User-based detections
SELECT 
    rc.rule_id,
    rc.rule_name,
    rc.severity,
    
    CASE 
        WHEN user.failed_attempts >= 10 THEN 0.9
        WHEN user.failed_attempts >= 7 THEN 0.8
        WHEN user.failed_attempts >= 5 THEN 0.7
        ELSE 0.6
    END as confidence,
    
    'USER_BASED' as detection_type,
    user.user_id as entity_id,
    user.username as entity_name,
    'user' as entity_type,
    
    user.failed_attempts as failed_attempts,
    user.unique_source_ips as unique_source_ips,
    user.attack_duration_minutes as attack_duration_minutes,
    user.source_ips as source_ips,
    user.user_agents as user_agents,
    user.avg_risk_score as risk_score,
    
    user.first_attempt as first_attempt,
    user.last_attempt as last_attempt,
    current_timestamp() as detection_timestamp,
    
    'system.access.audit' as data_source,
    'Databricks System Tables' as platform
    
FROM failed_logins_by_user user
CROSS JOIN rule_config rc;

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Results Summary

-- COMMAND ----------

-- Display detection summary
SELECT 
    detection_type,
    COUNT(*) as detection_count,
    AVG(confidence) as avg_confidence,
    AVG(failed_attempts) as avg_failed_attempts
FROM detection_results
GROUP BY detection_type
ORDER BY detection_count DESC;

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Detailed Results

-- COMMAND ----------

-- Show detailed detection results
SELECT 
    rule_id,
    rule_name,
    severity,
    confidence,
    detection_type,
    entity_type,
    entity_name,
    failed_attempts,
    first_attempt,
    last_attempt,
    detection_timestamp,
    data_source,
    platform
FROM detection_results
ORDER BY confidence DESC, failed_attempts DESC;

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Store Results

-- COMMAND ----------

-- Create or replace detection results table using configuration
CREATE TABLE IF NOT EXISTS detections.failed_login_results (
    rule_id STRING,
    rule_name STRING,
    severity STRING,
    confidence DOUBLE,
    detection_type STRING,
    entity_type STRING,
    entity_name STRING,
    failed_attempts INT,
    first_attempt TIMESTAMP,
    last_attempt TIMESTAMP,
    detection_timestamp TIMESTAMP,
    data_source STRING,
    platform STRING,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) USING DELTA;

-- Insert detection results
INSERT INTO detections.failed_login_results
SELECT 
    rule_id,
    rule_name,
    severity,
    confidence,
    detection_type,
    entity_type,
    entity_name,
    failed_attempts,
    first_attempt,
    last_attempt,
    detection_timestamp,
    data_source,
    platform
FROM detection_results;

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Alert Summary

-- COMMAND ----------

-- Generate alert summary
SELECT 
    CASE 
        WHEN detection_count > 0 THEN 
            CONCAT('🚨 ALERT: ', CAST(detection_count AS STRING), ' failed login detection(s) found!')
        ELSE 
            '✅ No failed login detections found in the analysis window'
    END as alert_message,
    detection_count,
    start_time as analysis_start,
    end_time as analysis_end,
    rule_config.failed_attempts_threshold as threshold_used,
    'Databricks System Tables (system.access.audit)' as data_source
FROM (
    SELECT COUNT(*) as detection_count 
    FROM detection_results
) det_summary
CROSS JOIN rule_config; 