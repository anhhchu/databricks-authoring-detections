-- Databricks notebook source
-- MAGIC %md
-- MAGIC # Privilege Escalation Detection Rule (System Tables)
-- MAGIC 
-- MAGIC **Rule ID**: AUTH-002  
-- MAGIC **Author**: Security Team  
-- MAGIC **Version**: 2.0.0  
-- MAGIC **Last Updated**: 2024-01-12  
-- MAGIC 
-- MAGIC ## Overview
-- MAGIC This detection rule identifies potential privilege escalation attempts by monitoring for unusual elevation of user permissions, role changes, and administrative actions performed by non-administrative users using Databricks system tables.
-- MAGIC 
-- MAGIC ## Detection Logic
-- MAGIC - Monitors system.access.audit for permission/role changes
-- MAGIC - Identifies users gaining elevated privileges
-- MAGIC - Detects unusual administrative actions
-- MAGIC - Compares against user baseline behavior
-- MAGIC - Uses system.query.history for additional context
-- MAGIC 
-- MAGIC ## MITRE ATT&CK Mapping
-- MAGIC - **Tactic**: TA0004 (Privilege Escalation)
-- MAGIC - **Technique**: T1548 (Abuse Elevation Control Mechanism)
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
    escalation_score_threshold
FROM current_rule_config
WHERE rule_id = 'AUTH-002' 
  AND environment = '${environment}';

-- Validate rule configuration is loaded
SELECT 
    CASE 
        WHEN COUNT(*) = 0 THEN RAISE_ERROR('No rule configuration found for AUTH-002 in environment ${environment}')
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

-- Create view for audit events from system.access.audit
CREATE OR REPLACE TEMP VIEW audit_events AS
SELECT 
    event_time as timestamp,
    user_identity.email as username,
    user_identity.subject_name as user_id,
    action_name as action_type,
    request_params['resource_type'] as resource_type,
    request_params['resource_id'] as resource_id,
    request_params['old_permissions'] as old_permissions,
    request_params['new_permissions'] as new_permissions,
    request_params['granted_by'] as granted_by_user_id,
    session_id,
    source_ip_address as source_ip,
    response.result as success
FROM system.access.audit
WHERE event_time >= '${start_time}'
  AND event_time <= '${end_time}'
  AND action_name IN (
    'grantPrivilege', 'revokePrivilege', 'createRole', 'deleteRole',
    'assignRole', 'unassignRole', 'createUser', 'deleteUser',
    'modifyUser', 'createGroup', 'deleteGroup', 'addUserToGroup',
    'removeUserFromGroup', 'createWorkspace', 'deleteWorkspace',
    'modifyWorkspace', 'createCluster', 'deleteCluster', 'modifyCluster'
  )
  AND user_identity.email IS NOT NULL;

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Privilege Escalation Detection

-- COMMAND ----------

-- Detect privilege escalations
CREATE OR REPLACE TEMP VIEW privilege_escalations AS
SELECT 
    user_id,
    username,
    timestamp,
    action_type,
    resource_type,
    resource_id,
    old_permissions,
    new_permissions,
    granted_by_user_id,
    source_ip,
    
    -- Calculate privilege elevation score
    CASE 
        WHEN action_type IN ('createRole', 'deleteRole', 'createUser', 'deleteUser') THEN 10
        WHEN action_type IN ('grantPrivilege', 'assignRole') AND 
             (new_permissions LIKE '%admin%' OR new_permissions LIKE '%owner%') THEN 9
        WHEN action_type IN ('grantPrivilege', 'assignRole') AND 
             (new_permissions LIKE '%write%' OR new_permissions LIKE '%modify%') THEN 7
        WHEN action_type IN ('createWorkspace', 'deleteWorkspace', 'createCluster', 'deleteCluster') THEN 8
        WHEN action_type IN ('modifyWorkspace', 'modifyCluster') THEN 6
        WHEN action_type IN ('addUserToGroup', 'removeUserFromGroup') THEN 4
        ELSE 2
    END as escalation_score,
    
    -- Identify escalation type
    CASE 
        WHEN action_type IN ('createRole', 'deleteRole') THEN 'role_management'
        WHEN action_type IN ('createUser', 'deleteUser') THEN 'user_management'
        WHEN new_permissions LIKE '%admin%' OR new_permissions LIKE '%owner%' THEN 'admin_privilege'
        WHEN new_permissions LIKE '%write%' OR new_permissions LIKE '%modify%' THEN 'write_privilege'
        WHEN action_type IN ('createWorkspace', 'deleteWorkspace') THEN 'workspace_management'
        WHEN action_type IN ('createCluster', 'deleteCluster') THEN 'cluster_management'
        ELSE 'other_privilege'
    END as escalation_type
    
FROM audit_events
WHERE success = 'SUCCESS'
  AND (
    (old_permissions IS NULL AND new_permissions IS NOT NULL) OR
    (old_permissions IS NOT NULL AND new_permissions IS NOT NULL AND old_permissions != new_permissions) OR
    action_type IN ('createRole', 'deleteRole', 'createUser', 'deleteUser', 'createWorkspace', 'deleteWorkspace', 'createCluster', 'deleteCluster')
  );

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## User Baseline Analysis

-- COMMAND ----------

-- Calculate user baselines for privilege escalation detection
CREATE OR REPLACE TEMP VIEW user_baselines AS
SELECT 
    user_id,
    username,
    COUNT(*) as total_privilege_events,
    COUNT(DISTINCT action_type) as unique_action_types,
    MAX(escalation_score) as max_escalation_score,
    AVG(escalation_score) as avg_escalation_score,
    COUNT(CASE WHEN escalation_score >= 7 THEN 1 END) as high_privilege_events,
    MIN(timestamp) as first_privilege_event,
    MAX(timestamp) as last_privilege_event
FROM privilege_escalations
GROUP BY user_id, username
HAVING COUNT(*) >= 1;  -- At least one privilege event

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Additional Context from Query History

-- COMMAND ----------

-- Get additional context from query history for users with privilege escalations
CREATE OR REPLACE TEMP VIEW privilege_user_queries AS
SELECT 
    qh.executed_by,
    COUNT(*) as query_count,
    AVG(qh.total_duration_ms) as avg_execution_time,
    MAX(qh.total_duration_ms) as max_execution_time,
    SUM(qh.produced_rows) as total_rows_produced,
    COUNT(DISTINCT qh.statement_text) as unique_queries,
    MIN(qh.start_time) as first_query,
    MAX(qh.end_time) as last_query
FROM system.query.history qh
INNER JOIN privilege_escalations pe ON qh.executed_by = pe.username
WHERE qh.start_time >= '${start_time}'
  AND qh.end_time <= '${end_time}'
GROUP BY qh.executed_by;

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Detection Results

-- COMMAND ----------

-- Generate detection results
CREATE OR REPLACE TEMP VIEW detection_results AS
SELECT 
    rc.rule_id,
    rc.rule_name,
    rc.severity,
    
    -- Confidence calculation based on escalation score and frequency
    CASE 
        WHEN pe.escalation_score >= 9 THEN 0.95
        WHEN pe.escalation_score >= 7 THEN 0.85
        WHEN pe.escalation_score >= 5 THEN 0.75
        ELSE 0.65
    END as confidence,
    
    pe.escalation_type as detection_type,
    pe.user_id as entity_id,
    pe.username as entity_name,
    'user' as entity_type,
    
    -- Privilege escalation details
    pe.escalation_score as escalation_score,
    pe.action_type as action_type,
    pe.resource_type as resource_type,
    pe.resource_id as resource_id,
    pe.old_permissions as old_permissions,
    pe.new_permissions as new_permissions,
    pe.granted_by_user_id as granted_by_user_id,
    pe.source_ip as source_ip,
    
    -- Timestamps
    pe.timestamp as event_timestamp,
    current_timestamp() as detection_timestamp,
    
    -- Additional metadata
    'system.access.audit' as data_source,
    'Databricks System Tables' as platform
    
FROM privilege_escalations pe
CROSS JOIN rule_config rc
WHERE pe.escalation_score >= (SELECT CAST(escalation_score_threshold AS INT) FROM rule_config);  -- Use dynamic threshold

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Results Summary

-- COMMAND ----------

-- Display detection summary
SELECT 
    escalation_type,
    COUNT(*) as detection_count,
    AVG(confidence) as avg_confidence,
    AVG(escalation_score) as avg_escalation_score,
    COUNT(DISTINCT entity_name) as unique_users
FROM detection_results
GROUP BY escalation_type
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
    escalation_score,
    action_type,
    resource_type,
    old_permissions,
    new_permissions,
    source_ip,
    event_timestamp,
    detection_timestamp,
    data_source,
    platform
FROM detection_results
ORDER BY escalation_score DESC, confidence DESC;

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Store Results

-- COMMAND ----------

-- Create or replace privilege escalation results table using dynamic configuration
CREATE TABLE IF NOT EXISTS detections.privilege_escalation_results (
    rule_id STRING,
    rule_name STRING,
    severity STRING,
    confidence DOUBLE,
    detection_type STRING,
    entity_type STRING,
    entity_name STRING,
    escalation_score INT,
    action_type STRING,
    resource_type STRING,
    resource_id STRING,
    old_permissions STRING,
    new_permissions STRING,
    granted_by_user_id STRING,
    source_ip STRING,
    event_timestamp TIMESTAMP,
    detection_timestamp TIMESTAMP,
    data_source STRING,
    platform STRING,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) USING DELTA;

-- Insert detection results into dynamic table
INSERT INTO detections.privilege_escalation_results
SELECT 
    rule_id,
    rule_name,
    severity,
    confidence,
    detection_type,
    entity_type,
    entity_name,
    escalation_score,
    action_type,
    resource_type,
    resource_id,
    old_permissions,
    new_permissions,
    granted_by_user_id,
    source_ip,
    event_timestamp,
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
            CONCAT('🚨 ALERT: ', CAST(detection_count AS STRING), ' privilege escalation detection(s) found!')
        ELSE 
            '✅ No privilege escalation detections found in the analysis window'
    END as alert_message,
    detection_count,
    start_time as analysis_start,
    end_time as analysis_end,
    'Databricks System Tables (system.access.audit)' as data_source
FROM (
    SELECT COUNT(*) as detection_count 
    FROM detection_results
) det_summary
CROSS JOIN rule_config;

-- COMMAND ----------

-- Escalation types breakdown
SELECT 
    '📈 Escalation Types Summary:' as summary_header,
    detection_type as escalation_type,
    COUNT(*) as event_count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
FROM detection_results
GROUP BY detection_type
ORDER BY event_count DESC; 