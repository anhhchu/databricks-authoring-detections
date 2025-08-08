-- Databricks notebook source
-- MAGIC %md
-- MAGIC # Large Data Export Detection Rule (System Tables)
-- MAGIC 
-- MAGIC **Rule ID**: DATA-001  
-- MAGIC **Author**: Data Protection Team  
-- MAGIC **Version**: 2.0.0  
-- MAGIC **Last Updated**: 2024-01-14  
-- MAGIC 
-- MAGIC ## Overview
-- MAGIC This detection rule identifies potential data exfiltration by monitoring for unusually large data exports, downloads, or transfers by users that deviate significantly from their baseline behavior using Databricks system tables.
-- MAGIC 
-- MAGIC ## Detection Logic
-- MAGIC - Monitors system.query.history for large data queries
-- MAGIC - Tracks system.access.table_lineage for data access patterns
-- MAGIC - Calculates user baseline export behavior
-- MAGIC - Identifies statistical anomalies in export volume
-- MAGIC - Considers time-of-day and access patterns
-- MAGIC 
-- MAGIC ## MITRE ATT&CK Mapping
-- MAGIC - **Tactic**: TA0010 (Exfiltration)
-- MAGIC - **Technique**: T1041 (Exfiltration Over C2 Channel)
-- MAGIC 
-- MAGIC ## Data Sources
-- MAGIC - system.query.history (Primary)
-- MAGIC - system.access.table_lineage (Context)

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
    volume_threshold_gb,
    anomaly_multiplier,
    anomaly_score_threshold
FROM current_rule_config
WHERE rule_id = 'DATA-001' 
  AND environment = '${environment}';

-- Validate rule configuration is loaded
DECLARE OR REPLACE VARIABLE end_time = CURRENT_TIMESTAMP();
DECLARE OR REPLACE VARIABLE start_time TIMESTAMP;
SET VARIABLE start_time = (SELECT CURRENT_TIMESTAMP() - INTERVAL 1 hour * COALESCE((SELECT time_window_hours FROM rule_config), 1) HOURS);

-- MAGIC %md
-- MAGIC ## Time Window Configuration

-- COMMAND ----------

-- Define time window variables for the analysis
DECLARE OR REPLACE VARIABLE end_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP();
DECLARE OR REPLACE VARIABLE start_time TIMESTAMP DEFAULT (
    SELECT CURRENT_TIMESTAMP() - INTERVAL COALESCE((SELECT time_window_hours FROM rule_config), 1) HOURS
);

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Data Preparation from System Tables

-- COMMAND ----------

-- Data access events from system.query.history
CREATE OR REPLACE TEMPORARY VIEW data_access_events AS
SELECT 
    start_time as timestamp,
    executed_by as username,
    executed_by as user_id,
    'query' as action_type,
    statement_text as resource_path,
    produced_rows as data_size_rows,
    produced_rows * 1024 as data_size_bytes,  -- Estimate bytes (1KB per row)
    produced_rows * 1024 / (1024 * 1024 * 1024) as data_size_gb,
    'sql_query' as export_method,
    NULL as destination_ip,
    'data' as file_type,
    'unclassified' as classification_level,
    session_id,
    NULL as source_ip
FROM system.query.history
WHERE start_time >= '${start_time}'
  AND end_time <= '${end_time}'
  AND produced_rows > 1000  -- Focus on queries producing significant data
  AND executed_by IS NOT NULL;

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Table Lineage Analysis

-- COMMAND ----------

-- Get table access patterns from system.access.table_lineage
CREATE OR REPLACE TEMPORARY VIEW table_access_patterns AS
SELECT 
    event_time as timestamp,
    created_by as username,
    source_table_name as table_name,
    'read' as action_type,
    NULL as rows_read,
    NULL as rows_written,
    NULL as bytes_read,
    NULL as bytes_written,
    statement_id as session_id
FROM system.access.table_lineage
WHERE event_time >= '${start_time}'
  AND event_time <= '${end_time}'
  AND created_by IS NOT NULL
  AND source_table_name IS NOT NULL;  -- Significant data operations

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## User Baseline Analysis

-- COMMAND ----------

-- Calculate user baselines (30-day lookback) from system.query.history
CREATE OR REPLACE TEMPORARY VIEW user_export_baselines AS
SELECT 
    executed_by as user_id,
    executed_by as username,
    COUNT(*) as historical_query_count,
    AVG(produced_rows) as avg_query_size_rows,
    STDDEV(produced_rows) as stddev_query_size_rows,
    MAX(produced_rows) as max_historical_query_rows,
    PERCENTILE_APPROX(produced_rows, 0.95) as p95_query_size_rows,
    AVG(produced_rows * 1024) / (1024 * 1024 * 1024) as avg_query_size_gb,
    MAX(produced_rows * 1024) / (1024 * 1024 * 1024) as max_historical_query_gb
FROM system.query.history
WHERE start_time >= DATE_SUB(CURRENT_DATE(), 30)
  AND end_time < start_time
  AND produced_rows > 1000
  AND executed_by IS NOT NULL
GROUP BY executed_by
HAVING COUNT(*) >= 5;  -- Only users with sufficient history

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Current Export Analysis

-- COMMAND ----------

-- Current export analysis
CREATE OR REPLACE TEMPORARY VIEW current_exports AS
SELECT 
    user_id,
    username,
    COUNT(*) as current_query_count,
    SUM(data_size_bytes) as total_export_bytes,
    SUM(data_size_gb) as total_export_gb,
    MAX(data_size_bytes) as max_export_bytes,
    MAX(data_size_gb) as max_export_gb,
    MIN(timestamp) as first_export,
    MAX(timestamp) as last_export,
    AVG(data_size_bytes) as avg_export_size_bytes,
    STDDEV(data_size_bytes) as stddev_export_size_bytes,
    -- Calculate export frequency
    (UNIX_TIMESTAMP(MAX(timestamp)) - UNIX_TIMESTAMP(MIN(timestamp))) / 3600 as export_duration_hours,
    COUNT(*) / NULLIF((UNIX_TIMESTAMP(MAX(timestamp)) - UNIX_TIMESTAMP(MIN(timestamp))) / 3600, 0) as exports_per_hour
FROM data_access_events
GROUP BY user_id, username
HAVING SUM(data_size_gb) >= (SELECT CAST(volume_threshold_gb AS DOUBLE) FROM rule_config);

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Anomaly Detection

-- COMMAND ----------

-- Detect anomalous data exports
CREATE OR REPLACE TEMPORARY VIEW anomalous_exports AS
SELECT 
    ce.user_id,
    ce.username,
    ce.current_query_count,
    ce.total_export_gb,
    ce.max_export_gb,
    ce.exports_per_hour,
    ce.first_export,
    ce.last_export,
    
    -- Baseline comparison
    ueb.historical_query_count,
    ueb.avg_query_size_gb,
    ueb.max_historical_query_gb,
    ueb.p95_query_size_gb,
    
    -- Anomaly scoring
    CASE 
        WHEN ce.total_export_gb > ueb.max_historical_query_gb * (SELECT CAST(anomaly_multiplier AS DOUBLE) FROM rule_config) THEN 'volume_anomaly'
        WHEN ce.exports_per_hour > ueb.historical_query_count / 30 * 2 THEN 'frequency_anomaly'
        WHEN ce.max_export_gb > ueb.p95_query_size_gb * 2 THEN 'size_anomaly'
        ELSE 'normal'
    END as anomaly_type,
    
    -- Calculate anomaly score
    CASE 
        WHEN ce.total_export_gb > ueb.max_historical_query_gb * (SELECT CAST(anomaly_multiplier AS DOUBLE) FROM rule_config) THEN 
            (ce.total_export_gb / ueb.max_historical_query_gb) * 0.8
        WHEN ce.exports_per_hour > ueb.historical_query_count / 30 * 2 THEN 
            (ce.exports_per_hour / (ueb.historical_query_count / 30)) * 0.6
        WHEN ce.max_export_gb > ueb.p95_query_size_gb * 2 THEN 
            (ce.max_export_gb / ueb.p95_query_size_gb) * 0.7
        ELSE 0.3
    END as anomaly_score
    
FROM current_exports ce
LEFT JOIN user_export_baselines ueb ON ce.user_id = ueb.user_id
WHERE ce.total_export_gb >= (SELECT CAST(volume_threshold_gb AS DOUBLE) FROM rule_config);

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Detection Results

-- COMMAND ----------

-- Generate detection results
CREATE OR REPLACE TEMPORARY VIEW detection_results AS
SELECT 
    rc.rule_id,
    rc.rule_name,
    rc.severity,
    
    -- Confidence calculation
    CASE 
        WHEN ae.anomaly_score >= 5.0 THEN 0.95
        WHEN ae.anomaly_score >= 3.0 THEN 0.85
        WHEN ae.anomaly_score >= 2.0 THEN 0.75
        ELSE 0.65
    END as confidence,
    
    ae.anomaly_type as detection_type,
    ae.user_id as entity_id,
    ae.username as entity_name,
    'user' as entity_type,
    
    -- Export details
    ae.current_query_count as query_count,
    ae.total_export_gb as total_export_gb,
    ae.max_export_gb as max_export_gb,
    ae.exports_per_hour as exports_per_hour,
    ae.anomaly_score as anomaly_score,
    
    -- Baseline comparison
    ae.historical_query_count as baseline_query_count,
    ae.avg_query_size_gb as baseline_avg_size_gb,
    ae.max_historical_query_gb as baseline_max_size_gb,
    
    -- Timestamps
    ae.first_export as first_export,
    ae.last_export as last_export,
    current_timestamp() as detection_timestamp,
    
    -- Additional metadata
    'system.query.history' as data_source,
    'Databricks System Tables' as platform
    
FROM anomalous_exports ae
CROSS JOIN rule_config rc
WHERE ae.anomaly_score >= (SELECT CAST(anomaly_score_threshold AS DOUBLE) FROM rule_config);  -- Focus on significant anomalies

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Results Summary

-- COMMAND ----------

-- Display detection summary
SELECT 
    anomaly_type,
    COUNT(*) as detection_count,
    AVG(confidence) as avg_confidence,
    AVG(anomaly_score) as avg_anomaly_score,
    AVG(total_export_gb) as avg_export_gb,
    COUNT(DISTINCT entity_name) as unique_users
FROM detection_results
GROUP BY anomaly_type
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
    query_count,
    total_export_gb,
    max_export_gb,
    exports_per_hour,
    anomaly_score,
    baseline_query_count,
    baseline_avg_size_gb,
    baseline_max_size_gb,
    first_export,
    last_export,
    detection_timestamp,
    data_source,
    platform
FROM detection_results
ORDER BY anomaly_score DESC, total_export_gb DESC;

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Store Results

-- COMMAND ----------

-- Create or replace data exfiltration results table
CREATE TABLE IF NOT EXISTS detections.data_exfiltration_results (
    rule_id STRING,
    rule_name STRING,
    severity STRING,
    confidence DOUBLE,
    detection_type STRING,
    entity_type STRING,
    entity_name STRING,
    query_count INT,
    total_export_gb DOUBLE,
    max_export_gb DOUBLE,
    exports_per_hour DOUBLE,
    anomaly_score DOUBLE,
    baseline_query_count INT,
    baseline_avg_size_gb DOUBLE,
    baseline_max_size_gb DOUBLE,
    first_export TIMESTAMP,
    last_export TIMESTAMP,
    detection_timestamp TIMESTAMP,
    data_source STRING,
    platform STRING,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) USING DELTA;

-- Insert detection results
INSERT INTO detections.data_exfiltration_results
SELECT 
    rule_id,
    rule_name,
    severity,
    confidence,
    detection_type,
    entity_type,
    entity_name,
    query_count,
    total_export_gb,
    max_export_gb,
    exports_per_hour,
    anomaly_score,
    baseline_query_count,
    baseline_avg_size_gb,
    baseline_max_size_gb,
    first_export,
    last_export,
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
            CONCAT('🚨 ALERT: ', CAST(detection_count AS STRING), ' data exfiltration detection(s) found!')
        ELSE 
            '✅ No data exfiltration detections found in the analysis window'
    END as alert_message,
    detection_count,
    start_time as analysis_start,
    end_time as analysis_end,
    CONCAT(rule_config.volume_threshold_gb, ' GB') as volume_threshold_used,
    'Databricks System Tables (system.query.history)' as data_source
FROM (
    SELECT COUNT(*) as detection_count 
    FROM detection_results
) det_summary
CROSS JOIN rule_config;

-- COMMAND ----------

-- Anomaly types breakdown with statistics
SELECT 
    '📈 Anomaly Types Summary:' as summary_header,
    detection_type as anomaly_type,
    COUNT(*) as event_count,
    ROUND(AVG(total_export_gb), 2) as avg_export_gb,
    ROUND(MAX(total_export_gb), 2) as max_export_gb,
    ROUND(SUM(total_export_gb), 2) as total_export_gb,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
FROM detection_results
GROUP BY detection_type
ORDER BY event_count DESC; 