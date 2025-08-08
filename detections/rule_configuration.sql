-- Databricks notebook source
-- MAGIC %md
-- MAGIC # Detection Rules Configuration Management
-- MAGIC 
-- MAGIC **Purpose**: Centralized configuration management for all detection rules
-- MAGIC **Author**: Security Team
-- MAGIC **Version**: 1.0.0
-- MAGIC **Last Updated**: 2024-01-15
-- MAGIC 
-- MAGIC ## Overview
-- MAGIC This notebook creates and manages the detection rules configuration table.
-- MAGIC All detection rules will query this table for their configuration parameters.
-- MAGIC 
-- MAGIC ## Configuration Table Schema
-- MAGIC - Environment-specific settings (dev, test, prod)
-- MAGIC - Rule-specific parameters and thresholds
-- MAGIC - Target table configurations
-- MAGIC - Dynamic parameter management

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Create Rules Configuration Table

-- COMMAND ----------

-- Create the rules configuration table
use catalog identifier(:catalog);
use schema identifier(:schema);

CREATE OR REPLACE TABLE rules_configuration (
    rule_id STRING COMMENT 'Unique identifier for the detection rule (e.g., AUTH-001, DATA-001)',
    rule_name STRING COMMENT 'Human-readable name describing the detection rule and its purpose',
    environment STRING COMMENT 'Deployment environment (dev, test, prod) for environment-specific configurations',
    time_window_hours INT COMMENT 'Analysis time window in hours for the detection rule (e.g., 1, 2, 24)',
    severity STRING COMMENT 'Alert severity level (low, medium, high, critical) for the detection rule',
    confidence_threshold DOUBLE COMMENT 'Minimum confidence score (0.0-1.0) required to trigger the detection alert',
    rule_specific_config MAP<STRING, STRING> COMMENT 'Key-value pairs containing rule-specific parameters and thresholds',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP() COMMENT 'Timestamp when the configuration record was created',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP() COMMENT 'Timestamp when the configuration record was last modified',
    is_active BOOLEAN DEFAULT TRUE COMMENT 'Flag indicating whether this configuration is currently active (true/false)'
) USING DELTA
TBLPROPERTIES (
    'delta.autoOptimize.optimizeWrite' = 'true',
    'delta.autoOptimize.autoCompact' = 'true',
    'delta.feature.allowColumnDefaults' = 'supported'
);

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Insert Rule Configurations

-- COMMAND ----------

-- Insert configurations for all environments and rules
INSERT OVERWRITE rules_configuration 
(rule_id, rule_name, environment, time_window_hours, severity, confidence_threshold, rule_specific_config)
VALUES
-- Failed Login Detection - Development
('AUTH-001', 'Failed Login Detection (System Tables)', 'dev', 1, 'medium', 0.5, 
 map('failed_attempts_threshold', '3', 'ip_threshold', '3', 'user_threshold', '3')),

-- Failed Login Detection - Production
('AUTH-001', 'Failed Login Detection (System Tables)', 'prod', 1, 'medium', 0.7, 
 map('failed_attempts_threshold', '5', 'ip_threshold', '5', 'user_threshold', '5')),

-- Privilege Escalation Detection - Development
('AUTH-002', 'Privilege Escalation Detection (System Tables)', 'dev', 1, 'high', 0.6, 
 map('escalation_score_threshold', '3', 'min_escalation_score', '3')),

-- Privilege Escalation Detection - Production
('AUTH-002', 'Privilege Escalation Detection (System Tables)', 'prod', 2, 'high', 0.8, 
 map('escalation_score_threshold', '5', 'min_escalation_score', '5')),

-- Data Exfiltration Detection - Development
('DATA-001', 'Large Data Export Detection (System Tables)', 'dev', 1, 'high', 0.6, 
 map('volume_threshold_gb', '0.5', 'anomaly_multiplier', '2.0', 'anomaly_score_threshold', '1.5')),

-- Data Exfiltration Detection - Production
('DATA-001', 'Large Data Export Detection (System Tables)', 'prod', 1, 'high', 0.75, 
 map('volume_threshold_gb', '1.0', 'anomaly_multiplier', '3.0', 'anomaly_score_threshold', '2.0'));

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Configuration Query Functions

-- COMMAND ----------

-- Create a view for easy rule configuration lookup
CREATE OR REPLACE VIEW current_rule_config AS
SELECT 
    rule_id,
    rule_name,
    environment,
    time_window_hours,
    severity,
    confidence_threshold,
    rule_specific_config,
    -- Extract commonly used parameters
    rule_specific_config['failed_attempts_threshold'] as failed_attempts_threshold,
    rule_specific_config['escalation_score_threshold'] as escalation_score_threshold,
    rule_specific_config['volume_threshold_gb'] as volume_threshold_gb,
    rule_specific_config['anomaly_multiplier'] as anomaly_multiplier,
    rule_specific_config['anomaly_score_threshold'] as anomaly_score_threshold,
    is_active
FROM rules_configuration
WHERE is_active = true;
