-- Databricks notebook source
-- MAGIC %md
-- MAGIC # Large Data Export Detection Rule (System Tables)
-- MAGIC 
-- MAGIC **Rule ID**: DATA-001  
-- MAGIC **Author**: Data Protection Team  
-- MAGIC **Version**: 2.0.0  
-- MAGIC **Last Updated**: 2024-01-14  -- MAGIC 
-- MAGIC ## Overview
-- MAGIC This detection rule identifies potential data exfiltration by monitoring for unusually large data exports, downloads, or transfers by users that deviate significantly from their baseline behavior using Databricks system tables.
-- MAGIC 
-- MAGIC ## Detection Logic
-- MAGIC - Monitors system.access.audit for large data exports, downloads, or transfers
-- MAGIC 
-- MAGIC ## MITRE ATT&CK Mapping
-- MAGIC - **Tactic**: TA0010 (Exfiltration)
-- MAGIC - **Technique**: T1041 (Exfiltration Over C2 Channel)
-- MAGIC 
-- MAGIC ## Data Sources
-- MAGIC - system.query.history (Primary)

-- COMMAND ----------
-- Define time window variables for the analysis
DECLARE OR REPLACE VARIABLE end_time = CURRENT_TIMESTAMP();
DECLARE OR REPLACE VARIABLE start_time TIMESTAMP;
SET VARIABLE start_time = (SELECT CURRENT_TIMESTAMP() - INTERVAL 168 HOURS);

-- COMMAND ----------

use catalog identifier(:catalog);
use schema identifier(:schema);

-- COMMAND ----------

-- DBTITLE 1,Create MV
CREATE VIEW IF NOT EXISTS sec_v_data_export_detection
COMMENT 'Unified indicators of data export activity outside of Databricks across SQL Editor, Filesystem, Notebooks, and Dashboards.'
---- set a schedule to refresh for mv
-- SCHEDULE EVERY 1 DAY
AS
-- SQL Editor: result downloads from the SQL Editor (excludes dashboards)
SELECT
  workspace_id,
  COALESCE(user_identity.email, identity_metadata.run_by) AS actor,
  service_name as source,
  action_name,
  CAST(request_params.queryId AS STRING) AS artifact,
  event_time
FROM system.access.audit
WHERE service_name in ('databrickssql')
  AND action_name in ('downloadQueryResult')
  AND COALESCE(response.status_code, 200) = 200

UNION ALL

-- Filesystem: file reads (exposes transferred bytes)
SELECT
  workspace_id,
  COALESCE(user_identity.email, identity_metadata.run_by) AS actor,
  'filesystem' AS source,
  action_name,
  CAST(request_params.path AS STRING) AS artifact,
  event_time
FROM system.access.audit
WHERE service_name = 'filesystem'
  AND action_name = 'filesGet'
  AND COALESCE(response.status_code, 200) = 200

UNION ALL

-- Notebooks: large results downloads from notebook runs
SELECT
  workspace_id,
  COALESCE(user_identity.email, identity_metadata.run_by) AS actor,
  'notebook' AS source,
  a.action_name,
  CAST(request_params.notebookFullPath AS STRING) AS artifact,
  event_time
FROM system.access.audit a
WHERE service_name = 'notebook'
  AND action_name in ('downloadLargeResults', 'downloadPreviewResults')
  AND COALESCE(response.status_code, 200) = 200

UNION ALL

-- Dashboards: snapshot/export triggers (successful only)
SELECT
  workspace_id,
  COALESCE(user_identity.email, identity_metadata.run_by) AS actor,
  'dashboards' AS source,
  a.action_name,
  CAST(a.request_params['dashboard_id'] AS STRING) AS artifact,
  event_time
FROM system.access.audit a
WHERE a.service_name = 'dashboards'
  AND a.action_name IN ('triggerDashboardSnapshot')
  AND a.response['status_code'] = 200;


-- COMMAND ----------

-- DBTITLE 1,Download by source
SELECT source, action_name, count(*) as num_actions FROM sec_v_data_export_detection
WHERE event_time between start_time and end_time 
group by all
order by num_actions desc
limit 10

-- COMMAND ----------

-- DBTITLE 1,Download by users
SELECT actor, 
count(*) as num_actions FROM sec_v_data_export_detection
WHERE event_time between start_time and end_time 
group by all
order by num_actions desc
limit 10