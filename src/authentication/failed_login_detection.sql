-- Databricks notebook source
-- MAGIC %md
-- MAGIC # Failed Login Detection Rule (System Tables)
-- MAGIC
-- MAGIC **Rule ID**: AUTH-001  
-- MAGIC **Author**: Security Team  
-- MAGIC **Version**: 2.0.0  
-- MAGIC
-- MAGIC ## Overview
-- MAGIC This detection rule identifies multiple failed login attempts from the same source IP or targeting the same user account within a specified time window using Databricks system tables.
-- MAGIC
-- MAGIC ## Detection Logic
-- MAGIC - Monitors system.access.audit for authentication events
-- MAGIC - Groups by source IP and target user
-- MAGIC - Triggers when threshold exceeded within time window
-- MAGIC
-- MAGIC ## Data Sources
-- MAGIC - system.access.audit

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Configuration Variables

-- COMMAND ----------

use catalog identifier(:catalog);
use schema identifier(:schema);

-- COMMAND ----------

-- Define time window variables for the analysis
DECLARE OR REPLACE VARIABLE end_time = CURRENT_TIMESTAMP();
DECLARE OR REPLACE VARIABLE start_time TIMESTAMP;
SET VARIABLE start_time = (SELECT CURRENT_TIMESTAMP() - INTERVAL 168 HOURS);

select start_time, end_time;

-- COMMAND ----------

CREATE VIEW IF NOT EXISTS sec_v_auth_events AS
select
  event_time, 
  event_date,
  service_name,
  coalesce(user_identity.email,request_params.user) as username,
  request_params.authenticationMethod as authentication_method,
  user_agent,
  action_name,
  response.status_code as response_code, 
  response.error_message as response_message,
  response.result as result,
  source_ip_address as source_ip
from system.access.audit 
where action_name IN ('login', 'logout')
and response.status_code <> 200;

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Failed Login Detection

-- COMMAND ----------

CREATE OR REPLACE TEMP VIEW sec_v_failed_login_detection AS
---- set a schedule to refresh for mv
-- SCHEDULE EVERY 1 DAY
with
failed_logins_by_ip AS (
  SELECT 
      source_ip,
      response_message,
      COUNT(*) AS failed_attempts,
      COUNT(DISTINCT username) AS unique_users,
      MIN(event_time) AS first_attempt,
      MAX(event_time) AS last_attempt,
      COLLECT_LIST(DISTINCT username) AS targeted_usernames,
      COLLECT_LIST(DISTINCT user_agent) AS user_agents
  FROM sec_v_auth_events
  WHERE source_ip IS NOT NULL
  and event_time >= start_time and event_time <= end_time
  GROUP BY source_ip, response_message
),
failed_logins_by_user AS (
  SELECT 
      username,
      COUNT(*) AS failed_attempts,
      COUNT(DISTINCT source_ip) AS unique_source_ips,
      MIN(event_time) AS first_attempt,
      MAX(event_time) AS last_attempt,
      COLLECT_LIST(DISTINCT source_ip) AS source_ips,
      COLLECT_LIST(DISTINCT user_agent) AS user_agents
  FROM sec_v_auth_events
  where username is not null
  and event_time >= start_time and event_time <= end_time
  GROUP BY username
)
-- IP-based detections
SELECT 
    'IP_BASED' AS detection_type,
    ip.source_ip AS entity_id,
    ip.source_ip AS entity_name,
    'source_ip' AS entity_type,
    ip.failed_attempts AS failed_attempts,
    ip.unique_users AS unique_entities,          -- will carry `unique_users`
    ip.targeted_usernames AS related_entities,   -- will carry usernames list
    ip.user_agents AS user_agents,
    ip.first_attempt AS first_attempt,
    ip.last_attempt AS last_attempt,
    current_timestamp() AS detection_timestamp
FROM failed_logins_by_ip ip

UNION ALL

-- User-based detections 
SELECT 
    'USER_BASED' AS detection_type,
    u.username AS entity_id,
    u.username AS entity_name,
    'user' AS entity_type,
    u.failed_attempts AS failed_attempts,
    u.unique_source_ips AS unique_entities,      -- mapped into same column
    u.source_ips AS related_entities,            -- mapped into same column
    u.user_agents AS user_agents,
    u.first_attempt AS first_attempt,
    u.last_attempt AS last_attempt,
    current_timestamp() AS detection_timestamp
FROM failed_logins_by_user u;



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
    'Databricks System Tables (system.access.audit)' as data_source
FROM (
    SELECT COUNT(*) as detection_count 
    FROM sec_v_auth_events
    where event_time >= start_time and event_time <= end_time
) det_summary;