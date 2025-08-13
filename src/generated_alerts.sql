-- Databricks Security Detection Alerts
-- Generated from rules.yml

-- COMMAND ----------

-- Alert for failed login attempts
SELECT create_alert(
  display_name => 'failed_login_alert',
  query_text => 'SELECT COUNT(*) AS value
FROM ${catalog}.${schema}.sec_v_auth_events
WHERE event_time >= current_timestamp() - INTERVAL 168 HOURS
',
  warehouse_id => ${warehouse_id},
  comparison_operator => 'GREATER_THAN',
  threshold_value => 0,
  empty_result_state => 'UNKNOWN',
  user_email => ${user_email},
  notify_on_ok => true,
  retrigger_seconds => 0,
  cron_schedule => '0 0 10 1/7 * ?',
  timezone_id => 'UTC',
  pause_status => 'PAUSED'
) as alert;

-- COMMAND ----------

-- Alert for account admin assignments
SELECT create_alert(
  display_name => 'account_admin_assignment',
  query_text => 'SELECT COUNT(*) AS admin_assignments
FROM ${catalog}.${schema}.sec_v_account_admin_assignments
WHERE event_time >= current_timestamp() - INTERVAL 168 HOURS
',
  warehouse_id => ${warehouse_id},
  comparison_operator => 'GREATER_THAN',
  threshold_value => 5,
  empty_result_state => 'UNKNOWN',
  user_email => ${user_email},
  notify_on_ok => true,
  retrigger_seconds => 0,
  cron_schedule => '0 0 10 1/7 * ?',
  timezone_id => 'UTC',
  pause_status => 'PAUSED'
) as alert;

-- COMMAND ----------

-- Alert for large data exports
SELECT create_alert(
  display_name => 'data_export_alert',
  query_text => 'SELECT COUNT(*) AS exports
FROM ${catalog}.${schema}.sec_v_data_export_detection
WHERE event_time >= current_timestamp() - INTERVAL 168 HOURS
',
  warehouse_id => ${warehouse_id},
  comparison_operator => 'GREATER_THAN',
  threshold_value => 1000,
  empty_result_state => 'UNKNOWN',
  user_email => ${user_email},
  notify_on_ok => true,
  retrigger_seconds => 0,
  cron_schedule => '0 0 10 1/7 * ?',
  timezone_id => 'UTC',
  pause_status => 'PAUSED'
) as alert;

-- COMMAND ----------

-- Alert for Unity Catalog permission escalations
SELECT create_alert(
  display_name => 'uc_permission_escalation',
  query_text => 'SELECT COUNT(*) AS permission_escalations
FROM ${catalog}.${schema}.sec_v_uc_permission_escalations
WHERE event_time >= current_timestamp() - INTERVAL 168 HOURS
',
  warehouse_id => ${warehouse_id},
  comparison_operator => 'GREATER_THAN',
  threshold_value => 5,
  empty_result_state => 'UNKNOWN',
  user_email => ${user_email},
  notify_on_ok => true,
  retrigger_seconds => 0,
  cron_schedule => '0 0 10 1/7 * ?',
  timezone_id => 'UTC',
  pause_status => 'PAUSED'
) as alert;

-- COMMAND ----------
