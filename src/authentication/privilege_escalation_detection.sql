-- Databricks notebook source
-- MAGIC %md
-- MAGIC # Privilege Escalation Detection Rule (System Tables)
-- MAGIC
-- MAGIC **Rule ID**: AUTH-002  
-- MAGIC **Author**: Security Team  
-- MAGIC **Version**: 2.0.0  
-- MAGIC
-- MAGIC ## Overview
-- MAGIC This detection rule identifies potential privilege escalation attempts by monitoring for unusual elevation of user permissions, role changes, and administrative actions performed by non-administrative users using Databricks system tables.
-- MAGIC
-- MAGIC ## Detection Logic
-- MAGIC - Monitors system.access.audit for permission/role changes
-- MAGIC - Identifies users gaining elevated privileges
-- MAGIC - Detects high-risk administrative actions
-- MAGIC
-- MAGIC ## MITRE ATT&CK Mapping
-- MAGIC - **Tactic**: TA0004 (Privilege Escalation)
-- MAGIC - **Technique**: T1548 (Abuse Elevation Control Mechanism)
-- MAGIC
-- MAGIC ## Data Sources
-- MAGIC - system.access.audit

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Configuration Parameters

-- COMMAND ----------

use catalog identifier(:catalog);
use schema identifier(:schema);

-- COMMAND ----------

-- MAGIC %md
-- MAGIC ## Privileges views

-- COMMAND ----------

-- DBTITLE 1,Account Admin Granted
CREATE VIEW IF NOT EXISTS sec_v_account_admin_assignments AS
SELECT
  event_time,
  service_name,
  workspace_id,
  COALESCE(user_identity.email, identity_metadata.run_by) AS actor,
  request_params['targetUserName']     AS target_user,
  action_name,
  'ACCOUNT_ADMIN_GRANTED' AS indicator,
  'Critical' as severity
FROM system.access.audit
WHERE service_name = 'accounts'
  AND action_name in ('setAccountAdmin', 'setAdmin');


-- COMMAND ----------

-- DBTITLE 1,Workspace Acl Changed
CREATE VIEW IF NOT EXISTS sec_v_workspace_acl_assignments AS
SELECT
  event_time,
  service_name,
  workspace_id,
  COALESCE(user_identity.email, identity_metadata.run_by) AS actor,
  request_params['targetUserId']     AS target_user,
  action_name,
  request_params['aclPermissionSet']     AS new_acl,
  'WORKSPACE_ACL_CHANGED' AS indicator,
  'Medium' as severity
FROM system.access.audit
WHERE service_name = 'accounts'
  AND action_name = 'changeDatabricksWorkspaceAcl';


-- COMMAND ----------

-- DBTITLE 1,Added to sensitive group
CREATE VIEW IF NOT EXISTS sec_v_sensitive_group_additions AS
WITH sensitive_groups AS (
  SELECT explode(array('admins','account_admins','metastore_admins','security-admins')) AS group_name
)
SELECT
  a.event_time,
  a.service_name,
  a.workspace_id,
  COALESCE(user_identity.email, identity_metadata.run_by) AS actor,
  a.request_params['targetUserName']   AS target_user,
  a.request_params['targetGroupName']  AS group_name,
  a.action_name,
  'SENSITIVE_GROUP_ADDED' AS indicator,
  'Medium' as severity
FROM system.access.audit a
JOIN sensitive_groups sg
  ON sg.group_name = a.request_params['targetGroupName']
WHERE a.service_name = 'accounts'
  AND a.action_name IN ('addPrincipalToGroup','addPrincipalsToGroup');


-- COMMAND ----------

-- DBTITLE 1,DBSQL ACL changes
CREATE VIEW IF NOT EXISTS sec_v_workspace_db_sql_acl_changes AS
SELECT
  event_time,
  service_name,
  workspace_id,
  COALESCE(user_identity.email, identity_metadata.run_by) AS actor,
  request_params['targetUserId'] as target_principal,
  action_name,
  request_params['aclPermissionSet']     AS new_acl,
  'WORKSPACE_OR_DBSQL_ACL_CHANGE' AS indicator,
  'Medium' as severity
FROM system.access.audit
WHERE service_name = 'accounts'
  AND action_name IN ('changeDatabricksSqlAcl');

-- COMMAND ----------

-- DBTITLE 1,Unity Catalog - sensitive data permissions
CREATE VIEW IF NOT EXISTS sec_v_uc_permission_escalations AS

WITH sensitive_tables AS
(SELECT
  concat(catalog_name,'.',schema_name,'.', table_name) as securable_full_name
FROM
  system.information_schema.table_tags where tag_value like '%pii%'
)

SELECT
  event_time, service_name, workspace_id,
  COALESCE(user_identity.email, identity_metadata.run_by) AS actor,
  request_params['securable_type']                     AS securable_type,
  request_params['securable_full_name']                AS securable_full_name,
  action_name,
  'UC_PERMISSION_CHANGE'                               AS escalation_type,
  changes_item['principal']                            AS target_principal,
  changes_item['add']                                  AS permissions
FROM system.access.audit a
left join sensitive_tables t ON t.securable_full_name = request_params['securable_full_name']
LATERAL VIEW explode(from_json(request_params['changes'], 'array<struct<principal:string, add:string>>')) AS changes_item
WHERE service_name = 'unityCatalog'
  AND action_name = 'updatePermissions'
  AND (
    request_params['changes'] LIKE '%OWNERSHIP%' OR
    request_params['changes'] LIKE '%ALL_PRIVILEGES%' OR
    request_params['changes'] LIKE '%MANAGE%'
  )
  and (request_params['securable_full_name']  like '%pii%' or request_params['securable_full_name']  = 'system' or t.securable_full_name is not null)
  and request_params['securable_type']   in ('CATALOG', 'SCHEMA', 'TABLE') ;


-- COMMAND ----------

-- DBTITLE 1,Account-level settings changed
CREATE VIEW IF NOT EXISTS sec_v_account_setting_changes AS
SELECT
  event_time,
  service_name,
  workspace_id,
  COALESCE(user_identity.email, identity_metadata.run_by) AS actor,
  action_name,
  request_params['settingKeyTypeName']             AS key_type,
  request_params['settingKeyName']                 AS key_name,
  request_params['settingValueForAudit']           AS settings
FROM system.access.audit
WHERE service_name = 'accounts'
  AND action_name IN ('setSetting','deleteSetting');
