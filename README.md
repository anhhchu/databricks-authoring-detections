# Detection-as-Code with Databricks

This project demonstrates how to author, test, and deploy detection rules using SQL and Databricks notebooks following Detection-as-Code principles. The detection rules use Databricks system tables for real-time security monitoring.

## 🏗️ Project Structure

```
databricks-authoring-detections/
└── detections/                 # Detection rule notebooks
    ├── authentication/        # Authentication-related detections
    │   ├── failed_login_detection.sql
    │   └── privilege_escalation_detection.sql
    └── data_access/           # Data access anomaly detections
        └── data_exfiltration_detection.sql
```

## 🚀 Key Features

- **SQL-based Detection Rules**: Write detection logic using familiar SQL syntax
- **Databricks System Tables**: Use real operational data from Databricks environment
- **Real-time Monitoring**: Query data from system tables for live detection
- **Rule Management**: Rule Configuration Delta table for rule lifecycle management
- **Databricks Asset Bundle (DAB)**: Deploy detection rules across workspaces to different environment dev, test, prod

## 📋 Prerequisites

Before you begin, ensure you have:

1. **Databricks Workspace**: Access to a Databricks workspace with appropriate permissions
2. **DBSQL Warehouse Access**: Ability to create and manage Databricks SQL Warehouse
3. **Git Repository**: Version control setup for your detection rules
4. **Python Environment**: Python 3.11+ with required packages
5. **Unity Catalog**: Workspace must be enabled for Unity Catalog to access system tables

## 🚀 Quick Starts

### 1. Python Virtual Environment

```bash

python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Install the Databricks CLI
Install the Databricks CLI from https://docs.databricks.com/dev-tools/cli/install.html

### 3. Authenticate to your Databricks workspace
Choose one of the following authentication methods:

#### Option A: Personal Access Token (PAT)

1. **Generate Personal Access Token:**
   - Log into your Databricks workspace
   - Click on your username in the top-right corner
   - Select **User Settings** → **Developer** → **Access tokens**
   - Click **Generate new token**
   - Give it a name (e.g., "Local Development") and set expiration
   - Copy the generated token

2. **Configure CLI with PAT:**
   ```bash
   databricks configure --token --profile DEFAULT
   ```
   
   You'll be prompted for:
   - **Databricks Host**: `https://your-workspace.cloud.databricks.com`
   - **Token**: Paste your generated token

    This will update DEFAULT profile in `~/.databrickscfg` 

#### Option B: OAuth Authentication

Configure OAuth:

```bash
databricks auth login --host https://your-workspace.cloud.databricks.com --profile DEFAULT
```

This will:
- Open your browser for authentication
- Create a profile in `~/.databrickscfg`
- Store OAuth credentials securely

#### Verify Databricks Configuration

Check your configuration:

```bash
# List all profiles
cat ~/.databrickscfg
```

Your `~/.databrickscfg` should look like:

```ini
[DEFAULT]
host = https://your-workspace.cloud.databricks.com
token = dapi123abc...

[DEV]
host = https://dev-workspace.cloud.databricks.com
token = dapi456def...

[PROD]
host = https://prod-workspace.cloud.databricks.com
token = databricks-cli
```

### 4. Configure databricks.yml Variables
Update the variables in `databricks.yml` to match your environment. The dev target defaults to catalog `users` and a schema based on on the developer's name.

- **catalog**: The catalog name where your tables will be created
- **schema**: The schema name within the catalog
- **warehouse_id**: ID of your SQL warehouse for production deployment. For development, the bundle will lookup the ID based on the specified name (Eg, Shared Serverless).
- **workspace.host**: Your Databricks workspace URL

Example configuration for prod target:
```yaml
targets:
  prod:
    mode: production
    default: true
    workspace:
      host: https://your-workspace.cloud.databricks.com
    variables:
      warehouse_id: your_warehouse_id
      catalog: your_catalog
      schema: your_schema
```

### 5. Deploy to Databricks Workspace

#### Deploy in Development Environment

```bash
$ databricks bundle deploy --target dev --profile DEFAULT
```
Note: Since "dev" is specified as the default target in databricks.yml, you can omit the `--target dev` parameter. Similarly, `--profile DEFAULT` can be omitted if you only have one profile configured for your workspace.

This deploys everything that's defined for this project, including:
- A job called `[dev yourname] databricks_authoring_detecion_job`
- All associated resources

You can find the deployed job by opening your workspace and clicking on **Workflows**.

#### Deploy to Production Environment
```bash
$ databricks bundle deploy --target prod --profile PROD
```

### Run a Job

**Run in Dev**

```bash
$ databricks bundle run --target dev --profile DEFAULT
```
**Run in Prod**

```bash
$ databricks bundle run --target prod --profile PROD
```

## Data Requirement
### System Tables Access

The detection rules use Databricks system tables for real-time monitoring:

#### 1. **Audit Logs** (`system.access.audit`)
- **Purpose**: Authentication and privilege events
- **Retention**: 365 days (free)
- **Streaming**: Yes
- **Use Cases**: Login attempts, privilege changes, administrative actions

#### 2. **Query History** (`system.query.history`)
- **Purpose**: Query execution history
- **Retention**: 180 days
- **Use Cases**: Data access patterns, query performance, user behavior analysis

#### 3. **Table Lineage** (`system.access.table_lineage`)
- **Purpose**: Table read/write events
- **Retention**: 365 days (free)
- **Streaming**: Yes
- **Use Cases**: Data access tracking, lineage analysis

### Grant System Table Permissions

Access to system tables is governed by Unity Catalog. To grant access:

```sql
-- Grant access to system tables (run as metastore admin)
GRANT USE ON SCHEMA system.access TO `your-security-group`;
GRANT SELECT ON SCHEMA system.access TO `your-security-group`;
GRANT USE ON SCHEMA system.query TO `your-security-group`;
GRANT SELECT ON SCHEMA system.query TO `your-security-group`;
```

## 🛠️ Additional Development Workflow

### 1. Create a New Detection Rule

#### Step 1: Add Rule Configuration to Delta Table

1. **Add rule configuration for all environments**:
   ```sql
   -- Insert new rule configuration into the rules_configuration table
   INSERT INTO rules_configuration VALUES
   -- Development Environment
   ('AUTH-004', 'Suspicious Login Locations Detection', 'dev', 'security', 'detections', 
    'detections.suspicious_locations_results', 24, 'medium', 0.6, 
    map('distance_threshold_km', '500', 'min_login_count', '2'), 
    current_timestamp(), current_timestamp(), true),
   
   -- Production Environment  
   ('AUTH-004', 'Suspicious Login Locations Detection', 'prod', 'security', 'detections',
    'detections.suspicious_locations_results', 24, 'medium', 0.8,
    map('distance_threshold_km', '1000', 'min_login_count', '3'),
    current_timestamp(), current_timestamp(), true);
   ```

#### Step 2: Create Location Detection Notebook

1. **Create Notebook**: `detections/authentication/suspicious_login_locations.sql`

2. **Add Standard Template**:
   ```sql
   -- MAGIC %md
   -- MAGIC # Suspicious Login Locations Detection
   -- MAGIC 
   -- MAGIC **Rule ID**: AUTH-004
   -- MAGIC **Author**: Security Team
   -- MAGIC **Version**: 1.0.0
   -- MAGIC 
   -- MAGIC ## Overview
   -- MAGIC Detects logins from unusual geographic locations using Databricks system tables
   -- MAGIC 
   -- MAGIC ## Data Sources
   -- MAGIC - system.access.audit (Primary)
   ```

3. **Implement Standard Configuration Pattern**:
   ```sql
   -- Load rule configuration from central configuration table
   use catalog identifier(:catalog);
   use schema identifier(:schema);

   CREATE OR REPLACE TEMP VIEW rule_config AS
   SELECT 
       rule_id, rule_name, environment, target_table,
       time_window_hours, severity, confidence_threshold,
       rule_specific_config['distance_threshold_km'] as distance_threshold_km,
       rule_specific_config['min_login_count'] as min_login_count
   FROM current_rule_config
   WHERE rule_id = 'AUTH-004' 
     AND environment = '${environment}';

   -- Define time window variables
   DECLARE OR REPLACE VARIABLE end_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP();
   DECLARE OR REPLACE VARIABLE start_time TIMESTAMP DEFAULT (
       SELECT CURRENT_TIMESTAMP() - INTERVAL (SELECT time_window_hours FROM rule_config) HOURS
   );
   ```

4. **Implement Detection Logic**:
   ```sql
   -- Detection query using system tables and configuration
   CREATE OR REPLACE TEMP VIEW suspicious_locations AS
   SELECT 
       user_identity.email as username,
       source_ip_address as source_ip,
       request_params.geolocation as geolocation,
       COUNT(*) as login_count,
       MIN(timestamp) as first_login,
       MAX(timestamp) as last_login
   FROM system.access.audit
   WHERE timestamp >= start_time
     AND timestamp <= end_time
     AND event_name IN ('login', 'loginFailed')
     AND user_identity.email IS NOT NULL
   GROUP BY user_identity.email, source_ip_address, request_params.geolocation
   HAVING COUNT(*) >= (SELECT CAST(min_login_count AS INT) FROM rule_config);

   -- Generate detection results
   CREATE OR REPLACE TEMP VIEW detection_results AS
   SELECT 
       rc.rule_id, rc.rule_name, rc.severity,
       0.75 as confidence, -- Calculate based on your logic
       'LOCATION_ANOMALY' as detection_type,
       sl.username as entity_name,
       'user' as entity_type,
       sl.login_count, sl.geolocation, sl.source_ip,
       sl.first_login, sl.last_login,
       current_timestamp() as detection_timestamp,
       'system.access.audit' as data_source,
       'Databricks System Tables' as platform
   FROM suspicious_locations sl
   CROSS JOIN rule_config rc;
   ```

#### Step 3: Add to Workflow (Optional)

If you want the new rule to run automatically with other detections:

```yaml
# Add to resources/databricks_workflow.yml tasks section:
- task_key: suspicious_login_locations_detection
  depends_on:
    - task_key: rule_configuration_setup
  notebook_task:
    notebook_path: ../detections/authentication/suspicious_login_locations.sql
    source: WORKSPACE
    warehouse_id: ${var.warehouse_id}
```

Finally, follow the deployment process above to deploy new rules

## 📚 Additional Resources

- [Databricks System Tables Documentation](https://docs.databricks.com/aws/en/admin/system-tables/)
- [Unity Catalog Setup Guide](https://docs.databricks.com/data-governance/unity-catalog/index.html)
- [System Tables Access Guide](https://docs.databricks.com/aws/en/admin/system-tables/audit-logs.html)