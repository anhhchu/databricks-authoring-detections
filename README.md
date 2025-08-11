# Security Detection-as-Code with Databricks

This project demonstrates how to author and deploy detection rules using SQL and Databricks notebooks for Security Detection-as-Code principles. The detection rules use Databricks system tables for real-time security monitoring and automatically create alerts for security incidents.

## 🏗️ Project Structure

```
databricks-authoring-detections/
├── src/                      # Source SQL files
│   ├── authentication/       # Authentication-related detections
│   │   ├── failed_login_detection.sql
│   │   └── privilege_escalation_detection.sql
│   ├── data_access/          # Data access anomaly detections
│   │   └── large_data_export_detection.sql
│   ├── create_alert.sql      # Alert creation and management
│   └── delete_alert.sql      # Alert deletion utilities, run on demand
├── resources/                # Databricks workflow configuration
│   └── databricks_workflow.yml
└── databricks.yml           # Bundle configuration
```

## 🚀 Key Features

- 📊 **SQL-based Detection Rules**: Leverage enterprise-grade SQL for sophisticated security detection logic
- 🔍 **Databricks System Tables**: Harness comprehensive operational data from your Databricks environment for deep visibility
- 🚨 **Automated Alert Creation**: Streamline security operations with intelligent alert generation and management
- 📦 **Databricks Asset Bundle (DAB)**: Enable seamless deployment across development, testing and production environments
- 🔄 **Workflow Orchestration**: Optimize detection rule execution with advanced dependency management and scheduling
- 📈 **Databricks AI/BI Dashboard**: Generate visualizations and interactive reports using Databricks SQL dashboards

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

## 🚨 Alerts Setup

### Alert Creation Workflow

The project includes an automated alert creation system that runs after all detection rules complete:

1. **Detection Execution**: All security detection rules run first
2. **Alert Generation**: The `create_alert.sql` script automatically creates alerts based on detection results
3. **Alert Management**: Alerts are configured with thresholds, notifications, and scheduling

### Alert Configuration

Alerts are automatically created with the following settings:

- **Failed Login Alert**: Triggers when failed login count > 0 in the last 168 hours
- **Account Admin Assignment**: Triggers when admin assignments > 5 in the last 168 hours  
- **Data Export Alert**: Triggers when data exports > 1000 in the last 168 hours
- **UC Permission Escalation**: Triggers when permission escalations > 5 in the last 168 hours

### Alert Parameters

Each alert can be configured with:

- **Threshold Values**: Configurable thresholds for triggering alerts
- **Comparison Operators**: Greater than, less than, equals, etc.
- **Notification Settings**: Email notifications to specified users
- **Schedule**: Cron-based scheduling for alert evaluation
- **Retrigger Settings**: Configurable retrigger intervals

### Customizing Alerts

To modify alert behavior, edit the `src/create_alert.sql` file:

```sql
-- Example: Modify threshold for failed login alert
SELECT create_alert(
  display_name => 'failed_login_alert',
  query_text => format_string(
    'SELECT COUNT(*) AS value
     FROM %s.%s.sec_v_auth_events
     WHERE event_time >= current_timestamp() - INTERVAL 168 HOURS',
    :catalog, :schema),
  warehouse_id => :warehouse_id,
  comparison_operator => 'GREATER_THAN',
  threshold_value => 5,  -- Changed from 0 to 5
  user_email => :user_email
) as alert;
```

## Data Requirement
### System Tables Access

The detection rules use Databricks system tables for real-time monitoring. Users must have READ permission on below system tables to run the detection rules.

#### **Audit Logs** (`system.access.audit`)
- **Purpose**: Authentication and privilege events
- **Retention**: 365 days (free)
- **Use Cases**: Login attempts, privilege changes, administrative actions


## 📚 Additional Resources

- [Databricks System Tables Documentation](https://docs.databricks.com/aws/en/admin/system-tables/)
- [Unity Catalog Setup Guide](https://docs.databricks.com/data-governance/unity-catalog/index.html)
- [Audit log system table reference](https://docs.databricks.com/aws/en/admin/system-tables/audit-logs.html)
- [Databricks Alerts Documentation](https://docs.databricks.com/aws/en/sql/user/alerts/)