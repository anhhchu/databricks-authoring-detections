# Example Usage of Generated Alerts

This document shows how to use the alerts generated from `rules.yml` in your Databricks workspace.

## 1. Generate Alerts from Rules

First, generate the SQL alerts from your rules configuration:

```bash
python src/generate_alerts.py
```

This creates `src/generated_alerts.sql` with all your configured alerts.

## 2. Use in Databricks Notebook

Copy the generated SQL into a Databricks notebook and run it. The alerts will be created automatically.

## 3. Customizing Rules

### Adding a New Alert

Add this to your `rules.yml`:

```yaml
alerts:
  # ... existing alerts ...
  
  new_security_alert:
    display_name: "new_security_alert"
    description: "Custom security detection"
    query_template: |
      SELECT COUNT(*) AS suspicious_activity
      FROM {catalog}.{schema}.your_security_table
      WHERE event_time >= current_timestamp() - INTERVAL 24 HOURS
      AND risk_score > 0.8
    comparison_operator: "GREATER_THAN"
    threshold_value: 10
    cron_schedule: "0 */6 * * * ?"  # Every 6 hours
```

### Modifying Existing Alerts

Change threshold values, comparison operators, or scheduling:

```yaml
alerts:
  data_export_alert:
    # ... other settings ...
    threshold_value: 500  # Changed from 1000
    cron_schedule: "0 */2 * * * ?"  # Every 2 hours instead of weekly
```

### Global Settings

Modify settings that apply to all alerts:

```yaml
global:
  # ... other settings ...
  timezone_id: "America/New_York"  # Change timezone
  notify_on_ok: false              # Don't notify on OK status
```

## 4. Environment Variables

The rules use placeholders that get replaced with actual values:

- `${catalog}` → Your Unity Catalog name
- `${schema}` → Your schema name  
- `${warehouse_id}` → Your SQL warehouse ID
- `${user_email}` → Email for notifications

## 5. Regenerating Alerts

After any changes to `rules.yml`, regenerate the SQL:

```bash
python src/generate_alerts.py
```

Then copy the new `generated_alerts.sql` content to your Databricks notebook.

## 6. Validation

The generated SQL includes:
- Proper SQL escaping for quotes
- All required parameters
- Consistent formatting
- Clear comments for each alert

## 7. Best Practices

- Keep alert descriptions clear and actionable
- Use appropriate threshold values for your environment
- Test alerts in development before production
- Version control your `rules.yml` alongside code
- Document any custom query logic in descriptions
