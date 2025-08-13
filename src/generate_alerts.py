#!/usr/bin/env python3
"""
Databricks Security Detection Alert Generator
Reads rules.yml and generates SQL alerts dynamically
"""

import yaml
import os
from typing import Dict, Any
from pathlib import Path

def load_rules(rules_file: str = "rules.yml") -> Dict[str, Any]:
    """Load alert rules from YAML file"""
    with open(rules_file, 'r') as f:
        return yaml.safe_load(f)

def generate_alert_sql(alert_config: Dict[str, Any], global_config: Dict[str, Any]) -> str:
    """Generate SQL for a single alert"""
    
    # Format the query template with catalog and schema placeholders
    query_text = alert_config['query_template'].format(
        catalog=global_config['catalog'],
        schema=global_config['schema']
    )
    
    sql = f"""-- {alert_config['description']}
SELECT create_alert(
  display_name => '{alert_config['display_name']}',
  query_text => '{query_text.replace("'", "''")}',
  warehouse_id => {global_config['warehouse_id']},
  comparison_operator => '{alert_config['comparison_operator']}',
  threshold_value => {alert_config['threshold_value']},
  empty_result_state => '{alert_config.get('empty_result_state', 'UNKNOWN')}',
  user_email => {global_config['user_email']},
  notify_on_ok => {str(global_config['notify_on_ok']).lower()},
  retrigger_seconds => {global_config['retrigger_seconds']},
  cron_schedule => '{alert_config.get('cron_schedule', global_config.get('cron_schedule', '0 0 10 1/7 * ?'))}',
  timezone_id => '{global_config['timezone_id']}',
  pause_status => '{global_config['pause_status']}'
) as alert;"""
    
    return sql

def generate_all_alerts_sql(rules: Dict[str, Any]) -> str:
    """Generate SQL for all alerts"""
    
    global_config = rules['global']
    alerts = rules['alerts']
    
    sql_parts = [
        "-- Databricks Security Detection Alerts",
        "-- Generated from rules.yml",
        "",
        "-- COMMAND ----------",
        ""
    ]
    
    for alert_name, alert_config in alerts.items():
        sql_parts.append(generate_alert_sql(alert_config, global_config))
        sql_parts.append("")
        sql_parts.append("-- COMMAND ----------")
        sql_parts.append("")
    
    return "\n".join(sql_parts)

def main():
    """Main function to generate alerts"""
    try:
        # Load rules
        rules = load_rules()
        
        # Generate SQL
        sql_content = generate_all_alerts_sql(rules)
        
        # Write to file
        output_file = "src/generated_alerts.sql"
        with open(output_file, 'w') as f:
            f.write(sql_content)
        
        print(f"✅ Generated alerts SQL: {output_file}")
        print(f"📊 Total alerts generated: {len(rules['alerts'])}")
        
        # Print alert summary
        print("\n📋 Alert Summary:")
        for alert_name, config in rules['alerts'].items():
            print(f"  • {config['display_name']}: {config['description']}")
            print(f"    Threshold: {config['comparison_operator']} {config['threshold_value']}")
        
    except FileNotFoundError:
        print("❌ Error: rules.yml not found. Please ensure the file exists in the current directory.")
    except yaml.YAMLError as e:
        print(f"❌ Error parsing YAML: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()
