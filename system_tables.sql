CREATE TABLE system.access.audit (
    account_id STRING COMMENT 'Unique identifier for the Databricks account associated with the event.',
    workspace_id STRING COMMENT 'Unique identifier for the Databricks workspace where the event took place. For account-level events, this may be set to 0.',
    version STRING COMMENT 'Audit log schema version',
    event_time TIMESTAMP COMMENT 'Timestamp of the event',
    event_date DATE COMMENT 'The calendar date when the event or action occurred. Useful for filtering and aggregating events by day.',
    source_ip_address STRING COMMENT 'The IP address from which the request originated.',
    user_agent STRING COMMENT 'The user agent string or identifier describing the client, browser, or tool that initiated the request (e.g., web browser, API client, CLI)',
    session_id STRING COMMENT 'Unique identifier for the session in which the request was made. Sessions group related actions by a user or service over a period of time',
    user_identity STRUCT < email: STRING,
    subject_name: STRING > COMMENT 'Structured information about the user or service account that initiated the request, including email and subject name.',
    service_name STRING COMMENT 'Name of the Databricks service or component that processed the request. See [service documentation](https://docs.databricks.com/en/admin/account-settings/audit-logs#audit-log-services) for details.',
    action_name STRING COMMENT 'The type or category of event captured. See [documentation of actions per service](https://docs.databricks.com/en/admin/account-settings/audit-logs) for details.',
    request_id STRING COMMENT 'Unique identifier for the specific request, allowing for traceability and correlation across logs',
    request_params MAP < STRING,
    STRING > COMMENT 'Map of key values containing all the request parameters. Specific params depend on the request type. See [documentation of request parameters per action](https://docs.databricks.com/<cloud>/en/admin/account-settings/audit-logs) for details.',
    response STRUCT < status_code: INT,
    error_message: STRING,
    result: STRING > COMMENT 'Struct of response, includes status code, error messages, and result string',
    audit_level STRING COMMENT 'Indicates whether the event is at the workspace or account level. Either `ACCOUNT_LEVEL` or `WORKSPACE_LEVEL`.',
    event_id STRING COMMENT 'Unique identifier for the event.',
    identity_metadata STRUCT < run_by: STRING,
    run_as: STRING > COMMENT 'Identities involved in the action, including run_by and run_as. See [Auditing group dedicated compute activity documentation](https://docs.databricks.com/en/compute/group-access#auditing-group-dedicated-compute-activity) for more details.'
);

CREATE TABLE system.query.history (
    account_id STRING COMMENT 'ID of the account.',
    workspace_id STRING COMMENT 'The ID of the workspace where the query was run.',
    statement_id STRING COMMENT 'The ID that uniquely identifies the execution of the statement. You can use this ID to find the statement execution in the Query History UI.',
    executed_by STRING COMMENT 'The email address or username of the user who ran the statement.',
    session_id STRING COMMENT 'The Spark session ID.',
    execution_status STRING COMMENT 'The statement termination state. Possible values are:

FINISHED: execution was successful

FAILED: execution failed with the reason for failure described in the accompanying error message

CANCELED: execution was canceled',
    compute STRUCT < type: STRING,
    cluster_id: STRING,
    warehouse_id: STRING COMMENT 'The warehouse ID.' > COMMENT 'A struct that represents the type of compute resource used to run the statement and the ID of the resource where applicable. The type value will be WAREHOUSE.',
    executed_by_user_id STRING COMMENT 'The ID of the user who ran the statement.',
    statement_text STRING COMMENT 'Text of the SQL statement. If you have configured customer-managed keys, statement_text is empty.',
    statement_type STRING COMMENT 'The statement type. For example: ALTER, COPY, and`INSERT`.',
    error_message STRING COMMENT 'Message describing the error condition. If you have configured customer-managed keys, error_message is empty.',
    client_application STRING COMMENT 'Client application that ran the statement. For example: Databricks SQL, Tableau, and Power BI.',
    client_driver STRING COMMENT 'The connector used to connect to Databricks to run the statement. For example: Databricks SQL Driver for Go, Databricks ODBC Driver, Databricks JDBC Driver.',
    total_duration_ms BIGINT COMMENT 'Total execution time of the statement in milliseconds ( excluding result fetch time ).',
    waiting_for_compute_duration_ms BIGINT COMMENT 'Time spent waiting for compute resources to be provisioned in milliseconds.',
    waiting_at_capacity_duration_ms BIGINT COMMENT 'Time spent waiting in queue for available compute capacity in milliseconds.',
    execution_duration_ms BIGINT COMMENT 'Time spent executing the statement in milliseconds.',
    compilation_duration_ms BIGINT COMMENT 'Time spent loading metadata and optimizing the statement in milliseconds.',
    total_task_duration_ms BIGINT COMMENT 'The sum of all task durations in milliseconds. This time represents the combined time it took to run the query across all cores of all nodes. It can be significantly longer than the wall-clock duration if multiple tasks are executed in parallel. It can be shorter than the wall-clock duration if tasks wait for available nodes.',
    result_fetch_duration_ms BIGINT COMMENT 'Time spent, in milliseconds, fetching the statement results after the execution finished.',
    start_time TIMESTAMP COMMENT 'The time when Databricks received the request. Timezone information is recorded at the end of the value with +00:00 representing UTC.',
    end_time TIMESTAMP COMMENT 'The time the statement execution ended, excluding result fetch time. Timezone information is recorded at the end of the value with +00:00 representing UTC.',
    update_time TIMESTAMP COMMENT 'The time the statement last received a progress update. Timezone information is recorded at the end of the value with +00:00 representing UTC.',
    read_partitions BIGINT COMMENT 'The number of partitions read after pruning.',
    pruned_files BIGINT COMMENT 'The number of pruned files.',
    read_files BIGINT COMMENT 'The number of files read after pruning.',
    read_rows BIGINT COMMENT 'Total number of rows read by the statement.',
    produced_rows BIGINT COMMENT 'Total number of rows returned by the statement.',
    read_bytes BIGINT COMMENT 'Total size of data read by the statement in bytes.',
    read_io_cache_percent TINYINT COMMENT 'The percentage of bytes of persistent data read from the IO cache.',
    from_result_cache BOOLEAN COMMENT 'TRUE indicates that the statement result was fetched from the cache.',
    spilled_local_bytes BIGINT COMMENT 'Size of data, in bytes, temporarily written to disk while executing the statement.',
    written_bytes BIGINT COMMENT 'The size in bytes of persistent data written to cloud object storage.',
    shuffle_read_bytes BIGINT COMMENT 'The total amount of data in bytes sent over the network.',
    query_source STRUCT < job_info: STRUCT < job_id: STRING,
    job_run_id: STRING,
    job_task_run_id: STRING >,
    legacy_dashboard_id: STRING,
    dashboard_id: STRING,
    alert_id: STRING,
    notebook_id: STRING,
    sql_query_id: STRING,
    genie_space_id: STRING > COMMENT 'A struct that contains key-value pairs representing one or more Databricks entities that were involved in the execution of this statement, such as jobs, notebooks, or dashboards. This field only records Databricks entities and are not sorted by execution order. Statement executions that contain multiple IDs indicate that the execution was triggered by multiple entities: for example, an Alert may trigger on a Job result and call a SQL Query, so all three IDs will be populated within query_source.',
    executed_as_user_id STRING COMMENT 'The ID of the user or service principal whose privilege was used to run the statement.',
    executed_as STRING COMMENT 'The name of the user or service principal whose privilege was used to run the statement.'
);

CREATE TABLE system.access.table_lineage (
    account_id STRING COMMENT 'The id of the Databricks account.',
    metastore_id STRING COMMENT 'The id of the Unity Catalog metastore.',
    workspace_id STRING COMMENT 'The id of the workspace',
    entity_type STRING COMMENT 'The type of entity the lineage transaction was captured from. The value is NOTEBOOK, JOB, PIPELINE, DASHBOARD_V3 (Dashboard), DBSQL_DASHBOARD (Legacy dashboard), DBSQL_QUERY, OR NULL.',
    entity_id STRING COMMENT 'The ID of the entity the lineage transaction was captured from. If entity_type is NULL, entity_id is NULL.',
    entity_run_id STRING COMMENT 'id to describe the unique run of the entity, or NULL. This differs for each entity type:

Notebook: command_run_id

Job: job_run_id

Databricks SQL query: statement_id

Dashboard: statement_id

Legacy dashboard: statement_id

Pipeline: pipeline_update_id

If entity_type is NULL, entity_run_id is NULL. Records with statement_id and job_run_id can be joined with the query history and jobs system tables respectively.',
    source_table_full_name STRING COMMENT 'Three-part name to identify the source table.',
    source_table_catalog STRING COMMENT 'The catalog of the source table.',
    source_table_schema STRING COMMENT 'The schema of the source table.',
    source_table_name STRING COMMENT 'The name of the source table.',
    source_path STRING COMMENT 'Location in cloud storage of the source table, or the path if it’s reading from cloud storage directly.',
    source_type STRING COMMENT 'The type of the source. The value is TABLE, PATH, VIEW, MATERIALIZED_VIEW, METRIC_VIEW, or STREAMING_TABLE.',
    target_table_full_name STRING COMMENT 'Three-part name to identify the target table.',
    target_table_catalog STRING COMMENT 'The catalog of the target table.',
    target_table_schema STRING COMMENT 'The schema of the target table.',
    target_table_name STRING COMMENT 'The name of the target table.',
    target_path STRING COMMENT 'Location in cloud storage of the target table.',
    target_type STRING COMMENT 'The type of the target. The value is TABLE, PATH, VIEW, MATERIALIZED_VIEW, METRIC_VIEW, or STREAMING_TABLE.',
    created_by STRING COMMENT 'The user who generated this lineage. This can be a Databricks username, a Databricks service principal ID, “System-User”, or NULL if the user information cannot be captured.',
    event_time TIMESTAMP COMMENT 'The timestamp when the lineage was generated. Timezone information is recorded at the end of the value with +00:00 representing UTC.',
    event_date DATE COMMENT 'The date when the lineage was generated. This is a partitioned column.',
    record_id STRING COMMENT 'Primary key of each row, it is auto-generated and cannot be joined with any tables',
    event_id STRING COMMENT 'One query or one spark job run could append multiple lineage rows, this event_id is a unique id to group the rows that belong to the same event. This is generated in the pipeline and cannot be joined with any tables.',
    statement_id STRING COMMENT 'A foreign key to join with query history system table. It is set when a query is from a warehouse or serverless warehouse.',
    entity_metadata STRUCT < job_info: STRUCT < job_id: STRING,
    job_run_id: STRING >,
    dashboard_id: STRING,
    legacy_dashboard_id: STRING,
    notebook_id: STRING,
    sql_query_id: STRING,
    dlt_pipeline_info: STRUCT < dlt_pipeline_id: STRING,
    dlt_update_id: STRING > > COMMENT 'It is a list of ids of the query context which is joinable with other system tables.'
)