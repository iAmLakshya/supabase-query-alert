# Hosted Supabase Integration Guide

This guide explains how to configure the Supabase Query Alert system to work with a hosted Supabase project, enabling real-time query analysis and alerting.

## Architecture Overview

The system operates as a pull-based log analysis pipeline that integrates with Supabase's logging infrastructure.

**How Supabase captures query logs:** When you enable the pgaudit extension on your Supabase PostgreSQL database, every SQL statement executed against the database generates an audit log entry. These entries flow through Supabase's internal logging pipeline (powered by Logflare) and are stored in a queryable analytics backend that uses BigQuery-style SQL syntax. The logs are retained based on your Supabase plan tier.

**How the application fetches logs:** The `SupabaseLogClient` component makes authenticated HTTP requests to Supabase's Management API at the `/v1/projects/{ref}/analytics/endpoints/logs.all` endpoint. This endpoint accepts a SQL query parameter that allows filtering the `postgres_logs` table for specific time ranges, user roles, command types, or custom patterns. The API returns JSON arrays containing log entries with timestamps, event messages, and nested metadata.

**How logs are parsed and analyzed:** The `PgAuditLogParser` extracts structured data from pgaudit's CSV-formatted event messages, pulling out the audit type, command class, object references, and the actual SQL statement. The `SupabaseLogInput` adapter wraps this parsing logic and implements the `QueryInput` protocol, allowing parsed queries to flow through the standard analysis pipeline. Each query passes through registered analyzers (SQL injection detection, data exfiltration detection, volume anomaly detection) which examine the SQL text and metadata for suspicious patterns.

**How alerts are generated:** When any analyzer returns findings for a query, those findings are aggregated into an `Alert` object that preserves the original query context, user attribution from the logs, and the specific security concerns identified. Alerts can be routed to multiple output channels (console, webhooks, logging systems) based on your configuration.

**Production deployment model:** In production, a scheduled job (cron, cloud scheduler, or serverless function trigger) periodically invokes the log fetching and analysis pipeline. Each invocation queries a rolling time window (typically the last 5 minutes with some overlap) to ensure continuous coverage without gaps. The stateless design means each invocation is independent—no persistent state is required between runs.

## Prerequisites

1. **Supabase Project** with a Pro plan or higher (for analytics access)
2. **Management API Access Token** - Generate from Supabase Dashboard
3. **Project Reference** - Found in your project settings

## Step 1: Enable pgaudit Extension

In your Supabase Dashboard:

1. Go to **Database** → **Extensions**
2. Search for `pgaudit`
3. Enable the extension

Or via SQL Editor:

```sql
CREATE EXTENSION IF NOT EXISTS pgaudit;

-- Configure session logging for all operations
ALTER ROLE postgres SET pgaudit.log TO 'all';
```

**Note:** Supabase restricts certain pgaudit settings (`pgaudit.log_parameter`) for security reasons related to pgsodium vault encryption.

## Step 2: Generate Management API Token

1. Go to your Supabase Dashboard
2. Click your avatar → **Account Settings**
3. Navigate to **Access Tokens**
4. Generate a new token with appropriate permissions

Store this token securely - it provides elevated access.

## Step 3: Configure the Application

Create a `.env` file (never commit this):

```bash
SUPABASE_PROJECT_REF=your-project-reference
SUPABASE_ACCESS_TOKEN=your-management-api-token
```

Or configure programmatically:

```python
from supabase_query_alert.input import SupabaseLogClient, SupabaseLogInput

client = SupabaseLogClient(
    project_ref="your-project-reference",
    access_token="your-management-api-token",
)

input_source = SupabaseLogInput(client, lookback_minutes=5)
```

## Step 4: Query postgres_logs

### API Endpoint

```
GET https://api.supabase.com/v1/projects/{ref}/analytics/endpoints/logs.all
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `iso_timestamp_start` | Yes* | Start of time range (ISO 8601) |
| `iso_timestamp_end` | Yes* | End of time range (ISO 8601) |
| `sql` | No | BigQuery SQL query |

*If neither provided, defaults to last 1 minute. Max range: 24 hours.

### Example Query

```sql
SELECT
    timestamp,
    event_message,
    metadata
FROM postgres_logs
WHERE event_message LIKE 'AUDIT%'
ORDER BY timestamp DESC
LIMIT 1000
```

### Response Format

```json
[
  {
    "timestamp": "2025-01-14T12:00:00Z",
    "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT * FROM users;",
    "metadata": [
      {
        "parsed": {
          "user_name": "postgres",
          "database_name": "postgres",
          "session_id": "abc123"
        }
      }
    ]
  }
]
```

### pgaudit Event Message Format

```
AUDIT: AUDIT_TYPE,STATEMENT_ID,SUBSTATEMENT_ID,CLASS,COMMAND,OBJECT_TYPE,OBJECT_NAME,STATEMENT
```

| Field | Description | Examples |
|-------|-------------|----------|
| `AUDIT_TYPE` | SESSION or OBJECT | `SESSION` |
| `STATEMENT_ID` | Statement counter | `1`, `2`, `3` |
| `SUBSTATEMENT_ID` | Sub-statement counter | `1` |
| `CLASS` | Operation category | `READ`, `WRITE`, `DDL`, `ROLE`, `FUNCTION`, `MISC` |
| `COMMAND` | SQL command | `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `CREATE TABLE` |
| `OBJECT_TYPE` | Database object type | `TABLE`, `INDEX`, `VIEW` |
| `OBJECT_NAME` | Fully qualified name | `public.users`, `public.orders` |
| `STATEMENT` | The SQL statement | `SELECT * FROM users WHERE id = 1;` |

## Step 5: Production Deployment

### Cron-Based Ingestion

For production, use a cron job to periodically ingest logs:

```python
import asyncio
from datetime import datetime, timedelta, UTC

from supabase_query_alert.input import SupabaseLogClient, SupabaseLogInput
from supabase_query_alert.analyzers import AnalyzerRegistry
from supabase_query_alert.analyzers.sql_injection import SQLInjectionAnalyzer
from supabase_query_alert.analyzers.data_exfiltration import DataExfiltrationAnalyzer
from supabase_query_alert.analyzers.volume_anomaly import VolumeAnomalyAnalyzer
from supabase_query_alert.domain import Alert


async def analyze_recent_logs():
    client = SupabaseLogClient(
        project_ref=os.environ["SUPABASE_PROJECT_REF"],
        access_token=os.environ["SUPABASE_ACCESS_TOKEN"],
    )

    # Query last 5 minutes of logs
    end_time = datetime.now(UTC)
    start_time = end_time - timedelta(minutes=5)

    log_rows = await client.query_logs(
        start_time=start_time,
        end_time=end_time,
    )

    # Create input source from fetched logs
    input_source = SupabaseLogInput.from_log_rows(log_rows)

    # Set up analyzers
    registry = AnalyzerRegistry()
    registry.register(SQLInjectionAnalyzer())
    registry.register(DataExfiltrationAnalyzer())
    registry.register(VolumeAnomalyAnalyzer())

    # Analyze each query
    alerts = []
    async for query in input_source:
        findings = await registry.analyze_all(query)
        if findings:
            alert = Alert(query=query, findings=tuple(findings))
            alerts.append(alert)
            # Send alert to your notification channel
            await send_alert(alert)

    return alerts


if __name__ == "__main__":
    asyncio.run(analyze_recent_logs())
```

### Cron Configuration

Run every 5 minutes via your scheduler:

```bash
# crontab example
*/5 * * * * /path/to/venv/bin/python /path/to/analyze_logs.py
```

Or use a managed scheduler (Railway, Render, AWS Lambda + EventBridge, etc.).

## API Rate Limits

As of April 2025, Supabase enforces these limits on the logs endpoint:

| Scenario | Limit |
|----------|-------|
| No timestamps provided | Last 1 minute only |
| One timestamp provided | 1 minute window |
| Both timestamps provided | Max 24 hours |

Plan your polling interval accordingly. For 5-minute polling:
- Query the last 5 minutes
- Keep some overlap to avoid missing logs during processing

## Filtering postgres_logs

### By User Role

```sql
SELECT event_message, parsed.user_name
FROM postgres_logs
CROSS JOIN UNNEST(metadata) AS metadata
CROSS JOIN UNNEST(parsed) AS parsed
WHERE parsed.user_name = 'app_backend'
```

### By Command Type

```sql
SELECT event_message
FROM postgres_logs
WHERE event_message LIKE 'AUDIT:%,WRITE,%'
  OR event_message LIKE 'AUDIT:%,DDL,%'
```

### Excluding Dashboard Queries

```sql
SELECT event_message
FROM postgres_logs
WHERE event_message LIKE 'AUDIT%'
  AND event_message NOT LIKE '%-- source: dashboard%'
```

### Using Regex

```sql
SELECT event_message
FROM postgres_logs
WHERE regexp_contains(event_message, r'UNION\s+SELECT|OR\s+1\s*=\s*1')
```

## Troubleshooting

### No Logs Appearing

1. Verify pgaudit extension is enabled
2. Check the time range - logs have retention limits
3. Ensure queries are actually being executed

### Authentication Errors (401/403)

1. Verify your access token is valid
2. Check token has analytics permissions
3. Ensure project reference is correct

### Rate Limiting (429)

1. Reduce polling frequency
2. Narrow your time range
3. Add caching between polls

## Security Considerations

1. **Never expose** the Management API token in client-side code
2. **Rotate tokens** regularly
3. **Use environment variables** for secrets
4. **Restrict token permissions** to only what's needed
5. **Monitor token usage** in Supabase Dashboard

## Local Development

For local testing without a hosted project:

```python
from supabase_query_alert.input import SupabaseLogInput

# Use mock data directly
test_logs = [
    {
        "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT * FROM users;",
        "timestamp": "2025-01-14T12:00:00Z",
        "user_name": "test_user",
    },
]

input_source = SupabaseLogInput.from_log_rows(test_logs)

async for query in input_source:
    # Process query
    pass
```

## Sources

- [Supabase Logging Documentation](https://supabase.com/docs/guides/telemetry/logs)
- [How to Interpret Postgres Logs](https://supabase.com/docs/guides/troubleshooting/how-to-interpret-and-explore-the-postgres-logs-OuCIOj)
- [PGAudit Extension](https://supabase.com/docs/guides/database/extensions/pgaudit)
- [Management API Reference](https://supabase.com/docs/reference/api/introduction)
- [API Rate Limits Discussion](https://github.com/orgs/supabase/discussions/34634)
