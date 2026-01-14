from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx


@dataclass(frozen=True, slots=True)
class LogQueryParams:
    """Parameters for querying Supabase logs."""

    start_time: datetime
    end_time: datetime
    sql: str | None = None
    limit: int = 1000

    def validate(self) -> None:
        if self.end_time <= self.start_time:
            raise ValueError("end_time must be after start_time")

        delta = self.end_time - self.start_time
        if delta > timedelta(hours=24):
            raise ValueError("Time range cannot exceed 24 hours")


class SupabaseLogClient:
    """Client for Supabase Management API logs endpoint.

    Queries postgres_logs via:
    GET /v1/projects/{ref}/analytics/endpoints/logs.all

    Authentication:
    - Bearer token in Authorization header
    - Token can be service_role key or Management API access token

    Rate limits and restrictions (as of April 2025):
    - Without timestamps: defaults to last 1 minute
    - With one timestamp: 1 minute window before/after
    - With both timestamps: max 24 hour window
    - Results limited to 1000 rows per query
    """

    BASE_URL = "https://api.supabase.com"
    LOGS_ENDPOINT = "/v1/projects/{ref}/analytics/endpoints/logs.all"

    DEFAULT_SQL = """
        SELECT
            timestamp,
            event_message,
            metadata
        FROM postgres_logs
        WHERE event_message LIKE 'AUDIT%'
        ORDER BY timestamp DESC
        LIMIT {limit}
    """

    def __init__(
        self,
        project_ref: str,
        access_token: str,
        base_url: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.project_ref = project_ref
        self.access_token = access_token
        self.base_url = base_url or self.BASE_URL
        self.timeout = timeout

    async def query_logs(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        sql: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Query postgres_logs from Supabase Management API.

        Args:
            start_time: Start of time range (UTC). Defaults to now - 1 minute.
            end_time: End of time range (UTC). Defaults to now.
            sql: Custom BigQuery SQL query. Defaults to selecting AUDIT entries.
            limit: Maximum rows to return (max 1000).

        Returns:
            List of log row dictionaries with event_message, timestamp, metadata.

        Raises:
            httpx.HTTPStatusError: On API errors (401, 403, 429, etc.)
            ValueError: On invalid parameters
        """
        now = datetime.now(UTC)
        if end_time is None:
            end_time = now
        if start_time is None:
            start_time = end_time - timedelta(minutes=1)

        params = LogQueryParams(
            start_time=start_time, end_time=end_time, sql=sql, limit=min(limit, 1000)
        )
        params.validate()

        url = f"{self.base_url}{self.LOGS_ENDPOINT.format(ref=self.project_ref)}"

        query_sql = sql or self.DEFAULT_SQL.format(limit=params.limit)

        request_params: dict[str, str] = {
            "iso_timestamp_start": params.start_time.isoformat(),
            "iso_timestamp_end": params.end_time.isoformat(),
            "sql": query_sql,
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(
                url,
                params=request_params,
                headers={
                    "Authorization": f"Bearer {self.access_token}",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
            data = response.json()

        return self._extract_rows(data)

    def _extract_rows(self, data: Any) -> list[dict[str, Any]]:
        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            if "result" in data:
                return self._extract_rows(data["result"])
            if "data" in data:
                return self._extract_rows(data["data"])
            if "rows" in data:
                return self._extract_rows(data["rows"])

        return []

    async def query_recent_audit_logs(
        self,
        minutes: int = 5,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Convenience method to query recent audit logs.

        Args:
            minutes: How many minutes back to query (max 60 for reasonable window).
            limit: Maximum rows to return.

        Returns:
            List of log rows containing AUDIT entries.
        """
        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(minutes=min(minutes, 60))
        return await self.query_logs(start_time=start_time, end_time=end_time, limit=limit)
