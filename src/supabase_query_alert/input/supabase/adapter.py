from datetime import UTC, datetime, timedelta
from typing import Any

from supabase_query_alert.domain import Query, QueryMetadata
from supabase_query_alert.input.supabase.client import SupabaseLogClient
from supabase_query_alert.input.supabase.parser import PgAuditLogParser


class SupabaseLogInput:
    """QueryInput adapter for Supabase Management API logs.

    Fetches postgres_logs via Management API and converts pgaudit
    entries to Query objects for analysis.

    Usage:
        client = SupabaseLogClient(project_ref="...", access_token="...")
        input_source = SupabaseLogInput(client)

        async for query in input_source:
            # Process query through pipeline

    For testing, inject mock log data via from_log_rows() class method.
    """

    def __init__(
        self,
        client: SupabaseLogClient,
        parser: PgAuditLogParser | None = None,
        lookback_minutes: int = 5,
    ) -> None:
        self._client = client
        self._parser = parser or PgAuditLogParser()
        self._lookback_minutes = lookback_minutes
        self._queries: list[Query] = []
        self._index: int = 0
        self._fetched: bool = False

    @classmethod
    def from_log_rows(
        cls,
        log_rows: list[dict[str, Any]],
        parser: PgAuditLogParser | None = None,
    ) -> "SupabaseLogInput":
        """Create adapter from pre-fetched log rows (for testing).

        This bypasses the API client and directly uses provided log data.
        """
        instance = cls.__new__(cls)
        instance._client = None  # type: ignore[assignment]
        instance._parser = parser or PgAuditLogParser()
        instance._lookback_minutes = 0
        instance._index = 0
        instance._fetched = True
        instance._queries = instance._parse_rows(log_rows)
        return instance

    def __aiter__(self) -> "SupabaseLogInput":
        return self

    async def __anext__(self) -> Query:
        if not self._fetched:
            await self._fetch_logs()

        if self._index >= len(self._queries):
            raise StopAsyncIteration

        query = self._queries[self._index]
        self._index += 1
        return query

    async def _fetch_logs(self) -> None:
        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(minutes=self._lookback_minutes)

        log_rows = await self._client.query_logs(start_time=start_time, end_time=end_time)

        self._queries = self._parse_rows(log_rows)
        self._fetched = True

    def _parse_rows(self, log_rows: list[dict[str, Any]]) -> list[Query]:
        queries: list[Query] = []

        for row in log_rows:
            parsed = self._parser.parse_log_row(row)
            if parsed is None:
                continue

            metadata = QueryMetadata(
                timestamp=parsed.timestamp,
                user_id=parsed.user_name,
                source=f"pgaudit:{parsed.audit_type}:{parsed.session_id or 'unknown'}",
            )

            query = Query(sql=parsed.statement, metadata=metadata)
            queries.append(query)

        return queries

    def reset(self) -> None:
        """Reset iterator to beginning (re-iterate over cached queries)."""
        self._index = 0

    async def refresh(self) -> None:
        """Fetch fresh logs from API (for polling scenarios)."""
        self._fetched = False
        self._index = 0
        self._queries = []
        await self._fetch_logs()

    @property
    def query_count(self) -> int:
        """Number of queries parsed from logs."""
        return len(self._queries)
