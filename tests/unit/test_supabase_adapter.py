import pytest

from supabase_query_alert.domain import Query
from supabase_query_alert.input import QueryInput
from supabase_query_alert.input.supabase.adapter import SupabaseLogInput


REALISTIC_LOG_ROWS = [
    {
        "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT * FROM users WHERE email = 'admin@example.com';",
        "timestamp": "2025-01-14T12:00:00Z",
        "user_name": "postgres",
        "database_name": "production",
        "session_id": "sess_001",
    },
    {
        "event_message": "AUDIT: SESSION,2,1,READ,SELECT,TABLE,public.orders,SELECT o.*, u.email FROM orders o JOIN users u ON o.user_id = u.id LIMIT 10000;",
        "timestamp": "2025-01-14T12:01:00Z",
        "user_name": "app_backend",
        "database_name": "production",
        "session_id": "sess_002",
    },
    {
        "event_message": "AUDIT: SESSION,3,1,WRITE,INSERT,TABLE,public.orders,INSERT INTO orders (user_id, total) VALUES (1, 99.99);",
        "timestamp": "2025-01-14T12:02:00Z",
        "user_name": "app_backend",
        "database_name": "production",
        "session_id": "sess_002",
    },
    {
        "event_message": "AUDIT: SESSION,4,1,DDL,DROP TABLE,TABLE,public.temp_data,DROP TABLE temp_data;",
        "timestamp": "2025-01-14T12:03:00Z",
        "user_name": "admin",
        "database_name": "production",
        "session_id": "sess_003",
    },
    {
        "event_message": "AUDIT: SESSION,5,1,READ,SELECT,TABLE,public.users,SELECT password_hash, api_key FROM users;",
        "timestamp": "2025-01-14T12:04:00Z",
        "user_name": "suspicious_user",
        "database_name": "production",
        "session_id": "sess_004",
    },
]

SUSPICIOUS_INJECTION_LOGS = [
    {
        "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT * FROM users WHERE id = 1 OR 1=1;",
        "timestamp": "2025-01-14T12:00:00Z",
        "user_name": "attacker",
    },
    {
        "event_message": "AUDIT: SESSION,2,1,READ,SELECT,TABLE,public.users,SELECT * FROM users; DROP TABLE users;--",
        "timestamp": "2025-01-14T12:01:00Z",
        "user_name": "attacker",
    },
    {
        "event_message": "AUDIT: SESSION,3,1,READ,SELECT,TABLE,public.users,SELECT * FROM users UNION SELECT * FROM passwords;",
        "timestamp": "2025-01-14T12:02:00Z",
        "user_name": "attacker",
    },
]


class TestSupabaseLogInput:
    class TestFromLogRows:
        def test_creates_adapter_from_log_rows(self) -> None:
            adapter = SupabaseLogInput.from_log_rows(REALISTIC_LOG_ROWS)
            assert adapter.query_count == 5

        def test_skips_non_audit_rows(self) -> None:
            rows = [
                {"event_message": "LOG: checkpoint starting", "timestamp": "2025-01-14T12:00:00Z"},
                {
                    "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT 1;",
                    "timestamp": "2025-01-14T12:01:00Z",
                },
            ]
            adapter = SupabaseLogInput.from_log_rows(rows)
            assert adapter.query_count == 1

        def test_handles_empty_rows(self) -> None:
            adapter = SupabaseLogInput.from_log_rows([])
            assert adapter.query_count == 0

    class TestAsyncIteration:
        @pytest.mark.asyncio
        async def test_iterates_over_all_queries(self) -> None:
            adapter = SupabaseLogInput.from_log_rows(REALISTIC_LOG_ROWS)
            queries = [query async for query in adapter]
            assert len(queries) == 5

        @pytest.mark.asyncio
        async def test_returns_query_objects(self) -> None:
            adapter = SupabaseLogInput.from_log_rows(REALISTIC_LOG_ROWS)
            query = await adapter.__anext__()

            assert isinstance(query, Query)
            assert "SELECT * FROM users" in query.sql

        @pytest.mark.asyncio
        async def test_populates_query_metadata(self) -> None:
            adapter = SupabaseLogInput.from_log_rows(REALISTIC_LOG_ROWS)
            query = await adapter.__anext__()

            assert query.metadata is not None
            assert query.metadata.user_id == "postgres"
            assert query.metadata.timestamp is not None
            assert "pgaudit:SESSION" in (query.metadata.source or "")

        @pytest.mark.asyncio
        async def test_raises_stop_iteration_when_exhausted(self) -> None:
            adapter = SupabaseLogInput.from_log_rows(REALISTIC_LOG_ROWS[:1])

            await adapter.__anext__()

            with pytest.raises(StopAsyncIteration):
                await adapter.__anext__()

        @pytest.mark.asyncio
        async def test_aiter_returns_self(self) -> None:
            adapter = SupabaseLogInput.from_log_rows([])
            assert adapter.__aiter__() is adapter

    class TestProtocolCompliance:
        def test_implements_query_input_protocol(self) -> None:
            adapter = SupabaseLogInput.from_log_rows([])
            assert isinstance(adapter, QueryInput)

    class TestReset:
        @pytest.mark.asyncio
        async def test_reset_allows_re_iteration(self) -> None:
            adapter = SupabaseLogInput.from_log_rows(REALISTIC_LOG_ROWS[:2])

            first_pass = [query async for query in adapter]
            assert len(first_pass) == 2

            adapter.reset()

            second_pass = [query async for query in adapter]
            assert len(second_pass) == 2

    class TestRealisticScenarios:
        @pytest.mark.asyncio
        async def test_parses_suspicious_injection_queries(self) -> None:
            adapter = SupabaseLogInput.from_log_rows(SUSPICIOUS_INJECTION_LOGS)
            queries = [query async for query in adapter]

            assert len(queries) == 3
            assert "1=1" in queries[0].sql
            assert "DROP TABLE" in queries[1].sql
            assert "UNION SELECT" in queries[2].sql

        @pytest.mark.asyncio
        async def test_preserves_user_attribution(self) -> None:
            adapter = SupabaseLogInput.from_log_rows(SUSPICIOUS_INJECTION_LOGS)
            queries = [query async for query in adapter]

            for query in queries:
                assert query.metadata is not None
                assert query.metadata.user_id == "attacker"


class TestSupabaseLogInputIntegration:
    @pytest.mark.asyncio
    async def test_full_log_parsing_flow(self) -> None:
        rows = [
            {
                "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT * FROM users;",
                "timestamp": 1705233600000000,
                "parsed": {
                    "user_name": "app",
                    "database_name": "db",
                    "session_id": "s1",
                },
            },
        ]

        adapter = SupabaseLogInput.from_log_rows(rows)
        queries = [q async for q in adapter]

        assert len(queries) == 1
        query = queries[0]
        assert query.sql == "SELECT * FROM users;"
        assert query.metadata is not None
        assert query.metadata.user_id == "app"
        assert query.metadata.timestamp is not None

    @pytest.mark.asyncio
    async def test_handles_mixed_valid_and_invalid_logs(self) -> None:
        rows = [
            {"event_message": "LOG: connection received", "timestamp": "2025-01-14T12:00:00Z"},
            {"event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.t,SELECT 1;", "timestamp": "2025-01-14T12:01:00Z"},
            {"event_message": "WARNING: autovacuum started", "timestamp": "2025-01-14T12:02:00Z"},
            {"event_message": "AUDIT: SESSION,2,1,WRITE,INSERT,TABLE,public.t,INSERT INTO t VALUES (1);", "timestamp": "2025-01-14T12:03:00Z"},
            {"event_message": "ERROR: division by zero", "timestamp": "2025-01-14T12:04:00Z"},
        ]

        adapter = SupabaseLogInput.from_log_rows(rows)
        queries = [q async for q in adapter]

        assert len(queries) == 2
        assert "SELECT 1" in queries[0].sql
        assert "INSERT INTO" in queries[1].sql
