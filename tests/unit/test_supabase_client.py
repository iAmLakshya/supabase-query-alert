from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from supabase_query_alert.input.supabase.client import LogQueryParams, SupabaseLogClient


def make_mock_response(status_code: int, json_data: dict | list) -> MagicMock:
    """Create a mock httpx.Response with proper request object."""
    mock = MagicMock(spec=httpx.Response)
    mock.status_code = status_code
    mock.json.return_value = json_data
    mock.request = httpx.Request("GET", "https://api.supabase.com/test")

    def raise_for_status() -> None:
        if status_code >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {status_code}",
                request=mock.request,
                response=mock,
            )

    mock.raise_for_status = raise_for_status
    return mock


class TestLogQueryParams:
    def test_valid_params(self) -> None:
        now = datetime.now(UTC)
        params = LogQueryParams(start_time=now - timedelta(minutes=5), end_time=now)
        params.validate()

    def test_raises_when_end_before_start(self) -> None:
        now = datetime.now(UTC)
        params = LogQueryParams(start_time=now, end_time=now - timedelta(minutes=5))

        with pytest.raises(ValueError, match="end_time must be after start_time"):
            params.validate()

    def test_raises_when_range_exceeds_24_hours(self) -> None:
        now = datetime.now(UTC)
        params = LogQueryParams(start_time=now - timedelta(hours=25), end_time=now)

        with pytest.raises(ValueError, match="cannot exceed 24 hours"):
            params.validate()

    def test_exactly_24_hours_is_valid(self) -> None:
        now = datetime.now(UTC)
        params = LogQueryParams(start_time=now - timedelta(hours=24), end_time=now)
        params.validate()


class TestSupabaseLogClient:
    @pytest.fixture
    def client(self) -> SupabaseLogClient:
        return SupabaseLogClient(
            project_ref="test-project-ref", access_token="test-access-token"
        )

    def test_initialization(self, client: SupabaseLogClient) -> None:
        assert client.project_ref == "test-project-ref"
        assert client.access_token == "test-access-token"
        assert client.base_url == "https://api.supabase.com"

    def test_custom_base_url(self) -> None:
        client = SupabaseLogClient(
            project_ref="ref",
            access_token="token",
            base_url="https://custom.api.com",
        )
        assert client.base_url == "https://custom.api.com"

    class TestQueryLogs:
        @pytest.mark.asyncio
        async def test_query_logs_success(self, client: SupabaseLogClient) -> None:
            mock_response = make_mock_response(
                200,
                [
                    {
                        "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT * FROM users;",
                        "timestamp": "2025-01-14T12:00:00Z",
                    },
                    {
                        "event_message": "AUDIT: SESSION,2,1,WRITE,INSERT,TABLE,public.orders,INSERT INTO orders VALUES (1);",
                        "timestamp": "2025-01-14T12:01:00Z",
                    },
                ],
            )

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_get.return_value = mock_response
                result = await client.query_logs()

            assert len(result) == 2
            assert "SELECT * FROM users" in result[0]["event_message"]

        @pytest.mark.asyncio
        async def test_query_logs_with_custom_time_range(
            self, client: SupabaseLogClient
        ) -> None:
            mock_response = make_mock_response(200, [])
            end_time = datetime.now(UTC)
            start_time = end_time - timedelta(hours=2)

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_get.return_value = mock_response
                await client.query_logs(start_time=start_time, end_time=end_time)

                call_args = mock_get.call_args
                params = call_args.kwargs["params"]
                assert "iso_timestamp_start" in params
                assert "iso_timestamp_end" in params

        @pytest.mark.asyncio
        async def test_query_logs_with_custom_sql(self, client: SupabaseLogClient) -> None:
            mock_response = make_mock_response(200, [])
            custom_sql = "SELECT * FROM postgres_logs WHERE event_message LIKE '%DROP%'"

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_get.return_value = mock_response
                await client.query_logs(sql=custom_sql)

                call_args = mock_get.call_args
                params = call_args.kwargs["params"]
                assert params["sql"] == custom_sql

        @pytest.mark.asyncio
        async def test_query_logs_extracts_nested_result(
            self, client: SupabaseLogClient
        ) -> None:
            mock_response = make_mock_response(
                200,
                {
                    "result": [
                        {"event_message": "AUDIT: SESSION,1,1,READ,SELECT,...", "timestamp": "2025-01-14T12:00:00Z"}
                    ]
                },
            )

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_get.return_value = mock_response
                result = await client.query_logs()

            assert len(result) == 1

        @pytest.mark.asyncio
        async def test_query_logs_extracts_data_field(
            self, client: SupabaseLogClient
        ) -> None:
            mock_response = make_mock_response(
                200,
                {
                    "data": [
                        {"event_message": "AUDIT: SESSION,1,1,READ,SELECT,...", "timestamp": "2025-01-14T12:00:00Z"}
                    ]
                },
            )

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_get.return_value = mock_response
                result = await client.query_logs()

            assert len(result) == 1

        @pytest.mark.asyncio
        async def test_query_logs_handles_empty_response(
            self, client: SupabaseLogClient
        ) -> None:
            mock_response = make_mock_response(200, [])

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_get.return_value = mock_response
                result = await client.query_logs()

            assert result == []

        @pytest.mark.asyncio
        async def test_query_logs_raises_on_auth_error(
            self, client: SupabaseLogClient
        ) -> None:
            mock_response = make_mock_response(401, {"error": "Unauthorized"})

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_get.return_value = mock_response

                with pytest.raises(httpx.HTTPStatusError):
                    await client.query_logs()

        @pytest.mark.asyncio
        async def test_query_logs_raises_on_rate_limit(
            self, client: SupabaseLogClient
        ) -> None:
            mock_response = make_mock_response(429, {"error": "Rate limited"})

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_get.return_value = mock_response

                with pytest.raises(httpx.HTTPStatusError):
                    await client.query_logs()

        @pytest.mark.asyncio
        async def test_query_logs_includes_auth_header(
            self, client: SupabaseLogClient
        ) -> None:
            mock_response = make_mock_response(200, [])

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_get.return_value = mock_response
                await client.query_logs()

                call_args = mock_get.call_args
                headers = call_args.kwargs["headers"]
                assert headers["Authorization"] == "Bearer test-access-token"

        @pytest.mark.asyncio
        async def test_query_logs_constructs_correct_url(
            self, client: SupabaseLogClient
        ) -> None:
            mock_response = make_mock_response(200, [])

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_get.return_value = mock_response
                await client.query_logs()

                call_args = mock_get.call_args
                url = call_args.args[0]
                assert "test-project-ref" in url
                assert "analytics/endpoints/logs.all" in url

    class TestQueryRecentAuditLogs:
        @pytest.mark.asyncio
        async def test_query_recent_audit_logs(self, client: SupabaseLogClient) -> None:
            mock_response = make_mock_response(200, [])

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_get.return_value = mock_response
                await client.query_recent_audit_logs(minutes=10)

                mock_get.assert_called_once()

        @pytest.mark.asyncio
        async def test_query_recent_audit_logs_caps_at_60_minutes(
            self, client: SupabaseLogClient
        ) -> None:
            mock_response = make_mock_response(200, [])

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_get.return_value = mock_response
                await client.query_recent_audit_logs(minutes=120)

                call_args = mock_get.call_args
                params = call_args.kwargs["params"]
                start = datetime.fromisoformat(params["iso_timestamp_start"])
                end = datetime.fromisoformat(params["iso_timestamp_end"])
                delta = end - start
                assert delta <= timedelta(minutes=60)
