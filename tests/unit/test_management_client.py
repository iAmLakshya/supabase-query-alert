import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from supabase_query_alert.api import (
    SupabaseManagementClient,
    Project,
    Organization,
    RateLimitError,
    AuthenticationError,
    NotFoundError,
)


class TestClientInitialization:
    def test_stores_access_token(self) -> None:
        client = SupabaseManagementClient(access_token="test-token")
        assert client.access_token == "test-token"

    def test_uses_default_base_url(self) -> None:
        client = SupabaseManagementClient(access_token="test-token")
        assert client.base_url == "https://api.supabase.com"

    def test_accepts_custom_base_url(self) -> None:
        client = SupabaseManagementClient(access_token="test-token", base_url="https://custom.api.com")
        assert client.base_url == "https://custom.api.com"


class TestAuthHeader:
    @pytest.mark.asyncio
    async def test_auth_header_included_in_requests(self) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_response.headers = {}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            async with SupabaseManagementClient(access_token="my-secret-token") as client:
                await client.list_projects()

            mock_get.assert_called_once()
            call_kwargs = mock_get.call_args.kwargs
            assert "headers" in call_kwargs
            assert call_kwargs["headers"]["Authorization"] == "Bearer my-secret-token"


class TestListProjects:
    @pytest.mark.asyncio
    async def test_returns_typed_project_objects(self) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "id": "proj-123",
                "name": "My Project",
                "ref": "abc123",
                "organization_id": "org-456",
                "status": "ACTIVE_HEALTHY",
                "region": "us-east-1",
            }
        ]
        mock_response.headers = {}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            async with SupabaseManagementClient(access_token="test-token") as client:
                projects = await client.list_projects()

        assert len(projects) == 1
        assert isinstance(projects[0], Project)
        assert projects[0].id == "proj-123"
        assert projects[0].name == "My Project"
        assert projects[0].ref == "abc123"

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_projects(self) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_response.headers = {}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            async with SupabaseManagementClient(access_token="test-token") as client:
                projects = await client.list_projects()

        assert projects == []


class TestGetProject:
    @pytest.mark.asyncio
    async def test_returns_single_project(self) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "proj-123",
            "name": "My Project",
            "ref": "abc123",
            "organization_id": "org-456",
            "status": "ACTIVE_HEALTHY",
            "region": "us-east-1",
        }
        mock_response.headers = {}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            async with SupabaseManagementClient(access_token="test-token") as client:
                project = await client.get_project("abc123")

        assert isinstance(project, Project)
        assert project.ref == "abc123"

    @pytest.mark.asyncio
    async def test_raises_not_found_for_404(self) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not Found", request=MagicMock(), response=mock_response
        )

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            async with SupabaseManagementClient(access_token="test-token") as client:
                with pytest.raises(NotFoundError):
                    await client.get_project("nonexistent")


class TestListOrganizations:
    @pytest.mark.asyncio
    async def test_returns_typed_organization_objects(self) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "id": "org-123",
                "name": "My Org",
                "slug": "my-org",
            }
        ]
        mock_response.headers = {}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            async with SupabaseManagementClient(access_token="test-token") as client:
                orgs = await client.list_organizations()

        assert len(orgs) == 1
        assert isinstance(orgs[0], Organization)
        assert orgs[0].id == "org-123"
        assert orgs[0].name == "My Org"
        assert orgs[0].slug == "my-org"


class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_raises_authentication_error_for_401(self) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Unauthorized", request=MagicMock(), response=mock_response
        )

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            async with SupabaseManagementClient(access_token="invalid-token") as client:
                with pytest.raises(AuthenticationError):
                    await client.list_projects()


class TestRateLimiting:
    @pytest.mark.asyncio
    async def test_retries_on_429_with_backoff(self) -> None:
        rate_limit_response = MagicMock()
        rate_limit_response.status_code = 429
        rate_limit_response.headers = {"Retry-After": "1"}
        rate_limit_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Too Many Requests", request=MagicMock(), response=rate_limit_response
        )

        success_response = MagicMock()
        success_response.status_code = 200
        success_response.json.return_value = []
        success_response.headers = {}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = [rate_limit_response, success_response]
            with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                async with SupabaseManagementClient(access_token="test-token") as client:
                    result = await client.list_projects()

        assert result == []
        assert mock_get.call_count == 2
        mock_sleep.assert_called()

    @pytest.mark.asyncio
    async def test_raises_rate_limit_error_after_max_retries(self) -> None:
        rate_limit_response = MagicMock()
        rate_limit_response.status_code = 429
        rate_limit_response.headers = {"Retry-After": "1"}
        rate_limit_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Too Many Requests", request=MagicMock(), response=rate_limit_response
        )

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = rate_limit_response
            with patch("asyncio.sleep", new_callable=AsyncMock):
                async with SupabaseManagementClient(access_token="test-token") as client:
                    with pytest.raises(RateLimitError):
                        await client.list_projects()

        assert mock_get.call_count >= 3

    @pytest.mark.asyncio
    async def test_exponential_backoff_delays(self) -> None:
        rate_limit_response = MagicMock()
        rate_limit_response.status_code = 429
        rate_limit_response.headers = {}
        rate_limit_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Too Many Requests", request=MagicMock(), response=rate_limit_response
        )

        sleep_delays: list[float] = []

        async def capture_sleep(delay: float) -> None:
            sleep_delays.append(delay)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = rate_limit_response
            with patch("asyncio.sleep", side_effect=capture_sleep):
                async with SupabaseManagementClient(access_token="test-token") as client:
                    with pytest.raises(RateLimitError):
                        await client.list_projects()

        assert len(sleep_delays) == 3
        assert 1.0 <= sleep_delays[0] <= 1.5
        assert 2.0 <= sleep_delays[1] <= 2.5
        assert 4.0 <= sleep_delays[2] <= 4.5


class TestContextManager:
    @pytest.mark.asyncio
    async def test_async_context_manager_usage(self) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_response.headers = {}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            async with SupabaseManagementClient(access_token="test-token") as client:
                assert client is not None
                await client.list_projects()
