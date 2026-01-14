import asyncio
import random
from typing import Any

import httpx

from supabase_query_alert.api.exceptions import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
)
from supabase_query_alert.api.models import Organization, Project


class SupabaseManagementClient:
    BASE_URL = "https://api.supabase.com"
    MAX_RETRIES = 3
    BASE_BACKOFF = 1.0
    MAX_JITTER = 0.5

    def __init__(self, access_token: str, base_url: str | None = None) -> None:
        self.access_token = access_token
        self.base_url = base_url or self.BASE_URL
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "SupabaseManagementClient":
        self._client = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _request(self, method: str, endpoint: str) -> Any:
        if not self._client:
            raise RuntimeError("Client not initialized. Use async context manager.")

        url = f"{self.base_url}{endpoint}"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

        retries = 0
        while True:
            response = await self._client.request(method, url, headers=headers)

            if response.status_code == 429:
                if retries >= self.MAX_RETRIES:
                    retry_after = response.headers.get("Retry-After")
                    raise RateLimitError(
                        "Rate limit exceeded after max retries",
                        retry_after=float(retry_after) if retry_after else None,
                    )

                delay = self.BASE_BACKOFF * (2**retries) + random.uniform(0, self.MAX_JITTER)
                await asyncio.sleep(delay)
                retries += 1
                continue

            if response.status_code == 401:
                raise AuthenticationError("Invalid or expired access token")

            if response.status_code == 404:
                raise NotFoundError("Resource not found")

            response.raise_for_status()
            return response.json()

    async def list_projects(self) -> list[Project]:
        data = await self._request("GET", "/v1/projects")
        return [
            Project(
                id=p["id"],
                name=p["name"],
                ref=p["ref"],
                organization_id=p["organization_id"],
                status=p["status"],
                region=p["region"],
            )
            for p in data
        ]

    async def get_project(self, ref: str) -> Project:
        data = await self._request("GET", f"/v1/projects/{ref}")
        return Project(
            id=data["id"],
            name=data["name"],
            ref=data["ref"],
            organization_id=data["organization_id"],
            status=data["status"],
            region=data["region"],
        )

    async def list_organizations(self) -> list[Organization]:
        data = await self._request("GET", "/v1/organizations")
        return [
            Organization(
                id=o["id"],
                name=o["name"],
                slug=o["slug"],
            )
            for o in data
        ]
