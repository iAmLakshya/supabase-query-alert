from supabase_query_alert.api.models import Organization, Project


class SupabaseManagementClient:
    def __init__(self, access_token: str, base_url: str | None = None) -> None:
        raise NotImplementedError

    async def list_projects(self) -> list[Project]:
        raise NotImplementedError

    async def get_project(self, ref: str) -> Project:
        raise NotImplementedError

    async def list_organizations(self) -> list[Organization]:
        raise NotImplementedError

    async def __aenter__(self) -> "SupabaseManagementClient":
        raise NotImplementedError

    async def __aexit__(self, *args: object) -> None:
        raise NotImplementedError
