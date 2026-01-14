from typing import Protocol, runtime_checkable

from supabase_query_alert.domain import Alert


@runtime_checkable
class AlertOutput(Protocol):
    """Protocol for alert output destinations."""

    @property
    def name(self) -> str:
        ...

    async def send(self, alert: Alert) -> None:
        ...
