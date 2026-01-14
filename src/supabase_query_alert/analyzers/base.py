from typing import Protocol, runtime_checkable

from supabase_query_alert.domain import Finding, Query


@runtime_checkable
class QueryAnalyzer(Protocol):
    """Protocol for query analyzers."""

    @property
    def name(self) -> str:
        ...

    async def analyze(self, query: Query) -> Finding | None:
        ...
