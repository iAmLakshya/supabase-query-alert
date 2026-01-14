from typing import Protocol, Self, runtime_checkable

from supabase_query_alert.domain import Query


@runtime_checkable
class QueryInput(Protocol):
    """Protocol for async query input sources."""

    def __aiter__(self) -> Self:
        ...

    async def __anext__(self) -> Query:
        ...
