from typing import Sequence

from supabase_query_alert.domain import Query


class ManualInput:
    """Manual input source for programmatically feeding queries."""

    def __init__(self, queries: Sequence[Query]) -> None:
        self._queries: tuple[Query, ...] = tuple(queries)
        self._index: int = 0

    def __aiter__(self) -> "ManualInput":
        return self

    async def __anext__(self) -> Query:
        if self._index >= len(self._queries):
            raise StopAsyncIteration
        query = self._queries[self._index]
        self._index += 1
        return query
