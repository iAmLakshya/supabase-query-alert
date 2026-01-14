import pytest

from supabase_query_alert.domain import Query
from supabase_query_alert.input import QueryInput


class MockQueryInput:
    """Mock implementation of QueryInput for testing."""

    def __init__(self, queries: list[Query]) -> None:
        self._queries = queries
        self._index = 0

    def __aiter__(self) -> "MockQueryInput":
        return self

    async def __anext__(self) -> Query:
        if self._index >= len(self._queries):
            raise StopAsyncIteration
        query = self._queries[self._index]
        self._index += 1
        return query


class TestQueryInputProtocol:
    def test_protocol_is_runtime_checkable(self) -> None:
        mock = MockQueryInput([])
        assert isinstance(mock, QueryInput)

    def test_non_conforming_class_fails_isinstance(self) -> None:
        class NotAnInput:
            pass

        assert not isinstance(NotAnInput(), QueryInput)

    @pytest.mark.asyncio
    async def test_mock_yields_query_objects(self) -> None:
        queries = [
            Query(sql="SELECT 1"),
            Query(sql="SELECT 2"),
            Query(sql="SELECT 3"),
        ]
        mock = MockQueryInput(queries)

        collected: list[Query] = []
        async for query in mock:
            collected.append(query)

        assert collected == queries

    @pytest.mark.asyncio
    async def test_empty_input_yields_nothing(self) -> None:
        mock = MockQueryInput([])

        collected: list[Query] = []
        async for query in mock:
            collected.append(query)

        assert collected == []
