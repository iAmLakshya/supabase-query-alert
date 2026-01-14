import pytest

from supabase_query_alert.domain import Query
from supabase_query_alert.input import ManualInput, QueryInput


class TestManualInput:
    def test_implements_query_input_protocol(self) -> None:
        manual = ManualInput([])
        assert isinstance(manual, QueryInput)

    @pytest.mark.asyncio
    async def test_iterates_over_queries(self) -> None:
        queries = [
            Query(sql="SELECT 1"),
            Query(sql="SELECT 2"),
            Query(sql="SELECT 3"),
        ]
        manual = ManualInput(queries)

        collected: list[Query] = []
        async for query in manual:
            collected.append(query)

        assert collected == queries

    @pytest.mark.asyncio
    async def test_empty_input(self) -> None:
        manual = ManualInput([])

        collected: list[Query] = []
        async for query in manual:
            collected.append(query)

        assert collected == []

    @pytest.mark.asyncio
    async def test_single_query(self) -> None:
        query = Query(sql="SELECT 42")
        manual = ManualInput([query])

        collected: list[Query] = []
        async for q in manual:
            collected.append(q)

        assert collected == [query]
