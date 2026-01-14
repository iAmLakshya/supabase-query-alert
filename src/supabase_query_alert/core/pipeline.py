from collections.abc import Sequence

from supabase_query_alert.analyzers import AnalyzerRegistry
from supabase_query_alert.domain import Alert
from supabase_query_alert.input import QueryInput
from supabase_query_alert.output import AlertOutput


class QueryPipeline:
    def __init__(
        self,
        input_source: QueryInput,
        registry: AnalyzerRegistry,
        outputs: Sequence[AlertOutput],
    ) -> None:
        self._input = input_source
        self._registry = registry
        self._outputs = tuple(outputs)

    async def run(self) -> None:
        async for query in self._input:
            findings = await self._registry.analyze_all(query)
            if findings:
                alert = Alert(query=query, findings=tuple(findings))
                for output in self._outputs:
                    await output.send(alert)
