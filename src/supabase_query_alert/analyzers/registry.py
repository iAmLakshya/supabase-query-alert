from supabase_query_alert.analyzers.base import QueryAnalyzer
from supabase_query_alert.domain import Finding, Query


class AnalyzerRegistry:
    """Registry for managing and orchestrating query analyzers."""

    def __init__(self) -> None:
        self._analyzers: list[QueryAnalyzer] = []

    def register(self, analyzer: QueryAnalyzer) -> None:
        self._analyzers.append(analyzer)

    @property
    def analyzers(self) -> tuple[QueryAnalyzer, ...]:
        return tuple(self._analyzers)

    async def analyze_all(self, query: Query) -> list[Finding]:
        findings: list[Finding] = []
        for analyzer in self._analyzers:
            result = await analyzer.analyze(query)
            if result is not None:
                findings.append(result)
        return findings
