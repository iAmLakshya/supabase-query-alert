import pytest

from supabase_query_alert.analyzers import AnalyzerRegistry, QueryAnalyzer
from supabase_query_alert.domain import Finding, Query, Severity


class MockAnalyzer:
    """Mock implementation of QueryAnalyzer for testing."""

    def __init__(self, name: str, finding: Finding | None) -> None:
        self._name = name
        self._finding = finding

    @property
    def name(self) -> str:
        return self._name

    async def analyze(self, query: Query) -> Finding | None:
        return self._finding


class TestQueryAnalyzerProtocol:
    def test_protocol_is_runtime_checkable(self) -> None:
        analyzer = MockAnalyzer("test", None)
        assert isinstance(analyzer, QueryAnalyzer)

    def test_non_conforming_class_fails_isinstance(self) -> None:
        class NotAnAnalyzer:
            pass

        assert not isinstance(NotAnAnalyzer(), QueryAnalyzer)


class TestAnalyzerRegistry:
    def test_register_adds_analyzer(self) -> None:
        registry = AnalyzerRegistry()
        analyzer = MockAnalyzer("test", None)

        registry.register(analyzer)

        assert len(registry.analyzers) == 1
        assert registry.analyzers[0] is analyzer

    def test_analyzers_returns_tuple(self) -> None:
        registry = AnalyzerRegistry()
        analyzer = MockAnalyzer("test", None)
        registry.register(analyzer)

        result = registry.analyzers

        assert isinstance(result, tuple)

    @pytest.mark.asyncio
    async def test_analyze_all_empty_registry_returns_empty_list(self) -> None:
        registry = AnalyzerRegistry()
        query = Query(sql="SELECT 1")

        findings = await registry.analyze_all(query)

        assert findings == []

    @pytest.mark.asyncio
    async def test_analyze_all_aggregates_findings(self) -> None:
        registry = AnalyzerRegistry()
        finding1 = Finding(
            analyzer_name="analyzer1",
            severity=Severity.LOW,
            message="Issue 1",
        )
        finding2 = Finding(
            analyzer_name="analyzer2",
            severity=Severity.HIGH,
            message="Issue 2",
        )
        registry.register(MockAnalyzer("analyzer1", finding1))
        registry.register(MockAnalyzer("analyzer2", finding2))
        query = Query(sql="SELECT * FROM users")

        findings = await registry.analyze_all(query)

        assert len(findings) == 2
        assert finding1 in findings
        assert finding2 in findings

    @pytest.mark.asyncio
    async def test_analyze_all_excludes_none_results(self) -> None:
        registry = AnalyzerRegistry()
        finding = Finding(
            analyzer_name="finder",
            severity=Severity.MEDIUM,
            message="Found something",
        )
        registry.register(MockAnalyzer("finder", finding))
        registry.register(MockAnalyzer("empty", None))
        registry.register(MockAnalyzer("also_empty", None))
        query = Query(sql="SELECT 1")

        findings = await registry.analyze_all(query)

        assert len(findings) == 1
        assert findings[0] is finding
