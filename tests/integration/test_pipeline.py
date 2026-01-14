import pytest

from supabase_query_alert import (
    Alert,
    AnalyzerRegistry,
    DataExfiltrationAnalyzer,
    ManualInput,
    Query,
    QueryPipeline,
    Severity,
    SQLInjectionAnalyzer,
    VolumeAnomalyAnalyzer,
)
from supabase_query_alert.output import AlertOutput


class MockAlertOutput:
    name: str = "mock"

    def __init__(self) -> None:
        self.alerts: list[Alert] = []

    async def send(self, alert: Alert) -> None:
        self.alerts.append(alert)


def test_mock_implements_protocol():
    output = MockAlertOutput()
    assert isinstance(output, AlertOutput)


@pytest.mark.asyncio
async def test_pipeline_with_clean_queries():
    queries = [
        Query(sql="SELECT id, name FROM products WHERE price > 10"),
        Query(sql="INSERT INTO orders (user_id, total) VALUES (1, 100)"),
    ]
    input_source = ManualInput(queries)
    registry = AnalyzerRegistry()
    registry.register(SQLInjectionAnalyzer())
    output = MockAlertOutput()

    pipeline = QueryPipeline(input_source, registry, [output])
    await pipeline.run()

    assert len(output.alerts) == 0


@pytest.mark.asyncio
async def test_pipeline_with_suspicious_query():
    queries = [Query(sql="SELECT * FROM users WHERE id = 1 OR 1=1")]
    input_source = ManualInput(queries)
    registry = AnalyzerRegistry()
    registry.register(SQLInjectionAnalyzer())
    output = MockAlertOutput()

    pipeline = QueryPipeline(input_source, registry, [output])
    await pipeline.run()

    assert len(output.alerts) == 1
    alert = output.alerts[0]
    assert len(alert.findings) == 1
    assert alert.findings[0].analyzer_name == "sql_injection"
    assert alert.severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_pipeline_multiple_analyzers():
    queries = [Query(sql="SELECT * FROM users WHERE id = 1 OR 1=1")]
    input_source = ManualInput(queries)
    registry = AnalyzerRegistry()
    registry.register(SQLInjectionAnalyzer())
    registry.register(DataExfiltrationAnalyzer())
    output = MockAlertOutput()

    pipeline = QueryPipeline(input_source, registry, [output])
    await pipeline.run()

    assert len(output.alerts) == 1
    alert = output.alerts[0]
    assert len(alert.findings) == 2
    analyzer_names = {f.analyzer_name for f in alert.findings}
    assert analyzer_names == {"sql_injection", "data_exfiltration"}


@pytest.mark.asyncio
async def test_pipeline_multiple_outputs():
    queries = [Query(sql="SELECT * FROM users WHERE id = 1 OR 1=1")]
    input_source = ManualInput(queries)
    registry = AnalyzerRegistry()
    registry.register(SQLInjectionAnalyzer())
    output1 = MockAlertOutput()
    output2 = MockAlertOutput()

    pipeline = QueryPipeline(input_source, registry, [output1, output2])
    await pipeline.run()

    assert len(output1.alerts) == 1
    assert len(output2.alerts) == 1
    assert output1.alerts[0].query.sql == output2.alerts[0].query.sql


@pytest.mark.asyncio
async def test_pipeline_empty_input():
    input_source = ManualInput([])
    registry = AnalyzerRegistry()
    registry.register(SQLInjectionAnalyzer())
    output = MockAlertOutput()

    pipeline = QueryPipeline(input_source, registry, [output])
    await pipeline.run()

    assert len(output.alerts) == 0


@pytest.mark.asyncio
async def test_pipeline_no_analyzers():
    queries = [Query(sql="SELECT * FROM users WHERE id = 1 OR 1=1")]
    input_source = ManualInput(queries)
    registry = AnalyzerRegistry()
    output = MockAlertOutput()

    pipeline = QueryPipeline(input_source, registry, [output])
    await pipeline.run()

    assert len(output.alerts) == 0


@pytest.mark.asyncio
async def test_pipeline_volume_anomaly_stateful():
    from supabase_query_alert.domain import QueryMetadata

    queries = [Query(sql="SELECT 1", metadata=QueryMetadata(user_id="user1")) for _ in range(25)]
    input_source = ManualInput(queries)
    registry = AnalyzerRegistry()
    registry.register(VolumeAnomalyAnalyzer())
    output = MockAlertOutput()

    pipeline = QueryPipeline(input_source, registry, [output])
    await pipeline.run()

    assert len(output.alerts) > 0
    has_volume_finding = any(
        f.analyzer_name == "volume_anomaly" for alert in output.alerts for f in alert.findings
    )
    assert has_volume_finding
