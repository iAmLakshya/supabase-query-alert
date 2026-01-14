from pathlib import Path

import pytest

from supabase_query_alert.analyzers import AnalyzerRegistry
from supabase_query_alert.analyzers.data_exfiltration import DataExfiltrationAnalyzer
from supabase_query_alert.analyzers.sql_injection import SQLInjectionAnalyzer
from supabase_query_alert.domain import Alert, Severity
from supabase_query_alert.input import LogFileInput

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "sample_postgres.log"


class TestLogFilePipeline:
    @pytest.fixture
    def registry(self) -> AnalyzerRegistry:
        reg = AnalyzerRegistry()
        reg.register(SQLInjectionAnalyzer())
        reg.register(DataExfiltrationAnalyzer())
        return reg

    @pytest.mark.asyncio
    async def test_processes_log_file_end_to_end(
        self, registry: AnalyzerRegistry
    ) -> None:
        input_source = LogFileInput(FIXTURE_PATH)
        alerts: list[Alert] = []
        query_count = 0

        async for query in input_source:
            query_count += 1
            findings = await registry.analyze_all(query)
            if findings:
                alert = Alert(query=query, findings=tuple(findings))
                alerts.append(alert)

        assert query_count == 14
        assert len(alerts) >= 5

    @pytest.mark.asyncio
    async def test_detects_sql_injection_from_log(
        self, registry: AnalyzerRegistry
    ) -> None:
        input_source = LogFileInput(FIXTURE_PATH)
        injection_findings = []

        async for query in input_source:
            findings = await registry.analyze_all(query)
            injection_findings.extend(
                f for f in findings if f.analyzer_name == "sql_injection"
            )

        assert len(injection_findings) >= 3
        severities = {f.severity for f in injection_findings}
        assert Severity.HIGH in severities

    @pytest.mark.asyncio
    async def test_detects_data_exfiltration_from_log(
        self, registry: AnalyzerRegistry
    ) -> None:
        input_source = LogFileInput(FIXTURE_PATH)
        exfil_findings = []

        async for query in input_source:
            findings = await registry.analyze_all(query)
            exfil_findings.extend(
                f for f in findings if f.analyzer_name == "data_exfiltration"
            )

        assert len(exfil_findings) >= 2

    @pytest.mark.asyncio
    async def test_no_alerts_for_normal_queries(
        self, registry: AnalyzerRegistry
    ) -> None:
        normal_lines = [
            "2026-01-14 10:00:00 UTC:127.0.0.1(12345):app@db:[1]: LOG: AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.products,SELECT id, name FROM products WHERE category = 'books';",
            "2026-01-14 10:00:01 UTC:127.0.0.1(12345):app@db:[1]: LOG: AUDIT: SESSION,2,1,WRITE,INSERT,TABLE,public.orders,INSERT INTO orders (user_id, product_id) VALUES (1, 42);",
            "2026-01-14 10:00:02 UTC:127.0.0.1(12345):app@db:[1]: LOG: AUDIT: SESSION,3,1,WRITE,UPDATE,TABLE,public.users,UPDATE users SET last_login = NOW() WHERE id = 1;",
        ]
        input_source = LogFileInput.from_lines(normal_lines)
        alerts = []

        async for query in input_source:
            findings = await registry.analyze_all(query)
            if findings:
                alerts.append(Alert(query=query, findings=tuple(findings)))

        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_preserves_log_metadata_in_alerts(
        self, registry: AnalyzerRegistry
    ) -> None:
        line = "2026-01-14 10:00:15 UTC:192.168.1.50(54321):web_user@mydb:[1002]: LOG: AUDIT: SESSION,4,1,READ,SELECT,TABLE,public.users,SELECT * FROM users WHERE username = 'admin' OR 1=1;"
        input_source = LogFileInput.from_lines([line])

        query = await input_source.__anext__()

        assert query.metadata is not None
        assert query.metadata.user_id == "web_user"
        assert query.metadata.timestamp is not None
        assert query.metadata.source is not None
        assert "logfile" in query.metadata.source
