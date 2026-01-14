"""
End-to-end integration tests for Supabase log analysis pipeline.

These tests simulate the full production flow:
1. Receive log data (via SupabaseLogInput.from_log_rows for testing)
2. Parse pgaudit entries into Query objects
3. Analyze queries through all registered analyzers
4. Generate alerts for suspicious activity

To run with real Supabase:
    See docs/HOSTED_SETUP.md for configuration instructions.
"""

import pytest

from supabase_query_alert.analyzers import AnalyzerRegistry
from supabase_query_alert.analyzers.data_exfiltration import DataExfiltrationAnalyzer
from supabase_query_alert.analyzers.sql_injection import SQLInjectionAnalyzer
from supabase_query_alert.analyzers.volume_anomaly import VolumeAnomalyAnalyzer
from supabase_query_alert.domain import Alert, Severity
from supabase_query_alert.input.supabase import SupabaseLogInput


REALISTIC_AUDIT_LOGS = [
    {
        "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT id, email FROM users WHERE id = 1;",
        "timestamp": "2025-01-14T12:00:00Z",
        "user_name": "app_backend",
        "database_name": "production",
    },
    {
        "event_message": "AUDIT: SESSION,2,1,READ,SELECT,TABLE,public.products,SELECT * FROM products WHERE category = 'electronics';",
        "timestamp": "2025-01-14T12:00:01Z",
        "user_name": "app_backend",
        "database_name": "production",
    },
    {
        "event_message": "AUDIT: SESSION,3,1,WRITE,INSERT,TABLE,public.orders,INSERT INTO orders (user_id, product_id, quantity) VALUES (1, 42, 2);",
        "timestamp": "2025-01-14T12:00:02Z",
        "user_name": "app_backend",
        "database_name": "production",
    },
]

SQL_INJECTION_ATTACK_LOGS = [
    {
        "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT * FROM users WHERE username = 'admin' OR 1=1--';",
        "timestamp": "2025-01-14T13:00:00Z",
        "user_name": "web_user",
        "database_name": "production",
    },
    {
        "event_message": "AUDIT: SESSION,2,1,READ,SELECT,TABLE,public.users,SELECT * FROM users WHERE id = 1; DROP TABLE users;--",
        "timestamp": "2025-01-14T13:00:01Z",
        "user_name": "web_user",
        "database_name": "production",
    },
    {
        "event_message": "AUDIT: SESSION,3,1,READ,SELECT,TABLE,public.users,SELECT * FROM users UNION SELECT username, password FROM admin_users;",
        "timestamp": "2025-01-14T13:00:02Z",
        "user_name": "web_user",
        "database_name": "production",
    },
]

DATA_EXFILTRATION_LOGS = [
    {
        "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT * FROM users;",
        "timestamp": "2025-01-14T14:00:00Z",
        "user_name": "suspicious_user",
        "database_name": "production",
    },
    {
        "event_message": "AUDIT: SESSION,2,1,READ,SELECT,TABLE,public.users,SELECT password_hash, api_key, secret_token FROM users;",
        "timestamp": "2025-01-14T14:00:01Z",
        "user_name": "suspicious_user",
        "database_name": "production",
    },
    {
        "event_message": "AUDIT: SESSION,3,1,READ,SELECT,TABLE,public.orders,SELECT * FROM orders LIMIT 50000;",
        "timestamp": "2025-01-14T14:00:02Z",
        "user_name": "suspicious_user",
        "database_name": "production",
    },
]

MIXED_ACTIVITY_LOGS = [
    *REALISTIC_AUDIT_LOGS,
    *SQL_INJECTION_ATTACK_LOGS,
    *DATA_EXFILTRATION_LOGS,
    {
        "event_message": "LOG: checkpoint starting: time",
        "timestamp": "2025-01-14T14:30:00Z",
    },
    {
        "event_message": "LOG: connection received: host=127.0.0.1 port=5432",
        "timestamp": "2025-01-14T14:30:01Z",
    },
]


async def analyze_logs(
    log_rows: list[dict], registry: AnalyzerRegistry
) -> list[Alert]:
    """Helper to analyze logs and return alerts."""
    input_source = SupabaseLogInput.from_log_rows(log_rows)
    alerts = []

    async for query in input_source:
        findings = await registry.analyze_all(query)
        if findings:
            alert = Alert(query=query, findings=tuple(findings))
            alerts.append(alert)

    return alerts


class TestSupabaseE2EPipeline:
    @pytest.fixture
    def registry(self) -> AnalyzerRegistry:
        reg = AnalyzerRegistry()
        reg.register(SQLInjectionAnalyzer())
        reg.register(DataExfiltrationAnalyzer())
        reg.register(VolumeAnomalyAnalyzer())
        return reg

    class TestNormalTraffic:
        @pytest.mark.asyncio
        async def test_no_alerts_for_normal_queries(
            self, registry: AnalyzerRegistry
        ) -> None:
            alerts = await analyze_logs(REALISTIC_AUDIT_LOGS, registry)
            assert len(alerts) == 0

    class TestSqlInjectionDetection:
        @pytest.mark.asyncio
        async def test_detects_sql_injection_attacks(
            self, registry: AnalyzerRegistry
        ) -> None:
            alerts = await analyze_logs(SQL_INJECTION_ATTACK_LOGS, registry)

            assert len(alerts) == 3

            severities = [a.severity for a in alerts]
            assert Severity.HIGH in severities

            injection_findings = [
                f
                for a in alerts
                for f in a.findings
                if f.analyzer_name == "sql_injection"
            ]
            assert len(injection_findings) >= 3

        @pytest.mark.asyncio
        async def test_detects_tautology_attack(self, registry: AnalyzerRegistry) -> None:
            logs = [
                {
                    "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT * FROM users WHERE user='admin' OR '1'='1';",
                    "timestamp": "2025-01-14T15:00:00Z",
                    "user_name": "attacker",
                }
            ]

            input_source = SupabaseLogInput.from_log_rows(logs)
            query = await input_source.__anext__()
            findings = await registry.analyze_all(query)

            assert len(findings) > 0
            assert any(f.analyzer_name == "sql_injection" for f in findings)

        @pytest.mark.asyncio
        async def test_detects_union_injection(self, registry: AnalyzerRegistry) -> None:
            logs = [
                {
                    "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT name FROM users UNION SELECT password FROM secrets;",
                    "timestamp": "2025-01-14T15:00:00Z",
                    "user_name": "attacker",
                }
            ]

            input_source = SupabaseLogInput.from_log_rows(logs)
            query = await input_source.__anext__()
            findings = await registry.analyze_all(query)

            injection_findings = [f for f in findings if f.analyzer_name == "sql_injection"]
            assert len(injection_findings) > 0
            assert any("UNION" in str(f.details) for f in injection_findings)

    class TestDataExfiltrationDetection:
        @pytest.mark.asyncio
        async def test_detects_sensitive_column_access(
            self, registry: AnalyzerRegistry
        ) -> None:
            alerts = await analyze_logs(DATA_EXFILTRATION_LOGS, registry)

            exfil_findings = [
                f
                for a in alerts
                for f in a.findings
                if f.analyzer_name == "data_exfiltration"
            ]
            assert len(exfil_findings) >= 2

        @pytest.mark.asyncio
        async def test_detects_select_star_on_users(
            self, registry: AnalyzerRegistry
        ) -> None:
            logs = [
                {
                    "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT * FROM users;",
                    "timestamp": "2025-01-14T16:00:00Z",
                    "user_name": "suspicious",
                }
            ]

            input_source = SupabaseLogInput.from_log_rows(logs)
            query = await input_source.__anext__()
            findings = await registry.analyze_all(query)

            exfil_findings = [f for f in findings if f.analyzer_name == "data_exfiltration"]
            assert len(exfil_findings) > 0
            assert any(f.severity == Severity.HIGH for f in exfil_findings)

        @pytest.mark.asyncio
        async def test_detects_large_limit_queries(
            self, registry: AnalyzerRegistry
        ) -> None:
            logs = [
                {
                    "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.data,SELECT id FROM data LIMIT 100000;",
                    "timestamp": "2025-01-14T16:00:00Z",
                    "user_name": "bulk_export",
                }
            ]

            input_source = SupabaseLogInput.from_log_rows(logs)
            query = await input_source.__anext__()
            findings = await registry.analyze_all(query)

            exfil_findings = [f for f in findings if f.analyzer_name == "data_exfiltration"]
            assert len(exfil_findings) > 0

    class TestMixedTraffic:
        @pytest.mark.asyncio
        async def test_processes_mixed_log_stream(
            self, registry: AnalyzerRegistry
        ) -> None:
            input_source = SupabaseLogInput.from_log_rows(MIXED_ACTIVITY_LOGS)
            alerts = []
            query_count = 0

            async for query in input_source:
                query_count += 1
                findings = await registry.analyze_all(query)
                if findings:
                    alert = Alert(query=query, findings=tuple(findings))
                    alerts.append(alert)

            assert query_count == 9

            assert len(alerts) >= 3

        @pytest.mark.asyncio
        async def test_preserves_user_attribution_in_alerts(
            self, registry: AnalyzerRegistry
        ) -> None:
            alerts = await analyze_logs(SQL_INJECTION_ATTACK_LOGS, registry)

            for alert in alerts:
                assert alert.query.metadata is not None
                assert alert.query.metadata.user_id == "web_user"

    class TestNonAuditLogFiltering:
        @pytest.mark.asyncio
        async def test_filters_out_non_audit_logs(self) -> None:
            logs = [
                {"event_message": "LOG: checkpoint starting", "timestamp": "2025-01-14T17:00:00Z"},
                {"event_message": "LOG: connection received: host=127.0.0.1", "timestamp": "2025-01-14T17:00:01Z"},
                {"event_message": "WARNING: autovacuum launcher started", "timestamp": "2025-01-14T17:00:02Z"},
                {"event_message": "ERROR: division by zero", "timestamp": "2025-01-14T17:00:03Z"},
                {
                    "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.t,SELECT 1;",
                    "timestamp": "2025-01-14T17:00:04Z",
                },
            ]

            input_source = SupabaseLogInput.from_log_rows(logs)
            queries = [q async for q in input_source]

            assert len(queries) == 1
            assert "SELECT 1" in queries[0].sql


class TestAlertAggregation:
    @pytest.fixture
    def registry(self) -> AnalyzerRegistry:
        reg = AnalyzerRegistry()
        reg.register(SQLInjectionAnalyzer())
        reg.register(DataExfiltrationAnalyzer())
        return reg

    @pytest.mark.asyncio
    async def test_aggregates_multiple_findings(self, registry: AnalyzerRegistry) -> None:
        logs = [
            {
                "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT * FROM users WHERE id = 1 OR 1=1;",
                "timestamp": "2025-01-14T18:00:00Z",
                "user_name": "attacker",
            }
        ]

        input_source = SupabaseLogInput.from_log_rows(logs)
        query = await input_source.__anext__()
        findings = await registry.analyze_all(query)

        analyzer_names = {f.analyzer_name for f in findings}
        assert "sql_injection" in analyzer_names
        assert "data_exfiltration" in analyzer_names

    @pytest.mark.asyncio
    async def test_alert_severity_is_max_of_findings(
        self, registry: AnalyzerRegistry
    ) -> None:
        logs = [
            {
                "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT * FROM users; DROP TABLE users;--",
                "timestamp": "2025-01-14T18:00:00Z",
                "user_name": "attacker",
            }
        ]

        input_source = SupabaseLogInput.from_log_rows(logs)
        query = await input_source.__anext__()
        findings = await registry.analyze_all(query)

        alert = Alert(query=query, findings=tuple(findings))

        assert alert.severity == Severity.HIGH
