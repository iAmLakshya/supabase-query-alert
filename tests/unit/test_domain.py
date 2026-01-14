"""Tests for domain models."""

from datetime import datetime

from supabase_query_alert.domain import (
    Alert,
    Finding,
    Query,
    QueryMetadata,
    Severity,
)


class TestSeverity:
    def test_severity_ordering(self) -> None:
        assert Severity.HIGH > Severity.MEDIUM > Severity.LOW

    def test_severity_values(self) -> None:
        assert Severity.LOW == 1
        assert Severity.MEDIUM == 2
        assert Severity.HIGH == 3


class TestQueryMetadata:
    def test_metadata_with_all_fields(self) -> None:
        ts = datetime(2024, 1, 15, 10, 30, 0)
        metadata = QueryMetadata(
            timestamp=ts,
            user_id="user-123",
            duration_ms=150.5,
            source="api",
        )
        assert metadata.timestamp == ts
        assert metadata.user_id == "user-123"
        assert metadata.duration_ms == 150.5
        assert metadata.source == "api"

    def test_metadata_with_defaults(self) -> None:
        metadata = QueryMetadata()
        assert metadata.timestamp is None
        assert metadata.user_id is None
        assert metadata.duration_ms is None
        assert metadata.source is None


class TestQuery:
    def test_query_with_sql_only(self) -> None:
        query = Query(sql="SELECT * FROM users")
        assert query.sql == "SELECT * FROM users"
        assert query.metadata is None

    def test_query_with_metadata(self) -> None:
        metadata = QueryMetadata(user_id="admin", source="dashboard")
        query = Query(sql="SELECT * FROM orders", metadata=metadata)
        assert query.sql == "SELECT * FROM orders"
        assert query.metadata is not None
        assert query.metadata.user_id == "admin"


class TestFinding:
    def test_finding_creation(self) -> None:
        finding = Finding(
            analyzer_name="sql_injection",
            severity=Severity.HIGH,
            message="Potential SQL injection detected",
            details={"pattern": "OR 1=1"},
        )
        assert finding.analyzer_name == "sql_injection"
        assert finding.severity == Severity.HIGH
        assert finding.message == "Potential SQL injection detected"
        assert finding.details == {"pattern": "OR 1=1"}

    def test_finding_without_details(self) -> None:
        finding = Finding(
            analyzer_name="volume_anomaly",
            severity=Severity.MEDIUM,
            message="High query volume detected",
        )
        assert finding.details is None


class TestAlert:
    def test_alert_with_multiple_findings(self) -> None:
        query = Query(sql="SELECT * FROM users WHERE id=1 OR 1=1")
        findings = (
            Finding("sql_injection", Severity.HIGH, "SQL injection detected"),
            Finding("volume_anomaly", Severity.LOW, "Normal volume"),
        )
        alert = Alert(query=query, findings=findings)
        assert alert.query == query
        assert len(alert.findings) == 2
        assert alert.severity == Severity.HIGH

    def test_alert_severity_returns_highest(self) -> None:
        query = Query(sql="SELECT * FROM sensitive_table")
        findings = (
            Finding("analyzer_a", Severity.LOW, "Low severity issue"),
            Finding("analyzer_b", Severity.MEDIUM, "Medium severity issue"),
            Finding("analyzer_c", Severity.LOW, "Another low severity"),
        )
        alert = Alert(query=query, findings=findings)
        assert alert.severity == Severity.MEDIUM

    def test_alert_with_no_findings(self) -> None:
        query = Query(sql="SELECT 1")
        alert = Alert(query=query)
        assert alert.severity == Severity.LOW

    def test_alert_has_timestamp(self) -> None:
        query = Query(sql="SELECT 1")
        before = datetime.now()
        alert = Alert(query=query)
        after = datetime.now()
        assert before <= alert.timestamp <= after

    def test_alert_immutability(self) -> None:
        query = Query(sql="SELECT 1")
        alert = Alert(query=query)
        try:
            alert.query = Query(sql="SELECT 2")  # type: ignore[misc]
            raise AssertionError("Should have raised FrozenInstanceError")
        except AttributeError:
            pass
