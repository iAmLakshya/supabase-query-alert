import pytest

from supabase_query_alert.domain import Alert, Finding, Query, Severity
from supabase_query_alert.output import AlertOutput, ConsoleAlertOutput


def test_alert_output_protocol_is_runtime_checkable():
    assert hasattr(AlertOutput, "__protocol_attrs__")


def test_console_output_implements_protocol():
    output = ConsoleAlertOutput()
    assert isinstance(output, AlertOutput)


def test_console_output_name_property():
    output = ConsoleAlertOutput()
    assert output.name == "console"


@pytest.mark.asyncio
async def test_console_output_send_formats_correctly(capsys):
    output = ConsoleAlertOutput()
    query = Query(sql="SELECT * FROM users WHERE id = 1")
    finding = Finding(
        analyzer_name="test_analyzer",
        severity=Severity.HIGH,
        message="Test finding message",
    )
    alert = Alert(query=query, findings=(finding,))

    await output.send(alert)

    captured = capsys.readouterr()
    assert "[ALERT]" in captured.out
    assert "[HIGH]" in captured.out
    assert "SELECT * FROM users WHERE id = 1" in captured.out
    assert "1 finding(s)" in captured.out
    assert "test_analyzer: Test finding message" in captured.out


@pytest.mark.asyncio
async def test_console_output_send_with_custom_prefix(capsys):
    output = ConsoleAlertOutput(prefix="[WARN]")
    query = Query(sql="SELECT 1")
    finding = Finding(
        analyzer_name="test",
        severity=Severity.LOW,
        message="msg",
    )
    alert = Alert(query=query, findings=(finding,))

    await output.send(alert)

    captured = capsys.readouterr()
    assert "[WARN]" in captured.out
    assert "[ALERT]" not in captured.out


@pytest.mark.asyncio
async def test_console_output_send_empty_findings(capsys):
    output = ConsoleAlertOutput()
    query = Query(sql="SELECT 1")
    alert = Alert(query=query, findings=())

    await output.send(alert)

    captured = capsys.readouterr()
    assert "0 finding(s)" in captured.out
    assert "[LOW]" in captured.out


@pytest.mark.asyncio
async def test_console_output_send_multiple_findings(capsys):
    output = ConsoleAlertOutput()
    query = Query(sql="SELECT * FROM users")
    findings = (
        Finding(analyzer_name="analyzer1", severity=Severity.HIGH, message="msg1"),
        Finding(analyzer_name="analyzer2", severity=Severity.MEDIUM, message="msg2"),
        Finding(analyzer_name="analyzer3", severity=Severity.LOW, message="msg3"),
    )
    alert = Alert(query=query, findings=findings)

    await output.send(alert)

    captured = capsys.readouterr()
    assert "3 finding(s)" in captured.out
    assert "[HIGH]" in captured.out
    assert "analyzer1: msg1" in captured.out
    assert "analyzer2: msg2" in captured.out
    assert "analyzer3: msg3" in captured.out
