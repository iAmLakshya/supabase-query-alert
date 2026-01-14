import json
from datetime import datetime, timezone

import pytest
from aiomoto import mock_aws
from aiobotocore.session import get_session

from supabase_query_alert.domain import Alert, Finding, Query, QueryMetadata, Severity
from supabase_query_alert.output import AlertOutput
from supabase_query_alert.output.sqs import SqsAlertOutput


def test_sqs_output_implements_protocol():
    output = SqsAlertOutput(queue_url="https://sqs.us-east-1.amazonaws.com/123456789/test")
    assert isinstance(output, AlertOutput)


def test_sqs_output_name_property():
    output = SqsAlertOutput(queue_url="https://sqs.us-east-1.amazonaws.com/123456789/test")
    assert output.name == "sqs"


@mock_aws
async def test_sqs_output_send_to_queue():
    session = get_session()
    async with session.create_client("sqs", region_name="us-east-1") as client:
        response = await client.create_queue(QueueName="test-queue")
        queue_url = response["QueueUrl"]

        output = SqsAlertOutput(queue_url=queue_url, region="us-east-1")
        query = Query(sql="SELECT * FROM users")
        finding = Finding(
            analyzer_name="sql_injection",
            severity=Severity.HIGH,
            message="Detected SQL injection",
        )
        alert = Alert(query=query, findings=(finding,))

        await output.send(alert)

        messages = await client.receive_message(QueueUrl=queue_url)
        assert "Messages" in messages
        assert len(messages["Messages"]) == 1

        body = json.loads(messages["Messages"][0]["Body"])
        assert body["query"]["sql"] == "SELECT * FROM users"
        assert len(body["findings"]) == 1
        assert body["findings"][0]["analyzer_name"] == "sql_injection"


@mock_aws
async def test_sqs_output_json_includes_all_fields():
    session = get_session()
    async with session.create_client("sqs", region_name="us-east-1") as client:
        response = await client.create_queue(QueueName="test-queue")
        queue_url = response["QueueUrl"]

        output = SqsAlertOutput(queue_url=queue_url, region="us-east-1")
        timestamp = datetime(2026, 1, 14, 12, 0, 0, tzinfo=timezone.utc)
        metadata = QueryMetadata(
            timestamp=timestamp,
            user_id="user_123",
            duration_ms=42.5,
            source="test",
        )
        query = Query(sql="SELECT 1", metadata=metadata)
        finding = Finding(
            analyzer_name="test",
            severity=Severity.MEDIUM,
            message="Test message",
            details={"key": "value"},
        )
        alert = Alert(query=query, findings=(finding,), timestamp=timestamp)

        await output.send(alert)

        messages = await client.receive_message(QueueUrl=queue_url)
        body = json.loads(messages["Messages"][0]["Body"])

        assert body["query"]["sql"] == "SELECT 1"
        assert body["query"]["metadata"]["user_id"] == "user_123"
        assert body["query"]["metadata"]["duration_ms"] == 42.5
        assert body["query"]["metadata"]["timestamp"] == "2026-01-14T12:00:00+00:00"
        assert body["findings"][0]["details"] == {"key": "value"}
        assert body["timestamp"] == "2026-01-14T12:00:00+00:00"


@mock_aws
async def test_sqs_output_severity_serialized_as_int():
    session = get_session()
    async with session.create_client("sqs", region_name="us-east-1") as client:
        response = await client.create_queue(QueueName="test-queue")
        queue_url = response["QueueUrl"]

        output = SqsAlertOutput(queue_url=queue_url, region="us-east-1")
        query = Query(sql="SELECT 1")
        findings = (
            Finding(analyzer_name="low", severity=Severity.LOW, message="Low"),
            Finding(analyzer_name="medium", severity=Severity.MEDIUM, message="Medium"),
            Finding(analyzer_name="high", severity=Severity.HIGH, message="High"),
        )
        alert = Alert(query=query, findings=findings)

        await output.send(alert)

        messages = await client.receive_message(QueueUrl=queue_url)
        body = json.loads(messages["Messages"][0]["Body"])

        assert body["findings"][0]["severity"] == 1
        assert body["findings"][1]["severity"] == 2
        assert body["findings"][2]["severity"] == 3
