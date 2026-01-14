from datetime import datetime, timezone

import pytest

from supabase_query_alert.input.logfile.parser import (
    LogLinePrefix,
    PostgresLogLineParser,
)
from supabase_query_alert.input.supabase.parser import PgAuditLogParser


VALID_AUDIT_LINE = "2020-12-21 00:27:09 UTC:157.230.232.139(54900):sgpostgres@test:[21835]: LOG: AUDIT: SESSION,10,1,READ,SELECT,TABLE,public.users,SELECT * FROM users;"
NON_AUDIT_LINE = "2020-12-21 00:27:09 UTC:::postgres@postgres:[21835]: LOG: checkpoint starting: time"
ERROR_LINE = "2020-12-21 00:27:09 UTC:::postgres@postgres:[21835]: ERROR: relation 'foo' does not exist"
EMPTY_CLIENT_LINE = "2020-12-21 00:27:09 UTC::sgpostgres@mydb:[12345]: LOG: AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.data,SELECT 1;"


class TestPostgresLogLineParser:
    @pytest.fixture
    def parser(self) -> PostgresLogLineParser:
        return PostgresLogLineParser()

    def test_parse_valid_audit_line(self, parser: PostgresLogLineParser) -> None:
        result = parser.parse_line(VALID_AUDIT_LINE)

        assert result is not None
        assert result.audit_type == "SESSION"
        assert result.statement_id == 10
        assert result.command_class == "READ"
        assert result.command == "SELECT"

    def test_parse_extracts_timestamp(self, parser: PostgresLogLineParser) -> None:
        result = parser.parse_line(VALID_AUDIT_LINE)

        assert result is not None
        assert result.timestamp is not None
        assert result.timestamp.year == 2020
        assert result.timestamp.month == 12
        assert result.timestamp.day == 21
        assert result.timestamp.hour == 0
        assert result.timestamp.minute == 27
        assert result.timestamp.second == 9
        assert result.timestamp.tzinfo == timezone.utc

    def test_parse_extracts_user_and_database(self, parser: PostgresLogLineParser) -> None:
        result = parser.parse_line(VALID_AUDIT_LINE)

        assert result is not None
        assert result.user_name == "sgpostgres"
        assert result.database_name == "test"

    def test_parse_extracts_client_address(self, parser: PostgresLogLineParser) -> None:
        result = parser.parse_line(VALID_AUDIT_LINE)

        assert result is not None
        assert result.session_id == "21835"

    def test_parse_handles_missing_client_addr(self, parser: PostgresLogLineParser) -> None:
        result = parser.parse_line(EMPTY_CLIENT_LINE)

        assert result is not None
        assert result.user_name == "sgpostgres"
        assert result.database_name == "mydb"
        assert result.session_id == "12345"

    def test_parse_extracts_sql_statement(self, parser: PostgresLogLineParser) -> None:
        result = parser.parse_line(VALID_AUDIT_LINE)

        assert result is not None
        assert result.statement == "SELECT * FROM users;"

    def test_parse_non_audit_returns_none(self, parser: PostgresLogLineParser) -> None:
        result = parser.parse_line(NON_AUDIT_LINE)
        assert result is None

    def test_parse_error_log_returns_none(self, parser: PostgresLogLineParser) -> None:
        result = parser.parse_line(ERROR_LINE)
        assert result is None

    def test_uses_existing_audit_parser(self) -> None:
        audit_parser = PgAuditLogParser()
        parser = PostgresLogLineParser(audit_parser=audit_parser)
        result = parser.parse_line(VALID_AUDIT_LINE)

        assert result is not None
        assert result.statement == "SELECT * FROM users;"

    def test_parse_preserves_all_audit_fields(self, parser: PostgresLogLineParser) -> None:
        line = "2020-12-21 00:27:09 UTC:1.2.3.4(5678):user@db:[99]: LOG: AUDIT: OBJECT,5,2,WRITE,INSERT,TABLE,public.orders,INSERT INTO orders VALUES (1);"
        result = parser.parse_line(line)

        assert result is not None
        assert result.audit_type == "OBJECT"
        assert result.statement_id == 5
        assert result.substatement_id == 2
        assert result.command_class == "WRITE"
        assert result.command == "INSERT"
        assert result.object_type == "TABLE"
        assert result.object_name == "public.orders"

    def test_parse_empty_line_returns_none(self, parser: PostgresLogLineParser) -> None:
        result = parser.parse_line("")
        assert result is None

    def test_parse_whitespace_line_returns_none(self, parser: PostgresLogLineParser) -> None:
        result = parser.parse_line("   \n\t  ")
        assert result is None

    def test_parse_with_not_logged_parameter(self, parser: PostgresLogLineParser) -> None:
        line = "2020-12-21 00:27:09 UTC::user@db:[100]: LOG: AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT * FROM users WHERE id = $1;,<not logged>"
        result = parser.parse_line(line)

        assert result is not None
        assert result.statement == "SELECT * FROM users WHERE id = $1;"
        assert result.parameter == "<not logged>"


class TestLogLinePrefix:
    def test_frozen_dataclass(self) -> None:
        prefix = LogLinePrefix(
            timestamp=datetime.now(timezone.utc),
            client_addr="127.0.0.1",
            user_name="postgres",
            database_name="mydb",
            process_id=12345,
            log_level="LOG",
        )

        with pytest.raises(AttributeError):
            prefix.user_name = "modified"  # type: ignore[misc]
