from datetime import datetime

import pytest

from supabase_query_alert.input.supabase.parser import ParsedAuditLog, PgAuditLogParser


class TestPgAuditLogParser:
    @pytest.fixture
    def parser(self) -> PgAuditLogParser:
        return PgAuditLogParser()

    class TestParseEventMessage:
        def test_parse_select_statement(self, parser: PgAuditLogParser) -> None:
            msg = "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT * FROM users;"
            result = parser.parse_event_message(msg)

            assert result is not None
            assert result.audit_type == "SESSION"
            assert result.statement_id == 1
            assert result.substatement_id == 1
            assert result.command_class == "READ"
            assert result.command == "SELECT"
            assert result.object_type == "TABLE"
            assert result.object_name == "public.users"
            assert result.statement == "SELECT * FROM users;"
            assert result.parameter is None

        def test_parse_insert_statement(self, parser: PgAuditLogParser) -> None:
            msg = "AUDIT: SESSION,2,1,WRITE,INSERT,TABLE,public.orders,INSERT INTO orders (user_id, total) VALUES (1, 99.99);"
            result = parser.parse_event_message(msg)

            assert result is not None
            assert result.command_class == "WRITE"
            assert result.command == "INSERT"
            assert "VALUES" in result.statement

        def test_parse_ddl_create_table(self, parser: PgAuditLogParser) -> None:
            msg = "AUDIT: SESSION,1,1,DDL,CREATE TABLE,TABLE,public.account,create table account(id int, name text);"
            result = parser.parse_event_message(msg)

            assert result is not None
            assert result.command_class == "DDL"
            assert result.command == "CREATE TABLE"

        def test_parse_with_not_logged_parameter(self, parser: PgAuditLogParser) -> None:
            msg = "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT * FROM users WHERE id = $1;,<not logged>"
            result = parser.parse_event_message(msg)

            assert result is not None
            assert result.statement == "SELECT * FROM users WHERE id = $1;"
            assert result.parameter == "<not logged>"

        def test_parse_object_audit_type(self, parser: PgAuditLogParser) -> None:
            msg = "AUDIT: OBJECT,1,1,READ,SELECT,TABLE,public.sensitive_data,SELECT * FROM sensitive_data;"
            result = parser.parse_event_message(msg)

            assert result is not None
            assert result.audit_type == "OBJECT"

        def test_parse_empty_object_type(self, parser: PgAuditLogParser) -> None:
            msg = "AUDIT: SESSION,1,1,MISC,SET,,session_replication_role,SET session_replication_role = replica;"
            result = parser.parse_event_message(msg)

            assert result is not None
            assert result.object_type is None or result.object_type == ""

        def test_parse_complex_statement_with_joins(self, parser: PgAuditLogParser) -> None:
            msg = "AUDIT: SESSION,3,1,READ,SELECT,TABLE,public.orders,SELECT u.email, o.total FROM users u JOIN orders o ON u.id = o.user_id;"
            result = parser.parse_event_message(msg)

            assert result is not None
            assert "JOIN" in result.statement

        def test_returns_none_for_non_audit_message(self, parser: PgAuditLogParser) -> None:
            msg = "LOG: connection received: host=127.0.0.1 port=5432"
            result = parser.parse_event_message(msg)
            assert result is None

        def test_returns_none_for_malformed_audit(self, parser: PgAuditLogParser) -> None:
            msg = "AUDIT: INVALID"
            result = parser.parse_event_message(msg)
            assert result is None

        def test_handles_multiline_statement(self, parser: PgAuditLogParser) -> None:
            msg = "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT *\nFROM users\nWHERE active = true;"
            result = parser.parse_event_message(msg)

            assert result is not None
            assert "FROM users" in result.statement

    class TestParseLogRow:
        def test_parse_row_with_event_message(self, parser: PgAuditLogParser) -> None:
            row = {
                "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT * FROM users;",
                "timestamp": "2025-01-14T12:00:00Z",
            }
            result = parser.parse_log_row(row)

            assert result is not None
            assert result.statement == "SELECT * FROM users;"
            assert result.timestamp is not None

        def test_parse_row_with_unix_microseconds_timestamp(
            self, parser: PgAuditLogParser
        ) -> None:
            ts_micros = 1705233600000000
            row = {
                "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT 1;",
                "timestamp": ts_micros,
            }
            result = parser.parse_log_row(row)

            assert result is not None
            assert result.timestamp is not None
            assert isinstance(result.timestamp, datetime)

        def test_parse_row_with_nested_metadata(self, parser: PgAuditLogParser) -> None:
            row = {
                "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT 1;",
                "timestamp": "2025-01-14T12:00:00Z",
                "parsed": {"user_name": "postgres", "database_name": "mydb", "session_id": "abc123"},
            }
            result = parser.parse_log_row(row)

            assert result is not None
            assert result.user_name == "postgres"
            assert result.database_name == "mydb"
            assert result.session_id == "abc123"

        def test_parse_row_with_flat_fields(self, parser: PgAuditLogParser) -> None:
            row = {
                "event_message": "AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,SELECT 1;",
                "timestamp": "2025-01-14T12:00:00Z",
                "user_name": "app_user",
                "database_name": "production",
            }
            result = parser.parse_log_row(row)

            assert result is not None
            assert result.user_name == "app_user"
            assert result.database_name == "production"

        def test_parse_row_skips_non_audit_message(self, parser: PgAuditLogParser) -> None:
            row = {"event_message": "LOG: checkpoint starting", "timestamp": "2025-01-14T12:00:00Z"}
            result = parser.parse_log_row(row)
            assert result is None

        def test_parse_row_handles_missing_event_message(self, parser: PgAuditLogParser) -> None:
            row = {"timestamp": "2025-01-14T12:00:00Z"}
            result = parser.parse_log_row(row)
            assert result is None

        def test_parse_row_handles_empty_event_message(self, parser: PgAuditLogParser) -> None:
            row = {"event_message": "", "timestamp": "2025-01-14T12:00:00Z"}
            result = parser.parse_log_row(row)
            assert result is None


class TestParsedAuditLog:
    def test_frozen_dataclass(self) -> None:
        log = ParsedAuditLog(
            audit_type="SESSION",
            statement_id=1,
            substatement_id=1,
            command_class="READ",
            command="SELECT",
            object_type="TABLE",
            object_name="public.users",
            statement="SELECT 1;",
            parameter=None,
        )

        with pytest.raises(AttributeError):
            log.statement = "modified"  # type: ignore[misc]

    def test_optional_fields_default_to_none(self) -> None:
        log = ParsedAuditLog(
            audit_type="SESSION",
            statement_id=1,
            substatement_id=1,
            command_class="READ",
            command="SELECT",
            object_type=None,
            object_name=None,
            statement="SELECT 1;",
            parameter=None,
        )

        assert log.timestamp is None
        assert log.user_name is None
        assert log.database_name is None
        assert log.session_id is None
