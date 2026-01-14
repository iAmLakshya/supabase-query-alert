import re
from dataclasses import dataclass
from datetime import datetime, timezone

from supabase_query_alert.input.supabase.parser import ParsedAuditLog, PgAuditLogParser


@dataclass(frozen=True, slots=True)
class LogLinePrefix:
    timestamp: datetime
    client_addr: str | None
    user_name: str | None
    database_name: str | None
    process_id: int | None
    log_level: str


class PostgresLogLineParser:
    """Parser for full PostgreSQL log lines containing pgaudit entries."""

    LOG_LINE_PATTERN = re.compile(
        r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<tz>\w+)"
        r":(?P<client>[^:]*):"
        r"(?P<conn>[^:]*)"
        r":\[(?P<pid>\d+)\]:\s*"
        r"(?P<level>\w+):\s*"
        r"(?P<message>.*)$"
    )

    USER_DB_PATTERN = re.compile(r"^(?P<user>[^@]+)(?:@(?P<db>.+))?$")

    def __init__(self, audit_parser: PgAuditLogParser | None = None) -> None:
        self._audit_parser = audit_parser or PgAuditLogParser()

    def parse_line(self, line: str) -> ParsedAuditLog | None:
        """Parse a PostgreSQL log line. Returns None if not an audit line."""
        line = line.strip()
        if not line:
            return None

        match = self.LOG_LINE_PATTERN.match(line)
        if not match:
            return None

        message = match.group("message")
        if not message.startswith("AUDIT:"):
            return None

        prefix = self._parse_prefix(match)
        parsed = self._audit_parser.parse_event_message(message)
        if parsed is None:
            return None

        return ParsedAuditLog(
            audit_type=parsed.audit_type,
            statement_id=parsed.statement_id,
            substatement_id=parsed.substatement_id,
            command_class=parsed.command_class,
            command=parsed.command,
            object_type=parsed.object_type,
            object_name=parsed.object_name,
            statement=parsed.statement,
            parameter=parsed.parameter,
            timestamp=prefix.timestamp,
            user_name=prefix.user_name,
            database_name=prefix.database_name,
            session_id=str(prefix.process_id) if prefix.process_id else None,
        )

    def _parse_prefix(self, match: re.Match[str]) -> LogLinePrefix:
        ts_str = match.group("ts")
        tz_str = match.group("tz")
        timestamp = self._parse_timestamp(ts_str, tz_str)

        client = match.group("client").strip() or None
        conn = match.group("conn").strip()
        user_name, database_name = self._parse_user_db(conn)

        pid_str = match.group("pid")
        process_id = int(pid_str) if pid_str else None

        return LogLinePrefix(
            timestamp=timestamp,
            client_addr=client,
            user_name=user_name,
            database_name=database_name,
            process_id=process_id,
            log_level=match.group("level"),
        )

    def _parse_timestamp(self, ts_str: str, tz_str: str) -> datetime:
        dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        if tz_str.upper() == "UTC":
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    def _parse_user_db(self, conn: str) -> tuple[str | None, str | None]:
        if not conn:
            return None, None
        match = self.USER_DB_PATTERN.match(conn)
        if not match:
            return None, None
        return match.group("user") or None, match.group("db") or None
