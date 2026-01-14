import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class ParsedAuditLog:
    """Parsed pgaudit log entry."""

    audit_type: str
    statement_id: int
    substatement_id: int
    command_class: str
    command: str
    object_type: str | None
    object_name: str | None
    statement: str
    parameter: str | None
    timestamp: datetime | None = None
    user_name: str | None = None
    database_name: str | None = None
    session_id: str | None = None


class PgAuditLogParser:
    """Parser for pgaudit log entries from Supabase postgres_logs."""

    AUDIT_PREFIX = re.compile(
        r"^AUDIT:\s*"
        r"(?P<audit_type>SESSION|OBJECT),"
        r"(?P<statement_id>\d+),"
        r"(?P<substatement_id>\d+),"
        r"(?P<command_class>\w+),"
        r"(?P<command>\w+(?:\s+\w+)*),"
        r"(?P<object_type>[^,]*),"
        r"(?P<object_name>[^,]*),"
    )

    def parse_event_message(self, event_message: str) -> ParsedAuditLog | None:
        """Parse a single pgaudit event_message.

        Returns None if the message is not a valid pgaudit log entry.
        """
        match = self.AUDIT_PREFIX.match(event_message.strip())
        if not match:
            return None

        statement_start = match.end()
        remainder = event_message[statement_start:]

        statement = remainder.strip()
        parameter = None

        if statement.endswith("<not logged>"):
            statement = statement[: -len("<not logged>")].rstrip(",").strip()
            parameter = "<not logged>"

        return ParsedAuditLog(
            audit_type=match.group("audit_type"),
            statement_id=int(match.group("statement_id")),
            substatement_id=int(match.group("substatement_id")),
            command_class=match.group("command_class"),
            command=match.group("command"),
            object_type=match.group("object_type") or None,
            object_name=match.group("object_name") or None,
            statement=statement,
            parameter=parameter,
        )

    def parse_log_row(self, row: dict[str, Any]) -> ParsedAuditLog | None:
        """Parse a log row from Supabase Management API response.

        Expected row structure from BigQuery-style response:
        {
            "event_message": "AUDIT: SESSION,1,1,READ,SELECT,...",
            "timestamp": "2025-01-14T12:00:00Z" or unix microseconds,
            "metadata": [...] or flattened parsed.* fields
        }
        """
        event_message = row.get("event_message", "")
        if not event_message or not event_message.startswith("AUDIT:"):
            return None

        parsed = self.parse_event_message(event_message)
        if not parsed:
            return None

        timestamp = self._extract_timestamp(row)
        user_name = self._extract_nested(row, "parsed.user_name", "user_name")
        database_name = self._extract_nested(row, "parsed.database_name", "database_name")
        session_id = self._extract_nested(row, "parsed.session_id", "session_id")

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
            timestamp=timestamp,
            user_name=user_name,
            database_name=database_name,
            session_id=session_id,
        )

    def _extract_timestamp(self, row: dict[str, Any]) -> datetime | None:
        ts = row.get("timestamp")
        if ts is None:
            return None

        if isinstance(ts, datetime):
            return ts

        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                pass

        if isinstance(ts, int | float):
            try:
                return datetime.fromtimestamp(ts / 1_000_000)
            except (ValueError, OSError):
                pass

        return None

    def _extract_nested(self, row: dict[str, Any], *keys: str) -> str | None:
        for key in keys:
            if "." in key:
                parts = key.split(".")
                value: Any = row
                for part in parts:
                    if isinstance(value, dict):
                        value = value.get(part)
                    else:
                        value = None
                        break
                if value is not None:
                    return str(value)
            elif key in row:
                return str(row[key]) if row[key] is not None else None
        return None
