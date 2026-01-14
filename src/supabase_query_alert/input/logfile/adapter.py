from pathlib import Path
from typing import TextIO

from supabase_query_alert.domain import Query, QueryMetadata
from supabase_query_alert.input.logfile.parser import PostgresLogLineParser


class LogFileInput:
    """Input adapter that reads pgaudit logs from a PostgreSQL log file."""

    def __init__(
        self,
        file_path: str | Path,
        parser: PostgresLogLineParser | None = None,
    ) -> None:
        self._file_path = Path(file_path)
        self._parser = parser or PostgresLogLineParser()
        self._file: TextIO | None = None
        self._lines: list[str] | None = None
        self._index: int = 0

    @classmethod
    def from_lines(
        cls,
        lines: list[str],
        parser: PostgresLogLineParser | None = None,
    ) -> "LogFileInput":
        """Create adapter from pre-loaded lines (for testing)."""
        instance = cls.__new__(cls)
        instance._file_path = Path("/dev/null")
        instance._parser = parser or PostgresLogLineParser()
        instance._file = None
        instance._lines = lines
        instance._index = 0
        return instance

    def __aiter__(self) -> "LogFileInput":
        return self

    async def __anext__(self) -> Query:
        if self._lines is None:
            self._open_file()

        while self._index < len(self._lines):  # type: ignore[arg-type]
            line = self._lines[self._index]  # type: ignore[index]
            self._index += 1

            parsed = self._parser.parse_line(line)
            if parsed is None:
                continue

            metadata = QueryMetadata(
                timestamp=parsed.timestamp,
                user_id=parsed.user_name,
                source=f"logfile:{parsed.audit_type}:{parsed.session_id or 'unknown'}",
            )
            return Query(sql=parsed.statement, metadata=metadata)

        self._close_file()
        raise StopAsyncIteration

    def _open_file(self) -> None:
        if not self._file_path.exists():
            raise FileNotFoundError(f"Log file not found: {self._file_path}")
        self._file = open(self._file_path, encoding="utf-8")
        self._lines = self._file.readlines()

    def _close_file(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
