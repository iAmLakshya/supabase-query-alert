from pathlib import Path

import pytest

from supabase_query_alert.input.base import QueryInput
from supabase_query_alert.input.logfile import LogFileInput, PostgresLogLineParser


VALID_AUDIT_LINE = "2020-12-21 00:27:09 UTC:157.230.232.139(54900):sgpostgres@test:[21835]: LOG: AUDIT: SESSION,10,1,READ,SELECT,TABLE,public.users,SELECT * FROM users;"
NON_AUDIT_LINE = "2020-12-21 00:27:09 UTC:::postgres@postgres:[21835]: LOG: checkpoint starting: time"
SECOND_AUDIT_LINE = "2020-12-21 00:28:00 UTC:1.2.3.4(1234):admin@prod:[99999]: LOG: AUDIT: SESSION,1,1,WRITE,INSERT,TABLE,public.logs,INSERT INTO logs VALUES (1);"


class TestLogFileInput:
    def test_logfile_input_implements_protocol(self) -> None:
        adapter = LogFileInput.from_lines([])
        assert isinstance(adapter, QueryInput)

    @pytest.mark.asyncio
    async def test_reads_audit_lines_from_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "postgres.log"
        log_file.write_text(VALID_AUDIT_LINE + "\n")

        adapter = LogFileInput(log_file)
        queries = [q async for q in adapter]

        assert len(queries) == 1
        assert queries[0].sql == "SELECT * FROM users;"

    @pytest.mark.asyncio
    async def test_skips_non_audit_lines(self, tmp_path: Path) -> None:
        log_file = tmp_path / "postgres.log"
        log_file.write_text(NON_AUDIT_LINE + "\n" + VALID_AUDIT_LINE + "\n")

        adapter = LogFileInput(log_file)
        queries = [q async for q in adapter]

        assert len(queries) == 1
        assert "SELECT * FROM users" in queries[0].sql

    @pytest.mark.asyncio
    async def test_handles_empty_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "postgres.log"
        log_file.write_text("")

        adapter = LogFileInput(log_file)
        queries = [q async for q in adapter]

        assert len(queries) == 0

    @pytest.mark.asyncio
    async def test_handles_mixed_content(self, tmp_path: Path) -> None:
        content = f"{NON_AUDIT_LINE}\n{VALID_AUDIT_LINE}\n{NON_AUDIT_LINE}\n{SECOND_AUDIT_LINE}\n"
        log_file = tmp_path / "postgres.log"
        log_file.write_text(content)

        adapter = LogFileInput(log_file)
        queries = [q async for q in adapter]

        assert len(queries) == 2
        assert queries[0].sql == "SELECT * FROM users;"
        assert "INSERT INTO logs" in queries[1].sql

    @pytest.mark.asyncio
    async def test_from_lines_factory(self) -> None:
        lines = [VALID_AUDIT_LINE, NON_AUDIT_LINE]
        adapter = LogFileInput.from_lines(lines)
        queries = [q async for q in adapter]

        assert len(queries) == 1
        assert queries[0].sql == "SELECT * FROM users;"

    @pytest.mark.asyncio
    async def test_query_has_metadata(self, tmp_path: Path) -> None:
        log_file = tmp_path / "postgres.log"
        log_file.write_text(VALID_AUDIT_LINE + "\n")

        adapter = LogFileInput(log_file)
        queries = [q async for q in adapter]

        assert len(queries) == 1
        assert queries[0].metadata is not None
        assert queries[0].metadata.user_id == "sgpostgres"
        assert queries[0].metadata.timestamp is not None
        assert "logfile:SESSION:" in queries[0].metadata.source

    @pytest.mark.asyncio
    async def test_raises_on_missing_file(self) -> None:
        adapter = LogFileInput("/nonexistent/path/to/file.log")

        with pytest.raises(FileNotFoundError):
            _ = [q async for q in adapter]

    @pytest.mark.asyncio
    async def test_accepts_custom_parser(self) -> None:
        parser = PostgresLogLineParser()
        adapter = LogFileInput.from_lines([VALID_AUDIT_LINE], parser=parser)
        queries = [q async for q in adapter]

        assert len(queries) == 1

    @pytest.mark.asyncio
    async def test_multiple_audit_entries(self, tmp_path: Path) -> None:
        lines = [
            "2020-12-21 00:27:09 UTC::user@db:[1]: LOG: AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.a,SELECT * FROM a;",
            "2020-12-21 00:27:10 UTC::user@db:[2]: LOG: AUDIT: SESSION,2,1,READ,SELECT,TABLE,public.b,SELECT * FROM b;",
            "2020-12-21 00:27:11 UTC::user@db:[3]: LOG: AUDIT: SESSION,3,1,READ,SELECT,TABLE,public.c,SELECT * FROM c;",
        ]
        log_file = tmp_path / "postgres.log"
        log_file.write_text("\n".join(lines) + "\n")

        adapter = LogFileInput(log_file)
        queries = [q async for q in adapter]

        assert len(queries) == 3
        assert queries[0].sql == "SELECT * FROM a;"
        assert queries[1].sql == "SELECT * FROM b;"
        assert queries[2].sql == "SELECT * FROM c;"
