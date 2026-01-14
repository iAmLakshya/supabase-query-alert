import pytest

from supabase_query_alert.analyzers import AnalyzerRegistry
from supabase_query_alert.analyzers.sql_injection import SQLInjectionAnalyzer
from supabase_query_alert.domain import Query
from supabase_query_alert.input import LogFileInput, ManualInput, QueryInput, SupabaseLogInput

INJECTION_SQL = "SELECT * FROM users WHERE id = 1 OR 1=1;"


class TestAdapterPattern:
    @pytest.fixture
    def registry(self) -> AnalyzerRegistry:
        reg = AnalyzerRegistry()
        reg.register(SQLInjectionAnalyzer())
        return reg

    class TestAllAdaptersImplementProtocol:
        def test_manual_input_implements_protocol(self) -> None:
            assert isinstance(ManualInput([]), QueryInput)

        def test_logfile_input_implements_protocol(self) -> None:
            input_source = LogFileInput.from_lines([])
            assert isinstance(input_source, QueryInput)

        def test_supabase_input_implements_protocol(self) -> None:
            input_source = SupabaseLogInput.from_log_rows([])
            assert isinstance(input_source, QueryInput)

    class TestSameQuerySameResult:
        @pytest.fixture
        def registry(self) -> AnalyzerRegistry:
            reg = AnalyzerRegistry()
            reg.register(SQLInjectionAnalyzer())
            return reg

        @pytest.mark.asyncio
        async def test_injection_detected_via_manual_input(
            self, registry: AnalyzerRegistry
        ) -> None:
            query = Query(sql=INJECTION_SQL)
            input_source = ManualInput([query])

            q = await input_source.__anext__()
            findings = await registry.analyze_all(q)

            assert len(findings) > 0
            assert any(f.analyzer_name == "sql_injection" for f in findings)

        @pytest.mark.asyncio
        async def test_injection_detected_via_logfile_input(
            self, registry: AnalyzerRegistry
        ) -> None:
            log_line = f"2026-01-14 10:00:00 UTC:127.0.0.1(1234):test@db:[1]: LOG: AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,{INJECTION_SQL}"
            input_source = LogFileInput.from_lines([log_line])

            q = await input_source.__anext__()
            findings = await registry.analyze_all(q)

            assert len(findings) > 0
            assert any(f.analyzer_name == "sql_injection" for f in findings)

        @pytest.mark.asyncio
        async def test_injection_detected_via_supabase_input(
            self, registry: AnalyzerRegistry
        ) -> None:
            log_row = {
                "event_message": f"AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,{INJECTION_SQL}",
                "timestamp": "2026-01-14T10:00:00Z",
            }
            input_source = SupabaseLogInput.from_log_rows([log_row])

            q = await input_source.__anext__()
            findings = await registry.analyze_all(q)

            assert len(findings) > 0
            assert any(f.analyzer_name == "sql_injection" for f in findings)

        @pytest.mark.asyncio
        async def test_all_adapters_produce_equivalent_analysis(
            self, registry: AnalyzerRegistry
        ) -> None:
            manual = ManualInput([Query(sql=INJECTION_SQL)])
            logfile = LogFileInput.from_lines([
                f"2026-01-14 10:00:00 UTC:127.0.0.1(1234):test@db:[1]: LOG: AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,{INJECTION_SQL}"
            ])
            supabase = SupabaseLogInput.from_log_rows([{
                "event_message": f"AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,{INJECTION_SQL}",
                "timestamp": "2026-01-14T10:00:00Z",
            }])

            results = []
            for input_source in [manual, logfile, supabase]:
                q = await input_source.__anext__()
                findings = await registry.analyze_all(q)
                results.append(findings)

            finding_counts = [len(f) for f in results]
            assert finding_counts[0] == finding_counts[1] == finding_counts[2]

            analyzer_names = [
                {f.analyzer_name for f in findings} for findings in results
            ]
            assert analyzer_names[0] == analyzer_names[1] == analyzer_names[2]

    class TestCleanQueriesAcrossAdapters:
        @pytest.fixture
        def registry(self) -> AnalyzerRegistry:
            reg = AnalyzerRegistry()
            reg.register(SQLInjectionAnalyzer())
            return reg

        @pytest.mark.asyncio
        async def test_clean_query_no_alerts_manual(
            self, registry: AnalyzerRegistry
        ) -> None:
            clean_sql = "SELECT id, name FROM products WHERE category = 'books';"
            query = Query(sql=clean_sql)
            findings = await registry.analyze_all(query)
            assert len(findings) == 0

        @pytest.mark.asyncio
        async def test_clean_query_no_alerts_logfile(
            self, registry: AnalyzerRegistry
        ) -> None:
            clean_sql = "SELECT id, name FROM products WHERE category = 'books';"
            line = f"2026-01-14 10:00:00 UTC:127.0.0.1(1234):app@db:[1]: LOG: AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.products,{clean_sql}"
            input_source = LogFileInput.from_lines([line])
            q = await input_source.__anext__()
            findings = await registry.analyze_all(q)
            assert len(findings) == 0

        @pytest.mark.asyncio
        async def test_clean_query_no_alerts_supabase(
            self, registry: AnalyzerRegistry
        ) -> None:
            clean_sql = "SELECT id, name FROM products WHERE category = 'books';"
            log_row = {
                "event_message": f"AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.products,{clean_sql}",
                "timestamp": "2026-01-14T10:00:00Z",
            }
            input_source = SupabaseLogInput.from_log_rows([log_row])
            q = await input_source.__anext__()
            findings = await registry.analyze_all(q)
            assert len(findings) == 0
