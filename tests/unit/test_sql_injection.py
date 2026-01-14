import pytest

from supabase_query_alert.analyzers import QueryAnalyzer
from supabase_query_alert.analyzers.sql_injection import SQLInjectionAnalyzer
from supabase_query_alert.domain import Query, Severity


class TestSQLInjectionAnalyzerProtocol:
    def test_implements_query_analyzer_protocol(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        assert isinstance(analyzer, QueryAnalyzer)

    def test_name_property_returns_sql_injection(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        assert analyzer.name == "sql_injection"


class TestCleanQueries:
    @pytest.mark.asyncio
    async def test_simple_select_returns_none(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT id, name FROM users WHERE id = $1")
        result = await analyzer.analyze(query)
        assert result is None

    @pytest.mark.asyncio
    async def test_parameterized_query_returns_none(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="INSERT INTO logs (message) VALUES ($1)")
        result = await analyzer.analyze(query)
        assert result is None

    @pytest.mark.asyncio
    async def test_complex_join_returns_none(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id")
        result = await analyzer.analyze(query)
        assert result is None


class TestHighSeverityStackedQueries:
    @pytest.mark.asyncio
    async def test_drop_table_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT * FROM users; DROP TABLE users")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH
        assert result.analyzer_name == "sql_injection"

    @pytest.mark.asyncio
    async def test_delete_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT 1; DELETE FROM users")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_update_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT 1; UPDATE users SET admin=true")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_insert_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT 1; INSERT INTO admins VALUES (1)")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_alter_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT 1; ALTER TABLE users ADD admin BOOLEAN")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_create_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT 1; CREATE TABLE backdoor (id INT)")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_truncate_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT 1; TRUNCATE users")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH


class TestHighSeverityUnionAttacks:
    @pytest.mark.asyncio
    async def test_union_select_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT name FROM users WHERE id=1 UNION SELECT password FROM credentials")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_union_all_select_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT id FROM products UNION ALL SELECT credit_card FROM payments")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH


class TestMediumSeverityTautology:
    @pytest.mark.asyncio
    async def test_or_1_equals_1_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT * FROM users WHERE username='admin' OR 1=1")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_or_single_quote_tautology_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT * FROM users WHERE id=1 OR '1'='1'")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_or_double_quote_tautology_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql='SELECT * FROM users WHERE id=1 OR "1"="1"')
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_or_string_tautology_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT * FROM users WHERE id=1 OR 'a'='a'")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM


class TestMediumSeverityCommentInjection:
    @pytest.mark.asyncio
    async def test_double_dash_comment_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT * FROM users WHERE id=1--")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_block_comment_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT * FROM users WHERE id=1/*")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_mysql_hash_comment_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT * FROM users WHERE id=1#")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM


class TestLowSeverityTimeBasedProbes:
    @pytest.mark.asyncio
    async def test_sleep_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT * FROM users WHERE id=1 AND SLEEP(5)")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_waitfor_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT * FROM users; WAITFOR DELAY '0:0:5'")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_benchmark_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT * FROM users WHERE id=1 AND BENCHMARK(10000000,SHA1('test'))")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.LOW


class TestLowSeverityErrorBasedProbes:
    @pytest.mark.asyncio
    async def test_extractvalue_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT EXTRACTVALUE(1, CONCAT(0x7e, (SELECT password FROM users)))")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_updatexml_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT UPDATEXML(1, CONCAT(0x7e, version()), 1)")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.LOW


class TestCaseInsensitivity:
    @pytest.mark.asyncio
    async def test_lowercase_union_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="select * from users union select * from passwords")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_mixed_case_drop_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT 1; dRoP TABLE users")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_mixed_case_sleep_detected(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT * FROM users WHERE SLeEp(5)")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.LOW


class TestMultipleMatches:
    @pytest.mark.asyncio
    async def test_multiple_patterns_returns_highest_severity(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT * FROM users WHERE 1=1 OR 'a'='a'; DROP TABLE users")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_multiple_patterns_includes_all_in_details(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT * FROM users WHERE id=1 OR 1=1--")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.details is not None
        assert "patterns" in result.details
        assert len(result.details["patterns"]) >= 2

    @pytest.mark.asyncio
    async def test_high_and_low_severity_returns_high(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT * FROM users WHERE SLEEP(5); DROP TABLE users")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH


class TestFindingDetails:
    @pytest.mark.asyncio
    async def test_finding_has_descriptive_message(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT * FROM users; DROP TABLE users")
        result = await analyzer.analyze(query)
        assert result is not None
        assert "sql injection" in result.message.lower() or "injection" in result.message.lower()

    @pytest.mark.asyncio
    async def test_finding_details_contains_patterns_list(self) -> None:
        analyzer = SQLInjectionAnalyzer()
        query = Query(sql="SELECT * FROM users; DROP TABLE users")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.details is not None
        assert "patterns" in result.details
        assert isinstance(result.details["patterns"], list)
