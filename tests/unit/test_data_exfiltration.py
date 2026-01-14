import pytest

from supabase_query_alert.analyzers import QueryAnalyzer
from supabase_query_alert.analyzers.data_exfiltration import DataExfiltrationAnalyzer
from supabase_query_alert.domain import Query, Severity


class TestDataExfiltrationAnalyzerProtocol:
    def test_implements_query_analyzer_protocol(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        assert isinstance(analyzer, QueryAnalyzer)

    def test_name_property_returns_data_exfiltration(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        assert analyzer.name == "data_exfiltration"


class TestCleanQueries:
    @pytest.mark.asyncio
    async def test_simple_select_with_where_returns_none(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT id, name FROM products WHERE id = $1")
        result = await analyzer.analyze(query)
        assert result is None

    @pytest.mark.asyncio
    async def test_insert_query_returns_none(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="INSERT INTO logs (message) VALUES ($1)")
        result = await analyzer.analyze(query)
        assert result is None

    @pytest.mark.asyncio
    async def test_update_query_returns_none(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="UPDATE products SET price = $1 WHERE id = $2")
        result = await analyzer.analyze(query)
        assert result is None

    @pytest.mark.asyncio
    async def test_small_limit_returns_none(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT name FROM products LIMIT 100")
        result = await analyzer.analyze(query)
        assert result is None


class TestHighSeveritySelectStar:
    @pytest.mark.asyncio
    async def test_select_star_from_users_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT * FROM users")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH
        assert result.analyzer_name == "data_exfiltration"

    @pytest.mark.asyncio
    async def test_select_star_from_credentials_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT * FROM credentials")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_select_star_from_payments_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT * FROM payments")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_select_star_from_secrets_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT * FROM secrets")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_select_star_from_tokens_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT * FROM tokens")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH


class TestHighSeverityBulkExport:
    @pytest.mark.asyncio
    async def test_into_outfile_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT * FROM users INTO OUTFILE '/tmp/users.csv'")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_into_dumpfile_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT password FROM users INTO DUMPFILE '/tmp/dump'")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_copy_to_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="COPY users TO '/tmp/users.csv'")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH


class TestMediumSeveritySensitiveColumns:
    @pytest.mark.asyncio
    async def test_password_column_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT email, password FROM users WHERE id = 1")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_secret_column_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT secret FROM config WHERE id = 1")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_token_column_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT token FROM sessions WHERE user_id = 1")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_api_key_column_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT api_key FROM integrations WHERE id = 1")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_credit_card_column_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT credit_card FROM payments WHERE user_id = 1")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_ssn_column_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT ssn FROM employees WHERE id = 1")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_private_key_column_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT private_key FROM certificates WHERE id = 1")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM


class TestLowSeverityLargeLimit:
    @pytest.mark.asyncio
    async def test_limit_over_1000_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT name FROM products LIMIT 5000")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_limit_exactly_1001_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT id FROM orders LIMIT 1001")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_limit_1000_not_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT name FROM products LIMIT 1000")
        result = await analyzer.analyze(query)
        assert result is None


class TestLowSeverityOffset:
    @pytest.mark.asyncio
    async def test_offset_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT name FROM products LIMIT 100 OFFSET 500")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_offset_zero_not_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT name FROM products LIMIT 100 OFFSET 0")
        result = await analyzer.analyze(query)
        assert result is None


class TestCaseInsensitivity:
    @pytest.mark.asyncio
    async def test_lowercase_select_star_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="select * from users")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_mixed_case_password_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT PassWord FROM users WHERE id = 1")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_mixed_case_limit_detected(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT name FROM products LiMiT 5000")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.LOW


class TestMultipleMatches:
    @pytest.mark.asyncio
    async def test_multiple_patterns_returns_highest_severity(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT * FROM users LIMIT 5000")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_multiple_patterns_includes_all_in_details(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT password FROM users LIMIT 5000 OFFSET 100")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.details is not None
        assert "patterns" in result.details
        assert len(result.details["patterns"]) >= 2


class TestFindingDetails:
    @pytest.mark.asyncio
    async def test_finding_has_descriptive_message(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT * FROM users")
        result = await analyzer.analyze(query)
        assert result is not None
        assert "exfiltration" in result.message.lower() or "data" in result.message.lower()

    @pytest.mark.asyncio
    async def test_finding_details_contains_patterns_list(self) -> None:
        analyzer = DataExfiltrationAnalyzer()
        query = Query(sql="SELECT * FROM users")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.details is not None
        assert "patterns" in result.details
        assert isinstance(result.details["patterns"], list)
