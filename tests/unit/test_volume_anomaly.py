from datetime import datetime, timedelta

import pytest

from supabase_query_alert.analyzers import QueryAnalyzer
from supabase_query_alert.analyzers.volume_anomaly import VolumeAnomalyAnalyzer
from supabase_query_alert.domain import Query, QueryMetadata, Severity


class TestVolumeAnomalyAnalyzerProtocol:
    def test_implements_query_analyzer_protocol(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        assert isinstance(analyzer, QueryAnalyzer)

    def test_name_property_returns_volume_anomaly(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        assert analyzer.name == "volume_anomaly"


class TestCleanQueries:
    @pytest.mark.asyncio
    async def test_single_query_returns_none(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        query = Query(
            sql="SELECT * FROM users",
            metadata=QueryMetadata(user_id="user1", timestamp=datetime.now()),
        )
        result = await analyzer.analyze(query)
        assert result is None

    @pytest.mark.asyncio
    async def test_twenty_queries_returns_none(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        now = datetime.now()
        for i in range(20):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=now),
            )
            result = await analyzer.analyze(query)
        assert result is None


class TestLowSeverityThreshold:
    @pytest.mark.asyncio
    async def test_twenty_one_queries_returns_low(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        now = datetime.now()
        for i in range(20):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=now),
            )
            await analyzer.analyze(query)
        query = Query(
            sql="SELECT * FROM users",
            metadata=QueryMetadata(user_id="user1", timestamp=now),
        )
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.LOW
        assert result.analyzer_name == "volume_anomaly"

    @pytest.mark.asyncio
    async def test_fifty_queries_returns_low(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        now = datetime.now()
        for i in range(49):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=now),
            )
            await analyzer.analyze(query)
        query = Query(
            sql="SELECT * FROM users",
            metadata=QueryMetadata(user_id="user1", timestamp=now),
        )
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.LOW


class TestMediumSeverityThreshold:
    @pytest.mark.asyncio
    async def test_fifty_one_queries_returns_medium(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        now = datetime.now()
        for i in range(50):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=now),
            )
            await analyzer.analyze(query)
        query = Query(
            sql="SELECT * FROM users",
            metadata=QueryMetadata(user_id="user1", timestamp=now),
        )
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_hundred_queries_returns_medium(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        now = datetime.now()
        for i in range(99):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=now),
            )
            await analyzer.analyze(query)
        query = Query(
            sql="SELECT * FROM users",
            metadata=QueryMetadata(user_id="user1", timestamp=now),
        )
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM


class TestHighSeverityThreshold:
    @pytest.mark.asyncio
    async def test_hundred_one_queries_returns_high(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        now = datetime.now()
        for i in range(100):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=now),
            )
            await analyzer.analyze(query)
        query = Query(
            sql="SELECT * FROM users",
            metadata=QueryMetadata(user_id="user1", timestamp=now),
        )
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH


class TestBoundaryConditions:
    @pytest.mark.asyncio
    async def test_exactly_twenty_queries_returns_none(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        now = datetime.now()
        result = None
        for i in range(20):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=now),
            )
            result = await analyzer.analyze(query)
        assert result is None

    @pytest.mark.asyncio
    async def test_exactly_twenty_one_queries_returns_low(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        now = datetime.now()
        for i in range(21):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=now),
            )
            result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_exactly_fifty_queries_returns_low(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        now = datetime.now()
        for i in range(50):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=now),
            )
            result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_exactly_fifty_one_queries_returns_medium(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        now = datetime.now()
        for i in range(51):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=now),
            )
            result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_exactly_hundred_queries_returns_medium(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        now = datetime.now()
        for i in range(100):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=now),
            )
            result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_exactly_hundred_one_queries_returns_high(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        now = datetime.now()
        for i in range(101):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=now),
            )
            result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.HIGH


class TestUserTracking:
    @pytest.mark.asyncio
    async def test_different_users_tracked_independently(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        now = datetime.now()
        for i in range(15):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=now),
            )
            await analyzer.analyze(query)
        for i in range(15):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user2", timestamp=now),
            )
            await analyzer.analyze(query)
        query1 = Query(
            sql="SELECT * FROM users",
            metadata=QueryMetadata(user_id="user1", timestamp=now),
        )
        query2 = Query(
            sql="SELECT * FROM users",
            metadata=QueryMetadata(user_id="user2", timestamp=now),
        )
        result1 = await analyzer.analyze(query1)
        result2 = await analyzer.analyze(query2)
        assert result1 is None
        assert result2 is None


class TestAnonymousQueries:
    @pytest.mark.asyncio
    async def test_queries_without_user_id_tracked_under_anonymous(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        now = datetime.now()
        for i in range(20):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(timestamp=now),
            )
            await analyzer.analyze(query)
        query = Query(
            sql="SELECT * FROM users",
            metadata=QueryMetadata(timestamp=now),
        )
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_queries_without_metadata_tracked_under_anonymous(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        for i in range(20):
            query = Query(sql="SELECT * FROM users")
            await analyzer.analyze(query)
        query = Query(sql="SELECT * FROM users")
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.LOW


class TestWindowExpiration:
    @pytest.mark.asyncio
    async def test_old_queries_dont_count(self) -> None:
        analyzer = VolumeAnomalyAnalyzer(window_seconds=60.0)
        now = datetime.now()
        old_time = now - timedelta(seconds=120)
        for i in range(30):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=old_time),
            )
            await analyzer.analyze(query)
        query = Query(
            sql="SELECT * FROM users",
            metadata=QueryMetadata(user_id="user1", timestamp=now),
        )
        result = await analyzer.analyze(query)
        assert result is None

    @pytest.mark.asyncio
    async def test_queries_within_window_count(self) -> None:
        analyzer = VolumeAnomalyAnalyzer(window_seconds=60.0)
        now = datetime.now()
        recent_time = now - timedelta(seconds=30)
        for i in range(20):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=recent_time),
            )
            await analyzer.analyze(query)
        query = Query(
            sql="SELECT * FROM users",
            metadata=QueryMetadata(user_id="user1", timestamp=now),
        )
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_custom_window_size(self) -> None:
        analyzer = VolumeAnomalyAnalyzer(window_seconds=10.0)
        now = datetime.now()
        for i in range(20):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=now),
            )
            await analyzer.analyze(query)
        query = Query(
            sql="SELECT * FROM users",
            metadata=QueryMetadata(user_id="user1", timestamp=now),
        )
        result = await analyzer.analyze(query)
        assert result is not None
        assert result.severity == Severity.LOW


class TestFindingDetails:
    @pytest.mark.asyncio
    async def test_finding_includes_query_count(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        now = datetime.now()
        for i in range(21):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=now),
            )
            result = await analyzer.analyze(query)
        assert result is not None
        assert result.details is not None
        assert "query_count" in result.details
        assert result.details["query_count"] == 21

    @pytest.mark.asyncio
    async def test_finding_includes_window_seconds(self) -> None:
        analyzer = VolumeAnomalyAnalyzer(window_seconds=120.0)
        now = datetime.now()
        for i in range(21):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=now),
            )
            result = await analyzer.analyze(query)
        assert result is not None
        assert result.details is not None
        assert "window_seconds" in result.details
        assert result.details["window_seconds"] == 120.0

    @pytest.mark.asyncio
    async def test_finding_has_descriptive_message(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        now = datetime.now()
        for i in range(21):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=now),
            )
            result = await analyzer.analyze(query)
        assert result is not None
        assert "volume" in result.message.lower() or "queries" in result.message.lower()

    @pytest.mark.asyncio
    async def test_finding_includes_user_id(self) -> None:
        analyzer = VolumeAnomalyAnalyzer()
        now = datetime.now()
        for i in range(21):
            query = Query(
                sql="SELECT * FROM users",
                metadata=QueryMetadata(user_id="user1", timestamp=now),
            )
            result = await analyzer.analyze(query)
        assert result is not None
        assert result.details is not None
        assert "user_id" in result.details
        assert result.details["user_id"] == "user1"
