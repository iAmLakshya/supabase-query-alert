from collections import defaultdict
from collections.abc import MutableMapping
from datetime import datetime
from typing import ClassVar

from supabase_query_alert.domain import Finding, Query, Severity


class VolumeAnomalyAnalyzer:
    name: str = "volume_anomaly"

    _default_thresholds: ClassVar[dict[Severity, int]] = {
        Severity.HIGH: 100,
        Severity.MEDIUM: 50,
        Severity.LOW: 20,
    }

    def __init__(self, window_seconds: float = 60.0) -> None:
        self._window_seconds = window_seconds
        self._queries: MutableMapping[str, list[datetime]] = defaultdict(list)

    def _cleanup_expired(self, current_time: datetime) -> None:
        expired_threshold = current_time.timestamp() - self._window_seconds
        for user_id in list(self._queries.keys()):
            self._queries[user_id] = [
                ts for ts in self._queries[user_id] if ts.timestamp() > expired_threshold
            ]
            if not self._queries[user_id]:
                del self._queries[user_id]

    async def analyze(self, query: Query) -> Finding | None:
        if query.metadata is not None and query.metadata.user_id is not None:
            user_id = query.metadata.user_id
        else:
            user_id = "__anonymous__"

        if query.metadata is not None and query.metadata.timestamp is not None:
            timestamp = query.metadata.timestamp
        else:
            timestamp = datetime.now()

        self._cleanup_expired(timestamp)
        self._queries[user_id].append(timestamp)
        count = len(self._queries[user_id])

        severity: Severity | None = None
        if count > self._default_thresholds[Severity.HIGH]:
            severity = Severity.HIGH
        elif count > self._default_thresholds[Severity.MEDIUM]:
            severity = Severity.MEDIUM
        elif count > self._default_thresholds[Severity.LOW]:
            severity = Severity.LOW

        if severity is None:
            return None

        return Finding(
            analyzer_name=self.name,
            severity=severity,
            message=f"High query volume detected: {count} queries in {self._window_seconds}s window",
            details={
                "query_count": count,
                "window_seconds": self._window_seconds,
                "user_id": user_id,
            },
        )
