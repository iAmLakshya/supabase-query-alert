import json
from dataclasses import asdict
from datetime import datetime
from enum import IntEnum
from typing import Any

from aiobotocore.session import get_session

from supabase_query_alert.domain import Alert


class SqsAlertOutput:
    def __init__(self, queue_url: str, region: str = "us-east-1") -> None:
        self._queue_url = queue_url
        self._region = region
        self._session = get_session()

    @property
    def name(self) -> str:
        return "sqs"

    async def send(self, alert: Alert) -> None:
        async with self._session.create_client("sqs", region_name=self._region) as client:
            await client.send_message(
                QueueUrl=self._queue_url,
                MessageBody=self._serialize_alert(alert),
            )

    def _serialize_alert(self, alert: Alert) -> str:
        return json.dumps(asdict(alert), default=self._json_default)

    @staticmethod
    def _json_default(obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, IntEnum):
            return int(obj)
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
