from supabase_query_alert.domain import Alert


class ConsoleAlertOutput:
    """Console output adapter for alerts."""

    def __init__(self, prefix: str = "[ALERT]") -> None:
        self._prefix = prefix

    @property
    def name(self) -> str:
        return "console"

    async def send(self, alert: Alert) -> None:
        sql_preview = alert.query.sql[:50]
        if len(alert.query.sql) > 50:
            sql_preview += "..."

        finding_count = len(alert.findings)
        print(f"{self._prefix} [{alert.severity.name}] {sql_preview} - {finding_count} finding(s)")

        for finding in alert.findings:
            print(f"  - {finding.analyzer_name}: {finding.message}")
