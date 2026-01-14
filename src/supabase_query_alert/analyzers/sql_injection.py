import re
from typing import ClassVar

from supabase_query_alert.domain import Finding, Query, Severity


class SQLInjectionAnalyzer:
    name: str = "sql_injection"

    _patterns: ClassVar[dict[Severity, list[tuple[re.Pattern[str], str]]]] = {
        Severity.HIGH: [
            (re.compile(r";\s*DROP\b", re.IGNORECASE), "stacked DROP"),
            (re.compile(r";\s*DELETE\b", re.IGNORECASE), "stacked DELETE"),
            (re.compile(r";\s*UPDATE\b", re.IGNORECASE), "stacked UPDATE"),
            (re.compile(r";\s*INSERT\b", re.IGNORECASE), "stacked INSERT"),
            (re.compile(r";\s*ALTER\b", re.IGNORECASE), "stacked ALTER"),
            (re.compile(r";\s*CREATE\b", re.IGNORECASE), "stacked CREATE"),
            (re.compile(r";\s*TRUNCATE\b", re.IGNORECASE), "stacked TRUNCATE"),
            (re.compile(r";\s*WAITFOR\b", re.IGNORECASE), "stacked WAITFOR"),
            (re.compile(r"\bUNION\s+ALL\s+SELECT\b", re.IGNORECASE), "UNION ALL SELECT"),
            (re.compile(r"\bUNION\s+SELECT\b", re.IGNORECASE), "UNION SELECT"),
        ],
        Severity.MEDIUM: [
            (re.compile(r"\bOR\s+1\s*=\s*1\b", re.IGNORECASE), "tautology OR 1=1"),
            (re.compile(r"\bOR\s+'1'\s*=\s*'1'", re.IGNORECASE), "tautology OR '1'='1'"),
            (re.compile(r'\bOR\s+"1"\s*=\s*"1"', re.IGNORECASE), "tautology OR \"1\"=\"1\""),
            (re.compile(r"\bOR\s+'[a-z]'\s*=\s*'[a-z]'", re.IGNORECASE), "tautology OR 'x'='x'"),
            (re.compile(r"--", re.IGNORECASE), "comment --"),
            (re.compile(r"/\*", re.IGNORECASE), "comment /*"),
            (re.compile(r"#", re.IGNORECASE), "comment #"),
        ],
        Severity.LOW: [
            (re.compile(r"\bSLEEP\s*\(", re.IGNORECASE), "time-based SLEEP"),
            (re.compile(r"\bWAITFOR\b", re.IGNORECASE), "time-based WAITFOR"),
            (re.compile(r"\bBENCHMARK\s*\(", re.IGNORECASE), "time-based BENCHMARK"),
            (re.compile(r"\bEXTRACTVALUE\s*\(", re.IGNORECASE), "error-based EXTRACTVALUE"),
            (re.compile(r"\bUPDATEXML\s*\(", re.IGNORECASE), "error-based UPDATEXML"),
        ],
    }

    async def analyze(self, query: Query) -> Finding | None:
        matches: list[tuple[Severity, str]] = []

        for severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            for pattern, description in self._patterns[severity]:
                if pattern.search(query.sql):
                    matches.append((severity, description))

        if not matches:
            return None

        highest_severity = max(m[0] for m in matches)
        pattern_names = [m[1] for m in matches]

        return Finding(
            analyzer_name=self.name,
            severity=highest_severity,
            message=f"SQL injection pattern detected: {pattern_names[0]}",
            details={"patterns": pattern_names},
        )
