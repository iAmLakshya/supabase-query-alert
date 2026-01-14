import re
from typing import ClassVar

from supabase_query_alert.domain import Finding, Query, Severity

SENSITIVE_TABLES = r"(?:users|credentials|payments|secrets|tokens)"


class DataExfiltrationAnalyzer:
    name: str = "data_exfiltration"

    _patterns: ClassVar[dict[Severity, list[tuple[re.Pattern[str], str]]]] = {
        Severity.HIGH: [
            (re.compile(rf"SELECT\s+\*\s+FROM\s+{SENSITIVE_TABLES}\b", re.IGNORECASE), "SELECT * from sensitive table"),
            (re.compile(r"\bINTO\s+OUTFILE\b", re.IGNORECASE), "INTO OUTFILE export"),
            (re.compile(r"\bINTO\s+DUMPFILE\b", re.IGNORECASE), "INTO DUMPFILE export"),
            (re.compile(r"\bCOPY\s+\w+\s+TO\b", re.IGNORECASE), "COPY TO export"),
        ],
        Severity.MEDIUM: [
            (re.compile(r"\bpassword\b", re.IGNORECASE), "sensitive column: password"),
            (re.compile(r"\bsecret\b", re.IGNORECASE), "sensitive column: secret"),
            (re.compile(r"\btoken\b", re.IGNORECASE), "sensitive column: token"),
            (re.compile(r"\bapi_key\b", re.IGNORECASE), "sensitive column: api_key"),
            (re.compile(r"\bcredit_card\b", re.IGNORECASE), "sensitive column: credit_card"),
            (re.compile(r"\bssn\b", re.IGNORECASE), "sensitive column: ssn"),
            (re.compile(r"\bprivate_key\b", re.IGNORECASE), "sensitive column: private_key"),
        ],
        Severity.LOW: [],
    }

    _limit_pattern: ClassVar[re.Pattern[str]] = re.compile(r"\bLIMIT\s+(\d+)", re.IGNORECASE)
    _offset_pattern: ClassVar[re.Pattern[str]] = re.compile(r"\bOFFSET\s+(\d+)", re.IGNORECASE)

    async def analyze(self, query: Query) -> Finding | None:
        matches: list[tuple[Severity, str]] = []

        for severity in (Severity.HIGH, Severity.MEDIUM):
            for pattern, description in self._patterns[severity]:
                if pattern.search(query.sql):
                    matches.append((severity, description))

        limit_match = self._limit_pattern.search(query.sql)
        if limit_match and int(limit_match.group(1)) > 1000:
            matches.append((Severity.LOW, f"large LIMIT: {limit_match.group(1)}"))

        offset_match = self._offset_pattern.search(query.sql)
        if offset_match and int(offset_match.group(1)) > 0:
            matches.append((Severity.LOW, f"OFFSET pagination: {offset_match.group(1)}"))

        if not matches:
            return None

        highest_severity = max(m[0] for m in matches)
        pattern_names = [m[1] for m in matches]

        return Finding(
            analyzer_name=self.name,
            severity=highest_severity,
            message=f"Data exfiltration pattern detected: {pattern_names[0]}",
            details={"patterns": pattern_names},
        )
