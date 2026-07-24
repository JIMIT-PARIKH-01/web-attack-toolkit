"""
Error-based SQL-injection tester (standard library only).

Injects classic payloads into a URL's query parameters and looks for database
error signatures in the response. A lightweight detector -- not an exploiter.

AUTHORIZED TARGETS ONLY. Testing sites without permission may be illegal.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

PAYLOADS = ["'", "\"", "')", "';", "' OR '1'='1", "1 OR 1=1", "' AND '1'='2"]

DB_ERRORS = re.compile(
    r"(SQL syntax|mysql_fetch|mysqli?_|ORA-\d{5}|PostgreSQL.*ERROR|"
    r"SQLServer|ODBC .*SQL|SQLite/JDBC|Warning.*\bpg_|unclosed quotation mark|"
    r"quoted string not properly terminated|you have an error in your sql syntax)",
    re.IGNORECASE)


@dataclass
class SQLiResult:
    url: str
    tested_params: list = field(default_factory=list)
    findings: list = field(default_factory=list)     # (param, payload, signature)

    def as_text(self) -> str:
        lines = [f"SQLi test: {self.url}",
                 f"  Parameters tested: {', '.join(self.tested_params) or '(none)'}"]
        if self.findings:
            lines.append("  LIKELY INJECTABLE:")
            for param, payload, sig in self.findings:
                lines.append(f"    ! param '{param}' with payload {payload!r} -> DB error: {sig}")
        else:
            lines.append("  No error-based SQLi signatures detected.")
        return "\n".join(lines)


def _request(url: str, timeout: float) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "web-attack-toolkit/1.0"})
    try:
        return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return (exc.read().decode("utf-8", "replace") if exc.fp else "")
    except (urllib.error.URLError, OSError):
        return ""


def test(url: str, timeout: float = 10.0) -> SQLiResult:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parts = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
    result = SQLiResult(url=url, tested_params=list(params))
    if not params:
        return result

    for param in params:
        for payload in PAYLOADS:
            mutated = dict(params)
            mutated[param] = [params[param][0] + payload]
            q = urllib.parse.urlencode(mutated, doseq=True)
            test_url = urllib.parse.urlunsplit(parts._replace(query=q))
            body = _request(test_url, timeout)
            m = DB_ERRORS.search(body)
            if m:
                result.findings.append((param, payload, m.group(0)))
                break       # one confirmation per param is enough
    return result
