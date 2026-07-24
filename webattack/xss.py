"""
Reflected-XSS scanner (standard library only).

Injects a unique marker payload into each query parameter and reports the ones
reflected back UNENCODED (a reflected-XSS indicator).

AUTHORIZED TARGETS ONLY.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

_MARKER = "xSs7Q2Zr"
# distinctive payloads; if any comes back verbatim, HTML output isn't encoding it
PAYLOADS = [f"<{_MARKER}>", f"\"{_MARKER}\"", f"'{_MARKER}'", f"{_MARKER}<img>"]


@dataclass
class XSSResult:
    url: str
    tested_params: list = field(default_factory=list)
    findings: list = field(default_factory=list)     # (param, payload)

    def as_text(self) -> str:
        lines = [f"Reflected-XSS test: {self.url}",
                 f"  Parameters tested: {', '.join(self.tested_params) or '(none)'}"]
        if self.findings:
            lines.append("  REFLECTED UNENCODED (possible XSS):")
            for param, payload in self.findings:
                lines.append(f"    ! param '{param}' reflects {payload!r} verbatim")
        else:
            lines.append("  No unencoded reflections detected.")
        return "\n".join(lines)


def _request(url: str, timeout: float) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "web-attack-toolkit/1.0"})
    try:
        return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return (exc.read().decode("utf-8", "replace") if exc.fp else "")
    except (urllib.error.URLError, OSError):
        return ""


def test(url: str, timeout: float = 10.0) -> XSSResult:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parts = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
    result = XSSResult(url=url, tested_params=list(params))
    if not params:
        return result

    for param in params:
        for payload in PAYLOADS:
            mutated = dict(params)
            mutated[param] = [payload]
            q = urllib.parse.urlencode(mutated, doseq=True)
            test_url = urllib.parse.urlunsplit(parts._replace(query=q))
            body = _request(test_url, timeout)
            if payload in body:              # exact, unencoded reflection
                result.findings.append((param, payload))
                break
    return result
