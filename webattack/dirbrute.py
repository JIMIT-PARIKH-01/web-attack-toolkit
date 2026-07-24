"""
Directory / content brute-forcer (standard library only).

Requests a wordlist of paths against a base URL and reports those that exist
(non-404). Concurrent GETs. Authorized targets only.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

COMMON_PATHS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "dashboard",
    "robots.txt", "sitemap.xml", ".git/", ".git/config", ".env", ".htaccess",
    "backup", "backup.zip", "backup.sql", "config.php", "config.php.bak",
    "phpinfo.php", "info.php", "test", "test.php", "uploads", "upload",
    "api", "api/v1", "server-status", "server-info", "console", "shell.php",
    "old", "tmp", "temp", "dev", "staging", "private", "secret", "db.sql",
    "readme.md", "license.txt", "CHANGELOG.md", "debug", "phpmyadmin",
]


@dataclass
class DirResult:
    base: str
    found: list = field(default_factory=list)      # (path, status, length)

    def as_text(self) -> str:
        lines = [f"Content discovery on {self.base}",
                 f"  {len(self.found)} path(s) responded (non-404):"]
        for path, status, length in sorted(self.found):
            lines.append(f"    [{status}] {path:<24} ({length} bytes)")
        if not self.found:
            lines.append("    (nothing found)")
        return "\n".join(lines)


def _probe(base: str, path: str, timeout: float):
    url = base.rstrip("/") + "/" + path.lstrip("/")
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "web-attack-toolkit/1.0"})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return path, resp.status, len(resp.read())
    except urllib.error.HTTPError as exc:
        return (path, exc.code, 0) if exc.code != 404 else None
    except (urllib.error.URLError, OSError):
        return None


def brute(base: str, paths=None, timeout: float = 8.0, workers: int = 20) -> DirResult:
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    paths = paths if paths is not None else COMMON_PATHS
    result = DirResult(base=base)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for hit in pool.map(lambda p: _probe(base, p, timeout), paths):
            if hit:
                result.found.append(hit)
    return result
