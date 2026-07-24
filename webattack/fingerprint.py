"""
Web technology fingerprinter (standard library only).

Fetches a URL and infers the tech stack from response headers, cookies, and
body signatures (server, framework, CMS, analytics). Read-only GET.
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field

# name -> compiled regex applied to the combined "headers + body" text
BODY_SIGNATURES = {
    "WordPress": re.compile(r"wp-content|wp-includes|/wp-json/", re.I),
    "Drupal": re.compile(r"Drupal\.settings|/sites/default/files", re.I),
    "Joomla": re.compile(r"/media/jui/|Joomla!", re.I),
    "Django": re.compile(r"csrfmiddlewaretoken|__admin__", re.I),
    "Laravel": re.compile(r"laravel_session|XSRF-TOKEN", re.I),
    "React": re.compile(r"data-reactroot|react\.production", re.I),
    "Vue.js": re.compile(r"data-v-[0-9a-f]{8}|__vue__", re.I),
    "Angular": re.compile(r"ng-version|ng-app", re.I),
    "jQuery": re.compile(r"jquery(?:\.min)?\.js", re.I),
    "Bootstrap": re.compile(r"bootstrap(?:\.min)?\.(?:css|js)", re.I),
    "Cloudflare": re.compile(r"cloudflare", re.I),
    "Google Analytics": re.compile(r"google-analytics\.com|gtag\(", re.I),
}
HEADER_HINTS = ("server", "x-powered-by", "x-generator", "x-aspnet-version",
                "via", "x-drupal-cache", "x-shopify-stage")


@dataclass
class FingerprintResult:
    url: str
    technologies: list = field(default_factory=list)
    header_hints: dict = field(default_factory=dict)

    def as_text(self) -> str:
        lines = [f"Fingerprint of {self.url}",
                 f"  Detected: {', '.join(self.technologies) or '(none matched)'}"]
        if self.header_hints:
            lines.append("  Header hints:")
            for k, v in self.header_hints.items():
                lines.append(f"    {k}: {v}")
        return "\n".join(lines)


def fingerprint(url: str, timeout: float = 10.0) -> FingerprintResult:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "web-attack-toolkit/1.0"})
    ctx = ssl.create_default_context()
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        body = ""
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        raise ConnectionError(f"Could not fetch {url}: {exc}") from exc

    hint_text = " ".join(f"{k}:{v}" for k, v in headers.items()) + " " + body
    techs = [name for name, rx in BODY_SIGNATURES.items() if rx.search(hint_text)]
    hints = {h: headers[h] for h in HEADER_HINTS if h in headers}
    # a Set-Cookie like laravel_session / PHPSESSID also hints the stack
    cookie = headers.get("set-cookie", "")
    if "PHPSESSID" in cookie and "PHP" not in " ".join(techs):
        techs.append("PHP")
    return FingerprintResult(url=url, technologies=techs, header_hints=hints)
