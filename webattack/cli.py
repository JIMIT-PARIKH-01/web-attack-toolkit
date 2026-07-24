"""
Web Attack Toolkit command line.  AUTHORIZED TARGETS ONLY.

    python -m webattack dirs   https://example.com
    python -m webattack finger https://example.com
    python -m webattack sqli   "https://example.com/item?id=1"
    python -m webattack xss    "https://example.com/search?q=test"
"""

from __future__ import annotations

import argparse
import sys

from . import dirbrute, fingerprint, sqli, xss


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webattack",
        description="Web app testing: content discovery, fingerprint, SQLi, XSS.")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("dirs", help="Directory/content brute-force.")
    d.add_argument("url")

    f = sub.add_parser("finger", help="Fingerprint the tech stack.")
    f.add_argument("url")

    s = sub.add_parser("sqli", help="Error-based SQL-injection test (URL with ?param=).")
    s.add_argument("url")

    x = sub.add_parser("xss", help="Reflected-XSS test (URL with ?param=).")
    x.add_argument("url")
    return p


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "dirs":
            print(dirbrute.brute(args.url).as_text())
        elif args.command == "finger":
            print(fingerprint.fingerprint(args.url).as_text())
        elif args.command == "sqli":
            print(sqli.test(args.url).as_text())
        elif args.command == "xss":
            print(xss.test(args.url).as_text())
    except (ValueError, ConnectionError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
