"""Entry point:  python -m webattack <dirs|finger|sqli|xss> ..."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
