"""Backwards-compatible source-checkout entry point."""

from cybernest.main import main


if __name__ == "__main__":
    raise SystemExit(main())
