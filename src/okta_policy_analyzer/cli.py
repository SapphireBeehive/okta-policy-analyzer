"""Command-line entry point (placeholder; the full CLI lands with the analyzer)."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args and args[0] in {"-V", "--version"}:
        from . import __version__

        print(__version__)
        return 0
    print("okta-policy-analyzer: analyzer not yet available in this build", file=sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
