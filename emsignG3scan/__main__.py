"""Allow ``python -m emsignG3scan`` to launch the CLI."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
