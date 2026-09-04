"""Allow ``python -m cryptolab`` to invoke the CLI."""

from __future__ import annotations

from cryptolab.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
