"""Module entrypoint for environments where console-script directories are not on PATH."""
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
