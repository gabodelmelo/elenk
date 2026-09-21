"""Lets you run `python -m elenk ...` as a shortcut for `python -m elenk.cli ...`,
useful when the `elenk` executable isn't on PATH (see README)."""

from elenk.cli import main

if __name__ == "__main__":
    main()
