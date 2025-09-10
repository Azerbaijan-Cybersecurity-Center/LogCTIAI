"""CLI package for running scans.

Exports legacy helpers used by tests and external callers by re-exporting
from the historical single-file CLI module `src/cli.py`.
"""

from ..cli import (  # type: ignore[F401]
    process_log,
    summarize_and_cti,
    _print_summary,
    _preview_records,
)

__all__ = [
    "process_log",
    "summarize_and_cti",
    "_print_summary",
    "_preview_records",
]
