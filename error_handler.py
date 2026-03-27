"""
error_handler.py — LogSentry Error Handler

Centralised exception handling strategy.
All user-facing errors go through here — no raw Python tracebacks ever reach stdout.
"""

import sys


def fatal(message: str, exit_code: int = 1) -> None:
    """
    Print a clean error message and exit.
    Used for unrecoverable conditions (file not found, invalid args, etc.)
    Never shows a Python traceback to the user.
    """
    print(f"\n  [ERROR] {message}\n", file=sys.stderr)
    sys.exit(exit_code)


def warn(message: str) -> None:
    """Non-fatal warning — prints to stderr, execution continues."""
    print(f"  [WARN]  {message}", file=sys.stderr)


def validate_inputs(args) -> None:
    """
    Validate all CLI arguments before any file I/O begins.
    Calls fatal() on the first validation failure — fast exit, clean message.
    """
    import os

    # File existence
    if not os.path.isfile(args.logfile):
        fatal(f"File not found: '{args.logfile}'\n  Check the path and try again.")

    # File readability
    if not os.access(args.logfile, os.R_OK):
        fatal(f"Permission denied: cannot read '{args.logfile}'")

    # File non-empty check
    if os.path.getsize(args.logfile) == 0:
        fatal("The log file is empty. Nothing to analyse.")

    # Threshold bounds
    if args.threshold <= 0:
        fatal("--threshold must be a positive integer (e.g. --threshold 60)")

    if args.threshold > 86400:
        warn("--threshold is set above 24 hours. This will only flag very large gaps.")

    # Export extension
    if args.export:
        ext = os.path.splitext(args.export)[1].lower()
        if ext not in (".json", ".csv"):
            fatal(f"Unsupported export format '{ext}'. Use .json or .csv")

    # Format key
    from parser import TIMESTAMP_PATTERNS
    valid_formats = list(TIMESTAMP_PATTERNS.keys()) + ["auto"]
    if args.format not in valid_formats:
        fatal(
            f"Unknown format '{args.format}'.\n"
            f"  Valid options: {', '.join(valid_formats)}"
        )
