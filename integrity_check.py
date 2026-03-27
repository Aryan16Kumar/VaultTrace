#!/usr/bin/env python3
"""
integrity_check.py — LogSentry CLI Entry Point

Usage:
    python integrity_check.py logfile.log
    python integrity_check.py logfile.log --threshold 120
    python integrity_check.py logfile.log --threshold 60 --format hdfs
    python integrity_check.py logfile.log --export report.json
    python integrity_check.py logfile.log --export report.csv --timeline

Standard library only. No pip install required. Python 3.8+.
"""

import argparse
import sys
import time

from error_handler import fatal, validate_inputs
from parser import stream_log, TIMESTAMP_PATTERNS
from detector import run_detection
from reporter import print_report, export_report


def build_parser() -> argparse.ArgumentParser:
    fmt_choices = ["auto"] + list(TIMESTAMP_PATTERNS.keys())

    p = argparse.ArgumentParser(
        prog="integrity_check.py",
        description=(
            "LogSentry — Automated Log Integrity Monitor\n"
            "Detects suspicious temporal gaps in server log files\n"
            "that may indicate deliberate log tampering.\n\n"
            "Examples:\n"
            "  python integrity_check.py server.log\n"
            "  python integrity_check.py server.log --threshold 120\n"
            "  python integrity_check.py server.log --export report.json --timeline"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument(
        "logfile",
        help="Path to the log file to analyse",
    )
    p.add_argument(
        "--threshold",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Minimum gap duration in seconds to flag as suspicious (default: 60)",
    )
    p.add_argument(
        "--format",
        default="auto",
        choices=fmt_choices,
        metavar="FORMAT",
        help=(
            f"Timestamp format to use. Options: {', '.join(fmt_choices)}. "
            "Default: auto (tries each pattern in order)"
        ),
    )
    p.add_argument(
        "--export",
        metavar="FILENAME",
        default=None,
        help=(
            "Export gap report to a file. Format inferred from extension: "
            ".json for JSON, .csv for CSV. (e.g. --export report.json)"
        ),
    )
    p.add_argument(
        "--timeline",
        action="store_true",
        default=False,
        help="Print an ASCII timeline showing gap positions across the log",
    )

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # ── Validate all inputs before touching the file ───────────────────────────
    validate_inputs(args)

    # ── Stream → Detect → Report ───────────────────────────────────────────────
    t_start = time.perf_counter()

    try:
        log_stream = stream_log(args.logfile, fmt_key=args.format)
        gaps, summary = run_detection(log_stream, threshold=args.threshold)
    except PermissionError:
        fatal(f"Permission denied reading '{args.logfile}'")
    except OSError as e:
        fatal(f"Could not open log file: {e}")
    except Exception as e:
        fatal(f"Unexpected error during analysis: {e}")

    t_elapsed = time.perf_counter() - t_start

    # Retrieve skip count and detected format from parser module state
    skip_count     = getattr(stream_log, "_last_skip_count",     0)
    fmt_detected   = getattr(stream_log, "_last_detected_format", args.format)

    # ── Stdout report ──────────────────────────────────────────────────────────
    print_report(
        gaps=gaps,
        summary=summary,
        logfile=args.logfile,
        skip_count=skip_count,
        fmt_detected=fmt_detected,
        show_timeline=args.timeline,
    )

    print(f"\n  Completed in {t_elapsed:.2f}s\n")

    # ── Optional export ────────────────────────────────────────────────────────
    if args.export:
        try:
            export_report(gaps, summary, skip_count, args.export)
        except Exception as e:
            fatal(f"Export failed: {e}")

    # Exit code: 0 = clean / no gaps, 1 = gaps found (useful for shell scripting)
    return 1 if summary["total_gaps"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
