"""
parser.py — LogSentry Parsing Layer

Streams log lines one at a time (never loads full file into memory).
Extracts timestamps via pre-compiled regex patterns.
Yields (datetime, raw_line, line_number) tuples to the detection engine.
"""

import re
from datetime import datetime
from typing import Generator, Tuple, Optional

# ─── Timestamp pattern registry ────────────────────────────────────────────────
# To add a new format: add one entry here. No other code changes needed.
TIMESTAMP_PATTERNS = {
    "hdfs": {
        "regex": re.compile(r"^(\d{6}\s\d{6})"),
        "fmt":   "%y%m%d %H%M%S",
        "desc":  "HDFS format: 081109 203615",
    },
    "syslog": {
        "regex": re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"),
        "fmt":   "%b %d %H:%M:%S",
        "desc":  "Syslog format: Nov  9 20:36:15",
    },
    "apache": {
        "regex": re.compile(r"\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2})"),
        "fmt":   "%d/%b/%Y:%H:%M:%S",
        "desc":  "Apache format: [09/Nov/2008:20:36:15",
    },
    "iso8601": {
        "regex": re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"),
        "fmt":   "%Y-%m-%dT%H:%M:%S",
        "desc":  "ISO 8601 format: 2008-11-09T20:36:15",
    },
    "iso8601_space": {
        "regex": re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"),
        "fmt":   "%Y-%m-%d %H:%M:%S",
        "desc":  "ISO 8601 space format: 2008-11-09 20:36:15",
    },
}


def _detect_format(sample_lines: list) -> Optional[str]:
    """
    Auto-detect timestamp format from the first few readable lines.
    Returns the format key from TIMESTAMP_PATTERNS, or None if undetected.
    """
    for line in sample_lines:
        for fmt_key, pattern in TIMESTAMP_PATTERNS.items():
            if pattern["regex"].search(line):
                return fmt_key
    return None


def _extract_timestamp(line: str, fmt_key: str) -> Optional[datetime]:
    """
    Extract a datetime from a single log line using the given format key.
    Returns None if extraction or parsing fails — never raises.
    """
    try:
        pattern = TIMESTAMP_PATTERNS[fmt_key]
        match = pattern["regex"].search(line)
        if not match:
            return None
        raw_ts = match.group(1)
        # ISO 8601 with T separator — normalise space variant
        fmt = pattern["fmt"]
        if "T" in raw_ts and "%T" not in fmt:
            raw_ts = raw_ts.replace("T", " ")
            fmt = fmt.replace("T", " ")
        return datetime.strptime(raw_ts, fmt)
    except (ValueError, KeyError, AttributeError):
        return None


def stream_log(
    filepath: str,
    fmt_key: str = "auto",
) -> Generator[Tuple[datetime, str, int], None, None]:
    """
    Generator: open log file, stream line-by-line, yield parsed tuples.

    Yields:
        (timestamp: datetime, raw_line: str, line_number: int)

    Side effects:
        Populates .skip_count and .detected_format attributes on the generator
        object after exhaustion — caller reads these for the summary report.
    """
    skip_count = 0
    detected_fmt = fmt_key
    sample_collected = False
    sample_lines = []

    with open(filepath, "r", errors="replace") as fh:
        for line_number, line in enumerate(fh, start=1):
            line = line.rstrip("\n")

            # Auto-detect format from the first 20 non-empty lines
            if fmt_key == "auto" and not sample_collected:
                if line.strip():
                    sample_lines.append(line)
                if len(sample_lines) >= 20:
                    detected_fmt = _detect_format(sample_lines)
                    sample_collected = True
                    if detected_fmt is None:
                        # Cannot detect — yield nothing, skip counter will reflect
                        continue
                    # Re-process already-sampled lines before continuing stream
                    for sline_no, sline in enumerate(sample_lines, start=1):
                        ts = _extract_timestamp(sline, detected_fmt)
                        if ts is not None:
                            yield ts, sline, sline_no
                        else:
                            skip_count += 1
                    continue

            # If still collecting sample, defer
            if fmt_key == "auto" and not sample_collected:
                continue

            # Normal streaming path
            if not line.strip():
                continue

            ts = _extract_timestamp(line, detected_fmt)
            if ts is not None:
                yield ts, line, line_number
            else:
                skip_count += 1

    # Attach metadata to generator frame — accessed by caller after exhaustion
    stream_log._last_skip_count = skip_count
    stream_log._last_detected_format = detected_fmt if detected_fmt else "unknown"
