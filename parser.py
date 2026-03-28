"""
parser.py — LogSentry Parsing Layer

Streams log lines one at a time via a generator (O(1) memory, FR-06).
Extracts timestamps via pre-compiled regex (FR-07).
Skips malformed lines gracefully, increments skip counter (FR-08).
Yields (datetime, raw_line, line_number) tuples (FR-09).
TIMESTAMP_PATTERNS dict enables multi-format extensibility (FR-10).

Performance note:
    datetime.strptime calls locale.getlocale() on every invocation, adding
    ~3s overhead on 500k lines. Fast-path manual parsers are used for all
    common formats to hit the M-01 (<10s on 500k lines) success metric.
"""

import re
from datetime import datetime
from typing import Generator, Tuple, Optional


# ─── Fast-path manual parsers (zero locale overhead) ──────────────────────────

def _parse_hdfs(raw: str) -> datetime:
    # "081109 203615" → YY MM DD  HH MM SS
    return datetime(
        2000 + int(raw[0:2]), int(raw[2:4]),  int(raw[4:6]),
        int(raw[7:9]),        int(raw[9:11]), int(raw[11:13]),
    )

def _parse_iso8601(raw: str) -> datetime:
    # "2008-11-09T20:36:15" or "2008-11-09 20:36:15"
    return datetime(
        int(raw[0:4]),  int(raw[5:7]),  int(raw[8:10]),
        int(raw[11:13]),int(raw[14:16]),int(raw[17:19]),
    )

_MONTH_MAP = {
    "Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
    "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12,
}

def _parse_syslog(raw: str) -> datetime:
    # "Nov  9 20:36:15"
    parts = raw.split()
    month = _MONTH_MAP.get(parts[0], 1)
    day   = int(parts[1])
    h, m, s = int(parts[2][0:2]), int(parts[2][3:5]), int(parts[2][6:8])
    return datetime(1900, month, day, h, m, s)

def _parse_apache(raw: str) -> datetime:
    # "09/Nov/2008:20:36:15"
    day   = int(raw[0:2])
    month = _MONTH_MAP.get(raw[3:6], 1)
    year  = int(raw[7:11])
    h, m, s = int(raw[12:14]), int(raw[15:17]), int(raw[18:20])
    return datetime(year, month, day, h, m, s)


# ─── Format registry ──────────────────────────────────────────────────────────
# To add a new format: add one entry here. No other code changes needed. (FR-10)

TIMESTAMP_PATTERNS = {
    "hdfs": {
        "regex":      re.compile(r"^(\d{6}\s\d{6})"),
        "fast_parse": _parse_hdfs,
        "desc":       "HDFS: 081109 203615",
    },
    "iso8601": {
        "regex":      re.compile(r"(\d{4}-\d{2}-\d{2}[T]\d{2}:\d{2}:\d{2})"),
        "fast_parse": _parse_iso8601,
        "desc":       "ISO 8601: 2008-11-09T20:36:15",
    },
    "iso8601_space": {
        "regex":      re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"),
        "fast_parse": _parse_iso8601,
        "desc":       "ISO 8601 space: 2008-11-09 20:36:15",
    },
    "syslog": {
        "regex":      re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"),
        "fast_parse": _parse_syslog,
        "desc":       "Syslog: Nov  9 20:36:15",
    },
    "apache": {
        "regex":      re.compile(r"\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2})"),
        "fast_parse": _parse_apache,
        "desc":       "Apache: [09/Nov/2008:20:36:15",
    },
}


# ─── Internal helpers ──────────────────────────────────────────────────────────

def _detect_format(lines: list) -> Optional[str]:
    """Try each pattern against sample lines; return first matching key."""
    for line in lines:
        for key, pat in TIMESTAMP_PATTERNS.items():
            if pat["regex"].search(line):
                return key
    return None


def _extract_timestamp(line: str, fmt_key: str) -> Optional[datetime]:
    """
    Extract a datetime from one log line using the fast-path parser.
    Never raises — returns None on any failure (FR-08).
    """
    try:
        pat   = TIMESTAMP_PATTERNS[fmt_key]
        match = pat["regex"].search(line)
        if not match:
            return None
        return pat["fast_parse"](match.group(1))
    except (ValueError, KeyError, AttributeError, IndexError):
        return None


# ─── Module-level state (written after each run, read by caller) ───────────────
_last_skip_count      = 0
_last_detected_format = "unknown"


# ─── Public API ───────────────────────────────────────────────────────────────

def stream_log(
    filepath: str,
    fmt_key: str = "auto",
) -> Generator[Tuple[datetime, str, int], None, None]:
    """
    Generator: stream log file line-by-line.
    Yields (datetime, raw_line, line_number).
    Memory: O(1) regardless of file size (FR-06).
    """
    global _last_skip_count, _last_detected_format

    skip_count   = 0
    detected_fmt = fmt_key

    # ── Auto-detect: sample first 20 non-empty lines, then single-pass stream ──
    if fmt_key == "auto":
        sample_buf = []   # (line_text, line_number)

        with open(filepath, "r", errors="replace") as fh:
            for line_number, line in enumerate(fh, start=1):
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                sample_buf.append((line, line_number))
                if len(sample_buf) >= 20:
                    break

        detected_fmt = _detect_format([l for l, _ in sample_buf])

        if detected_fmt is None:
            _last_skip_count      = 0
            _last_detected_format = "unknown"
            return

        # Replay buffered sample
        for line, line_number in sample_buf:
            ts = _extract_timestamp(line, detected_fmt)
            if ts is not None:
                yield ts, line, line_number
            else:
                skip_count += 1

        # Stream the remainder (skip already-buffered line numbers)
        max_buf_lineno = sample_buf[-1][1] if sample_buf else 0
        with open(filepath, "r", errors="replace") as fh:
            for line_number, line in enumerate(fh, start=1):
                if line_number <= max_buf_lineno:
                    continue
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                ts = _extract_timestamp(line, detected_fmt)
                if ts is not None:
                    yield ts, line, line_number
                else:
                    skip_count += 1

    # ── Known format: single pass ──────────────────────────────────────────────
    else:
        detected_fmt = fmt_key
        with open(filepath, "r", errors="replace") as fh:
            for line_number, line in enumerate(fh, start=1):
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                ts = _extract_timestamp(line, detected_fmt)
                if ts is not None:
                    yield ts, line, line_number
                else:
                    skip_count += 1

    _last_skip_count      = skip_count
    _last_detected_format = detected_fmt