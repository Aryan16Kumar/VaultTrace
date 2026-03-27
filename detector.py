"""
detector.py — LogSentry Detection Engine

Consumes the parser generator one tuple at a time.
Maintains prev_timestamp state.
Computes deltas, applies threshold, classifies severity.
Returns a list of GapRecord dataclass instances + summary stats.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Tuple, Generator, Dict, Any


@dataclass
class GapRecord:
    """A single detected temporal gap event."""
    gap_number:       int
    start:            datetime
    end:              datetime
    duration_seconds: float
    severity:         str        # "LOW" | "MEDIUM" | "HIGH"
    line_number:      int        # line in the file where the gap ends
    threshold_used:   int        # threshold value active during detection

    @property
    def start_str(self) -> str:
        return self.start.strftime("%Y-%m-%d %H:%M:%S")

    @property
    def end_str(self) -> str:
        return self.end.strftime("%Y-%m-%d %H:%M:%S")

    @property
    def duration_str(self) -> str:
        secs = int(self.duration_seconds)
        if secs < 60:
            return f"{secs}s"
        elif secs < 3600:
            m, s = divmod(secs, 60)
            return f"{m}m {s}s"
        else:
            h, rem = divmod(secs, 3600)
            m, s = divmod(rem, 60)
            return f"{h}h {m}m {s}s"


def _classify_severity(delta_seconds: float, threshold: int) -> str:
    """
    Tier gaps relative to the threshold multiplier.

    LOW    → 1x  to 5x  threshold  (suspicious but potentially explainable)
    MEDIUM → 5x  to 10x threshold  (notable, warrants investigation)
    HIGH   → >10x threshold        (primary escalation signal)
    """
    multiplier = delta_seconds / threshold
    if multiplier >= 10:
        return "HIGH"
    elif multiplier >= 5:
        return "MEDIUM"
    else:
        return "LOW"


def run_detection(
    log_stream: Generator[Tuple[datetime, str, int], None, None],
    threshold: int,
) -> Tuple[List[GapRecord], Dict[str, Any]]:
    """
    Core detection loop.

    Iterates the log stream exactly once. O(1) memory — only prev_timestamp
    is kept in state between iterations.

    Returns:
        gaps:    list of GapRecord instances (may be empty)
        summary: dict with counts and metadata for the reporter
    """
    gaps: List[GapRecord] = []
    prev_dt = None
    total_lines = 0
    gap_number = 0
    first_ts = None
    last_ts = None

    for current_dt, raw_line, line_number in log_stream:
        total_lines += 1

        if first_ts is None:
            first_ts = current_dt

        last_ts = current_dt

        if prev_dt is None:
            # First valid timestamp — nothing to compare against yet
            prev_dt = current_dt
            continue

        delta = (current_dt - prev_dt).total_seconds()

        # Guard: skip negative or zero deltas
        # Negative = midnight wrap, clock skew, or non-chronological log
        # Zero     = two events in the same second — not a gap
        if delta <= 0:
            prev_dt = current_dt
            continue

        if delta > threshold:
            gap_number += 1
            severity = _classify_severity(delta, threshold)
            gaps.append(GapRecord(
                gap_number=gap_number,
                start=prev_dt,
                end=current_dt,
                duration_seconds=delta,
                severity=severity,
                line_number=line_number,
                threshold_used=threshold,
            ))

        prev_dt = current_dt

    # Build summary statistics
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for gap in gaps:
        severity_counts[gap.severity] += 1

    summary = {
        "total_gaps":       len(gaps),
        "high_count":       severity_counts["HIGH"],
        "medium_count":     severity_counts["MEDIUM"],
        "low_count":        severity_counts["LOW"],
        "total_lines":      total_lines,
        "threshold":        threshold,
        "first_timestamp":  first_ts,
        "last_timestamp":   last_ts,
        "log_span_seconds": (last_ts - first_ts).total_seconds() if first_ts and last_ts else 0,
    }

    return gaps, summary
