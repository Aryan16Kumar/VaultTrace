"""
reporter.py — LogSentry Reporting Layer

Renders the gap list and summary into:
  - Human-readable stdout forensic report
  - Optional JSON export  (--export report.json)
  - Optional CSV export   (--export report.csv)
  - ASCII timeline        (--timeline flag)
"""

import csv
import json
import os
import sys
from datetime import datetime
from typing import List, Dict, Any, Optional

from detector import GapRecord

# ─── Colour codes (disabled automatically if not a TTY) ───────────────────────
def _supports_colour() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

COLOURS = {
    "reset":  "\033[0m"  if _supports_colour() else "",
    "bold":   "\033[1m"  if _supports_colour() else "",
    "red":    "\033[91m" if _supports_colour() else "",
    "yellow": "\033[93m" if _supports_colour() else "",
    "cyan":   "\033[96m" if _supports_colour() else "",
    "green":  "\033[92m" if _supports_colour() else "",
    "dim":    "\033[2m"  if _supports_colour() else "",
    "white":  "\033[97m" if _supports_colour() else "",
}

C = COLOURS

SEVERITY_COLOUR = {
    "HIGH":   C["red"],
    "MEDIUM": C["yellow"],
    "LOW":    C["cyan"],
}

SEVERITY_BADGE = {
    "HIGH":   f"{C['red']}{C['bold']}[ HIGH   ]{C['reset']}",
    "MEDIUM": f"{C['yellow']}{C['bold']}[ MEDIUM ]{C['reset']}",
    "LOW":    f"{C['cyan']}[ LOW    ]{C['reset']}",
}

WIDTH = 72


def _divider(char: str = "─") -> str:
    return char * WIDTH


def _header_block(logfile: str, threshold: int, fmt_detected: str) -> str:
    lines = [
        _divider("═"),
        f"{C['bold']}{C['white']}  LogSentry  |  Automated Log Integrity Monitor{C['reset']}",
        _divider("─"),
        f"  File      : {logfile}",
        f"  Threshold : {threshold}s  |  Format: {fmt_detected}",
        f"  Run at    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        _divider("═"),
    ]
    return "\n".join(lines)


def _gap_block(gap: GapRecord) -> str:
    badge = SEVERITY_BADGE[gap.severity]
    sc = SEVERITY_COLOUR[gap.severity]
    lines = [
        "",
        f"  {badge}  Gap #{gap.gap_number}  (line {gap.line_number})",
        f"  {C['dim']}Start    :{C['reset']}  {gap.start_str}",
        f"  {C['dim']}End      :{C['reset']}  {gap.end_str}",
        f"  {C['dim']}Duration :{C['reset']}  {sc}{gap.duration_str}{C['reset']}  "
        f"{C['dim']}({int(gap.duration_seconds)}s  |  {gap.duration_seconds / gap.threshold_used:.1f}x threshold){C['reset']}",
        f"  {_divider()}",
    ]
    return "\n".join(lines)


def _summary_block(summary: Dict[str, Any], skip_count: int) -> str:
    total = summary["total_gaps"]
    span = summary["log_span_seconds"]
    span_str = f"{int(span // 3600)}h {int((span % 3600) // 60)}m {int(span % 60)}s" if span >= 3600 else \
               f"{int(span // 60)}m {int(span % 60)}s" if span >= 60 else f"{int(span)}s"

    high_str   = f"{C['red']}{C['bold']}{summary['high_count']} HIGH{C['reset']}"
    medium_str = f"{C['yellow']}{summary['medium_count']} MEDIUM{C['reset']}"
    low_str    = f"{C['cyan']}{summary['low_count']} LOW{C['reset']}"

    verdict = (
        f"{C['red']}{C['bold']}TAMPERING LIKELY — immediate escalation recommended.{C['reset']}"
        if summary["high_count"] > 0 else
        f"{C['yellow']}SUSPICIOUS — review MEDIUM gaps in context.{C['reset']}"
        if summary["medium_count"] > 0 else
        f"{C['green']}CLEAN — no significant gaps detected.{C['reset']}"
        if total == 0 else
        f"{C['cyan']}LOW RISK — minor gaps only.{C['reset']}"
    )

    lines = [
        "",
        _divider("═"),
        f"{C['bold']}  SUMMARY{C['reset']}",
        _divider("─"),
        f"  Total gaps found    : {C['bold']}{total}{C['reset']}",
        f"  By severity         : {high_str}  {medium_str}  {low_str}",
        f"  Lines parsed        : {summary['total_lines']}",
        f"  Lines skipped       : {skip_count}",
        f"  Log time span       : {span_str}",
        f"  Threshold used      : {summary['threshold']}s",
        "",
        f"  Verdict  : {verdict}",
        "",
        f"  {C['dim']}Note: Gaps may include valid system restart intervals.{C['reset']}",
        f"  {C['dim']}Cross-reference with maintenance schedules before escalating.{C['reset']}",
        _divider("═"),
    ]
    return "\n".join(lines)


def _ascii_timeline(gaps: List[GapRecord], summary: Dict[str, Any], width: int = 60) -> str:
    """
    Render an ASCII timeline showing where gaps fall across the log's time span.
    Each character = (log_span / width) seconds. Gaps are marked by severity symbol.
    """
    if not gaps or summary["log_span_seconds"] == 0:
        return ""

    span = summary["log_span_seconds"]
    bar = ["."] * width

    for gap in gaps:
        offset = (gap.start - summary["first_timestamp"]).total_seconds()
        pos = int((offset / span) * (width - 1))
        pos = max(0, min(width - 1, pos))
        symbol = "H" if gap.severity == "HIGH" else "M" if gap.severity == "MEDIUM" else "L"
        bar[pos] = symbol

    timeline_str = "".join(bar)
    legend = f"  H={C['red']}HIGH{C['reset']}  M={C['yellow']}MEDIUM{C['reset']}  L={C['cyan']}LOW{C['reset']}  .=clean"

    lines = [
        "",
        _divider("─"),
        f"{C['bold']}  TIMELINE{C['reset']}  (each char ≈ {int(span / width)}s)",
        f"  |{timeline_str}|",
        f"  ^start{' ' * (width - 10)}end^",
        legend,
        _divider("─"),
    ]
    return "\n".join(lines)


def print_report(
    gaps: List[GapRecord],
    summary: Dict[str, Any],
    logfile: str,
    skip_count: int,
    fmt_detected: str,
    show_timeline: bool = False,
) -> None:
    """Print the full forensic report to stdout."""
    print(_header_block(logfile, summary["threshold"], fmt_detected))

    if not gaps:
        print(f"\n  {C['green']}{C['bold']}No gaps detected above threshold.{C['reset']}\n")
    else:
        for gap in gaps:
            print(_gap_block(gap))

    if show_timeline and gaps:
        print(_ascii_timeline(gaps, summary))

    print(_summary_block(summary, skip_count))


def export_report(
    gaps: List[GapRecord],
    summary: Dict[str, Any],
    skip_count: int,
    export_path: str,
) -> None:
    """
    Export gap report to JSON or CSV based on file extension.
    Raises ValueError for unsupported extensions.
    """
    ext = os.path.splitext(export_path)[1].lower()

    if ext == ".json":
        _export_json(gaps, summary, skip_count, export_path)
    elif ext == ".csv":
        _export_csv(gaps, export_path)
    else:
        raise ValueError(f"Unsupported export format '{ext}'. Use .json or .csv")


def _export_json(
    gaps: List[GapRecord],
    summary: Dict[str, Any],
    skip_count: int,
    path: str,
) -> None:
    payload = {
        "metadata": {
            "tool":       "LogSentry v1.0",
            "generated":  datetime.now().isoformat(),
            "threshold":  summary["threshold"],
        },
        "summary": {
            "total_gaps":    summary["total_gaps"],
            "high_count":    summary["high_count"],
            "medium_count":  summary["medium_count"],
            "low_count":     summary["low_count"],
            "total_lines":   summary["total_lines"],
            "lines_skipped": skip_count,
            "log_span_seconds": summary["log_span_seconds"],
            "first_timestamp": summary["first_timestamp"].isoformat() if summary["first_timestamp"] else None,
            "last_timestamp":  summary["last_timestamp"].isoformat()  if summary["last_timestamp"]  else None,
        },
        "gaps": [
            {
                "gap_number":       g.gap_number,
                "start":            g.start_str,
                "end":              g.end_str,
                "duration_seconds": g.duration_seconds,
                "duration_human":   g.duration_str,
                "severity":         g.severity,
                "line_number":      g.line_number,
                "multiplier":       round(g.duration_seconds / g.threshold_used, 2),
            }
            for g in gaps
        ],
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\n  {C['green']}Exported JSON report → {path}{C['reset']}")


def _export_csv(gaps: List[GapRecord], path: str) -> None:
    fieldnames = [
        "gap_number", "start", "end", "duration_seconds",
        "duration_human", "severity", "line_number", "multiplier"
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for g in gaps:
            writer.writerow({
                "gap_number":       g.gap_number,
                "start":            g.start_str,
                "end":              g.end_str,
                "duration_seconds": g.duration_seconds,
                "duration_human":   g.duration_str,
                "severity":         g.severity,
                "line_number":      g.line_number,
                "multiplier":       round(g.duration_seconds / g.threshold_used, 2),
            })
    print(f"\n  {C['green']}Exported CSV report  → {path}{C['reset']}")
