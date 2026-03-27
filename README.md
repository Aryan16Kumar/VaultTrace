# LogSentry — Automated Log Integrity Monitor

> First-responder triage tool for log tampering detection.  
> Detects suspicious temporal gaps in server logs that indicate deliberate evidence destruction.

---

## Quick Start

```bash
# Minimal — auto-detects format, 60s threshold
python integrity_check.py server.log

# Custom threshold + ASCII timeline
python integrity_check.py server.log --threshold 120 --timeline

# Export machine-readable report
python integrity_check.py server.log --export report.json
python integrity_check.py server.log --export report.csv
```

**Requirements:** Python 3.8+, standard library only. No pip install.

---

## How It Works

When a hacker breaches a server, one of their first actions is deleting log entries
that reveal their activity. Removing entries from a chronological log creates a
**temporal gap** — a jump in timestamps where events should exist but don't.

LogSentry reads the log file **line-by-line** (streaming, O(1) memory), extracts
timestamps, and flags any gap exceeding the configured threshold.

```
Normal:    20:36:15 → 20:36:17 → 20:36:18   (2s delta — OK)
Tampered:  20:36:17 → 20:45:00              (523s delta — GAP DETECTED)
```

---

## Sample Output

```
════════════════════════════════════════════════════════════════════════
  LogSentry  |  Automated Log Integrity Monitor
────────────────────────────────────────────────────────────────────────
  File      : server.log
  Threshold : 60s  |  Format: hdfs
════════════════════════════════════════════════════════════════════════

  [ HIGH   ]  Gap #1  (line 946)
  Start    :  2008-11-09 21:06:50
  End      :  2008-11-09 21:31:51
  Duration :  25m 1s  (1501s  |  25.0x threshold)

════════════════════════════════════════════════════════════════════════
  SUMMARY
  Total gaps found    : 1
  By severity         : 1 HIGH  0 MEDIUM  0 LOW
  Lines parsed        : 1300
  Lines skipped       : 49
  Verdict  : TAMPERING LIKELY — immediate escalation recommended.
════════════════════════════════════════════════════════════════════════
```

---

## CLI Reference

| Argument | Type | Default | Description |
|---|---|---|---|
| `logfile` | positional | — | Path to the log file |
| `--threshold` | int (seconds) | 60 | Minimum gap to flag |
| `--format` | string | auto | Timestamp format (see below) |
| `--export` | filename | — | Export to .json or .csv |
| `--timeline` | flag | off | Print ASCII timeline |

### Supported Formats

| Key | Example | Description |
|---|---|---|
| `auto` | — | Tries all patterns in order |
| `hdfs` | `081109 203615` | HDFS / Hadoop logs |
| `syslog` | `Nov  9 20:36:15` | Linux syslog |
| `apache` | `[09/Nov/2008:20:36:15` | Apache access/error logs |
| `iso8601` | `2008-11-09T20:36:15` | ISO 8601 with T separator |
| `iso8601_space` | `2008-11-09 20:36:15` | ISO 8601 with space separator |

**Adding a new format:** Add one entry to `TIMESTAMP_PATTERNS` in `parser.py`. No other changes needed.

---

## Severity Model

| Tier | Condition | Action |
|---|---|---|
| LOW | 1x – 5x threshold | Note in report, lower priority |
| MEDIUM | 5x – 10x threshold | Investigate in context |
| HIGH | > 10x threshold | Immediate escalation |

---

## Architecture

```
integrity_check.py   ← CLI entry point (argparse)
    │
    ├── error_handler.py  ← Input validation, fatal(), warn()
    ├── parser.py         ← Line-by-line generator, TIMESTAMP_PATTERNS
    ├── detector.py       ← Delta comparison, severity scoring, GapRecord
    └── reporter.py       ← Stdout render, JSON/CSV export, ASCII timeline
```

### Key Design Decisions

**Generator-based streaming** — The log file is consumed one line at a time.
Peak memory is constant regardless of file size. This is the correct choice for
forensic tools that may run on the compromised server itself.

**TIMESTAMP_PATTERNS dictionary** — All format logic lives in one dict.
Adding a new log format = adding one entry. Zero logic changes required.

**Severity tiers** — Gaps are classified relative to the threshold multiplier,
not as raw seconds. This gives the analyst a triage signal that scales with
their chosen threshold.

**Trade-off acknowledged** — A vectorised pandas approach would compute deltas
faster but would load the full file into memory. Memory safety takes priority
in incident response contexts.

---

## Running the Test Suite

```bash
# Generate a test log with 3 injected gaps and 5% malformed lines
python generate_test_log.py

# Run against it
python integrity_check.py test_server.log --threshold 60 --timeline

# Export and validate
python integrity_check.py test_server.log --export report.json
python -c "import json; d=json.load(open('report.json')); print(d['summary'])"
```

### Expected test output

- Gap #1: ~300s → MEDIUM (5x threshold)
- Gap #2: ~480s → MEDIUM (8x threshold)  
- Gap #3: ~1500s → HIGH (25x threshold)
- Lines skipped: ~49 (malformed lines)
- Completed in < 1s

---

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | No gaps found — log appears clean |
| 1 | One or more gaps detected |

Useful for shell scripting:
```bash
python integrity_check.py server.log || echo "ALERT: gaps detected"
```

---

## References

- [SANS White Paper on Log Management](https://www.sans.org/white-papers/38130)
- [Loghub HDFS Dataset](https://github.com/logpai/loghub/tree/master/HDFS)
- [NIST SP 800-92 — Guide to Computer Security Log Management](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf)

---

*LogSentry v1.0 — Dell x GDG Ideathon 2025*
