"""
generate_test_log.py — Generates a realistic HDFS-format test log.

Injects:
  - 3 suspicious gaps (LOW / MEDIUM / HIGH severity)
  - ~5% malformed lines (FR-08 compliance test)
  - Normal activity noise around the gaps
"""

import random
from datetime import datetime, timedelta

random.seed(42)

COMPONENTS = [
    "dfs.DataNode$DataXceiver",
    "dfs.FSNamesystem",
    "dfs.DataBlockScanner",
    "dfs.DataNode$PacketResponder",
    "dfs.DataNode",
    "heartbeat.HeartbeatManager",
    "namenode.FSEditLog",
]

MESSAGES = [
    "Receiving block blk_-{} src: /10.250.10.{}: PORT dst: /10.250.10.{}: PORT",
    "Served block blk_{} to /10.251.{}.{}",
    "PacketResponder 1 for block blk_{} terminating",
    "writeBlock blk_{} received exception java.io.IOException",
    "BLOCK* ask 10.250.10.{} to replicate blk_{} to datanode(s)",
    "Verification succeeded for blk_{}",
    "BLOCK* NameSystem.addStoredBlock: blockMap updated",
]

def fmt_ts(dt: datetime) -> str:
    return dt.strftime("%y%m%d %H%M%S")

def make_line(dt: datetime, n: int) -> str:
    comp = random.choice(COMPONENTS)
    msg_template = random.choice(MESSAGES)
    try:
        msg = msg_template.format(
            random.randint(1000000, 9999999),
            random.randint(1, 254),
            random.randint(1, 254),
            random.randint(1, 254),
        )
    except (IndexError, KeyError):
        msg = msg_template.format(random.randint(1000000, 9999999))
    level = random.choice(["INFO", "INFO", "INFO", "WARN", "ERROR"])
    thread = random.randint(100, 999)
    return f"{fmt_ts(dt)} {thread} {level} {comp}: {msg}"

lines = []
current = datetime(2008, 11, 9, 20, 30, 0)

# Block 1: 400 normal lines
for i in range(400):
    lines.append(make_line(current, i))
    current += timedelta(seconds=random.uniform(0.5, 3))

# GAP 1 — LOW severity: 5 minutes (300s), threshold=60 → 5x = boundary LOW/MEDIUM
current += timedelta(seconds=300)
for i in range(200):
    lines.append(make_line(current, i))
    current += timedelta(seconds=random.uniform(0.5, 3))

# GAP 2 — MEDIUM severity: 8 minutes (480s), threshold=60 → 8x
current += timedelta(seconds=480)
for i in range(300):
    lines.append(make_line(current, i))
    current += timedelta(seconds=random.uniform(0.5, 2))

# GAP 3 — HIGH severity: 25 minutes (1500s), threshold=60 → 25x
current += timedelta(seconds=1500)
for i in range(400):
    lines.append(make_line(current, i))
    current += timedelta(seconds=random.uniform(0.5, 2))

# Inject ~5% malformed lines at random positions
total = len(lines)
malformed_count = int(total * 0.05)
malformed_lines = [
    "this line has no timestamp at all",
    "20:36:17 incomplete",
    "XXXXXX YYYYYY bad format entry",
    "",
    "   ",
    "null null null null",
    "081109 BADTIME 148 INFO Component: Message",
    "random garbage line with no structure whatsoever !!!",
]
for _ in range(malformed_count):
    pos = random.randint(0, len(lines) - 1)
    lines.insert(pos, random.choice(malformed_lines))

with open("test_server.log", "w") as f:
    f.write("\n".join(lines))

print(f"Generated test_server.log: {len(lines)} lines, {malformed_count} malformed, 3 injected gaps")
print("Expected gaps:")
print("  Gap 1: ~300s  → LOW severity    (5x threshold)")
print("  Gap 2: ~480s  → MEDIUM severity (8x threshold)")
print("  Gap 3: ~1500s → HIGH severity   (25x threshold)")
