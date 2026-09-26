#!/usr/bin/env python3
"""
Log Analyzer — Brute-Force & Anomaly Detection

Parses SSH/auth-style log files and flags brute-force attempts and unusual
login times.
"""

import argparse
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

# Matches lines like:
# Sep 20 03:14:02 host sshd[1234]: Failed password for root from 203.0.113.45 port 51514 ssh2
# Sep 20 03:14:02 host sshd[1234]: Accepted password for deploy from 192.0.2.15 port 51515 ssh2
LOG_LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<result>Failed|Accepted)\s+password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)"
)

DEFAULT_YEAR = datetime.now().year
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=10)
NORMAL_HOURS_START = 7   # 7am
NORMAL_HOURS_END = 23    # 11pm


@dataclass
class LogEntry:
    timestamp: datetime
    result: str  # "Failed" or "Accepted"
    user: str
    ip: str


def parse_log(path: str) -> list:
    entries = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            match = LOG_LINE_RE.match(line.strip())
            if not match:
                continue
            gd = match.groupdict()
            try:
                timestamp = datetime.strptime(
                    f"{DEFAULT_YEAR} {gd['month']} {gd['day']} {gd['time']}",
                    "%Y %b %d %H:%M:%S",
                )
            except ValueError:
                continue
            entries.append(
                LogEntry(timestamp=timestamp, result=gd["result"], user=gd["user"], ip=gd["ip"])
            )
    entries.sort(key=lambda e: e.timestamp)
    return entries


def find_brute_force(entries: list) -> dict:
    """
    Returns {ip: {"count": int, "users": set, "first": dt, "last": dt}} for any IP with
    BRUTE_FORCE_THRESHOLD+ failed attempts inside any BRUTE_FORCE_WINDOW.
    """
    failed_by_ip = defaultdict(list)
    for entry in entries:
        if entry.result == "Failed":
            failed_by_ip[entry.ip].append(entry)

    suspects = {}
    for ip, attempts in failed_by_ip.items():
        attempts.sort(key=lambda e: e.timestamp)
        # sliding window: for each attempt, count how many fall within the window after it
        max_in_window = 0
        window_users = set()
        for i, start in enumerate(attempts):
            window_end = start.timestamp + BRUTE_FORCE_WINDOW
            window_entries = [a for a in attempts[i:] if a.timestamp <= window_end]
            if len(window_entries) > max_in_window:
                max_in_window = len(window_entries)
                window_users = {a.user for a in window_entries}

        if max_in_window >= BRUTE_FORCE_THRESHOLD:
            suspects[ip] = {
                "count": len(attempts),
                "max_in_window": max_in_window,
                "users": {a.user for a in attempts},
                "first": attempts[0].timestamp,
                "last": attempts[-1].timestamp,
            }
    return suspects


def find_unusual_hours(entries: list) -> list:
    unusual = []
    for entry in entries:
        if entry.result != "Accepted":
            continue
        hour = entry.timestamp.hour
        if hour < NORMAL_HOURS_START or hour >= NORMAL_HOURS_END:
            unusual.append(entry)
    return unusual


def print_report(entries: list, brute_force: dict, unusual_hours: list):
    if not entries:
        print("No matching log lines found.")
        return

    print(
        f"Parsed {len(entries)} log lines "
        f"({entries[0].timestamp} to {entries[-1].timestamp})\n"
    )

    if brute_force:
        print(f"⚠ Brute-force suspects ({BRUTE_FORCE_THRESHOLD}+ failed attempts within "
              f"{int(BRUTE_FORCE_WINDOW.total_seconds() // 60)} minutes):")
        for ip, info in sorted(brute_force.items(), key=lambda kv: -kv[1]["count"]):
            users = ", ".join(sorted(info["users"]))
            print(f"  {ip} — {info['count']} failed attempts targeting users: {users}")
        print()
    else:
        print("No brute-force patterns detected.\n")

    if unusual_hours:
        print(f"⚠ Unusual-hour logins (outside {NORMAL_HOURS_START:02d}:00-{NORMAL_HOURS_END:02d}:00):")
        for entry in unusual_hours:
            print(f"  Successful login for '{entry.user}' from {entry.ip} at {entry.timestamp}")
        print()
    else:
        print("No unusual-hour logins detected.\n")

    print(
        f"Summary: {len(brute_force)} brute-force suspect(s), "
        f"{len(unusual_hours)} unusual-hour login(s), out of {len(entries)} total log lines."
    )


def main():
    parser = argparse.ArgumentParser(description="Analyze auth logs for brute-force and anomaly patterns.")
    parser.add_argument("--log", required=True, help="Path to the log file to analyze")
    args = parser.parse_args()

    entries = parse_log(args.log)
    brute_force = find_brute_force(entries)
    unusual_hours = find_unusual_hours(entries)
    print_report(entries, brute_force, unusual_hours)


if __name__ == "__main__":
    main()
