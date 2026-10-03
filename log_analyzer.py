"""
log_analyzer.py

Parses an SSH auth log file and detects suspicious activity:
- Brute-force attempts (many failed logins from one IP in a short window)
- Invalid user probing (attackers trying common usernames like root, admin)
- Off-hours logins (successful logins at unusual times, e.g. 1-5 AM)

Outputs a structured findings report (findings.json) that ai_report.py
can turn into a plain-English summary.

Usage:
    python3 log_analyzer.py data/auth.log
"""

import re
import sys
import json
from zoneinfo import ZoneInfo
from datetime import datetime, timedelta
from collections import defaultdict

# --- Config: tune these thresholds based on your environment ---
BRUTE_FORCE_THRESHOLD = 10       # failed attempts from one IP to flag as brute force
BRUTE_FORCE_WINDOW_MIN = 10      # within this many minutes
OFF_HOURS_START = 0              # midnight
OFF_HOURS_END = 5                # 5 AM - logins in this window get flagged
LOCAL_TIMEZONE = "America/New_York"   # convert UTC server logs to this time zone

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<message>.+)$"
)

ISO_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)\s+"
    r"(?P<host>\S+)\s+sshd(?:-session)?\[\d+\]:\s+"
    r"(?P<message>.+)$"
)

FAILED_PATTERN = re.compile(
    r"Failed (?:password|publickey) for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
SUCCESS_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)


def parse_log_file(filepath):
    """Reads the log file and returns a list of parsed event dicts."""
    events = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            match = LOG_PATTERN.match(line) or ISO_PATTERN.match(line)
            if not match:
                continue

            timestamp_str = match.group("timestamp")
            # Year isn't in raw syslog format, so we assume the current year
            timestamp = datetime.fromisoformat(timestamp_str).astimezone(ZoneInfo(LOCAL_TIMEZONE)).replace(tzinfo=None) if timestamp_str[0].isdigit() else datetime.strptime(f"{datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            message = match.group("message")

            failed_match = FAILED_PATTERN.search(message)
            success_match = SUCCESS_PATTERN.search(message)

            if failed_match:
                events.append({
                    "timestamp": timestamp,
                    "type": "failed",
                    "user": failed_match.group("user"),
                    "ip": failed_match.group("ip"),
                    "invalid_user": "invalid user" in message,
                })
            elif success_match:
                events.append({
                    "timestamp": timestamp,
                    "type": "success",
                    "user": success_match.group("user"),
                    "ip": success_match.group("ip"),
                    "invalid_user": False,
                })
    return events


def detect_brute_force(events):
    """Groups failed logins by IP, flags IPs with a burst of attempts in a short window.

    Uses a sliding window: instead of requiring the ENTIRE first-to-last span
    of attempts to be short (which one stray outlier attempt days later would
    break), it checks whether any BRUTE_FORCE_WINDOW_MIN-minute window contains
    at least BRUTE_FORCE_THRESHOLD attempts. This matches how brute-force
    attacks actually look: a tight burst, possibly with unrelated noise
    elsewhere in the log from the same IP.
    """
    failed_by_ip = defaultdict(list)
    for e in events:
        if e["type"] == "failed":
            failed_by_ip[e["ip"]].append(e["timestamp"])

    findings = []
    window = timedelta(minutes=BRUTE_FORCE_WINDOW_MIN)

    for ip, timestamps in failed_by_ip.items():
        timestamps.sort()
        if len(timestamps) < BRUTE_FORCE_THRESHOLD:
            continue

        # Slide a window across the sorted timestamps looking for a dense burst
        best_window_count = 0
        best_start_idx = 0
        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > window:
                left += 1
            count_in_window = right - left + 1
            if count_in_window > best_window_count:
                best_window_count = count_in_window
                best_start_idx = left

        if best_window_count >= BRUTE_FORCE_THRESHOLD:
            burst_start = timestamps[best_start_idx]
            burst_end = timestamps[best_start_idx + best_window_count - 1]
            duration_min = (burst_end - burst_start).total_seconds() / 60
            findings.append({
                "ip": ip,
                "attempt_count": best_window_count,
                "total_attempts_from_ip": len(timestamps),
                "first_attempt": burst_start.isoformat(),
                "last_attempt": burst_end.isoformat(),
                "duration_minutes": round(duration_min, 1),
            })

    return sorted(findings, key=lambda x: x["attempt_count"], reverse=True)


def detect_invalid_user_probing(events):
    """Flags IPs that tried multiple different usernames that don't exist (common attack pattern)."""
    users_tried_by_ip = defaultdict(set)
    for e in events:
        if e["invalid_user"]:
            users_tried_by_ip[e["ip"]].add(e["user"])

    findings = []
    for ip, users in users_tried_by_ip.items():
        if len(users) >= 3:
            findings.append({
                "ip": ip,
                "usernames_tried": sorted(users),
                "unique_username_count": len(users),
            })
    return sorted(findings, key=lambda x: x["unique_username_count"], reverse=True)


def detect_off_hours_logins(events):
    """Flags successful logins that happened during unusual hours (e.g. 12am-5am)."""
    findings = []
    for e in events:
        if e["type"] == "success" and OFF_HOURS_START <= e["timestamp"].hour < OFF_HOURS_END:
            findings.append({
                "user": e["user"],
                "ip": e["ip"],
                "timestamp": e["timestamp"].isoformat(),
            })
    return findings


def summarize(events):
    total_events = len(events)
    total_failed = sum(1 for e in events if e["type"] == "failed")
    total_success = sum(1 for e in events if e["type"] == "success")
    unique_ips = len(set(e["ip"] for e in events))

    return {
        "total_events": total_events,
        "total_failed_logins": total_failed,
        "total_successful_logins": total_success,
        "unique_ips_seen": unique_ips,
        "brute_force_candidates": detect_brute_force(events),
        "invalid_user_probing": detect_invalid_user_probing(events),
        "off_hours_successful_logins": detect_off_hours_logins(events),
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 log_analyzer.py <path_to_log_file>")
        sys.exit(1)

    filepath = sys.argv[1]
    events = parse_log_file(filepath)

    if not events:
        print(f"No valid SSH log entries found in {filepath}")
        sys.exit(1)

    findings = summarize(events)

    with open("findings.json", "w") as f:
        json.dump(findings, f, indent=2)

    # Print a quick human-readable summary to the terminal too
    print(f"Parsed {findings['total_events']} events from {filepath}")
    print(f"  Failed logins:     {findings['total_failed_logins']}")
    print(f"  Successful logins: {findings['total_successful_logins']}")
    print(f"  Unique IPs:        {findings['unique_ips_seen']}")
    print(f"\nBrute-force candidates: {len(findings['brute_force_candidates'])}")
    for bf in findings["brute_force_candidates"]:
        print(f"  - {bf['ip']}: {bf['attempt_count']} attempts in {bf['duration_minutes']} min")
    print(f"\nInvalid-user probing IPs: {len(findings['invalid_user_probing'])}")
    for probe in findings["invalid_user_probing"]:
        print(f"  - {probe['ip']}: tried {probe['unique_username_count']} usernames {probe['usernames_tried']}")
    print(f"\nOff-hours successful logins: {len(findings['off_hours_successful_logins'])}")
    for oh in findings["off_hours_successful_logins"]:
        print(f"  - {oh['user']} from {oh['ip']} at {oh['timestamp']}")

    print("\nFull findings written to findings.json")


if __name__ == "__main__":
    main()
