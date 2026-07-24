"""
generate_sample_logs.py

Creates a realistic sample SSH auth log file (data/auth.log) that mimics
what you'd find on a real Linux server at /var/log/auth.log.

This includes:
- Normal successful logins from regular users
- A brute-force attack pattern (many failed logins from one IP)
- Some random one-off failed logins (typos, scans, etc.)
- Logins at unusual hours (potential red flag)

Run this first so you have data to feed into log_analyzer.py
"""

import random
from datetime import datetime, timedelta

# Config
OUTPUT_FILE = "data/auth.log"
NORMAL_USERS = ["bryan", "admin", "deploy", "backup"]
FAKE_ATTACKER_USERS = ["root", "admin", "test", "user", "oracle", "postgres"]

def random_ip(suspicious=False):
    if suspicious:
        # Simulate attack traffic coming from a small set of IPs
        return random.choice(["185.220.101.7", "45.155.204.13", "103.45.67.2"])
    return f"192.168.1.{random.randint(2, 50)}"

def format_log_line(timestamp, event_type, user, ip, port):
    ts = timestamp.strftime("%b %d %H:%M:%S")
    host = "webserver01"
    if event_type == "success":
        return f"{ts} {host} sshd[1234]: Accepted password for {user} from {ip} port {port} ssh2"
    elif event_type == "fail":
        return f"{ts} {host} sshd[1234]: Failed password for {user} from {ip} port {port} ssh2"
    elif event_type == "invalid_user":
        return f"{ts} {host} sshd[1234]: Failed password for invalid user {user} from {ip} port {port} ssh2"

def generate_logs():
    lines = []
    start_time = datetime(2026, 7, 20, 0, 0, 0)

    # 1. Normal daytime logins across a few days (business hours mostly)
    current = start_time
    for _ in range(40):
        current += timedelta(minutes=random.randint(20, 240))
        hour = random.choice(list(range(7, 20)))  # normal business hours
        ts = current.replace(hour=hour, minute=random.randint(0, 59))
        user = random.choice(NORMAL_USERS)
        ip = random_ip()
        port = random.randint(40000, 60000)
        lines.append(format_log_line(ts, "success", user, ip, port))

    # 2. A brute-force attack burst: one IP hammering login attempts in a short window
    attack_start = start_time + timedelta(days=1, hours=3, minutes=15)  # 3:15 AM, off-hours
    attacker_ip = "185.220.101.7"
    for i in range(60):
        ts = attack_start + timedelta(seconds=i * 4)
        user = random.choice(FAKE_ATTACKER_USERS)
        port = random.randint(40000, 60000)
        event = "invalid_user" if user not in NORMAL_USERS else "fail"
        lines.append(format_log_line(ts, event, user, attacker_ip, port))

    # 3. A second, smaller brute-force attempt from a different IP, different day
    attack2_start = start_time + timedelta(days=2, hours=2, minutes=40)
    attacker_ip2 = "45.155.204.13"
    for i in range(25):
        ts = attack2_start + timedelta(seconds=i * 6)
        user = random.choice(FAKE_ATTACKER_USERS)
        port = random.randint(40000, 60000)
        event = "invalid_user" if user not in NORMAL_USERS else "fail"
        lines.append(format_log_line(ts, event, user, attacker_ip2, port))

    # 4. Random one-off noise (scanners, typos) scattered across the period
    for _ in range(15):
        ts = start_time + timedelta(
            days=random.randint(0, 3),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
        )
        user = random.choice(FAKE_ATTACKER_USERS + NORMAL_USERS)
        ip = random_ip(suspicious=random.random() < 0.3)
        port = random.randint(40000, 60000)
        lines.append(format_log_line(ts, "fail", user, ip, port))

    # 5. One legit login at a weird hour (not an attack, just a night owl - tests false positive handling)
    ts = start_time + timedelta(days=3, hours=1, minutes=12)
    lines.append(format_log_line(ts, "success", "bryan", random_ip(), random.randint(40000, 60000)))

    # Sort all lines by timestamp so the log reads chronologically
    def extract_ts(line):
        return datetime.strptime(" ".join(line.split()[:3]), "%b %d %H:%M:%S")

    lines.sort(key=extract_ts)

    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Generated {len(lines)} log lines -> {OUTPUT_FILE}")

if __name__ == "__main__":
    generate_logs()
