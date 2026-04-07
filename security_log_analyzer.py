#!/usr/bin/env python3
"""
Security Log Analyzer
Author: Muniver Kharod
Project: Beginner cybersecurity project that scans authentication logs
for suspicious activity such as repeated failed logins and "impossible travel".
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable


LOG_PATTERN = re.compile(
    r"""
    ^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+\|\s+
    user=(?P<user>[^\|]+)\s+\|\s+
    ip=(?P<ip>[^\|]+)\s+\|\s+
    country=(?P<country>[^\|]+)\s+\|\s+
    action=(?P<action>[^\|]+)\s+\|\s+
    status=(?P<status>[^\|]+)
    $
    """,
    re.VERBOSE,
)


@dataclass
class LogEntry:
    timestamp: datetime
    user: str
    ip: str
    country: str
    action: str
    status: str


@dataclass
class Alert:
    alert_type: str
    severity: str
    user: str
    ip: str
    timestamp: str
    description: str


def parse_log_line(line: str) -> LogEntry | None:
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    parts = match.groupdict()
    return LogEntry(
        timestamp=datetime.strptime(parts["timestamp"], "%Y-%m-%dT%H:%M:%SZ"),
        user=parts["user"].strip(),
        ip=parts["ip"].strip(),
        country=parts["country"].strip(),
        action=parts["action"].strip(),
        status=parts["status"].strip(),
    )


def read_logs(path: Path) -> list[LogEntry]:
    entries = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            entry = parse_log_line(line)
            if entry is None:
                print(f"[warning] Skipping malformed line {line_no}: {line.strip()}")
                continue
            entries.append(entry)
    return sorted(entries, key=lambda e: e.timestamp)


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def detect_failed_login_bursts(
    entries: Iterable[LogEntry],
    threshold: int,
    window_minutes: int,
) -> list[Alert]:
    alerts: list[Alert] = []
    failures_by_user_ip: dict[tuple[str, str], list[datetime]] = defaultdict(list)
    seen_alert_keys = set()

    window = timedelta(minutes=window_minutes)

    for entry in entries:
        if entry.status.lower() != "failed":
            continue

        key = (entry.user, entry.ip)
        failures_by_user_ip[key].append(entry.timestamp)

        recent = [t for t in failures_by_user_ip[key] if entry.timestamp - t <= window]
        failures_by_user_ip[key] = recent

        if len(recent) >= threshold:
            dedupe = (entry.user, entry.ip, recent[0], recent[-1], "failed_burst")
            if dedupe not in seen_alert_keys:
                seen_alert_keys.add(dedupe)
                alerts.append(
                    Alert(
                        alert_type="Repeated Failed Logins",
                        severity="High",
                        user=entry.user,
                        ip=entry.ip,
                        timestamp=entry.timestamp.isoformat() + "Z",
                        description=(
                            f"{len(recent)} failed login attempts for user '{entry.user}' "
                            f"from IP {entry.ip} within {window_minutes} minutes."
                        ),
                    )
                )
    return alerts


def detect_impossible_travel(entries: Iterable[LogEntry], hours_limit: int = 2) -> list[Alert]:
    alerts: list[Alert] = []
    last_success_by_user: dict[str, LogEntry] = {}

    for entry in entries:
        if entry.status.lower() != "success":
            continue

        previous = last_success_by_user.get(entry.user)
        if previous and previous.country != entry.country:
            delta = entry.timestamp - previous.timestamp
            if delta <= timedelta(hours=hours_limit):
                alerts.append(
                    Alert(
                        alert_type="Impossible Travel",
                        severity="Medium",
                        user=entry.user,
                        ip=entry.ip,
                        timestamp=entry.timestamp.isoformat() + "Z",
                        description=(
                            f"User '{entry.user}' logged in successfully from {previous.country} "
                            f"and then from {entry.country} within {delta}."
                        ),
                    )
                )
        last_success_by_user[entry.user] = entry

    return alerts


def detect_public_ip_success_after_failures(entries: Iterable[LogEntry], min_failures: int = 3) -> list[Alert]:
    alerts: list[Alert] = []
    failures_before_success: dict[tuple[str, str], int] = defaultdict(int)

    for entry in entries:
        key = (entry.user, entry.ip)
        if entry.status.lower() == "failed":
            failures_before_success[key] += 1
        elif entry.status.lower() == "success":
            if failures_before_success[key] >= min_failures and is_public_ip(entry.ip):
                alerts.append(
                    Alert(
                        alert_type="Success After Multiple Failures",
                        severity="High",
                        user=entry.user,
                        ip=entry.ip,
                        timestamp=entry.timestamp.isoformat() + "Z",
                        description=(
                            f"User '{entry.user}' had {failures_before_success[key]} failed attempts "
                            f"before a successful login from public IP {entry.ip}."
                        ),
                    )
                )
            failures_before_success[key] = 0

    return alerts


def summarize(entries: list[LogEntry], alerts: list[Alert]) -> dict:
    total = len(entries)
    failed = sum(1 for e in entries if e.status.lower() == "failed")
    success = sum(1 for e in entries if e.status.lower() == "success")

    top_failed_ips: dict[str, int] = defaultdict(int)
    for e in entries:
        if e.status.lower() == "failed":
            top_failed_ips[e.ip] += 1

    top_failed_sorted = sorted(top_failed_ips.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "total_events": total,
        "successful_events": success,
        "failed_events": failed,
        "alert_count": len(alerts),
        "top_failed_ips": [{"ip": ip, "failed_attempts": count} for ip, count in top_failed_sorted],
    }


def write_alerts_csv(alerts: list[Alert], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["alert_type", "severity", "user", "ip", "timestamp", "description"],
        )
        writer.writeheader()
        for alert in alerts:
            writer.writerow(asdict(alert))


def write_summary_json(summary: dict, path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)


def print_console_summary(summary: dict, alerts: list[Alert]) -> None:
    print("\n=== Security Log Analyzer Summary ===")
    print(f"Total events:       {summary['total_events']}")
    print(f"Successful events:  {summary['successful_events']}")
    print(f"Failed events:      {summary['failed_events']}")
    print(f"Alerts generated:   {summary['alert_count']}")
    print("\nTop failed IPs:")
    if summary["top_failed_ips"]:
        for item in summary["top_failed_ips"]:
            print(f"  - {item['ip']}: {item['failed_attempts']} failed attempts")
    else:
        print("  - None")

    print("\nAlerts:")
    if not alerts:
        print("  - No suspicious activity detected.")
        return

    for i, alert in enumerate(alerts, start=1):
        print(f"  {i}. [{alert.severity}] {alert.alert_type} | {alert.description}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze auth logs for suspicious activity.")
    parser.add_argument(
        "--input",
        required=True,
        help="Path to the input log file.",
    )
    parser.add_argument(
        "--failed-threshold",
        type=int,
        default=3,
        help="Number of failed login attempts within the time window needed to raise an alert.",
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=10,
        help="Time window in minutes for repeated failed login detection.",
    )
    parser.add_argument(
        "--alerts-output",
        default="alerts.csv",
        help="Filename for CSV alert output.",
    )
    parser.add_argument(
        "--summary-output",
        default="summary.json",
        help="Filename for JSON summary output.",
    )

    args = parser.parse_args()
    input_path = Path(args.input)

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    entries = read_logs(input_path)
    alerts: list[Alert] = []
    alerts.extend(detect_failed_login_bursts(entries, args.failed_threshold, args.window_minutes))
    alerts.extend(detect_impossible_travel(entries))
    alerts.extend(detect_public_ip_success_after_failures(entries))

    # Sort alerts for readability
    alerts = sorted(alerts, key=lambda a: (a.timestamp, a.severity), reverse=False)

    summary = summarize(entries, alerts)
    write_alerts_csv(alerts, Path(args.alerts_output))
    write_summary_json(summary, Path(args.summary_output))
    print_console_summary(summary, alerts)


if __name__ == "__main__":
    main()
