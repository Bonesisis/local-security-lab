"""Detects suspicious login patterns (brute-force, user enumeration) in
SSH-style authentication logs. Works only on local text files supplied by
the caller — it does not read live system logs or reach any network.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

FAILED_LOGIN_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)

ACCEPTED_LOGIN_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)


@dataclass
class IpActivity:
    ip: str
    failed_attempts: int = 0
    users_tried: set = field(default_factory=set)
    accepted_after_failures: bool = False


def parse_log_lines(lines: list[str]) -> dict[str, IpActivity]:
    """Group failed/accepted SSH login lines by source IP."""
    activity: dict[str, IpActivity] = {}

    for line in lines:
        failed = FAILED_LOGIN_RE.match(line)
        if failed:
            ip = failed.group("ip")
            entry = activity.setdefault(ip, IpActivity(ip=ip))
            entry.failed_attempts += 1
            entry.users_tried.add(failed.group("user"))
            continue

        accepted = ACCEPTED_LOGIN_RE.match(line)
        if accepted:
            ip = accepted.group("ip")
            entry = activity.setdefault(ip, IpActivity(ip=ip))
            if entry.failed_attempts > 0:
                entry.accepted_after_failures = True

    return activity


def analyze(
    lines: list[str],
    failed_threshold: int = 5,
    distinct_user_threshold: int = 3,
) -> list[dict]:
    """Flag IPs that look like brute-force or user-enumeration sources.

    Returns a list of findings, most severe first.
    """
    activity = parse_log_lines(lines)
    findings = []

    for entry in activity.values():
        reasons = []
        severity = "info"

        if entry.failed_attempts >= failed_threshold:
            reasons.append(f"{entry.failed_attempts} failed login attempts")
            severity = "high"

        if len(entry.users_tried) >= distinct_user_threshold:
            reasons.append(f"{len(entry.users_tried)} distinct usernames tried")
            severity = "high"

        if entry.accepted_after_failures:
            reasons.append("login accepted after failed attempts")
            severity = "critical"

        if reasons:
            findings.append(
                {
                    "ip": entry.ip,
                    "severity": severity,
                    "failed_attempts": entry.failed_attempts,
                    "distinct_users": sorted(entry.users_tried),
                    "reasons": reasons,
                }
            )

    severity_order = {"critical": 0, "high": 1, "info": 2}
    findings.sort(key=lambda f: (severity_order[f["severity"]], -f["failed_attempts"]))
    return findings


def analyze_file(
    path: str,
    failed_threshold: int = 5,
    distinct_user_threshold: int = 3,
) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        lines = handle.readlines()
    return analyze(lines, failed_threshold, distinct_user_threshold)
