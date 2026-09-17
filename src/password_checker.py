"""Checks passwords against a simple, local password policy.

This module never transmits, stores, or logs passwords anywhere — it only
evaluates strings passed to it in-process and returns a report.
"""

from __future__ import annotations

import re

# Small built-in list for demonstration purposes only. For real use, check
# against a full breached-password corpus (e.g. Have I Been Pwned's range API).
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "qwerty", "abc123", "111111",
    "12345678", "1234567", "letmein", "admin", "welcome", "iloveyou",
    "monkey", "dragon", "password1", "admin123",
}

MIN_LENGTH = 12


def check_password(password: str) -> dict:
    """Evaluate a single password and return a policy report."""
    checks = {
        "min_length": len(password) >= MIN_LENGTH,
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_digit": bool(re.search(r"\d", password)),
        "has_special": bool(re.search(r"[^A-Za-z0-9]", password)),
        "not_common": password.lower() not in COMMON_PASSWORDS,
    }

    score = sum(checks.values())
    if not checks["min_length"] or not checks["not_common"]:
        # Length and common-password checks are hard requirements: no
        # combination of character classes compensates for either.
        verdict = "weak"
    elif score == len(checks):
        verdict = "strong"
    elif score >= 4:
        verdict = "moderate"
    else:
        verdict = "weak"

    return {
        "length": len(password),
        "checks": checks,
        "score": f"{score}/{len(checks)}",
        "verdict": verdict,
    }


def check_password_file(path: str) -> list[dict]:
    """Evaluate one password per line from a local sample file."""
    results = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            pwd = line.rstrip("\n")
            if not pwd:
                continue
            results.append({"password_masked": _mask(pwd), **check_password(pwd)})
    return results


def _mask(password: str) -> str:
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]
