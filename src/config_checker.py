"""Static checker for docker-compose files used in this lab.

It only reads and parses a local YAML file — it never starts containers,
connects to a daemon, or touches any host other than the one it runs on.
"""

from __future__ import annotations

import yaml

SENSITIVE_ENV_KEYWORDS = ("PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY")
DANGEROUS_MOUNTS = ("/var/run/docker.sock", "/:/", "/etc:/etc")


def check_compose_file(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}

    findings = []
    services = config.get("services", {}) or {}

    for name, service in services.items():
        findings.extend(_check_service(name, service or {}))

    return findings


def _check_service(name: str, service: dict) -> list[dict]:
    findings = []

    if service.get("privileged") is True:
        findings.append(_finding(name, "high", "runs with privileged: true"))

    if service.get("network_mode") == "host":
        findings.append(_finding(name, "high", "uses network_mode: host"))

    if service.get("user") in (None, "root", "0"):
        findings.append(_finding(name, "low", "no non-root user configured"))

    for env_entry in _iter_env(service.get("environment")):
        key, _, value = env_entry.partition("=")
        if any(word in key.upper() for word in SENSITIVE_ENV_KEYWORDS) and value:
            findings.append(
                _finding(name, "medium", f"hardcoded secret in environment variable '{key}'")
            )

    for volume in service.get("volumes", []) or []:
        volume_str = volume if isinstance(volume, str) else str(volume)
        if any(mount in volume_str for mount in DANGEROUS_MOUNTS):
            findings.append(_finding(name, "critical", f"dangerous volume mount: {volume_str}"))

    for port in service.get("ports", []) or []:
        port_str = str(port)
        if port_str.startswith("0.0.0.0:"):
            findings.append(_finding(name, "medium", f"port explicitly bound to all interfaces: {port_str}"))

    return findings


def _iter_env(environment) -> list[str]:
    if environment is None:
        return []
    if isinstance(environment, dict):
        return [f"{k}={v}" for k, v in environment.items()]
    return list(environment)


def _finding(service: str, severity: str, message: str) -> dict:
    return {"service": service, "severity": severity, "message": message}
