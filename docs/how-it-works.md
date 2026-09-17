# How It Works

Three independent, local-only analysis tools live under [`src/`](../src/),
each with a matching test file under [`tests/`](../tests/).

## 1. Log Analyzer (`src/log_analyzer.py`)

Reads a text file line by line and matches two regular expressions modeled
on OpenSSH's auth log format:

- `Failed password for [invalid user] <user> from <ip> port <port>`
- `Accepted password for <user> from <ip> port <port>`

It groups matches by source IP and flags an IP when:

| Condition | Severity |
|---|---|
| Failed attempts ≥ `--threshold` (default 5) | high |
| Distinct usernames tried ≥ `--distinct-users` (default 3) | high |
| A successful login follows failed attempts from the same IP | critical |

This mirrors the basic heuristics a real intrusion-detection or SIEM rule
uses for brute-force and user-enumeration detection, without needing a live
log stream or any external service.

## 2. Password Checker (`src/password_checker.py`)

Evaluates a password string against six local checks: minimum length (12),
uppercase, lowercase, digit, special character, and membership in a small
built-in list of common/breached passwords. The combined score maps to a
`weak` / `moderate` / `strong` verdict.

No password is ever written to disk, logged, or transmitted — `check_password`
operates purely on the in-memory string, and the CLI only ever prints a
masked version (`p******3`) back to the terminal.

## 3. Config Checker (`src/config_checker.py`)

Parses a `docker-compose.yml` file with `yaml.safe_load` (never executes
it) and walks each service definition for known risky patterns:

- `privileged: true`
- `network_mode: host`
- containers running as `root` (no `user:` set)
- environment variables whose key looks like a secret
  (`PASSWORD`, `SECRET`, `TOKEN`, `API_KEY`, `PRIVATE_KEY`) with a literal value
- dangerous bind mounts (e.g. `/var/run/docker.sock`, mounting `/`)
- ports explicitly bound to `0.0.0.0`

This is static analysis only — the file is never used to actually start a
container.

## CLI (`src/cli.py`)

A thin `argparse`-based dispatcher exposing all three tools as subcommands
(`log-scan`, `password-check`, `config-check`), each supporting `--json` for
machine-readable output. Each subcommand exits non-zero when it finds
something worth flagging, so it can be used as a lint-style check in a
script or (local, non-production) CI job.
