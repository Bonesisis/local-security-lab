# local-security-lab

> **This project is intended exclusively for legal, defensive learning,
> analysis, and testing purposes in isolated, self-owned environments.**
> It contains no exploits, no payloads, no authentication-bypass code, and
> nothing designed to be used against systems you do not own or are not
> explicitly authorized to test. See [`docs/legal-and-ethics.md`](docs/legal-and-ethics.md).

## Project Goal

A small, self-contained toolkit that demonstrates practical defensive
security skills:

- parsing and analyzing logs for suspicious authentication patterns,
- evaluating password strength against a policy,
- statically checking a container configuration for common misconfigurations,
- and packaging all of it in a reproducible, isolated local test environment.

Everything runs against local sample data or an isolated, network-disabled
Docker container — never against a real or remote system.

## Legal Notice

This repository is a learning/portfolio project. Use of any of this code
against systems, networks, or data you do not own or do not have explicit
written authorization to test is not endorsed and may be illegal in your
jurisdiction. See [`docs/legal-and-ethics.md`](docs/legal-and-ethics.md) for
details.

## Security & Ethics

- No exploits, payloads, or malware functionality.
- No authentication bypass, credential stuffing, or brute-forcing of real services.
- No stealth, evasion, or persistence mechanisms.
- All sample data is fabricated (RFC 5737/5735 documentation IP ranges, made-up
  credentials) — nothing in `sample_data/` refers to a real host or account.

## Features

| Tool | Command | What it does |
|---|---|---|
| Log Analyzer | `log-scan` | Flags IPs with brute-force-like or user-enumeration patterns in an SSH-style auth log |
| Password Checker | `password-check` | Scores a password (or file of passwords) against a local strength policy |
| Config Checker | `config-check` | Flags insecure patterns (privileged mode, hardcoded secrets, dangerous mounts, root user) in a docker-compose file |

See [`docs/how-it-works.md`](docs/how-it-works.md) for the detection logic behind each tool.

## Requirements

- Python 3.10+ **or** Docker with the Compose plugin
- No external network access needed at any point

## Installation

```bash
git clone <your-repo-url>
cd local-security-lab
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
```

Or, without installing Python dependencies locally, use Docker (see below).

## Usage

### Local Python

```bash
python -m src.cli log-scan sample_data/sample_auth.log
python -m src.cli password-check --password "correct-horse-battery-staple"
python -m src.cli password-check --file sample_data/sample_passwords.txt
python -m src.cli config-check sample_data/demo_docker-compose.yml
```

Add `--json` to any command for machine-readable output.

### Docker (isolated, no network)

```bash
docker compose build
docker compose run --rm security-lab log-scan sample_data/sample_auth.log
```

Full setup details: [`docs/test-environment.md`](docs/test-environment.md).

## Example Output

```text
$ python -m src.cli log-scan sample_data/sample_auth.log
- ip=203.0.113.42, severity=critical, failed_attempts=6, distinct_users=['admin', 'guest', 'oracle', 'root', 'test'], reasons=['6 failed login attempts', '5 distinct usernames tried', 'login accepted after failed attempts']
- ip=192.0.2.15, severity=info, failed_attempts=2, distinct_users=['pi'], reasons=[]
```

## Project Structure

```
local-security-lab/
├── README.md
├── LICENSE
├── .gitignore
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── requirements-dev.txt
├── src/
│   ├── cli.py
│   ├── log_analyzer.py
│   ├── password_checker.py
│   └── config_checker.py
├── tests/
│   ├── test_log_analyzer.py
│   ├── test_password_checker.py
│   └── test_config_checker.py
├── sample_data/
│   ├── sample_auth.log
│   ├── sample_passwords.txt
│   └── demo_docker-compose.yml
└── docs/
    ├── how-it-works.md
    ├── test-environment.md
    └── legal-and-ethics.md
```

## Limitations

- Detection rules are intentionally simple (threshold-based), not
  ML-based or time-window-aware — this is a learning project, not a
  production SIEM.
- The log parser only understands one OpenSSH log line format.
- The config checker covers a small, illustrative set of Docker
  misconfigurations, not a full CIS Benchmark.
- Not a replacement for established tools (e.g. `fail2ban`, `trivy`,
  `docker-bench-security`, `zxcvbn`) — it exists to demonstrate the
  underlying concepts clearly and readably.

## Ideas for Future Extensions

- Time-windowed rate detection (e.g. N failures per 60 seconds) instead of
  whole-file totals.
- Support for additional log formats (nginx access logs, cloud audit logs).
- Integrate `zxcvbn` for more realistic password-strength scoring.
- Expand the config checker toward a docker-bench-security-style ruleset.
- A small local web dashboard (e.g. Flask) to visualize findings instead of CLI-only output.
- GitHub Actions workflow that runs `pytest` and the config-checker against
  this repo's own `docker-compose.yml` on every push.

## License

MIT — see [`LICENSE`](LICENSE). Replace `<Your Name>` in the license file with your name before publishing.
