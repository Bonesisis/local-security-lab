# Legal & Ethics

**This project is intended exclusively for legal, defensive learning,
analysis, and testing purposes in isolated environments that you own or are
explicitly authorized to use.**

## Scope

- All code in this repository operates only on local, static input: files
  you provide (sample logs, sample passwords, a docker-compose file) or the
  isolated container defined in [`docker-compose.yml`](../docker-compose.yml).
- Nothing in this repository sends network traffic to another host, scans a
  network, brute-forces a real service, bypasses authentication, or targets
  any system other than the local demo data shipped in `sample_data/`.
- The sample data (`sample_data/sample_auth.log`, `sample_data/demo_docker-compose.yml`,
  `sample_data/sample_passwords.txt`) is entirely fabricated for demonstration.
  IP addresses use the ranges reserved for documentation (RFC 5737 / RFC 5735:
  `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and are not real hosts.

## What this project does not do

- No exploit code, payload generation, or malware functionality.
- No authentication bypass or credential-stuffing against real services.
- No stealth, obfuscation, or persistence mechanisms.
- No functionality intended to be pointed at systems you do not own or lack
  authorization to test.

## Responsible use

If you extend this project to analyze real logs or real infrastructure:

- Only ever point it at systems and data **you own or are explicitly
  authorized in writing to test or analyze**.
- Follow applicable law (in Germany, among others: StGB §202a–c, §303a–b;
  and equivalent computer-misuse laws in other jurisdictions) and any
  responsible-disclosure or authorization agreements that apply.
- Handle real log data as sensitive/personal data (GDPR applies to IP
  addresses and usernames) — do not commit real logs to a public repository.

## Disclaimer

This software is provided "as is" for educational purposes, without warranty
of any kind (see [`LICENSE`](../LICENSE)). The author is not responsible for
misuse of this code outside of its intended, authorized, defensive scope.
