# Test Environment

The lab is designed to run entirely on your own machine, offline, with no
dependency on any real target system.

## Option A — Docker Compose (recommended)

```bash
docker compose build
docker compose run --rm security-lab log-scan sample_data/sample_auth.log
docker compose run --rm security-lab password-check --file sample_data/sample_passwords.txt
docker compose run --rm security-lab config-check sample_data/demo_docker-compose.yml
```

Notes on isolation:

- `network_mode: none` in [`docker-compose.yml`](../docker-compose.yml) means
  the container has no network access at all — it cannot reach the internet
  or your local network even if the code tried to.
- The container only mounts `sample_data/` read-only; it cannot write
  anywhere on your host.
- Nothing is exposed on any port.

## Option B — Local Python (no Docker)

Requires Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

python -m src.cli log-scan sample_data/sample_auth.log
python -m src.cli password-check --file sample_data/sample_passwords.txt
python -m src.cli config-check sample_data/demo_docker-compose.yml
```

## Running the automated tests

```bash
pytest
```

## Using your own data

All three tools accept any local file path. If you point `log-scan` at a
real auth log or `config-check` at a real compose file, treat that data as
sensitive (see [`docs/legal-and-ethics.md`](legal-and-ethics.md)) — don't
commit real logs or real secrets into this repository.
