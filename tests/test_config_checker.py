import os

from src.config_checker import check_compose_file

DEMO_PATH = os.path.join(
    os.path.dirname(__file__), "..", "sample_data", "demo_docker-compose.yml"
)


def test_flags_privileged_service():
    findings = check_compose_file(DEMO_PATH)
    messages = [f["message"] for f in findings]
    assert any("privileged" in m for m in messages)


def test_flags_dangerous_docker_socket_mount():
    findings = check_compose_file(DEMO_PATH)
    messages = [f["message"] for f in findings]
    assert any("docker.sock" in m for m in messages)


def test_flags_hardcoded_secret_env_var():
    findings = check_compose_file(DEMO_PATH)
    messages = [f["message"] for f in findings]
    assert any("API_KEY" in m for m in messages)


def test_flags_root_user():
    findings = check_compose_file(DEMO_PATH)
    root_findings = [f for f in findings if f["service"] == "demo-db"]
    assert any("root" in f["message"] for f in root_findings)
