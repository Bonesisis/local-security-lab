from src.log_analyzer import analyze

BRUTE_FORCE_LINES = [
    "Sep 14 03:20:0{0} lab-host sshd[100{0}]: Failed password for admin from 203.0.113.42 port 5151{0} ssh2".format(i)
    for i in range(6)
]

NORMAL_LOGIN_LINES = [
    "Sep 14 08:05:02 lab-host sshd[1101]: Accepted password for luca from 198.51.100.7 port 52210 ssh2",
]


def test_flags_ip_over_failed_threshold():
    findings = analyze(BRUTE_FORCE_LINES, failed_threshold=5)
    assert len(findings) == 1
    assert findings[0]["ip"] == "203.0.113.42"
    assert findings[0]["severity"] in ("high", "critical")


def test_no_findings_for_normal_login():
    findings = analyze(NORMAL_LOGIN_LINES)
    assert findings == []


def test_flags_accepted_login_after_failures_as_critical():
    lines = BRUTE_FORCE_LINES + [
        "Sep 14 03:20:19 lab-host sshd[1007]: Accepted password for admin from 203.0.113.42 port 51521 ssh2"
    ]
    findings = analyze(lines, failed_threshold=5)
    assert findings[0]["severity"] == "critical"


def test_flags_user_enumeration():
    lines = [
        f"Sep 14 09:12:4{i} lab-host sshd[120{i}]: Failed password for invalid user user{i} from 192.0.2.15 port 4001{i} ssh2"
        for i in range(4)
    ]
    findings = analyze(lines, failed_threshold=100, distinct_user_threshold=3)
    assert len(findings) == 1
    assert len(findings[0]["distinct_users"]) == 4
