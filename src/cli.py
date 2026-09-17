"""Command-line entry point for the local security lab tools."""

from __future__ import annotations

import argparse
import json
import sys

from src import config_checker, log_analyzer, password_checker


def cmd_log_scan(args: argparse.Namespace) -> int:
    findings = log_analyzer.analyze_file(
        args.path,
        failed_threshold=args.threshold,
        distinct_user_threshold=args.distinct_users,
    )
    _print_json_or_table(findings, args.json, empty_message="No suspicious login activity found.")
    return 1 if findings else 0


def cmd_password_check(args: argparse.Namespace) -> int:
    if args.file:
        results = password_checker.check_password_file(args.file)
    elif args.password:
        results = [check_and_label(args.password)]
    else:
        print("Provide --password or --file", file=sys.stderr)
        return 2

    _print_json_or_table(results, args.json, empty_message="No passwords checked.")
    return 1 if any(r["verdict"] != "strong" for r in results) else 0


def check_and_label(password: str) -> dict:
    result = password_checker.check_password(password)
    result["password_masked"] = password_checker._mask(password)
    return result


def cmd_config_check(args: argparse.Namespace) -> int:
    findings = config_checker.check_compose_file(args.path)
    _print_json_or_table(findings, args.json, empty_message="No issues found in compose file.")
    return 1 if findings else 0


def _print_json_or_table(items: list[dict], as_json: bool, empty_message: str) -> None:
    if as_json:
        print(json.dumps(items, indent=2))
        return

    if not items:
        print(empty_message)
        return

    for item in items:
        print("- " + ", ".join(f"{k}={v}" for k, v in item.items()))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-lab",
        description="Local, defensive security lab tools (log analysis, password policy, config checks).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    log_scan = subparsers.add_parser("log-scan", help="Analyze an auth log for suspicious patterns")
    log_scan.add_argument("path", help="Path to a local log file")
    log_scan.add_argument("--threshold", type=int, default=5, help="Failed-attempt threshold per IP")
    log_scan.add_argument("--distinct-users", type=int, default=3, help="Distinct-username threshold per IP")
    log_scan.add_argument("--json", action="store_true", help="Output JSON instead of a table")
    log_scan.set_defaults(func=cmd_log_scan)

    pwd_check = subparsers.add_parser("password-check", help="Check password(s) against the local policy")
    pwd_check.add_argument("--password", help="A single password to check")
    pwd_check.add_argument("--file", help="Path to a file with one password per line")
    pwd_check.add_argument("--json", action="store_true", help="Output JSON instead of a table")
    pwd_check.set_defaults(func=cmd_password_check)

    cfg_check = subparsers.add_parser("config-check", help="Check a docker-compose file for insecure patterns")
    cfg_check.add_argument("path", help="Path to a local docker-compose.yml file")
    cfg_check.add_argument("--json", action="store_true", help="Output JSON instead of a table")
    cfg_check.set_defaults(func=cmd_config_check)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
