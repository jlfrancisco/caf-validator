#!/usr/bin/env python3
"""
Service YAML Validator
Usage: python3 validator.py --mode=warn|enforce service.yaml [exceptions.yaml]
"""

import argparse
import sys
from datetime import date

import yaml


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REQUIRED_FIELDS = [
    "schema_version",
    "service_name",
    "owner",
    "env",
    "data_sensitivity",
    "alerts",
]

VALID_ENVS = {"dev", "staging", "prod"}
VALID_DATA_SENSITIVITIES = {"low", "medium", "high"}

USER_IMPACTING_ALERTS = {
    "high_5xx_rate",
    "p99_latency_breach",
    "auth_errors",
    "request_failures",
    "health_checks_failures",
}

INFRASTRUCTURE_ALERTS = {
    "cpu_high",
    "memory_pressure",
    "disk_full",
}

ALL_VALID_ALERTS = USER_IMPACTING_ALERTS | INFRASTRUCTURE_ALERTS

# Rule identifiers (used for exception matching)
RULE_REQUIRED_FIELDS         = "REQUIRED_FIELDS"
RULE_ENVIRONMENT_NAME_ALERT  = "ENVIRONMENT_NAME_ALERT"
RULE_DATA_SENSITIVITY_ALERT  = "DATA_SENSITIVITY_NAME_ALERT"
RULE_PROD_SYMPTOM_ALERT      = "PROD_SYMPTOM_ALERT"
RULE_RUNBOOK_URL_ALERT       = "RUNBOOK_URL_ALERT"
RULE_BACKUPS_ENABLED_ALERT   = "BACKUPS_ENABLED_ALERT"


# ---------------------------------------------------------------------------
# Output formatting helpers
# ---------------------------------------------------------------------------

def fmt_fail(rule: str, service: str, body: str) -> str:
    """Format a FAIL block matching the spec in readme.md."""
    return (
        f"FAIL: {rule}\n"
        f"Service: {service}\n"
        f"\n"
        f"{body}"
    )


def fmt_exception(exc: dict) -> str:
    """Format an EXCEPTION block matching the spec in readme.md."""
    return (
        f"[EXCEPTION: {exc['rule']}] \n"
        f"Reason: {exc['reason']}\n"
        f"expires: {exc['expires'].isoformat()}\n"
        f"approved_by: {exc['approved_by']}"
    )


# ---------------------------------------------------------------------------
# Exception parsing
# ---------------------------------------------------------------------------

def parse_exceptions(exceptions_raw: list) -> tuple[list, list]:
    """
    Validate and parse the exceptions list.
    Returns (valid_exceptions, parse_errors).
    """
    valid = []
    errors = []
    required_keys = {"rule", "service", "reason", "expires", "approved_by"}

    for i, exc in enumerate(exceptions_raw):
        prefix = f"Exception[{i}]"

        if not isinstance(exc, dict):
            errors.append(f"{prefix}: must be a YAML object.")
            continue

        missing = required_keys - exc.keys()
        if missing:
            errors.append(f"{prefix}: missing fields: {sorted(missing)}.")
            continue

        empty = [k for k in required_keys if exc.get(k) is None or exc.get(k) == ""]
        if empty:
            errors.append(f"{prefix}: empty fields: {sorted(empty)}.")
            continue

        # Parse and validate the expiration date
        expires = exc["expires"]
        if isinstance(expires, date):
            expires_date = expires
        else:
            try:
                expires_date = date.fromisoformat(str(expires))
            except ValueError:
                errors.append(
                    f"{prefix}: 'expires' must be ISO 8601 (YYYY-MM-DD), got: '{expires}'."
                )
                continue

        valid.append({
            "rule":        exc["rule"].upper(),
            "service":     exc["service"],
            "reason":      exc["reason"],
            "expires":     expires_date,
            "approved_by": exc["approved_by"],
        })

    return valid, errors


def find_exception(rule: str, service_name: str, exceptions: list):
    """
    Return the first active (non-expired) exception that matches
    both the rule name and the service name, or None.
    """
    today = date.today()
    for exc in exceptions:
        if exc["rule"] == rule and exc["service"] == service_name:
            if exc["expires"] >= today:
                return exc
    return None


# ---------------------------------------------------------------------------
# Validation rules
# ---------------------------------------------------------------------------

def check_required_fields(data: dict, service_name: str, exceptions: list):
    """
    REQUIRED_FIELDS — all required fields must be present and non-empty.
    Returns (error_message | None, applied_exception | None).
    """
    missing = []
    for field in REQUIRED_FIELDS:
        if field not in data or data[field] is None or data[field] == "" or data[field] == []:
            missing.append(field)

    if not missing:
        return None, None

    exc = find_exception(RULE_REQUIRED_FIELDS, service_name, exceptions)
    if exc:
        return None, exc

    fields_str = ", ".join(f"{f} (str)" for f in missing)
    body = (
        f'Issue: "Some fields are missing"\n'
        f"Missing fields: {fields_str}\n"
        f"\n"
        f"Fix: Required fields must be present and non-empty"
    )
    return fmt_fail(RULE_REQUIRED_FIELDS, service_name, body), None


def check_env(data: dict, service_name: str, exceptions: list):
    """
    ENVIRONMENT_NAME_ALERT — env must be one of dev, staging, prod.
    """
    env = data.get("env", "")
    if env in VALID_ENVS:
        return None, None

    exc = find_exception(RULE_ENVIRONMENT_NAME_ALERT, service_name, exceptions)
    if exc:
        return None, exc

    body = (
        f'Issue: "env name must be dev, staging or prod"\n'
        f'Found: "{env}"\n'
        f"\n"
        f'Example: "env: prod"'
    )
    return fmt_fail(RULE_ENVIRONMENT_NAME_ALERT, service_name, body), None


def check_data_sensitivity(data: dict, service_name: str, exceptions: list):
    """
    DATA_SENSITIVITY_NAME_ALERT — data_sensitivity must be one of low, medium, high.
    """
    sensitivity = data.get("data_sensitivity", "")
    if sensitivity in VALID_DATA_SENSITIVITIES:
        return None, None

    exc = find_exception(RULE_DATA_SENSITIVITY_ALERT, service_name, exceptions)
    if exc:
        return None, exc

    body = (
        f'Issue: "data_sensitivity must be low, medium or high"\n'
        f'Found: "{sensitivity}"\n'
        f"\n"
        f'Example: "data_sensitivity: medium"'
    )
    return fmt_fail(RULE_DATA_SENSITIVITY_ALERT, service_name, body), None


def check_prod_symptom_alert(data: dict, service_name: str, exceptions: list):
    """
    PROD_SYMPTOM_ALERT — if env is prod, at least one user-impacting alert is required.
    """
    if data.get("env") != "prod":
        return None, None

    alerts = data.get("alerts", [])
    if not isinstance(alerts, list):
        alerts = []

    has_user_impacting = any(a in USER_IMPACTING_ALERTS for a in alerts)
    if has_user_impacting:
        return None, None

    exc = find_exception(RULE_PROD_SYMPTOM_ALERT, service_name, exceptions)
    if exc:
        return None, exc

    found_str = str([a for a in alerts if a in ALL_VALID_ALERTS])
    body = (
        f'Issue: "No symptom-based alerts found"\n'
        f"Found: {found_str}\n"
        f"\n"
        f"Need: At least one alert about user-facing symptoms\n"
        f'Examples: "high_5xx_rate", "p99_latency_breach", "auth_errors", "request_failures", "health_checks_failures"\n'
        f"Fix: Add an alert that monitors service behaviour, not just resources"
    )
    return fmt_fail(RULE_PROD_SYMPTOM_ALERT, service_name, body), None


def check_runbook_url(data: dict, service_name: str, exceptions: list):
    """
    RUNBOOK_URL_ALERT — if env is prod, runbook_url must be present and non-empty.
    """
    if data.get("env") != "prod":
        return None, None

    runbook = data.get("runbook_url")
    if runbook and str(runbook).strip():
        return None, None

    exc = find_exception(RULE_RUNBOOK_URL_ALERT, service_name, exceptions)
    if exc:
        return None, exc

    body = (
        f'Issue: "For production environment, a runbook url is required"\n'
        f"\n"
        f"Need: At least one runbook url must be specified."
    )
    return fmt_fail(RULE_RUNBOOK_URL_ALERT, service_name, body), None


def check_backups_enabled(data: dict, service_name: str, exceptions: list):
    """
    BACKUPS_ENABLED_ALERT — if env is prod and data_sensitivity is high,
    backup_enabled must be true.
    """
    if data.get("env") != "prod":
        return None, None
    if data.get("data_sensitivity") != "high":
        return None, None

    if data.get("backup_enabled") is True:
        return None, None

    exc = find_exception(RULE_BACKUPS_ENABLED_ALERT, service_name, exceptions)
    if exc:
        return None, exc

    body = (
        f'Issue: "For production environment with high data sensitivity, backup_enabled: true is required"\n'
        f"\n"
        f"Need: backup_enabled must be set to true."
    )
    return fmt_fail(RULE_BACKUPS_ENABLED_ALERT, service_name, body), None


# ---------------------------------------------------------------------------
# Main validation orchestrator
# ---------------------------------------------------------------------------

def validate(data: dict, exceptions: list):
    """
    Run all validation rules against the service data.
    Returns (failures, applied_exceptions).
    """
    # Resolve the service name as early as possible for error messages
    service_name = data.get("service_name") or "UNKNOWN"

    failures: list[str]    = []
    applied:  list[dict]   = []

    checks = [
        check_required_fields,
        check_env,
        check_data_sensitivity,
        check_prod_symptom_alert,
        check_runbook_url,
        check_backups_enabled,
    ]

    for check_fn in checks:
        error, exc = check_fn(data, service_name, exceptions)
        if exc:
            applied.append(exc)
        elif error:
            failures.append(error)

    return failures, applied


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Validate a service.yaml file against defined rules."
    )
    parser.add_argument(
        "--mode",
        choices=["warn", "enforce"],
        default="warn",
        help="warn: exit 0 on failures | enforce: exit 1 on failures",
    )
    parser.add_argument(
        "service_yaml",
        help="Path to the service YAML file (e.g. service.yaml)",
    )
    parser.add_argument(
        "exceptions_yaml",
        nargs="?",
        default=None,
        help="Path to the exceptions YAML file (optional)",
    )

    args = parser.parse_args()

    # --- Load service.yaml ---
    try:
        with open(args.service_yaml, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"ERROR: File not found: {args.service_yaml}", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"ERROR: Failed to parse {args.service_yaml}: {e}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(data, dict):
        print("ERROR: service.yaml must contain a YAML object at the root level.", file=sys.stderr)
        sys.exit(1)

    # --- Load exceptions.yaml (optional) ---
    exceptions: list = []
    if args.exceptions_yaml:
        try:
            with open(args.exceptions_yaml, "r", encoding="utf-8") as f:
                exc_raw = yaml.safe_load(f)
        except FileNotFoundError:
            print(f"ERROR: Exceptions file not found: {args.exceptions_yaml}", file=sys.stderr)
            sys.exit(1)
        except yaml.YAMLError as e:
            print(f"ERROR: Failed to parse {args.exceptions_yaml}: {e}", file=sys.stderr)
            sys.exit(1)

        if exc_raw is not None:
            if not isinstance(exc_raw, list):
                print("ERROR: exceptions.yaml must contain a list of exception objects.", file=sys.stderr)
                sys.exit(1)

            exceptions, parse_errors = parse_exceptions(exc_raw)
            if parse_errors:
                print("ERROR: Invalid exception entries:", file=sys.stderr)
                for err in parse_errors:
                    print(f"  - {err}", file=sys.stderr)
                sys.exit(1)

    # --- Run validation ---
    failures, applied_exceptions = validate(data, exceptions)

    # --- Print applied exceptions ---
    for exc in applied_exceptions:
        print(fmt_exception(exc))
        print()

    # --- Print failures ---
    for failure in failures:
        print(failure)
        print()

    # --- Summary and exit code ---
    total_issues  = len(failures)
    total_excepted = len(applied_exceptions)

    if total_issues == 0 and total_excepted == 0:
        print("OK: All validation rules passed.")
        sys.exit(0)

    if total_issues == 0 and total_excepted > 0:
        print(f"OK (with {total_excepted} exception(s) applied): Validation passed.")
        sys.exit(0)

    # There are actual failures
    print(f"Found {total_issues} issue(s).", end="")
    if total_excepted:
        print(f" {total_excepted} exception(s) applied.", end="")
    print()

    # enforce mode exits non-zero; warn mode always exits 0
    sys.exit(1 if args.mode == "enforce" else 0)


if __name__ == "__main__":
    main()