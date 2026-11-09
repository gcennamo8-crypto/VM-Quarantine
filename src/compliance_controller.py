import json
import argparse
import os
import subprocess
import sys
from datetime import datetime, timezone
import yaml
import quarantine as quarantine_manager
from notifier import send_notification

from pathlib import Path


EXPECTED_VM_ID = "02952f12-af9a-44f5-87a8-15d3412e599e"
VM_IP = "10.0.0.41"
VM_USER = "debian"

SSH_KEY = "/home/tana/.ssh/vm-quarantine-key"

NETWORK_NAMESPACE = (
    "ovnmeta-0faf4f95-583d-4c8b-8ae2-b31b63f29feb"
)


def fetch_report():
    ssh_auth_sock = os.environ.get("SSH_AUTH_SOCK")

    if not ssh_auth_sock:
        raise ValueError("SSH Agent non disponibile")

    command = [
        "sudo", "--preserve-env=SSH_AUTH_SOCK",
        "ip", "netns", "exec", NETWORK_NAMESPACE,
        "sudo", "-u", "tana",
        "env", f"SSH_AUTH_SOCK={ssh_auth_sock}",
        "ssh",
        "-i", SSH_KEY,
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=10",
        f"{VM_USER}@{VM_IP}",
        (
            "cd /home/debian/vm-quarantine-agent "
            "&& sudo -n python3 src/compliance_agent.py --json"
        ),
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )

    return json.loads(result.stdout)


def validate_report(report):
    if not isinstance(report, dict):
        raise ValueError("Report JSON non valido")

    if report.get("vm_id") != EXPECTED_VM_ID:
        raise ValueError("UUID della VM non autorizzato")

    if report.get("vm_name") != "vm-security-compliance":
        raise ValueError("Nome VM non corrispondente")

    # Controllo del timestamp
    timestamp = report.get("timestamp")

    if not isinstance(timestamp, str):
        raise ValueError("Timestamp mancante o non valido")

    try:
        report_time = datetime.fromisoformat(timestamp)
    except ValueError as error:
        raise ValueError("Formato timestamp non valido") from error

    if report_time.tzinfo is None:
        raise ValueError("Timestamp senza fuso orario")

    age = (
        datetime.now(timezone.utc)
        - report_time.astimezone(timezone.utc)
    ).total_seconds()

    if abs(age) > 300:
        raise ValueError("Report scaduto o con data futura")

    # Policy attendibili presenti sul controller
    policy_file = (
        Path(__file__).resolve().parent.parent
        / "config"
        / "ssh-policies.yaml"
    )

    with policy_file.open("r", encoding="utf-8") as file:
        config = yaml.safe_load(file)

    trusted_policies = config["policies"]
    reported_policies = report.get("policies")

    if not isinstance(reported_policies, dict):
        raise ValueError("Sezione policies non valida")

    if set(reported_policies) != set(trusted_policies):
        raise ValueError("Elenco delle policy non corrispondente")

    expected_violations = []
    has_unknown = False

    for policy_id, trusted in trusted_policies.items():
        reported = reported_policies[policy_id]

        if not isinstance(reported, dict):
            raise ValueError(f"Policy {policy_id} non valida")

        parameter = trusted["parameter"]
        expected = str(trusted["expected"]).lower()
        severity = trusted["severity"]

        if reported.get("parameter") != parameter:
            raise ValueError(f"Parametro errato: {policy_id}")

        if reported.get("expected") != expected:
            raise ValueError(f"Valore atteso errato: {policy_id}")

        if reported.get("severity") != severity:
            raise ValueError(f"Gravità errata: {policy_id}")

        actual = reported.get("actual")

        if actual is not None and not isinstance(actual, str):
            raise ValueError(f"Valore effettivo non valido: {policy_id}")

        if actual is None:
            expected_status = "UNKNOWN"
            has_unknown = True
        elif actual.lower() == expected:
            expected_status = "COMPLIANT"
        else:
            expected_status = "NON_COMPLIANT"

            expected_violations.append({
                "policy_id": policy_id,
                "parameter": parameter,
                "actual": actual,
                "expected": expected,
                "severity": severity,
            })

        if reported.get("status") != expected_status:
            raise ValueError(f"Stato incoerente: {policy_id}")

    # Verifica delle violazioni dichiarate
    violations = report.get("violations")

    if not isinstance(violations, list):
        raise ValueError("Elenco violazioni non valido")

    if violations != expected_violations:
        raise ValueError("Violazioni incoerenti con le policy")

    # Verifica dello stato complessivo
    if has_unknown:
        expected_overall = "UNKNOWN"
    elif expected_violations:
        expected_overall = "NON_COMPLIANT"
    else:
        expected_overall = "COMPLIANT"

    if report.get("status") != expected_overall:
        raise ValueError("Stato complessivo incoerente")

    return True


def simulate_quarantine(vm_id):
    if vm_id != EXPECTED_VM_ID:
        raise ValueError("Tentativo di quarantena su VM non autorizzata")

    print("\n[OPENSTACK NEUTRON - DRY RUN]", flush=True)

    project_dir = Path(__file__).resolve().parent.parent
    python_executable = project_dir / ".venv" / "bin" / "python"
    quarantine_script = project_dir / "src" / "quarantine.py"

    command = [
        "sudo",
        "--preserve-env=OS_AUTH_TYPE,OS_AUTH_URL,OS_CACERT,OS_PASSWORD,"
        "OS_PROJECT_DOMAIN_ID,OS_PROJECT_NAME,OS_REGION_NAME,"
        "OS_USER_DOMAIN_ID,OS_USERNAME",
        str(python_executable),
        str(quarantine_script),
        "quarantine",
        "--vm",
        vm_id,
        "--dry-run",
    ]

    subprocess.run(
        command,
        check=True,
        timeout=60,
    )


def notify_compliance_violation(report, critical_violations):
    vm_name = report["vm_name"]

    policy_ids = ", ".join(
        violation["policy_id"]
        for violation in critical_violations
    )

    message = (
        f"Rilevata configurazione SSH non conforme.\n"
        f"VM UUID: {report['vm_id']}\n"
        f"Policy violate: {policy_ids}\n"
        f"Gravità: critical\n"
        f"Stato: DRY RUN\n"
        f"Quarantena NON applicata."
    )

    send_notification(
        event="SSH_COMPLIANCE_VIOLATION_DRY_RUN",
        vm_name=vm_name,
        message=message,
    )

def analyze_report(report, notify=False):
    validate_report(report)

    critical_violations = [
        violation
        for violation in report["violations"]
        if violation.get("severity") == "critical"
    ]

    print("\n[VM QUARANTINE - COMPLIANCE CONTROLLER]")
    print(f"VM: {report.get('vm_name')}")
    print(f"UUID: {report['vm_id']}")
    print(f"Stato: {report['status']}")

    if critical_violations:
        print("\n[DRY RUN] Violazioni critiche rilevate:")

        for violation in critical_violations:
            print(f"- {violation['policy_id']}")

        print("Quarantena richiesta, ma NON applicata.")

        simulate_quarantine(report["vm_id"])

        if notify:
            notify_compliance_violation(report, critical_violations)
    else:
        print("\nNessuna violazione critica rilevata.")

def main():
    parser = argparse.ArgumentParser(
        description="VM Quarantine - Compliance Controller"
    )

    parser.add_argument(
        "--fetch",
        action="store_true",
        help="Recupera il report dalla VM Debian tramite SSH"
    )

    parser.add_argument(
        "--notify",
        action="store_true",
        help="Invia una notifica email per violazioni SSH critiche"
    )

    args = parser.parse_args()

    try:
        if args.fetch:
            report = fetch_report()
        else:
            report = json.load(sys.stdin)

        if args.notify and not args.fetch:
            raise ValueError(
                "L'opzione --notify richiede --fetch"
            )

        analyze_report(report, notify=args.notify)

    except subprocess.TimeoutExpired:
        print("ERRORE: Timeout della connessione SSH", file=sys.stderr)
        raise SystemExit(1)

    except subprocess.CalledProcessError as error:
        print(
            f"ERRORE: Connessione SSH fallita (codice {error.returncode})",
            file=sys.stderr,
        )
        if error.stderr:
            print(error.stderr.strip(), file=sys.stderr)
        raise SystemExit(1)

    except (json.JSONDecodeError, ValueError, KeyError, TypeError) as error:
        print(f"ERRORE: Report non valido: {error}", file=sys.stderr)
        raise SystemExit(1)

if __name__ == "__main__":
    main()
