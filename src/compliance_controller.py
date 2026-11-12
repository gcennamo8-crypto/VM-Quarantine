
import argparse
import fcntl
import json
import os
import subprocess
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import yaml

import quarantine as quarantine_manager
from horizon_report import save_horizon_report
from notifier import send_notification
from notification_state import (
    STATE_DIR,
    get_violation_signature,
    load_notification_state,
    save_notification_state,
)


BASE_DIR = Path(__file__).resolve().parent.parent

EXPECTED_VM_ID = "02952f12-af9a-44f5-87a8-15d3412e599e"
EXPECTED_VM_NAME = "vm-security-compliance"

VM_IP = "10.0.0.41"
VM_USER = "debian"

SSH_KEY = "/home/tana/.ssh/vm-quarantine-key"

NETWORK_NAMESPACE = (
    "ovnmeta-0faf4f95-583d-4c8b-8ae2-b31b63f29feb"
)

POLICY_FILE = BASE_DIR / "config" / "ssh-policies.yaml"
NOTIFICATION_LOCK = STATE_DIR / ".notification.lock"


def fetch_report():
    ssh_auth_sock = os.environ.get("SSH_AUTH_SOCK")

    if not ssh_auth_sock:
        raise ValueError("SSH Agent non disponibile")

    command = [
        "sudo", "-n",
        "ip", "netns", "exec", NETWORK_NAMESPACE,
        "sudo", "-n", "-u", "tana",
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
        timeout=60,
        check=True,
    )

    return json.loads(result.stdout)


def validate_report(report):
    if not isinstance(report, dict):
        raise ValueError("Report JSON non valido")

    if report.get("vm_id") != EXPECTED_VM_ID:
        raise ValueError("UUID della VM non autorizzato")

    if report.get("vm_name") != EXPECTED_VM_NAME:
        raise ValueError("Nome VM non corrispondente")

    timestamp = report.get("timestamp")

    if not isinstance(timestamp, str):
        raise ValueError("Timestamp mancante o non valido")

    try:
        report_time = datetime.fromisoformat(timestamp)
    except ValueError as error:
        raise ValueError(
            "Formato timestamp non valido"
        ) from error

    if report_time.tzinfo is None:
        raise ValueError("Timestamp senza fuso orario")

    age = (
        datetime.now(timezone.utc)
        - report_time.astimezone(timezone.utc)
    ).total_seconds()

    if abs(age) > 300:
        raise ValueError("Report scaduto o con data futura")

    with POLICY_FILE.open("r", encoding="utf-8") as file:
        config = yaml.safe_load(file)

    if (
        not isinstance(config, dict)
        or not isinstance(config.get("policies"), dict)
    ):
        raise ValueError("Configurazione policy locale non valida")

    trusted_policies = config["policies"]
    reported_policies = report.get("policies")

    if not isinstance(reported_policies, dict):
        raise ValueError("Sezione policies non valida")

    if set(reported_policies) != set(trusted_policies):
        raise ValueError(
            "Elenco delle policy non corrispondente"
        )

    expected_violations = []
    has_unknown = False

    for policy_id, trusted in trusted_policies.items():
        if not isinstance(trusted, dict):
            raise ValueError(
                f"Configurazione locale non valida: {policy_id}"
            )

        reported = reported_policies[policy_id]

        if not isinstance(reported, dict):
            raise ValueError(f"Policy {policy_id} non valida")

        parameter = trusted["parameter"]
        expected = str(trusted["expected"]).lower()
        severity = trusted["severity"]

        if reported.get("parameter") != parameter:
            raise ValueError(f"Parametro errato: {policy_id}")

        if reported.get("expected") != expected:
            raise ValueError(
                f"Valore atteso errato: {policy_id}"
            )

        if reported.get("severity") != severity:
            raise ValueError(f"Gravità errata: {policy_id}")

        actual = reported.get("actual")

        if actual is not None and not isinstance(actual, str):
            raise ValueError(
                f"Valore effettivo non valido: {policy_id}"
            )

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

    violations = report.get("violations")

    if not isinstance(violations, list):
        raise ValueError("Elenco violazioni non valido")

    if violations != expected_violations:
        raise ValueError(
            "Violazioni incoerenti con le policy"
        )

    if has_unknown:
        expected_overall = "UNKNOWN"
    elif expected_violations:
        expected_overall = "NON_COMPLIANT"
    else:
        expected_overall = "COMPLIANT"

    if report.get("status") != expected_overall:
        raise ValueError("Stato complessivo incoerente")

    return True


def check_quarantine_state():
    """
    Controlla tramite Neutron se la VM e' gia' isolata.

    Non tenta connessioni SSH e non modifica la rete.
    """
    conn = quarantine_manager.connect()

    vm, group, ports = quarantine_manager.get_resources(
        conn, EXPECTED_VM_ID
    )

    if vm.id != EXPECTED_VM_ID:
        raise RuntimeError("Identita' OpenStack inattesa")

    isolated_ports = []

    for port in ports:
        groups = set(port.security_group_ids or [])

        if group.id in groups and groups != {group.id}:
            raise RuntimeError(
                f"Security Group misti sulla porta {port.id}"
            )

        isolated_ports.append(groups == {group.id})

    if all(isolated_ports):
        return "QUARANTINED"

    if any(isolated_ports):
        raise RuntimeError(
            "Quarantena parziale: verifica manuale necessaria"
        )

    return "NOT_QUARANTINED"


def execute_quarantine(vm_id, dry_run=True):
    if vm_id != EXPECTED_VM_ID:
        raise ValueError(
            "Tentativo di quarantena su VM non autorizzata"
        )

    mode = "DRY RUN" if dry_run else "REALE"
    print(f"\n[OPENSTACK NEUTRON - {mode}]", flush=True)

    python_executable = BASE_DIR / ".venv" / "bin" / "python"
    quarantine_script = BASE_DIR / "src" / "quarantine.py"

    command = []

    # Solo la quarantena reale richiede privilegi amministrativi.
    if not dry_run:
        command.extend([
            "sudo",
            "-n",
            "--preserve-env=OS_AUTH_TYPE,OS_AUTH_URL,OS_CACERT,"
            "OS_PASSWORD,OS_PROJECT_DOMAIN_ID,OS_PROJECT_NAME,"
            "OS_REGION_NAME,OS_USER_DOMAIN_ID,OS_USERNAME",
        ])

    command.extend([
        str(python_executable),
        str(quarantine_script),
        "quarantine",
        "--vm",
        vm_id,
    ])

    if dry_run:
        command.append("--dry-run")

    subprocess.run(
        command,
        check=True,
        timeout=60,
    )


@contextmanager
def notification_lock():
    STATE_DIR.mkdir(mode=0o700, exist_ok=True)

    fd = os.open(
        NOTIFICATION_LOCK,
        os.O_CREAT | os.O_RDWR,
        0o600,
    )

    with os.fdopen(fd, "r+") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)

        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def notify_compliance_violation(report, critical_violations):
    vm_id = report["vm_id"]
    vm_name = report["vm_name"]

    signature = get_violation_signature(
        critical_violations
    )

    with notification_lock():
        state = load_notification_state()

        previous = state.get(vm_id, {})
        previous_signature = previous.get(
            "notified_violations", []
        )

        if previous_signature == signature:
            print(
                "\n[EMAIL] Violazione gia' notificata. "
                "Nessuna nuova email inviata."
            )
            return True

        message = (
            "Rilevata configurazione SSH non conforme.\n"
            f"VM UUID: {vm_id}\n"
            f"Policy violate: {', '.join(signature)}\n"
            "Gravita': critical\n"
            "Stato: DRY RUN\n"
            "Quarantena NON applicata."
        )

        sent = send_notification(
            event="SSH_COMPLIANCE_VIOLATION_DRY_RUN",
            vm_name=vm_name,
            message=message,
        )

        if sent is not True:
            print(
                "[STATO] Email non confermata: "
                "violazione non registrata."
            )
            return False

        state[vm_id] = {
            "notified_violations": signature,
            "last_notification": (
                datetime.now(timezone.utc).isoformat()
            ),
        }

        save_notification_state(state)

        print(
            "[STATO] Violazione registrata come notificata."
        )
        return True


def clear_notification_state(vm_id):
    with notification_lock():
        state = load_notification_state()

        if vm_id not in state:
            print(
                "[STATO] Nessuna notifica precedente da azzerare."
            )
            return

        del state[vm_id]
        save_notification_state(state)

        print(
            "[STATO] VM conforme: stato notifiche azzerato."
        )


def analyze_report(
    report,
    notify=False,
    trusted_source=False,
    apply_quarantine=False,
):
    validate_report(report)

    # Pubblica soltanto report verificati e ottenuti dalla VM.
    if trusted_source:
        save_horizon_report(report)

    critical_violations = [
        violation
        for violation in report["violations"]
        if violation.get("severity") == "critical"
    ]

    print("\n[VM QUARANTINE - COMPLIANCE CONTROLLER]")
    print(f"VM: {report['vm_name']}")
    print(f"UUID: {report['vm_id']}")
    print(f"Stato: {report['status']}")

    if report["status"] == "UNKNOWN":
        print(
            "\n[ATTENZIONE] Verifica SSH incompleta. "
            "Nessuna quarantena applicata."
        )
        print("[STATO] Notifiche precedenti conservate.")
        return

    if critical_violations:
        print("\nViolazioni critiche rilevate:")

        for violation in critical_violations:
            print(f"- {violation['policy_id']}")

        if not trusted_source:
            print(
                "[SICUREZZA] Report stdin: "
                "operazioni Neutron disabilitate."
            )
            return

        if apply_quarantine:
            print(
                "\n[AZIONE] Richiesta quarantena reale."
            )

            execute_quarantine(
                report["vm_id"],
                dry_run=False,
            )

            print(
                "[AZIONE] Operazione di quarantena "
                "terminata."
            )

            # quarantine.py invia gia' QUARANTINE_APPLIED.
            # Evitiamo una seconda email dello stesso evento.
            return

        print(
            "Quarantena richiesta, ma NON applicata."
        )

        execute_quarantine(
            report["vm_id"],
            dry_run=True,
        )

        if notify:
            notify_compliance_violation(
                report,
                critical_violations,
            )

    else:
        print("\nNessuna violazione critica rilevata.")

        if (
            notify
            and trusted_source
            and report["status"] == "COMPLIANT"
        ):
            clear_notification_state(report["vm_id"])


def main():
    parser = argparse.ArgumentParser(
        description="VM Quarantine - Compliance Controller"
    )

    parser.add_argument(
        "--fetch",
        action="store_true",
        help="Recupera il report Debian tramite SSH",
    )

    parser.add_argument(
        "--notify",
        action="store_true",
        help="Invia email senza duplicati in DRY RUN",
    )

    parser.add_argument(
        "--apply-quarantine",
        action="store_true",
        help=(
            "ABILITA la quarantena reale tramite Neutron. "
            "Usare soltanto per test controllati."
        ),
    )

    args = parser.parse_args()

    try:
        if args.notify and not args.fetch:
            raise ValueError(
                "L'opzione --notify richiede --fetch"
            )

        if args.apply_quarantine and not args.fetch:
            raise ValueError(
                "La quarantena reale richiede --fetch"
            )

        if args.apply_quarantine and args.notify:
            raise ValueError(
                "Non combinare --apply-quarantine e --notify: "
                "quarantine.py gestisce gia' le notifiche reali"
            )

        if args.fetch:
            status = check_quarantine_state()

            if status == "QUARANTINED":
                print(
                    "\n[VM QUARANTINE] "
                    "La VM e' gia' isolata tramite Neutron."
                )
                print(
                    "Nessun nuovo tentativo SSH o "
                    "di quarantena."
                )
                return

            report = fetch_report()

        else:
            report = json.load(sys.stdin)

        analyze_report(
            report,
            notify=args.notify,
            trusted_source=args.fetch,
            apply_quarantine=args.apply_quarantine,
        )

    except subprocess.TimeoutExpired:
        print(
            "ERRORE: Timeout SSH o Neutron",
            file=sys.stderr,
        )
        raise SystemExit(1)

    except subprocess.CalledProcessError as error:
        print(
            f"ERRORE: Comando esterno fallito "
            f"(codice {error.returncode})",
            file=sys.stderr,
        )

        if error.stderr:
            print(error.stderr.strip(), file=sys.stderr)

        raise SystemExit(1)

    except (
        json.JSONDecodeError,
        ValueError,
        KeyError,
        TypeError,
        RuntimeError,
        OSError,
        yaml.YAMLError,
    ) as error:
        print(
            f"ERRORE: {error}",
            file=sys.stderr,
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
