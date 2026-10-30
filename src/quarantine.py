
import argparse
import json
from pathlib import Path

import openstack
from config_loader import load_config

VM_NAME = "vm-test-quarantena"

CONFIG = load_config()
QUARANTINE_GROUP = CONFIG["quarantine"]["security_group"]


BACKUP_FILE = Path.home() / ".vm-quarantine-backup.json"


def connect():
    conn = openstack.connect()
    conn.authorize()
    return conn


def get_resources(conn):
    vm = conn.compute.find_server(VM_NAME)

    if vm is None:
        raise RuntimeError("VM non trovata")

    group = conn.network.find_security_group(
        QUARANTINE_GROUP
    )

    if group is None:
        raise RuntimeError("Security Group non trovato")

    ports = list(conn.network.ports(device_id=vm.id))

    if not ports:
        raise RuntimeError("Nessuna porta Neutron trovata")

    return vm, group, ports


def show_status(conn):
    vm, group, ports = get_resources(conn)

    print(f"VM: {vm.name}")
    print(f"Stato: {vm.status}")
    print(f"Security Group quarantena: {group.name}")

    for port in ports:
        print(f"\nPorta: {port.id}")
        print(f"Security Groups: {port.security_group_ids}")

def validate_quarantine_group(conn, group):
    config = CONFIG["quarantine"]
    policy = config["policy"]

    rules = list(
        conn.network.security_group_rules(
            security_group_id=group.id
        )
    )

    print("\n[CONTROLLO SECURITY GROUP]")

    if policy["ingress"] == "deny":
        ingress_rules = [
            rule for rule in rules
            if rule.direction == "ingress"
        ]

        if ingress_rules:
            raise RuntimeError(
                "Il Security Group contiene regole Ingress non autorizzate"
            )

    if policy["egress"] == "deny":
        egress_rules = [
            rule for rule in rules
            if rule.direction == "egress"
        ]

        if egress_rules:
            raise RuntimeError(
                "Il Security Group contiene regole Egress non autorizzate"
            )

    print("Security Group verificato: nessuna regola non autorizzata")


def quarantine(conn, dry_run=False):
    vm, group, ports = get_resources(conn)

    validate_quarantine_group(conn, group)

    if BACKUP_FILE.exists():
        raise RuntimeError(
            "Esiste già un backup. "
            "Ripristina prima di applicare una nuova quarantena."
        )

    backup = {
        "vm_id": vm.id,
        "ports": {}
    }

    for port in ports:
        current = list(port.security_group_ids or [])

        if current == [group.id]:
            raise RuntimeError(
                "La VM è già in quarantena. "
                "Nessuna modifica eseguita."
            )

        if not port.is_port_security_enabled:
            raise RuntimeError(
                f"Port security disabilitata: {port.id}"
            )

        backup["ports"][port.id] = current

        print(f"Porta: {port.id}")
        print(f"Security Groups attuali: {current}")
        print(f"Nuovo Security Group: {group.id}")

    if dry_run:
        print("\n[DRY RUN] Nessuna modifica effettuata.")
        return

    with BACKUP_FILE.open("x") as file:
        json.dump(backup, file, indent=2)

    BACKUP_FILE.chmod(0o600)

    for port in ports:
        conn.network.update_port(
            port.id,
            security_groups=[group.id]
        )
        print(f"Porta {port.id} messa in quarantena")

    print("\nQuarantena applicata.")


def restore(conn, dry_run=False):
    if not BACKUP_FILE.exists():
        raise RuntimeError("Backup non disponibile")

    vm, group, ports = get_resources(conn)
    backup = json.loads(BACKUP_FILE.read_text())

    if backup["vm_id"] != vm.id:
        raise RuntimeError("Il backup appartiene a un'altra VM")

    port_ids = {p.id for p in ports}
    backup_ids = set(backup["ports"])

    if port_ids != backup_ids:
        raise RuntimeError("Le porte della VM sono cambiate")

    for port_id, original_groups in backup["ports"].items():
        print(f"Ripristino porta: {port_id}")
        print(f"Security Groups originali: {original_groups}")

        if not dry_run:
            conn.network.update_port(
                port_id,
                security_groups=original_groups
            )

    if dry_run:
        print("\n[DRY RUN] Nessuna modifica effettuata.")
        return

    BACKUP_FILE.unlink()
    print("\nConfigurazione originale ripristinata.")


def main():
    parser = argparse.ArgumentParser(
        description="VM Quarantine Manager"
    )

    parser.add_argument(
        "action",
        choices=["status", "quarantine", "restore"]
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Mostra le modifiche senza applicarle"
    )

    args = parser.parse_args()
    conn = connect()

    try:
        if args.action == "status":
            show_status(conn)

        elif args.action == "quarantine":
            quarantine(conn, args.dry_run)

        elif args.action == "restore":
            restore(conn, args.dry_run)

    except Exception as error:
        print(f"ERRORE: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
