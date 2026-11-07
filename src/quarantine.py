
import argparse
import json
from pathlib import Path

import openstack
from logger import setup_logger
from notifier import send_notification
from config_loader import load_config

import os

DEFAULT_VM_NAME = "vm-test-quarantena"

CONFIG = load_config()
QUARANTINE_GROUP = CONFIG["quarantine"]["security_group"]


BACKUP_DIR = Path("/var/lib/vm-quarantine")


def get_backup_file(vm_id):
    return BACKUP_DIR / f"{vm_id}.json"

def connect():
    conn = openstack.connect()
    conn.authorize()
    return conn


def get_resources(conn, vm_identifier):
    vm = conn.compute.find_server(vm_identifier)

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


def show_status(conn, vm_identifier):
    vm, group, ports = get_resources(conn, vm_identifier)
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


def quarantine(conn, vm_identifier, dry_run=False):
    vm, group, ports = get_resources(conn, vm_identifier)

    validate_quarantine_group(conn, group)
    backup_file = get_backup_file(vm.id)

    if backup_file.exists():
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

    fd = os.open(
        backup_file,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600
    )

    with os.fdopen(fd, "w", encoding="utf-8") as file:
        json.dump(backup, file, indent=2)
        file.flush()
        os.fsync(file.fileno())

    try:
        for port in ports:
            conn.network.update_port(
                port.id,
                security_groups=[group.id]
            )
            print(f"Porta {port.id} messa in quarantena")

    except Exception as error:
        setup_logger().error(
            f"Errore durante la quarantena | "
            f"VM: {vm.name} | Errore: {error}"
        )

        raise RuntimeError(
            f"Quarantena non completata per {vm.name}. "
            f"Verificare lo stato delle porte Neutron. "
            f"Backup conservato in {backup_file}"
        ) from error

    print("\nQuarantena applicata.")

    setup_logger().info(
        f"Quarantena applicata | VM: {vm.name} | "
        f"Security Group: {group.name}"
    )

    send_notification(
        event="QUARANTINE_APPLIED",
        vm_name=vm.name,
        message=f"VM isolata tramite Security Group {group.name}."
    )




def restore(conn, vm_identifier, dry_run=False):
    vm, group, ports = get_resources(conn, vm_identifier)
    backup_file = get_backup_file(vm.id)

    if not backup_file.exists():
        raise RuntimeError(
            f"Backup non disponibile per la VM {vm.name}"
        )

    backup = json.loads(backup_file.read_text())

    if backup["vm_id"] != vm.id:
        raise RuntimeError("Il backup appartiene a un'altra VM")

    port_ids = {p.id for p in ports}
    backup_ids = set(backup["ports"])

    if port_ids != backup_ids:
        raise RuntimeError("Le porte della VM sono cambiate")

    try:
        for port_id, original_groups in backup["ports"].items():
            print(f"Ripristino porta: {port_id}")
            print(f"Security Groups originali: {original_groups}")

            if not dry_run:
                conn.network.update_port(
                    port_id,
                    security_groups=original_groups
                )

    except Exception as error:
        setup_logger().error(
            f"Errore durante il ripristino | "
            f"VM: {vm.name} | Errore: {error}"
        )

        raise RuntimeError(
            f"Ripristino non completato per {vm.name}. "
            f"Verificare lo stato delle porte Neutron. "
            f"Backup conservato in {backup_file}"
        ) from error

    if dry_run:
        print("\n[DRY RUN] Nessuna modifica effettuata.")
        return

    for port_id, original_groups in backup["ports"].items():
        updated_port = conn.network.get_port(port_id)

        if set(updated_port.security_group_ids or []) != set(original_groups):
            raise RuntimeError(
                f"Ripristino non verificato per la porta {port_id}. "
                f"Backup conservato in {backup_file}"
            )

    backup_file.unlink()
    print("\nConfigurazione originale ripristinata.")

    setup_logger().info(
        f"Configurazione originale ripristinata | VM: {vm.name}"
    )

    send_notification(
        event="QUARANTINE_RESTORED",
        vm_name=vm.name,
        message="Security Group originale ripristinato correttamente."
    )


def main():
    parser = argparse.ArgumentParser(
        description="VM Quarantine Manager"
    )

    parser.add_argument(
        "--vm",
        default=DEFAULT_VM_NAME,
        help="Nome o UUID della macchina virtuale OpenStack"
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
           show_status(conn, args.vm)

       elif args.action == "quarantine":
           quarantine(conn, args.vm, args.dry_run)

       elif args.action == "restore":
           restore(conn, args.vm, args.dry_run)

    except Exception as error:
        print(f"ERRORE: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
