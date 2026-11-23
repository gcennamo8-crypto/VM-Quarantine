#!/usr/bin/env python3

import argparse
import sys
import openstack

VM_ID = "02952f12-af9a-44f5-87a8-15d3412e599e"
PORT_ID = "d0b7f99f-3813-44da-a09d-e6a7c61a1add"

ORIGINAL_SG = "89eea6bf-ece1-45e6-864e-8e287d0b79e0"
QUARANTINE_SG = "419c86d7-7d25-4954-a3cb-5c5fced4f78f"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--restore", action="store_true")
    args = parser.parse_args()

    conn = openstack.connect()
    conn.authorize()

    port = conn.network.get_port(PORT_ID)

    if port is None:
        raise RuntimeError("Porta Neutron non trovata")

    if port.device_id != VM_ID:
        raise RuntimeError("Identità della VM non corrispondente")

    current = set(port.security_group_ids or [])

    print("VM:", VM_ID)
    print("Security Group attuali:", sorted(current))
    print("Security Group originale:", ORIGINAL_SG)

    if not args.restore:
        print("[CHECK] Nessuna modifica effettuata")
        return

    if current != {QUARANTINE_SG}:
        raise RuntimeError(
            "La porta non è nella quarantena attesa. "
            "Ripristino automatico rifiutato."
        )

    conn.network.update_port(
        PORT_ID,
        security_groups=[ORIGINAL_SG]
    )

    updated = conn.network.get_port(PORT_ID)

    if set(updated.security_group_ids or []) != {ORIGINAL_SG}:
        raise RuntimeError(
            "Ripristino non verificato: controllare Neutron"
        )

    print("[OK] Security Group originale ripristinato")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("ERRORE:", error, file=sys.stderr)
        sys.exit(1)
