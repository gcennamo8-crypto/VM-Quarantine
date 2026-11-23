#!/usr/bin/env bash

set -e

cd /home/tana/VM-Quarantine || exit 1

# Caricamento credenziali OpenStack
source /opt/stack/devstack/openrc demo demo

# SSH Agent dedicato
export SSH_AUTH_SOCK=/run/user/1000/vm-quarantine-agent.sock

echo "[VM QUARANTINE] Monitoraggio avviato"

while true; do
    echo "========== NUOVO CONTROLLO =========="
    date -u

    case "${VMQ_MODE:-dry-run}" in
        real)
            /home/tana/VM-Quarantine/.venv/bin/python \
                src/compliance_controller.py \
                --fetch --notify --apply-quarantine || \
                echo "[VM QUARANTINE] Controllo reale non riuscito"
            ;;
        dry-run)
            /home/tana/VM-Quarantine/.venv/bin/python \
                src/compliance_controller.py --fetch --notify || \
                echo "[VM QUARANTINE] Controllo DRY RUN non riuscito"
            ;;
        *)
            echo "[VM QUARANTINE] VMQ_MODE non valida" >&2
            exit 1
            ;;
    esac

    echo "[VM QUARANTINE] Prossimo controllo dopo 60 secondi"
    sleep 60
done
