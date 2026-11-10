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

    /home/tana/VM-Quarantine/.venv/bin/python \
        src/compliance_controller.py --fetch --notify || \
        echo "[VM QUARANTINE] Controllo non riuscito"

    echo "[VM QUARANTINE] Prossimo controllo dopo 60 secondi"
    sleep 60
done
