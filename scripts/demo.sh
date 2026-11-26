#!/usr/bin/env bash
# VM Quarantine — dimostrazione guidata per laboratorio OpenStack.
# Non applica la quarantena direttamente: la applica il monitor in REAL.
# START, STOP e RESTORE rimangono operazioni da eseguire su Horizon.

set -Eeuo pipefail

VM_NAME="vm-security-compliance"
VM_ID="02952f12-af9a-44f5-87a8-15d3412e599e"
VM_IP="10.0.0.41"
VM_USER="debian"
HOST_USER="tana"
NETNS="ovnmeta-0faf4f95-583d-4c8b-8ae2-b31b63f29feb"
SSH_KEY="/home/tana/.ssh/vm-quarantine-key"
AGENT_SOCK="/run/user/1000/vm-quarantine-agent.sock"
GUEST_DIR="/home/debian/vm-quarantine-agent"
GUEST_POLICY_FILE="/etc/ssh/sshd_config.d/00-vm-quarantine.conf"
MANAGER="/opt/vm-quarantine/run_manager.sh"
SERVICE="vm-quarantine-monitor.service"
HORIZON_URL="http://192.168.141.132/dashboard/project/vm_quarantine/"

say() { printf '\n%s\n' "$*"; }
err() { printf 'ERRORE: %s\n' "$*" >&2; }
line() { printf '%s\n' '------------------------------------------------------------'; }
pause() { read -r -p 'Premi INVIO per tornare al menu...' _ || true; }

# Non chiediamo mai la passphrase e non mostriamo il contenuto della chiave.
remote() {
  sudo -n ip netns exec "$NETNS" \
    runuser -u "$HOST_USER" -- \
    env "SSH_AUTH_SOCK=$AGENT_SOCK" \
    ssh -o BatchMode=yes -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=yes -o ConnectTimeout=10 \
        -i "$SSH_KEY" "${VM_USER}@${VM_IP}" "$@"
}

manager_status() { sudo -n "$MANAGER" status; }

quarantine_state() {
  local result
  result="$(manager_status)" || return 1
  awk -F ': ' '$1 == "Stato" {print $2}' <<< "$result"
}

monitor_active() { systemctl --user is-active --quiet "$SERVICE"; }

monitor_mode() {
  systemctl --user show "$SERVICE" -p Environment --value
}

require_real_mode() {
  local env_value
  env_value="$(monitor_mode)" || { err 'Impossibile leggere VMQ_MODE.'; return 1; }
  if ! grep -Eq '(^|[[:space:]])VMQ_MODE=real($|[[:space:]])' <<< "$env_value"; then
    err "Modalita' REAL non confermata: ${env_value:-nessuna variabile}."
    return 1
  fi
}

require_not_quarantined() {
  local state
  state="$(quarantine_state)" || { err 'Stato quarantena non leggibile.'; return 1; }
  [[ "$state" == 'NOT_QUARANTINED' ]] || {
    err "La VM non e' in stato NOT_QUARANTINED (stato: $state)."
    return 1
  }
}

require_inactive() {
  if monitor_active; then
    err "Il monitor e' ancora attivo: premi STOP su Horizon prima di proseguire."
    return 1
  fi
}

confirm_word() {
  local expected="$1" label="$2" answer
  read -r -p "$label (scrivi $expected): " answer || return 1
  [[ "$answer" == "$expected" ]] || { say 'Operazione annullata.'; return 1; }
}

read_report() {
  remote "cd '$GUEST_DIR' && sudo -n python3 src/compliance_agent.py --json"
}

report_status() {
  local report="$1"
  python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])' <<< "$report"
}

preflight() {
  say '=== PREPARAZIONE E STATO INIZIALE ==='
  say "VM: $VM_NAME ($VM_IP)"
  say "Dashboard Horizon: $HORIZON_URL"
  printf 'Monitor: '
  systemctl --user is-active "$SERVICE" || true
  printf 'Modalita':
  monitor_mode || true
  printf '\n'
  manager_status || return 1
  say "Chiavi caricate nell'SSH Agent:"
  SSH_AUTH_SOCK="$AGENT_SOCK" ssh-add -l || {
    say 'Se manca la chiave, caricala manualmente (inserisci la passphrase quando richiesta):'
    printf 'SSH_AUTH_SOCK=%q ssh-add %q\n' "$AGENT_SOCK" "$SSH_KEY"
    return 1
  }
  say 'Test accesso Debian:'
  remote 'echo SSH_OK; hostname; whoami'
}

show_report() {
  local report
  say '=== REPORT DEL COMPLIANCE AGENT ==='
  require_not_quarantined || return 1
  report="$(read_report)" || return 1
  python3 -m json.tool <<< "$report"
}

start_horizon() {
  say '=== AVVIA MONITORAGGIO DA HORIZON ==='
  require_real_mode || return 1
  require_not_quarantined || return 1
  if monitor_active; then
    say "Monitor gia' attivo."
    return 0
  fi
  say "Apri $HORIZON_URL"
  say 'Verifica la console della VM, poi premi START sul pannello VM Quarantine.'
  read -r -p 'Dopo START premi INVIO per verificare...' _ || return 1
  if monitor_active; then
    say 'OK: monitor attivo.'
  else
    err 'Monitor non attivo: controlla il messaggio su Horizon.'
    return 1
  fi
}

show_logs_state() {
  say '=== LOG MONITORAGGIO (inclusi timestamp) ==='
  journalctl --user -u "$SERVICE" -n 55 --no-pager || true
  say '=== STATO NEUTRON ==='
  manager_status
}

# Cambia solo il file dedicato alla demo. Richiede il valore precedente atteso;
# se la modifica non supera sshd -t o il reload, tenta il ripristino.
# I comandi sudo sono quelli gia' verificati nella demo (tee, sshd, systemctl).
change_guest_policy() {
  local previous="$1" next="$2"
  remote "bash -s -- '$previous' '$next'" <<'REMOTE_SCRIPT'
set -Eeuo pipefail
previous="$1"
next="$2"
policy_file='/etc/ssh/sshd_config.d/00-vm-quarantine.conf'
[[ "$previous" == 'yes' || "$previous" == 'no' ]] || exit 2
[[ "$next" == 'yes' || "$next" == 'no' ]] || exit 2
if [[ ! -f "$policy_file" ]]; then
  echo 'ERRORE: file della demo non trovato; nessuna modifica eseguita.' >&2
  exit 1
fi
actual="$(cat "$policy_file")"
if [[ "$actual" != "PermitRootLogin $previous" ]]; then
  echo "ERRORE: configurazione inattesa: $actual" >&2
  echo 'Non sovrascrivo un file modificato al di fuori della demo.' >&2
  exit 1
fi
rollback() {
  printf '%s\n' "$actual" | sudo -n tee "$policy_file" >/dev/null || true
  sudo -n /usr/sbin/sshd -t && sudo -n systemctl reload ssh || true
  echo 'Ripristino della configurazione precedente tentato dopo un errore.' >&2
}
trap rollback ERR
printf 'PermitRootLogin %s\n' "$next" | sudo -n tee "$policy_file" >/dev/null
sudo -n /usr/sbin/sshd -t
sudo -n systemctl reload ssh
trap - ERR
sudo -n /usr/sbin/sshd -T | grep '^permitrootlogin '
REMOTE_SCRIPT
}

introduce_violation() {
  say '=== SIMULAZIONE DELLA VIOLAZIONE SSH-03 ==='
  require_real_mode || return 1
  monitor_active || { err 'Avvia prima START da Horizon e verifica COMPLIANT.'; return 1; }
  require_not_quarantined || return 1
  local report
  report="$(read_report)" || return 1
  if ! python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["vm_id"] == sys.argv[1] and d["vm_name"] == sys.argv[2]' "$VM_ID" "$VM_NAME" <<< "$report"; then
    err 'Identita della VM inattesa: modifica bloccata.'
    return 1
  fi
  if [[ "$(report_status "$report")" != 'COMPLIANT' ]]; then
    err "La VM non e' COMPLIANT: modifica bloccata."
    return 1
  fi
  say "ATTENZIONE: PermitRootLogin yes consentira' il login root tramite SSH, se esistono credenziali adatte."
  say "Questa prova va svolta solo nella VM di laboratorio; la quarantena interrompera' SSH."
  confirm_word 'VERIFICATO' 'Hai verificato la connessione Debian sia funzionante?' || return 1
  confirm_word 'VIOLA' 'Confermi la violazione temporanea SSH-03?' || return 1
  change_guest_policy 'no' 'yes' || return 1
  say 'Violazione introdotta. Non fermare il monitor: al controllo successivo dovrebbe isolare la VM.'
  say 'Usa la voce 4 per osservare log, notifica e Security Group.'
}

stop_horizon() {
  say '=== STOP MONITORAGGIO DA HORIZON ==='
  say "Apri $HORIZON_URL e premi STOP."
  read -r -p 'Dopo STOP premi INVIO per verificare...' _ || return 1
  if monitor_active; then
    err 'Il monitor risulta ancora attivo.'
    return 1
  fi
  say 'OK: monitor inattivo. STOP non rimuove la quarantena.'
  manager_status
}

restore_horizon() {
  say '=== RESTORE DEL SECURITY GROUP DA HORIZON ==='
  require_inactive || return 1
  local state
  state="$(quarantine_state)" || return 1
  if [[ "$state" != 'QUARANTINED' ]]; then
    err "RESTORE previsto solo se QUARANTINED (attuale: $state)."
    return 1
  fi
  say "Apri $HORIZON_URL e premi RESTORE / Ripristina VM."
  read -r -p 'Dopo RESTORE premi INVIO per verificare...' _ || return 1
  manager_status
  require_not_quarantined || return 1
  say 'OK: Security Group originale ripristinato.'
  say "ATTENZIONE: SSH-03 e' ancora violata; correggi con la voce 8."
}

correct_policy() {
  say '=== RIPRISTINO SSH-03: PermitRootLogin no ==='
  require_inactive || return 1
  require_not_quarantined || return 1
  confirm_word 'CORREGGI' 'Riportare Debian a PermitRootLogin no?' || return 1
  change_guest_policy 'yes' 'no' || return 1
  say 'Controllo finale delle policy:'
  local report
  report="$(read_report)" || return 1
  python3 -m json.tool <<< "$report"
  if [[ "$(report_status "$report")" == 'COMPLIANT' ]]; then
    say 'OK: Debian nuovamente COMPLIANT.'
  else
    err "Il report non e' COMPLIANT: controlla i dettagli."
    return 1
  fi
}

final_check() {
  say '=== VERIFICA FINALE DELLA DEMO ==='
  if monitor_active; then
    err 'Monitor ancora attivo: ferma il monitor prima di dichiarare la demo chiusa.'
    return 1
  fi
  require_not_quarantined || return 1
  local report
  report="$(read_report)" || return 1
  [[ "$(report_status "$report")" == 'COMPLIANT' ]] || {
    err 'Debian non COMPLIANT.'
    python3 -m json.tool <<< "$report"
    return 1
  }
  manager_status
  say 'RISULTATO: monitor inattivo, SG originale, Debian COMPLIANT.'
}

menu() {
  line
  cat <<'MENU'
 VM QUARANTINE — DEMO GUIDATA

 1) Controlli preliminari (VM, SG, modo, SSH Agent)
 2) Mostra report Compliance Agent (stato iniziale)
 3) START monitor su Horizon + controllo servizio
 4) Mostra log recenti e stato Neutron (ripetibile)
 5) Introduci violazione SSH-03 (PermitRootLogin yes)
 6) STOP monitor su Horizon
 7) RESTORE su Horizon (SG originale)
 8) Correggi SSH-03 (PermitRootLogin no) + report
 9) Verifica finale: COMPLIANT e NOT_QUARANTINED
 0) Esci
MENU
  line
}

main() {
  if [[ "$(id -un)" != "$HOST_USER" ]]; then
    err "Esegui come utente $HOST_USER sull'host Ubuntu (non con sudo)."
    exit 1
  fi
  if [[ ! -f "$SSH_KEY" ]]; then
    err "Chiave SSH non trovata: $SSH_KEY"
    exit 1
  fi
  say "Dashboard Horizon: $HORIZON_URL"
  say 'Questa demo non applica mai la quarantena manualmente.'
  while true; do
    menu
    local choice
    read -r -p 'Seleziona fase [0-9]: ' choice || break
    case "$choice" in
      1) preflight || err 'Controlli non superati.' ;;
      2) show_report || err 'Verifica report non riuscita.' ;;
      3) start_horizon || err 'Avvio non confermato.' ;;
      4) show_logs_state || err 'Controllo non riuscito.' ;;
      5) introduce_violation || err 'Violazione non applicata o non confermata.' ;;
      6) stop_horizon || err 'STOP non confermato.' ;;
      7) restore_horizon || err 'RESTORE non confermato.' ;;
      8) correct_policy || err 'Correzione non confermata.' ;;
      9) final_check || err 'Verifica finale non superata.' ;;
      0) say 'Uscita. Ricorda che uscire non ferma automaticamente il monitor.'; break ;;
      *) say 'Scelta non valida.' ;;
    esac
    pause
  done
}

main "$@"
