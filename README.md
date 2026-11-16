# VM Quarantine

VM Quarantine è un progetto universitario di sicurezza cloud sviluppato in Python e integrato con OpenStack.

Il sistema verifica periodicamente la conformità della configurazione SSH di una macchina virtuale Debian, identifica eventuali violazioni delle policy di sicurezza e simula l'isolamento della VM tramite OpenStack Neutron.

## Architettura

Il progetto utilizza i seguenti componenti:

- **Compliance Agent:** verifica la configurazione SSH della VM Debian.
- **Compliance Controller:** valida i report e identifica le violazioni.
- **Keystone:** gestisce l'autenticazione OpenStack.
- **Nova:** gestisce le macchine virtuali.
- **Neutron:** controlla i Security Group.
- **Horizon:** permette di avviare e arrestare il monitoraggio e visualizzare i report.

## Policy SSH

| ID | Parametro | Valore richiesto |
|---|---|---|
| SSH-01 | pubkeyauthentication | yes |
| SSH-02 | passwordauthentication | no |
| SSH-02B | kbdinteractiveauthentication | no |
| SSH-03 | permitrootlogin | no |

## Funzionamento

1. L'utente avvia il monitoraggio tramite Horizon.
2. Il Controller si collega alla VM Debian tramite SSH.
3. Il Compliance Agent verifica le quattro policy SSH.
4. Il Controller valida il report ricevuto.
5. Se rileva violazioni critiche, simula la quarantena tramite Neutron.
6. Il risultato viene salvato e visualizzato su Horizon.
7. Il controllo viene ripetuto periodicamente fino allo STOP.

## Sicurezza

Il progetto implementa diverse misure di sicurezza:

- Autenticazione SSH con chiave protetta da passphrase.
- Controllo del socket e delle identità dell'SSH Agent.
- Verifica dell'UUID della VM autorizzata.
- Validazione del timestamp e delle policy.
- Gestione degli errori SSH e dei timeout.
- Prevenzione delle notifiche email duplicate.
- Monitoraggio disattivato all'avvio del sistema.

**IMPORTANTE:** il monitoraggio automatico opera esclusivamente in DRY RUN.

La quarantena viene simulata: nessun Security Group viene modificato automaticamente.
## Test automatici

Il progetto include una suite di test basata su unittest.

I test verificano:
- La validazione dei report SSH.
- Il rifiuto di UUID non autorizzati.
- Il controllo dei timestamp.
- La coerenza delle policy.
- Il comportamento del Controller con VM conformi e non conformi.

Per eseguire gli 8 test automatici:

    .venv/bin/python -m unittest discover -s tests -v

## Interfaccia Horizon

Il pannello si trova in:

Project → Compute → VM Quarantine

L'interfaccia permette di:
- Avviare il monitoraggio con START.
- Arrestare il monitoraggio con STOP.
- Visualizzare lo stato del servizio.
- Consultare i risultati delle quattro policy SSH.
- Visualizzare il report dell'ultimo controllo.

## Repository GitHub

Repository:
https://github.com/gcennamo8-crypto/VM-Quarantine

Branch di sviluppo:
feature/security-compliance

## Stato del progetto

Il monitoraggio SSH, l'integrazione Horizon, la simulazione Neutron e gli 8 test automatici sono stati verificati.

Il monitoraggio rimane disattivato all'avvio e viene attivato dall'utente tramite Horizon.

La quarantena automatica è limitata alla modalità DRY RUN.
