import os
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import apprise


EMAIL_CONFIG_FILE = (
    Path.home() / ".config" / "vm-quarantine" / "email.env"
)


def load_email_config():
    config = {}

    if not EMAIL_CONFIG_FILE.exists():
        return config

    with EMAIL_CONFIG_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if "=" not in line:
                continue

            key, value = line.split("=", 1)

            key = key.strip()
            value = value.strip().strip('"').strip("'")

            if key:
                config[key] = value

    return config


def send_notification(event, vm_name, message):
    timestamp = datetime.now().astimezone().strftime(
        "%Y-%m-%d %H:%M:%S %z"
    )

    notification = (
        f"\n[NOTIFICA VM QUARANTINE]\n"
        f"Data: {timestamp}\n"
        f"Evento: {event}\n"
        f"VM: {vm_name}\n"
        f"Messaggio: {message}\n"
    )

    print(notification)

    try:
        config = load_email_config()

        email = config.get("GMAIL_ADDRESS")
        password = config.get("GMAIL_APP_PASSWORD")
        recipient = config.get("NOTIFY_EMAIL")

        if not all((email, password, recipient)):
            print("[EMAIL] Configurazione Gmail mancante.")
            return False

        username, domain = email.rsplit("@", 1)

        url = (
            f"mailto://{quote(username, safe='')}:"
            f"{quote(password, safe='')}"
            f"@{domain}/{quote(recipient, safe='')}"
        )

        notifier = apprise.Apprise()

        if not notifier.add(url):
            print("[EMAIL] Configurazione Apprise non valida.")
            return False

        sent = notifier.notify(
            title=f"VM Quarantine - {event}",
            body=notification,
        )

        if sent:
            print("[EMAIL] Invio riuscito.")
            return True

        print("[EMAIL] Invio fallito.")
        return False

    except Exception as error:
        print(
            "[EMAIL] Errore durante la notifica: "
            f"{type(error).__name__}"
        )
        return False


if __name__ == "__main__":
    result = send_notification(
        event="TEST_NOTIFICATION",
        vm_name="vm-security-compliance",
        message="Test del sistema di notifiche VM Quarantine.",
    )

    if not result:
        raise SystemExit(1)
