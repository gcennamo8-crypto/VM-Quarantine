
import os
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import apprise


def load_email_config():
    """Legge le credenziali dal file privato."""
    config = {}

    import pwd

    username = os.environ.get("SUDO_USER")

    if username:
        home = Path(pwd.getpwnam(username).pw_dir)
    else:
        home = Path.home()

    path = home / ".config/vm-quarantine/email.env"
    if not path.is_file():
        return config

    import shlex

    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        key, separator, value = line.partition("=")

        if separator:
            values = shlex.split(value)
            if len(values) == 1:
                config[key.strip()] = values[0]

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
            return notification

        username, domain = email.rsplit("@", 1)

        url = (
            f"mailto://{quote(username, safe='')}:"
            f"{quote(password, safe='')}"
            f"@{domain}/{quote(recipient, safe='')}"
        )

        notifier = apprise.Apprise()

        if not notifier.add(url):
            print("[EMAIL] Configurazione Apprise non valida.")
            return notification

        sent = notifier.notify(
            title=f"VM Quarantine - {event}",
            body=notification
        )

        if sent:
            print("[EMAIL] Invio riuscito.")
        else:
            print("[EMAIL] Invio fallito.")

    except Exception as error:
        print(
            f"[EMAIL] Errore durante la notifica: "
            f"{type(error).__name__}"
        )

    return notification


if __name__ == "__main__":
    send_notification(
        event="TEST_NOTIFICATION",
        vm_name="vm-test-quarantena",
        message="Test delle notifiche automatiche con Apprise."
    )

