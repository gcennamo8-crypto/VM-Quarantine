
import json
import socket
from datetime import datetime

SOCKET_PATH = "/run/vm-quarantine-notifications/notify.sock"


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

    payload = {
        "event": event,
        "vm_name": vm_name,
        "message": message
    }

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(SOCKET_PATH)
            client.sendall(json.dumps(payload).encode("utf-8"))

            response = client.recv(4096)
            if not response:
                raise ConnectionError("Nessuna risposta dal server")

            result = json.loads(response.decode("utf-8"))

            if result.get("emails_processed") == 1:
                print("[EMAIL] Notifica elaborata da Horizon.")
            else:
                print("[EMAIL] Il server non ha confermato l'invio.")

    except (OSError, ValueError, UnicodeError) as error:
        print(f"[EMAIL] Notifica remota non disponibile: {error}")

    return notification


if __name__ == "__main__":
    send_notification(
        event="QUARANTINE_APPLIED",
        vm_name="vm-test-quarantena",
        message="TEST: collegamento notifiche a Horizon."
    )

