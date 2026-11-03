
import json
import os
import socket
import struct

from email_sender import send_notification_email

SOCKET_PATH = "/run/vm-quarantine-notifications/notify.sock"

ALLOWED_EVENTS = {
    "QUARANTINE_APPLIED",
    "QUARANTINE_RESTORED",
    "QUARANTINE_FAILED",
}


def handle_client(client):
    credentials = client.getsockopt(
        socket.SOL_SOCKET,
        socket.SO_PEERCRED,
        struct.calcsize("3i")
    )

    pid, uid, gid = struct.unpack("3i", credentials)

    if uid != 0:
        raise PermissionError("Client non autorizzato")

    client.settimeout(5)

    data = client.recv(4097)

    if len(data) > 4096:
        raise ValueError("Messaggio troppo grande")

    event_data = json.loads(data.decode("utf-8"))

    event = event_data["event"]
    vm_name = event_data["vm_name"]
    message = event_data["message"]

    if event not in ALLOWED_EVENTS:
        raise ValueError("Evento non autorizzato")

    if not all(
        isinstance(value, str) and len(value) <= 500
        for value in (event, vm_name, message)
    ):
        raise ValueError("Dati non validi")

    result = send_notification_email(
        event, vm_name, message
    )

    client.sendall(
        json.dumps({"emails_processed": result}).encode()
    )


def main():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        os.umask(0o077)
        server.bind(SOCKET_PATH)
        server.listen(5)

        print("Servizio notifiche VM Quarantine avviato.", flush=True)

        while True:
            client, _ = server.accept()

            with client:
                try:
                    handle_client(client)
                except Exception as error:
                    print(f"Errore notifica: {error}", flush=True)

                    try:
                        client.sendall(
                            json.dumps({
                                "status": "error",
                                "message": "Richiesta non elaborata"
                            }).encode("utf-8")
                        )
                    except OSError:
                        pass


if __name__ == "__main__":
    main()
