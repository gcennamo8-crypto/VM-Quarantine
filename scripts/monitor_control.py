
#!/usr/bin/env python3

import json
import os
import socket
import struct
import subprocess
from pathlib import Path


SOCKET_PATH = Path(
    "/run/vm-quarantine-control/control.sock"
)

MONITOR_SERVICE = "vm-quarantine-monitor.service"
AUTHORIZED_UID = 1001  # Utente stack


def service_command(action):
    command = [
        "systemctl",
        "--user",
        action,
        MONITOR_SERVICE,
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    return result


def handle_request(connection):
    credentials = connection.getsockopt(
        socket.SOL_SOCKET,
        socket.SO_PEERCRED,
        struct.calcsize("3i"),
    )

    _, uid, _ = struct.unpack("3i", credentials)

    if uid != AUTHORIZED_UID:
        raise PermissionError("Utente non autorizzato")

    connection.settimeout(5)
    data = connection.recv(1024)

    request = json.loads(data.decode("utf-8"))

    if not isinstance(request, dict):
        raise ValueError("Richiesta non valida")

    action = request.get("action")

    if action not in ("start", "stop", "status"):
        raise ValueError("Azione non consentita")

    if action == "status":
        result = service_command("is-active")

        response = {
            "success": True,
            "status": (
                "active"
                if result.returncode == 0
                else "inactive"
            ),
        }
    else:
        result = service_command(action)

        response = {
            "success": result.returncode == 0,
            "action": action,
            "message": (
                "Operazione completata"
                if result.returncode == 0
                else "Operazione non riuscita"
            ),
        }

    connection.sendall(
        json.dumps(response).encode("utf-8")
    )


def main():
    if not SOCKET_PATH.parent.is_dir():
        raise RuntimeError(
            "Directory del socket non disponibile"
        )

    if SOCKET_PATH.exists():
        raise RuntimeError(
            "Socket già presente: verificare "
            "che il servizio non sia in esecuzione"
        )

    old_umask = os.umask(0o117)

    try:
        with socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        ) as server:

            server.bind(str(SOCKET_PATH))
            os.chmod(SOCKET_PATH, 0o660)

            server.listen(5)

            print(
                "[VM QUARANTINE] "
                "Servizio di controllo pronto",
                flush=True,
            )

            while True:
                connection, _ = server.accept()

                with connection:
                    try:
                        handle_request(connection)

                    except (
                        OSError,
                        ValueError,
                        PermissionError,
                        json.JSONDecodeError,
                        subprocess.TimeoutExpired,
                    ):
                        try:
                            connection.sendall(
                                json.dumps({
                                    "success": False,
                                    "message": "Richiesta non elaborata",
                                }).encode("utf-8")
                            )
                        except OSError:
                            pass
    finally:
        os.umask(old_umask)

        if SOCKET_PATH.is_socket():
            SOCKET_PATH.unlink()


if __name__ == "__main__":
    main()
