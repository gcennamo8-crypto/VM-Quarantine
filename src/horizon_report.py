import json
import os
import tempfile
from pathlib import Path


REPORT_PATH = Path(
    "/var/lib/vm-quarantine-reports/last_report.json"
)


def save_horizon_report(report):
    """
    Salva atomicamente l'ultimo report validato.

    Horizon potrà leggere il file, ma non modificarlo.
    """

    data = {
        "vm_id": report["vm_id"],
        "vm_name": report["vm_name"],
        "timestamp": report["timestamp"],
        "status": report["status"],
        "policies": report["policies"],
        "violations": report["violations"],
    }

    directory = REPORT_PATH.parent

    fd, temporary_path = tempfile.mkstemp(
        prefix=".report-",
        suffix=".json",
        dir=directory,
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())

            # Lettura consentita al gruppo stack
            os.fchmod(file.fileno(), 0o640)

        os.replace(temporary_path, REPORT_PATH)

    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)
