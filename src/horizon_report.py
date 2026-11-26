import json
import os
import tempfile
from pathlib import Path


REPORT_PATH = Path(
    "/var/lib/vm-quarantine-reports/last_report.json"
)

#Riceve e salva il report di sicurezza della VM
def save_horizon_report(report):
    

    data = {
        "vm_id": report["vm_id"],
        "vm_name": report["vm_name"],
        "timestamp": report["timestamp"],
        "status": report["status"],
        "policies": report["policies"],
        "violations": report["violations"],
    }

    directory = REPORT_PATH.parent
    
#Creazione di un file temporaneo JSON per evitare la lettura di un report incompleto da parte di Horizon
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
            #Garantisce il salvataggio dei dati sul disco 
            os.fsync(file.fileno())

            #Imposta i permessi per consentire a Horizon la sola lettura.
            os.fchmod(file.fileno(), 0o640)

        os.replace(temporary_path, REPORT_PATH)

    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)
