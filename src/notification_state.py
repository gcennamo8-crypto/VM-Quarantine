import json
import os
import tempfile
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
STATE_DIR = BASE_DIR / "state"
STATE_FILE = STATE_DIR / "notification_state.json"


def load_notification_state():
    if not STATE_FILE.exists():
        return {}

    with STATE_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Stato notifiche non valido")

    return data


def save_notification_state(state):
    if not isinstance(state, dict):
        raise ValueError("Stato notifiche non valido")

    STATE_DIR.mkdir(mode=0o700, exist_ok=True)

    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=STATE_DIR,
            prefix=".notification-",
            suffix=".tmp",
            delete=False,
        ) as file:
            temporary_path = Path(file.name)
            os.fchmod(file.fileno(), 0o600)
            json.dump(state, file, indent=2)
            file.flush()
            os.fsync(file.fileno())

        os.replace(temporary_path, STATE_FILE)

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def get_violation_signature(critical_violations):
    return sorted(
        violation["policy_id"]
        for violation in critical_violations
    )
