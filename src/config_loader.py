
from pathlib import Path
import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = BASE_DIR / "config" / "security-groups.yaml"


def load_config():
    with CONFIG_FILE.open("r", encoding="utf-8") as file:
        config = yaml.safe_load(file)

    if not isinstance(config, dict) or "quarantine" not in config:
        raise ValueError("Configurazione quarantine mancante o non valida")

    return config


if __name__ == "__main__":
    configuration = load_config()
    print(configuration)
