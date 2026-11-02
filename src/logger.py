
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_DIR = Path("/var/log/vm-quarantine")
LOG_FILE = LOG_DIR / "events.log"


def setup_logger():
    logger = logging.getLogger("vm_quarantine")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=1_000_000,
        backupCount=3,
        encoding="utf-8"
    )
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger


if __name__ == "__main__":
    log = setup_logger()
    log.info("Sistema di logging VM Quarantine avviato")
    print("Messaggio di test registrato.")
