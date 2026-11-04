from pathlib import Path
import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
POLICY_FILE = BASE_DIR / "config" / "ssh-policies.yaml"


def load_policies():
    with POLICY_FILE.open("r", encoding="utf-8") as file:
        config = yaml.safe_load(file)

    if not isinstance(config, dict) or not isinstance(config.get("policies"), dict):
        raise ValueError("Configurazione delle policy SSH non valida")

    return config["policies"]


def evaluate_policies(ssh_settings):
    policies = load_policies()
    results = {}

    for policy_id, policy in policies.items():
        parameter = policy["parameter"]
        expected = str(policy["expected"]).lower()
        actual = ssh_settings.get(parameter)

        if actual is None:
            status = "UNKNOWN"
        elif str(actual).lower() == expected:
            status = "COMPLIANT"
        else:
            status = "NON_COMPLIANT"

        results[policy_id] = {
            "parameter": parameter,
            "expected": expected,
            "actual": actual,
            "severity": policy["severity"],
            "status": status,
        }

    return results
