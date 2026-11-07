import argparse
import json
import subprocess
from datetime import datetime, timezone

from policy_engine import evaluate_policies
from urllib.request import urlopen

SSH_PARAMETERS = (
    "pubkeyauthentication",
    "passwordauthentication",
    "kbdinteractiveauthentication",
    "permitrootlogin",
)


def read_ssh_configuration():
    result = subprocess.run(
        ["/usr/sbin/sshd", "-T"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )

    settings = {}

    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 1)

        if len(parts) == 2:
            parameter, value = parts

            if parameter in SSH_PARAMETERS:
                settings[parameter] = value

    return settings




def get_vm_identity():
    metadata_url = "http://169.254.169.254/openstack/latest/meta_data.json"

    with urlopen(metadata_url, timeout=5) as response:
        metadata = json.load(response)

    vm_id = metadata.get("uuid")
    vm_name = metadata.get("name")

    if not vm_id or not vm_name:
        raise RuntimeError("Identità OpenStack non disponibile")

    return vm_id, vm_name


def generate_report(results, vm_id=None, vm_name=None):
    violations = []

    for policy_id, result in results.items():
        if result["status"] == "NON_COMPLIANT":
            violations.append({
                "policy_id": policy_id,
                "parameter": result["parameter"],
                "actual": result["actual"],
                "expected": result["expected"],
                "severity": result["severity"],
            })

    return {
        "vm_id": vm_id,
        "vm_name": vm_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "UNKNOWN" if any(
            result["status"] == "UNKNOWN"
            for result in results.values()
        ) else ("NON_COMPLIANT" if violations else "COMPLIANT"),
        "violations": violations,
        "policies": results,
    }


def main():
    parser = argparse.ArgumentParser(
        description="VM Quarantine SSH Compliance Agent"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Mostra il report in formato JSON"
    )

    args = parser.parse_args()

    settings = read_ssh_configuration()
    results = evaluate_policies(settings)

    if args.json:
        vm_id, vm_name = get_vm_identity()
        report = generate_report(results, vm_id, vm_name)
        print(json.dumps(report, indent=2))
        return

    print("\n[VM QUARANTINE - SSH COMPLIANCE CHECK]")

    for policy_id, result in results.items():
        print(
            f"{policy_id}: {result['status']} "
            f"(attuale={result['actual']}, "
            f"richiesto={result['expected']})"
        )


if __name__ == "__main__":
    main()
