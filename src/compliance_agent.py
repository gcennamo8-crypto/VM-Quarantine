import subprocess

from policy_engine import evaluate_policies


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


def main():
    settings = read_ssh_configuration()
    results = evaluate_policies(settings)

    print("\n[VM QUARANTINE - SSH COMPLIANCE CHECK]")

    for policy_id, result in results.items():
        print(
            f"{policy_id}: {result['status']} "
            f"(attuale={result['actual']}, "
            f"richiesto={result['expected']})"
        )


if __name__ == "__main__":
    main()
