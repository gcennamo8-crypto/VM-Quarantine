
import os
import sys

sys.path.insert(0, "/opt/stack/horizon")

os.environ.setdefault(
    "DJANGO_SETTINGS_MODULE",
    "openstack_dashboard.settings"
)

import django

django.setup()

from django.core.mail import send_mail


def send_notification_email(event, vm_name, message):
    subject = f"[VM Quarantine] {event} - {vm_name}"

    body = (
        f"VM Quarantine - Notifica di sicurezza\n\n"
        f"Evento: {event}\n"
        f"VM: {vm_name}\n"
        f"Messaggio: {message}\n"
    )

    return send_mail(
        subject,
        body,
        "vm-quarantine@example.com",
        ["admin@example.com"],
        fail_silently=False,
    )


if __name__ == "__main__":
    result = send_notification_email(
        "QUARANTINE_APPLIED",
        "vm-test-quarantena",
        "La VM è stata isolata tramite Neutron."
    )

    print(f"Email elaborate: {result}")
