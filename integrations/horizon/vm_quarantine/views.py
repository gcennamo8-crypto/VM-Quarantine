
import json
import socket
from pathlib import Path

from django.contrib.auth.decorators import (
    login_required,
    permission_required,
)
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST
from django.views.generic import TemplateView


SOCKET_PATH = "/run/vm-quarantine-control/control.sock"
REPORT_PATH = Path(
    "/run/vm-quarantine-control/last_report.json"
)

COMPUTE_PERMISSION = "openstack.services.compute"


def send_control_command(action):
    """Comunica con il servizio locale VM Quarantine."""

    if action not in ("start", "stop", "status"):
        return {
            "success": False,
            "message": "Azione non consentita",
        }

    try:
        with socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        ) as client:
            client.settimeout(5)
            client.connect(SOCKET_PATH)

            client.sendall(
                json.dumps({"action": action}).encode("utf-8")
            )

            response = client.recv(4096)

            if not response:
                raise ConnectionError(
                    "Risposta vuota dal servizio"
                )

            result = json.loads(response.decode("utf-8"))

            if not isinstance(result, dict):
                raise ValueError("Risposta non valida")

            return result

    except (OSError, ValueError, ConnectionError):
        return {
            "success": False,
            "message": (
                "Impossibile comunicare con "
                "il servizio VM Quarantine"
            ),
        }


class IndexView(LoginRequiredMixin, TemplateView):
    template_name = "vm_quarantine/index.html"

    def dispatch(self, request, *args, **kwargs):
        if not request.user.has_perm(COMPUTE_PERMISSION):
            raise PermissionDenied

        return super().dispatch(request, *args, **kwargs)


@login_required
@permission_required(COMPUTE_PERMISSION, raise_exception=True)
@require_GET
def monitor_status(request):
    result = send_control_command("status")

    return JsonResponse(
        result,
        status=200 if result.get("success") else 503,
    )


@login_required
@permission_required(COMPUTE_PERMISSION, raise_exception=True)
@require_POST
def monitor_start(request):
    result = send_control_command("start")

    return JsonResponse(
        result,
        status=200 if result.get("success") else 503,
    )


@login_required
@permission_required(COMPUTE_PERMISSION, raise_exception=True)
@require_POST
def monitor_stop(request):
    result = send_control_command("stop")

    return JsonResponse(
        result,
        status=200 if result.get("success") else 503,
    )


@login_required
@permission_required(COMPUTE_PERMISSION, raise_exception=True)
@require_GET
def monitor_report(request):
    """Restituisce l'ultimo report SSH validato."""

    try:
        with REPORT_PATH.open(
            "r", encoding="utf-8"
        ) as file:
            report = json.load(file)

        if not isinstance(report, dict):
            raise ValueError("Report non valido")

        return JsonResponse({
            "success": True,
            "report": report,
        })

    except FileNotFoundError:
        return JsonResponse({
            "success": True,
            "report": None,
            "message": "Nessun controllo ancora disponibile",
        })

    except (OSError, ValueError, json.JSONDecodeError):
        return JsonResponse({
            "success": False,
            "message": "Impossibile leggere il report",
        }, status=503)
