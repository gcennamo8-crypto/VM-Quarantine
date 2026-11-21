
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
    "/var/lib/vm-quarantine-reports/last_report.json"
)

COMPUTE_PERMISSION = "openstack.services.compute"


def send_control_command(action):
    """Comunica con il servizio locale VM Quarantine."""

    if action not in ("start", "stop", "status", "restore"):
        return {
            "success": False,
            "message": "Azione non consentita",
        }

    try:
        with socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        ) as client:
            client.settimeout(180 if action == "restore" else 5)
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



EXPECTED_VM_ID = "02952f12-af9a-44f5-87a8-15d3412e599e"


@login_required
@permission_required(COMPUTE_PERMISSION, raise_exception=True)
@permission_required("openstack.roles.admin", raise_exception=True)
@require_POST
def restore_instance(request):
    vm_id = request.POST.get("vm_id")

    if vm_id != EXPECTED_VM_ID:
        return JsonResponse({
            "success": False,
            "message": "VM non autorizzata",
        }, status=403)

    result = send_control_command("restore")

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


@login_required
@permission_required(COMPUTE_PERMISSION, raise_exception=True)
@require_GET
def quarantined_instances(request):
    """Elenca le VM isolate secondo lo stato reale di Neutron."""
    from openstack_dashboard import api

    try:
        groups = api.neutron.security_group_list(request)
        quarantine_groups = [
            group for group in groups
            if group.name == "quarantine-sg"
        ]

        if len(quarantine_groups) != 1:
            return JsonResponse({
                "success": False,
                "message": "Security Group di quarantena non univoco o assente",
            }, status=503)

        quarantine_id = quarantine_groups[0].id
        ports = api.neutron.port_list(request)

        instances = {}

        for port in ports:
            vm_id = getattr(port, "device_id", None)
            owner = getattr(port, "device_owner", "") or ""

            if not vm_id or not owner.startswith("compute:"):
                continue

            group_ids = getattr(port, "security_group_ids", None)

            if group_ids is None:
                group_ids = getattr(port, "security_groups", None)

            if group_ids is None:
                raise ValueError(
                    "Attributi Security Group assenti nella porta Neutron"
                )

            security_groups = set(group_ids)

            record = instances.setdefault(vm_id, {
                "vm_id": vm_id,
                "ports": [],
            })

            record["ports"].append({
                "port_id": port.id,
                "isolated": security_groups == {quarantine_id},
            })

        results = []

        for record in instances.values():
            isolated = [
                port["isolated"] for port in record["ports"]
            ]

            if all(isolated):
                record["status"] = "QUARANTINED"
            elif any(isolated):
                record["status"] = "PARTIAL"
            else:
                continue

            results.append(record)

        return JsonResponse({
            "success": True,
            "instances": results,
            "count": sum(
                item["status"] == "QUARANTINED"
                for item in results
            ),
        })

    except Exception:
        return JsonResponse({
            "success": False,
            "message": "Impossibile interrogare Neutron",
        }, status=503)
