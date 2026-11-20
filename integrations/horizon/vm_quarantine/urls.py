from django.urls import path

from .views import (
    quarantined_instances,
    IndexView,
    monitor_start,
    monitor_stop,
    monitor_status,
    monitor_report,
    restore_instance,
)

urlpatterns = [
    path("restore/", restore_instance, name="restore_instance"),
    path("quarantined/", quarantined_instances, name="quarantined_instances"),
    path("", IndexView.as_view(), name="index"),
    path("start/", monitor_start, name="monitor_start"),
    path("stop/", monitor_stop, name="monitor_stop"),
    path("status/", monitor_status, name="monitor_status"),
    path("report/", monitor_report, name="monitor_report"),
]
