from django.urls import path

from .views import (
    IndexView,
    monitor_start,
    monitor_stop,
    monitor_status,
    monitor_report,
)

urlpatterns = [
    path("", IndexView.as_view(), name="index"),
    path("start/", monitor_start, name="monitor_start"),
    path("stop/", monitor_stop, name="monitor_stop"),
    path("status/", monitor_status, name="monitor_status"),
    path("report/", monitor_report, name="monitor_report"),
]
