from django.utils.translation import gettext_lazy as _

import horizon


class VMQuarantine(horizon.Panel):
    name = _("VM Quarantine")
    slug = "vm_quarantine"
    permissions = ("openstack.services.compute",)
