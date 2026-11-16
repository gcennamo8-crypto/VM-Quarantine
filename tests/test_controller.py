import copy
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import compliance_controller as controller

REPORT_PATH = (
    ROOT / "tests" / "fixtures" / "non_compliant_report.json"
)


class TestController(unittest.TestCase):

    def setUp(self):
        self.report = copy.deepcopy(
            json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        )
        self.report["timestamp"] = (
            datetime.now(timezone.utc).isoformat()
        )

    def test_compliant_no_quarantine(self):
        for policy in self.report["policies"].values():
            policy["actual"] = policy["expected"]
            policy["status"] = "COMPLIANT"

        self.report["violations"] = []
        self.report["status"] = "COMPLIANT"

        with (
            patch.object(controller, "execute_quarantine") as quarantine,
            patch.object(controller, "notify_compliance_violation") as notify,
            patch.object(controller, "save_horizon_report") as save,
            patch.object(controller, "clear_notification_state") as clear,
        ):
            controller.analyze_report(
                self.report,
                notify=True,
                trusted_source=True,
            )

            quarantine.assert_not_called()
            notify.assert_not_called()
            save.assert_called_once()
            clear.assert_called_once_with(self.report["vm_id"])

    def test_non_compliant_dry_run(self):
        with (
            patch.object(controller, "execute_quarantine") as quarantine,
            patch.object(controller, "notify_compliance_violation") as notify,
            patch.object(controller, "save_horizon_report") as save,
        ):
            controller.analyze_report(
                self.report,
                notify=True,
                trusted_source=True,
                apply_quarantine=False,
            )

            quarantine.assert_called_once_with(
                self.report["vm_id"],
                dry_run=True,
            )
            notify.assert_called_once()
            save.assert_called_once()


if __name__ == "__main__":
    unittest.main()
