import copy
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from compliance_controller import validate_report

REPORT_PATH = (
    ROOT / "tests" / "fixtures" / "non_compliant_report.json"
)


class TestComplianceValidation(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not REPORT_PATH.is_file():
            raise RuntimeError(
                "Report di riferimento non disponibile"
            )

        cls.reference = json.loads(
            REPORT_PATH.read_text(encoding="utf-8")
        )

    def setUp(self):
        self.report = copy.deepcopy(self.reference)
        self.report["timestamp"] = (
            datetime.now(timezone.utc).isoformat()
        )

    def test_valid_report(self):
        self.assertTrue(validate_report(self.report))

    def test_invalid_vm_uuid(self):
        self.report["vm_id"] = "uuid-non-autorizzato"

        with self.assertRaisesRegex(
            ValueError, "UUID della VM non autorizzato"
        ):
            validate_report(self.report)


    def test_expired_timestamp(self):
        from datetime import timedelta

        self.report["timestamp"] = (
            datetime.now(timezone.utc)
            - timedelta(hours=1)
        ).isoformat()

        with self.assertRaisesRegex(
            ValueError, "Report scaduto o con data futura"
        ):
            validate_report(self.report)

    def test_missing_policy(self):
        self.report["policies"].pop("SSH-03")

        with self.assertRaisesRegex(
            ValueError, "Elenco delle policy non corrispondente"
        ):
            validate_report(self.report)

    def test_inconsistent_status(self):
        self.report["status"] = "COMPLIANT"

        with self.assertRaisesRegex(
            ValueError, "Stato complessivo incoerente"
        ):
            validate_report(self.report)

    def test_fully_compliant_report(self):
        for policy in self.report["policies"].values():
            policy["actual"] = policy["expected"]
            policy["status"] = "COMPLIANT"

        self.report["violations"] = []
        self.report["status"] = "COMPLIANT"

        self.assertTrue(validate_report(self.report))


if __name__ == "__main__":
    unittest.main()
