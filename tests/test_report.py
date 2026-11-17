import csv
import json
import tempfile
import unittest
from pathlib import Path

from vuln_detect.models import VulnerabilityFinding
from vuln_detect.report import write_report


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.finding = VulnerabilityFinding(
            agent_id="001",
            agent_name="poste-01",
            operating_system="Linux",
            package_name="openssl",
            package_version="1.0",
            package_type="deb",
            cve="CVE-2025-0001",
            severity="High",
            cvss_score="8.8",
            description="Example",
            affected_condition="Package less than 2.0",
            reference="https://cti.wazuh.com/example",
            detected_at="2025-01-01T00:00:00Z",
            status="",
        )

    def test_writes_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "report.json"
            write_report([self.finding], output, "json")

            data = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(data[0]["agent_id"], "001")
        self.assertEqual(data[0]["package_name"], "openssl")

    def test_writes_csv_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.csv"
            write_report([self.finding], output, "csv")

            with output.open(encoding="utf-8", newline="") as report_file:
                rows = list(csv.DictReader(report_file))

        self.assertEqual(rows[0]["cve"], "CVE-2025-0001")
        self.assertEqual(rows[0]["severity"], "High")
