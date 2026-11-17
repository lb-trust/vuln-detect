import csv
import json
from pathlib import Path
from typing import Iterable

from vuln_detect.models import VulnerabilityFinding

CSV_FIELDS = [
    "agent_id",
    "agent_name",
    "operating_system",
    "package_name",
    "package_version",
    "package_type",
    "cve",
    "severity",
    "cvss_score",
    "description",
    "affected_condition",
    "reference",
    "detected_at",
    "status",
]


def write_report(
    findings: Iterable[VulnerabilityFinding], output: Path, output_format: str
) -> None:
    rows = [finding.to_dict() for finding in findings]
    output.parent.mkdir(parents=True, exist_ok=True)

    if output_format == "json":
        output.write_text(
            json.dumps(rows, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return
    if output_format == "csv":
        with output.open("w", encoding="utf-8", newline="") as report_file:
            writer = csv.DictWriter(report_file, fieldnames=CSV_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        return
    raise ValueError(f"Unsupported report format: {output_format}")
