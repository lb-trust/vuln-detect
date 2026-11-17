import argparse
import logging
import sys
from pathlib import Path

from vuln_detect.client import WazuhIndexerClient, WazuhIndexerError
from vuln_detect.config import ConfigurationError, Settings
from vuln_detect.report import write_report


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export the Wazuh vulnerability inventory without modifying agents."
    )
    parser.add_argument(
        "--format",
        choices=("csv", "json"),
        default="csv",
        help="report format (default: csv)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/vulnerabilities.csv"),
        help="destination file (default: reports/vulnerabilities.csv)",
    )
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        default="INFO",
        help="logging verbosity (default: INFO)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)s: %(message)s",
    )
    if args.output.suffix.lower() not in {".csv", ".json"}:
        print("Error: output file must have a .csv or .json extension.", file=sys.stderr)
        return 2
    if args.output.suffix.lower() != f".{args.format}":
        print(
            f"Error: --output extension must match --format ({args.format}).",
            file=sys.stderr,
        )
        return 2

    try:
        settings = Settings.from_env()
        findings = WazuhIndexerClient(settings).fetch_vulnerabilities()
        write_report(findings, args.output, args.format)
    except (ConfigurationError, WazuhIndexerError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Exported {len(findings)} vulnerability findings to {args.output}.")
    return 0
