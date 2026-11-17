import json
import unittest
from unittest.mock import MagicMock, patch

from vuln_detect.client import WazuhIndexerClient, WazuhIndexerError
from vuln_detect.config import Settings


def _response(payload: dict[str, object]) -> MagicMock:
    response = MagicMock()
    response.read.return_value = json.dumps(payload).encode("utf-8")
    response.__enter__.return_value = response
    return response


def _hit(agent_id: str, cve: str, package: str) -> dict[str, object]:
    return {
        "_source": {
            "agent": {"id": agent_id, "name": f"host-{agent_id}"},
            "host": {"os": {"full": "Linux"}},
            "package": {"name": package, "version": "1.0"},
            "vulnerability": {
                "id": cve,
                "severity": "High",
                "score": {"base": 8.8},
                "scanner": {"condition": "Package less than 2.0"},
            },
        }
    }


class WazuhIndexerClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = WazuhIndexerClient(
            Settings(
                indexer_url="https://indexer.example.net:9200",
                username="reporter",
                password="not-a-real-password",
            )
        )

    @patch("vuln_detect.client.urlopen")
    def test_reads_all_scroll_pages_and_clears_scroll(self, urlopen: MagicMock) -> None:
        urlopen.side_effect = [
            _response(
                {
                    "_scroll_id": "scroll-1",
                    "hits": {"hits": [_hit("001", "CVE-1", "pkg-a")]},
                }
            ),
            _response(
                {
                    "_scroll_id": "scroll-2",
                    "hits": {"hits": [_hit("002", "CVE-2", "pkg-b")]},
                }
            ),
            _response({"_scroll_id": "scroll-2", "hits": {"hits": []}}),
            _response({"succeeded": True}),
        ]

        findings = self.client.fetch_vulnerabilities()

        self.assertEqual([finding.agent_id for finding in findings], ["001", "002"])
        self.assertEqual(urlopen.call_count, 4)
        cleanup_request = urlopen.call_args_list[-1].args[0]
        self.assertEqual(cleanup_request.method, "DELETE")

    @patch("vuln_detect.client.urlopen")
    def test_rejects_malformed_finding(self, urlopen: MagicMock) -> None:
        urlopen.side_effect = [
            _response(
                {
                    "_scroll_id": "scroll-1",
                    "hits": {"hits": [{"_source": {"agent": {"id": "001"}}}]},
                }
            ),
            _response({"succeeded": True}),
        ]

        with self.assertRaisesRegex(WazuhIndexerError, "malformed vulnerability record"):
            self.client.fetch_vulnerabilities()

        self.assertEqual(urlopen.call_count, 2)

    @patch("vuln_detect.client.urlopen")
    def test_does_not_accept_a_page_without_scroll_id(
        self, urlopen: MagicMock
    ) -> None:
        urlopen.return_value = _response(
            {"hits": {"hits": [_hit("001", "CVE-1", "pkg-a")]}}
        )

        with self.assertRaisesRegex(WazuhIndexerError, "results may be incomplete"):
            self.client.fetch_vulnerabilities()

        self.assertEqual(urlopen.call_count, 1)
