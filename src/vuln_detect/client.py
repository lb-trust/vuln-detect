import base64
import json
import logging
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from vuln_detect.config import Settings
from vuln_detect.models import VulnerabilityFinding

LOGGER = logging.getLogger(__name__)
INDEX_PATTERN = "wazuh-states-vulnerabilities-*"
PAGE_SIZE = 500
SCROLL_KEEP_ALIVE = "2m"


class WazuhIndexerError(RuntimeError):
    """Raised when the Wazuh Indexer request or response is unsuccessful."""


class WazuhIndexerClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._ssl_context = ssl.create_default_context()
        if not settings.verify_tls:
            LOGGER.warning("TLS certificate verification is disabled.")
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE
        credentials = f"{settings.username}:{settings.password}".encode("utf-8")
        self._authorization = "Basic " + base64.b64encode(credentials).decode("ascii")

    def _request(
        self, method: str, path: str, payload: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            f"{self._settings.indexer_url}{path}",
            data=body,
            method=method,
            headers={
                "Authorization": self._authorization,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with urlopen(
                request,
                timeout=self._settings.timeout,
                context=self._ssl_context if self._settings.indexer_url.startswith("https:") else None,
            ) as response:
                response_body = response.read()
        except HTTPError as exc:
            raise WazuhIndexerError(
                f"Indexer returned HTTP {exc.code} for {method} {path}."
            ) from exc
        except URLError as exc:
            raise WazuhIndexerError(
                f"Could not reach the Wazuh Indexer for {method} {path}: {exc.reason}."
            ) from exc
        except TimeoutError as exc:
            raise WazuhIndexerError(
                f"The Wazuh Indexer request timed out for {method} {path}."
            ) from exc

        try:
            decoded = json.loads(response_body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise WazuhIndexerError(
                f"Indexer returned invalid JSON for {method} {path}."
            ) from exc
        if not isinstance(decoded, dict):
            raise WazuhIndexerError(
                f"Indexer returned an unexpected response for {method} {path}."
            )
        return decoded

    def _clear_scroll(self, scroll_id: str) -> None:
        self._request("DELETE", "/_search/scroll", {"scroll_id": [scroll_id]})

    def fetch_vulnerabilities(self) -> list[VulnerabilityFinding]:
        encoded_pattern = quote(INDEX_PATTERN, safe="*,-_")
        first_page = self._request(
            "POST",
            f"/{encoded_pattern}/_search?scroll={SCROLL_KEEP_ALIVE}",
            {
                "size": PAGE_SIZE,
                "query": {"match_all": {}},
            },
        )
        scroll_id = first_page.get("_scroll_id")
        findings: list[VulnerabilityFinding] = []
        page = first_page
        try:
            while True:
                hits_block = page.get("hits", {})
                hits = hits_block.get("hits") if isinstance(hits_block, dict) else None
                if not isinstance(hits, list):
                    raise WazuhIndexerError("Indexer response is missing the hits list.")
                if not hits:
                    break
                if not isinstance(scroll_id, str) or not scroll_id:
                    raise WazuhIndexerError(
                        "Indexer did not provide a scroll ID; results may be incomplete."
                    )

                for hit in hits:
                    source = hit.get("_source") if isinstance(hit, dict) else None
                    try:
                        findings.append(VulnerabilityFinding.from_source(source))
                    except (TypeError, ValueError) as exc:
                        raise WazuhIndexerError(
                            "Indexer returned a malformed vulnerability record."
                        ) from exc

                page = self._request(
                    "POST",
                    "/_search/scroll",
                    {"scroll": SCROLL_KEEP_ALIVE, "scroll_id": scroll_id},
                )
                next_scroll_id = page.get("_scroll_id")
                if not isinstance(next_scroll_id, str) or not next_scroll_id:
                    raise WazuhIndexerError(
                        "Indexer did not provide a scroll ID for the next page."
                    )
                scroll_id = next_scroll_id

        except WazuhIndexerError as primary_error:
            if isinstance(scroll_id, str) and scroll_id:
                try:
                    self._clear_scroll(scroll_id)
                except WazuhIndexerError as cleanup_error:
                    raise primary_error from cleanup_error
            raise

        if isinstance(scroll_id, str) and scroll_id:
            self._clear_scroll(scroll_id)
        return findings
