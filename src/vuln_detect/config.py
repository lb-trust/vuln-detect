import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit


class ConfigurationError(ValueError):
    """Raised when required environment configuration is missing or invalid."""


ENVIRONMENT_VARIABLES = (
    "WAZUH_INDEXER_URL",
    "WAZUH_INDEXER_USERNAME",
    "WAZUH_INDEXER_PASSWORD",
    "WAZUH_VERIFY_TLS",
    "WAZUH_TIMEOUT",
)


def load_dotenv(path: Path = Path(".env")) -> None:
    """Load simple KEY=VALUE entries without overriding process environment."""
    if not path.exists():
        return

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConfigurationError(
                f"Invalid configuration in {path} on line {line_number}."
            )
        name, raw_value = line.split("=", 1)
        name = name.strip()
        raw_value = raw_value.strip()
        if name not in ENVIRONMENT_VARIABLES:
            continue
        if raw_value.startswith('"'):
            try:
                value = json.loads(raw_value)
            except json.JSONDecodeError as exc:
                raise ConfigurationError(
                    f"Invalid quoted value in {path} on line {line_number}."
                ) from exc
            if not isinstance(value, str):
                raise ConfigurationError(
                    f"Invalid value in {path} on line {line_number}."
                )
        else:
            value = raw_value
        os.environ.setdefault(name, value)


def _read_bool(
    name: str, default: bool, environ: Mapping[str, str]
) -> bool:
    value = environ.get(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be a boolean value.")


@dataclass(frozen=True)
class Settings:
    indexer_url: str
    username: str
    password: str
    verify_tls: bool = True
    timeout: float = 30.0

    @classmethod
    def from_env(cls) -> "Settings":
        return cls.from_mapping(os.environ)

    @classmethod
    def from_mapping(cls, environ: Mapping[str, str]) -> "Settings":
        url = environ.get("WAZUH_INDEXER_URL", "").strip().rstrip("/")
        username = environ.get("WAZUH_INDEXER_USERNAME", "")
        password = environ.get("WAZUH_INDEXER_PASSWORD", "")
        if not url:
            raise ConfigurationError("WAZUH_INDEXER_URL is required.")
        if not username or not password:
            raise ConfigurationError(
                "WAZUH_INDEXER_USERNAME and WAZUH_INDEXER_PASSWORD are required."
            )

        parsed_url = urlsplit(url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.hostname:
            raise ConfigurationError(
                "WAZUH_INDEXER_URL must be an absolute HTTP or HTTPS URL."
            )
        if parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment:
            raise ConfigurationError(
                "WAZUH_INDEXER_URL must not contain credentials, a query, or a fragment."
            )

        timeout_value = environ.get("WAZUH_TIMEOUT", "30")
        try:
            timeout = float(timeout_value)
        except ValueError as exc:
            raise ConfigurationError("WAZUH_TIMEOUT must be a positive number.") from exc
        if timeout <= 0:
            raise ConfigurationError("WAZUH_TIMEOUT must be a positive number.")

        return cls(
            indexer_url=url,
            username=username,
            password=password,
            verify_tls=_read_bool("WAZUH_VERIFY_TLS", True, environ),
            timeout=timeout,
        )
