import os
from dataclasses import dataclass
from urllib.parse import urlsplit


class ConfigurationError(ValueError):
    """Raised when required environment configuration is missing or invalid."""


def _read_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
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
        url = os.getenv("WAZUH_INDEXER_URL", "").strip().rstrip("/")
        username = os.getenv("WAZUH_INDEXER_USERNAME", "")
        password = os.getenv("WAZUH_INDEXER_PASSWORD", "")
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

        timeout_value = os.getenv("WAZUH_TIMEOUT", "30")
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
            verify_tls=_read_bool("WAZUH_VERIFY_TLS", True),
            timeout=timeout,
        )
