from dataclasses import asdict, dataclass
from typing import Any


class InvalidFindingError(ValueError):
    """Raised when an Indexer hit cannot be interpreted as a vulnerability."""


def _at_path(data: dict[str, Any], *path: str) -> Any:
    value: Any = data
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return ""


@dataclass(frozen=True)
class VulnerabilityFinding:
    agent_id: str
    agent_name: str
    operating_system: str
    package_name: str
    package_version: str
    package_type: str
    cve: str
    severity: str
    cvss_score: str
    description: str
    affected_condition: str
    reference: str
    detected_at: str
    status: str

    @classmethod
    def from_source(cls, source: dict[str, Any]) -> "VulnerabilityFinding":
        if not isinstance(source, dict):
            raise InvalidFindingError("A vulnerability source must be a JSON object.")

        agent_id = _text(_at_path(source, "agent", "id"))
        cve = _text(_at_path(source, "vulnerability", "id"))
        package_name = _text(_at_path(source, "package", "name"))
        if not agent_id or not cve or not package_name:
            raise InvalidFindingError(
                "A vulnerability record is missing its agent ID, CVE ID, or package name."
            )

        return cls(
            agent_id=agent_id,
            agent_name=_text(_at_path(source, "agent", "name")),
            operating_system=(
                _text(_at_path(source, "host", "os", "full"))
                or _text(_at_path(source, "host", "os", "name"))
            ),
            package_name=package_name,
            package_version=_text(_at_path(source, "package", "version")),
            package_type=_text(_at_path(source, "package", "type")),
            cve=cve,
            severity=_text(_at_path(source, "vulnerability", "severity")),
            cvss_score=_text(_at_path(source, "vulnerability", "score", "base")),
            description=_text(_at_path(source, "vulnerability", "description")),
            affected_condition=_text(
                _at_path(source, "vulnerability", "scanner", "condition")
            ),
            reference=_text(
                _at_path(source, "vulnerability", "scanner", "reference")
            )
            or _text(_at_path(source, "vulnerability", "reference")),
            detected_at=_text(_at_path(source, "vulnerability", "detected_at")),
            status=_text(_at_path(source, "vulnerability", "status")),
        )

    def to_dict(self) -> dict[str, str]:
        return asdict(self)
