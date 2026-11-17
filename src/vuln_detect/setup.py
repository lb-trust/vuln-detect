import getpass
import json
from pathlib import Path
from typing import Callable

from vuln_detect.config import ConfigurationError, Settings


def _ask_value(
    prompt: str, default: str, input_fn: Callable[[str], str]
) -> str:
    value = input_fn(f"{prompt} [{default}]: ").strip()
    return value or default


def configure(
    env_file: Path = Path(".env"),
    input_fn: Callable[[str], str] = input,
    password_fn: Callable[[str], str] = getpass.getpass,
    output_fn: Callable[[str], None] = print,
) -> bool:
    output_fn("Configuration de l'accès en lecture au Wazuh Indexer.")
    output_fn("Utilisez l'adresse de l'Indexer, pas celle du Wazuh Manager.")
    output_fn("Exemple : https://wazuh.example.net:9200")
    if env_file.exists():
        overwrite = input_fn(
            f"{env_file} existe déjà. Le remplacer ? [y/N]: "
        ).strip().lower()
        if overwrite not in {"y", "yes", "o", "oui"}:
            output_fn("Configuration annulée ; aucun fichier n'a été modifié.")
            return False

    url = input_fn("URL de l'API Indexer: ").strip()
    username = input_fn("Nom du compte Indexer en lecture: ").strip()
    password = password_fn("Mot de passe Indexer (saisie masquée): ")
    verify_tls_input = _ask_value(
        "Vérifier le certificat TLS ? (oui/non)", "oui", input_fn
    ).lower()
    if verify_tls_input in {"oui", "o", "yes", "y"}:
        verify_tls = "true"
    elif verify_tls_input in {"non", "n", "no"}:
        verify_tls = "false"
    else:
        raise ConfigurationError("Répondez oui ou non pour la vérification TLS.")
    timeout = _ask_value("Délai d'attente en secondes", "30", input_fn)

    values = {
        "WAZUH_INDEXER_URL": url,
        "WAZUH_INDEXER_USERNAME": username,
        "WAZUH_INDEXER_PASSWORD": password,
        "WAZUH_VERIFY_TLS": verify_tls,
        "WAZUH_TIMEOUT": timeout,
    }
    settings = Settings.from_mapping(values)

    normalized_values = {
        "WAZUH_INDEXER_URL": settings.indexer_url,
        "WAZUH_INDEXER_USERNAME": settings.username,
        "WAZUH_INDEXER_PASSWORD": settings.password,
        "WAZUH_VERIFY_TLS": str(settings.verify_tls).lower(),
        "WAZUH_TIMEOUT": str(settings.timeout),
    }
    content = (
        "# Wazuh Indexer connection. Keep this file private and out of Git.\n"
        + "".join(
            f"{name}={json.dumps(value, ensure_ascii=False)}\n"
            for name, value in normalized_values.items()
        )
    )
    env_file.write_text(content, encoding="utf-8")
    output_fn(f"Configuration enregistrée dans {env_file}.")
    output_fn("Vous pouvez maintenant lancer : python -m vuln_detect")
    return True
