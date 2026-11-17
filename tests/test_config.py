import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vuln_detect.config import ConfigurationError, Settings, load_dotenv
from vuln_detect.setup import configure


class SettingsTests(unittest.TestCase):
    def test_reads_required_settings_and_defaults(self) -> None:
        env = {
            "WAZUH_INDEXER_URL": "https://indexer.example.net:9200/",
            "WAZUH_INDEXER_USERNAME": "reporter",
            "WAZUH_INDEXER_PASSWORD": "not-a-real-password",
        }
        with patch.dict(os.environ, env, clear=True):
            settings = Settings.from_env()

        self.assertEqual(settings.indexer_url, "https://indexer.example.net:9200")
        self.assertTrue(settings.verify_tls)
        self.assertEqual(settings.timeout, 30)

    def test_rejects_url_with_embedded_credentials(self) -> None:
        env = {
            "WAZUH_INDEXER_URL": "https://user:password@indexer.example.net:9200",
            "WAZUH_INDEXER_USERNAME": "reporter",
            "WAZUH_INDEXER_PASSWORD": "password",
        }
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ConfigurationError):
                Settings.from_env()

    def test_rejects_invalid_tls_setting(self) -> None:
        env = {
            "WAZUH_INDEXER_URL": "https://indexer.example.net:9200",
            "WAZUH_INDEXER_USERNAME": "reporter",
            "WAZUH_INDEXER_PASSWORD": "password",
            "WAZUH_VERIFY_TLS": "sometimes",
        }
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ConfigurationError):
                Settings.from_env()

    def test_loads_dotenv_values_without_overriding_process_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text(
                'WAZUH_INDEXER_URL="https://indexer.example.net:9200"\n'
                'WAZUH_INDEXER_USERNAME="reporter"\n'
                'WAZUH_INDEXER_PASSWORD="pass # with spaces"\n',
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"WAZUH_INDEXER_USERNAME": "from-shell"}, clear=True):
                load_dotenv(env_file)
                settings = Settings.from_env()

        self.assertEqual(settings.username, "from-shell")
        self.assertEqual(settings.password, "pass # with spaces")

    def test_configuration_wizard_saves_private_values(self) -> None:
        answers = iter(
            [
                "https://indexer.example.net:9200",
                "reporter",
                "oui",
                "30",
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            configure(
                env_file=env_file,
                input_fn=lambda _prompt: next(answers),
                password_fn=lambda _prompt: "pass # with spaces",
                output_fn=lambda _message: None,
            )
            with patch.dict(os.environ, {}, clear=True):
                load_dotenv(env_file)
                settings = Settings.from_env()

        self.assertEqual(settings.indexer_url, "https://indexer.example.net:9200")
        self.assertEqual(settings.username, "reporter")
        self.assertEqual(settings.password, "pass # with spaces")

    def test_configuration_wizard_keeps_existing_file_when_not_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text("existing", encoding="utf-8")
            configure(
                env_file=env_file,
                input_fn=lambda _prompt: "n",
                password_fn=lambda _prompt: self.fail("Password must not be requested"),
                output_fn=lambda _message: None,
            )

            self.assertEqual(env_file.read_text(encoding="utf-8"), "existing")

    def test_cli_configure_command_runs_setup_without_connecting(self) -> None:
        from unittest.mock import Mock

        from vuln_detect.cli import main

        with patch("vuln_detect.cli.configure", Mock()) as configure_command:
            result = main(["configure"])

        self.assertEqual(result, 0)
        configure_command.assert_called_once_with()
