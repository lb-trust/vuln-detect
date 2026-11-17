import os
import unittest
from unittest.mock import patch

from vuln_detect.config import ConfigurationError, Settings


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
