"""Unit tests for security_events.config — log path selection."""

import os
import unittest
from unittest.mock import patch

from agent_sec_cli.security_events.config import (
    FALLBACK_LOG_PATH,
    PRIMARY_LOG_PATH,
    get_db_path,
    get_log_path,
)

# Remove AGENT_SEC_DATA_DIR for these tests so we exercise the real path logic.
_env_without_override = {
    k: v for k, v in os.environ.items() if k != "AGENT_SEC_DATA_DIR"
}


@patch.dict(os.environ, _env_without_override, clear=True)
class TestGetLogPath(unittest.TestCase):
    @patch("agent_sec_cli.security_events.config.os.access", return_value=True)
    @patch("agent_sec_cli.security_events.config.Path.is_dir", return_value=True)
    @patch("agent_sec_cli.security_events.config.Path.mkdir")
    @patch("agent_sec_cli.security_events.config.Path.chmod")
    def test_primary_path_when_writable(
        self, mock_chmod, mock_mkdir, mock_isdir, mock_access
    ):
        path = get_log_path()
        self.assertEqual(path, PRIMARY_LOG_PATH)

    @patch("agent_sec_cli.security_events.config.os.access", return_value=False)
    @patch("agent_sec_cli.security_events.config.Path.is_dir", return_value=True)
    @patch("agent_sec_cli.security_events.config.Path.mkdir")
    @patch("agent_sec_cli.security_events.config.Path.chmod")
    def test_fallback_when_primary_not_writable(
        self, mock_chmod, mock_mkdir, mock_isdir, mock_access
    ):
        path = get_log_path()
        self.assertEqual(path, FALLBACK_LOG_PATH)

    @patch("agent_sec_cli.security_events.config.Path.mkdir")
    @patch("agent_sec_cli.security_events.config.Path.chmod")
    def test_fallback_when_makedirs_fails(self, mock_chmod, mock_mkdir):
        # First call (primary) raises, second call (fallback) succeeds
        mock_mkdir.side_effect = [OSError("permission denied"), None]
        path = get_log_path()
        self.assertEqual(path, FALLBACK_LOG_PATH)


@patch.dict(os.environ, _env_without_override, clear=True)
class TestGetDbPath(unittest.TestCase):
    @patch("agent_sec_cli.security_events.config.os.access", return_value=True)
    @patch("agent_sec_cli.security_events.config.Path.is_dir", return_value=True)
    @patch("agent_sec_cli.security_events.config.Path.mkdir")
    @patch("agent_sec_cli.security_events.config.Path.chmod")
    def test_db_path_uses_primary_dir(
        self, mock_chmod, mock_mkdir, mock_isdir, mock_access
    ):
        path = get_db_path()
        self.assertEqual(path, "/var/log/agent-sec/security-events.db")

    @patch("agent_sec_cli.security_events.config.os.access", return_value=False)
    @patch("agent_sec_cli.security_events.config.Path.is_dir", return_value=True)
    @patch("agent_sec_cli.security_events.config.Path.mkdir")
    @patch("agent_sec_cli.security_events.config.Path.chmod")
    def test_db_path_uses_fallback_dir(
        self, mock_chmod, mock_mkdir, mock_isdir, mock_access
    ):
        path = get_db_path()
        self.assertTrue(path.endswith(".agent-sec-core/security-events.db"))


if __name__ == "__main__":
    unittest.main()
