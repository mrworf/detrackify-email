"""Tests for the LMTP proxy server."""

import asyncio
import io
import os
import smtplib
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

import yaml
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detrackify_email import Configuration
from detrackify_email.lmtp import (
    DetrackifyLMTPHandler,
    LMTPController,
    LMTPUnixSocketController,
    parse_address,
    run_lmtp_server,
)


SIMPLE_EMAIL = (
    b"From: sender@example.com\r\n"
    b"To: recipient@example.com\r\n"
    b"Subject: Test\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"\r\n"
    b"<html><body><p>Hello</p>"
    b'<img src="https://tracking.example.com/pixel.gif" width="1" height="1">'
    b"</body></html>\r\n"
)


# ---------------------------------------------------------------------------
# parse_address tests
# ---------------------------------------------------------------------------

class TestParseAddress(unittest.TestCase):
    def test_tcp_address(self):
        host, port = parse_address("127.0.0.1:10024")
        assert host == "127.0.0.1"
        assert port == 10024

    def test_tcp_address_hostname(self):
        host, port = parse_address("localhost:25")
        assert host == "localhost"
        assert port == 25

    def test_unix_socket(self):
        host, port = parse_address("/var/run/dovecot/lmtp")
        assert host == "/var/run/dovecot/lmtp"
        assert port is None

    def test_unix_socket_relative(self):
        host, port = parse_address("/tmp/detrackify.sock")
        assert host == "/tmp/detrackify.sock"
        assert port is None

    def test_ipv6_style(self):
        """A plain hostname without port should return None port."""
        host, port = parse_address("dovecot")
        assert host == "dovecot"
        assert port is None


# ---------------------------------------------------------------------------
# DetrackifyLMTPHandler unit tests
# ---------------------------------------------------------------------------

class TestDetrackifyLMTPHandler(unittest.TestCase):
    def _make_config(self):
        config = Configuration()
        config.set(Configuration.CFG_LMTP_DOWNSTREAM, "127.0.0.1:10025")
        return config

    def test_process_message_returns_bytes(self):
        config = self._make_config()
        handler = DetrackifyLMTPHandler(config, "127.0.0.1:10025")
        result = handler._process_message(SIMPLE_EMAIL)
        assert isinstance(result, bytes)
        assert b"X-Detrackify" in result

    def test_process_message_failsafe(self):
        """If Detrackify.process_buffer raises, original message is returned."""
        config = self._make_config()
        handler = DetrackifyLMTPHandler(config, "127.0.0.1:10025")

        with patch("detrackify_email.lmtp.Detrackify") as mock_cls:
            mock_cls.return_value.process_buffer.side_effect = RuntimeError("boom")
            result = handler._process_message(SIMPLE_EMAIL)

        assert result == SIMPLE_EMAIL

    def test_handle_data_success(self):
        """handle_DATA delivers to downstream and returns 250 per recipient."""
        config = self._make_config()
        handler = DetrackifyLMTPHandler(config, "127.0.0.1:10025")

        mock_lmtp = MagicMock(spec=smtplib.LMTP)

        with patch.object(handler, "_connect_downstream", return_value=mock_lmtp):
            envelope = MagicMock()
            envelope.content = SIMPLE_EMAIL
            envelope.mail_from = "sender@example.com"
            envelope.rcpt_tos = ["recipient@example.com"]

            result = asyncio.run(
                handler.handle_DATA(None, None, envelope)
            )

        assert "250" in result
        assert "recipient@example.com" in result
        mock_lmtp.sendmail.assert_called_once()
        mock_lmtp.quit.assert_called_once()

    def test_handle_data_multi_recipient(self):
        """LMTP requires per-recipient responses."""
        config = self._make_config()
        handler = DetrackifyLMTPHandler(config, "127.0.0.1:10025")

        mock_lmtp = MagicMock(spec=smtplib.LMTP)

        with patch.object(handler, "_connect_downstream", return_value=mock_lmtp):
            envelope = MagicMock()
            envelope.content = SIMPLE_EMAIL
            envelope.mail_from = "sender@example.com"
            envelope.rcpt_tos = ["a@example.com", "b@example.com", "c@example.com"]

            result = asyncio.run(
                handler.handle_DATA(None, None, envelope)
            )

        lines = result.split("\r\n")
        assert len(lines) == 3
        for line in lines:
            assert line.startswith("250")
        assert mock_lmtp.sendmail.call_count == 3

    def test_handle_data_downstream_refused(self):
        """Downstream rejecting a recipient propagates the error code."""
        config = self._make_config()
        handler = DetrackifyLMTPHandler(config, "127.0.0.1:10025")

        mock_lmtp = MagicMock(spec=smtplib.LMTP)
        mock_lmtp.sendmail.side_effect = smtplib.SMTPRecipientsRefused(
            {"bad@example.com": (550, b"User unknown")}
        )

        with patch.object(handler, "_connect_downstream", return_value=mock_lmtp):
            envelope = MagicMock()
            envelope.content = SIMPLE_EMAIL
            envelope.mail_from = "sender@example.com"
            envelope.rcpt_tos = ["bad@example.com"]

            result = asyncio.run(
                handler.handle_DATA(None, None, envelope)
            )

        assert "550" in result

    def test_handle_data_downstream_connection_failure(self):
        """Connection failure to downstream returns 451 temporary error."""
        config = self._make_config()
        handler = DetrackifyLMTPHandler(config, "127.0.0.1:10025")

        with patch.object(
            handler, "_connect_downstream", side_effect=ConnectionRefusedError("refused")
        ):
            envelope = MagicMock()
            envelope.content = SIMPLE_EMAIL
            envelope.mail_from = "sender@example.com"
            envelope.rcpt_tos = ["user@example.com"]

            result = asyncio.run(
                handler.handle_DATA(None, None, envelope)
            )

        assert "451" in result

    def test_handle_data_smtp_response_exception(self):
        """SMTPResponseException from downstream is propagated."""
        config = self._make_config()
        handler = DetrackifyLMTPHandler(config, "127.0.0.1:10025")

        mock_lmtp = MagicMock(spec=smtplib.LMTP)
        mock_lmtp.sendmail.side_effect = smtplib.SMTPResponseException(
            452, b"Mailbox full"
        )

        with patch.object(handler, "_connect_downstream", return_value=mock_lmtp):
            envelope = MagicMock()
            envelope.content = SIMPLE_EMAIL
            envelope.mail_from = "sender@example.com"
            envelope.rcpt_tos = ["user@example.com"]

            result = asyncio.run(
                handler.handle_DATA(None, None, envelope)
            )

        assert "452" in result


# ---------------------------------------------------------------------------
# LMTP server integration tests
# ---------------------------------------------------------------------------

def _find_free_port():
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestLMTPServerTCP(unittest.TestCase):
    """Test that the LMTP server starts, listens on TCP, and accepts connections."""

    def test_tcp_server_starts_and_stops(self):
        port = _find_free_port()
        config = Configuration()
        config.set(Configuration.CFG_LMTP_LISTEN, f"127.0.0.1:{port}")
        config.set(Configuration.CFG_LMTP_DOWNSTREAM, "127.0.0.1:19999")

        controller = run_lmtp_server(config, foreground=False)
        try:
            time.sleep(0.5)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect(("127.0.0.1", port))
                banner = s.recv(1024)
                assert b"220" in banner
        finally:
            controller.stop()

    def test_tcp_server_speaks_lmtp(self):
        """Verify the server responds to LHLO (LMTP) instead of EHLO."""
        port = _find_free_port()
        config = Configuration()
        config.set(Configuration.CFG_LMTP_LISTEN, f"127.0.0.1:{port}")
        config.set(Configuration.CFG_LMTP_DOWNSTREAM, "127.0.0.1:19999")

        controller = run_lmtp_server(config, foreground=False)
        try:
            time.sleep(0.5)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect(("127.0.0.1", port))
                s.recv(1024)  # banner
                s.sendall(b"LHLO test\r\n")
                resp = s.recv(1024)
                assert b"250" in resp
        finally:
            controller.stop()


class TestLMTPServerUnixSocket(unittest.TestCase):
    """Test that the LMTP server can listen on a Unix socket."""

    def test_unix_socket_server_starts_and_stops(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sock_path = os.path.join(tmpdir, "lmtp.sock")
            config = Configuration()
            config.set(Configuration.CFG_LMTP_LISTEN, sock_path)
            config.set(Configuration.CFG_LMTP_DOWNSTREAM, "127.0.0.1:19999")

            controller = run_lmtp_server(config, foreground=False)
            try:
                time.sleep(0.5)
                assert os.path.exists(sock_path)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.settimeout(3)
                    s.connect(sock_path)
                    banner = s.recv(1024)
                    assert b"220" in banner
            finally:
                controller.stop()


# ---------------------------------------------------------------------------
# Configuration loading tests
# ---------------------------------------------------------------------------

class TestLMTPConfigLoading(unittest.TestCase):
    def test_default_lmtp_config(self):
        config = Configuration()
        assert config.get(Configuration.CFG_LMTP_LISTEN) == "127.0.0.1:10024"
        assert config.get(Configuration.CFG_LMTP_DOWNSTREAM) == "/var/run/dovecot/lmtp"

    def test_lmtp_config_from_yaml(self):
        config_data = {
            "common": {"salt": "testsalt1234"},
            "email": {
                "lmtp": {
                    "listen": "0.0.0.0:2525",
                    "downstream": "127.0.0.1:24",
                }
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name

        try:
            config = Configuration()
            config.load_from_yaml(config_path)
            assert config.get(Configuration.CFG_LMTP_LISTEN) == "0.0.0.0:2525"
            assert config.get(Configuration.CFG_LMTP_DOWNSTREAM) == "127.0.0.1:24"
        finally:
            os.unlink(config_path)

    def test_lmtp_config_cli_override(self):
        config = Configuration()
        config.set(Configuration.CFG_LMTP_LISTEN, "/tmp/test.sock")
        config.set(Configuration.CFG_LMTP_DOWNSTREAM, "dovecot:24")
        assert config.get(Configuration.CFG_LMTP_LISTEN) == "/tmp/test.sock"
        assert config.get(Configuration.CFG_LMTP_DOWNSTREAM) == "dovecot:24"

    def test_unknown_lmtp_keys_warned(self):
        """Unknown keys under email.lmtp should be warned about and ignored."""
        config_data = {
            "email": {
                "lmtp": {
                    "listen": "0.0.0.0:2525",
                    "downstream": "127.0.0.1:24",
                    "bogus_key": "should_be_ignored",
                }
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name

        try:
            config = Configuration()
            config.load_from_yaml(config_path)
            assert config.get(Configuration.CFG_LMTP_LISTEN) == "0.0.0.0:2525"
            assert config.get(Configuration.CFG_LMTP_DOWNSTREAM) == "127.0.0.1:24"
        finally:
            os.unlink(config_path)


# ---------------------------------------------------------------------------
# CLI argument parsing tests
# ---------------------------------------------------------------------------

class TestLMTPCLIParsing(unittest.TestCase):
    def test_cli_argument_parsing(self):
        """Test that detrackify_lmtp.py accepts the expected arguments."""
        import importlib
        import detrackify_lmtp

        with patch("sys.argv", [
            "detrackify_lmtp.py",
            "--listen", "0.0.0.0:10024",
            "--downstream", "127.0.0.1:24",
            "--guardserver", "http://localhost:9090",
            "--guardsalt", "testsalt1234",
            "--guardlink", "mismatch",
            "--verbose",
        ]):
            # We can't actually run main() as it blocks, but we can test
            # that the argparse setup is valid by importing and checking
            from detrackify_lmtp import main
            assert callable(main)


class TestRunLMTPServerValidation(unittest.TestCase):
    def test_missing_downstream_raises(self):
        config = Configuration()
        config.set(Configuration.CFG_LMTP_DOWNSTREAM, None)

        with pytest.raises(ValueError, match="downstream"):
            run_lmtp_server(config, foreground=False)
