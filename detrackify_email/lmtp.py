"""
LMTP proxy server for detrackify email processing.

Receives mail via LMTP, processes it through the Detrackify engine,
and forwards it to a downstream LMTP server (e.g., Dovecot).
"""

import asyncio
import io
import logging
import os
import signal
import smtplib
from typing import Optional, Tuple

from aiosmtpd.controller import Controller, UnixSocketController
from aiosmtpd.lmtp import LMTP

from .detrackify import Detrackify
from .configuration import Configuration


def parse_address(address: str) -> Tuple[str, Optional[int]]:
    """Parse an address string into (host, port) or (socket_path, None).

    Returns (host, port) for TCP addresses like '127.0.0.1:10024',
    or (path, None) for Unix socket paths like '/var/run/dovecot/lmtp'.
    """
    if '/' in address or not any(c.isdigit() for c in address.split(':')[-1:]):
        return address, None

    if ':' in address:
        parts = address.rsplit(':', 1)
        try:
            return parts[0], int(parts[1])
        except ValueError:
            return address, None

    return address, None


class LMTPController(Controller):
    """Controller that creates an LMTP server instead of SMTP."""

    def factory(self):
        return LMTP(self.handler, **self.SMTP_kwargs)


class LMTPUnixSocketController(UnixSocketController):
    """UnixSocketController that creates an LMTP server instead of SMTP."""

    def factory(self):
        return LMTP(self.handler, **self.SMTP_kwargs)


class DetrackifyLMTPHandler:
    """aiosmtpd handler that processes email through Detrackify and forwards downstream via LMTP."""

    def __init__(self, config: Configuration, downstream: str):
        self.config = config
        self.downstream = downstream

    def _connect_downstream(self) -> smtplib.LMTP:
        """Connect to the downstream LMTP server."""
        host, port = parse_address(self.downstream)
        if port is not None:
            return smtplib.LMTP(host, port)
        return smtplib.LMTP(host)

    def _process_message(self, raw_data: bytes) -> bytes:
        """Run the raw email through Detrackify, returning processed bytes.

        On failure, returns the original message unchanged (failsafe).
        """
        detrack = Detrackify(self.config)
        output = io.BytesIO()
        try:
            detrack.process_buffer(raw_data, output)
            return output.getvalue()
        except Exception:
            logging.exception("Detrackify processing failed; forwarding original message")
            return raw_data

    async def handle_DATA(self, server, session, envelope):
        """Handle an incoming LMTP DATA command.

        LMTP requires one response line per recipient (RFC 2033 Sec 4.2).
        We process the message once, then deliver per-recipient to the downstream.
        """
        processed = self._process_message(envelope.content)
        responses = []

        for rcpt in envelope.rcpt_tos:
            try:
                downstream = self._connect_downstream()
                try:
                    downstream.sendmail(envelope.mail_from, [rcpt], processed)
                    responses.append(f'250 OK <{rcpt}>')
                except smtplib.SMTPRecipientsRefused as exc:
                    code, msg = list(exc.recipients.values())[0]
                    responses.append(f'{code} {msg.decode("utf-8", errors="replace")}')
                except smtplib.SMTPResponseException as exc:
                    responses.append(f'{exc.smtp_code} {exc.smtp_error.decode("utf-8", errors="replace")}')
                finally:
                    try:
                        downstream.quit()
                    except smtplib.SMTPException:
                        pass
            except Exception as exc:
                logging.exception("Failed to deliver to %s via downstream %s", rcpt, self.downstream)
                responses.append(f'451 Temporary failure delivering to <{rcpt}>')

        return '\r\n'.join(responses)


def run_lmtp_server(config: Configuration, *, foreground: bool = True) -> None:
    """Start the LMTP proxy server.

    Reads listen/downstream addresses from *config* and blocks
    until interrupted (SIGINT / SIGTERM) when *foreground* is True.
    """
    listen = config.get(Configuration.CFG_LMTP_LISTEN)
    downstream = config.get(Configuration.CFG_LMTP_DOWNSTREAM)

    if not downstream:
        raise ValueError("LMTP downstream address must be configured")

    handler = DetrackifyLMTPHandler(config, downstream)

    host, port = parse_address(listen)
    if port is not None:
        controller = LMTPController(handler, hostname=host, port=port)
        logging.info("Starting LMTP server on %s:%d (downstream: %s)", host, port, downstream)
    else:
        controller = LMTPUnixSocketController(handler, unix_socket=host)
        logging.info("Starting LMTP server on unix:%s (downstream: %s)", host, downstream)

    controller.start()

    if foreground:
        shutdown = asyncio.Event()

        def _signal_handler(*_):
            shutdown.set()

        loop = asyncio.new_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _signal_handler)

        try:
            loop.run_until_complete(shutdown.wait())
        finally:
            controller.stop()
            loop.close()
            logging.info("LMTP server stopped")
    else:
        return controller
