#!/usr/bin/env python3
"""Tests for alert__gmail_check_important_senders.py.

alert.sh stores each alert under a checksum of its (subject, body), so the
alert text alone decides de-duplication. These tests pin down the rule:
one alert per Gmail message -- the same message always yields identical
alert text, and two distinct messages never do, even when their sender,
subject and snippet are identical.

usage: python3 test_alert__gmail_check_important_senders.py
"""

from __future__ import annotations

import contextlib
import errno
import io
import socket
import sys
import unittest
from typing import Callable
from unittest import mock

import alert__gmail_check_important_senders as gmail_check

IDENTICAL_TEXT_HEADERS: list[dict[str, str]] = [
    {"name": "From", "value": '"Deirdre Sproul (SMS)" <1.2.x@txt.voice.google.com>'},
    {"name": "Subject", "value": "New text message from Deirdre Sproul (415) 370-6422"},
]


class FakeGmailService:
    """Minimal stand-in for the googleapiclient Gmail service: every
    message id resolves to the same sender, subject and snippet."""

    def users(self) -> "FakeGmailService":
        return self

    def messages(self) -> "FakeGmailService":
        return self

    def get(self, **_kwargs) -> "FakeGmailService":
        return self

    def execute(self) -> dict:
        return {"payload": {"headers": IDENTICAL_TEXT_HEADERS}, "snippet": "Google Voice ok"}


def dispatch_alerts_for_message_ids(message_ids: list[str]) -> list[tuple[str, str]]:
    """Run process_single_message once per id (with an empty seen cache)
    and return the (summary, body) pairs handed to alert.sh."""
    dispatched: list[tuple[str, str]] = []

    def record_dispatch(summary: str, body: str) -> bool:
        dispatched.append((summary, body))
        return True

    with mock.patch.object(gmail_check, "dispatch_alert", side_effect=record_dispatch):
        for message_id in message_ids:
            gmail_check.process_single_message(FakeGmailService(), {"id": message_id}, set(), set())
    return dispatched


class OneAlertPerGmailMessageTest(unittest.TestCase):
    def test_same_message_yields_identical_alert_text(self) -> None:
        first, second = dispatch_alerts_for_message_ids(["1a15bf20285cc366", "1a15bf20285cc366"])
        self.assertEqual(first, second)

    def test_distinct_messages_with_identical_text_yield_distinct_alerts(self) -> None:
        first, second = dispatch_alerts_for_message_ids(["1a15bf20285cc366", "1a15bf12711c3e0c"])
        self.assertNotEqual(first, second)

    def test_alert_body_names_the_gmail_message_id(self) -> None:
        ((_summary, body),) = dispatch_alerts_for_message_ids(["1a15bf20285cc366"])
        self.assertIn("1a15bf20285cc366", body)


def raise_wrapped_dns_failure() -> None:
    """Mimic the google-auth/requests/urllib3 layering: the socket.gaierror
    is buried several links down the __cause__/__context__ chain."""
    try:
        try:
            raise socket.gaierror(8, "nodename nor servname provided, or not known")
        except socket.gaierror as dns_error:
            raise RuntimeError("Max retries exceeded with url: /token") from dns_error
    except RuntimeError:
        raise ValueError("HTTPSConnectionPool(host='oauth2.googleapis.com', port=443)")


def capture_exception(operation: Callable[[], None]) -> BaseException:
    try:
        operation()
    except BaseException as error:  # noqa: BLE001 - the test inspects whatever was raised
        return error
    raise AssertionError("operation did not raise")


def run_main_expecting_exit_code(error: BaseException) -> tuple[int, str, str]:
    """Run main() with check_for_important_mail raising error; return
    (exit code, stdout, stderr)."""
    stdout, stderr = io.StringIO(), io.StringIO()
    exit_code = 0
    with mock.patch.object(gmail_check, "check_for_important_mail", side_effect=error), \
            mock.patch.object(sys, "argv", ["alert__gmail_check_important_senders.py"]), \
            contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            gmail_check.main()
        except SystemExit as exit_request:
            exit_code = int(exit_request.code or 0)
    return exit_code, stdout.getvalue(), stderr.getvalue()


class NetworkUnreachableTest(unittest.TestCase):
    def test_dns_failure_buried_in_exception_chain_counts_as_offline(self) -> None:
        self.assertTrue(gmail_check.is_network_unreachable_error(capture_exception(raise_wrapped_dns_failure)))

    def test_network_unreachable_errno_counts_as_offline(self) -> None:
        self.assertTrue(gmail_check.is_network_unreachable_error(OSError(errno.ENETUNREACH, "Network is unreachable")))

    def test_unrelated_errors_do_not_count_as_offline(self) -> None:
        self.assertFalse(gmail_check.is_network_unreachable_error(ValueError("invalid_grant")))
        self.assertFalse(gmail_check.is_network_unreachable_error(OSError(errno.ENOENT, "No such file")))

    def test_real_google_auth_dns_failure_counts_as_offline(self) -> None:
        from google.auth.transport.requests import Request

        error = capture_exception(lambda: Request()("https://nonexistent-host.invalid/token", method="POST"))
        self.assertTrue(gmail_check.is_network_unreachable_error(error))

    def test_main_skips_quietly_when_offline(self) -> None:
        exit_code, stdout, stderr = run_main_expecting_exit_code(capture_exception(raise_wrapped_dns_failure))
        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, "")
        self.assertTrue(stdout.startswith("OK "), stdout)

    def test_main_still_fails_loudly_on_other_errors(self) -> None:
        exit_code, _stdout, stderr = run_main_expecting_exit_code(ValueError("boom"))
        self.assertEqual(exit_code, 1)
        self.assertTrue(stderr.startswith("FAIL "), stderr)


if __name__ == "__main__":
    unittest.main()
