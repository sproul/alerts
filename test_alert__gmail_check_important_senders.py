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

import unittest
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


if __name__ == "__main__":
    unittest.main()
