#!/usr/bin/env python3

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Iterable, Pattern, Sequence

IMPORTANT_SENDERS: tuple[str, ...] = (
    "Armando Sanchez",
    "Ava Sproul",
    "Bill Riley",
    "Brace Sproul",
    "Constance Porteous",
    "Craig Carlino",
    "Daisy Li",
    "Dan Kanter",
    "Danielle Sullivan",
    "David Abraham",
    "David Buxbaum",
    "David Krebsbach",
    "Deirdre Sproul",
    "Ken Marx",
    "Leighton Sproul",
    "Google Voice",
    "Grant Thompson",
    "Greg Dingens",
    "Jose Lopez",
    "Jeff Carlton",
    "Linda Martin",
    "Luke Meyer",
    "Mary Baumann",
    "Mary Sproul",
    "Melanie Capasso",
    "Michelle Pierce",
    "Nate Reynolds",
    "Robert Jones",
    "Stuart Rickard",
)

INSIGNIFICANCE_PATTERNS: tuple[str, ...] = (
    "https://sameday.costco.com",
    "your Costco Shopper",
    "YOUR ACCOUNT HELP CENTER HELP FORUM",
    "Your Costco order",
)

SIGNIFICANCE_PATTERNS: tuple[str, ...] = (
    "despain",
    "langchain",
    "New text message from ",
)


def _compile_regex_patterns(patterns: Sequence[str], label: str) -> list[Pattern[str]]:
    compiled: list[Pattern[str]] = []
    for raw_pattern in patterns:
        try:
            compiled.append(re.compile(raw_pattern, re.IGNORECASE))
        except re.error as error:  # noqa: TRY002 - we must inspect message for diagnostics
            raise SystemExit(f"FAIL Invalid {label} regex '{raw_pattern}': {error}") from error
    return compiled


INSIGNIFICANCE_REGEXES: tuple[Pattern[str], ...] = tuple(
    _compile_regex_patterns(INSIGNIFICANCE_PATTERNS, "insignificance")
)
SIGNIFICANCE_REGEXES: tuple[Pattern[str], ...] = tuple(
    _compile_regex_patterns(SIGNIFICANCE_PATTERNS, "significance")
)


def match_any_regex(patterns: Iterable[Pattern[str]], fields: Iterable[str]) -> bool:
    for pattern in patterns:
        for field in fields:
            if field and pattern.search(field):
                return True
    return False


def get_important_senders() -> tuple[str, ...]:
    return IMPORTANT_SENDERS


def get_insignificance_regexes() -> tuple[Pattern[str], ...]:
    return INSIGNIFICANCE_REGEXES


def get_significance_regexes() -> tuple[Pattern[str], ...]:
    return SIGNIFICANCE_REGEXES


def dispatch_alert(summary: str, body: str) -> bool:
    dp_root = os.environ.get("dp", os.path.join(Path.home(), "dp"))
    alert_sh = os.path.join(dp_root, "git", "bin", "alert.sh")

    process = subprocess.Popen(
        ["/bin/bash", alert_sh, "-stdin", summary],
        stdin=subprocess.PIPE,
        text=True,
    )
    process.communicate(input=body)
    return process.returncode == 0
