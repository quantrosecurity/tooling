"""Shared fixtures + sample payloads for the offline test suite."""

from __future__ import annotations

import pytest

BASE = "https://api.test"


@pytest.fixture
def base() -> str:
    return BASE


def queue_item(cve: str = "CVE-2024-4577", status: str = "processing", **details):
    """A representative GET /queue/{id} payload."""
    return {
        "id": cve,
        "cveId": cve,
        "status": status,
        "source": "community",
        "submittedBy": None,
        "position": 3,
        "priority": 820,
        "details": {"title": "PHP CGI argument injection", **details},
        "submittedAt": "2026-10-14T09:00:00+00:00",
        "updatedAt": "2026-10-14T09:12:00+00:00",
    }


def cve_record(cve: str = "CVE-2024-4577"):
    """A representative GET /cves item."""
    return {
        "cve": cve,
        "title": "PHP CGI argument injection",
        "ecosystem": "php",
        "package": "php",
        "affectedVersion": "8.1.0",
        "aiExploit": True,
        "costUsd": 3.82,
        "timeToGenerateSec": 672.4,
        "tokens": 419772,
        "difficultyLevel": 3,
        "epss": 0.944,
        "exploitInWild": True,
        "cwe": "CWE-78",
        "cweLabel": "OS Command Injection",
        "outcome": "exploit_generated",
        "processedAt": "2026-10-14T09:12:00+00:00",
    }


def replay_trace(cve: str = "CVE-2024-4577", *, attempts=None, verdict=None):
    """A representative GET /replay/{cve} payload — public projection by
    default; pass raw-journal attempts (trigger_error/reasoning/tool_calls)
    and a verdict for the internal view."""
    return {
        "cve": cve,
        "package": "php",
        "ecosystem": "php",
        "vulnVersion": "8.1.0",
        "fixedVersions": ["8.1.1"],
        "harnessVersion": "3.0",
        "finalStatus": "exploit_generated",
        "ingestedAt": "2026-10-16T21:00:00+00:00",
        "attempts": attempts
        if attempts is not None
        else [
            {
                "attempt": 1,
                "ts": "2026-10-14T09:00:00Z",
                "rejected": True,
                "triggerError": (
                    "judge rejected: [positive.no_marker] the exploit produced no marker "
                    "on the vulnerable build"
                ),
            },
            {"attempt": 2, "ts": "2026-10-14T09:12:00Z", "rejected": False},
        ],
        **({"verdict": verdict} if verdict is not None else {}),
    }


def journal_attempts():
    """Raw-journal attempt entries (the internal view's spelling)."""
    return [
        {
            "cve": "CVE-2024-4577",
            "attempt": 1,
            "ts": "2026-10-14T09:00:00Z",
            "trigger_error": "judge rejected: [positive.no_marker] no marker",
            "reasoning": ["first attempt reasoning", "second reasoning entry"],
            "tool_calls": [{"tool": "read_file", "target": "Dockerfile", "ok": True}],
        },
        {
            "cve": "CVE-2024-4577",
            "attempt": 2,
            "ts": "2026-10-14T09:12:00Z",
            "reasoning": ["final attempt reasoning"],
            "tool_calls": [],
        },
    ]
