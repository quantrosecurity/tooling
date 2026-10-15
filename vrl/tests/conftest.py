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
