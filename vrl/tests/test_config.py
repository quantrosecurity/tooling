from __future__ import annotations

import pytest

from vrl import config


@pytest.mark.parametrize(
    "token,ok",
    [
        ("CVE-2024-4577", True),
        ("cve-2024-4577", True),
        ("CVE-1999-0001", True),
        ("CVE-2024-1234567", True),
        ("CVE-2024-123", False),  # needs 4+ digits
        ("CVE-24-1234", False),
        ("notacve", False),
        ("2024-4577", False),
    ],
)
def test_is_cve(token, ok):
    assert config.is_cve(token) is ok


def test_parse_cve_tokens_splits_and_dedupes():
    raw = "cve-2024-1, CVE-2024-2;CVE-2024-2  cve-2024-3"
    assert config.parse_cve_tokens(raw) == ["CVE-2024-1", "CVE-2024-2", "CVE-2024-3"]


def test_parse_cve_tokens_empty():
    assert config.parse_cve_tokens("   ") == []


@pytest.mark.parametrize(
    "email,ok",
    [("a@b.com", True), ("x.y@sub.example.co", True), ("no-at", False), ("a@b", False)],
)
def test_is_email(email, ok):
    assert config.is_email(email) is ok


def test_base_url_precedence(monkeypatch):
    monkeypatch.delenv(config.ENV_BASE_URL, raising=False)
    assert config.base_url() == config.DEFAULT_BASE_URL
    assert config.base_url("https://x/") == "https://x"
    monkeypatch.setenv(config.ENV_BASE_URL, "https://env.example/")
    assert config.base_url() == "https://env.example"
    assert config.base_url("https://flag.example") == "https://flag.example"  # flag wins


def test_terminal_statuses():
    assert config.is_terminal("exploit_generated")
    assert config.is_terminal("no_exploit")
    assert not config.is_terminal("pending")
    assert not config.is_terminal("processing")
    assert not config.is_terminal(None)


def test_status_meta_fallback():
    meta = config.status_meta("some_new_state")
    assert meta.label == "some_new_state"
    assert meta.terminal is False
