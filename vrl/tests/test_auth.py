from __future__ import annotations

import base64
import json

import pytest

from vrl import auth, config
from vrl.errors import AuthError


def _jwt(payload: dict) -> str:
    def seg(obj) -> str:
        raw = json.dumps(obj).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{seg({'alg': 'RS256'})}.{seg(payload)}.sig"


def test_resolve_token_explicit_wins(monkeypatch):
    monkeypatch.setenv(config.ENV_TOKEN, "from-env")
    assert auth.resolve_token("explicit", base_url="https://x") == "explicit"


def test_resolve_token_env(monkeypatch):
    monkeypatch.setenv(config.ENV_TOKEN, "from-env")
    assert auth.resolve_token(None, base_url="https://x") == "from-env"


def test_resolve_token_no_mint_raises(monkeypatch):
    monkeypatch.delenv(config.ENV_TOKEN, raising=False)
    with pytest.raises(AuthError):
        auth.resolve_token(None, base_url="https://x", allow_mint=False)


def test_resolve_token_mints(monkeypatch):
    monkeypatch.delenv(config.ENV_TOKEN, raising=False)
    monkeypatch.setattr(auth, "mint_oidc_token", lambda **kw: "minted-" + kw["audience"])
    tok = auth.resolve_token(None, base_url="https://api.test")
    assert tok == "minted-https://api.test"


def test_mint_failure_raises(monkeypatch):
    monkeypatch.setattr(auth, "_mint_with_google_auth", lambda *a: None)
    monkeypatch.setattr(auth, "_mint_with_gcloud", lambda *a: None)
    with pytest.raises(AuthError):
        auth.mint_oidc_token(audience="https://x", impersonate_sa="sa@x")


def test_token_email_decodes_jwt():
    tok = _jwt({"email": "me@example.com", "aud": "https://x"})
    assert auth.token_email(tok) == "me@example.com"


def test_token_email_none_for_shared_secret():
    assert auth.token_email("not-a-jwt") is None
