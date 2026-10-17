"""Credentials for the privileged ``/internal`` plane.

The server accepts either a Google-signed OIDC identity token (verified by
signature + audience + an email allow-list) **or** a configured break-glass
shared secret, both presented as ``Authorization: Bearer <token>``. Public reads
and the public submit form need none of this.

Resolution order for a bearer token:

1. an explicit ``--token`` (also used verbatim for a shared secret);
2. the ``VRL_TOKEN`` environment variable;
3. a freshly minted Google OIDC token — in-process via ``google-auth`` if it is
   installed, otherwise by shelling out to ``gcloud``.

The audience of a minted token must equal the API base URL, and the caller must
either run as, or be able to impersonate, an allow-listed service account.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from typing import Optional

from . import config
from .errors import AuthError


def resolve_token(
    explicit: Optional[str],
    *,
    base_url: str,
    impersonate_sa: Optional[str] = None,
    audience: Optional[str] = None,
    allow_mint: bool = True,
) -> str:
    """Return a bearer token for the internal plane, or raise :class:`AuthError`.

    ``explicit`` wins (a ``--token`` flag, which may be an OIDC token or the
    shared secret). Otherwise ``VRL_TOKEN`` is used, and failing that an OIDC
    token is minted (unless ``allow_mint`` is false).
    """
    if explicit:
        return explicit.strip()

    env_token = os.getenv(config.ENV_TOKEN)
    if env_token:
        return env_token.strip()

    if not allow_mint:
        raise AuthError(
            "No credentials for the internal plane.",
            hint=f"Pass --token or set {config.ENV_TOKEN}.",
        )

    aud = audience or os.getenv(config.ENV_OIDC_AUDIENCE) or base_url
    # impersonate_sa wins when a caller passes one explicitly; otherwise this
    # deployment's default SA (see config.internal_sa) — the operator's
    # `--internal` works out of the box, no env var required.
    sa = impersonate_sa or config.internal_sa()
    return mint_oidc_token(audience=aud, impersonate_sa=sa)


def mint_oidc_token(*, audience: str, impersonate_sa: Optional[str]) -> str:
    """Mint a Google OIDC identity token with ``aud == audience``.

    Prefers the in-process ``google-auth`` path; falls back to ``gcloud`` so the
    CLI works whether or not the optional ``auth`` extra is installed.
    """
    token = _mint_with_google_auth(audience, impersonate_sa)
    if token:
        return token
    token = _mint_with_gcloud(audience, impersonate_sa)
    if token:
        return token
    target = impersonate_sa or config.DEFAULT_INTERNAL_SA
    raise AuthError(
        "Could not mint a Google OIDC token.",
        hint=(
            "Install the auth extra (pip install 'vrl-cli[auth]') or the gcloud CLI, "
            f"run `gcloud auth login`, and ensure you can impersonate {target} "
            "(roles/iam.serviceAccountTokenCreator) — or run on a GCP workload whose "
            "own identity is allow-listed. Or pass --token directly."
        ),
    )


def _mint_with_google_auth(audience: str, impersonate_sa: Optional[str]) -> Optional[str]:
    try:
        import google.auth  # type: ignore
        from google.auth.transport.requests import Request  # type: ignore
    except Exception:
        return None

    try:
        from google.auth import impersonated_credentials  # type: ignore
        from google.oauth2 import id_token as oauth_id_token  # type: ignore

        request = Request()
        source_creds, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )

        if impersonate_sa:
            target = impersonated_credentials.Credentials(
                source_credentials=source_creds,
                target_principal=impersonate_sa,
                target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
            id_creds = impersonated_credentials.IDTokenCredentials(
                target, target_audience=audience, include_email=True
            )
            id_creds.refresh(request)
            return id_creds.token

        # No impersonation: fetch an ID token for the ambient identity (works on
        # a GCP workload whose own SA is allow-listed).
        return oauth_id_token.fetch_id_token(request, audience)
    except Exception:
        return None


def _mint_with_gcloud(audience: str, impersonate_sa: Optional[str]) -> Optional[str]:
    gcloud = shutil.which("gcloud")
    if not gcloud:
        return None
    cmd = [
        gcloud,
        "auth",
        "print-identity-token",
        f"--audiences={audience}",
        "--include-email",
    ]
    if impersonate_sa:
        cmd.append(f"--impersonate-service-account={impersonate_sa}")
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception:
        return None
    if out.returncode != 0:
        return None
    token = out.stdout.strip()
    return token or None


def token_email(token: str) -> Optional[str]:
    """Best-effort read of the ``email`` claim for display — no verification.

    Returns ``None`` for a shared secret or any non-JWT token.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)  # pad to a multiple of 4
        claims = json.loads(base64.urlsafe_b64decode(payload.encode()).decode())
    except Exception:
        return None
    return claims.get("email")
