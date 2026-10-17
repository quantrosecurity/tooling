"""HTTP client for the VRL CVE Queue API.

A thin wrapper over ``httpx`` that speaks the documented contract and turns
non-2xx responses into the typed exceptions in :mod:`vrl.errors`. Public reads
and the public submit carry no ``Authorization``; the ``/internal`` writers send
a bearer token.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from . import config
from .errors import ApiError, AuthError, NotFound, RateLimited, TurnstileRequired
from .models import CveRecord, QueueItem, ReplayTrace, SubmitResult

_USER_AGENT = "vrl-cli"


def _detail(resp: httpx.Response) -> str:
    """Extract FastAPI's ``detail`` (string or list of ``{msg}``) as one line."""
    try:
        body = resp.json()
    except Exception:
        return (resp.text or resp.reason_phrase or "").strip()[:300]
    detail = body.get("detail") if isinstance(body, dict) else None
    if detail is None:
        return str(body)[:300]
    if isinstance(detail, str):
        # Strip pydantic's "Value error, " noise, like the website does.
        return detail.replace("Value error, ", "").strip()
    if isinstance(detail, list):
        msgs = [str(x.get("msg", x)) for x in detail if isinstance(x, (dict, str))]
        return "; ".join(m.replace("Value error, ", "") for m in msgs) or str(detail)
    return str(detail)[:300]


class VrlClient:
    """Client for one VRL API base URL.

    Usable as a context manager so the underlying connection pool is closed::

        with VrlClient() as c:
            item = c.get_item("CVE-2024-1234")
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        *,
        token: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = config.base_url(base_url)
        self.token = token
        self._http = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
            follow_redirects=True,
        )

    def __enter__(self) -> VrlClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    # ── low-level ────────────────────────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict[str, Any]] = None,
        json_body: Optional[dict[str, Any]] = None,
        auth: bool = False,
    ) -> httpx.Response:
        headers: dict[str, str] = {}
        if auth:
            if not self.token:
                raise AuthError(
                    "This call needs internal credentials but no token is set.",
                    hint="Pass --token, set VRL_TOKEN, or let the CLI mint an OIDC token.",
                )
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            resp = self._http.request(
                method, path, params=params, json=json_body, headers=headers or None
            )
        except httpx.HTTPError as exc:
            raise ApiError(0, f"request to {self.base_url} failed: {exc}") from exc

        if resp.status_code < 400:
            return resp
        self._raise_for_status(resp)
        raise AssertionError("unreachable")  # _raise_for_status always raises

    @staticmethod
    def _raise_for_status(resp: httpx.Response) -> None:
        detail = _detail(resp)
        code = resp.status_code
        if code == 404:
            raise NotFound(detail or "Not found.")
        if code == 429:
            raise RateLimited("Rate limited by the API.", hint="Wait a bit and try again.")
        if code in (401, 403):
            raise AuthError(
                detail or "Not authorized.",
                hint="Your token may be missing, expired, or not on the allow-list.",
            )
        if code == 400 and "turnstile" in detail.lower():
            raise TurnstileRequired(
                detail,
                hint=(
                    "Public submit needs a browser-solved Cloudflare Turnstile token. "
                    "Pass --turnstile-token, or submit via the website / the --internal path."
                ),
            )
        raise ApiError(code, detail or resp.reason_phrase)

    # ── public reads ──────────────────────────────────────────────────────────
    # Every read takes ``internal=False``: the API's read plane projects records
    # (paid-feed data, cost/tokens, verdicts hidden — see its public_view), and a
    # caller presenting a valid internal credential gets the full record instead.
    # Reads send ``Authorization`` only when ``internal=True``; a public read
    # never touches credentials.

    def get_item(self, cve: str, *, internal: bool = False) -> QueueItem:
        """``GET /queue/{cve}`` — the one row for a CVE (404 → :class:`NotFound`)."""
        resp = self._request("GET", f"/queue/{cve.upper()}", auth=internal)
        return QueueItem.from_dict(resp.json())

    def list_feed(
        self,
        *,
        status: Optional[str] = None,
        source: Optional[str] = None,
        order: str = "desc",
        limit: int = 25,
        cursor: Optional[str] = None,
        internal: bool = False,
    ) -> tuple[list[QueueItem], Optional[str]]:
        """``GET /queue`` — one page of the live feed; returns (items, nextCursor)."""
        params: dict[str, Any] = {"limit": max(1, min(limit, 100)), "order": order}
        if status:
            params["status"] = status
        if source:
            params["source"] = source
        if cursor:
            params["cursor"] = cursor
        body = self._request("GET", "/queue", params=params, auth=internal).json()
        items = [QueueItem.from_dict(x) for x in body.get("items", [])]
        return items, body.get("nextCursor")

    def list_completed(self, *, limit: int = 8) -> list[QueueItem]:
        """``GET /queue/completed`` — most recently finished items."""
        params = {"limit": max(1, min(limit, 50))}
        body = self._request("GET", "/queue/completed", params=params).json()
        return [QueueItem.from_dict(x) for x in body.get("items", [])]

    def queue_stats(self) -> dict[str, Any]:
        """``GET /queue/stats`` — true per-status depths."""
        return self._request("GET", "/queue/stats").json()

    def find_record(self, cve: str, *, internal: bool = False) -> Optional[CveRecord]:
        """``GET /cves?q={cve}`` — the processed-ledger record, if present."""
        params = {"q": cve.upper(), "limit": 5}
        body = self._request("GET", "/cves", params=params, auth=internal).json()
        want = cve.upper()
        for item in body.get("items", []):
            rec = CveRecord.from_dict(item)
            if rec.cve == want:
                return rec
        return None

    def get_replay(self, cve: str, *, internal: bool = False) -> ReplayTrace:
        """``GET /replay/{cve}`` — the step/retry story of a processed CVE.

        The public projection carries attempts + judge rejections + the final
        outcome; ``internal=True`` adds reasoning, tool calls, and the full
        verdict (the operator's demo view)."""
        resp = self._request("GET", f"/replay/{cve.upper()}", auth=internal)
        return ReplayTrace.from_dict(resp.json())

    def list_replays(self) -> list[dict[str, Any]]:
        """``GET /replay`` — which CVEs have traces (public-safe index rows).

        The index is the same for every caller: cve, package, finalStatus,
        attempt count. Replay coverage is exactly the corpus-harness runs —
        a queue row without a trace here has no step/retry story."""
        body = self._request("GET", "/replay").json()
        return list(body.get("items", []))

    def harness_telemetry(self) -> dict[str, Any]:
        """``GET /harness/telemetry`` — program economics snapshot."""
        return self._request("GET", "/harness/telemetry").json()

    # ── submit ──────────────────────────────────────────────────────────────

    def submit_public(
        self,
        cve_id: str,
        *,
        email: Optional[str] = None,
        name: Optional[str] = None,
        submitted_by: Optional[str] = None,
        turnstile_token: Optional[str] = None,
    ) -> SubmitResult:
        """``POST /queue`` — the public form path (email + Turnstile)."""
        body = {
            "cveId": cve_id,
            "submitterEmail": email,
            "submitterName": name,
            "submittedBy": submitted_by,
            "turnstileToken": turnstile_token,
        }
        resp = self._request("POST", "/queue", json_body=body)
        return SubmitResult.from_dict(resp.json())

    def submit_internal(
        self,
        cve_id: str,
        *,
        status: str = "pending",
        source: str = "community",
        submitted_by: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> QueueItem:
        """``POST /internal/queue`` — the privileged path (bearer token, no Turnstile)."""
        body = {
            "cveId": cve_id.upper(),
            "status": status,
            "source": source,
            "submittedBy": submitted_by,
            "details": details or {},
        }
        resp = self._request("POST", "/internal/queue", json_body=body, auth=True)
        return QueueItem.from_dict(resp.json())
