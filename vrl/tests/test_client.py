from __future__ import annotations

import httpx
import pytest
import respx

from vrl.client import VrlClient
from vrl.errors import ApiError, AuthError, NotFound, RateLimited, TurnstileRequired

from conftest import BASE, cve_record, queue_item


@respx.mock
def test_get_item():
    respx.get(f"{BASE}/queue/CVE-2024-4577").mock(
        return_value=httpx.Response(200, json=queue_item())
    )
    with VrlClient(BASE) as c:
        it = c.get_item("cve-2024-4577")  # lower-cased input is upper-cased in the path
    assert it.cve_id == "CVE-2024-4577"
    assert it.status == "processing"


@respx.mock
def test_get_item_not_found():
    respx.get(f"{BASE}/queue/CVE-2000-1").mock(
        return_value=httpx.Response(404, json={"detail": "Not found"})
    )
    with VrlClient(BASE) as c, pytest.raises(NotFound):
        c.get_item("CVE-2000-1")


@respx.mock
def test_list_feed_clamps_limit_and_parses():
    route = respx.get(f"{BASE}/queue").mock(
        return_value=httpx.Response(200, json={"items": [queue_item()], "nextCursor": "abc"})
    )
    with VrlClient(BASE) as c:
        items, cursor = c.list_feed(limit=9999, status="processing")
    assert cursor == "abc"
    assert items[0].cve_id == "CVE-2024-4577"
    req = route.calls.last.request
    assert req.url.params["limit"] == "100"  # clamped to the API max
    assert req.url.params["status"] == "processing"


@respx.mock
def test_find_record_matches_cve():
    respx.get(f"{BASE}/cves").mock(
        return_value=httpx.Response(200, json={"items": [cve_record()], "total": 1})
    )
    with VrlClient(BASE) as c:
        rec = c.find_record("CVE-2024-4577")
    assert rec is not None
    assert rec.cwe == "CWE-78"


@respx.mock
def test_submit_public_body_shape():
    route = respx.post(f"{BASE}/queue").mock(
        return_value=httpx.Response(
            201, json={"submitted": [queue_item("CVE-2024-4577", "pending")], "count": 1}
        )
    )
    with VrlClient(BASE) as c:
        res = c.submit_public(
            "CVE-2024-4577", email="a@b.com", name="Ada", turnstile_token="tok"
        )
    assert res.count == 1
    body = respx.calls.last.request.read().decode()
    assert '"submitterEmail":"a@b.com"' in body.replace(" ", "")
    assert '"turnstileToken":"tok"' in body.replace(" ", "")
    # Public submit carries no Authorization header.
    assert "authorization" not in {k.lower() for k in route.calls.last.request.headers}


@respx.mock
def test_submit_public_turnstile_rejected():
    respx.post(f"{BASE}/queue").mock(
        return_value=httpx.Response(400, json={"detail": "Turnstile challenge failed"})
    )
    with VrlClient(BASE) as c, pytest.raises(TurnstileRequired):
        c.submit_public("CVE-2024-4577", email="a@b.com", turnstile_token="bad")


@respx.mock
def test_submit_internal_sends_bearer():
    route = respx.post(f"{BASE}/internal/queue").mock(
        return_value=httpx.Response(201, json=queue_item("CVE-2024-4577", "pending"))
    )
    with VrlClient(BASE, token="sekret") as c:
        it = c.submit_internal("cve-2024-4577", source="quantro")
    assert it.cve_id == "CVE-2024-4577"
    req = route.calls.last.request
    assert req.headers["authorization"] == "Bearer sekret"
    body = req.read().decode().replace(" ", "")
    assert '"cveId":"CVE-2024-4577"' in body  # upper-cased
    assert '"source":"quantro"' in body


def test_submit_internal_without_token_raises():
    with VrlClient(BASE) as c, pytest.raises(AuthError):
        c.submit_internal("CVE-2024-4577")


@respx.mock
def test_rate_limited():
    respx.get(f"{BASE}/queue/CVE-2024-4577").mock(return_value=httpx.Response(429))
    with VrlClient(BASE) as c, pytest.raises(RateLimited):
        c.get_item("CVE-2024-4577")


@respx.mock
def test_unexpected_error():
    respx.get(f"{BASE}/queue/stats").mock(
        return_value=httpx.Response(500, json={"detail": "boom"})
    )
    with VrlClient(BASE) as c:
        with pytest.raises(ApiError) as ei:
            c.queue_stats()
    assert ei.value.status_code == 500
