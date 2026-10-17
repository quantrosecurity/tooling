from __future__ import annotations

import httpx
import respx
from typer.testing import CliRunner

from vrl.cli import app
from vrl.errors import InvalidCve, InvalidEmail, VrlError

from conftest import BASE, cve_record, queue_item

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "vrl" in result.output


def test_submit_bad_cve_offline():
    result = runner.invoke(app, ["submit", "notacve", "--email", "a@b.com"])
    assert result.exit_code != 0
    assert isinstance(result.exception, InvalidCve)


def test_submit_bad_email_offline():
    result = runner.invoke(app, ["submit", "CVE-2024-4577", "--email", "nope"])
    assert result.exit_code != 0
    assert isinstance(result.exception, InvalidEmail)


def test_submit_missing_email_offline():
    result = runner.invoke(app, ["submit", "CVE-2024-4577"])
    assert result.exit_code != 0
    assert isinstance(result.exception, VrlError)


@respx.mock
def test_show_happy_path():
    respx.get(f"{BASE}/queue/CVE-2024-4577").mock(
        return_value=httpx.Response(200, json=queue_item(status="exploit_generated"))
    )
    respx.get(f"{BASE}/cves").mock(
        return_value=httpx.Response(200, json={"items": [cve_record()], "total": 1})
    )
    result = runner.invoke(app, ["--base-url", BASE, "show", "CVE-2024-4577"])
    assert result.exit_code == 0, result.output
    assert "CVE-2024-4577" in result.output


@respx.mock
def test_show_json_output():
    respx.get(f"{BASE}/queue/CVE-2024-4577").mock(
        return_value=httpx.Response(200, json=queue_item(status="pending"))
    )
    result = runner.invoke(app, ["--base-url", BASE, "--json", "show", "CVE-2024-4577"])
    assert result.exit_code == 0, result.output
    assert '"cveId"' in result.output


@respx.mock
def test_list_happy_path():
    respx.get(f"{BASE}/queue").mock(
        return_value=httpx.Response(
            200, json={"items": [queue_item("CVE-2024-1", "pending")], "nextCursor": None}
        )
    )
    result = runner.invoke(app, ["--base-url", BASE, "list", "--status", "pending"])
    assert result.exit_code == 0, result.output
    assert "CVE-2024-1" in result.output


@respx.mock
def test_submit_internal_with_token():
    respx.post(f"{BASE}/internal/queue").mock(
        return_value=httpx.Response(201, json=queue_item("CVE-2024-4577", "pending"))
    )
    result = runner.invoke(
        app, ["--base-url", BASE, "--token", "sekret", "submit", "CVE-2024-4577", "--internal"]
    )
    assert result.exit_code == 0, result.output
    assert "Queued" in result.output


# ── replay + view tiers (PR D) ───────────────────────────────────────────────


from conftest import journal_attempts, replay_trace  # noqa: E402


@respx.mock
def test_replay_public_projection():
    respx.get(f"{BASE}/replay/CVE-2024-4577").mock(
        return_value=httpx.Response(200, json=replay_trace())
    )
    result = runner.invoke(app, ["--base-url", BASE, "replay", "CVE-2024-4577"])
    assert result.exit_code == 0, result.output
    assert "attempt 1" in result.output
    assert "judge rejected" in result.output
    assert "public view" in result.output
    assert "reasoning" not in result.output  # methodology never on the public plane


@respx.mock
def test_replay_internal_sends_token_and_renders_reasoning():
    route = respx.get(f"{BASE}/replay/CVE-2024-4577").mock(
        return_value=httpx.Response(
            200,
            json=replay_trace(attempts=journal_attempts(), verdict={"run_id": "abc123"}),
        )
    )
    result = runner.invoke(
        app,
        ["--base-url", BASE, "--token", "test-token", "replay", "CVE-2024-4577", "--internal"],
    )
    assert result.exit_code == 0, result.output
    assert route.calls.last.request.headers["authorization"] == "Bearer test-token"
    assert "reasoning (2 entries)" in result.output
    assert "tool calls: 1" in result.output


@respx.mock
def test_replay_404_is_a_clean_error():
    respx.get(f"{BASE}/replay/CVE-2024-4577").mock(
        return_value=httpx.Response(404, json={"detail": "Not found"})
    )
    result = runner.invoke(app, ["--base-url", BASE, "replay", "CVE-2024-4577"])
    assert result.exit_code != 0


@respx.mock
def test_show_internal_sends_token():
    route = respx.get(f"{BASE}/queue/CVE-2024-4577").mock(
        return_value=httpx.Response(200, json=queue_item(status="pending"))
    )
    result = runner.invoke(
        app, ["--base-url", BASE, "--token", "test-token", "show", "CVE-2024-4577", "--internal"]
    )
    assert result.exit_code == 0, result.output
    assert route.calls.last.request.headers["authorization"] == "Bearer test-token"


@respx.mock
def test_show_public_names_the_view_and_sends_no_token():
    route = respx.get(f"{BASE}/queue/CVE-2024-4577").mock(
        return_value=httpx.Response(200, json=queue_item(status="pending"))
    )
    result = runner.invoke(app, ["--base-url", BASE, "show", "CVE-2024-4577"])
    assert result.exit_code == 0, result.output
    assert "public view" in result.output
    assert "authorization" not in route.calls.last.request.headers


@respx.mock
def test_list_internal_sends_token():
    route = respx.get(f"{BASE}/queue").mock(
        return_value=httpx.Response(200, json={"items": [queue_item()], "nextCursor": None})
    )
    result = runner.invoke(app, ["--base-url", BASE, "--token", "test-token", "list", "--internal"])
    assert result.exit_code == 0, result.output
    assert route.calls.last.request.headers["authorization"] == "Bearer test-token"


def test_submit_browser_opens_the_form(monkeypatch):
    import vrl.cli as cli

    opened = {}
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: opened.setdefault("url", url) or True)
    monkeypatch.setattr(cli, "_copy_to_clipboard", lambda text: True)
    result = runner.invoke(app, ["submit", "CVE-2024-4577", "--browser"])
    assert result.exit_code == 0, result.output
    assert opened["url"] == "https://vulnerabilityresearchlabs.ai/ai-xi/"
    assert "vrl watch CVE-2024-4577" in result.output
    assert "Turnstile" in result.output


@respx.mock
def test_replay_list_renders_coverage():
    respx.get(f"{BASE}/replay").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "cve": "CVE-2026-104457",
                        "finalStatus": "exploit_generated",
                        "attempts": 17,
                        "package": "yeswiki",
                    },
                    {
                        "cve": "CVE-2026-87115",
                        "finalStatus": "exploit_generated",
                        "attempts": 10,
                        "package": None,
                    },
                ],
                "total": 2,
            },
        )
    )
    result = runner.invoke(app, ["--base-url", BASE, "replay", "--list"])
    assert result.exit_code == 0, result.output
    assert "CVE-2026-104457" in result.output
    assert "17" in result.output
    assert "Replay coverage" in result.output


def test_replay_requires_a_cve_offline():
    result = runner.invoke(app, ["replay"])
    assert result.exit_code != 0
    assert isinstance(result.exception, VrlError)


@respx.mock
def test_replay_404_names_the_traces_on_file():
    respx.get(f"{BASE}/replay/CVE-2024-27198").mock(
        return_value=httpx.Response(404, json={"detail": "No replay trace for this CVE..."})
    )
    respx.get(f"{BASE}/replay").mock(
        return_value=httpx.Response(
            200, json={"items": [{"cve": "CVE-2026-104457", "attempts": 17}], "total": 1}
        )
    )
    result = runner.invoke(app, ["--base-url", BASE, "replay", "CVE-2024-27198"])
    assert result.exit_code != 0
    assert isinstance(result.exception, VrlError)
    assert "No replay trace for CVE-2024-27198" in result.exception.message
    assert "CVE-2026-104457" in result.exception.message  # coverage named, not guessed


@respx.mock
def test_internal_read_mints_with_the_default_sa(monkeypatch):
    import vrl.auth as auth_mod
    from vrl import config

    minted = {}

    def fake_mint(*, audience: str, impersonate_sa):
        minted["aud"] = audience
        minted["sa"] = impersonate_sa
        return "minted-token"

    monkeypatch.setattr(auth_mod, "mint_oidc_token", fake_mint)
    monkeypatch.delenv("VRL_TOKEN", raising=False)
    monkeypatch.delenv("VRL_INTERNAL_SA", raising=False)
    route = respx.get(f"{BASE}/queue/CVE-2024-4577").mock(
        return_value=httpx.Response(200, json=queue_item(status="pending"))
    )
    result = runner.invoke(app, ["--base-url", BASE, "show", "CVE-2024-4577", "--internal"])
    assert result.exit_code == 0, result.output
    assert minted["sa"] == config.DEFAULT_INTERNAL_SA  # no env var needed
    assert minted["aud"] == BASE
    assert route.calls.last.request.headers["authorization"] == "Bearer minted-token"
