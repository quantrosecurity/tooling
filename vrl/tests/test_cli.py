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
