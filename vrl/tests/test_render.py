from __future__ import annotations

import io

from rich.console import Console

from vrl import render
from vrl.models import CveRecord, QueueItem, SubmitResult

from conftest import cve_record, queue_item


def _to_text(renderable) -> str:
    con = Console(width=100, record=True, file=io.StringIO())
    con.print(renderable)
    return con.export_text()


def test_formatters():
    assert render.fmt_duration(42) == "42s"
    assert render.fmt_duration(125) == "2m 05s"
    assert render.fmt_duration(None) == "—"
    assert render.fmt_money(3.8) == "$3.80"
    assert render.fmt_money(None) == "—"
    assert render.fmt_tokens(419772) == "419.8k"
    assert render.fmt_tokens(2_500_000) == "2.5M"
    assert render.fmt_bool(True) == "yes"
    assert render.difficulty_bar(3) == "●●●○○ (3/5)"


def test_issue_panel_renders_terminal():
    item = QueueItem.from_dict(
        queue_item(status="exploit_generated", why="exploit fired, controls held")
    )
    record = CveRecord.from_dict(cve_record())
    text = _to_text(render.issue_panel(item, record))
    assert "CVE-2024-4577" in text
    assert "Exploit generated" in text
    assert "CWE-78" in text


def test_pipeline_timeline_marks_current():
    item = QueueItem.from_dict(queue_item(status="processing"))
    text = _to_text(render.pipeline_timeline(item))
    assert "Processing" in text
    assert "Queued" in text


def test_feed_table():
    items = [QueueItem.from_dict(queue_item(f"CVE-2024-{i}", "pending")) for i in (1, 2)]
    text = _to_text(render.feed_table(items))
    assert "CVE-2024-1" in text
    assert "CVE-2024-2" in text


def test_submit_result_view():
    res = SubmitResult.from_dict(
        {"submitted": [queue_item("CVE-2024-9", "pending")], "count": 1}
    )
    text = _to_text(render.submit_result_view(res, email="a@b.com"))
    assert "Queued CVE-2024-9" in text
    assert "a@b.com" in text


def test_stats_view():
    stats = {"pending": 1200, "processing": 3, "exploit_generated": 800, "total": 2003}
    text = _to_text(render.stats_view(stats))
    assert "Queue depth" in text
    assert "1,200" in text
