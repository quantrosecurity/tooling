from __future__ import annotations

from vrl.models import CveRecord, QueueItem, SubmitResult

from conftest import cve_record, queue_item


def test_queue_item_basic():
    it = QueueItem.from_dict(queue_item(status="pending"))
    assert it.cve_id == "CVE-2024-4577"
    assert it.status == "pending"
    assert it.title == "PHP CGI argument injection"
    assert it.position == 3
    assert it.priority == 820


def test_queue_item_tolerant_detail_keys():
    # Different spellings the harness has used over time.
    it = QueueItem.from_dict(
        queue_item(
            status="exploit_generated",
            costUsd=3.82,
            aiTokens=419772,
            genSeconds=600,
            difficultyLevel=4,
            outcome="verified",
            why="exploit fired, controls held",
        )
    )
    assert it.cost_usd == 3.82
    assert it.tokens == 419772
    assert it.seconds == 600
    assert it.difficulty == 4
    assert it.outcome == "verified"
    assert it.why == "exploit fired, controls held"


def test_queue_item_minutes_to_seconds():
    it = QueueItem.from_dict(queue_item(timeMin=5))
    assert it.seconds == 300


def test_queue_item_cve_uppercased_from_aliases():
    it = QueueItem.from_dict({"cve": "cve-2024-1", "status": "failed"})
    assert it.cve_id == "CVE-2024-1"


def test_submit_result():
    res = SubmitResult.from_dict(
        {
            "submitted": [queue_item("CVE-2024-1", "pending")],
            "duplicates": [queue_item("CVE-2024-2", "processing")],
            "rejected": [{"cveId": "CVE-1000-1", "reason": "year 1000 predates the CVE program"}],
            "count": 2,
        }
    )
    assert [i.cve_id for i in res.submitted] == ["CVE-2024-1"]
    assert [i.cve_id for i in res.duplicates] == ["CVE-2024-2"]
    assert res.rejected[0].reason.startswith("year 1000")
    assert res.count == 2


def test_cve_record():
    rec = CveRecord.from_dict(cve_record())
    assert rec.cve == "CVE-2024-4577"
    assert rec.cwe == "CWE-78"
    assert rec.cwe_label == "OS Command Injection"
    assert rec.difficulty_level == 3
    assert rec.exploit_in_wild is True
    assert rec.epss == 0.944
