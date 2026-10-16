"""Lightweight dataclasses for the API's JSON shapes.

Only the fields the CLI actually renders are modelled; the original payload is
kept on ``.raw`` so nothing is lost and ``--json`` can echo it verbatim. The
free-form ``details`` map is read through tolerant accessors because the harness
has used a few different key spellings over time (the website does the same).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


def _first(d: dict[str, Any], *keys: str) -> Optional[Any]:
    """Return the first present, non-None value among ``keys``."""
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return None


@dataclass
class QueueItem:
    """A row in the CVE queue — the shape of ``GET /queue/{id}``."""

    cve_id: str
    status: str
    source: Optional[str] = None
    submitted_by: Optional[str] = None
    position: Optional[int] = None
    priority: Optional[int] = None
    submitted_at: Optional[str] = None
    updated_at: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> QueueItem:
        return cls(
            cve_id=(_first(d, "cveId", "cve", "cve_id", "id") or "").upper(),
            status=_first(d, "status") or "unknown",
            source=_first(d, "source"),
            submitted_by=_first(d, "submittedBy", "submitted_by"),
            position=_first(d, "position"),
            priority=_first(d, "priority"),
            submitted_at=_first(d, "submittedAt", "submitted_at"),
            updated_at=_first(d, "updatedAt", "updated_at"),
            details=_first(d, "details") or {},
            raw=d,
        )

    # ── Tolerant readers over the free-form details map ──
    # (Key spellings mirror the website's QueueBoard metric extraction.)

    @property
    def title(self) -> Optional[str]:
        return _first(self.details, "title", "Title", "package", "target")

    @property
    def cost_usd(self) -> Optional[float]:
        v = _first(self.details, "cost", "costUsd", "cost_usd", "aiExploitCostUsd")
        return float(v) if v is not None else None

    @property
    def tokens(self) -> Optional[int]:
        v = _first(self.details, "tokens", "aiTokens", "total_tokens")
        return int(v) if v is not None else None

    @property
    def seconds(self) -> Optional[float]:
        """Wall time, normalized to seconds from whichever unit was stored."""
        secs = _first(self.details, "secs", "genSeconds", "wall_s", "timeToGenerateSec")
        if secs is not None:
            return float(secs)
        mins = _first(self.details, "timeMin", "minutes")
        return float(mins) * 60 if mins is not None else None

    @property
    def difficulty(self) -> Optional[int]:
        v = _first(self.details, "aixi", "difficultyLevel", "difficulty", "difficulty_level")
        return int(v) if v is not None else None

    @property
    def outcome(self) -> Optional[str]:
        return _first(self.details, "outcome", "verdict")

    @property
    def why(self) -> Optional[str]:
        return _first(self.details, "why", "reason", "summary")

    @property
    def remediation(self) -> Optional[str]:
        return _first(self.details, "remediation", "fix", "REMEDIATION")


@dataclass
class RejectedCve:
    cve_id: str
    reason: str

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RejectedCve:
        return cls(cve_id=_first(d, "cveId", "cve") or "?", reason=_first(d, "reason") or "")


@dataclass
class SubmitResult:
    """Outcome of ``POST /queue`` — a (possibly multi-CVE) public submission."""

    submitted: list[QueueItem] = field(default_factory=list)
    duplicates: list[QueueItem] = field(default_factory=list)
    rejected: list[RejectedCve] = field(default_factory=list)
    count: int = 0
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SubmitResult:
        return cls(
            submitted=[QueueItem.from_dict(x) for x in (d.get("submitted") or [])],
            duplicates=[QueueItem.from_dict(x) for x in (d.get("duplicates") or [])],
            rejected=[RejectedCve.from_dict(x) for x in (d.get("rejected") or [])],
            count=int(d.get("count") or 0),
            raw=d,
        )


@dataclass
class CveRecord:
    """A processed-ledger row — the shape of ``GET /cves`` items.

    This is the rich record used for the final "here's the issue" presentation.
    """

    cve: str
    title: Optional[str] = None
    ecosystem: Optional[str] = None
    package: Optional[str] = None
    affected_version: Optional[str] = None
    ai_exploit: Optional[bool] = None
    cost_usd: Optional[float] = None
    time_to_generate_sec: Optional[float] = None
    tokens: Optional[int] = None
    difficulty_level: Optional[int] = None
    epss: Optional[float] = None
    exploit_in_wild: Optional[bool] = None
    cwe: Optional[str] = None
    cwe_label: Optional[str] = None
    outcome: Optional[str] = None
    processed_at: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CveRecord:
        return cls(
            cve=(d.get("cve") or "").upper(),
            title=d.get("title"),
            ecosystem=d.get("ecosystem"),
            package=d.get("package"),
            affected_version=d.get("affectedVersion"),
            ai_exploit=d.get("aiExploit"),
            cost_usd=d.get("costUsd"),
            time_to_generate_sec=d.get("timeToGenerateSec"),
            tokens=d.get("tokens"),
            difficulty_level=d.get("difficultyLevel"),
            epss=d.get("epss"),
            exploit_in_wild=d.get("exploitInWild"),
            cwe=d.get("cwe"),
            cwe_label=d.get("cweLabel"),
            outcome=d.get("outcome"),
            processed_at=d.get("processedAt"),
            raw=d,
        )


@dataclass
class ReplayAttempt:
    """One attempt of a replay trace — tolerant over the public/internal key
    spellings (the public projection uses ``triggerError``/``toolCalls``-style
    keys, the raw journal ``trigger_error``/``tool_calls``)."""

    n: Optional[int] = None
    ts: Optional[str] = None
    rejected: Optional[bool] = None
    trigger_error: Optional[str] = None
    reasoning: list[str] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ReplayAttempt:
        trigger_error = _first(d, "triggerError", "trigger_error")
        # The public projection states `rejected` explicitly; a raw journal
        # entry implies it — an attempt with a judge rejection was rejected.
        rejected = _first(d, "rejected")
        if rejected is None:
            rejected = bool(trigger_error)
        return cls(
            n=_first(d, "attempt"),
            ts=_first(d, "ts"),
            rejected=rejected,
            trigger_error=trigger_error,
            reasoning=list(_first(d, "reasoning") or []),
            tool_calls=list(_first(d, "toolCalls", "tool_calls") or []),
            raw=d,
        )

    @property
    def accepted(self) -> bool:
        """An attempt without a rejection made progress (the judge said yes)."""
        return not self.rejected


@dataclass
class ReplayTrace:
    """The step/retry story of a processed CVE — ``GET /replay/{cve}``.

    The public projection carries the story only (attempts + judge rejections +
    final outcome); the internal view adds reasoning, tool calls, and the full
    verdict document on ``.verdict``.
    """

    cve: str
    package: Optional[str] = None
    ecosystem: Optional[str] = None
    vuln_version: Optional[str] = None
    fixed_versions: list[str] = field(default_factory=list)
    harness_version: Optional[str] = None
    final_status: Optional[str] = None
    attempts: list[ReplayAttempt] = field(default_factory=list)
    verdict: Optional[dict[str, Any]] = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ReplayTrace:
        return cls(
            cve=(d.get("cve") or "").upper(),
            package=_first(d, "package"),
            ecosystem=_first(d, "ecosystem"),
            vuln_version=_first(d, "vulnVersion", "vuln_version"),
            fixed_versions=list(_first(d, "fixedVersions", "fixed_versions") or []),
            harness_version=_first(d, "harnessVersion", "harness_version"),
            final_status=_first(d, "finalStatus", "final_status"),
            attempts=[ReplayAttempt.from_dict(a) for a in (d.get("attempts") or [])],
            verdict=_first(d, "verdict"),
            raw=d,
        )
