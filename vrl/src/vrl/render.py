"""Terminal rendering with Rich.

Pure presentation: every function takes already-fetched models and returns (or
prints) a renderable. Keeping it separate from :mod:`vrl.client` means the same
views back both the one-shot commands and the live ``watch`` loop.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import config
from .models import CveRecord, QueueItem, SubmitResult

console = Console()
err_console = Console(stderr=True)


# ── small formatters ─────────────────────────────────────────────────────────


def fmt_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "—"
    seconds = float(seconds)
    if seconds < 60:
        return f"{seconds:.0f}s"
    m, s = divmod(int(seconds), 60)
    if m < 60:
        return f"{m}m {s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m"


def fmt_money(usd: Optional[float]) -> str:
    return f"${usd:,.2f}" if usd is not None else "—"


def fmt_tokens(tokens: Optional[int]) -> str:
    if tokens is None:
        return "—"
    if tokens >= 1_000_000:
        return f"{tokens / 1_000_000:.1f}M"
    if tokens >= 1_000:
        return f"{tokens / 1_000:.1f}k"
    return str(tokens)


def fmt_bool(value: Optional[bool]) -> str:
    if value is None:
        return "—"
    return "yes" if value else "no"


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def fmt_relative(ts: Optional[str]) -> str:
    dt = _parse_ts(ts)
    if dt is None:
        return "—"
    now = datetime.now(timezone.utc)
    delta = now - dt
    secs = int(delta.total_seconds())
    if secs < 0:
        return "just now"
    if secs < 60:
        return f"{secs}s ago"
    if secs < 3600:
        return f"{secs // 60}m ago"
    if secs < 86400:
        return f"{secs // 3600}h ago"
    return f"{secs // 86400}d ago"


def difficulty_bar(level: Optional[int]) -> str:
    """Render the AI-XI difficulty (1–5) as filled/empty pips."""
    if not level:
        return "—"
    level = max(1, min(int(level), 5))
    return f"{'●' * level}{'○' * (5 - level)} ({level}/5)"


# ── status + pipeline ──────────────────────────────────────────────────────


def status_badge(status: Optional[str]) -> Text:
    meta = config.status_meta(status)
    return Text(f" {meta.label} ", style=f"bold white on {meta.color}")


def status_code(status: Optional[str]) -> Text:
    """A compact, colored status token for dense tables (e.g. EXPL)."""
    meta = config.status_meta(status)
    return Text(meta.code, style=f"bold {meta.color}")


def pipeline_timeline(item: QueueItem) -> Text:
    """A one-line journey: Submitted → Queued → Processing → Done.

    The current stage is highlighted; finished stages are dim/green. The remote
    queue only exposes these coarse states, so this is an honest map of them —
    not a fabricated sub-phase stream.
    """
    status = item.status
    if config.is_terminal(status):
        active = "done"
    elif status == "processing":
        active = "processing"
    else:
        active = "pending"

    order = ["submitted", "pending", "processing", "done"]
    labels = {
        "submitted": "Submitted",
        "pending": "Queued",
        "processing": "Processing",
        "done": "Done",
    }
    done_color = config.status_meta(status).color if active == "done" else "green"

    active_idx = order.index(active)
    parts: list[tuple[str, str]] = []
    for i, stage in enumerate(order):
        if stage == "done" and active == "done":
            label = config.status_meta(status).label
        else:
            label = labels[stage]
        if i < active_idx:
            parts.append((f"✓ {label}", "green"))
        elif i == active_idx:
            style = "bold " + (done_color if stage == "done" else config.status_meta(status).color)
            marker = "✓" if stage == "done" else "▶"
            parts.append((f"{marker} {label}", style))
        else:
            parts.append((f"○ {label}", "grey50"))

    out = Text()
    for i, (txt, style) in enumerate(parts):
        if i:
            out.append("  →  ", style="grey37")
        out.append(txt, style=style)
    return out


# ── the issue presentation ──────────────────────────────────────────────────


def _metrics_table(item: QueueItem, record: Optional[CveRecord]) -> Table:
    t = Table.grid(padding=(0, 2))
    t.add_column(style="bold grey70", justify="right")
    t.add_column()

    def row(label: str, value: Any) -> None:
        t.add_row(label, value if isinstance(value, (Text,)) else str(value))

    outcome = item.outcome or (record.outcome if record else None)
    difficulty = item.difficulty or (record.difficulty_level if record else None)
    cost = item.cost_usd if item.cost_usd is not None else (record.cost_usd if record else None)
    tokens = item.tokens if item.tokens is not None else (record.tokens if record else None)
    secs = item.seconds if item.seconds is not None else (
        record.time_to_generate_sec if record else None
    )

    row("Status", status_badge(item.status))
    if outcome:
        row("Outcome", outcome)
    if record and (record.cwe or record.cwe_label):
        cwe = " ".join(x for x in [record.cwe, record.cwe_label and f"· {record.cwe_label}"] if x)
        row("Weakness", cwe)
    if record and record.ecosystem:
        pkg = record.package or ""
        row("Component", f"{pkg} ({record.ecosystem})".strip())
    if record and record.affected_version:
        row("Affected", record.affected_version)
    if record and record.epss is not None:
        row("EPSS", f"{record.epss * 100:.1f}%")
    if record and record.exploit_in_wild is not None:
        row("In the wild", fmt_bool(record.exploit_in_wild))
    if difficulty:
        row("AI-XI difficulty", difficulty_bar(difficulty))
    row("Cost", fmt_money(cost))
    row("Tokens", fmt_tokens(tokens))
    row("Time to solve", fmt_duration(secs))
    if item.source:
        row("Source", item.source)
    if item.priority is not None:
        row("Priority", item.priority)
    if item.submitted_at:
        row("Submitted", fmt_relative(item.submitted_at))
    if item.updated_at:
        row("Updated", fmt_relative(item.updated_at))
    return t


def issue_panel(item: QueueItem, record: Optional[CveRecord] = None) -> Panel:
    """The headline presentation of one CVE and how its run went."""
    title = item.title or (record.title if record else None)
    header = Text(item.cve_id, style="bold white")
    if title:
        header.append(f"  {title}", style="white")

    blocks: list[RenderableType] = [
        pipeline_timeline(item),
        Text(config.status_meta(item.status).blurb, style="italic grey62"),
        Text(""),
        _metrics_table(item, record),
    ]

    why = item.why
    if why:
        blocks += [Text(""), Text("Verdict", style="bold grey70"), Text(why, style="grey82")]

    remediation = item.remediation
    if remediation:
        blocks += [
            Text(""),
            Text("Remediation", style="bold grey70"),
            Text(str(remediation), style="grey82"),
        ]

    border = config.status_meta(item.status).color
    return Panel(
        Group(*blocks), title=header, title_align="left", border_style=border, padding=(1, 2)
    )


# ── feed + submit + stats ───────────────────────────────────────────────────


def feed_table(items: list[QueueItem], *, title: str = "CVE queue") -> Table:
    t = Table(title=title, title_style="bold", header_style="bold grey70", pad_edge=False)
    t.add_column("CVE", style="bold", no_wrap=True, min_width=14)
    t.add_column("Status", no_wrap=True, min_width=5)
    t.add_column("Title", overflow="ellipsis", no_wrap=True, max_width=34)
    t.add_column("Src", justify="center", no_wrap=True)
    t.add_column("Cost", justify="right", no_wrap=True)
    t.add_column("Time", justify="right", no_wrap=True)
    t.add_column("Updated", justify="right", no_wrap=True)
    for it in items:
        t.add_row(
            it.cve_id,
            status_code(it.status),
            it.title or "—",
            it.source or "—",
            fmt_money(it.cost_usd),
            fmt_duration(it.seconds),
            fmt_relative(it.updated_at or it.submitted_at),
        )
    return t


def submit_result_view(result: SubmitResult, *, email: Optional[str] = None) -> RenderableType:
    blocks: list[RenderableType] = []
    for it in result.submitted:
        blocks.append(Text(f"✓ Queued {it.cve_id}", style="bold green"))
    for it in result.duplicates:
        blocks.append(Text(f"• {it.cve_id} is already tracked", style="yellow"))
    for rej in result.rejected:
        blocks.append(Text(f"✗ {rej.cve_id} rejected — {rej.reason}", style="red"))
    if not blocks:
        blocks.append(Text("Nothing was queued.", style="grey62"))
    if email and (result.submitted or result.duplicates):
        blocks.append(Text(""))
        blocks.append(
            Text(
                f"You'll be emailed at {email} when processing starts and finishes.",
                style="grey62",
            )
        )
    return Panel(
        Group(*blocks), title="Submission", title_align="left", border_style="green", padding=(1, 2)
    )


def stats_view(stats: dict[str, Any], telemetry: Optional[dict[str, Any]] = None) -> RenderableType:
    t = Table(title="Queue depth", header_style="bold grey70")
    t.add_column("Status", style="bold")
    t.add_column("Count", justify="right")
    total = stats.get("total")
    for key in config.STATUS_ORDER:
        if key in stats:
            t.add_row(config.status_meta(key).label, f"{stats[key]:,}")
    if total is not None:
        t.add_row(Text("Total", style="bold"), Text(f"{total:,}", style="bold"))

    blocks: list[RenderableType] = [t]
    if telemetry:
        tiles = (telemetry.get("tiles") or {})
        window = tiles.get("all") or next(iter(tiles.values()), None)
        if window:
            econ = Table.grid(padding=(0, 2))
            econ.add_column(style="bold grey70", justify="right")
            econ.add_column()
            econ.add_row("CVEs processed", f"{window.get('cvesProcessed', 0):,}")
            econ.add_row("Verified exploits", f"{window.get('verifiedExploits', 0):,}")
            rate = window.get("verifiedRate")
            if rate is not None:
                econ.add_row("Verified rate", f"{rate * 100:.1f}%")
            econ.add_row("Total spend", fmt_money(window.get("totalSpendUsd")))
            econ.add_row("Median run cost", fmt_money(window.get("medianRunUsd")))
            blocks.append(
                Panel(econ, title="Program economics", title_align="left", border_style="cyan")
            )
    return Group(*blocks)
