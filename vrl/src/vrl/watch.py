"""The live ``watch`` loop: poll one CVE until it reaches a terminal state.

The VRL queue is a coarse status store (``pending → processing → terminal``),
not a turn-by-turn event stream, so ``watch`` renders an honest live view of
those states — a pipeline timeline, elapsed time, queue position, and the
details filling in — refreshed every few seconds until the run finishes.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional

from rich.console import Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from . import config, render
from .client import VrlClient
from .errors import NotFound
from .models import CveRecord, QueueItem


def _fmt_elapsed(start: float) -> str:
    return render.fmt_duration(time.monotonic() - start)


def _header(cve: str, start: float, polls: int, status: Optional[str]) -> RenderableType:
    line = Text()
    line.append(f"watching {cve}", style="bold")
    line.append(f"   elapsed {_fmt_elapsed(start)}", style="grey62")
    line.append(f"   polls {polls}", style="grey62")
    if config.is_terminal(status):
        line.append("   done", style="bold green")
        return line
    grid = Table.grid(padding=(0, 1))
    grid.add_row(Spinner("dots", style="cyan"), line)
    return grid


def _tick_log(ticks: list[str], limit: int = 8) -> RenderableType:
    rows = ticks[-limit:]
    return Panel(
        Text("\n".join(rows) or "…", style="grey58"),
        title="poll log",
        title_align="left",
        border_style="grey37",
        padding=(0, 1),
    )


def _view(
    item: QueueItem,
    record: Optional[CveRecord],
    start: float,
    polls: int,
    ticks: list[str],
    verbose: bool,
) -> RenderableType:
    blocks: list[RenderableType] = [
        _header(item.cve_id, start, polls, item.status),
        render.issue_panel(item, record),
    ]
    if verbose:
        blocks.append(_tick_log(ticks))
    return Group(*blocks)


def watch_cve(
    client: VrlClient,
    cve: str,
    *,
    interval: float = config.DEFAULT_POLL_SECONDS,
    timeout: Optional[float] = None,
    verbose: bool = False,
    console=None,
) -> QueueItem:
    """Poll ``cve`` until terminal (or ``timeout`` seconds elapse); return the row.

    Raises :class:`vrl.errors.NotFound` if the CVE is not in the queue at all on
    the first poll (it may legitimately 404 briefly right after a submit, which
    is tolerated).
    """
    console = console or render.console
    interval = max(interval, config.MIN_POLL_SECONDS)
    start = time.monotonic()
    polls = 0
    ticks: list[str] = []
    last: Optional[QueueItem] = None
    record: Optional[CveRecord] = None
    saw_item = False

    with Live(console=console, refresh_per_second=8, transient=False) as live:
        while True:
            polls += 1
            now = datetime.now(timezone.utc).strftime("%H:%M:%S")
            try:
                item = client.get_item(cve)
                saw_item = True
                last = item
                tick = f"{now}  {item.status}"
                if item.position is not None and item.status == "pending":
                    tick += f"  (position {item.position})"
                ticks.append(tick)
            except NotFound:
                ticks.append(f"{now}  not in queue yet")
                if saw_item:
                    # It was there and now isn't — treat the last state as final.
                    break
                # Give a just-submitted CVE a few polls to appear.
                if time.monotonic() - start > max(interval * 3, 20):
                    raise
                live.update(
                    Group(
                        Text(f"waiting for {cve} to appear in the queue…", style="yellow"),
                        _tick_log(ticks) if verbose else Text(""),
                    )
                )
                time.sleep(interval)
                continue

            # Enrich with the processed-ledger record once it is terminal, so the
            # final panel is as rich as the data allows.
            if config.is_terminal(item.status) and record is None:
                try:
                    record = client.find_record(cve)
                except Exception:
                    record = None

            live.update(_view(item, record, start, polls, ticks, verbose))

            if config.is_terminal(item.status):
                break
            if timeout is not None and time.monotonic() - start > timeout:
                ticks.append(f"{now}  (timeout reached, stopping)")
                break
            time.sleep(interval)

    if last is None:
        raise NotFound(f"{cve} is not in the queue.")
    return last
