"""The ``vrl`` command-line interface.

Commands:

* ``vrl submit <CVE>``  — queue a CVE (public email path, ``--internal``, or
  ``--browser`` to finish in the website's Turnstile-protected form)
* ``vrl watch  <CVE>``  — live-poll a CVE until it finishes (alias: ``track``)
* ``vrl show   <CVE>``  — the full write-up of one CVE (alias: ``status``)
* ``vrl replay <CVE>``  — what happened when it was processed: every attempt,
  what the judge rejected each one for, how it ended
* ``vrl list``          — browse the live queue (alias: ``feed``)
* ``vrl stats``         — queue depth + program economics
* ``vrl auth whoami``   — show the identity a token resolves to

Reads are tiered like the API's read plane: anonymous (default) gets the public
projection; ``--internal`` attaches the operator credential for the full record
(cost/verdict/AI-XI, replay reasoning and verdict).
"""

from __future__ import annotations

import json
import sys
import webbrowser
from typing import Optional

import typer
from rich.console import Console

from . import __version__, auth, config, render
from .client import VrlClient
from .errors import InvalidCve, InvalidEmail, NotFound, TurnstileRequired, VrlError

app = typer.Typer(
    name="vrl",
    help="Submit a CVE to Vulnerability Research Labs, watch it run, and read the result.",
    no_args_is_help=True,
    invoke_without_command=True,
    add_completion=False,
)
auth_app = typer.Typer(help="Identity + credentials for the privileged /internal plane.")
app.add_typer(auth_app, name="auth")


class AppState:
    def __init__(self, base_url: Optional[str], token: Optional[str], json_out: bool) -> None:
        self.base_url = base_url
        self.token = token
        self.json_out = json_out

    def client(self, *, token: Optional[str] = None) -> VrlClient:
        return VrlClient(self.base_url, token=token)


def _print_json(obj: object) -> None:
    render.console.print_json(json.dumps(obj, default=str))


def _validate_cves(raw: str) -> list[str]:
    tokens = config.parse_cve_tokens(raw)
    if not tokens:
        raise InvalidCve("Provide at least one CVE id, e.g. CVE-2024-1234.")
    bad = [t for t in tokens if not config.is_cve(t)]
    if bad:
        raise InvalidCve(
            "Not valid CVE ids: " + ", ".join(bad[:5]) + (" …" if len(bad) > 5 else ""),
            hint="Expected CVE-YYYY-NNNN (comma-separate several).",
        )
    return tokens


def _internal_token(state: AppState) -> Optional[str]:
    """Resolve the operator credential for a full-record read (``--internal``).

    Never silently anonymous: ``--internal`` is an explicit request, so a failed
    mint raises instead of quietly downgrading to the public view.
    """
    return auth.resolve_token(state.token, base_url=config.base_url(state.base_url))


def _copy_to_clipboard(text: str) -> bool:
    """Best-effort cross-platform clipboard copy; False when nothing worked."""
    import shutil
    import subprocess

    for cmd in (
        ["pbcopy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
        ["clip.exe"],
    ):
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text.encode(), check=True, timeout=5)
                return True
            except Exception:  # noqa: BLE001 — clipboard is convenience, never a blocker
                continue
    return False


# ── global options ──────────────────────────────────────────────────────────


@app.callback()
def _main(
    ctx: typer.Context,
    base_url: Optional[str] = typer.Option(
        None, "--base-url", help=f"API base URL (env {config.ENV_BASE_URL}; default production)."
    ),
    token: Optional[str] = typer.Option(
        None, "--token", help=f"Bearer token for /internal calls (env {config.ENV_TOKEN})."
    ),
    json_out: bool = typer.Option(
        False, "--json", help="Emit raw JSON instead of a rendered view."
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI color."),
    version: bool = typer.Option(False, "--version", help="Show version and exit.", is_eager=True),
) -> None:
    if version:
        render.console.print(f"vrl {__version__}")
        raise typer.Exit()
    if no_color:
        render.console = Console(no_color=True)
        render.err_console = Console(stderr=True, no_color=True)
    ctx.obj = AppState(base_url=base_url, token=token, json_out=json_out)


# ── submit ────────────────────────────────────────────────────────────────


@app.command()
def submit(
    ctx: typer.Context,
    cve: str = typer.Argument(..., help="A CVE id (comma-separate several)."),
    email: Optional[str] = typer.Option(
        None, "--email", "-e", help="Your email — where the result is sent (public path)."
    ),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Your name (public path)."),
    submitted_by: Optional[str] = typer.Option(
        None, "--submitted-by", help="Optional attribution / org name."
    ),
    turnstile_token: Optional[str] = typer.Option(
        None,
        "--turnstile-token",
        envvar=config.ENV_TURNSTILE_TOKEN,
        help="Cloudflare Turnstile token (public path, if the deployment enforces it).",
    ),
    browser: bool = typer.Option(
        False,
        "--browser",
        help="Open the website's Turnstile-protected submit form in your browser "
        "(the CVE id is copied to the clipboard) instead of POSTing from here.",
    ),
    internal: bool = typer.Option(
        False, "--internal", help="Use the privileged /internal path (bearer token, no Turnstile)."
    ),
    source: str = typer.Option("quantro", "--source", help="Origin tag (internal path)."),
    watch_: bool = typer.Option(False, "--watch", "-w", help="Watch the CVE after submitting."),
    interval: float = typer.Option(
        config.DEFAULT_POLL_SECONDS, "--interval", help="Seconds between polls when --watch."
    ),
) -> None:
    """Queue a CVE for processing.

    By default this mirrors the website's public form (email + name + Turnstile).
    With ``--internal`` it uses your Google Cloud identity (or ``--token`` /
    ``VRL_TOKEN``) against the privileged plane — no email or Turnstile needed.
    """
    state: AppState = ctx.obj
    cves = _validate_cves(cve)

    if browser:
        url = config.submit_url()
        copied = _copy_to_clipboard(", ".join(cves))
        webbrowser.open(url)
        render.console.print(
            f"[bold]✓ Opened the submit form[/] {url}\n"
            + (
                "The CVE id"
                + ("s are" if len(cves) > 1 else " is")
                + " in your clipboard — paste, clear the Turnstile, submit.\n"
                if copied
                else "Paste " + ", ".join(cves) + ", clear the Turnstile, submit.\n"
            )
            + f"Then follow it from here: [bold]vrl watch {cves[0]} --verbose[/]"
        )
        raise typer.Exit()

    if internal:
        token = auth.resolve_token(state.token, base_url=config.base_url(state.base_url))
        with state.client(token=token) as c:
            items = [c.submit_internal(x, source=source, submitted_by=submitted_by) for x in cves]
        if state.json_out:
            _print_json([it.raw for it in items])
        else:
            for it in items:
                render.console.print(f"[bold green]✓ Queued[/] {it.cve_id}  ([cyan]{it.status}[/])")
    else:
        if email and not config.is_email(email):
            raise InvalidEmail(f"{email!r} is not a valid email address.")
        if not email:
            raise VrlError(
                "Public submit needs an email so the result can be sent to you.",
                hint=(
                    "Pass --email you@example.com (and --name), or use --internal "
                    "(your Google identity, no email, no Turnstile), or --browser "
                    "(the website's form)."
                ),
            )
        with state.client() as c:
            result = c.submit_public(
                ",".join(cves),
                email=email,
                name=name,
                submitted_by=submitted_by,
                turnstile_token=turnstile_token,
            )
        if state.json_out:
            _print_json(result.raw)
        else:
            render.console.print(render.submit_result_view(result, email=email))

    if watch_:
        render.console.print()
        _watch_impl(state, cves[0], interval=interval, verbose=False)


# ── watch ───────────────────────────────────────────────────────────────────


def _watch_impl(
    state: AppState,
    cve: str,
    *,
    interval: float,
    timeout: Optional[float] = None,
    verbose: bool = False,
) -> None:
    from .watch import watch_cve

    with state.client() as c:
        item = watch_cve(c, cve, interval=interval, timeout=timeout, verbose=verbose)
    meta = config.status_meta(item.status)
    render.console.print(f"\n[bold {meta.color}]{item.cve_id} → {meta.label}[/]  {meta.blurb}")


@app.command()
@app.command(name="track", hidden=True)
def watch(
    ctx: typer.Context,
    cve: str = typer.Argument(..., help="The CVE id to watch."),
    interval: float = typer.Option(
        config.DEFAULT_POLL_SECONDS, "--interval", help="Seconds between polls."
    ),
    timeout: Optional[float] = typer.Option(None, "--timeout", help="Give up after N seconds."),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show the poll log (prove it's live)."
    ),
) -> None:
    """Poll a CVE live until it reaches a terminal state (alias: track)."""
    _watch_impl(ctx.obj, cve.upper(), interval=interval, timeout=timeout, verbose=verbose)


# ── show ────────────────────────────────────────────────────────────────────


@app.command()
@app.command(name="status", hidden=True)
def show(
    ctx: typer.Context,
    cve: str = typer.Argument(..., help="The CVE id to describe."),
    internal: bool = typer.Option(
        False,
        "--internal",
        help="Attach the operator credential for the full record (cost/verdict/AI-XI).",
    ),
) -> None:
    """Show the write-up of one CVE: status and how the run went (alias: status).

    Without ``--internal`` this is the public view by construction — the API
    projects the record for anonymous callers (see its public_view)."""
    state: AppState = ctx.obj
    cve = cve.upper()
    token = _internal_token(state) if internal else None
    with state.client(token=token) as c:
        item = c.get_item(cve, internal=internal)
        record = None
        if config.is_terminal(item.status):
            try:
                record = c.find_record(cve, internal=internal)
            except VrlError:
                record = None
    if state.json_out:
        payload = {"queue": item.raw, "record": record.raw if record else None}
        _print_json(payload)
    else:
        render.console.print(render.issue_panel(item, record))
        if not internal:
            render.console.print(render.public_view_note())


# ── list ──────────────────────────────────────────────────────────────────


@app.command(name="list")
@app.command(name="feed", hidden=True)
def list_cmd(
    ctx: typer.Context,
    status: Optional[str] = typer.Option(None, "--status", help="Filter by status."),
    source: Optional[str] = typer.Option(
        None, "--source", help="Filter by origin, e.g. community."
    ),
    order: str = typer.Option("desc", "--order", help="asc | desc | priority."),
    limit: int = typer.Option(25, "--limit", "-l", min=1, max=100, help="How many rows."),
    internal: bool = typer.Option(
        False,
        "--internal",
        help="Attach the operator credential for full records (cost/paid-feed fields).",
    ),
) -> None:
    """Browse the live queue (alias: feed)."""
    state: AppState = ctx.obj
    token = _internal_token(state) if internal else None
    with state.client(token=token) as c:
        items, _ = c.list_feed(
            status=status, source=source, order=order, limit=limit, internal=internal
        )
    if state.json_out:
        _print_json([it.raw for it in items])
    elif not items:
        render.console.print("[grey62]No matching items.[/]")
    else:
        render.console.print(render.feed_table(items))
        if not internal:
            render.console.print(render.public_view_note())


# ── replay ──────────────────────────────────────────────────────────────────


@app.command()
def replay(
    ctx: typer.Context,
    cve: Optional[str] = typer.Argument(None, help="The processed CVE id (omit with --list)."),
    internal: bool = typer.Option(
        False,
        "--internal",
        help="Attach the operator credential for the full trace (reasoning, verdict).",
    ),
    list_all: bool = typer.Option(
        False, "--list", help="List which CVEs have replay traces, then exit."
    ),
) -> None:
    """Replay what happened when a processed CVE ran: every attempt, what the
    judge rejected each one for, and how it ended.

    Without ``--internal`` this is the sanitized public trace; with it, the
    operator's demo view — the agent's reasoning per attempt and the full
    verdict. ``--list`` shows coverage: replay covers corpus-harness runs only."""
    state: AppState = ctx.obj
    if list_all:
        with state.client() as c:
            rows = c.list_replays()
        if state.json_out:
            _print_json(rows)
        elif not rows:
            render.console.print("[grey62]No replay traces yet.[/]")
        else:
            render.console.print(render.replay_index_table(rows))
        raise typer.Exit()

    if not cve:
        raise VrlError(
            "Provide a CVE id, e.g. vrl replay CVE-2026-104457, or --list to see "
            "which CVEs have traces.",
        )
    cve = cve.upper()
    token = _internal_token(state) if internal else None
    with state.client(token=token) as c:
        try:
            trace = c.get_replay(cve, internal=internal)
        except NotFound:
            with state.client() as c2:
                covered = ", ".join(r["cve"] for r in c2.list_replays())
            raise VrlError(
                f"No replay trace for {cve}. Replay covers corpus-harness runs only — "
                "the queue row exists, but there is no step/retry story for it. "
                f"Traces on file: {covered}",
                hint=f"vrl show {cve} works for any queued CVE; vrl replay --list shows coverage.",
            ) from None
    if state.json_out:
        _print_json(trace.raw)
    else:
        render.console.print(render.replay_panel(trace, internal=internal))


# ── stats ─────────────────────────────────────────────────────────────────


@app.command()
def stats(ctx: typer.Context) -> None:
    """Queue depth and program-level economics."""
    state: AppState = ctx.obj
    with state.client() as c:
        depths = c.queue_stats()
        telemetry = None
        try:
            telemetry = c.harness_telemetry()
        except VrlError:
            telemetry = None
    if state.json_out:
        _print_json({"stats": depths, "telemetry": telemetry})
    else:
        render.console.print(render.stats_view(depths, telemetry))


# ── auth ────────────────────────────────────────────────────────────────────


@auth_app.command("whoami")
def auth_whoami(ctx: typer.Context) -> None:
    """Resolve a token and show the identity it carries (no server call)."""
    state: AppState = ctx.obj
    token = auth.resolve_token(state.token, base_url=config.base_url(state.base_url))
    email = auth.token_email(token)
    if email:
        render.console.print(f"OIDC identity: [bold]{email}[/]")
    else:
        render.console.print("[grey62]Token resolved (opaque — likely a shared secret).[/]")


@auth_app.command("token")
def auth_token(ctx: typer.Context) -> None:
    """Print a bearer token for the internal plane (e.g. to export VRL_TOKEN)."""
    state: AppState = ctx.obj
    token = auth.resolve_token(state.token, base_url=config.base_url(state.base_url))
    print(token)


# ── entry point ───────────────────────────────────────────────────────────


def main() -> None:
    try:
        app()
    except TurnstileRequired as exc:
        render.err_console.print(f"[bold red]turnstile[/] {exc.message}")
        if exc.hint:
            render.err_console.print(f"[grey62]hint:[/] {exc.hint}")
        sys.exit(2)
    except VrlError as exc:
        render.err_console.print(f"[bold red]error[/] {exc.message}")
        if exc.hint:
            render.err_console.print(f"[grey62]hint:[/] {exc.hint}")
        sys.exit(1)
    except KeyboardInterrupt:
        render.err_console.print("[grey62]interrupted[/]")
        sys.exit(130)


if __name__ == "__main__":
    main()
