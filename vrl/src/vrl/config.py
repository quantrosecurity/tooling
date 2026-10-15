"""Static configuration, environment-variable names, and the CVE/queue vocabulary.

Everything that might sensibly be overridden at runtime is read from an env var
here, so the rest of the package never touches ``os.environ`` directly.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

# ── Service endpoints ────────────────────────────────────────────────────────

# The public VRL API (Cloud Run). Reads and the public submit form hit this
# directly; the website does the same (no proxy in between). Override for a
# self-hosted or staging deployment via --base-url / VRL_API_BASE.
DEFAULT_BASE_URL = "https://api.vrl.quantrosecurity.ai"

# The privileged /internal plane mints a Google OIDC identity token. The service
# account to impersonate is deployment-specific, so it is NOT hardcoded here —
# set it via VRL_INTERNAL_SA (or run on a GCP workload whose own identity is
# allow-listed). Public reads and the public submit path need none of this.

# ── Environment variable names ───────────────────────────────────────────────

ENV_BASE_URL = "VRL_API_BASE"
ENV_TOKEN = "VRL_TOKEN"
ENV_INTERNAL_SA = "VRL_INTERNAL_SA"
ENV_OIDC_AUDIENCE = "VRL_OIDC_AUDIENCE"
ENV_TURNSTILE_TOKEN = "VRL_TURNSTILE_TOKEN"
ENV_EMAIL = "VRL_SUBMITTER_EMAIL"
ENV_NAME = "VRL_SUBMITTER_NAME"

# ── Validation (mirrors the server + website exactly) ────────────────────────

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_CVE_SPLIT = re.compile(r"[\s,;]+")

# ── Polling ──────────────────────────────────────────────────────────────────

DEFAULT_POLL_SECONDS = 8.0  # the website polls every 7–8s
MIN_POLL_SECONDS = 2.0


def base_url(override: str | None = None) -> str:
    """Resolve the API base URL: explicit override > env > default."""
    raw = override or os.getenv(ENV_BASE_URL) or DEFAULT_BASE_URL
    return raw.rstrip("/")


def parse_cve_tokens(raw: str) -> list[str]:
    """Split a free-form submission string into de-duped, upper-cased CVE tokens.

    Mirrors the website: split on whitespace/comma/semicolon, upper-case, and
    preserve first-seen order. Does NOT validate shape — see :func:`is_cve`.
    """
    seen: set[str] = set()
    out: list[str] = []
    for tok in _CVE_SPLIT.split(raw.strip()):
        if not tok:
            continue
        u = tok.upper()
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def is_cve(token: str) -> bool:
    return bool(CVE_RE.match(token.strip()))


def is_email(value: str) -> bool:
    return bool(EMAIL_RE.match(value.strip()))


# ── Queue status vocabulary ──────────────────────────────────────────────────


@dataclass(frozen=True)
class StatusMeta:
    """Presentation metadata for one queue status."""

    label: str
    code: str  # compact badge for dense tables, e.g. EXPL
    color: str  # a rich color/style name
    terminal: bool
    blurb: str  # one-line explanation for humans


# Keyed by the exact status strings the API uses (backend/models.py::Status).
STATUS: dict[str, StatusMeta] = {
    "pending": StatusMeta(
        "Queued", "QUEUE", "yellow", False,
        "Accepted and waiting in line for a solver to pick it up.",
    ),
    "processing": StatusMeta(
        "Processing", "PROC", "cyan", False,
        "A solver is working it: discovery → proof-of-concept → lab → verify.",
    ),
    "exploit_generated": StatusMeta(
        "Exploit generated", "EXPL", "green", True,
        "A working exploit was produced and verified against a live lab.",
    ),
    "no_exploit": StatusMeta(
        "No exploit", "NONE", "blue", True,
        "The lab built and ran, but no reproducible exploit was found — an honest negative.",
    ),
    "failed": StatusMeta(
        "Failed", "FAIL", "red", True,
        "The run hit a build/infrastructure error before reaching a verdict.",
    ),
    "unsupported": StatusMeta(
        "Unsupported", "UNSUP", "magenta", True,
        "Out of scope for the Linux/container pipeline (e.g. Windows-only software).",
    ),
    "insufficient_metadata": StatusMeta(
        "Insufficient metadata", "META", "magenta", True,
        "Skipped for now — no derivable version data to pin a target. Recoverable later.",
    ),
}

# A sensible display order (lifecycle, then terminal states).
STATUS_ORDER = [
    "pending", "processing", "exploit_generated", "no_exploit",
    "failed", "unsupported", "insufficient_metadata",
]

# The states that mean "done" — polling stops when one is reached.
TERMINAL_STATUSES = frozenset(s for s, m in STATUS.items() if m.terminal)

# The ordered journey a CVE takes, for the pipeline timeline view.
PIPELINE_STAGES = ["submitted", "pending", "processing", "done"]


def status_meta(status: str | None) -> StatusMeta:
    """Return metadata for a status string, with a safe fallback for unknowns."""
    if status and status in STATUS:
        return STATUS[status]
    return StatusMeta(status or "unknown", "?", "white", False, "Unrecognized status.")


def is_terminal(status: str | None) -> bool:
    return bool(status) and status in TERMINAL_STATUSES
