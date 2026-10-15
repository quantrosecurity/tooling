"""Typed exceptions with human-friendly messages.

The CLI layer catches :class:`VrlError` and prints ``.message`` (plus an
optional ``.hint``) rather than a traceback, so a mistyped CVE or an expired
token reads like a tool talking, not a crash.
"""

from __future__ import annotations


class VrlError(Exception):
    """Base class for every error the CLI knows how to explain."""

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


class InvalidCve(VrlError):
    """A token did not look like ``CVE-YYYY-NNNN``."""


class InvalidEmail(VrlError):
    """An email address failed the basic deliverability shape check."""


class NotFound(VrlError):
    """The queue has no record for this CVE (HTTP 404)."""


class AuthError(VrlError):
    """Missing/invalid credentials for the privileged /internal plane."""


class TurnstileRequired(VrlError):
    """The deployment enforces Turnstile and no token was supplied."""


class RateLimited(VrlError):
    """Too many submissions from this client (HTTP 429)."""


class ApiError(VrlError):
    """An unexpected, non-2xx response from the API."""

    def __init__(self, status_code: int, detail: str, *, hint: str | None = None) -> None:
        super().__init__(f"API error {status_code}: {detail}", hint=hint)
        self.status_code = status_code
        self.detail = detail
