import base64
import os
import secrets
from typing import Final

from fastapi import Request

CSRF_SESSION_KEY: Final = "csrf_token"
CSRF_HEADER_NAME: Final = "x-csrf-token"
CSRF_FORM_FIELD: Final = "csrf_token"
UNSAFE_HTTP_METHODS: Final = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def csrf_enabled() -> bool:
    return os.environ.get("CSRF_ENABLED", "1").lower() not in {"0", "false", "no"}


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def mask_csrf_token(raw_token: str) -> str:
    """One-time-pad encoding of the token for embedding in HTML.

    Every call returns a different value, so the raw session token is
    never reflected verbatim in a response body — a static secret
    repeated across responses is recoverable via compression
    side-channels (BREACH) and lingers in cached or archived pages.
    """
    token_bytes = raw_token.encode("utf-8")
    pad = secrets.token_bytes(len(token_bytes))
    masked = bytes(p ^ t for p, t in zip(pad, token_bytes))
    return base64.urlsafe_b64encode(pad + masked).decode("utf-8")


def unmask_csrf_token(masked_token: str) -> str | None:
    """Invert mask_csrf_token; None if the value isn't a valid masking."""
    try:
        decoded = base64.urlsafe_b64decode(masked_token.encode("utf-8"))
    except ValueError:
        return None
    if not decoded or len(decoded) % 2:
        return None
    half = len(decoded) // 2
    pad, masked = decoded[:half], decoded[half:]
    try:
        return bytes(p ^ m for p, m in zip(pad, masked)).decode("utf-8")
    except UnicodeDecodeError:
        return None


def validate_csrf_token(request: Request, submitted_token: str | None) -> bool:
    """Compare a submitted token against the session's raw token.

    Submissions are normally masked (forms and the meta tag embed
    mask_csrf_token output), but the raw token is accepted too: masking
    protects the token from leaking out of response bodies, not from a
    caller who already holds it.
    """
    if not csrf_enabled():
        return True
    if not submitted_token:
        return False
    expected = request.session.get(CSRF_SESSION_KEY)
    if not isinstance(expected, str) or not expected:
        return False
    unmasked = unmask_csrf_token(submitted_token)
    if unmasked is not None and secrets.compare_digest(expected, unmasked):
        return True
    return secrets.compare_digest(expected, submitted_token)


async def extract_submitted_csrf_token(request: Request) -> str | None:
    header_token = request.headers.get(CSRF_HEADER_NAME)
    if header_token:
        return header_token

    content_type = request.headers.get("content-type", "")
    if (
        "application/x-www-form-urlencoded" in content_type
        or "multipart/form-data" in content_type
    ):
        form = await request.form()
        value = form.get(CSRF_FORM_FIELD)
        if isinstance(value, str):
            return value
    return None


async def enforce_csrf(request: Request) -> None:
    """App-level dependency validating the CSRF token on unsafe methods.

    Runs as a dependency (not middleware) because it may parse the form
    body: on the route's own Request instance the parse is cached, so the
    route's Form(...) parameters read the same data instead of finding a
    consumed body stream.
    """
    from exceptions.http_exceptions import CsrfError

    if csrf_enabled() and request.method in UNSAFE_HTTP_METHODS:
        submitted = await extract_submitted_csrf_token(request)
        if not validate_csrf_token(request, submitted):
            raise CsrfError()
