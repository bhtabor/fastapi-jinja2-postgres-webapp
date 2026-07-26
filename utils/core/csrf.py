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


def get_request_csrf_token(request: Request) -> str:
    token = getattr(request.state, "csrf_token", None)
    if isinstance(token, str) and token:
        return token
    token = request.session.get(CSRF_SESSION_KEY)
    if isinstance(token, str) and token:
        return token
    return generate_csrf_token()


def validate_csrf_token(request: Request, submitted_token: str | None) -> bool:
    if not csrf_enabled():
        return True
    if not submitted_token:
        return False
    expected = get_request_csrf_token(request)
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
