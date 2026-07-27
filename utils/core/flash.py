from typing import Final

from fastapi import Request

FLASH_SESSION_KEY: Final = "flash"


def set_flash(request: Request, message: str, level: str = "success") -> None:
    """Store a one-shot flash message in the session.

    The next request pops it and renders it as a toast. Call this after
    log_in_session/log_out_session: both clear the session, which would
    discard a flash set earlier in the same request.
    """
    request.session[FLASH_SESSION_KEY] = {"message": message, "level": level}


def pop_flash(request: Request) -> dict | None:
    """Remove and return the pending flash message, or None."""
    flash = request.session.pop(FLASH_SESSION_KEY, None)
    if isinstance(flash, dict) and isinstance(flash.get("message"), str):
        return flash
    return None
