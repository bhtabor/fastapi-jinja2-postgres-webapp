from typing import Optional

from fastapi import Request
from fastapi_turbo import TurboStreamResponse, streams
from fastapi_turbo.templates import TurboTemplates
from markupsafe import Markup


def toast_stream(
    templates: TurboTemplates, request: Request, message: str, level: str = "success"
) -> Markup:
    """Render the toast partial as a stream action appending to #toast-container."""
    html = templates.render_string(
        request, "base/partials/toast_item.html", message=message, level=level
    )
    return streams.append(html, target="toast-container")


def toast_stream_response(
    templates: TurboTemplates,
    request: Request,
    message: str,
    level: str = "success",
    status_code: int = 200,
    headers: Optional[dict[str, str]] = None,
) -> TurboStreamResponse:
    """A stream response containing only a toast.

    Turbo processes stream bodies on failed form submissions too, so real
    error status codes (401/403/422/429/500) are preserved.
    """
    return TurboStreamResponse(
        toast_stream(templates, request, message, level=level),
        status_code=status_code,
        headers=headers,
    )
