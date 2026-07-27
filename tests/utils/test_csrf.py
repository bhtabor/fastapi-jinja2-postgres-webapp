import re
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from main import app
from tests.conftest import get_session_data
from utils.core.csrf import (
    CSRF_FORM_FIELD,
    CSRF_HEADER_NAME,
    CSRF_SESSION_KEY,
    generate_csrf_token,
    mask_csrf_token,
    unmask_csrf_token,
    validate_csrf_token,
)


def _get_page_csrf_token(client: TestClient) -> str:
    """Fetch the login page and read the (masked) CSRF token form field."""
    response = client.get(app.url_path_for("read_login"))
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "login page should render a csrf_token form field"
    return match.group(1)


def _session_request(token: str) -> MagicMock:
    request = MagicMock()
    request.session = {CSRF_SESSION_KEY: token}
    return request


def test_mask_roundtrip_and_uniqueness():
    token = generate_csrf_token()
    masked1 = mask_csrf_token(token)
    masked2 = mask_csrf_token(token)

    assert masked1 != masked2  # fresh pad per call
    assert masked1 != token
    assert unmask_csrf_token(masked1) == token
    assert unmask_csrf_token(masked2) == token


def test_unmask_rejects_garbage():
    assert unmask_csrf_token("") is None
    assert unmask_csrf_token("not base64 !!") is None
    assert unmask_csrf_token("YWJj") is None  # odd-length decoded value


def test_validate_csrf_token_accepts_masked_submission(monkeypatch):
    monkeypatch.setenv("CSRF_ENABLED", "1")
    token = generate_csrf_token()
    request = _session_request(token)
    assert validate_csrf_token(request, mask_csrf_token(token)) is True


def test_validate_csrf_token_accepts_raw_submission(monkeypatch):
    monkeypatch.setenv("CSRF_ENABLED", "1")
    token = generate_csrf_token()
    request = _session_request(token)
    assert validate_csrf_token(request, token) is True


def test_validate_csrf_token_rejects_mismatch(monkeypatch):
    monkeypatch.setenv("CSRF_ENABLED", "1")
    request = _session_request(generate_csrf_token())
    other = generate_csrf_token()
    assert validate_csrf_token(request, other) is False
    assert validate_csrf_token(request, mask_csrf_token(other)) is False


def test_post_without_csrf_rejected_when_enabled(
    unauth_client: TestClient, monkeypatch
):
    monkeypatch.setenv("CSRF_ENABLED", "1")
    _get_page_csrf_token(unauth_client)

    response = unauth_client.post(
        app.url_path_for("login"),
        data={"email": "test@example.com", "password": "Password123!@#"},
    )

    assert response.status_code == 403


def test_post_with_forged_csrf_rejected_when_enabled(
    unauth_client: TestClient, monkeypatch
):
    """A token not issued via the session is rejected, even if well-formed."""
    monkeypatch.setenv("CSRF_ENABLED", "1")
    _get_page_csrf_token(unauth_client)

    response = unauth_client.post(
        app.url_path_for("login"),
        data={
            CSRF_FORM_FIELD: mask_csrf_token(generate_csrf_token()),
            "email": "test@example.com",
            "password": "Password123!@#",
        },
    )

    assert response.status_code == 403


def test_post_with_form_csrf_accepted_when_enabled(
    unauth_client: TestClient, test_account, monkeypatch
):
    monkeypatch.setenv("CSRF_ENABLED", "1")
    token = _get_page_csrf_token(unauth_client)

    response = unauth_client.post(
        app.url_path_for("login"),
        data={
            CSRF_FORM_FIELD: token,
            "email": test_account.email,
            "password": "Test123!@#",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard/"


def test_post_with_header_csrf_accepted_when_enabled(
    unauth_client: TestClient, monkeypatch
):
    monkeypatch.setenv("CSRF_ENABLED", "1")
    token = _get_page_csrf_token(unauth_client)

    response = unauth_client.post(
        app.url_path_for("forgot_password"),
        data={"email": "missing@example.com"},
        headers={CSRF_HEADER_NAME: token},
        follow_redirects=False,
    )

    assert response.status_code == 303


def test_csrf_token_not_exposed_in_a_readable_cookie(
    unauth_client: TestClient, monkeypatch
):
    """The token is stored in the signed session, not its own cookie."""
    monkeypatch.setenv("CSRF_ENABLED", "1")
    token = _get_page_csrf_token(unauth_client)

    assert token
    cookie_names = set(unauth_client.cookies.keys())
    assert "csrf_token" not in cookie_names
    assert "session" in cookie_names


def test_raw_csrf_token_never_appears_in_page(
    unauth_client: TestClient, monkeypatch
):
    """Pages embed a per-request masked encoding, never the raw token."""
    monkeypatch.setenv("CSRF_ENABLED", "1")
    response = unauth_client.get(app.url_path_for("read_login"))
    raw = get_session_data(unauth_client)[CSRF_SESSION_KEY]

    assert raw not in response.text

    rendered = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert rendered and unmask_csrf_token(rendered.group(1)) == raw


def test_rendered_token_differs_per_request_but_session_token_is_stable(
    unauth_client: TestClient, monkeypatch
):
    monkeypatch.setenv("CSRF_ENABLED", "1")
    first = _get_page_csrf_token(unauth_client)
    raw_after_first = get_session_data(unauth_client)[CSRF_SESSION_KEY]
    second = _get_page_csrf_token(unauth_client)
    raw_after_second = get_session_data(unauth_client)[CSRF_SESSION_KEY]

    assert first != second  # fresh mask per response
    assert raw_after_first == raw_after_second  # same underlying token
    assert unmask_csrf_token(first) == unmask_csrf_token(second) == raw_after_first


def test_csrf_token_rotates_on_login(
    unauth_client: TestClient, test_account, test_user, monkeypatch
):
    """Logging in clears the session, which also issues a fresh CSRF token."""
    monkeypatch.setenv("CSRF_ENABLED", "1")
    token = _get_page_csrf_token(unauth_client)
    raw_before = get_session_data(unauth_client)[CSRF_SESSION_KEY]

    response = unauth_client.post(
        app.url_path_for("login"),
        data={
            CSRF_FORM_FIELD: token,
            "email": test_account.email,
            "password": "Test123!@#",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    unauth_client.get(app.url_path_for("read_dashboard"))
    raw_after = get_session_data(unauth_client)[CSRF_SESSION_KEY]
    assert raw_after != raw_before
