import re
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from main import app
from utils.core.csrf import (
    CSRF_FORM_FIELD,
    CSRF_HEADER_NAME,
    generate_csrf_token,
    validate_csrf_token,
)


def _get_page_csrf_token(client: TestClient) -> str:
    """Fetch the login page and read the CSRF token from the form field."""
    response = client.get(app.url_path_for("read_login"))
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "login page should render a csrf_token form field"
    return match.group(1)


def test_validate_csrf_token_accepts_matching_values(monkeypatch):
    monkeypatch.setenv("CSRF_ENABLED", "1")
    request = MagicMock()
    token = generate_csrf_token()
    request.state.csrf_token = token
    assert validate_csrf_token(request, token) is True


def test_validate_csrf_token_rejects_mismatch(monkeypatch):
    monkeypatch.setenv("CSRF_ENABLED", "1")
    request = MagicMock()
    request.state.csrf_token = generate_csrf_token()
    assert validate_csrf_token(request, generate_csrf_token()) is False


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
            CSRF_FORM_FIELD: generate_csrf_token(),
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


def test_csrf_token_is_stable_across_requests(
    unauth_client: TestClient, monkeypatch
):
    monkeypatch.setenv("CSRF_ENABLED", "1")
    first = _get_page_csrf_token(unauth_client)
    second = _get_page_csrf_token(unauth_client)
    assert first == second


def test_csrf_token_rotates_on_login(
    unauth_client: TestClient, test_account, test_user, monkeypatch
):
    """Logging in clears the session, which also issues a fresh CSRF token."""
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

    response = unauth_client.get(app.url_path_for("read_dashboard"))
    match = re.search(r'name="csrf-token" content="([^"]+)"', response.text)
    assert match
    assert match.group(1) != token
