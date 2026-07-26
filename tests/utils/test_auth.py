import re
import string
import random
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse, parse_qs
from unittest.mock import MagicMock
from starlette.datastructures import URLPath
from starlette.responses import Response
from main import app
from utils.core.auth import (
    REMEMBER_ME_COOKIE_NAME,
    SESSION_TOKEN_KEY,
    SESSION_VALIDITY_DAYS,
    delete_session_token,
    generate_session_token,
    get_account_by_session_token,
    log_in_session,
    log_out_session,
    revoke_all_session_tokens,
    verify_password,
    get_password_hash,
    generate_password_reset_url,
    COMPILED_PASSWORD_PATTERN,
    convert_python_regex_to_html,
)
from utils.core.models import AccountToken


def test_convert_python_regex_to_html() -> None:
    PYTHON_SPECIAL_CHARS = r"(?=.*[\[\]\\@$!%*?&{}<>.,'#\-_=+\(\):;|~/\^])"
    HTML_EQUIVALENT = r"(?=.*[\[\]\\@$!%*?&\{\}\<\>\.\,\\'#\-_=\+\(\):;\|~\/\^])"

    PYTHON_SPECIAL_CHARS = convert_python_regex_to_html(PYTHON_SPECIAL_CHARS)

    assert PYTHON_SPECIAL_CHARS == HTML_EQUIVALENT


def test_password_hashing() -> None:
    password = "Test123!@#"
    hashed = get_password_hash(password)
    assert verify_password(password, hashed)
    assert not verify_password("wrong_password", hashed)


def test_session_token_round_trip(session, test_account) -> None:
    """A generated session token resolves back to its account."""
    token = generate_session_token(test_account.id, session)
    session.commit()

    account = get_account_by_session_token(token, session)
    assert account is not None
    assert account.id == test_account.id


def test_expired_session_token(session, test_account) -> None:
    """Tokens older than the validity window no longer authenticate."""
    token = generate_session_token(test_account.id, session)
    session.commit()

    row = session.exec(
        __import__("sqlmodel").select(AccountToken).where(AccountToken.token == token)
    ).one()
    row.inserted_at = datetime.now(UTC) - timedelta(days=SESSION_VALIDITY_DAYS + 1)
    session.commit()

    assert get_account_by_session_token(token, session) is None


def test_session_token_context_is_scoped(session, test_account) -> None:
    """A token stored under another context never authenticates a session."""
    session.add(
        AccountToken(
            account_id=test_account.id, token="not-a-session", context="reset_password"
        )
    )
    session.commit()

    assert get_account_by_session_token("not-a-session", session) is None


def test_delete_and_revoke_session_tokens(session, test_account) -> None:
    token_one = generate_session_token(test_account.id, session)
    token_two = generate_session_token(test_account.id, session)
    session.commit()

    delete_session_token(token_one, session)
    session.commit()
    assert get_account_by_session_token(token_one, session) is None
    assert get_account_by_session_token(token_two, session) is not None

    revoke_all_session_tokens(test_account.id, session)
    session.commit()
    assert get_account_by_session_token(token_two, session) is None


def test_password_reset_url_generation(env_vars) -> None:
    """
    Tests that the password reset URL is correctly formatted and contains
    the required query parameters.
    """
    test_email = "test@example.com"
    test_token = "abc123"

    url = generate_password_reset_url(test_email, test_token)

    # Parse the URL
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    # Get the actual path from the FastAPI app
    reset_password_path: URLPath = app.url_path_for("reset_password")

    # Verify URL path
    assert parsed.path == str(reset_password_path)

    # Verify query parameters
    assert "email" in query_params
    assert "token" in query_params
    assert query_params["email"][0] == test_email
    assert query_params["token"][0] == test_token


def test_password_pattern() -> None:
    """
    Tests that the password pattern is correctly defined. to require at least
    one uppercase letter, one lowercase letter, one digit, and one special
    character, and at least 8 characters long. Allowed special characters are:
    !@#$%^&*()_+-=[]{}|;:,.<>?
    """
    special_characters = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    uppercase_letters = string.ascii_uppercase
    lowercase_letters = string.ascii_lowercase
    digits = string.digits

    required_elements = {
        "special": special_characters,
        "uppercase": uppercase_letters,
        "lowercase": lowercase_letters,
        "digit": digits,
    }

    # Valid password tests
    for element in required_elements:
        for c in required_elements[element]:
            password = c + "test"
            for other_element in required_elements:
                if other_element != element:
                    password += random.choice(required_elements[other_element])
            # Randomize the order of the characters in the string
            password = "".join(random.sample(password, len(password)))
            assert re.match(COMPILED_PASSWORD_PATTERN, password) is not None, (
                f"Password {password} does not match the pattern"
            )

    # Invalid password tests

    # Empty password
    password = ""
    assert re.match(COMPILED_PASSWORD_PATTERN, password) is None

    # Too short
    password = "aA1!aA1"
    assert re.match(COMPILED_PASSWORD_PATTERN, password) is None

    # No uppercase letter
    password = "a1!" * 3
    assert re.match(COMPILED_PASSWORD_PATTERN, password) is None

    # No lowercase letter
    password = "A1!" * 3
    assert re.match(COMPILED_PASSWORD_PATTERN, password) is None

    # No digit
    password = "aA!" * 3
    assert re.match(COMPILED_PASSWORD_PATTERN, password) is None

    # No special character
    password = "aA1" * 3
    assert re.match(COMPILED_PASSWORD_PATTERN, password) is None


def _fake_request() -> MagicMock:
    request = MagicMock()
    request.session = {}
    request.cookies = {}
    return request


def test_log_in_session_renews_and_sets_remember_cookie(session, test_account) -> None:
    request = _fake_request()
    request.session["stale"] = "value"  # must be cleared (fixation defense)
    response = Response()

    token = log_in_session(
        request, response, test_account.id, session, remember=True
    )
    session.commit()

    assert "stale" not in request.session
    assert request.session[SESSION_TOKEN_KEY] == token
    set_cookies = response.headers.getlist("set-cookie")
    assert any(header.startswith(f"{REMEMBER_ME_COOKIE_NAME}=") for header in set_cookies)
    assert any("Max-Age=" in header for header in set_cookies)


def test_log_in_session_without_remember_sets_no_cookie(session, test_account) -> None:
    request = _fake_request()
    response = Response()

    log_in_session(request, response, test_account.id, session)
    session.commit()

    assert response.headers.getlist("set-cookie") == []
    assert SESSION_TOKEN_KEY in request.session


def test_log_out_session_deletes_token_and_clears(session, test_account) -> None:
    request = _fake_request()
    response = Response()
    token = log_in_session(request, response, test_account.id, session)
    session.commit()

    log_out_session(request, response, session)

    assert request.session == {}
    assert get_account_by_session_token(token, session) is None
    set_cookies = response.headers.getlist("set-cookie")
    assert any(header.startswith(f"{REMEMBER_ME_COOKIE_NAME}=") for header in set_cookies)
