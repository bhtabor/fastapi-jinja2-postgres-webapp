from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta, UTC
from utils.core.models import (
    Account,
    AccountToken,
    User,
    Role,
)
from utils.core.dependencies import (
    get_account_from_credentials,
    get_account_from_session,
    get_authenticated_account,
    get_authenticated_user,
    get_optional_user,
    get_account_from_reset_token,
    get_account_from_recovery_token,
    get_user_with_relations,
    require_unauthenticated_client,
    require_unauthenticated_unless_invitation_warning,
    get_verified_account,
)
from exceptions.http_exceptions import (
    AlreadyAuthenticatedError,
    AuthenticationError,
    CredentialsError,
    PasswordValidationError,
)
import pytest


def test_get_account_from_credentials() -> None:
    """
    Tests retrieving an account using credentials.
    """
    session = MagicMock()
    mock_account = Account(
        id=1, email="test@example.com", hashed_password="hashed_password"
    )
    session.exec.return_value.first.return_value = mock_account

    # Test with valid credentials
    with patch("utils.core.dependencies.verify_password") as mock_verify:
        mock_verify.return_value = True
        account, returned_session = get_account_from_credentials(
            "test@example.com", "password123", session
        )
        assert account == mock_account
        assert returned_session == session
        mock_verify.assert_called_once_with("password123", "hashed_password")

    # Test with invalid password
    with patch("utils.core.dependencies.verify_password") as mock_verify:
        mock_verify.return_value = False
        with pytest.raises(CredentialsError):
            get_account_from_credentials("test@example.com", "wrong_password", session)

    # Test with non-existent account
    session.exec.return_value.first.return_value = None
    with pytest.raises(CredentialsError):
        get_account_from_credentials("nonexistent@example.com", "password123", session)


def _fake_request(session_data=None, cookies=None) -> MagicMock:
    request = MagicMock()
    request.session = dict(session_data or {})
    request.cookies = dict(cookies or {})
    return request


def test_get_account_from_session() -> None:
    """Resolves the account from the session token, with remember-me fallback."""
    from utils.core.auth import REMEMBER_ME_COOKIE_NAME, SESSION_TOKEN_KEY

    db = MagicMock()
    mock_account = Account(id=1, email="test@example.com")

    # Valid token in the cookie session
    with patch(
        "utils.core.dependencies.get_account_by_session_token"
    ) as mock_lookup:
        mock_lookup.return_value = mock_account
        request = _fake_request({SESSION_TOKEN_KEY: "tok"})
        assert get_account_from_session(request, db) == mock_account
        mock_lookup.assert_called_once_with("tok", db)

    # No session token, valid remember-me cookie: session is repopulated
    with patch(
        "utils.core.dependencies.get_account_by_session_token"
    ) as mock_lookup:
        mock_lookup.return_value = mock_account
        request = _fake_request(cookies={REMEMBER_ME_COOKIE_NAME: "remember-tok"})
        assert get_account_from_session(request, db) == mock_account
        assert request.session[SESSION_TOKEN_KEY] == "remember-tok"

    # Nothing valid anywhere
    with patch(
        "utils.core.dependencies.get_account_by_session_token"
    ) as mock_lookup:
        mock_lookup.return_value = None
        request = _fake_request({SESSION_TOKEN_KEY: "stale"})
        assert get_account_from_session(request, db) is None


def test_get_authenticated_account() -> None:
    db = MagicMock()
    request = _fake_request()

    with patch("utils.core.dependencies.get_account_from_session") as mock_resolve:
        mock_account = Account(id=1, email="test@example.com")
        mock_resolve.return_value = mock_account
        assert get_authenticated_account(request, db) == mock_account

    with patch("utils.core.dependencies.get_account_from_session") as mock_resolve:
        mock_resolve.return_value = None
        with pytest.raises(AuthenticationError):
            get_authenticated_account(request, db)


def test_get_authenticated_user() -> None:
    db = MagicMock()
    request = _fake_request()

    with patch("utils.core.dependencies.get_account_from_session") as mock_resolve:
        mock_user = User(id=1, name="Test User")
        mock_resolve.return_value = Account(
            id=1, email="test@example.com", user=mock_user
        )
        assert get_authenticated_user(request, db) == mock_user

    with patch("utils.core.dependencies.get_account_from_session") as mock_resolve:
        mock_resolve.return_value = None
        with pytest.raises(AuthenticationError):
            get_authenticated_user(request, db)


def test_get_optional_user() -> None:
    db = MagicMock()
    request = _fake_request()

    with patch("utils.core.dependencies.get_account_from_session") as mock_resolve:
        mock_user = User(id=1, name="Test User")
        mock_resolve.return_value = Account(
            id=1, email="test@example.com", user=mock_user
        )
        assert get_optional_user(request, db) == mock_user

    with patch("utils.core.dependencies.get_account_from_session") as mock_resolve:
        mock_resolve.return_value = None
        assert get_optional_user(request, db) is None


def test_get_account_from_reset_token() -> None:
    """
    Tests retrieving an account from a password reset token.
    """
    session = MagicMock()
    mock_account = Account(id=1, email="test@example.com")
    mock_token = AccountToken(
        account_id=1, token="hashed", context="reset_password", sent_to="test@example.com"
    )

    # Valid token belonging to the account with the given email
    with patch("utils.core.dependencies.get_email_token_row") as mock_row:
        mock_row.return_value = mock_token
        session.get.return_value = mock_account
        account, token = get_account_from_reset_token(
            "test@example.com", "raw_token", session
        )
        assert account == mock_account
        assert token == mock_token

    # Valid token but email mismatch
    with patch("utils.core.dependencies.get_email_token_row") as mock_row:
        mock_row.return_value = mock_token
        session.get.return_value = Account(id=1, email="other@example.com")
        account, token = get_account_from_reset_token(
            "test@example.com", "raw_token", session
        )
        assert account is None
        assert token is None

    # Invalid/expired/consumed token
    with patch("utils.core.dependencies.get_email_token_row") as mock_row:
        mock_row.return_value = None
        account, token = get_account_from_reset_token(
            "test@example.com", "invalid_token", session
        )
        assert account is None
        assert token is None


def test_get_user_with_relations() -> None:
    """
    Tests retrieving a user with loaded relationships.
    """
    session = MagicMock()
    mock_user = User(id=1, name="Test User")

    # Create a mock user with loaded relationships
    mock_eager_user = User(
        id=1, name="Test User", roles=[Role(id=1, name="Admin", organization_id=1)]
    )

    session.exec.return_value.one.return_value = mock_eager_user

    # Test getting user with relations
    user = get_user_with_relations(mock_user, session)
    assert user == mock_eager_user

    # Verify the query was constructed correctly
    session.exec.assert_called_once()
    # We can't easily check the exact query construction with selectinload,
    # but we can verify the where clause was applied correctly
    assert '"user".id' in str(session.exec.call_args[0][0])
    assert "id_1" in str(session.exec.call_args[0][0])


def test_require_unauthenticated_client() -> None:
    """Tests that require_unauthenticated_client raises when user is authenticated."""
    # Test with no user (should return None)
    result = require_unauthenticated_client(user=None)
    assert result is None

    # Test with authenticated user (should raise)
    mock_user = User(id=1, name="Test User")
    with pytest.raises(AlreadyAuthenticatedError):
        require_unauthenticated_client(user=mock_user)


def test_require_unauthenticated_unless_invitation_warning() -> None:
    """Authenticated users may view auth pages when an invite token warning applies."""
    mock_user = User(id=1, name="Test User")
    mock_session = MagicMock()

    with patch(
        "utils.core.dependencies.get_invitation_token_warning",
        return_value=None,
    ):
        with pytest.raises(AlreadyAuthenticatedError):
            require_unauthenticated_unless_invitation_warning(
                invitation_token="some-token",
                user=mock_user,
                session=mock_session,
            )

    with patch(
        "utils.core.dependencies.get_invitation_token_warning",
        return_value="expired",
    ):
        require_unauthenticated_unless_invitation_warning(
            invitation_token="expired-token",
            user=mock_user,
            session=mock_session,
        )


def test_get_verified_account() -> None:
    """Tests that get_verified_account verifies email and password."""
    mock_account = Account(
        id=1, email="test@example.com", hashed_password="hashed_password"
    )

    # Test with matching email and correct password
    with patch("utils.core.dependencies.verify_password") as mock_verify:
        mock_verify.return_value = True
        account = get_verified_account(
            email="test@example.com", password="correct_password", account=mock_account
        )
        assert account == mock_account
        mock_verify.assert_called_once_with("correct_password", "hashed_password")

    # Test with mismatched email
    with pytest.raises(CredentialsError) as exc_info:
        get_verified_account(
            email="wrong@example.com", password="correct_password", account=mock_account
        )
    assert "Email does not match" in str(exc_info.value.detail)

    # Test with wrong password
    with patch("utils.core.dependencies.verify_password") as mock_verify:
        mock_verify.return_value = False
        with pytest.raises(PasswordValidationError) as exc_info:
            get_verified_account(
                email="test@example.com",
                password="wrong_password",
                account=mock_account,
            )
        assert exc_info.value.detail["field"] == "password"


# --- Recovery token dependency tests ---


def test_get_account_from_recovery_token_valid() -> None:
    """Test valid recovery token returns (account, token row)."""
    session = MagicMock()
    mock_account = Account(id=1, email="test@example.com")
    mock_token = AccountToken(
        account_id=1, token="hashed", context="recovery", sent_to="victim@example.com"
    )
    with patch("utils.core.dependencies.get_email_token_row") as mock_row:
        mock_row.return_value = mock_token
        session.get.return_value = mock_account
        account, token = get_account_from_recovery_token("raw_token", session)
        assert account == mock_account
        assert token == mock_token


def test_get_account_from_recovery_token_invalid() -> None:
    """Expired, consumed, or nonexistent recovery tokens return (None, None).

    All three cases collapse to the same lookup miss: expiry is a query-time
    window and consumption deletes the row.
    """
    session = MagicMock()
    with patch("utils.core.dependencies.get_email_token_row") as mock_row:
        mock_row.return_value = None
        account, token = get_account_from_recovery_token("nonexistent", session)
        assert account is None
        assert token is None
