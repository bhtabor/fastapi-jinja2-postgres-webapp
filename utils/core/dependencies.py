import logging
from collections.abc import Generator
from datetime import UTC, datetime

from fastapi import Depends, Form, Query, Request
from pydantic import EmailStr
from sqlalchemy.orm import selectinload
from sqlmodel import Session, select
from starlette.concurrency import run_in_threadpool

from exceptions.http_exceptions import (
    AlreadyAuthenticatedError,
    AuthenticationError,
    CredentialsError,
    PasswordValidationError,
)
from utils.core.auth import (
    REMEMBER_ME_COOKIE_NAME,
    SESSION_TOKEN_KEY,
    get_account_by_session_token,
    verify_password,
)
from utils.core.db import get_engine
from utils.core.invitations import get_invitation_token_warning
from utils.core.models import (
    Account,
    AccountRecoveryToken,
    EmailVerificationToken,
    PasswordResetToken,
    Role,
    User,
)

logger = logging.getLogger(__name__)


def get_session() -> Generator[Session]:
    """
    Provides a database session for executing queries.

    Yields:
        Session: A SQLModel session object for database operations.
    """
    with Session(get_engine()) as session:
        yield session


def get_account_from_session(request: Request, session: Session) -> Account | None:
    """Resolve the authenticated account from the cookie session.

    The signed session cookie carries an opaque token; its authority is the
    AccountToken row (context "session"). When the browser-lifetime session
    cookie is gone but a remember-me cookie is present, the session is
    repopulated from it (phx.gen.auth's ensure_user_token behavior).
    """
    token = request.session.get(SESSION_TOKEN_KEY)
    if token:
        account = get_account_by_session_token(token, session)
        if account:
            return account

    remember_token = request.cookies.get(REMEMBER_ME_COOKIE_NAME)
    if remember_token and remember_token != token:
        account = get_account_by_session_token(remember_token, session)
        if account:
            request.session[SESSION_TOKEN_KEY] = remember_token
            return account

    return None


def get_account_from_credentials(
    email: EmailStr = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
) -> tuple[Account, Session]:
    """
    Validates user credentials and returns the account if valid.

    Args:
        email: Email address from form
        password: Password from form
        session: Database session

    Returns:
        Tuple containing the account and session

    Raises:
        HTTPException: If credentials are invalid
    """
    account = session.exec(select(Account).where(Account.email == email)).first()

    if not account or not verify_password(password, account.hashed_password):
        raise CredentialsError()

    return account, session


def get_authenticated_account(
    request: Request,
    session: Session = Depends(get_session),
) -> Account:
    """
    Dependency that returns the authenticated account or raises an exception.

    Raises:
        AuthenticationError: If no valid session is found
    """
    account = get_account_from_session(request, session)
    if account:
        return account
    raise AuthenticationError()


def get_authenticated_user(
    request: Request,
    session: Session = Depends(get_session),
) -> User:
    account = get_account_from_session(request, session)
    if account and account.user:
        return account.user
    raise AuthenticationError()


def get_optional_user(
    request: Request,
    session: Session = Depends(get_session),
) -> User | None:
    account = get_account_from_session(request, session)
    if account and account.user:
        return account.user
    return None


def require_unauthenticated_client(
    user: User | None = Depends(get_optional_user),
) -> None:
    """
    Dependency that ensures the client is NOT authenticated.
    Raises AlreadyAuthenticatedError (caught by exception handler) if a user is found.
    """
    if user:
        raise AlreadyAuthenticatedError()


def require_unauthenticated_unless_invitation_warning(
    invitation_token: str | None = Query(None),
    user: User | None = Depends(get_optional_user),
    session: Session = Depends(get_session),
) -> None:
    """
    Allow authenticated users to view login/register when an invitation token
    warning must be shown (expired or invalid invite links).
    """
    warning = (
        get_invitation_token_warning(session, invitation_token)
        if invitation_token
        else None
    )
    if user and not warning:
        raise AlreadyAuthenticatedError()


def get_verified_account(
    email: EmailStr = Form(
        ..., title="Email", description="Account email address for verification"
    ),
    password: str = Form(
        ..., title="Password", description="Account password for verification"
    ),
    account: Account = Depends(get_authenticated_account),
) -> Account:
    """
    Dependency that returns an authenticated account after verifying credentials.
    Wraps get_authenticated_account with an additional email/password check.
    """
    if email != account.email:
        raise CredentialsError(message="Email does not match authenticated account")
    if not verify_password(password, account.hashed_password):
        raise PasswordValidationError(field="password", message="Password is incorrect")
    return account


def get_account_from_email_verification_token(
    token: str, session: Session
) -> tuple[Account | None, EmailVerificationToken | None]:
    """
    Get account from an email verification token.

    Returns:
        Tuple of (account, token) if valid, or (None, None) if invalid
    """
    result = session.exec(
        select(Account, EmailVerificationToken).where(
            EmailVerificationToken.token == token,
            EmailVerificationToken.expires_at > datetime.now(UTC),
            EmailVerificationToken.used == False,
            EmailVerificationToken.account_id == Account.id,
        )
    ).first()

    if not result:
        return None, None

    account, verification_token = result
    return account, verification_token


def get_account_from_recovery_token(
    token: str, session: Session
) -> tuple[Account | None, AccountRecoveryToken | None]:
    """
    Get account from an account recovery token.

    Returns:
        Tuple of (account, token) if valid, or (None, None) if invalid
    """
    result = session.exec(
        select(Account, AccountRecoveryToken).where(
            AccountRecoveryToken.token == token,
            AccountRecoveryToken.expires_at > datetime.now(UTC),
            AccountRecoveryToken.used == False,
            AccountRecoveryToken.account_id == Account.id,
        )
    ).first()

    if not result:
        return None, None

    account, recovery_token = result
    return account, recovery_token


def get_account_from_reset_token(
    email: str, token: str, session: Session
) -> tuple[Account | None, PasswordResetToken | None]:
    """
    Get account from a password reset token.

    Args:
        email: Email address of the account
        token: Password reset token
        session: Database session

    Returns:
        Tuple of (account, token) if valid, or (None, None) if invalid
    """
    result = session.exec(
        select(Account, PasswordResetToken).where(
            Account.email == email,
            PasswordResetToken.token == token,
            PasswordResetToken.expires_at > datetime.now(UTC),
            PasswordResetToken.used == False,
            PasswordResetToken.account_id == Account.id,
        )
    ).first()

    if not result:
        return None, None

    account, reset_token = result
    return account, reset_token


def get_user_with_relations(
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session),
) -> User:
    """
    Returns an authenticated user with fully loaded role and organization relationships.
    """
    # Refresh the user instance with eagerly loaded relationships
    eager_user = session.exec(
        select(User)
        .where(User.id == user.id)
        .options(
            selectinload(User.roles).selectinload(Role.organization),
            selectinload(User.roles).selectinload(Role.permissions),
        )
    ).one()

    return eager_user


async def get_user_from_request(request: Request) -> User | None:
    """
    Helper function to get the user in exception handlers.
    Exception handlers can't use Depends(), so we resolve the session manually.

    Cookie/session reads stay on the event loop; sync DB/session work runs in
    the thread pool. This is called directly (not via Depends()) from async
    exception handlers, so without offloading it would block the loop while
    querying.
    """
    token = request.session.get(SESSION_TOKEN_KEY)
    remember_token = request.cookies.get(REMEMBER_ME_COOKIE_NAME)
    return await run_in_threadpool(_get_user_from_request_sync, token, remember_token)


def _get_user_from_request_sync(
    token: str | None,
    remember_token: str | None,
) -> User | None:
    with Session(get_engine()) as session:
        account = get_account_by_session_token(token, session) if token else None
        if account is None and remember_token and remember_token != token:
            account = get_account_by_session_token(remember_token, session)
        user = account.user if account else None

        if user:
            # Eagerly load avatar so it's available after the session closes
            _ = user.avatar

        return user
