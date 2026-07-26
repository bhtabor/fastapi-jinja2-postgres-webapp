# utils.core.py
import os
import re
import secrets
import uuid
import logging
import resend
from sqlmodel import Session, select, delete
from bcrypt import gensalt, hashpw, checkpw
from datetime import UTC, datetime, timedelta
from typing import Optional
from jinja2.environment import Template
from fastapi.templating import Jinja2Templates
from fastapi import Request
from starlette.responses import Response
from utils.core.db import create_engine, get_connection_url
from utils.core.models import (
    AccountRecoveryToken,
    AccountToken,
    EmailVerificationToken,
    PasswordResetToken,
    Account,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())


# --- Constants ---


templates = Jinja2Templates(directory="templates")
COOKIE_SECURE = os.getenv("BASE_URL", "http://localhost:8000").startswith("https")

# Session authentication (modeled on phx.gen.auth): the signed session
# cookie carries an opaque token whose authority is an AccountToken row.
SESSION_TOKEN_KEY = "account_token"
SESSION_TOKEN_CONTEXT = "session"
SESSION_VALIDITY_DAYS = 14
REMEMBER_ME_COOKIE_NAME = "remember_me"
REMEMBER_ME_MAX_AGE = SESSION_VALIDITY_DAYS * 24 * 60 * 60
PASSWORD_PATTERN_COMPONENTS = [
    r"(?=.*\d)",  # At least one digit
    r"(?=.*[a-z])",  # At least one lowercase letter
    r"(?=.*[A-Z])",  # At least one uppercase letter
    r"(?=.*[\[\]\\@$!%*?&{}<>.,'#\-_=+\(\):;|~/\^])",  # At least one special character
    r".{8,}",  # At least 8 characters long
]
COMPILED_PASSWORD_PATTERN = re.compile(r"".join(PASSWORD_PATTERN_COMPONENTS))


def convert_python_regex_to_html(regex: str) -> str:
    """
    Replace each special character with its escaped version only when inside character classes.
    Ensures that the single quote "'" is doubly escaped.
    """
    # Map each special char to its escaped form
    special_map = {
        "{": r"\{",
        "}": r"\}",
        "<": r"\<",
        ">": r"\>",
        ".": r"\.",
        "+": r"\+",
        "|": r"\|",
        ",": r"\,",
        "'": r"\\'",  # doubly escaped single quote
        "/": r"\/",
    }

    # Regex to match the entire character class [ ... ]
    pattern = r"\[((?:\\.|[^\]])*)\]"

    def replacer(match: re.Match) -> str:
        """
        For the matched character class, replace all special characters inside it.
        """
        inside = match.group(1)  # the contents inside [ ... ]
        for ch, escaped in special_map.items():
            inside = inside.replace(ch, escaped)
        return f"[{inside}]"

    # Use re.sub with a function to ensure we only replace inside the character class
    return re.sub(pattern, replacer, regex)


HTML_PASSWORD_PATTERN = "".join(
    convert_python_regex_to_html(component) for component in PASSWORD_PATTERN_COMPONENTS
)


# --- Helpers ---


def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt with a random salt
    """
    # Convert the password to bytes and generate the hash
    password_bytes = password.encode("utf-8")
    salt = gensalt()
    return hashpw(password_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against a bcrypt hash
    """
    password_bytes = plain_password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    return checkpw(password_bytes, hashed_bytes)


# --- Session authentication ---


def generate_session_token(account_id: int, session: Session) -> str:
    """Create a session AccountToken row and return the raw token.

    Session tokens are stored raw (they are random and their exposure is
    bounded by the validity window); email-delivered token kinds should be
    stored hashed instead. Does NOT commit — caller is responsible.
    """
    token = secrets.token_urlsafe(32)
    session.add(
        AccountToken(
            account_id=account_id, token=token, context=SESSION_TOKEN_CONTEXT
        )
    )
    return token


def get_account_by_session_token(token: str, session: Session) -> Optional[Account]:
    """Return the account a valid, unexpired session token belongs to."""
    cutoff = datetime.now(UTC) - timedelta(days=SESSION_VALIDITY_DAYS)
    result = session.exec(
        select(Account, AccountToken).where(
            AccountToken.token == token,
            AccountToken.context == SESSION_TOKEN_CONTEXT,
            AccountToken.inserted_at > cutoff,
            AccountToken.account_id == Account.id,
        )
    ).first()
    return result[0] if result else None


def delete_session_token(token: str, session: Session) -> None:
    session.exec(
        delete(AccountToken).where(
            AccountToken.token == token,  # ty: ignore[invalid-argument-type]
            AccountToken.context == SESSION_TOKEN_CONTEXT,
        )
    )


def revoke_all_session_tokens(account_id: int, session: Session) -> None:
    """Delete every session token for the account (logs out all devices)."""
    session.exec(
        delete(AccountToken).where(
            AccountToken.account_id == account_id,  # ty: ignore[invalid-argument-type]
            AccountToken.context == SESSION_TOKEN_CONTEXT,
        )
    )


def log_in_session(
    request: Request,
    response: Response,
    account_id: int,
    session: Session,
    *,
    remember: bool = False,
) -> str:
    """Log the account in: fresh token row, renewed cookie session.

    The session dict is cleared before storing the new token to prevent
    session fixation. With ``remember``, the token is also written to a
    long-lived remember-me cookie that the auth dependency falls back to
    when the (browser-lifetime) session cookie is gone.
    """
    token = generate_session_token(account_id, session)
    request.session.clear()
    request.session[SESSION_TOKEN_KEY] = token
    if remember:
        response.set_cookie(
            key=REMEMBER_ME_COOKIE_NAME,
            value=token,
            httponly=True,
            secure=COOKIE_SECURE,
            samesite="lax",
            max_age=REMEMBER_ME_MAX_AGE,
        )
    return token


def log_out_session(request: Request, response: Response, session: Session) -> None:
    """Log out: delete the token row, clear the session, drop remember-me."""
    token = request.session.get(SESSION_TOKEN_KEY) or request.cookies.get(
        REMEMBER_ME_COOKIE_NAME
    )
    if token:
        delete_session_token(token, session)
        session.commit()
    request.session.clear()
    response.delete_cookie(REMEMBER_ME_COOKIE_NAME)


def cleanup_expired_session_tokens(session: Session) -> int:
    """Delete expired session token rows; returns the number removed."""
    cutoff = datetime.now(UTC) - timedelta(days=SESSION_VALIDITY_DAYS)
    expired = session.exec(
        select(AccountToken).where(
            AccountToken.context == SESSION_TOKEN_CONTEXT,
            AccountToken.inserted_at <= cutoff,
        )
    ).all()
    count = len(expired)
    for token in expired:
        session.delete(token)
    session.commit()
    return count


def generate_password_reset_url(email: str, token: str) -> str:
    """
    Generates the password reset URL with proper query parameters.

    Args:
        email: User's email address
        token: Password reset token

    Returns:
        Complete password reset URL
    """
    base_url = os.getenv("BASE_URL")
    return f"{base_url}/account/reset_password?email={email}&token={token}"


def send_reset_email(email: str, session: Session) -> None:
    # Check for an existing unexpired token
    account: Optional[Account] = session.exec(
        select(Account).where(Account.email == email)
    ).first()

    if account:
        existing_token = session.exec(
            select(PasswordResetToken).where(
                PasswordResetToken.account_id == account.id,
                PasswordResetToken.expires_at > datetime.now(UTC),
                PasswordResetToken.used == False,  # noqa: E712 - SQL expression for boolean false
            )
        ).first()

        if existing_token:
            logger.debug("An unexpired token already exists for this account.")
            return

        # Generate a new token
        token: str = str(uuid.uuid4())
        reset_token: PasswordResetToken = PasswordResetToken(
            account_id=account.id, token=token
        )
        session.add(reset_token)

        try:
            reset_url: str = generate_password_reset_url(email, token)

            # Render the email template
            template: Template = templates.get_template("emails/reset_email.html")
            html_content: str = template.render({"reset_url": reset_url})

            resend.api_key = os.getenv("RESEND_API_KEY")
            params = {
                "from": os.getenv("EMAIL_FROM", ""),
                "to": [email],
                "subject": "Password Reset Request",
                "html": html_content,
            }

            sent_email = resend.Emails.send(params)  # ty: ignore[invalid-argument-type]
            logger.debug(f"Password reset email sent: {sent_email.get('id')}")

            session.commit()
        except Exception as e:
            logger.error(f"Failed to send password reset email: {e}")
            session.rollback()
    else:
        logger.debug("No account found with the provided email.")


def send_reset_email_task(email: str) -> None:
    """
    Background-task wrapper that creates its own session.

    FastAPI background tasks should not reuse request-scoped resources from
    `yield` dependencies, because cleanup may run before the task executes.
    """
    engine = create_engine(get_connection_url())
    with Session(engine) as session:
        send_reset_email(email, session)


# --- Multi-email functions ---


MAX_EMAILS_PER_ACCOUNT = 2


def generate_email_verification_url(token: str) -> str:
    """Generates the email verification URL."""
    base_url = os.getenv("BASE_URL")
    return f"{base_url}/account/emails/verify?token={token}"


def send_email_verification(account_id: int, new_email: str, session: Session) -> bool:
    """
    Send a verification email for adding a new email address.
    Returns True if email was sent, False if suppressed (existing unexpired token).
    """
    # Check for existing unexpired token for this account+email
    existing_token = session.exec(
        select(EmailVerificationToken).where(
            EmailVerificationToken.account_id == account_id,
            EmailVerificationToken.new_email == new_email,
            EmailVerificationToken.expires_at > datetime.now(UTC),
            EmailVerificationToken.used == False,  # noqa: E712
        )
    ).first()

    if existing_token:
        logger.debug("An unexpired verification token already exists for this email.")
        return False

    # Create new token
    token = EmailVerificationToken(
        account_id=account_id,
        new_email=new_email,
    )
    session.add(token)

    try:
        verification_url = generate_email_verification_url(token.token)

        template: Template = templates.get_template("emails/verify_new_email.html")
        html_content: str = template.render({"verification_url": verification_url})

        resend.api_key = os.getenv("RESEND_API_KEY")
        params = {
            "from": os.getenv("EMAIL_FROM", ""),
            "to": [new_email],
            "subject": "Verify Your Email Address",
            "html": html_content,
        }

        sent_email = resend.Emails.send(params)  # ty: ignore[invalid-argument-type]
        logger.debug(f"Email verification sent: {sent_email.get('id')}")

        session.commit()
        return True
    except Exception as e:
        logger.error(f"Failed to send email verification: {e}")
        session.rollback()
        return False


def send_email_verified_notification(primary_email: str, new_email: str) -> None:
    """Send a notification to the primary email that a new email was verified."""
    try:
        template: Template = templates.get_template("emails/email_verified_alert.html")
        html_content: str = template.render({"new_email": new_email})

        resend.api_key = os.getenv("RESEND_API_KEY")
        params = {
            "from": os.getenv("EMAIL_FROM", ""),
            "to": [primary_email],
            "subject": "New Email Address Added to Your Account",
            "html": html_content,
        }

        sent_email = resend.Emails.send(params)  # ty: ignore[invalid-argument-type]
        logger.debug(f"Email verified notification sent: {sent_email.get('id')}")
    except Exception as e:
        logger.error(f"Failed to send email verified notification: {e}")


def send_primary_email_changed_notification(
    old_email: str, new_email: str, recovery_url: str
) -> None:
    """Send a notification to the old primary email that primary was changed."""
    try:
        template: Template = templates.get_template("emails/primary_email_changed.html")
        html_content: str = template.render(
            {
                "old_email": old_email,
                "new_email": new_email,
                "recovery_url": recovery_url,
            }
        )

        resend.api_key = os.getenv("RESEND_API_KEY")
        params = {
            "from": os.getenv("EMAIL_FROM", ""),
            "to": [old_email],
            "subject": "Your Primary Email Has Been Changed",
            "html": html_content,
        }

        sent_email = resend.Emails.send(params)  # ty: ignore[invalid-argument-type]
        logger.debug(f"Primary email changed notification sent: {sent_email.get('id')}")
    except Exception as e:
        logger.error(f"Failed to send primary email changed notification: {e}")


def send_email_removed_notification(removed_email: str, recovery_url: str) -> None:
    """Send a notification to the removed email address."""
    try:
        template: Template = templates.get_template("emails/email_removed_alert.html")
        html_content: str = template.render(
            {
                "removed_email": removed_email,
                "recovery_url": recovery_url,
            }
        )

        resend.api_key = os.getenv("RESEND_API_KEY")
        params = {
            "from": os.getenv("EMAIL_FROM", ""),
            "to": [removed_email],
            "subject": "Email Address Removed from Your Account",
            "html": html_content,
        }

        sent_email = resend.Emails.send(params)  # ty: ignore[invalid-argument-type]
        logger.debug(f"Email removed notification sent: {sent_email.get('id')}")
    except Exception as e:
        logger.error(f"Failed to send email removed notification: {e}")


# --- Account recovery functions ---


def generate_recovery_url(token: str) -> str:
    """Generates the account recovery URL."""
    base_url = os.getenv("BASE_URL")
    return f"{base_url}/account/recover?token={token}"


def create_recovery_token(account_id: int, email: str, session: Session) -> str:
    """
    Create an account recovery token for the given email.
    Returns the token string. Does NOT commit — caller is responsible.
    If an unexpired token already exists for the same account+email, returns it.
    """
    existing = session.exec(
        select(AccountRecoveryToken).where(
            AccountRecoveryToken.account_id == account_id,
            AccountRecoveryToken.email == email,
            AccountRecoveryToken.expires_at > datetime.now(UTC),
            AccountRecoveryToken.used == False,  # noqa: E712
        )
    ).first()

    if existing:
        return existing.token

    token = AccountRecoveryToken(
        account_id=account_id,
        email=email,
    )
    session.add(token)
    return token.token
