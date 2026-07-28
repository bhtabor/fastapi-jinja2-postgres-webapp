# auth.py
import os
from logging import getLogger
from typing import Optional, Tuple
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, BackgroundTasks, Form, Request, Query
from fastapi.responses import RedirectResponse, Response
from fastapi_turbo import TurboStreamResponse, accepts_turbo_stream, streams
from fastapi_turbo.templates import TurboTemplates
from starlette.datastructures import URLPath
from pydantic import EmailStr
from sqlmodel import Session, col, select
from utils.core.models import (
    User,
    DataIntegrityError,
    Account,
    AccountEmail,
    Invitation,
    Organization,
    Role,
    UserRoleLink,
)
from utils.core.dependencies import get_session
from utils.core.auth import (
    HTML_PASSWORD_PATTERN,
    COMPILED_PASSWORD_PATTERN,
    MAX_EMAILS_PER_ACCOUNT,
    get_password_hash,
    log_in_session,
    log_out_session,
    revoke_all_session_tokens,
    send_reset_email_task,
    send_email_verification,
    send_email_verified_notification,
    send_primary_email_changed_notification,
    send_email_removed_notification,
    create_recovery_token,
    generate_recovery_url,
)
from utils.core.dependencies import (
    get_authenticated_account,
    get_optional_user,
    get_account_from_reset_token,
    get_account_from_email_verification_token,
    get_account_from_recovery_token,
    get_account_from_credentials,
    require_unauthenticated_client,
    require_unauthenticated_unless_invitation_warning,
    get_verified_account,
)
from exceptions.http_exceptions import (
    EmailAlreadyRegisteredError,
    CannotRemovePrimaryEmailError,
    CredentialsError,
    EmailNotVerifiedError,
    MaxEmailsReachedError,
    PasswordValidationError,
    InvitationEmailMismatchError,
    InvitationProcessingError,
)
from routers.core.dashboard import router as dashboard_router
from routers.core.user import router as user_router
from routers.core.organization import router as org_router
from utils.core.invitations import (
    process_invitation,
    require_active_invitation_by_token,
    get_invitation_token_warning,
)
from utils.core.rate_limit import (
    check_login_ip_rate_limit,
    check_login_email_rate_limit,
    check_register_ip_rate_limit,
    check_forgot_password_ip_rate_limit,
    check_forgot_password_email_rate_limit,
    login_email_limiter,
)
from utils.core.toast import toast_stream
from utils.core.flash import set_flash
from utils.core.communication_preferences import (
    parse_communication_preferences,
    apply_communication_preferences,
)

logger = getLogger("uvicorn.error")

router = APIRouter(prefix="/account", tags=["account"])
templates = TurboTemplates(directory="templates")


# --- Route-specific dependencies ---


def _delete_organizations_where_user_is_only_member(
    session: Session, user: User
) -> None:
    """Delete organizations that would have no remaining users after user deletion."""
    if user.id is None:
        return

    organization_ids = session.exec(
        select(Role.organization_id)
        .join(UserRoleLink, col(UserRoleLink.role_id) == col(Role.id))
        .where(UserRoleLink.user_id == user.id)
        .distinct()
    ).all()

    for organization_id in organization_ids:
        user_ids = {
            user_id
            for user_id in session.exec(
                select(UserRoleLink.user_id)
                .join(Role, col(Role.id) == col(UserRoleLink.role_id))
                .where(Role.organization_id == organization_id)
                .distinct()
            ).all()
            if user_id is not None
        }
        if user_ids == {user.id}:
            organization = session.get(Organization, organization_id)
            if organization is not None:
                session.delete(organization)


def validate_password_strength_and_match(
    password: str = Form(..., title="Password", description="Account password"),
    confirm_password: str = Form(
        ..., title="Confirm password", description="Re-enter password to confirm"
    ),
) -> str:
    """
    Validates password strength and confirms passwords match.

    Args:
        password: Password from form
        confirm_password: Confirmation password from form

    Raises:
        PasswordValidationError: If password is weak or passwords don't match

    Returns:
        str: The validated password
    """
    # Validate password strength
    if not COMPILED_PASSWORD_PATTERN.match(password):
        raise PasswordValidationError(
            field="password",
            message="Password must contain at least 8 characters, including one uppercase letter, one lowercase letter, one number, and one special character",
        )

    # Validate passwords match
    if password != confirm_password:
        raise PasswordValidationError(
            field="confirm_password", message="The passwords you entered do not match"
        )

    return password


# --- Routes ---


@router.get("/logout", response_class=RedirectResponse)
def logout(
    request: Request,
    session: Session = Depends(get_session),
):
    """
    Log out a user by deleting their session token and clearing the session.
    """
    response = RedirectResponse(url="/", status_code=303)
    log_out_session(request, response, session)
    return response


@router.get("/login")
async def read_login(
    request: Request,
    _: None = Depends(require_unauthenticated_unless_invitation_warning),
    invitation_token: Optional[str] = Query(None),
    user: Optional[User] = Depends(get_optional_user),
    session: Session = Depends(get_session),
):
    """
    Render login page or redirect to dashboard if already logged in.
    """
    invitation_token_warning = (
        get_invitation_token_warning(session, invitation_token)
        if invitation_token
        else None
    )
    return templates.TemplateResponse(
        request,
        "account/login.html",
        {
            "user": user,
            "invitation_token": invitation_token,
            "invitation_token_warning": invitation_token_warning,
        },
    )


@router.get("/register")
async def read_register(
    request: Request,
    _: None = Depends(require_unauthenticated_unless_invitation_warning),
    email: Optional[EmailStr] = Query(None),
    invitation_token: Optional[str] = Query(None),
    user: Optional[User] = Depends(get_optional_user),
    session: Session = Depends(get_session),
):
    """
    Render registration page or redirect to dashboard if already logged in.
    """
    invitation_token_warning = (
        get_invitation_token_warning(session, invitation_token)
        if invitation_token
        else None
    )
    return templates.TemplateResponse(
        request,
        "account/register.html",
        {
            "user": user,
            "password_pattern": HTML_PASSWORD_PATTERN,
            "email": email,
            "invitation_token": invitation_token,
            "host_name": os.getenv("HOST_NAME", "our platform"),
            "invitation_token_warning": invitation_token_warning,
        },
    )


@router.get("/forgot_password")
async def read_forgot_password(
    request: Request,
    _: None = Depends(require_unauthenticated_client),
    show_form: Optional[str] = "true",
):
    """
    Render forgot password page or redirect to dashboard if already logged in.
    """
    return templates.TemplateResponse(
        request,
        "account/forgot_password.html",
        {"user": None, "show_form": show_form == "true"},
    )


@router.get("/reset_password")
async def read_reset_password(
    request: Request,
    email: str,
    token: str,
    user: Optional[User] = Depends(get_optional_user),
    session: Session = Depends(get_session),
):
    """
    Render reset password page after validating token.
    """
    authorized_account, _ = get_account_from_reset_token(email, token, session)

    # Raise informative error to let user know the token is invalid and may have expired
    if not authorized_account:
        raise CredentialsError(message="Invalid or expired token")

    return templates.TemplateResponse(
        request,
        "account/reset_password.html",
        {
            "user": user,
            "email": email,
            "token": token,
            "password_pattern": HTML_PASSWORD_PATTERN,
        },
    )


@router.post("/delete", response_class=RedirectResponse)
async def delete_account(
    account: Account = Depends(get_verified_account),
    session: Session = Depends(get_session),
):
    """
    Delete a user account after verifying credentials.
    """
    user = account.user
    if user is None:
        session.refresh(account, attribute_names=["user"])
        user = account.user

    if user is not None:
        _delete_organizations_where_user_is_only_member(session, user)

    session.delete(account)
    session.commit()

    # Log out the user
    return RedirectResponse(url=router.url_path_for("logout"), status_code=303)


@router.post("/register", response_class=RedirectResponse)
async def register(
    request: Request,
    _ip_check: None = Depends(check_register_ip_rate_limit),
    name: str = Form(
        ...,
        min_length=1,
        strip_whitespace=True,
        title="Name",
        description="Your full name",
    ),
    email: EmailStr = Form(
        ..., title="Email", description="Email address for the new account"
    ),
    session: Session = Depends(get_session),
    _: None = Depends(validate_password_strength_and_match),
    password: str = Form(..., title="Password", description="Account password"),
    invitation_token: Optional[str] = Form(
        None,
        title="Invitation token",
        description="Optional invitation token to join an organization",
    ),
    comm_opt_in: Optional[str] = Form(None),
    comm_updates: Optional[str] = Form(None),
    comm_marketing: Optional[str] = Form(None),
) -> Response:
    """
    Register a new user account, optionally processing an invitation.
    """
    pending_invitation: Optional[Invitation] = None
    if invitation_token:
        pending_invitation = require_active_invitation_by_token(
            session, invitation_token
        )
        if email != pending_invitation.invitee_email:
            logger.warning(
                f"Invitation email mismatch for token {invitation_token} during registration. "
                f"Account: {email}, Invitation: {pending_invitation.invitee_email}"
            )
            raise InvitationEmailMismatchError()

    # Check if the email is already registered
    existing_account: Optional[Account] = session.exec(
        select(Account).where(Account.email == email)
    ).one_or_none()

    if existing_account:
        raise EmailAlreadyRegisteredError()

    # Hash the password
    hashed_password = get_password_hash(password)

    # Create the account and user instances (don't commit yet)
    account = Account(email=email, hashed_password=hashed_password)
    session.add(account)
    session.flush()  # Flush here to get account.id before creating User

    # Ensure account has an ID after flush
    if not account.id:
        logger.error(
            f"Account ID not generated after flush for email {email}. Aborting registration."
        )
        session.rollback()  # Rollback the account add
        raise DataIntegrityError(resource="Account ID generation")

    new_user = User(name=name, account_id=account.id)  # Use account.id
    apply_communication_preferences(
        new_user,
        parse_communication_preferences(comm_opt_in, comm_updates, comm_marketing),
    )
    session.add(new_user)

    # Create the primary AccountEmail entry
    from datetime import datetime, UTC

    account_email = AccountEmail(
        account_id=account.id,
        email=email,
        is_primary=True,
        verified=True,
        verified_at=datetime.now(UTC),
    )
    session.add(account_email)

    # Default redirect target
    redirect_url = dashboard_router.url_path_for("read_dashboard")

    # Process invitation if token is provided (BEFORE final commit)
    if pending_invitation:
        logger.info(
            f"Registration attempt with invitation token: {invitation_token} for email {email}"
        )

        # Process the invitation (adds changes to the session)
        try:
            logger.info(
                f"Processing invitation {pending_invitation.id} for new user {new_user.name} ({email}) during registration."
            )
            process_invitation(pending_invitation, new_user, session)
            # Set redirect to the organization page
            redirect_url = org_router.url_path_for(
                "read_organization", org_id=pending_invitation.organization_id
            )
            logger.info(
                f"Redirecting new user {new_user.name} to organization {pending_invitation.organization_id} after accepting invitation {pending_invitation.id}."
            )
        except Exception as e:
            logger.error(
                f"Error processing invitation {pending_invitation.id} for new user {new_user.name} ({email}) during registration: {e}",
                exc_info=True,
            )
            session.rollback()
            raise InvitationProcessingError()

    else:
        logger.info(
            f"Standard registration for email {email}. Redirecting to dashboard."
        )

    # Commit all changes (Account, User, potentially Invitation)
    try:
        session.commit()
    except Exception as e:
        logger.error(
            f"Error committing transaction during registration for {email}: {e}",
            exc_info=True,
        )
        session.rollback()
        # Use DataIntegrityError for commit failure
        raise DataIntegrityError(resource="Account/User registration")

    # Refresh the account to ensure all relationships (like user) are loaded after commit
    session.refresh(account)
    # We might need the user object refreshed too if process_invitation modified it directly
    # session.refresh(new_user) # Let's assume process_invitation only modifies the invitation object for now

    # Log the new account in with a fresh session
    response = RedirectResponse(url=str(redirect_url), status_code=303)
    assert account.id is not None
    log_in_session(request, response, account.id, session)
    session.commit()

    return response


@router.post("/login", response_class=RedirectResponse)
async def login(
    request: Request,
    _ip_check: None = Depends(check_login_ip_rate_limit),
    _email_check: EmailStr = Depends(check_login_email_rate_limit),
    account_and_session: Tuple[Account, Session] = Depends(
        get_account_from_credentials
    ),
    remember: Optional[str] = Form(None),
    invitation_token: Optional[str] = Form(
        None,
        title="Invitation token",
        description="Optional invitation token to join an organization after login",
    ),
) -> Response:
    """
    Log in a user with valid credentials and process invitation if token is provided.
    """
    account, session = account_and_session

    # Successful login: reset the per-email rate limiter so legitimate users
    # are not penalised for earlier mistyped attempts.
    login_email_limiter.reset(f"email:{account.email.lower().strip()}")

    # Default redirect target
    redirect_url = dashboard_router.url_path_for("read_dashboard")

    if invitation_token:
        logger.info(
            f"Login attempt with invitation token: {invitation_token} for account {account.email}"
        )
        invitation = require_active_invitation_by_token(session, invitation_token)

        # Verify email matches (check primary and any verified secondary emails)
        account_emails = session.exec(
            select(AccountEmail.email).where(
                AccountEmail.account_id == account.id,
                AccountEmail.verified == True,  # noqa: E712
            )
        ).all()
        if invitation.invitee_email not in account_emails:
            logger.warning(
                f"Invitation email mismatch for token {invitation_token}. "
                f"Account: {account.email}, Invitation: {invitation.invitee_email}"
            )
            raise InvitationEmailMismatchError()

        # Ensure user relationship is loaded for process_invitation
        if not account.user:
            logger.debug(f"Refreshing user relationship for account {account.id}")
            session.refresh(account, attribute_names=["user"])
            if not account.user:
                # This should not happen if the account has a valid user relationship
                logger.error(
                    f"Failed to load user for account {account.id} during invitation processing."
                )
                raise DataIntegrityError(resource="User relation")

        # Process the invitation
        try:
            if account.user and account.user.id:
                logger.info(
                    f"Processing invitation {invitation.id} for user {account.user.id} during login."
                )
                process_invitation(invitation, account.user, session)
                session.commit()
                # Set redirect to the organization page
                redirect_url = org_router.url_path_for(
                    "read_organization", org_id=invitation.organization_id
                )
                logger.info(
                    f"Redirecting user {account.user.id} to organization {invitation.organization_id} after accepting invitation {invitation.id}."
                )
            else:
                logger.error("User has no ID during invitation processing.")
                raise DataIntegrityError(resource="User ID")
        except Exception as e:
            logger.error(
                f"Error processing invitation during login: {e}", exc_info=True
            )
            session.rollback()
            # Raise the specific invitation processing error
            raise InvitationProcessingError()

    else:
        logger.info(
            f"Standard login for account {account.email}. Redirecting to dashboard."
        )

    # Log in with a fresh session; remember-me extends it past browser close
    assert account.id is not None
    persistent = remember == "on"

    response = RedirectResponse(url=str(redirect_url), status_code=303)
    log_in_session(request, response, account.id, session, remember=persistent)
    session.commit()

    return response


@router.post("/forgot_password")
async def forgot_password(
    background_tasks: BackgroundTasks,
    request: Request,
    _ip_check: None = Depends(check_forgot_password_ip_rate_limit),
    email: EmailStr = Depends(check_forgot_password_email_rate_limit),
    session: Session = Depends(get_session),
):
    """
    Send a password reset email to the user.
    """
    # TODO: Make this a dependency?
    account = session.exec(select(Account).where(Account.email == email)).one_or_none()

    if account:
        background_tasks.add_task(send_reset_email_task, email)

    # Get the referer header, default to /forgot_password if not present
    referer = request.headers.get("referer", "/forgot_password")

    # Extract the path from the full URL
    redirect_path = urlparse(referer).path

    response = RedirectResponse(
        url=f"{redirect_path}?show_form=false", status_code=303
    )
    set_flash(
        request,
        "If an account exists with this email, a password reset link will be sent.",
    )
    return response


@router.post("/reset_password")
async def reset_password(
    request: Request,
    email: EmailStr = Form(..., title="Email", description="Account email address"),
    token: str = Form(
        ..., title="Reset token", description="Password reset token from email"
    ),
    new_password: str = Depends(validate_password_strength_and_match),
    session: Session = Depends(get_session),
):
    """
    Reset a user's password using a valid token.
    """

    # Get account from reset token
    authorized_account, reset_token = get_account_from_reset_token(
        email, token, session
    )

    if not authorized_account or not reset_token:
        raise CredentialsError(
            "Invalid or expired password reset token; please request a new one"
        )

    assert authorized_account.id is not None
    # Update password and consume the single-use token
    authorized_account.hashed_password = get_password_hash(new_password)

    session.delete(reset_token)
    session.commit()
    session.refresh(authorized_account)

    # Log out every device (the password just changed), then auto-login this
    # one so the user doesn't have to re-enter credentials.
    revoke_all_session_tokens(authorized_account.id, session)

    redirect_url = str(dashboard_router.url_path_for("read_dashboard"))
    message = "Password reset successfully."

    response = RedirectResponse(url=redirect_url, status_code=303)

    log_in_session(request, response, authorized_account.id, session)
    session.commit()
    set_flash(request, message)
    return response


@router.get("/recover")
async def recover_account_confirm(
    request: Request,
    token: str = Query(...),
    session: Session = Depends(get_session),
):
    """Show a confirmation form before performing account recovery."""
    account, recovery_token = get_account_from_recovery_token(token, session)

    if not account or not recovery_token:
        raise CredentialsError(message="Invalid or expired recovery token")

    return templates.TemplateResponse(
        request,
        "account/recover_confirm.html",
        {"token": token, "user": None},
    )


@router.post("/recover")
async def recover_account(
    request: Request,
    token: str = Form(...),
    session: Session = Depends(get_session),
):
    """
    Recover an account using a recovery token sent via email.
    Restores the victim's email as primary, revokes all sessions,
    and redirects to password reset.
    """
    account, recovery_token = get_account_from_recovery_token(token, session)

    if not account or not recovery_token:
        raise CredentialsError(message="Invalid or expired recovery token")

    assert account.id is not None
    assert recovery_token.sent_to is not None
    recovered_email = recovery_token.sent_to
    # Consume the single-use token
    session.delete(recovery_token)

    # Delete ALL existing AccountEmail rows (purge attacker's emails)
    # Flush deletes before inserting the restored email to avoid unique constraint
    # violations — SQLAlchemy's autoflush processes INSERTs before DELETEs.
    existing_emails = session.exec(
        select(AccountEmail).where(AccountEmail.account_id == account.id)
    ).all()
    for email_row in existing_emails:
        session.delete(email_row)
    session.flush()

    # Restore the victim's email as primary
    from datetime import datetime as dt, UTC as utc_tz

    restored_email = AccountEmail(
        account_id=account.id,
        email=recovered_email,
        is_primary=True,
        verified=True,
        verified_at=dt.now(utc_tz),
    )
    session.add(restored_email)

    # Update Account.email
    account.email = recovered_email

    # Log out every device
    revoke_all_session_tokens(account.id, session)

    # Create a password reset token (raw value goes into the redirect URL)
    from utils.core.auth import RESET_PASSWORD_CONTEXT, build_email_token

    raw_reset_token = build_email_token(
        account.id, RESET_PASSWORD_CONTEXT, recovered_email, session
    )

    session.commit()

    # Redirect to password reset page
    from utils.core.auth import generate_password_reset_url

    reset_url = generate_password_reset_url(recovered_email, raw_reset_token)
    response = RedirectResponse(url=reset_url, status_code=303)
    set_flash(request, "Account recovered. Please set a new password.")
    return response


# --- Multi-email management routes ---


def _email_addresses_stream(request: Request, session: Session, account: Account):
    """A <turbo-stream> replacing the Email Addresses card body with fresh state."""
    account_emails = session.exec(
        select(AccountEmail)
        .where(AccountEmail.account_id == account.id)
        .order_by(col(AccountEmail.is_primary).desc())
    ).all()
    html = templates.render_string(
        request,
        "users/partials/email_addresses.html",
        account_emails=account_emails,
        max_emails=MAX_EMAILS_PER_ACCOUNT,
    )
    return streams.replace(html, target="email-addresses")


@router.post("/emails/add")
async def add_email(
    request: Request,
    new_email: EmailStr = Form(
        ..., title="New email", description="New email address to add"
    ),
    account: Account = Depends(get_authenticated_account),
    session: Session = Depends(get_session),
):
    """
    Request to add a new email address to the account.
    Sends a verification link to the new email address.
    """
    # Check email not already registered on any account
    existing = session.exec(
        select(AccountEmail).where(AccountEmail.email == new_email)
    ).first()
    if existing:
        raise EmailAlreadyRegisteredError()

    # Check account hasn't reached the limit
    email_count = len(
        session.exec(
            select(AccountEmail).where(AccountEmail.account_id == account.id)
        ).all()
    )
    if email_count >= MAX_EMAILS_PER_ACCOUNT:
        raise MaxEmailsReachedError()

    assert account.id is not None
    # Send verification email (suppresses if unexpired token exists)
    sent = send_email_verification(account.id, new_email, session)

    message = (
        "Verification email sent. Check your inbox."
        if sent
        else "A verification email was already sent. Please check your inbox."
    )

    if accepts_turbo_stream(request):
        # Replace the card body (fresh, empty add form) and append a toast.
        return TurboStreamResponse(
            _email_addresses_stream(request, session, account)
            + toast_stream(templates, request, message)
        )
    profile_path: URLPath = user_router.url_path_for("read_profile")
    response = RedirectResponse(url=str(profile_path), status_code=303)
    set_flash(request, message)
    return response


@router.get("/emails/verify")
async def verify_email(
    request: Request,
    token: str,
    session: Session = Depends(get_session),
):
    """
    Verify a new email address using the token from the verification link.

    Always redirects to the login page because verification links are clicked
    from an email client (cross-site navigation), so samesite=strict auth
    cookies are never sent — even when the user has an active session.
    """
    account, verification_token = get_account_from_email_verification_token(
        token, session
    )

    if not account or not verification_token:
        raise CredentialsError(message="Invalid or expired verification token")

    assert account.id is not None

    # Race condition guard: check email not already taken
    assert verification_token.sent_to is not None
    verified_email = verification_token.sent_to
    existing = session.exec(
        select(AccountEmail).where(AccountEmail.email == verified_email)
    ).first()
    if existing:
        raise EmailAlreadyRegisteredError()

    # Create the AccountEmail row
    from datetime import datetime as dt, UTC as utc_tz

    account_email = AccountEmail(
        account_id=account.id,
        email=verified_email,
        is_primary=False,
        verified=True,
        verified_at=dt.now(utc_tz),
    )
    session.add(account_email)

    # Consume the single-use token
    session.delete(verification_token)
    session.commit()

    # Send notification to primary email
    send_email_verified_notification(account.email, verified_email)

    login_path: URLPath = router.url_path_for("read_login")
    response = RedirectResponse(url=str(login_path), status_code=303)
    set_flash(request, "Email address verified and added to your account.")
    return response


@router.post("/emails/promote")
async def promote_email(
    request: Request,
    email_id: int = Form(
        ..., title="Email ID", description="ID of the email to promote"
    ),
    account: Account = Depends(get_authenticated_account),
    session: Session = Depends(get_session),
):
    """
    Promote a secondary email address to primary.
    """
    assert account.id is not None
    # Look up the AccountEmail
    target_email = session.exec(
        select(AccountEmail).where(
            AccountEmail.id == email_id,
            AccountEmail.account_id == account.id,
        )
    ).first()

    if not target_email:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Email address not found")

    # If already primary, no-op
    if target_email.is_primary:
        profile_path: URLPath = user_router.url_path_for("read_profile")
        response = RedirectResponse(url=str(profile_path), status_code=303)
        return response

    # Must be verified
    if not target_email.verified:
        raise EmailNotVerifiedError()

    # Find the current primary
    current_primary = session.exec(
        select(AccountEmail).where(
            AccountEmail.account_id == account.id,
            AccountEmail.is_primary == True,  # noqa: E712
        )
    ).first()

    old_primary_email = account.email

    # Swap primary flags
    if current_primary:
        current_primary.is_primary = False
    target_email.is_primary = True

    # Update Account.email
    account.email = target_email.email

    # Log out every device; the current one gets a fresh session below
    revoke_all_session_tokens(account.id, session)
    session.commit()

    # Create recovery token and send notification to the old primary
    recovery_token_str = create_recovery_token(account.id, old_primary_email, session)
    session.commit()
    recovery_url = generate_recovery_url(recovery_token_str)
    send_primary_email_changed_notification(
        old_primary_email, target_email.email, recovery_url
    )

    profile_path = user_router.url_path_for("read_profile")
    response = RedirectResponse(url=str(profile_path), status_code=303)
    log_in_session(request, response, account.id, session)
    session.commit()
    set_flash(request, "Primary email address updated.")
    return response


@router.post("/emails/remove")
async def remove_email(
    request: Request,
    email_id: int = Form(
        ..., title="Email ID", description="ID of the email to remove"
    ),
    account: Account = Depends(get_authenticated_account),
    session: Session = Depends(get_session),
):
    """
    Remove a non-primary email address from the account.
    """
    assert account.id is not None
    target_email = session.exec(
        select(AccountEmail).where(
            AccountEmail.id == email_id,
            AccountEmail.account_id == account.id,
        )
    ).first()

    if not target_email:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Email address not found")

    if target_email.is_primary:
        raise CannotRemovePrimaryEmailError()

    removed_address = target_email.email
    session.delete(target_email)
    session.commit()

    # Create recovery token and send notification to the removed address
    recovery_token_str = create_recovery_token(account.id, removed_address, session)
    session.commit()
    recovery_url = generate_recovery_url(recovery_token_str)
    send_email_removed_notification(removed_address, recovery_url)

    if accepts_turbo_stream(request):
        # Replace the card body (removed email disappears) and append a toast.
        return TurboStreamResponse(
            _email_addresses_stream(request, session, account)
            + toast_stream(templates, request, "Email address removed.")
        )
    profile_path: URLPath = user_router.url_path_for("read_profile")
    response = RedirectResponse(url=str(profile_path), status_code=303)
    set_flash(request, "Email address removed.")
    return response
