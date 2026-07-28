from fastapi import APIRouter, Depends, Form, UploadFile, File, Request, HTTPException
from fastapi.responses import RedirectResponse, Response
from sqlmodel import Session, select, col
from typing import Optional, List
from fastapi_turbo import (
    TurboContext,
    TurboStreamResponse,
    accepts_turbo_stream,
    streams,
    turbo_context,
)
from fastapi_turbo.templates import TurboTemplates
from sqlalchemy.orm import selectinload
import os
from utils.core.models import (
    User,
    UserAvatar,
    AccountEmail,
    DataIntegrityError,
    Organization,
)
from utils.core.organizations import members_stream_response
from utils.core.auth import MAX_EMAILS_PER_ACCOUNT
from utils.core.dependencies import (
    get_authenticated_user,
    get_user_with_relations,
    get_session,
)
from utils.core.images import (
    validate_and_process_image,
    read_upload_with_size_limit,
    reject_oversized_content_length,
    MAX_FILE_SIZE,
    MAX_AVATAR_UPLOAD_BYTES,
    MIN_DIMENSION,
    MAX_DIMENSION,
    ALLOWED_CONTENT_TYPES,
)
from utils.core.enums import ValidPermissions
from utils.app.enums import AppPermissions
from exceptions.http_exceptions import (
    InsufficientPermissionsError,
    UserNotFoundError,
    OrganizationNotFoundError,
)
from routers.core.organization import router as organization_router
from utils.core.toast import toast_stream, toast_stream_response
from utils.core.flash import set_flash
from utils.core.communication_preferences import (
    parse_communication_preferences,
    apply_communication_preferences,
)

router = APIRouter(prefix="/user", tags=["user"])
templates = TurboTemplates(directory="templates")


# --- Routes ---


@router.get("/profile")
async def read_profile(
    request: Request,
    user: User = Depends(get_user_with_relations),
    session: Session = Depends(get_session),
    show_form: Optional[str] = "true",
):
    # Load account emails
    account_emails = (
        session.exec(
            select(AccountEmail)
            .where(AccountEmail.account_id == user.account_id)
            .order_by(col(AccountEmail.is_primary).desc())
        ).all()
        if user.account_id
        else []
    )

    return templates.TemplateResponse(
        request,
        "users/profile.html",
        {
            "show_form": show_form == "true",
            "user": user,
            "account_emails": account_emails,
            "max_emails": MAX_EMAILS_PER_ACCOUNT,
            "host_name": os.getenv("HOST_NAME", "our platform"),
        },
    )


@router.get("/edit-form")
async def edit_profile_form(
    request: Request,
    user: User = Depends(get_authenticated_user),
    turbo: TurboContext = Depends(turbo_context),
):
    if not turbo.is_frame_request:
        return RedirectResponse(
            url=router.url_path_for("read_profile"), status_code=303
        )
    return templates.render_fragment(
        request,
        "users/partials/profile_form.html",
        user=user,
        max_file_size_mb=MAX_FILE_SIZE / (1024 * 1024),
        min_dimension=MIN_DIMENSION,
        max_dimension=MAX_DIMENSION,
        allowed_formats=list(ALLOWED_CONTENT_TYPES.keys()),
    )


@router.get("/profile-display")
async def profile_display(
    request: Request,
    user: User = Depends(get_authenticated_user),
    turbo: TurboContext = Depends(turbo_context),
):
    if not turbo.is_frame_request:
        return RedirectResponse(
            url=router.url_path_for("read_profile"), status_code=303
        )
    return templates.render_fragment(
        request,
        "users/partials/profile_display.html",
        user=user,
    )


@router.post("/update", response_class=RedirectResponse)
async def update_profile(
    request: Request,
    name: Optional[str] = Form(
        None, strip_whitespace=True, title="Name", description="Updated display name"
    ),
    avatar_file: Optional[UploadFile] = File(None),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session),
):
    avatar_changed = bool(avatar_file and avatar_file.filename)

    # Handle avatar update
    if avatar_changed:
        assert avatar_file is not None
        reject_oversized_content_length(
            request.headers.get("content-length"), MAX_AVATAR_UPLOAD_BYTES
        )
        avatar_data = await read_upload_with_size_limit(avatar_file, MAX_FILE_SIZE)
        avatar_content_type = avatar_file.content_type

        processed_image, content_type = validate_and_process_image(
            avatar_data, avatar_content_type
        )
        if user.avatar:
            user.avatar.avatar_data = processed_image
            user.avatar.avatar_content_type = content_type
        else:
            assert user.id is not None
            user.avatar = UserAvatar(
                user_id=user.id,
                avatar_data=processed_image,
                avatar_content_type=content_type,
            )

    # Update user details
    user.name = name

    session.commit()
    session.refresh(user)

    if accepts_turbo_stream(request):
        # Swap the profile card back to display mode without a full reload.
        stream = streams.replace(
            templates.render_string(
                request, "users/partials/profile_display.html", user=user
            ),
            target="profile-frame",
        )
        if avatar_changed:
            # Avatar also appears in the navbar — refresh it too.
            stream += streams.replace(
                templates.render_string(
                    request, "base/partials/navbar_avatar.html", user=user
                ),
                target="navbar-avatar",
            )
        stream += toast_stream(templates, request, "Profile updated successfully.")
        return TurboStreamResponse(stream)
    redirect = RedirectResponse(
        url=router.url_path_for("read_profile"), status_code=303
    )
    set_flash(request, "Profile updated successfully.")
    return redirect


@router.post("/communication-preferences", response_class=RedirectResponse)
async def update_communication_preferences(
    request: Request,
    comm_opt_in: Optional[str] = Form(None),
    comm_updates: Optional[str] = Form(None),
    comm_marketing: Optional[str] = Form(None),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session),
) -> Response:
    apply_communication_preferences(
        user,
        parse_communication_preferences(comm_opt_in, comm_updates, comm_marketing),
    )
    session.commit()
    session.refresh(user)

    if accepts_turbo_stream(request):
        return toast_stream_response(
            templates,
            request,
            "Communication preferences updated.",
        )
    response = RedirectResponse(url=router.url_path_for("read_profile"), status_code=303)
    set_flash(request, "Communication preferences updated.")
    return response


@router.get("/avatar")
async def get_avatar(user: User = Depends(get_authenticated_user)):
    """Serve avatar image from database"""
    if not user.avatar:
        raise DataIntegrityError(resource="User avatar")

    return Response(
        content=user.avatar.avatar_data, media_type=user.avatar.avatar_content_type
    )


@router.post("/role/update", response_class=RedirectResponse)
def update_user_role(
    request: Request,
    user_id: int = Form(
        ..., title="User ID", description="ID of the user whose roles are being updated"
    ),
    organization_id: int = Form(
        ..., title="Organization ID", description="ID of the organization"
    ),
    roles: Optional[List[int]] = Form(
        None, title="Role IDs", description="List of role IDs to assign to the user"
    ),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session),
) -> Response:
    """Update the roles of a user in an organization"""
    # Check if the current user has permission to edit user roles
    if not user.has_permission(ValidPermissions.EDIT_USER_ROLE, organization_id):
        raise InsufficientPermissionsError()

    # Find the organization
    organization = session.exec(
        select(Organization)
        .where(Organization.id == organization_id)
        .options(selectinload(Organization.roles))
    ).first()

    if not organization:
        raise OrganizationNotFoundError()

    # Find the target user
    target_user = session.exec(
        select(User).where(User.id == user_id).options(selectinload(User.roles))
    ).first()

    if not target_user:
        raise UserNotFoundError()

    # Get all roles for this organization
    org_roles = {role.id: role for role in organization.roles}

    # Remove all current organization roles from the user
    for role in list(target_user.roles):
        if role.organization_id == organization_id:
            target_user.roles.remove(role)

    # Add selected roles to the user
    if roles:
        for role_id in roles:
            fetched_role = org_roles.get(role_id)
            if fetched_role is not None:
                target_user.roles.append(fetched_role)

    session.commit()

    if accepts_turbo_stream(request):
        return members_stream_response(
            templates,
            request,
            session,
            organization_id,
            user,
            "User role updated successfully.",
            list(ValidPermissions) + list(AppPermissions),
            dismiss_modals=True,
        )
    return RedirectResponse(
        url=organization_router.url_path_for(
            "read_organization", org_id=organization_id
        ),
        status_code=303,
    )


@router.post("/organization/remove", response_class=RedirectResponse)
def remove_user_from_organization(
    request: Request,
    user_id: int = Form(..., title="User ID", description="ID of the user to remove"),
    organization_id: int = Form(
        ...,
        title="Organization ID",
        description="ID of the organization to remove the user from",
    ),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session),
) -> Response:
    """Remove a user from an organization by removing all their roles in that organization"""
    # Check if the current user has permission to remove users
    if not user.has_permission(ValidPermissions.REMOVE_USER, organization_id):
        raise InsufficientPermissionsError()

    # Find the organization
    organization = session.exec(
        select(Organization).where(Organization.id == organization_id)
    ).first()

    if not organization:
        raise OrganizationNotFoundError()

    # Find the target user
    target_user = session.exec(
        select(User).where(User.id == user_id).options(selectinload(User.roles))
    ).first()

    if not target_user:
        raise UserNotFoundError()

    # Prevent removing oneself
    if target_user.id == user.id:
        raise HTTPException(
            status_code=400, detail="You cannot remove yourself from the organization"
        )

    # Remove all organization roles from the user
    for role in list(target_user.roles):
        if role.organization_id == organization_id:
            target_user.roles.remove(role)

    session.commit()

    if accepts_turbo_stream(request):
        return members_stream_response(
            templates,
            request,
            session,
            organization_id,
            user,
            "User removed from organization.",
            list(ValidPermissions) + list(AppPermissions),
        )
    return RedirectResponse(
        url=organization_router.url_path_for(
            "read_organization", org_id=organization_id
        ),
        status_code=303,
    )
