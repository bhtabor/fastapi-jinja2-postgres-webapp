from typing import Any, cast

from fastapi import Request
from fastapi_turbo import TurboStreamResponse, streams
from fastapi_turbo.templates import TurboTemplates
from sqlmodel import Session, select
from sqlalchemy.orm import InstrumentedAttribute, selectinload

from utils.core.enums import ValidPermissions
from utils.core.models import Organization, Role, User, Invitation
from utils.core.toast import toast_stream


def _user_permissions_for_org(user: User, organization_id: int) -> set[str]:
    user_permissions: set[str] = set()
    for role in user.roles:
        if role.organization_id == organization_id:
            for permission in role.permissions:
                user_permissions.add(permission.name)
    return user_permissions


def load_org_for_members_partial(
    session: Session, organization_id: int, user: User
) -> tuple[Organization | None, set[str], list[Invitation]]:
    """Re-query org with members fully loaded and compute user_permissions."""
    organization = session.exec(
        select(Organization)
        .where(Organization.id == organization_id)
        .options(
            selectinload(cast(InstrumentedAttribute[Any], Organization.roles))
            .selectinload(cast(InstrumentedAttribute[Any], Role.users))
            .selectinload(cast(InstrumentedAttribute[Any], User.account)),
            selectinload(cast(InstrumentedAttribute[Any], Organization.roles))
            .selectinload(cast(InstrumentedAttribute[Any], Role.users))
            .selectinload(cast(InstrumentedAttribute[Any], User.roles)),
            selectinload(
                cast(InstrumentedAttribute[Any], Organization.roles)
            ).selectinload(cast(InstrumentedAttribute[Any], Role.permissions)),
        )
    ).first()
    user_permissions = _user_permissions_for_org(user, organization_id)
    pending_invitations = Invitation.get_pending_for_org(session, organization_id)
    return organization, user_permissions, pending_invitations


def load_org_for_roles_partial(
    session: Session, organization_id: int, user: User
) -> tuple[Organization | None, set[str]]:
    """Re-query org with roles/users/permissions and compute user_permissions."""
    organization = session.exec(
        select(Organization)
        .where(Organization.id == organization_id)
        .options(
            selectinload(
                cast(InstrumentedAttribute[Any], Organization.roles)
            ).selectinload(cast(InstrumentedAttribute[Any], Role.users)),
            selectinload(
                cast(InstrumentedAttribute[Any], Organization.roles)
            ).selectinload(cast(InstrumentedAttribute[Any], Role.permissions)),
        )
    ).first()
    user_permissions = _user_permissions_for_org(user, organization_id)
    return organization, user_permissions


def roles_card_streams(
    templates: TurboTemplates,
    request: Request,
    session: Session,
    organization_id: int,
    user: User,
    all_permissions: list,
):
    """Streams refreshing the Roles card: table body update + modals replace."""
    organization, user_permissions = load_org_for_roles_partial(
        session, organization_id, user
    )
    context = {
        "organization": organization,
        "user": user,
        "user_permissions": user_permissions,
        "ValidPermissions": ValidPermissions,
        "all_permissions": all_permissions,
    }
    return streams.update(
        templates.render_string(
            request, "organization/partials/roles_table.html", **context
        ),
        target="roles-card-content",
    ) + streams.replace(
        templates.render_string(
            request, "organization/partials/role_modals.html", **context
        ),
        target="role-modals-container",
    )


def members_card_streams(
    templates: TurboTemplates,
    request: Request,
    session: Session,
    organization_id: int,
    current_user: User,
    all_permissions: list,
):
    """Streams refreshing the Members card: table body update + modals replace."""
    organization, user_permissions, pending_invitations = load_org_for_members_partial(
        session, organization_id, current_user
    )
    context = {
        "organization": organization,
        "pending_invitations": pending_invitations,
        "user": current_user,
        "user_permissions": user_permissions,
        "ValidPermissions": ValidPermissions,
        "all_permissions": all_permissions,
    }
    return streams.update(
        templates.render_string(
            request, "organization/partials/members_table.html", **context
        ),
        target="members-card-content",
    ) + streams.replace(
        templates.render_string(
            request, "organization/partials/member_modals.html", **context
        ),
        target="member-role-modals-container",
    )


def members_stream_response(
    templates: TurboTemplates,
    request: Request,
    session: Session,
    organization_id: int,
    current_user: User,
    toast_message: str,
    all_permissions: list,
    dismiss_modals: bool = False,
) -> TurboStreamResponse:
    """Refresh the Members card (table + modals), optionally close open
    modals, and append a toast. Shared by the invitation and member-management
    endpoints."""
    stream = members_card_streams(
        templates, request, session, organization_id, current_user, all_permissions
    )
    if dismiss_modals:
        stream += streams.stream("dismiss_modals")
    stream += toast_stream(templates, request, toast_message)
    return TurboStreamResponse(stream)
