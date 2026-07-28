"""
Tests for Turbo-specific endpoint behavior.

Convention: Turbo Stream-accepting requests send an Accept header listing
text/vnd.turbo-stream.html.
- Success responses return 200 turbo-stream bodies (no <!DOCTYPE html>).
- Error responses return 422/400/401 toast streams.
- Navigation responses use plain 303 redirects — Turbo Drive follows them.
- Requests outside a Turbo Stream/Frame context get the same full-page
  behavior as a plain browser request.
"""

from fastapi_turbo.testing import assert_turbo_stream, parse_streams
from tests.conftest import turbo_frame_headers, turbo_stream_headers
from utils.core.rate_limit import (
    forgot_password_ip_limiter,
    login_ip_limiter,
)

# ---------------------------------------------------------------------------
# 1.4 — Exception handler branches
# ---------------------------------------------------------------------------


def _assert_error_toast_stream(response, target: str = "toast-container"):
    """Assert an error response is a single append-toast turbo-stream.

    main.py's global exception handlers respond to Turbo Stream-accepting
    clients with exactly one <turbo-stream action="append" target="..."> —
    unlike a full-page error render, this never clobbers whatever element
    triggered the request.
    """
    assert_turbo_stream(response)
    actions = parse_streams(response)
    assert len(actions) == 1, f"expected exactly one stream action, got {actions}"
    assert actions[0].action == "append"
    assert actions[0].target == target


def test_validation_error_returns_toast_for_turbo(unauth_client):
    """RequestValidationError from a Turbo Stream request returns a 422 toast."""
    response = unauth_client.post(
        "/account/login",
        data={"email": "", "password": ""},
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 422
    assert "<!DOCTYPE html>" not in response.text
    assert "toast" in response.text
    _assert_error_toast_stream(response)


def test_credentials_error_turbo_is_single_toast_stream(unauth_client):
    """CredentialsError Turbo response must be a single toast stream."""
    response = unauth_client.post(
        "/account/login",
        data={"email": "nobody@example.com", "password": "wrongpass"},
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 401
    _assert_error_toast_stream(response)


def test_http_exception_turbo_is_single_toast_stream(auth_client, test_organization):
    """HTTPException Turbo response (e.g. duplicate org name) must be a single toast stream."""
    response = auth_client.post(
        "/organizations/create",
        data={"name": test_organization.name},
        headers=turbo_stream_headers(),
    )
    assert response.status_code in (400, 422)
    _assert_error_toast_stream(response)


def test_validation_error_returns_full_page_for_non_turbo(unauth_client):
    response = unauth_client.post(
        "/account/login",
        data={"email": "", "password": ""},
    )
    assert response.status_code == 422
    assert "<!DOCTYPE html>" in response.text


# ---------------------------------------------------------------------------
# 1.5 — Full-page error pages: human-readable, consistent navigation
# ---------------------------------------------------------------------------


def test_password_validation_error_full_page_shows_readable_message(unauth_client):
    """PasswordValidationError must render human-readable text, not raw dicts."""
    from html import unescape

    response = unauth_client.post(
        "/account/register",
        data={
            "name": "T",
            "email": "t@t.com",
            "password": "Abcdef1!",
            "confirm_password": "wrong",
        },
    )
    assert response.status_code == 422
    # Unescape so HTML entities don't hide raw dict syntax
    text = unescape(response.text)
    # Must contain the actual message, not the raw dict
    assert "password" in text.lower()
    assert "{'field'" not in text, "Raw dict rendered in error page"
    assert "{'message'" not in text, "Raw dict rendered in error page"


def test_full_page_error_pages_have_go_back_and_home_links(unauth_client):
    """All full-page error pages should have both Go Back and Return to Home."""
    # Validation error (422)
    response = unauth_client.post(
        "/account/login",
        data={"email": "", "password": ""},
    )
    assert response.status_code == 422
    assert "Go Back" in response.text
    assert "Return to Home" in response.text

    # Credentials error (401)
    response = unauth_client.post(
        "/account/login",
        data={"email": "nobody@example.com", "password": "wrongpass"},
    )
    assert response.status_code == 401
    assert "Go Back" in response.text
    assert "Return to Home" in response.text


# ---------------------------------------------------------------------------
# 1.6 — Auth forms submit as plain forms (Turbo Drive needs no opt-in markup)
# ---------------------------------------------------------------------------


def test_login_form_has_no_hx_post(unauth_client):
    response = unauth_client.get("/account/login")
    assert response.status_code == 200
    assert "hx-post" not in response.text


def test_register_form_has_no_hx_post(unauth_client):
    response = unauth_client.get("/account/register")
    assert response.status_code == 200
    assert "hx-post" not in response.text


def test_forgot_password_form_has_no_hx_post(unauth_client):
    response = unauth_client.get("/account/forgot_password")
    assert response.status_code == 200
    assert "hx-post" not in response.text


def test_reset_password_form_has_no_hx_post(unauth_client, session, test_account):
    from utils.core.auth import RESET_PASSWORD_CONTEXT, build_email_token

    token = build_email_token(
        test_account.id, RESET_PASSWORD_CONTEXT, test_account.email, session
    )
    session.commit()
    response = unauth_client.get(
        "/account/reset_password",
        params={"email": test_account.email, "token": token},
    )
    assert response.status_code == 200
    assert "hx-post" not in response.text


# ---------------------------------------------------------------------------
# 4.2 — Password mismatch on register/reset
# ---------------------------------------------------------------------------


def test_password_mismatch_turbo_returns_toast(unauth_client):
    response = unauth_client.post(
        "/account/register",
        data={
            "name": "T",
            "email": "t@t.com",
            "password": "Abcdef1!",
            "confirm_password": "wrong",
        },
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 422
    assert "toast" in response.text
    assert "<!DOCTYPE html>" not in response.text
    _assert_error_toast_stream(response)


# ---------------------------------------------------------------------------
# 4.3 — Login failure toast
# ---------------------------------------------------------------------------


def test_bad_login_turbo_returns_toast(unauth_client):
    response = unauth_client.post(
        "/account/login",
        data={"email": "nobody@example.com", "password": "wrongpass"},
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 401
    assert "toast" in response.text
    assert "<!DOCTYPE html>" not in response.text
    _assert_error_toast_stream(response)


# ---------------------------------------------------------------------------
# 2.3 — Role CRUD endpoints
# ---------------------------------------------------------------------------


def test_create_role_turbo_returns_partial(auth_client_owner, test_organization):
    assert test_organization.id is not None
    response = auth_client_owner.post(
        "/roles/create",
        data={
            "name": "Viewer",
            "organization_id": str(test_organization.id),
        },
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert "Viewer" in response.text
    assert 'data-bs-target="#editRoleModal' in response.text


def test_create_role_non_turbo_redirects(auth_client_owner, test_organization):
    assert test_organization.id is not None
    response = auth_client_owner.post(
        "/roles/create",
        data={
            "name": "Viewer2",
            "organization_id": str(test_organization.id),
        },
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"/organizations/{test_organization.id}"


def test_delete_role_turbo_returns_partial(
    auth_client_owner, test_organization, session
):
    """After deleting a custom role via Turbo, returns updated roles table stream."""
    from utils.core.models import Role

    # Create a custom role to delete
    custom_role = Role(name="ToDelete", organization_id=test_organization.id)
    session.add(custom_role)
    session.commit()
    session.refresh(custom_role)

    assert test_organization.id is not None
    response = auth_client_owner.post(
        "/roles/delete",
        data={
            "id": str(custom_role.id),
            "organization_id": str(test_organization.id),
        },
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert "ToDelete" not in response.text


def test_create_role_turbo_returns_modal_markup_for_new_role(
    auth_client_owner, test_organization
):
    assert test_organization.id is not None
    response = auth_client_owner.post(
        "/roles/create",
        data={
            "name": "Auditor",
            "organization_id": str(test_organization.id),
        },
        headers=turbo_stream_headers(),
    )

    assert response.status_code == 200
    assert 'id="editRoleModal' in response.text
    assert "Edit Role: Auditor" in response.text


# ---------------------------------------------------------------------------
# 2.4 — Invitation endpoint
# ---------------------------------------------------------------------------


def test_create_invitation_turbo_returns_invitations_partial(
    auth_client_owner, test_organization, member_role, mock_resend_send
):
    assert test_organization.id is not None
    assert member_role.id is not None
    response = auth_client_owner.post(
        "/invitations/",
        data={
            "invitee_email": "newperson@example.com",
            "role_id": str(member_role.id),
            "organization_id": str(test_organization.id),
        },
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert "newperson@example.com" in response.text


# ---------------------------------------------------------------------------
# 3.2 — Update profile endpoint
# ---------------------------------------------------------------------------


def test_update_profile_turbo_returns_profile_display(auth_client):
    response = auth_client.post(
        "/user/update",
        data={"name": "Updated Name"},
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    assert "Updated Name" in response.text
    assert "<!DOCTYPE html>" not in response.text


def test_update_profile_turbo_returns_display_without_form(auth_client):
    """After refactor, update_profile's stream swaps in only the display
    partial — no edit form, since it's fetched on demand via the Edit link."""
    response = auth_client.post(
        "/user/update",
        data={"name": "Synced Name"},
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    assert "Synced Name" in response.text
    assert "profile-form" not in response.text


def test_avatar_url_includes_cache_buster():
    """The avatar img src in the display partial must include a cache-busting
    query param so the browser doesn't show a stale image after upload."""
    import pathlib
    import re

    template = (
        pathlib.Path(__file__).resolve().parent.parent
        / "templates"
        / "users"
        / "partials"
        / "profile_display.html"
    ).read_text()
    assert "get_avatar" in template, "Template should reference get_avatar"
    # The src should NOT end right after url_for — it must have a query param
    assert re.search(r"get_avatar.*\?\w+=", template), (
        "Avatar URL in profile_display.html must include a cache-busting query param"
    )


def test_avatar_upload_turbo_returns_navbar_replace_stream(auth_client):
    """When an avatar is uploaded, the Turbo Stream response should include a
    replace action for the navbar avatar instead of a full page refresh."""
    import io
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (100, 100), color="red").save(buf, format="PNG")
    buf.seek(0)
    response = auth_client.post(
        "/user/update",
        data={"name": "Avatar User"},
        files={"avatar_file": ("test.png", buf, "image/png")},
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    assert_turbo_stream(response)
    actions = parse_streams(response)
    navbar_actions = [a for a in actions if a.target == "navbar-avatar"]
    assert len(navbar_actions) == 1
    assert navbar_actions[0].action == "replace"
    assert 'id="navbar-avatar"' in navbar_actions[0].content


def test_name_only_update_turbo_no_navbar_stream(auth_client):
    """Name-only updates should return the display partial, not a navbar swap."""
    response = auth_client.post(
        "/user/update",
        data={"name": "No Refresh"},
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    actions = parse_streams(response)
    assert not [a for a in actions if a.target == "navbar-avatar"]
    assert "No Refresh" in response.text


def test_update_profile_non_turbo_redirects(auth_client):
    response = auth_client.post(
        "/user/update",
        data={"name": "Updated Name"},
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/user/profile"


# ---------------------------------------------------------------------------
# 4.1 — Business logic errors via HTTPException handler
# ---------------------------------------------------------------------------


def test_duplicate_org_name_turbo_returns_toast(auth_client, test_organization):
    assert test_organization.id is not None
    response = auth_client.post(
        "/organizations/create",
        data={"name": test_organization.name},
        headers=turbo_stream_headers(),
    )
    assert response.status_code in (400, 422)
    assert "toast" in response.text
    assert "<!DOCTYPE html>" not in response.text
    _assert_error_toast_stream(response)


def test_update_user_role_turbo_returns_member_modal_markup(
    auth_client_owner, org_member_user, test_organization, member_role
):
    assert org_member_user.id is not None
    assert test_organization.id is not None
    assert member_role.id is not None

    response = auth_client_owner.post(
        "/user/role/update",
        data={
            "user_id": str(org_member_user.id),
            "organization_id": str(test_organization.id),
            "roles": [str(member_role.id)],
        },
        headers=turbo_stream_headers(),
    )

    assert response.status_code == 200
    assert f'id="editUserRoleModal{org_member_user.id}"' in response.text


def test_remove_last_non_owner_member_turbo_preserves_empty_state(
    auth_client_owner, org_member_user, test_organization
):
    assert org_member_user.id is not None
    assert test_organization.id is not None

    response = auth_client_owner.post(
        "/user/organization/remove",
        data={
            "user_id": str(org_member_user.id),
            "organization_id": str(test_organization.id),
        },
        headers=turbo_stream_headers(),
    )

    assert response.status_code == 200
    assert "No members found" in response.text


# ---------------------------------------------------------------------------
# 2.3 — update_role Turbo stream refreshes both table and modal container
# ---------------------------------------------------------------------------


def test_update_role_turbo_refreshes_modal_container(
    auth_client_owner, test_organization, session
):
    """
    update_role's Turbo stream response includes the updated role name in the
    table-update stream and a separate replace stream for
    #role-modals-container so the edit modal title reflects the renamed role.
    """
    from utils.core.models import Role

    # Create a custom role to rename
    custom_role = Role(name="OldName", organization_id=test_organization.id)
    session.add(custom_role)
    session.commit()
    session.refresh(custom_role)

    assert test_organization.id is not None
    response = auth_client_owner.post(
        "/roles/update",
        data={
            "id": str(custom_role.id),
            "name": "NewName",
            "organization_id": str(test_organization.id),
        },
        headers=turbo_stream_headers(),
    )

    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    # Updated name appears in the table rows
    assert "NewName" in response.text
    # Old name is gone from the table
    assert "OldName" not in response.text
    # Replaced modal container includes updated edit modal title
    assert "Edit Role: NewName" in response.text
    actions = parse_streams(response)
    modal_actions = [a for a in actions if a.target == "role-modals-container"]
    assert len(modal_actions) == 1
    assert modal_actions[0].action == "replace"


# ---------------------------------------------------------------------------
# 5.1 — Rate limit 429 toast responses
# ---------------------------------------------------------------------------


def test_login_rate_limit_turbo_returns_toast(unauth_client):
    """Rate-limited Turbo login returns a 429 toast stream with Retry-After."""
    for _ in range(login_ip_limiter.max_attempts):
        unauth_client.post(
            "/account/login",
            data={"email": "nobody@example.com", "password": "wrongpass"},
            headers=turbo_stream_headers(),
        )

    response = unauth_client.post(
        "/account/login",
        data={"email": "nobody@example.com", "password": "wrongpass"},
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 429
    assert "toast" in response.text
    assert "<!DOCTYPE html>" not in response.text
    assert "Retry-After" in response.headers
    _assert_error_toast_stream(response)


def test_forgot_password_rate_limit_turbo_returns_toast(unauth_client):
    """Rate-limited Turbo forgot-password returns a 429 toast stream."""
    for _ in range(forgot_password_ip_limiter.max_attempts):
        unauth_client.post(
            "/account/forgot_password",
            data={"email": "user@example.com"},
            headers=turbo_stream_headers(),
        )

    response = unauth_client.post(
        "/account/forgot_password",
        data={"email": "user@example.com"},
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 429
    assert "toast" in response.text
    assert "<!DOCTYPE html>" not in response.text
    _assert_error_toast_stream(response)


# ---------------------------------------------------------------------------
# 6.2 — Success toasts in Turbo mutation responses
# ---------------------------------------------------------------------------


def test_update_profile_turbo_includes_success_toast(auth_client):
    response = auth_client.post(
        "/user/update",
        data={"name": "Toast Name"},
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    assert "Profile updated successfully" in response.text
    assert "toast" in response.text


def test_edit_profile_form_turbo_frame_returns_form_partial(auth_client):
    """GET /user/edit-form for a turbo-frame request returns the edit form partial."""
    response = auth_client.get(
        "/user/edit-form", headers=turbo_frame_headers("profile-frame")
    )
    assert response.status_code == 200
    assert "<form" in response.text
    assert "<!DOCTYPE html>" not in response.text


def test_edit_profile_form_non_frame_redirects(auth_client):
    """GET /user/edit-form outside a turbo-frame request redirects to profile."""
    response = auth_client.get("/user/edit-form")
    assert response.status_code == 303
    assert response.headers["location"] == "/user/profile"


def test_profile_display_turbo_frame_returns_display_partial(auth_client):
    """GET /user/profile-display for a turbo-frame request returns the display partial."""
    response = auth_client.get(
        "/user/profile-display", headers=turbo_frame_headers("profile-frame")
    )
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text


def test_profile_display_non_frame_redirects(auth_client):
    """GET /user/profile-display outside a turbo-frame request redirects to profile."""
    response = auth_client.get("/user/profile-display")
    assert response.status_code == 303
    assert response.headers["location"] == "/user/profile"


def test_create_role_turbo_includes_success_toast(auth_client_owner, test_organization):
    response = auth_client_owner.post(
        "/roles/create",
        data={
            "name": "ToastRole",
            "organization_id": str(test_organization.id),
        },
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    assert "Role created successfully" in response.text


def test_delete_role_turbo_includes_success_toast(
    auth_client_owner, test_organization, session
):
    from utils.core.models import Role

    custom_role = Role(name="ToDeleteToast", organization_id=test_organization.id)
    session.add(custom_role)
    session.commit()
    session.refresh(custom_role)

    response = auth_client_owner.post(
        "/roles/delete",
        data={
            "id": str(custom_role.id),
            "organization_id": str(test_organization.id),
        },
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    assert "Role deleted successfully" in response.text


def test_update_role_turbo_includes_success_toast(
    auth_client_owner, test_organization, session
):
    from utils.core.models import Role

    custom_role = Role(name="RenameMe", organization_id=test_organization.id)
    session.add(custom_role)
    session.commit()
    session.refresh(custom_role)

    response = auth_client_owner.post(
        "/roles/update",
        data={
            "id": str(custom_role.id),
            "name": "Renamed",
            "organization_id": str(test_organization.id),
        },
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    assert "Role updated successfully" in response.text


def test_update_role_turbo_triggers_modal_cleanup(
    auth_client_owner, test_organization, session
):
    """The response must include a dismiss_modals stream action so the client
    can close the Bootstrap modal and its backdrop.  The replace stream for
    #role-modals-container replaces the modal element itself, so the client
    needs an explicit signal to also clean up the backdrop."""
    from utils.core.models import Role

    custom_role = Role(name="TriggerRole", organization_id=test_organization.id)
    session.add(custom_role)
    session.commit()
    session.refresh(custom_role)

    response = auth_client_owner.post(
        "/roles/update",
        data={
            "id": str(custom_role.id),
            "name": "TriggerRenamed",
            "organization_id": str(test_organization.id),
        },
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    actions = parse_streams(response)
    assert any(a.action == "dismiss_modals" for a in actions)


def test_create_role_turbo_triggers_modal_cleanup(auth_client_owner, test_organization):
    """create_role must include a dismiss_modals stream action to close the
    create-role Bootstrap modal after the swap."""
    response = auth_client_owner.post(
        "/roles/create",
        data={
            "name": "ModalCleanupRole",
            "organization_id": str(test_organization.id),
        },
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    actions = parse_streams(response)
    assert any(a.action == "dismiss_modals" for a in actions)


def test_create_invitation_turbo_triggers_modal_cleanup(
    auth_client_owner, test_organization, member_role, mock_resend_send
):
    """create_invitation must include a dismiss_modals stream action to
    close the invite-member Bootstrap modal after the swap."""
    response = auth_client_owner.post(
        "/invitations/",
        data={
            "invitee_email": "modaldismiss@example.com",
            "role_id": str(member_role.id),
            "organization_id": str(test_organization.id),
        },
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    actions = parse_streams(response)
    assert any(a.action == "dismiss_modals" for a in actions)


def test_update_user_role_turbo_triggers_modal_cleanup(
    auth_client_owner, org_member_user, test_organization, member_role
):
    """update_user_role must include a dismiss_modals stream action to
    close the edit-user-role Bootstrap modal after the swap."""
    assert org_member_user.id is not None
    assert test_organization.id is not None
    assert member_role.id is not None

    response = auth_client_owner.post(
        "/user/role/update",
        data={
            "user_id": str(org_member_user.id),
            "organization_id": str(test_organization.id),
            "roles": [str(member_role.id)],
        },
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    actions = parse_streams(response)
    assert any(a.action == "dismiss_modals" for a in actions)


def test_create_invitation_turbo_includes_success_toast(
    auth_client_owner, test_organization, member_role, mock_resend_send
):
    response = auth_client_owner.post(
        "/invitations/",
        data={
            "invitee_email": "toastinvite@example.com",
            "role_id": str(member_role.id),
            "organization_id": str(test_organization.id),
        },
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    assert "Invitation sent successfully" in response.text


def test_delete_invitation_turbo_returns_members_partial(
    auth_client_owner,
    test_organization,
    member_role,
    session,
):
    from utils.core.models import Invitation

    invitation = Invitation(
        organization_id=test_organization.id,
        role_id=member_role.id,
        invitee_email="cancelme@example.com",
        token="htmx-delete-token",
    )
    session.add(invitation)
    session.commit()
    session.refresh(invitation)

    response = auth_client_owner.post(
        "/invitations/delete",
        data={
            "invitation_id": str(invitation.id),
            "organization_id": str(test_organization.id),
        },
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert 'id="invitations-list"' in response.text
    assert "cancelme@example.com" not in response.text


def test_delete_invitation_turbo_includes_success_toast(
    auth_client_owner,
    test_organization,
    member_role,
    session,
):
    from utils.core.models import Invitation

    invitation = Invitation(
        organization_id=test_organization.id,
        role_id=member_role.id,
        invitee_email="toastcancel@example.com",
        token="htmx-delete-toast-token",
    )
    session.add(invitation)
    session.commit()
    session.refresh(invitation)

    response = auth_client_owner.post(
        "/invitations/delete",
        data={
            "invitation_id": str(invitation.id),
            "organization_id": str(test_organization.id),
        },
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    assert "Invitation cancelled successfully" in response.text


def test_update_user_role_turbo_includes_success_toast(
    auth_client_owner, org_member_user, test_organization, member_role
):
    response = auth_client_owner.post(
        "/user/role/update",
        data={
            "user_id": str(org_member_user.id),
            "organization_id": str(test_organization.id),
            "roles": [str(member_role.id)],
        },
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    assert "User role updated successfully" in response.text


def test_remove_user_turbo_includes_success_toast(
    auth_client_owner, org_member_user, test_organization
):
    response = auth_client_owner.post(
        "/user/organization/remove",
        data={
            "user_id": str(org_member_user.id),
            "organization_id": str(test_organization.id),
        },
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    assert "User removed from organization" in response.text


# ---------------------------------------------------------------------------
# 7 — Architectural guard: no htmx attributes anywhere in templates
# ---------------------------------------------------------------------------


def test_no_templates_use_htmx_attributes():
    """This app migrated from htmx to Turbo — no template should carry an
    hx-* attribute (dead markup at best, misleading at worst)."""
    import pathlib
    import re

    attr_pattern = re.compile(r'\bhx-[a-zA-Z-]+\s*=')

    templates_dir = pathlib.Path(__file__).resolve().parent.parent / "templates"
    violations = []
    for path in templates_dir.rglob("*.html"):
        text = path.read_text()
        if attr_pattern.search(text):
            violations.append(str(path.relative_to(templates_dir)))

    assert violations == [], f"Templates must not use hx-* attributes: {violations}"


# ---------------------------------------------------------------------------
# --- Flash session tests ---


def test_flash_set_and_pop_roundtrip():
    """set_flash() queues a one-shot message in the session; pop_flash() drains it."""
    from unittest.mock import MagicMock

    from utils.core.flash import pop_flash, set_flash

    request = MagicMock()
    request.session = {}

    set_flash(request, "Email address verified and added to your account.")
    assert "flash" in request.session

    flashed = pop_flash(request)
    assert flashed == {
        "message": "Email address verified and added to your account.",
        "level": "success",
    }
    assert "flash" not in request.session
    assert pop_flash(request) is None


def test_flash_appears_once_on_next_page(unauth_client, test_account, session):
    """A redirect's flash renders as a toast on the next page load only."""
    from main import app

    response = unauth_client.post(
        app.url_path_for("forgot_password"),
        data={"email": "missing@example.com"},
        follow_redirects=False,
    )
    assert response.status_code == 303

    follow = unauth_client.get(response.headers["location"])
    assert "If an account exists" in follow.text

    again = unauth_client.get(response.headers["location"])
    assert "If an account exists" not in again.text


# ---------------------------------------------------------------------------
# 8 - Turbo matrix gaps (dashboard, org CRUD, resend)
# ---------------------------------------------------------------------------


def _url(name: str, **path_params) -> str:
    from main import app

    return str(app.url_path_for(name, **path_params))


def test_resend_invitation_turbo_returns_members_partial(
    auth_client_owner,
    test_organization,
    test_invitation,
    mock_resend_send,
):
    assert test_organization.id is not None
    assert test_invitation.id is not None
    response = auth_client_owner.post(
        _url("resend_invitation"),
        data={
            "invitation_id": str(test_invitation.id),
            "organization_id": str(test_organization.id),
        },
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert 'id="invitations-list"' in response.text
    assert "Invitation resent" in response.text


def test_csrf_enabled_turbo_login_returns_toast(unauth_client, monkeypatch):
    monkeypatch.setenv("CSRF_ENABLED", "1")

    response = unauth_client.post(
        "/account/login",
        data={"email": "nobody@example.com", "password": "wrong"},
        headers=turbo_stream_headers(),
    )
    assert response.status_code == 403
    assert "toast" in response.text
    _assert_error_toast_stream(response)
