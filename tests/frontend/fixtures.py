"""Fixtures shared by frontend GET and redirect integration tests."""

from __future__ import annotations

import pytest

from utils.core.auth import (
    RECOVERY_CONTEXT,
    RESET_PASSWORD_CONTEXT,
    build_email_token,
)


@pytest.fixture
def password_reset_credentials(session, test_account):
    """Valid email/token pair for GET /account/reset_password."""
    raw_token = build_email_token(
        test_account.id, RESET_PASSWORD_CONTEXT, test_account.email, session
    )
    session.commit()
    return test_account.email, raw_token


@pytest.fixture
def account_recovery_token(session, test_account):
    """Valid recovery token for GET /account/recover."""
    raw_token = build_email_token(
        test_account.id, RECOVERY_CONTEXT, test_account.email, session
    )
    session.commit()
    return raw_token
