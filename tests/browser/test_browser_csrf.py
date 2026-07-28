"""Browser E2E tests with CSRF_ENABLED=1."""

import re
from collections.abc import Iterator

import pytest
from playwright.sync_api import Page, expect

from tests.browser.conftest import register_user
from tests.browser.db_helpers import browser_csrf_db_session


@pytest.fixture(scope="session")
def _register_csrf_user(browser, live_server_csrf: str):
    register_user(
        browser,
        live_server_csrf,
        name="CSRF Browser User",
        email="csrf-browser@example.com",
        password="TestPass123!@#",
    )


@pytest.fixture()
def csrf_login_page(
    browser, live_server_csrf: str, _register_csrf_user
) -> Iterator[Page]:
    context = browser.new_context(viewport={"width": 1280, "height": 720})
    page = context.new_page()
    page.goto(f"{live_server_csrf}/account/login")
    page.wait_for_load_state("networkidle")
    yield page
    context.close()


def test_login_page_exposes_csrf_meta_and_form_field(csrf_login_page: Page):
    page = csrf_login_page
    meta = page.locator('meta[name="csrf-token"]')
    expect(meta).to_have_attribute("content", re.compile(r".+"))
    expect(page.locator('input[name="csrf_token"]')).to_have_count(1)


def test_login_without_csrf_shows_error_toast(csrf_login_page: Page):
    page = csrf_login_page
    page.evaluate(
        """() => {
            document.querySelector('input[name="csrf_token"]')?.remove();
            const meta = document.querySelector('meta[name="csrf-token"]');
            if (meta) meta.content = '';
        }"""
    )
    page.fill("#email", "csrf-browser@example.com")
    page.fill("#password", "wrong-password")
    page.click('button[type="submit"]')

    toast = page.locator("#toast-container .toast")
    expect(toast).to_be_visible(timeout=10_000)
    expect(toast).to_contain_text("CSRF")


def test_login_with_valid_csrf_succeeds(browser, live_server_csrf: str):
    context = browser.new_context(viewport={"width": 1280, "height": 720})
    page = context.new_page()
    page.goto(f"{live_server_csrf}/account/login")
    page.fill("#email", "csrf-browser@example.com")
    page.fill("#password", "TestPass123!@#")
    page.click('button[type="submit"]')
    page.wait_for_function(
        "window.location.pathname.startsWith('/dashboard')", timeout=10_000
    )
    context.close()


def test_forgot_password_without_csrf_shows_error_toast(browser, live_server_csrf: str):
    context = browser.new_context(viewport={"width": 1280, "height": 720})
    page = context.new_page()
    page.goto(f"{live_server_csrf}/account/forgot_password")
    page.fill("#email", "csrf-browser@example.com")
    page.evaluate(
        """() => {
            document.querySelector('input[name="csrf_token"]')?.remove();
            const meta = document.querySelector('meta[name="csrf-token"]');
            if (meta) meta.content = '';
        }"""
    )
    page.click('button[type="submit"]')

    toast = page.locator("#toast-container .toast")
    expect(toast).to_be_visible(timeout=10_000)
    expect(toast).to_contain_text("CSRF")
    context.close()


def test_csrf_token_not_exposed_in_a_readable_cookie(
    browser, live_server_csrf: str
):
    """The token lives in the signed session cookie, not its own cookie."""
    context = browser.new_context(viewport={"width": 1280, "height": 720})
    page = context.new_page()
    page.goto(f"{live_server_csrf}/account/login")
    meta_token = page.get_attribute('meta[name="csrf-token"]', "content")
    assert meta_token
    cookie_names = {c["name"] for c in context.cookies()}
    assert "csrf_token" not in cookie_names
    assert "session" in cookie_names
    context.close()


def test_register_form_post_without_csrf_is_rejected(browser, live_server_csrf: str):
    context = browser.new_context(viewport={"width": 1280, "height": 720})
    page = context.new_page()
    page.goto(f"{live_server_csrf}/account/register")
    page.evaluate(
        """() => {
            document.querySelector('input[name="csrf_token"]')?.remove();
            const meta = document.querySelector('meta[name="csrf-token"]');
            if (meta) meta.content = '';
        }"""
    )
    page.fill("#name", "No CSRF User")
    page.fill("#email", "no-csrf@example.com")
    page.fill("#password", "TestPass123!@#")
    page.fill("#confirm_password", "TestPass123!@#")
    page.click('button[type="submit"]')

    toast = page.locator("#toast-container .toast")
    expect(toast).to_be_visible(timeout=10_000)
    expect(toast).to_contain_text("CSRF")

    with browser_csrf_db_session() as session:
        from sqlmodel import select
        from utils.core.models import Account

        account = session.exec(
            select(Account).where(Account.email == "no-csrf@example.com")
        ).first()
        assert account is None
    context.close()
