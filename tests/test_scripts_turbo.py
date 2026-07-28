"""
Test that the front-end scripts are loaded in <head>, keeping them outside
the Turbo Drive body swap zone so their document-level event delegation
(dropdowns, modals, collapse, toasts) persists across navigations.
"""

from main import app


def test_scripts_in_head_not_body(unauth_client):
    """
    Turbo and our component JS (ui.js, app.js) <script> tags must be in <head>
    (module/defer), not in <body>. Turbo Drive replaces <body> on navigation
    and merges <head>, so scripts in <body> would be re-executed during swaps,
    while scripts in <head> load once and their document-level event
    delegation persists.
    """
    response = unauth_client.get(
        app.url_path_for("read_home"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    html = response.text

    # Split on </head> to separate head from body
    head, body = html.split("</head>", 1)

    # Turbo and our component scripts must be in <head>
    assert "@hotwired/turbo" in head, "Turbo script must be in <head>"
    assert "js/ui.js" in head, "ui.js must be in <head>"
    assert "js/app.js" in head, "app.js must be in <head>"
    assert "defer" in head, "Scripts in <head> must use defer"

    # They must NOT be in <body>
    assert "@hotwired/turbo" not in body, "Turbo script must not be in <body>"
    assert "js/ui.js" not in body, (
        "ui.js must not be in <body> — Turbo Drive would re-execute it during "
        "body swaps, duplicating event delegation"
    )

    # htmx has been replaced by Turbo; make sure it does not creep back in.
    assert "htmx" not in html.lower(), (
        "htmx must not be referenced — this branch uses Hotwire Turbo"
    )

    # Bootstrap has been removed entirely; make sure it does not creep back in.
    assert "bootstrap" not in html.lower(), (
        "Bootstrap must not be referenced — the app ships its own CSS/JS"
    )
