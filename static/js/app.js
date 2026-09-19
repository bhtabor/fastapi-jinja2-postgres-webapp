// app.js — global Turbo wiring loaded with defer in <head>.
// Because this script lives in <head> (outside <body>), it is never
// re-executed during Turbo Drive body swaps, which means the event
// listeners registered here persist across page navigations.

// Attach the CSRF token to every state-changing Turbo request. The server
// accepts either this header or the csrf_token form field; the header covers
// requests Turbo issues itself (e.g. frame navigations, future streams).
document.addEventListener('turbo:before-fetch-request', function(event) {
    var method = (event.detail.fetchOptions.method || 'GET').toUpperCase();
    if (method === 'GET' || method === 'HEAD') { return; }
    var meta = document.querySelector('meta[name="csrf-token"]');
    if (meta && meta.content) {
        event.detail.fetchOptions.headers['X-CSRF-Token'] = meta.content;
    }
});

// If a frame navigation lands on a page without a matching frame (e.g. an
// expired session redirecting to the login page), promote it to a full-page
// visit instead of showing Turbo's "Content missing" placeholder.
document.addEventListener('turbo:frame-missing', function(event) {
    event.preventDefault();
    event.detail.visit(event.detail.response);
});

// When a modal closes, reset any create-* form it contains so reopening it
// starts blank. ui.js dispatches 'hidden.bs.modal' when a modal is hidden.
document.addEventListener('hidden.bs.modal', function(event) {
    var modal = event.target;
    if (modal.id && modal.id.startsWith('create')) {
        var form = modal.querySelector('form');
        if (form) { form.reset(); }
    }
});

// Close any open modal and leftover backdrop. Dispatched by the
// dismiss_modals custom stream action below, after a stream update has
// already replaced the modal elements themselves.
document.addEventListener('modalDismiss', function() {
    if (window.UI) {
        window.UI.hideAllModals();
    }
});

// Custom stream action: <turbo-stream action="dismiss_modals"> — sent by
// modal-launched form responses (create role, invite member, …) alongside
// the card update streams.
if (window.Turbo) {
    window.Turbo.StreamActions.dismiss_modals = function () {
        document.dispatchEvent(new CustomEvent('modalDismiss'));
    };
}
