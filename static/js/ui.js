// ui.js — lightweight interactive components (dropdowns, modals, collapse,
// toast dismissal) that replace Bootstrap's JavaScript bundle.
//
// Loaded with defer in <head> (outside <body>) so it is never re-executed
// during Turbo Drive body swaps. All behavior is wired through
// document-level event delegation, so it keeps working for markup that Turbo
// injects or swaps in after the initial page load.
//
// The components read the same data-bs-* attributes the templates already use
// (data-bs-toggle, data-bs-target, data-bs-dismiss), so no template markup
// needs to change.

(function () {
    "use strict";

    // ---------------------------------------------------------------- Dropdowns

    function closeAllDropdowns(except) {
        document.querySelectorAll(".dropdown-menu.show").forEach(function (menu) {
            if (except && menu === except) {
                return;
            }
            menu.classList.remove("show");
            var toggle = menu.parentElement
                ? menu.parentElement.querySelector('[data-bs-toggle="dropdown"]')
                : null;
            if (toggle) {
                toggle.setAttribute("aria-expanded", "false");
            }
        });
    }

    function toggleDropdown(toggle) {
        var container = toggle.closest(".dropdown");
        if (!container) {
            return;
        }
        var menu = container.querySelector(".dropdown-menu");
        if (!menu) {
            return;
        }
        var willOpen = !menu.classList.contains("show");
        closeAllDropdowns(menu);
        menu.classList.toggle("show", willOpen);
        toggle.setAttribute("aria-expanded", willOpen ? "true" : "false");
    }

    // ----------------------------------------------------------------- Collapse

    function toggleCollapse(trigger) {
        var target = resolveTarget(trigger);
        if (!target) {
            return;
        }
        var willOpen = !target.classList.contains("show");
        target.classList.toggle("show", willOpen);
        trigger.setAttribute("aria-expanded", willOpen ? "true" : "false");
    }

    // ------------------------------------------------------------------- Modals

    function ensureBackdrop() {
        var backdrop = document.querySelector(".modal-backdrop");
        if (!backdrop) {
            backdrop = document.createElement("div");
            backdrop.className = "modal-backdrop";
            document.body.appendChild(backdrop);
        }
        return backdrop;
    }

    function openModal(modal) {
        if (!modal || modal.classList.contains("show")) {
            return;
        }
        ensureBackdrop();
        modal.classList.add("show");
        modal.removeAttribute("aria-hidden");
        modal.setAttribute("aria-modal", "true");
        document.body.classList.add("modal-open");
        var focusable = modal.querySelector(
            "input:not([type=hidden]), select, textarea, button"
        );
        if (focusable) {
            focusable.focus();
        }
    }

    function hideModal(modal) {
        if (!modal || !modal.classList.contains("show")) {
            return;
        }
        modal.classList.remove("show");
        modal.setAttribute("aria-hidden", "true");
        modal.removeAttribute("aria-modal");
        cleanupModalChrome();
        // Notify listeners (e.g. app.js resets create-* forms on close).
        modal.dispatchEvent(new CustomEvent("hidden.bs.modal", { bubbles: true }));
    }

    function hideAllModals() {
        document.querySelectorAll(".modal.show").forEach(hideModal);
        cleanupModalChrome();
    }

    // Remove leftover chrome once no modals remain open. Safe to call after a
    // stream update has already replaced the modal element itself.
    function cleanupModalChrome() {
        if (document.querySelector(".modal.show")) {
            return;
        }
        document.querySelectorAll(".modal-backdrop").forEach(function (el) {
            el.remove();
        });
        document.body.classList.remove("modal-open");
        document.body.style.removeProperty("overflow");
        document.body.style.removeProperty("padding-right");
    }

    // --------------------------------------------------------------- Utilities

    function resolveTarget(el) {
        var selector = el.getAttribute("data-bs-target");
        if (!selector || selector === "#") {
            return null;
        }
        try {
            return document.querySelector(selector);
        } catch (e) {
            return null;
        }
    }

    // ------------------------------------------------------------ Auto-dismiss

    // Toasts marked data-auto-dismiss="5s" remove themselves after the given
    // delay. The observer watches the whole document so it survives Turbo
    // body swaps and catches toasts added by any means: flash-cookie renders,
    // client scripts, or stream appends.

    function scheduleAutoDismiss(el) {
        if (el.dataset.autoDismissScheduled) {
            return;
        }
        el.dataset.autoDismissScheduled = "true";
        var match = /^(\d+(?:\.\d+)?)(ms|s)?$/.exec(
            (el.getAttribute("data-auto-dismiss") || "").trim()
        );
        var delay = match
            ? parseFloat(match[1]) * (match[2] === "ms" ? 1 : 1000)
            : 5000;
        setTimeout(function () {
            el.remove();
        }, delay);
    }

    function scanAutoDismiss(root) {
        if (root.matches && root.matches("[data-auto-dismiss]")) {
            scheduleAutoDismiss(root);
        }
        if (root.querySelectorAll) {
            root.querySelectorAll("[data-auto-dismiss]").forEach(scheduleAutoDismiss);
        }
    }

    new MutationObserver(function (mutations) {
        mutations.forEach(function (mutation) {
            mutation.addedNodes.forEach(function (node) {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    scanAutoDismiss(node);
                }
            });
        });
    }).observe(document.documentElement, { childList: true, subtree: true });

    document.addEventListener("DOMContentLoaded", function () {
        scanAutoDismiss(document.body);
    });

    // ------------------------------------------------------------- Delegation

    document.addEventListener("click", function (event) {
        var target = event.target;

        var toggle = target.closest('[data-bs-toggle="dropdown"]');
        if (toggle) {
            event.preventDefault();
            toggleDropdown(toggle);
            return;
        }

        // Clicking an item closes the containing dropdown.
        var item = target.closest(".dropdown-item");
        if (item) {
            closeAllDropdowns();
        }

        var collapseTrigger = target.closest('[data-bs-toggle="collapse"]');
        if (collapseTrigger) {
            event.preventDefault();
            toggleCollapse(collapseTrigger);
            return;
        }

        var modalTrigger = target.closest('[data-bs-toggle="modal"]');
        if (modalTrigger) {
            event.preventDefault();
            openModal(resolveTarget(modalTrigger));
            return;
        }

        var modalDismiss = target.closest('[data-bs-dismiss="modal"]');
        if (modalDismiss) {
            event.preventDefault();
            hideModal(modalDismiss.closest(".modal"));
            return;
        }

        var toastDismiss = target.closest('[data-bs-dismiss="toast"]');
        if (toastDismiss) {
            var toast = toastDismiss.closest(".toast");
            if (toast) {
                toast.classList.remove("show");
            }
            return;
        }

        // Click on the modal overlay (outside the dialog) closes the modal.
        if (target.classList && target.classList.contains("modal")) {
            hideModal(target);
            return;
        }

        // Any other click closes open dropdowns.
        if (!target.closest(".dropdown-menu")) {
            closeAllDropdowns();
        }
    });

    document.addEventListener("keydown", function (event) {
        if (event.key !== "Escape") {
            return;
        }
        var openModals = document.querySelectorAll(".modal.show");
        if (openModals.length) {
            hideModal(openModals[openModals.length - 1]);
            return;
        }
        closeAllDropdowns();
    });

    // Expose a tiny API for scripts that need to dismiss modals programmatically
    // (e.g. responses that trigger a modalDismiss event after a partial update).
    window.UI = {
        openModal: openModal,
        hideModal: hideModal,
        hideAllModals: hideAllModals,
    };
})();
