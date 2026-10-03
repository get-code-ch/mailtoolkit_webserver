// Copy buttons of the links panel. Links are never made clickable.
document.addEventListener("click", function (event) {
    var button = event.target.closest("button[data-copy]");
    if (!button || !navigator.clipboard) {
        return;
    }
    navigator.clipboard.writeText(button.dataset.copy).then(function () {
        button.textContent = "Copié";
        setTimeout(function () { button.textContent = "Copier"; }, 1500);
    });
});

// Upload forms: the analysis starts as soon as a file is chosen.
document.addEventListener("change", function (event) {
    var input = event.target;
    if (!input.matches("form.upload input[type=file]") || input.files.length === 0) {
        return;
    }
    var button = input.form.querySelector("button");
    if (button) {
        button.disabled = true;
        button.textContent = "Envoi…";
    }
    input.form.submit();
});

// Pages listing the received mails reload themselves, but never while the
// visitor is choosing or sending a file.
(function () {
    var seconds = parseInt(document.body.dataset.autorefresh, 10);
    if (!seconds) {
        return;
    }
    function busy() {
        var uploading = Array.prototype.some.call(document.querySelectorAll("form.upload input[type=file]"), function (input) {
            return input.files.length > 0 || input.closest("details[open]") !== null;
        });
        var focused = document.activeElement && document.activeElement.closest("form");
        return document.hidden || uploading || focused;
    }
    setInterval(function () {
        if (!busy()) {
            location.reload();
        }
    }, seconds * 1000);
})();

// Remaining time before the mailbox expires.
(function () {
    var countdown = document.querySelector(".countdown[data-expires]");
    if (!countdown) {
        return;
    }
    var expires = Date.parse(countdown.dataset.expires);
    function update() {
        var left = Math.max(0, Math.floor((expires - Date.now()) / 1000));
        var h = Math.floor(left / 3600), m = Math.floor(left / 60) % 60, s = left % 60;
        countdown.textContent = left ? "(dans " + h + " h " + (m < 10 ? "0" : "") + m + " min " + (s < 10 ? "0" : "") + s + " s)" : "(expirée)";
    }
    update();
    setInterval(update, 1000);
})();

// Drop zones of the upload forms.
document.querySelectorAll(".dropzone").forEach(function (zone) {
    ["dragenter", "dragover"].forEach(function (type) {
        zone.addEventListener(type, function () { zone.classList.add("dragover"); });
    });
    ["dragleave", "drop"].forEach(function (type) {
        zone.addEventListener(type, function () { zone.classList.remove("dragover"); });
    });
});

// Theme switch: flips the theme shown and remembers the choice.
document.addEventListener("click", function (event) {
    if (!event.target.closest("button.theme-toggle")) {
        return;
    }
    var root = document.documentElement;
    var current = root.dataset.theme || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
    var next = current === "light" ? "dark" : "light";
    root.dataset.theme = next;
    try {
        localStorage.setItem("theme", next);
    } catch (e) {
        // Storage blocked: the choice lasts for this page only.
    }
});

// Deletion forms ask for a confirmation.
document.addEventListener("submit", function (event) {
    var form = event.target;
    if (form.dataset.confirm && !confirm(form.dataset.confirm)) {
        event.preventDefault();
    }
});

// Folding sections marked data-remember stay open or closed across the
// automatic reloads of the page.
document.querySelectorAll("details[data-remember]").forEach(function (details) {
    var key = "open:" + details.dataset.remember;
    try {
        var saved = sessionStorage.getItem(key);
        if (saved !== null) {
            details.open = saved === "1";
        }
    } catch (e) {
        // Storage blocked: default state.
    }
    details.addEventListener("toggle", function () {
        try {
            sessionStorage.setItem(key, details.open ? "1" : "0");
        } catch (e) {
            // Storage blocked: the state is not kept.
        }
    });
});

// Links to a folding section open it.
document.addEventListener("click", function (event) {
    var link = event.target.closest("a.open-details[href^='#']");
    var target = link && document.getElementById(link.getAttribute("href").slice(1));
    if (target && target.tagName === "DETAILS") {
        target.open = true;
    }
});

// View switch of the analysis page: simplified (default) or detailed.
document.addEventListener("click", function (event) {
    var button = event.target.closest("button.view-toggle, button[data-view]");
    if (!button) {
        return;
    }
    var root = document.documentElement;
    var next = button.dataset.view || (root.dataset.view === "detailed" ? "simple" : "detailed");
    root.dataset.view = next;
    try {
        localStorage.setItem("view", next);
    } catch (e) {
        // Storage blocked: the choice lasts for this page only.
    }
    window.scrollTo(0, 0);
});
