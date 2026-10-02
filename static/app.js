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
