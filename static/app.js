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
