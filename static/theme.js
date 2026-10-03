// Applies the theme chosen by the visitor before the page is drawn (loaded
// without defer). Without a choice, the system preference applies.
(function () {
    try {
        var theme = localStorage.getItem("theme");
        if (theme === "light" || theme === "dark") {
            document.documentElement.dataset.theme = theme;
        }
    } catch (e) {
        // Storage blocked: the system preference applies.
    }
})();
