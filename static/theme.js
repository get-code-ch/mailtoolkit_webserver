// Applies the theme and the view chosen by the visitor before the page is drawn (loaded
// without defer). Without a choice, the system preference applies.
(function () {
    try {
        var theme = localStorage.getItem("theme");
        if (theme === "light" || theme === "dark") {
            document.documentElement.dataset.theme = theme;
        }
        var view = localStorage.getItem("view");
        if (view === "simple" || view === "detailed") {
            document.documentElement.dataset.view = view;
        }
    } catch (e) {
        // Storage blocked: the system preference applies.
    }
})();
