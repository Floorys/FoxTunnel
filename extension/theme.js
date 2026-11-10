/* Sync theme early to avoid white flash on dark systems. */
"use strict";
(function () {
  const KEY = "foxtunnel.theme";
  function apply(mode) {
    const valid = mode === "light" || mode === "dark" || mode === "system" ? mode : "system";
    if (valid === "system") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = valid;
    try { localStorage.setItem(KEY, valid); } catch {}
    return valid;
  }
  try { apply(localStorage.getItem(KEY) || "system"); } catch {}
  window.applyFoxTunnelTheme = apply;
})();

