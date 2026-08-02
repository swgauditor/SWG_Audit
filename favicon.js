/* Ensure the browser tab shows the SWG Audit favicon.
   Mintlify custom-mode pages often omit <link rel="icon"> tags. */
(function () {
  if (window.__swgFavicon) return;
  window.__swgFavicon = true;
  if (document.querySelector('link[rel="icon"], link[rel="shortcut icon"]')) return;
  var head = document.head || document.getElementsByTagName("head")[0];
  if (!head) return;
  [
    { rel: "icon", type: "image/png", href: "/favicon.png", sizes: "48x48" },
    { rel: "shortcut icon", type: "image/x-icon", href: "/favicon.ico" },
    { rel: "apple-touch-icon", href: "/apple-touch-icon.png" },
  ].forEach(function (spec) {
    var link = document.createElement("link");
    Object.keys(spec).forEach(function (k) { link.setAttribute(k, spec[k]); });
    head.appendChild(link);
  });
})();
