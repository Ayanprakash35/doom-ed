// SPDX-License-Identifier: GPL-3.0-or-later
/* Boot script: theme bootstrap, KaTeX CSS fallback, and vendor loader.
   Loaded synchronously in <head> to avoid theme flash and satisfy strict CSP. */

(function () {
  "use strict";

  // 1. Theme bootstrap: avoid a flash of the wrong theme. Key: doomed.theme (light|dark).
  try {
    var saved = localStorage.getItem("doomed.theme");
    var prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    var nextTheme = saved === "dark" || saved === "light" ? saved : (prefersDark ? "dark" : "light");
    document.documentElement.setAttribute("data-theme", nextTheme);
    document.documentElement.style.colorScheme = nextTheme;
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "light");
    document.documentElement.style.colorScheme = "light";
  }

  // 2. KaTeX CSS fallback (replaces inline onerror handler).
  var KATEX_CDN_CSS = "https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.css";
  var katexCss = document.getElementById("katex-css");
  if (katexCss && !katexCss.sheet) {
    var localKatexHref = katexCss.getAttribute("href") || "/assets/vendor/katex.min.css";
    var probe = document.createElement("link");
    probe.id = "katex-css";
    probe.rel = "stylesheet";
    probe.addEventListener("error", function onKatexCssError() {
      probe.removeEventListener("error", onKatexCssError);
      probe.href = KATEX_CDN_CSS;
    });
    probe.href = localKatexHref;
    katexCss.parentNode.replaceChild(probe, katexCss);
  }

  // 3. Vendor loader: local first (/assets/vendor/, no network needed), then CDN
  //    fallbacks (jsdelivr -> unpkg; cdnjs -> jsdelivr for PDF.js).
  //    app.js must `await window.__vendorReady` before first render.
  var SOURCES = {
    marked: [
      "/assets/vendor/marked.min.js",
      "https://cdn.jsdelivr.net/npm/marked@14.1.2/marked.min.js",
      "https://unpkg.com/marked@14.1.2/marked.min.js"
    ],
    katex: [
      "/assets/vendor/katex.min.js",
      "https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.js",
      "https://unpkg.com/katex@0.16.11/dist/katex.min.js"
    ],
    dompurify: [
      "/assets/vendor/purify.min.js",
      "https://cdn.jsdelivr.net/npm/dompurify@3.1.7/dist/purify.min.js",
      "https://unpkg.com/dompurify@3.1.7/dist/purify.min.js"
    ],
    mermaid: [
      "/assets/vendor/mermaid.min.js",
      "https://cdn.jsdelivr.net/npm/mermaid@11.3.0/dist/mermaid.min.js",
      "https://unpkg.com/mermaid@11.3.0/dist/mermaid.min.js"
    ],
    pdfjs: [
      "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js",
      "https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.min.js"
    ]
  };
  var PDF_WORKERS = [
    "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js",
    "https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.worker.min.js"
  ];

  function loadOne(urls) {
    return new Promise(function (resolve) {
      var i = 0;
      (function attempt() {
        if (i >= urls.length) { resolve(false); return; }
        var el = document.createElement("script");
        el.src = urls[i++];
        el.async = true;
        el.onload = function () { resolve(true); };
        el.onerror = function () { el.remove(); attempt(); };
        document.head.appendChild(el);
      })();
    });
  }

  var names = Object.keys(SOURCES);
  window.__vendorReady = Promise.all(names.map(function (n) { return loadOne(SOURCES[n]); }))
    .then(function (results) {
      var ok = {};
      names.forEach(function (n, i) { ok[n] = results[i]; });
      window.__vendors = ok;
      if (ok.pdfjs) {
        window.__PDFJS_WORKER_SRC = PDF_WORKERS[0];
        window.__PDFJS_WORKER_FALLBACK = PDF_WORKERS[1];
      }
      return ok;
    });
})();
