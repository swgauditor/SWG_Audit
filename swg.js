/* =========================================================================
   SWG Audit v3 — Mintlify prototype client logic (Phase 1)
   Loaded once; uses document-level event delegation so it keeps working
   across Mintlify's client-side (SPA) navigation. No backend required:
   every test either downloads a static file or reconstructs one in the
   browser (base64 decode, AES-GCM decrypt, or chunk reassembly).
   ========================================================================= */
(function () {
  if (window.__swgInit) return;
  window.__swgInit = true;

  /* Mintlify sometimes omits <link rel="icon"> in custom-mode pages.
     Ensure the tab icon is set from the site favicon assets. */
  (function ensureFavicon() {
    if (document.querySelector('link[rel="icon"], link[rel="shortcut icon"]')) return;
    var icons = [
      { rel: "icon", type: "image/png", href: "/favicon.png", sizes: "48x48" },
      { rel: "icon", type: "image/x-icon", href: "/favicon.ico" },
      { rel: "apple-touch-icon", href: "/apple-touch-icon.png" },
    ];
    var head = document.head || document.getElementsByTagName("head")[0];
    if (!head) return;
    icons.forEach(function (spec) {
      var link = document.createElement("link");
      Object.keys(spec).forEach(function (k) { link.setAttribute(k, spec[k]); });
      head.appendChild(link);
    });
  })();

  /* The v2 access flow is intentionally enabled for v3.  A verified session
     identifies the visitor for test-result tracking without exposing its token
     to the DOM or to individual simulation endpoints. */
  // Set to true to restore the v3 work-email + reCAPTCHA access gate.
  var TEST_ACCESS_GATE_ENABLED = false;
  var testAccessGate = (function () {
    if (!TEST_ACCESS_GATE_ENABLED) return { hasAccess: function () { return true; } };
    var sessionKey = "swgaudit-v3-test-session";
    var accessGranted = false;
    var rememberedToken = "";
    var dialog, form, status, emailInput, recaptchaContainer, submitButton;
    var widgetId = null;
    var recaptchaPromise = null;

    try { rememberedToken = window.sessionStorage.getItem(sessionKey) || ""; } catch (error) {}

    function injectStyles() {
      if (document.getElementById("swg-test-access-styles")) return;
      var style = document.createElement("style");
      style.id = "swg-test-access-styles";
      style.textContent = ".test-access-overlay{position:fixed;inset:0;z-index:2147483647;display:grid;place-items:center;padding:20px;background:rgba(3,7,18,.88);backdrop-filter:blur(7px)}.test-access-dialog{width:min(100%,480px);padding:30px;border:1px solid #314363;border-radius:16px;background:#0d1627;color:#edf4ff;box-shadow:0 24px 80px rgba(0,0,0,.55)}.test-access-dialog h2{margin:6px 0 10px;font-size:26px}.test-access-eyebrow{margin:0;color:#80aaff;font-weight:700;text-transform:uppercase;letter-spacing:.1em;font-size:12px}.test-access-safety-note{margin:0 0 22px;color:#bac8dc}.test-access-dialog label{display:block;margin-bottom:7px;font-weight:600}.test-access-dialog input{box-sizing:border-box;width:100%;padding:12px;border:1px solid #4b6084;border-radius:8px;background:#101c31;color:#fff}.test-access-recaptcha{margin:20px 0}.test-access-status{min-height:22px;margin:10px 0;color:#ffb4b4}.test-access-submit{width:100%;padding:12px;border:0;border-radius:8px;background:#5b8cff;color:#061124;font-weight:800;cursor:pointer}.test-access-submit:disabled{opacity:.6;cursor:wait}.test-access-honeypot{position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden}";
      document.head.appendChild(style);
    }

    function setStatus(message) { status.textContent = message || ""; }
    function loadRecaptcha() {
      if (window.grecaptcha && window.grecaptcha.render) return Promise.resolve();
      if (recaptchaPromise) return recaptchaPromise;
      recaptchaPromise = new Promise(function (resolve, reject) {
        window.swgAuditRecaptchaReady = resolve;
        var script = document.createElement("script");
        script.src = "https://www.google.com/recaptcha/api.js?onload=swgAuditRecaptchaReady&render=explicit";
        script.async = true;
        script.defer = true;
        script.onerror = function () { reject(new Error("reCAPTCHA could not be loaded.")); };
        document.head.appendChild(script);
      });
      return recaptchaPromise;
    }

    function close() {
      accessGranted = true;
      window.__swgAccessToken = rememberedToken;
      if (dialog) dialog.remove();
      document.body.classList.remove("has-test-access-gate");
    }

    function buildDialog() {
      injectStyles();
      dialog = document.createElement("div");
      dialog.className = "test-access-overlay";
      dialog.setAttribute("role", "dialog");
      dialog.setAttribute("aria-modal", "true");
      dialog.setAttribute("aria-labelledby", "test-access-title");
      dialog.innerHTML = '<div class="test-access-dialog"><p class="test-access-eyebrow">Security verification</p><h2 id="test-access-title">Verify to enter SWG Audit</h2><p class="test-access-safety-note">All tests are safe and no real threats are delivered. Your email, IP-derived location, and test activity are recorded for the SWG Audit dashboard.</p><form data-test-access-form><div data-test-access-email-row><label for="test-access-email">Work email</label><input id="test-access-email" name="email" type="email" autocomplete="email" maxlength="254" placeholder="you@company.com" required></div><div class="test-access-recaptcha" data-test-access-recaptcha aria-label="reCAPTCHA verification"></div><div class="test-access-honeypot" aria-hidden="true"><label for="test-access-company">Company website</label><input id="test-access-company" name="company" type="text" tabindex="-1" autocomplete="off"></div><p class="test-access-status" data-test-access-status aria-live="polite"></p><button class="test-access-submit" type="submit" data-test-access-submit>Verify and enter site</button></form></div>';
      document.body.appendChild(dialog);
      document.body.classList.add("has-test-access-gate");
      form = dialog.querySelector("[data-test-access-form]");
      status = dialog.querySelector("[data-test-access-status]");
      emailInput = dialog.querySelector("#test-access-email");
      recaptchaContainer = dialog.querySelector("[data-test-access-recaptcha]");
      submitButton = dialog.querySelector("[data-test-access-submit]");
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        if (!form.reportValidity()) return;
        var recaptchaResponse = widgetId === null ? "" : window.grecaptcha.getResponse(widgetId);
        if (!recaptchaResponse) { setStatus("Complete the reCAPTCHA challenge."); return; }
        submitButton.disabled = true;
        var payload = Object.fromEntries(new FormData(form).entries());
        payload.page = window.location.pathname;
        payload.recaptcha_response = recaptchaResponse;
        fetch("/test-access.php", { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json" }, body: JSON.stringify(payload) })
          .then(function (response) { return response.json().then(function (result) { if (!response.ok) throw new Error(result.error || "Verification failed."); return result; }); })
          .then(function (result) {
            rememberedToken = result.token || "";
            try { window.sessionStorage.setItem(sessionKey, rememberedToken); } catch (error) {}
            close();
          })
          .catch(function (error) { setStatus(error.message || "Verification failed. Please try again."); if (widgetId !== null) window.grecaptcha.reset(widgetId); })
          .finally(function () { submitButton.disabled = false; });
      });
    }

    function open() {
      buildDialog();
      submitButton.disabled = true;
      fetch("/test-access.php", { headers: { Accept: "application/json" }, cache: "no-store" })
        .then(function (response) { return response.json().then(function (result) { if (!response.ok) throw new Error(result.error || "Verification is unavailable."); return result; }); })
        .then(function (result) {
          return loadRecaptcha().then(function () {
            widgetId = window.grecaptcha.render(recaptchaContainer, { sitekey: result.site_key, theme: "dark", callback: function () { form.requestSubmit(); } });
            emailInput.focus();
          });
        })
        .catch(function (error) { setStatus(error.message || "Verification is unavailable."); })
        .finally(function () { submitButton.disabled = false; });
    }

    open();
    return { hasAccess: function () { return accessGranted; } };
  })();

  function trackTestResult(outcome) {
    var token = window.__swgAccessToken;
    if (!token) return;
    fetch("/test-access.php", {
      method: "POST",
      keepalive: true,
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ action: "activity", token: token, test: window.location.pathname, outcome: outcome })
    }).catch(function () {});
  }

  function closeMobileSidebar() {
    document.documentElement.classList.remove("swg-mobile-sb-open");
    document.querySelectorAll("[data-mobile-sb-toggle]").forEach(function (btn) {
      btn.setAttribute("aria-expanded", "false");
    });
  }

  var lastMobileSidebarTouch = 0;

  function toggleMobileSidebarFrom(control) {
    var willOpen = !document.documentElement.classList.contains("swg-mobile-sb-open");
    document.documentElement.classList.toggle("swg-mobile-sb-open", willOpen);
    if (control) control.setAttribute("aria-expanded", willOpen ? "true" : "false");
  }

  function handleMobileSidebarActivation(event) {
    var mobileToggle = event.target.closest && event.target.closest("[data-mobile-sb-toggle]");
    var isMobileSidebarControl = mobileToggle || (event.target.hasAttribute && event.target.hasAttribute("data-mobile-sb-close"));
    if (isMobileSidebarControl && Date.now() - lastMobileSidebarTouch < 250) {
      event.preventDefault();
      event.stopPropagation();
      return true;
    }

    if (mobileToggle) {
      event.preventDefault();
      event.stopPropagation();
      lastMobileSidebarTouch = Date.now();
      toggleMobileSidebarFrom(mobileToggle);
      return true;
    }

    if (event.target.hasAttribute && event.target.hasAttribute("data-mobile-sb-close")) {
      event.preventDefault();
      event.stopPropagation();
      lastMobileSidebarTouch = Date.now();
      closeMobileSidebar();
      return true;
    }

    return false;
  }

  function initMobileSidebar() {
    document.querySelectorAll(".swg-audit-ui").forEach(function (app) {
      var nav = app.querySelector(".swg-nav");
      var sidebar = app.querySelector(".swg-sb");
      if (!nav || !sidebar || nav.querySelector("[data-mobile-sb-toggle]")) return;

      var button = document.createElement("button");
      button.className = "swg-mobile-menu";
      button.type = "button";
      button.setAttribute("data-mobile-sb-toggle", "");
      button.setAttribute("aria-expanded", "false");
      button.setAttribute("aria-controls", "swg-mobile-tests");
      button.setAttribute("aria-label", "Open tests menu");
      button.innerHTML = '<span class="swg-mobile-menu-icon" aria-hidden="true"><i></i><i></i><i></i></span><span class="swg-mobile-menu-text">Tests</span>';
      nav.insertBefore(button, nav.firstChild);

      if (!sidebar.id) sidebar.id = "swg-mobile-tests";
      var overlay = document.createElement("div");
      overlay.className = "swg-mobile-sb-backdrop";
      overlay.setAttribute("data-mobile-sb-close", "");
      overlay.setAttribute("role", "presentation");
      overlay.setAttribute("aria-label", "Close tests menu");
      app.appendChild(overlay);
    });
  }

  /* ---- helpers --------------------------------------------------------- */
  function base64ToBytes(value) {
    var binary = window.atob(value.replace(/\s+/g, ""));
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function base32ToBytes(value) {
    var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    var clean = value.toUpperCase().replace(/=+$/g, "").replace(/\s+/g, "");
    var bits = "";
    var out = [];
    for (var i = 0; i < clean.length; i += 1) {
      var index = alphabet.indexOf(clean.charAt(i));
      if (index === -1) throw new Error("Invalid Base32 payload.");
      bits += index.toString(2).padStart(5, "0");
      while (bits.length >= 8) {
        out.push(parseInt(bits.slice(0, 8), 2));
        bits = bits.slice(8);
      }
    }
    return new Uint8Array(out);
  }

  function downloadBytes(bytes, filename, mime) {
    var blob = new Blob([bytes], { type: mime || "application/octet-stream" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename || "download";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
  }

  function runConsoleFor(el) {
    var run = el && el.closest && el.closest(".swg-run");
    return run ? run.querySelector("[data-smuggle-console], [data-test-console]") : null;
  }

  function clearTimers(consoleEl) {
    if (!consoleEl) return;
    (consoleEl.__swgTimers || []).forEach(function (timer) { clearTimeout(timer); });
    consoleEl.__swgTimers = [];
  }

  function startConsole(el, command) {
    var consoleEl = runConsoleFor(el);
    if (!consoleEl) return null;
    clearTimers(consoleEl);
    consoleEl.innerHTML =
      '<div class="swg-console-line"><span class="swg-console-prompt">$</span> ' +
      command +
      "</div>";
    return consoleEl;
  }

  function terminalLine(el, text, state) {
    var consoleEl = runConsoleFor(el);
    if (!consoleEl) return;
    var line = document.createElement("div");
    line.className = "swg-console-line";
    if (state) line.classList.add("swg-console-" + state);
    line.textContent = text;
    consoleEl.appendChild(line);
    consoleEl.scrollTop = consoleEl.scrollHeight;
  }

  function terminalPass(el, text) {
    terminalLine(el, "Your perimeter security has passed. " + sentenceCase(text), "pass");
    trackTestResult("passed");
  }

  function terminalFail(el, text) {
    terminalLine(el, "Your perimeter security has failed. " + sentenceCase(text), "fail");
    trackTestResult("failed");
  }

  function sentenceCase(text) {
    var value = String(text || "").trim();
    return value ? value.charAt(0).toUpperCase() + value.slice(1) : "";
  }

  function hideBanner(fromEl) {
    var run = fromEl && fromEl.closest && fromEl.closest(".swg-run");
    var banner = run && run.querySelector(".swg-banner");
    if (!banner) return;
    banner.hidden = true;
    banner.setAttribute("hidden", "");
  }

  function isBlockedFetchError(err) {
    if (!err) return false;
    var msg = String(err.message || err);
    if (err instanceof TypeError) return true;
    if (msg === "Failed to fetch" || msg.indexOf("NetworkError") !== -1) return true;
    if (/Download request failed|Manifest request failed|Chunk request failed|WebAssembly module request failed|Unable to load|Request blocked/.test(msg)) return true;
    if (/HTTP (403|451|502|503)\b/.test(msg)) return true;
    return false;
  }

  function isBlockedHttpError(err) {
    if (!err) return false;
    if (isBlockedFetchError(err)) return true;
    var msg = String(err.message || err);
    if (/HTTP (400|403|404|405|408|410|451|502|503)\b/.test(msg)) return true;
    return false;
  }

  function reportBlockedSubmission(el, out, pagePath, passText, outputText) {
    terminalPass(el, passText);
    setPersistentOutput(out, outputText || "Test passed.", "is-pass", pagePath);
  }

  function reportIncompleteSubmission(el, out, detail) {
    terminalLine(el, detail || "submission could not complete.");
    setOutput(out, "Test could not complete. Please retry.");
  }

  function runDownloadTest(url, name, mime, revealFrom, command) {
    if (!url) return;
    if (revealFrom) {
      startConsole(revealFrom, command || "swg-audit fetch");
      terminalLine(revealFrom, "requesting file ...");
    }
    return buildDirect(url, name, mime)
      .then(function (out) {
        downloadBytes(out.bytes, name || out.filename, mime || out.mime);
        terminalFail(revealFrom, "download request was allowed.");
        terminalLine(revealFrom, "file was downloaded: " + (name || out.filename));
        revealBanner(revealFrom);
      })
      .catch(function (err) {
        if (isBlockedFetchError(err)) {
          terminalPass(revealFrom, "the download was blocked or could not complete.");
          hideBanner(revealFrom);
          return;
        }
        terminalLine(revealFrom, "download result could not be verified automatically.");
        hideBanner(revealFrom);
      });
  }

  function runLinkDownload(url, name, revealFrom, command) {
    if (!url) return;
    if (revealFrom) {
      startConsole(revealFrom, command || "swg-audit fetch --channel=external");
      terminalLine(revealFrom, "requesting external file: " + url);
    }
    // These channels are cross-origin (cleartext HTTP host or cloud storage), so
    // the same-origin policy blocks a fetch() and we cannot read the response.
    // Open the delivery URL in a new tab instead: if the gateway lets the tab
    // open, the delivery went through and the test FAILS; if the browser/gateway
    // blocks the tab, it PASSES.
    var opened = openNewTab(url);
    if (opened) {
      terminalFail(revealFrom, "external delivery opened in a new tab.");
      revealBanner(revealFrom);
    } else {
      terminalPass(revealFrom, "external delivery was blocked before it could open.");
      hideBanner(revealFrom);
    }
  }

  function openProtectedUrl(url, revealFrom, failText, passText) {
    if (!url) return;
    return fetch(url, { cache: "no-store" })
      .then(function (response) {
        if (!response.ok) throw new Error("Request blocked: HTTP " + response.status);
        var opened = openNewTab(url);
        if (!opened) {
          terminalPass(revealFrom, passText || "request was blocked by the browser.");
          hideBanner(revealFrom);
          return;
        }
        terminalFail(revealFrom, failText);
        revealBanner(revealFrom);
      })
      .catch(function (err) {
        if (isBlockedFetchError(err)) {
          terminalPass(revealFrom, passText || "request was blocked or could not complete.");
          hideBanner(revealFrom);
          return;
        }
        terminalLine(revealFrom, "request result could not be verified automatically.");
        hideBanner(revealFrom);
      });
  }

  function derivePayloadKey(password, salt) {
    return crypto.subtle
      .importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"])
      .then(function (material) {
        return crypto.subtle.deriveKey(
          { name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: 200000 },
          material,
          { name: "AES-GCM", length: 256 },
          false,
          ["decrypt"]
        );
      });
  }

  /* ---- payload builders (mirror the live app's client-side tests) ------ */
  function buildAssembled(url) {
    return fetch(url, { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (p) {
        if (p.mode === "decode-base64") {
          return { bytes: base64ToBytes(p.payload), filename: p.filename, mime: p.mime };
        }
        if (p.mode === "decode-base32") {
          return { bytes: base32ToBytes(p.payload), filename: p.filename, mime: p.mime };
        }
        if (p.mode === "decrypt-aes-gcm") {
          var salt = base64ToBytes(p.salt);
          var iv = base64ToBytes(p.iv);
          var ct = base64ToBytes(p.payload);
          return derivePayloadKey(p.password || "123456", salt).then(function (key) {
            return crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ct).then(function (out) {
              return { bytes: new Uint8Array(out), filename: p.filename, mime: p.mime };
            });
          });
        }
        throw new Error("Unsupported assembly mode.");
      });
  }

  function buildChunk(url) {
    return fetch(url, { cache: "no-store" })
      .then(function (r) {
        if (!r.ok) throw new Error("Manifest request failed.");
        return r.json();
      })
      .then(function (manifest) {
        function fetchChunk(chunk) {
          return fetch(chunk.url, { cache: "no-store" }).then(function (r) {
            if (!r.ok) throw new Error("Chunk request failed: " + chunk.url);
            return r.text().then(function (text) {
              return {
                include: chunk.include !== false,
                order: Number(chunk.order),
                text: text.replace(/\r?\n$/, ""),
                transform: chunk.transform || "none",
              };
            });
          });
        }
        var seq;
        if (manifest.fetchMode === "parallel") {
          seq = Promise.all(manifest.chunks.map(fetchChunk));
        } else {
          seq = manifest.chunks.reduce(function (acc, chunk) {
            return acc.then(function (list) {
              return fetchChunk(chunk).then(function (c) { list.push(c); return list; });
            });
          }, Promise.resolve([]));
        }
        return seq.then(function (chunks) {
          var text = chunks
            .filter(function (c) { return c.include; })
            .sort(function (a, b) { return a.order - b.order; })
            .map(function (c) {
              return c.transform === "reverse-content"
                ? Array.from(c.text).reverse().join("")
                : c.text;
            })
            .join("");
          return {
            bytes: new TextEncoder().encode(text),
            filename: manifest.filename || "eicar-chunk-attack.txt",
            mime: manifest.mime || "text/plain",
          };
        });
      });
  }

  function buildDirect(url, name, mime) {
    return fetch(url, { cache: "no-store" }).then(function (r) {
      if (!r.ok) throw new Error("Download request failed: " + url);
      return r.arrayBuffer().then(function (buf) {
        return { bytes: new Uint8Array(buf), filename: name || url.split("/").pop(), mime: mime };
      });
    });
  }

  function buildWasm(url, name, mime) {
    return fetch(url, { cache: "no-store" })
      .then(function (r) {
        if (!r.ok) throw new Error("WebAssembly module request failed.");
        return r.arrayBuffer();
      })
      .then(function (buffer) {
        return WebAssembly.instantiate(buffer, {});
      })
      .then(function (result) {
        var exports = result.instance.exports;
        if (!exports.a || typeof exports.c !== "function") {
          throw new Error("Unexpected WebAssembly module exports.");
        }
        if (typeof exports.b === "function") exports.b();
        var pointer = exports.c();
        var memory = new Uint8Array(exports.a.buffer);
        var end = pointer;
        while (end < memory.length && memory[end] !== 0) end += 1;
        if (end === pointer) throw new Error("WebAssembly module returned an empty payload.");
        return {
          bytes: memory.slice(pointer, end),
          filename: name || "eicar.txt",
          mime: mime || "text/plain",
        };
      });
  }

  function clickDownloadLink(url, name, revealFrom, command, mime) {
    return runDownloadTest(url, name, mime, revealFrom, command);
  }

  function extractSmugglingPayload(format) {
    var carrier = document.querySelector('[data-smuggling-carrier="' + format + '"]');
    if (!carrier && format === "css") {
      carrier = document.querySelector('[data-smuggling-carrier="html"]');
      return carrier ? carrier.getAttribute("data-smuggling-payload") || "" : "";
    }
    if (!carrier) return "";

    if (format === "html" || format === "js") {
      return carrier.getAttribute("data-smuggling-payload") || "";
    }

    if (format === "css") {
      var cssMatch = carrier.textContent.match(/--smuggled-payload:\s*["']([A-Za-z0-9+/=\s]+)["']/);
      return cssMatch ? cssMatch[1] : "";
    }

    if (format === "svg") {
      var payload = carrier.querySelector("metadata");
      return payload ? payload.textContent : "";
    }

    return "";
  }

  function buildSmuggled(format, name) {
    var payload = extractSmugglingPayload(format).replace(/\s+/g, "");
    if (!payload) throw new Error(format.toUpperCase() + " smuggling payload was not found.");
    return Promise.resolve({
      bytes: base64ToBytes(payload),
      filename: name || format + "_smuggling.docm",
      mime: "application/vnd.ms-word.document.macroEnabled.12",
    });
  }

  /* ---- chip pickers ---------------------------------------------------- */
  function activeChip(groupId) {
    var group = document.querySelector('[data-pick="' + groupId + '"]');
    if (!group) return null;
    return group.querySelector("[data-chip].is-active") || group.querySelector("[data-chip]");
  }


  function activeDropdownOption(groupId) {
    var dd = document.querySelector('[data-dd-dl="' + groupId + '"]');
    if (!dd) return null;
    return dd.querySelector("[data-dd-opt].is-active") || dd.querySelector("[data-dd-opt]");
  }

  function activePick(groupId) {
    return activeDropdownOption(groupId) || activeChip(groupId);
  }

  function smugglingConsoleFor(el) {
    var run = el && el.closest(".swg-run");
    return run ? run.querySelector("[data-smuggle-console]") : null;
  }

  function smugglingCarrierLabel(chip) {
    return (chip && (chip.textContent || chip.getAttribute("data-carrier")) || "html").trim().toLowerCase();
  }

  function resetSmugglingConsole(chip) {
    var consoleEl = smugglingConsoleFor(chip);
    if (!consoleEl) return;
    consoleEl.innerHTML =
      '<div class="swg-console-line"><span class="swg-console-prompt">$</span> swg-audit run --carrier=' +
      smugglingCarrierLabel(chip) +
      '<span class="swg-console-cursor"></span></div>';
  }

  function initSmugglingConsoles() {
    document.querySelectorAll("[data-smuggle-console]").forEach(function (consoleEl) {
      var run = consoleEl.closest(".swg-run");
      var chip = run && run.querySelector("[data-chip].is-active");
      if (chip && !consoleEl.textContent.trim()) resetSmugglingConsole(chip);
    });
  }

  function initTestConsoles() {
    document.querySelectorAll("[data-test-console]").forEach(function (consoleEl) {
      if (!consoleEl.textContent.trim()) {
        consoleEl.innerHTML = '<div class="swg-console-line"><span class="swg-console-prompt">$</span> swg-audit ready</div>';
      }
    });
  }

  function revealBanner(fromEl) {
    hideBanner(fromEl);
  }

  function closeAllDropdowns() {
    document.querySelectorAll("[data-dd].is-open").forEach(function (dd) {
      dd.classList.remove("is-open");
      var m = dd.querySelector("[data-dd-menu]");
      if (m) m.hidden = true;
    });
  }

  function openNewTab(url) {
    var opened = window.open(url, "_blank");
    if (opened) { try { opened.opener = null; } catch (e) {} }
    return opened;
  }

  function isNewTabActivation(event) {
    return event && (event.button === 1 || event.ctrlKey || event.metaKey);
  }

  function downloadTarget(control) {
    if (!control) return null;
    var reveal = control.closest("[data-reveal]");
    if (reveal) {
      return { url: reveal.getAttribute("href"), name: (reveal.getAttribute("href") || "").split("/").pop(), kind: "direct" };
    }

    var single = control.closest("[data-single-download]");
    if (single) {
      return { url: single.getAttribute("data-url"), name: single.getAttribute("data-name"), kind: "direct" };
    }

    var dl = control.closest("[data-dl]");
    if (!dl) return null;
    var sel = activePick(dl.getAttribute("data-dl"));
    if (!sel) return null;
    var kind = sel.getAttribute("data-kind") || "direct";
    return {
      url: sel.getAttribute("data-url"),
      name: sel.getAttribute("data-name"),
      mime: sel.getAttribute("data-mime"),
      carrier: sel.getAttribute("data-carrier"),
      kind: kind,
    };
  }

  function handleDownloadNewTabActivation(event) {
    if (!isNewTabActivation(event)) return false;
    var control = event.target.closest("[data-reveal], [data-single-download], [data-dl]");
    var target = downloadTarget(control);
    if (!target || (!target.url && target.kind !== "smuggle")) return false;
    event.preventDefault();
    event.stopPropagation();
    startConsole(control, "swg-audit fetch --new-tab" + (target.name ? " --file=" + target.name : ""));
    terminalLine(control, "opening delivery URL in a new tab ...");
    var opened = openNewTab("about:blank");
    if (!opened) {
      terminalPass(control, "download delivery was blocked before it could open.");
      hideBanner(control);
      return true;
    }

    if (target.kind === "direct" || target.kind === "link") {
      opened.location.href = target.url;
      terminalFail(control, "download delivery opened in a new tab.");
      revealBanner(control);
      return true;
    }

    control.setAttribute("aria-busy", "true");
    terminalLine(control, "assembling file for the new tab ...");
    var work;
    if (target.kind === "assemble") work = buildAssembled(target.url);
    else if (target.kind === "wasm") work = buildWasm(target.url, target.name, target.mime);
    else if (target.kind === "chunk") work = buildChunk(target.url);
    else if (target.kind === "smuggle") work = buildSmuggled(target.carrier || "html", target.name);
    else work = buildDirect(target.url, target.name, target.mime);

    work
      .then(function (out) {
        var blobUrl = URL.createObjectURL(new Blob([out.bytes], { type: target.mime || out.mime || "application/octet-stream" }));
        opened.location.href = blobUrl;
        setTimeout(function () { URL.revokeObjectURL(blobUrl); }, 15000);
        terminalFail(control, "file was assembled and opened in a new tab.");
        revealBanner(control);
      })
      .catch(function (err) {
        try { opened.close(); } catch (error) {}
        if (isBlockedFetchError(err)) {
          terminalPass(control, "the download was blocked or could not complete.");
          hideBanner(control);
          return;
        }
        terminalLine(control, "download result could not be verified automatically.");
        hideBanner(control);
      })
      .finally(function () {
        control.removeAttribute("aria-busy");
      });
    return true;
  }

  function testId() {
    if (crypto.randomUUID) return crypto.randomUUID().replaceAll("-", "");
    var bytes = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(bytes, function (b) { return b.toString(16).padStart(2, "0"); }).join("");
  }

  function makeDummyMicrosoftLoginHtml() {
    return "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <title>SWG Audit Test - Dummy Microsoft Login</title>\n  <style>\n    * { box-sizing: border-box; }\n    body {\n      min-height: 100vh;\n      margin: 0;\n      display: grid;\n      place-items: center;\n      color: #1b1b1b;\n      background:\n        radial-gradient(circle at 12% 15%, rgba(0, 120, 215, 0.12), transparent 32rem),\n        radial-gradient(circle at 85% 72%, rgba(243, 119, 53, 0.11), transparent 26rem),\n        linear-gradient(135deg, #f6f8fc, #fff);\n      font-family: \"Segoe UI\", Arial, sans-serif;\n    }\n    main { width: min(440px, calc(100% - 36px)); }\n    .panel {\n      width: 100%;\n      min-height: 338px;\n      padding: 44px;\n      background: #fff;\n      box-shadow: 0 6px 18px rgba(0, 0, 0, 0.22);\n    }\n    .brand {\n      display: flex;\n      align-items: center;\n      gap: 7px;\n      color: #737373;\n      font-size: 26px;\n      font-weight: 600;\n    }\n    .mark {\n      width: 24px;\n      height: 24px;\n      display: grid;\n      grid-template-columns: repeat(2, 1fr);\n      gap: 2px;\n    }\n    .mark span:nth-child(1) { background: #f35325; }\n    .mark span:nth-child(2) { background: #81bc06; }\n    .mark span:nth-child(3) { background: #05a6f0; }\n    .mark span:nth-child(4) { background: #ffba08; }\n    h1 {\n      margin: 24px 0 16px;\n      font-size: 24px;\n      font-weight: 600;\n      line-height: 1.18;\n    }\n    input {\n      width: 100%;\n      height: 36px;\n      border: 0;\n      border-bottom: 1px solid #666;\n      color: #1b1b1b;\n      font-size: 15px;\n      outline: 0;\n    }\n    input::placeholder {\n      color: #666;\n      opacity: 1;\n    }\n    input:focus {\n      border-bottom-color: #0067b8;\n    }\n    .links {\n      display: grid;\n      gap: 18px;\n      margin: 18px 0 0;\n      font-size: 13px;\n    }\n    .links a {\n      color: #0067b8;\n      text-decoration: none;\n    }\n    .actions {\n      display: flex;\n      justify-content: flex-end;\n      gap: 4px;\n      margin-top: 34px;\n    }\n    button {\n      min-width: 108px;\n      min-height: 32px;\n      border: 0;\n      font-size: 15px;\n      cursor: pointer;\n    }\n    .back { background: #ccc; }\n    .next { color: #fff; background: #0067b8; }\n    .options {\n      display: flex;\n      align-items: center;\n      gap: 16px;\n      min-height: 48px;\n      margin-top: 20px;\n      padding: 0 44px;\n      background: #fff;\n      box-shadow: 0 4px 14px rgba(0, 0, 0, 0.16);\n      font-size: 15px;\n    }\n    .key {\n      width: 26px;\n      height: 26px;\n      object-fit: contain;\n    }\n    .result {\n      margin-top: 18px;\n      padding: 12px;\n      border-left: 4px solid #b00020;\n      color: #5f000f;\n      background: #fff3f3;\n      font-size: 13px;\n      line-height: 1.45;\n      word-break: break-word;\n    }\n    @media (max-width: 640px) {\n      .panel { min-height: auto; padding: 42px 28px 48px; }\n      .brand { font-size: 24px; }\n      .mark { width: 28px; height: 28px; }\n      h1 { font-size: 30px; }\n      input { font-size: 20px; }\n      .links, button, .options { font-size: 18px; }\n      .actions { flex-direction: column; }\n      button { width: 100%; }\n      .options { min-height: 64px; padding: 0 28px; }\n      .key { width: 28px; height: 28px; }\n    }\n  </style>\n</head>\n<body>\n  <main>\n    <section class=\"panel\" aria-labelledby=\"dummy-login-title\">\n      <div class=\"brand\" aria-label=\"Microsoft-style dummy brand\">\n        <span class=\"mark\" aria-hidden=\"true\"><span></span><span></span><span></span><span></span></span>\n        <span>Microsoft</span>\n      </div>\n      <h1 id=\"dummy-login-title\">Sign in</h1>\n      <div class=\"result\" id=\"dummy-microsoft-result\" hidden></div>\n      <form id=\"dummy-microsoft-form\">\n        <input id=\"dummy-account\" name=\"dummy-account\" type=\"text\" autocomplete=\"off\" inputmode=\"email\" placeholder=\"Email, phone, or Skype\" aria-label=\"Email, phone, or Skype\">\n        <input id=\"dummy-password\" name=\"dummy-password\" type=\"password\" autocomplete=\"off\" placeholder=\"Password\" aria-label=\"Password\">\n        <div class=\"links\">\n          <span>No account? <a href=\"#\" aria-disabled=\"true\">Create one!</a></span>\n          <a href=\"#\" aria-disabled=\"true\">Can't access your account?</a>\n        </div>\n        <div class=\"actions\">\n          <button class=\"back\" type=\"button\">Back</button>\n          <button class=\"next\" type=\"submit\">Next</button>\n        </div>\n      </form>\n    </section>\n    <section class=\"options\" aria-label=\"Dummy sign-in options\">\n      <img class=\"key\" src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAQAAAAD6CAYAAABODJmtAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAAFiUAABYlAUlSJPAAAA5TSURBVHhe7d09YuJIGoDhb3YPQd0CXaEjdIBJiMQVHJF2SsQVcMQVROQryAeYXOSTe4NBXqzBGL76UZW+90m6W+7tHVvSqyr98cfHx8eHADDpP+MFAOwgAIBhBAAwjAAAhhEAwDACABhGAADDCABgGAEADCMAgGEEADCMAACGEQDAMAIAGEYAAMMIAGAYAQAMIwCAYQQAMIwAAIb9wUtBw+r7/svvhz8Pv57PZ+n7Xpxzn39vsVh8/vn61+u/A8RAADwMO3jXdfL+/i5d143/ijfnnFRVJcvl8vP3QCgE4EEpdvZHEQWEQgDu6Pte2raV8/ksbduOv5wN55ysViupqooY4CkE4Iau6+R0OmW903+HGOAZBOCi6zrpuk5eX1/HXyrWEIO6rjmhiJvMB6DrOtntdl/O3s/NcJ6gaRpCgC/MBsDCjj9GCDBmLgAWd/wxQoCBmQCw4/8bIcDsA9D3vex2u0mv2+duOFm42WzGX8LMzToAbdvKbrcbL8Y3nHOy3+8ZDRgyywBw1NdjNGDL7ALQdZ28vLyMFyflLg/yLJfLL8uuf5UbDw6dz+fP308dL0YDNswmAFMd9YcjZlVVnzt+KMPzB33fy+l0mux7YzQwX7MIQN/3sl6vx4ujuN7hU99qO4wY2rZN+kBSXdey3W7HizEDxQcgxZB/2Olzu6V2mCqkGB045+R4PI4Xo3BFByD2zt80zSRHeo3+8uTi6XSKdq8D5wXmp9gAHA6HaA/uNE1T7Lx3GBW8vr5GCQERmJciA7Db7YI/qju3E14xQzC3n5VlxQXg5eUl+Hy35CP+T2KFgAjMQ1EBCL3zO+dku90WMcf3NZwjCD1tmnM8LSgmACF3fstHr9D3SzjnpGkaqet6/CUUoIgAhJzzV1Ul+/1+vNickCdRLY2k5ib7AITcUBmuftX3vby8vAQ5N8DVgTJlHYBQ1/k5Qn0v5LkBIlCebAMQaudnyP+YUCMtxx2DRckyAKHu7Wfnf06onzvPDpQjyw8HDfESj7qu2fmfNBy9fYfwbdvK4XAYL0aGsgtAiEtUTdNwBFIKNY9P8YAS/GU1BQgx799ut1yTDiDE/QKcD8hfViMA36F/Xdfs/IEMV058RgJ93zMVyFw2AfC9Hl1VFcP+wEJMB5gK5C2LAHSXz+XT4mx/PEMEtIapBPKURQB8NhDfDRQ/853LE4F8TR4A36E/w/40hnMCWm3beo3yEMekAfAd+u/3e27vTcj3JGuIOw0R1qQB8NkgSnlX39z4fI6gb/AR3mQB8NkYmPdPx/dn7xN9hDfZjUA+L/hIMfQfnpJ7f3///LO7fPDHYrEwPwLxeXgoxfrDYyYJgM8df7EfNHnmv204MWZxY/Z5l4DvVQWEM0kAfI7+b29v40XBaI9qVjfoZ2I5xiggD8nPAfjM/WMd+buuk/V6rdr55eoxWs3RsGQ+0yDuC8hD8gBod7KqqrwuQX1nOIr57rzDkNgabZT7DD4BGRMEQLvSm6YZL/IWeqe1eMebc04dZu3BAOEkDYD2zb4+Q817YuysFu9408bZd9QFf0kDcDqdxoseot3A7vE5F/GTGGHJmXYUMFxqxXSSBkCzw8U6+mtj9Ije4HPw2kjHXA/4WbIAaEu/Wq3Gi4LQ/vc8ariByAqfUQCmkywA2hM+mo3qJ7F3frmMdqxt3JpYWxwt5SRZADQ7Q4ydPyXN91wy7XTN2mgpJ0kCoD3iao4oj7C2Y6a0XC7Hi34U84Qs7ksSAM3wX3s0yYnF0GhHbQRgGkkCoNkRYh39Uyo9YBrOOdX3zTRgGtEDoB3+azaiR8X8t6GLt+YgAX/RA6Bdsdq3zjwi5r89qKoqyf9PjjSB1W4n8BM9AOfzebzoR9p55KO0w9RnWN355fK9a75/zgOkFz0AmpWqOZP8LM0w9RnaO+PmggCUIXoANEO72EdnCfCG23vqulbtAHOiCSwnAtOLGgDNCcCUc2efN9x+x3m+P38uNBHXHCzgJ2oANCs09A55T4ydNfS/VyrNetRsL/ATNQCaE4CLxWK8KKqqqoLM193lddmaI99caX4WnAdIK2oANCtTc+TwtdlsvN51X9e1HI9H1QaPrxgFpBU1ABpT7URVVcnxeHxqNDAc9Rn236a5mkMA0or6WvBfv36NF/0o5mu/H9VfXlj5/v7+5bHeYXSyWq3EKZ9/t6RTvDa8aRrZbDbjxYgkqwA4o+/XnytNAGJ/8Au+ijYF0Azlppj/Ix7N+tRsN9CLFgAA+YsWAE3JNUcMAHpZBQDzogk6201a0QIAIH9ZBSD1XYCI79lRACOAtLIKgObWYeSNHTpv0QLwbPkBYbtJLloAAM3RnwCkFS0AmhWp2WAwL5rtBnrRAgAQ9PxFC4Cm5Gww86JZn1wJSitaAEQZAQDpRA3As/q+Vx01kCfNSz45aKQVNQCalUkA5kPzRiikFTUAGgRgPjTrcqo3QlkVNQC8Esou7XrUjBqhFzUAmppr5o3Ij2b4r9le4CdqADQ11x45kBdNyDXbC/xED8CzVe8vL+RE2TSfCqWZMsJP1ABoEYCyaXZ+YQowiegB0FRdM3xEPrTrjylAetEDoKk65wHKphnB8RkL04geAE3VOQ9QrrZtVQHXjBThL0kANKOA19fX8SIUQDv812wj8Bc9AKKsO88FlEk7ctOMFOEvSQA087u+79VnkzENn2jvdrvxIiSQJADaacDpdBovQsa0R3+5nDsgAuklCYB4TAN8Niqk5Xvepm3bpz9MFH6SBUAzDZAAGxXSWa1W40VP67pO1uv1eDEiSRYA7TSg6zpGAYXYbDbSNM148dP6vicCiSQLgHgcIRgFlIMIlCVpADQjAGEUUBwiUI6kAdBOA4QrAsUhAmVIGgARke12O170kLZtGQUUhgjkL3kAfEYBXCcuDxHIW/IAiMcooO97ORwO48XIHBHI1yQB8BkFnE4npgIFIgJ5+uPj4+NjvDAFnxXpnJPj8ThejAIcDocgl3XZBsKYZAQgnqMApgLlYiSQl8kCIB7nAuRycxBTgTIRgXxMGgDnnPoZAblcFdA+foppEYE8TBoAEZGmadQvg+j7nqfHCkYEpjd5AJxzXlOBvu+5P6BgRGBakwdALs8I+EwFeJlE2YjAdLIIgHhOBeQSAa4MlIsITCObAPhOBeRyZYAIlIsIpPff379//x4vnMowAtC+Wlqu/rfaewwwrWG9+WwDIiJ///23nE4n+fPPP8dfwpWsAiCXCPz1119el/eIQNmIQDqT3Qp8T6ghXFVVst/vx4tRCG4bji/LAEjACDjnZL/fe51gtOCREdcUP0MiEFe2AZCAl/ecc7JarWSz2Yy/ZN5wH8Ujt1Ufj0ciMDPZXAW4pa7rYGeFuULwb23bynq9fmjnnxJXB+LJOgAScOXL5TLher1+aLg7Z8Mt1CFGV6mE2g6IwFfZB0AuIwGfOwWvDRu/1dHA8MEbuR/1byEC4WV9DuDaM3PVRznnpGmaYHHJWYif31TnAMY4JxBOMQGQq7l86E8NHs415LBxxxBqh8klABLwe7IegaICIJcItG0bZOVfc5c3FK1Wq1ncQBTj55RTAIQIBFFcAAahVv4tdV0XG4IYO/4gtwBIwO3AagSKDYAEXPnfKekcQazp0bUcAyABtwOLESg6AHI5qx37rUC5Tg+Go/3pdEpyaTPXAAgRUCs+AHJ1aS/FTjDEYLlcTjIySL3TX8s5AEIEVGYRAIk8973nOgjD70Pp+176vpeu6+T9/d3rEl4IuQdAiMDTZhOAQagNwMc4BMvl8nP5tesj+PD74RHYqXf2W0oIgATcBixEYHYBkAlHA3NXSgCECDysiFuBn+WcC3bbKMoUav33M79teJYBGGw2Gzkej0Hn5SgHEfjZrAMgl9HAfr+X7XZLCAwiAvfN8hzAPcMltBxPsuWupHMAY5wTuG32I4Cxuq7Njgjc5c7Gt7e3YndkLUYCt5kbAYxZGBG4G69E07wYpeQRwICRwFfmAzDouk5Op1PUe+lTG474t+5YtBoAIQJfEICR6zvvSozBcLSv6/ruzmo5AEIEPhGAO0qJwaM7/TXrARAiIEIAHncdg+H3U3HOiXNOlsul+lXnBOAf1iNAADykiIK7PFewWCykqqpgVy4IwP9ZjgABCGzYqfrLk3zXy8/n85e/45yTxWLx+XeGnWv4NdTOfosmANvtNkkAYn7f37EaAQJglCYAqby9vY0XJWExAuZuBAK+Y/FmIQIAXLEWAQIAjFiKAAEAbrASAQIAfMNCBAgAcMfcI0AAgB/MOQIEAHjAXCNAAIAHzTECBAB4wtwiQACAJ80pAjwLYNThcPh8OCkmzXsUpnoW4FlzeHaAACAqzUNHpQRAZhABpgCAh9KnAwQA8FRyBAgAEEDICLy8vIwXR0MAgEBCRSAlAgAEVFoECAAQWEkRIABABKVEgAAAkZQQAQIARDTFK86fQQAAwwgAYBjPAiAqzbMA2+12vCiKWx+bHlrXdU/f2FNVlez3+/HiKAgAotIEIIVUD9/kHgCmAIBhBAAwjAAAhhEAwDACABhGAADDCABgGAEADCMAgGEEADCMAACG8SwAosr1E4h4FuAfBACz8OvXr/GiuwjAP5gCAIYRAMAwAgAYRgAAwwgAYBgBAAwjAIBhBAAwjAAAhhEAwDACABjGswCYBc2zAKvVarw4uPP5/PSDSimfBSAAmIVnA5CzlAFgCgAYRgAAwwgAYBgBAAwjAIBhBAAwjAAAhhEAwDACABhGAADDCABgGM8CYBYOh8N4UbGcc1LX9XhxFAQAMIwpAGAYAQAMIwCAYQQAMIwAAIYRAMAwAgAYRgAAwwgAYBgBAAwjAIBhBAAwjAAAhhEAwDACABhGAADDCABgGAEADCMAgGEEADDsfwkh+i7jBYyQAAAAAElFTkSuQmCC\" alt=\"\" aria-hidden=\"true\">\n      <span>Sign-in options</span>\n    </section>\n  </main>\n  <script>\n    const form = document.getElementById(\"dummy-microsoft-form\");\n    const result = document.getElementById(\"dummy-microsoft-result\");\n    const account = document.getElementById(\"dummy-account\");\n    const password = document.getElementById(\"dummy-password\");\n\n    form.addEventListener(\"submit\", (event) => {\n      event.preventDefault();\n      result.hidden = false;\n      result.innerHTML = \"<strong>Test Failed: credential submission was supposed to be blocked.</strong><br>Username: \" + account.value + \"<br>Password: \" + password.value;\n    });\n  </script>\n</body>\n</html>";
  }

  function openClientHtml(html) {
    var blob = new Blob([html], { type: "text/html" });
    var opened = window.open(URL.createObjectURL(blob), "_blank");
    if (opened) { try { opened.opener = null; } catch (e) {} }
    return opened;
  }

  function buildClientMhtml(html) {
    var boundary = "----SWG-Audit-" + testId();
    return [
      "MIME-Version: 1.0",
      'Content-Type: multipart/related; boundary="' + boundary + '"; type="text/html"',
      "X-SWG-Audit-Test: Client-generated MHTML phishing page",
      "",
      "--" + boundary,
      'Content-Type: text/html; charset="utf-8"',
      "Content-Location: https://client-generated.invalid/login.html",
      "",
      html,
      "--" + boundary + "--",
      "",
    ].join("\r\n");
  }

  function extractHtmlFromMhtml(mhtml) {
    var boundaryMatch = mhtml.match(/boundary="?([^";\r\n]+)"?/i);
    if (!boundaryMatch) throw new Error("The generated MHTML has no MIME boundary.");
    var htmlPart = mhtml
      .split("--" + boundaryMatch[1])
      .find(function (part) { return /Content-Type:\s*text\/html\b/i.test(part); });
    if (!htmlPart) throw new Error("The generated MHTML has no HTML part.");
    var contentStart = htmlPart.search(/\r?\n\r?\n/);
    if (contentStart === -1) throw new Error("The generated MHTML HTML part is malformed.");
    return htmlPart.slice(contentStart).replace(/^\r?\n\r?\n/, "").replace(/\r?\n$/, "");
  }

  function buildCanvasHtml() {
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SWG Audit Test - Dummy GitHub Canvas Login</title><style>html,body{width:100%;height:100%;margin:0;overflow:hidden;background:#0d1117}canvas{width:100vw;height:100vh;display:block;outline:none}.kbd{position:fixed;left:50%;top:72%;width:1px;height:1px;padding:0;border:0;opacity:.01;background:transparent;color:transparent;font-size:16px;caret-color:transparent;pointer-events:none}</style></head><body><canvas id="login-canvas" tabindex="0" aria-label="SWG Audit dummy GitHub-style login rendered entirely on canvas"></canvas><input id="canvas-keyboard" class="kbd" autocomplete="off" autocapitalize="none" spellcheck="false" aria-hidden="true"><script>' +
      'const canvas=document.getElementById("login-canvas"),keyboard=document.getElementById("canvas-keyboard"),ctx=canvas.getContext("2d"),state={active:"username",username:"",password:"",submitted:false,boxes:{},scale:1};' +
      'const rr=(x,y,w,h,r)=>{ctx.beginPath();ctx.roundRect(x,y,w,h,r)};' +
      'const write=(v,x,y,s,c,w,a)=>{ctx.fillStyle=c;ctx.font=(w||"400")+" "+s+"px -apple-system,BlinkMacSystemFont,Segoe UI,Arial,sans-serif";ctx.textAlign=a||"left";ctx.textBaseline="middle";ctx.fillText(v,x,y)};' +
      'const input=(n,l,v,x,y,w)=>{write(l,x,y,15,"#f0f6fc","600");const b={x:x,y:y+18,width:w,height:44};state.boxes[n]=b;rr(b.x,b.y,b.width,b.height,6);ctx.fillStyle="#0d1117";ctx.fill();ctx.strokeStyle=state.active===n?"#2f81f7":"#3d444d";ctx.lineWidth=state.active===n?2:1;ctx.stroke();write(v,b.x+12,b.y+b.height/2,16,"#f0f6fc")};' +
      'const draw=()=>{const vw=innerWidth,vh=innerHeight;state.scale=Math.min(1.14,vw/390,vh/650);const w=vw/state.scale,h=vh/state.scale,pw=Math.min(420,w-36),x=(w-pw)/2;let y=Math.max(44,(h-650)/2);state.boxes={};ctx.clearRect(0,0,vw,vh);ctx.save();ctx.scale(state.scale,state.scale);ctx.fillStyle="#0d1117";ctx.fillRect(0,0,w,h);ctx.fillStyle="#f0f6fc";ctx.beginPath();ctx.arc(w/2,y+30,28,0,Math.PI*2);ctx.fill();write("GH",w/2,y+31,16,"#0d1117","800","center");write("Sign in to GitHub",w/2,y+94,26,"#f0f6fc","600","center");y+=138;if(state.submitted){rr(x,y,pw,92,6);ctx.fillStyle="#2d1519";ctx.fill();ctx.strokeStyle="#f85149";ctx.stroke();write("Test Failed: submission was supposed to be blocked.",x+14,y+22,13,"#ffb4b4","700");write("Username: "+state.username,x+14,y+49,13,"#f0f6fc");write("Password: "+state.password,x+14,y+72,13,"#f0f6fc");y+=116}input("username","Username or email address",state.username,x,y,pw);y+=88;write("Forgot password?",x+pw,y,14,"#2f81f7","400","right");input("password","Password","*".repeat(state.password.length),x,y,pw);y+=86;const sub={x:x,y:y,width:pw,height:46};state.boxes.submit=sub;rr(sub.x,sub.y,sub.width,sub.height,6);ctx.fillStyle="#238636";ctx.fill();write("Sign in",w/2,sub.y+sub.height/2,16,"#fff","700","center");y+=82;ctx.strokeStyle="#3d444d";ctx.beginPath();ctx.moveTo(x,y);ctx.lineTo(x+pw*.44,y);ctx.moveTo(x+pw*.56,y);ctx.lineTo(x+pw,y);ctx.stroke();write("or",w/2,y,15,"#8b949e","400","center");write("Continue with Google",w/2,y+55,15,"#f0f6fc","600","center");write("Continue with Apple",w/2,y+102,15,"#f0f6fc","600","center");write("New to GitHub?  Create an account",w/2,y+162,15,"#2f81f7","400","center");ctx.restore()};' +
      'const resize=()=>{const r=devicePixelRatio||1;canvas.width=Math.floor(innerWidth*r);canvas.height=Math.floor(innerHeight*r);ctx.setTransform(r,0,0,r,0,0);draw()};const contains=(p,b)=>b&&p.x>=b.x&&p.x<=b.x+b.width&&p.y>=b.y&&p.y<=b.y+b.height;const syncKeyboard=()=>{keyboard.type=state.active==="password"?"password":"text";keyboard.value=state[state.active];keyboard.setSelectionRange(keyboard.value.length,keyboard.value.length)};const focusField=()=>{syncKeyboard();keyboard.focus({preventScroll:true})};const press=e=>{const p={x:e.clientX/state.scale,y:e.clientY/state.scale};if(contains(p,state.boxes.username)){state.active="username";focusField()}else if(contains(p,state.boxes.password)){state.active="password";focusField()}else if(contains(p,state.boxes.submit)){state.submitted=true;keyboard.blur()}draw()};canvas.addEventListener("pointerdown",e=>{e.preventDefault();press(e)});canvas.addEventListener("touchstart",e=>{if(e.touches&&e.touches[0]){e.preventDefault();press(e.touches[0])}},{passive:false});canvas.addEventListener("mousedown",e=>{press(e)});keyboard.addEventListener("input",()=>{state[state.active]=keyboard.value;draw()});keyboard.addEventListener("keydown",e=>{if(e.key==="Enter"){e.preventDefault();state.submitted=true;keyboard.blur();draw()}else if(e.key==="Tab"){e.preventDefault();state.active=state.active==="username"?"password":"username";focusField();draw()}});canvas.addEventListener("keydown",e=>{if(e.key==="Tab"){e.preventDefault();state.active=state.active==="username"?"password":"username";syncKeyboard()}else if(e.key==="Enter"){e.preventDefault();state.submitted=true}else if(e.key==="Backspace"){e.preventDefault();state[state.active]=state[state.active].slice(0,-1);syncKeyboard()}else if(e.key.length===1&&!e.ctrlKey&&!e.metaKey&&!e.altKey){e.preventDefault();state[state.active]+=e.key;syncKeyboard()}draw()});addEventListener("resize",resize);resize();syncKeyboard();canvas.focus();' +
      '</script></body></html>';
  }

  function cardOutput(form, selector) {
    var run = form.closest(".swg-run") || form;
    return run.querySelector(selector || "[data-test-output]");
  }

  var outputState = {};
  var serverFileState = {};
  var selectedFileState = {};

  function outputMarker(out) {
    if (!out) return "swg-output";
    if (out.hasAttribute("data-test-output")) return "data-test-output";
    if (out.hasAttribute("data-dns-tunnel-status")) return "data-dns-tunnel-status";
    if (out.hasAttribute("data-path-tunnel-status")) return "data-path-tunnel-status";
    return "swg-output";
  }

  function pagePathFor(el) {
    var run = el && el.closest && el.closest(".swg-run");
    return (run && run.getAttribute("data-page-path")) || location.pathname;
  }

  function bindRunPage(runOrChild) {
    var run = runOrChild && runOrChild.closest ? (runOrChild.closest(".swg-run") || runOrChild) : runOrChild;
    if (run && !run.getAttribute("data-page-path")) {
      run.setAttribute("data-page-path", location.pathname);
    }
    return run;
  }

  function outputKey(out) {
    if (!out) return "";
    return pagePathFor(out) + "::" + outputMarker(out);
  }

  function setOutput(out, text, state) {
    if (!out) return;
    out.hidden = false;
    out.removeAttribute("hidden");
    out.style.display = "block";
    out.classList.remove("is-pass", "is-fail");
    if (state) out.classList.add(state);
    out.textContent = text;
  }

  function setPersistentOutput(out, text, state, pagePath) {
    var key = (pagePath || pagePathFor(out)) + "::" + outputMarker(out);
    if (key) outputState[key] = { text: text, state: state };
    setOutput(out, text, state);
  }

  function serverFileKey(button) {
    return button ? pagePathFor(button) + "::open-server-file" : "";
  }

  function showServerFileButton(button, fileUrl) {
    if (!button || !safeUploadUrl(fileUrl)) return;
    button.hidden = false;
    button.removeAttribute("hidden");
    button.style.display = "block";
    button.setAttribute("data-file-url", fileUrl);
    serverFileState[serverFileKey(button)] = fileUrl;
  }

  function restorePersistentResults() {
    document.querySelectorAll(".swg-output").forEach(function (out) {
      var saved = outputState[outputKey(out)];
      if (saved) setOutput(out, saved.text, saved.state);
    });
    document.querySelectorAll("[data-open-server-file]").forEach(function (button) {
      var fileUrl = serverFileState[serverFileKey(button)];
      if (fileUrl) showServerFileButton(button, fileUrl);
    });
  }

  function clearPersistentOutput(out) {
    var key = outputKey(out);
    if (key) delete outputState[key];
  }

  function clearServerFileButton(button) {
    if (!button) return;
    delete serverFileState[serverFileKey(button)];
    button.removeAttribute("data-file-url");
    button.style.display = "";
    button.hidden = true;
    button.setAttribute("hidden", "");
  }

  function serverFileButtonFor(el) {
    var run = el && el.closest && el.closest(".swg-run");
    return run && run.querySelector("[data-open-server-file]");
  }

  function clearRunResult(form, out) {
    clearPersistentOutput(out);
    clearServerFileButton(serverFileButtonFor(form));
  }

  function fileInputKey(input) {
    if (!input) return "";
    var marker =
      input.getAttribute("name") ||
      (input.hasAttribute("data-dns-tunnel-file") ? "dns-tunnel-file" : "") ||
      (input.hasAttribute("data-path-tunnel-file") ? "path-tunnel-file" : "") ||
      "file";
    return pagePathFor(input) + "::" + marker;
  }

  function selectedFile(input) {
    if (!input) return null;
    var nativeFile = input.files && input.files[0];
    var key = fileInputKey(input);
    if (nativeFile) {
      selectedFileState[key] = nativeFile;
      return nativeFile;
    }
    return selectedFileState[key] || null;
  }

  function updateFileLabel(input, file) {
    var field = input && input.closest(".swg-file-field");
    var label = field && field.querySelector("[data-file-name]");
    if (label) label.textContent = file ? file.name : "No file chosen";
  }

  function restoreFileInput(input, file) {
    if (!input || !file || (input.files && input.files[0])) return;
    try {
      var transfer = new DataTransfer();
      transfer.items.add(file);
      input.files = transfer.files;
    } catch (error) {
      // The cached File is still used by the submit handlers if assignment is restricted.
    }
  }

  function initFileControls() {
    document.querySelectorAll('.swg-file-field input[type="file"]').forEach(function (input) {
      var file = selectedFile(input);
      if (file) restoreFileInput(input, file);
      updateFileLabel(input, file);
    });
  }

  function clearSelectedFile(input) {
    if (!input) return;
    delete selectedFileState[fileInputKey(input)];
    input.value = "";
    updateFileLabel(input, null);
  }

  function fileBytes(file) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.addEventListener("load", function () { resolve(new Uint8Array(reader.result)); });
      reader.addEventListener("error", function () { reject(reader.error); });
      reader.readAsArrayBuffer(file);
    });
  }

  function bytesToBase64(bytes) {
    var binary = "";
    for (var offset = 0; offset < bytes.length; offset += 0x8000) {
      binary += String.fromCharCode.apply(null, bytes.subarray(offset, offset + 0x8000));
    }
    return window.btoa(binary);
  }

  function bytesToHex(bytes) {
    return Array.from(bytes, function (byte) { return byte.toString(16).padStart(2, "0"); }).join("");
  }

  function activeMode(form) {
    var option =
      form.querySelector("[data-dd-opt].is-active") ||
      form.querySelector("[data-chip].is-active") ||
      form.querySelector("[data-dd-opt]") ||
      form.querySelector("[data-chip]");
    return option ? option.getAttribute("data-mode") : "";
  }

  function metadata(file) {
    return JSON.stringify({ name: file.name, type: file.type || "application/octet-stream", size: file.size });
  }

  function submitEvasion(formData) {
    return fetch("/data-theft/process_evasion_upload.php", {
      method: "post",
      body: formData,
      headers: { Accept: "application/json" },
    }).then(function (response) {
      if (!response.ok) throw new Error("Submission returned HTTP " + response.status);
      return response.json();
    });
  }

  function readJson(response) {
    return response.text().then(function (text) {
      if (!text) return {};
      try { return JSON.parse(text); }
      catch (error) { return { raw: text }; }
    });
  }

  function runDataTheftForm(form, build, preparingText) {
    bindRunPage(form);
    var pagePath = location.pathname;
    var out = cardOutput(form);
    var button = form.querySelector('button[type="submit"]');
    var input = form.querySelector('input[type="file"]');
    var file = selectedFile(input);
    if (!file) {
      setOutput(out, "Choose a file before running the test.");
      return;
    }
    clearRunResult(form, out);
    startConsole(form, "swg-audit data-theft submit --file=" + file.name);
    terminalLine(form, preparingText);
    setOutput(out, preparingText);
    if (button) button.disabled = true;
    build(file, form)
      .then(function (formData) {
        terminalLine(form, "submitting transformed file to server ...");
        setOutput(out, "Submitting transformed file...");
        return submitEvasion(formData);
      })
      .then(function (result) {
        if (result && result.reconstructed) {
          terminalFail(form, "server reconstructed the submitted file.");
          revealServerFile(form, result.fileUrl);
          setPersistentOutput(out, "Test failed.", "is-fail", pagePath);
          return;
        }
        terminalPass(form, "the server could not reconstruct the submitted file.");
        setPersistentOutput(out, "Test passed.", "is-pass", pagePath);
      })
      .catch(function (err) {
        if (isBlockedHttpError(err)) {
          reportBlockedSubmission(form, out, pagePath, "the server could not reconstruct the submitted file.");
          return;
        }
        reportIncompleteSubmission(form, out, "submission could not complete.");
      })
      .finally(function () {
        if (button) button.disabled = false;
      });
  }

  function buildEncodingForm(file, form) {
    return fileBytes(file).then(function (bytes) {
      var mode = activeMode(form) || "base64";
      var encoded;
      var filename = file.name + "." + mode + ".txt";
      if (mode === "base64") encoded = bytesToBase64(bytes);
      else if (mode === "double-base64") encoded = window.btoa(bytesToBase64(bytes));
      else if (mode === "hex") { encoded = bytesToHex(bytes); filename = file.name + ".hex.txt"; }
      else if (mode === "url") encoded = encodeURIComponent(bytesToBase64(bytes));
      else throw new Error("Unsupported encoding mode.");
      var formData = new FormData();
      formData.append("test_type", "encoding");
      formData.append("encoding_mode", mode);
      formData.append("metadata", metadata(file));
      formData.append("encoded_payload", new Blob([encoded], { type: "text/plain" }), filename);
      return formData;
    });
  }

  function buildEncryptionForm(file, form) {
    return fileBytes(file).then(function (bytes) {
      var salt = crypto.getRandomValues(new Uint8Array(16));
      var iv = crypto.getRandomValues(new Uint8Array(12));
      return crypto.subtle.importKey("raw", new TextEncoder().encode("123456"), "PBKDF2", false, ["deriveKey"])
        .then(function (material) {
          return crypto.subtle.deriveKey(
            { name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: 200000 },
            material,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt"]
          );
        })
        .then(function (key) { return crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, bytes); })
        .then(function (encryptedBuffer) {
          var encrypted = new Uint8Array(encryptedBuffer);
          var tagLength = 16;
          var formData = new FormData();
          formData.append("test_type", "encryption");
          formData.append("encryption_mode", activeMode(form) || "aes-gcm");
          formData.append("metadata", metadata(file));
          formData.append("password", "123456");
          formData.append("salt", bytesToBase64(salt));
          formData.append("iv", bytesToBase64(iv));
          formData.append("tag", bytesToBase64(encrypted.subarray(encrypted.length - tagLength)));
          formData.append("ciphertext", new Blob([encrypted.subarray(0, encrypted.length - tagLength)], { type: "application/octet-stream" }), file.name + ".aes-gcm");
          return formData;
        });
    });
  }

  function makeChunks(bytes, mode) {
    var base = Math.max(1, Math.ceil(bytes.length / 6));
    var chunks = [];
    if (mode === "randomized-size") {
      var ratios = [0.09, 0.21, 0.13, 0.27, 0.17, 0.13];
      var offset = 0;
      ratios.forEach(function (ratio, index) {
        var remaining = bytes.length - offset;
        var size = index === ratios.length - 1 ? remaining : Math.max(1, Math.min(remaining, Math.floor(bytes.length * ratio)));
        chunks.push({ order: index + 1, include: true, bytes: bytes.subarray(offset, offset + size) });
        offset += size;
      });
    } else {
      for (var start = 0, order = 1; start < bytes.length; start += base, order += 1) {
        chunks.push({ order: order, include: true, bytes: bytes.subarray(start, Math.min(bytes.length, start + base)) });
      }
    }
    if (mode === "reverse-order") return chunks.reverse();
    if (mode === "mixed-noise") {
      return [{ order: 0, include: false, bytes: new TextEncoder().encode("benign decoy before file\n") }]
        .concat(chunks)
        .concat([{ order: 999, include: false, bytes: new TextEncoder().encode("benign decoy after file\n") }]);
    }
    return chunks;
  }

  function buildChunkingForm(file, form) {
    return fileBytes(file).then(function (bytes) {
      var mode = activeMode(form) || "straight-split";
      var chunks = makeChunks(bytes, mode);
      var formData = new FormData();
      formData.append("test_type", "chunking");
      formData.append("chunking_mode", mode);
      formData.append("metadata", metadata(file));
      formData.append("manifest", JSON.stringify(chunks.map(function (chunk, index) {
        return { field: "chunk_" + index, order: chunk.order, include: chunk.include };
      })));
      chunks.forEach(function (chunk, index) {
        formData.append("chunk_" + index, new Blob([chunk.bytes], { type: "application/octet-stream" }), "chunk-" + (index + 1) + ".part");
      });
      return formData;
    });
  }

  var dnsAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  function base32(bytes) {
    var output = "";
    var value = 0;
    var bits = 0;
    bytes.forEach(function (byte) {
      value = (value << 8) | byte;
      bits += 8;
      while (bits >= 5) {
        output += dnsAlphabet[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    });
    if (bits > 0) output += dnsAlphabet[(value << (5 - bits)) & 31];
    return output;
  }

  function wait(ms) {
    return new Promise(function (resolve) { window.setTimeout(resolve, ms); });
  }

  function runLimited(items, limit, worker) {
    var index = 0;
    var active = 0;
    return new Promise(function (resolve) {
      function next() {
        if (index >= items.length && active === 0) return resolve();
        while (active < limit && index < items.length) {
          var item = items[index++];
          active += 1;
          Promise.resolve(worker(item))
            .catch(function () {})
            .finally(function () {
              active -= 1;
              next();
            });
        }
      }
      next();
    });
  }

  function safeUploadUrl(url) {
    return typeof url === "string" && /^\/data-theft\/uploads\/[^/?#]+$/.test(url);
  }

  function setTunnelStatus(out, message, state, fileUrl) {
    setPersistentOutput(out, message, state);
  }

  function revealServerFile(fromEl, fileUrl) {
    if (!safeUploadUrl(fileUrl)) return;
    var run = fromEl.closest(".swg-run");
    var button = run && run.querySelector("[data-open-server-file]");
    if (!button) return;
    showServerFileButton(button, fileUrl);
    terminalLine(fromEl, "server file is available at " + fileUrl);
  }

  function buildDnsChunks(id, file, encodedData) {
    var suffix = ".swgaudit.com";
    var maxDataLength = 253 - id.length - suffix.length - 5;
    var chunks = [];
    for (var offset = 0, chunkNumber = 1; offset < encodedData.length; chunkNumber += 1) {
      var labels = [];
      var remainingLength = maxDataLength;
      while (offset < encodedData.length && remainingLength > 0) {
        var labelLength = Math.min(60, remainingLength, encodedData.length - offset);
        labels.push(encodedData.slice(offset, offset + labelLength));
        remainingLength -= labelLength + 1;
        offset += labelLength;
      }
      chunks.push({ number: chunkNumber, labels: labels });
    }
    var safeName = (file.name || "dns-tunnel-file").replace(/[^\w.-]+/g, "_");
    if (safeName.length > 48) {
      var dot = safeName.lastIndexOf(".");
      var ext = dot > 0 && safeName.length - dot <= 12 ? safeName.slice(dot) : "";
      safeName = safeName.slice(0, 48 - ext.length) + ext;
    }
    var meta = new TextEncoder().encode(JSON.stringify({
      n: safeName,
      t: (file.type || "").slice(0, 48),
      s: file.size,
      c: chunks.length,
      l: encodedData.length,
    }));
    var metaPayload = base32(meta);
    if (metaPayload.length > maxDataLength) {
      meta = new TextEncoder().encode(JSON.stringify({
        n: "dns-tunnel-file",
        t: "",
        s: file.size,
        c: chunks.length,
        l: encodedData.length,
      }));
      metaPayload = base32(meta);
    }
    return [{ number: 0, labels: (metaPayload.match(/.{1,60}/g) || []) }].concat(chunks);
  }

  function checkDnsResult(id, form, attempts, pagePath) {
    var out = cardOutput(form, "[data-dns-tunnel-status]");
    var last = null;
    var chain = Promise.resolve();
    for (var i = 1; i <= attempts; i += 1) {
      (function (attempt) {
        chain = chain.then(function () {
          setOutput(out, "Checking server result (" + attempt + "/" + attempts + ")...");
          terminalLine(form, "checking server result (" + attempt + "/" + attempts + ") ...");
          return fetch("/data-theft/fetch_uploaded_data.php?id=" + encodeURIComponent(id), { headers: { Accept: "application/json" } })
            .then(function (r) { return r.json(); })
            .then(function (result) {
              last = result;
              if (result.success && result.fileUrl) return result;
              if (result.partial) return result;
              if (attempt < attempts) return wait(2000);
              return null;
            });
        }).then(function (result) {
          if (result && ((result.success && result.fileUrl) || result.partial)) {
            throw { done: true, result: result };
          }
        });
      })(i);
    }
    return chain.then(function () { return last || { success: false, message: "No complete file could be reconstructed from the received DNS chunks." }; })
      .catch(function (marker) { if (marker.done) return marker.result; throw marker; });
  }

  function runDnsTunnel(form) {
    bindRunPage(form);
    var pagePath = location.pathname;
    var out = cardOutput(form, "[data-dns-tunnel-status]");
    var input = form.querySelector("[data-dns-tunnel-file]");
    var submit = form.querySelector("[data-dns-tunnel-submit]");
    var reset = form.querySelector("[data-dns-tunnel-reset]");
    var file = selectedFile(input);
    if (!file) {
      return setOutput(out, "Choose a file before running the test.");
    }
    if (file.size > 100 * 1024) {
      startConsole(form, "swg-audit dns-tunnel --file=" + file.name);
      terminalLine(form, "file exceeds 100 KB limit.");
      return setOutput(out, "Choose a file smaller than 100 KB.");
    }
    submit.disabled = true;
    if (reset) reset.hidden = true;
    clearRunResult(form, out);
    startConsole(form, "swg-audit dns-tunnel --file=" + file.name);
    terminalLine(form, "encoding file into DNS labels ...");
    setOutput(out, "Preparing DNS tunnelling test...");
    var id = testId().slice(0, 16);
    fileBytes(file)
      .then(function (bytes) {
        var chunks = buildDnsChunks(id, file, base32(bytes));
        var attempted = 0;
        return runLimited(chunks, 8, function (chunk) {
          var url = "https://" + id + "." + chunk.number + "." + chunk.labels.join(".") + ".swgaudit.com";
          return fetch(url, { mode: "no-cors" }).catch(function () {}).finally(function () {
            attempted += 1;
            setOutput(out, "Running DNS tunnelling test: " + attempted + "/" + chunks.length + " requests attempted...");
            if (attempted === 1 || attempted === chunks.length || attempted % 10 === 0) {
              terminalLine(form, "attempted " + attempted + "/" + chunks.length + " DNS requests ...");
            }
          });
        });
      })
      .then(function () { return checkDnsResult(id, form, 8, pagePath); })
      .then(function (result) {
        if (result.success && result.fileUrl) {
          terminalFail(form, "server reconstructed the full file from DNS queries.");
          revealServerFile(form, result.fileUrl);
          setPersistentOutput(out, "Test failed: the full file was reconstructed from DNS queries.", "is-fail", pagePath);
        }
        else if (result.partial) {
          terminalPass(form, "the file was not fully reconstructed from DNS queries.");
          setPersistentOutput(out, "Test passed.", "is-pass", pagePath);
        }
        else {
          terminalPass(form, "the file was not reconstructed from DNS queries.");
          setPersistentOutput(out, "Test passed.", "is-pass", pagePath);
        }
      })
      .catch(function () {
        terminalLine(form, "DNS tunnel test could not complete.");
        setOutput(out, "Test could not complete. Please retry.");
      })
      .finally(function () {
        submit.disabled = false;
        if (reset) reset.hidden = false;
      });
  }

  function buildPathChunks(file, bytes) {
    var encoded = bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
    var chunks = [];
    for (var offset = 0, num = 1; offset < encoded.length; offset += 1500, num += 1) {
      chunks.push({ number: num, payload: encoded.slice(offset, offset + 1500) });
    }
    var meta = bytesToBase64(new TextEncoder().encode(JSON.stringify({
      name: file.name,
      type: file.type || "application/octet-stream",
      size: file.size,
      totalDataChunks: chunks.length,
      encodedLength: encoded.length,
    }))).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
    return [{ number: 0, payload: meta }].concat(chunks);
  }

  function runPathTunnel(form) {
    bindRunPage(form);
    var pagePath = location.pathname;
    var out = cardOutput(form, "[data-path-tunnel-status]");
    var input = form.querySelector("[data-path-tunnel-file]");
    var submit = form.querySelector("[data-path-tunnel-submit]");
    var reset = form.querySelector("[data-path-tunnel-reset]");
    var file = selectedFile(input);
    if (!file) {
      return setOutput(out, "Choose a file before running the test.");
    }
    if (file.size === 0) {
      startConsole(form, "swg-audit path-tunnel --file=" + file.name);
      terminalLine(form, "empty file was not sent.");
      return setOutput(out, "Choose a non-empty file before running the test.");
    }
    if (file.size > 200 * 1024) {
      startConsole(form, "swg-audit path-tunnel --file=" + file.name);
      terminalLine(form, "file exceeds 200 KB limit.");
      return setOutput(out, "Choose a file smaller than 200 KB.");
    }
    var id = testId().slice(0, 16);
    submit.disabled = true;
    input.disabled = true;
    if (reset) reset.hidden = true;
    clearRunResult(form, out);
    startConsole(form, "swg-audit path-tunnel --file=" + file.name);
    terminalLine(form, "encoding file into URL path chunks ...");
    setOutput(out, "Preparing HTTP path tunneling test...");
    fileBytes(file)
      .then(function (bytes) {
        var chunks = buildPathChunks(file, bytes);
        var delivered = 0;
        var chain = Promise.resolve();
        chunks.forEach(function (chunk) {
          chain = chain.then(function () {
            var url = "/data-theft/path-tunnel.php/" + encodeURIComponent(id) + "/" + chunk.number + "/" + encodeURIComponent(chunk.payload);
            terminalLine(form, "sending path chunk " + chunk.number + "/" + (chunks.length - 1) + " ...");
            return fetch(url, { method: "GET", cache: "no-store", headers: { Accept: "application/json" } })
              .then(function (response) {
                if (response.ok) delivered += 1;
              })
              .catch(function () {});
          });
        });
        return chain.then(function () { return { total: chunks.length, delivered: delivered }; });
      })
      .then(function (delivery) {
        var last = null;
        var chain = Promise.resolve();
        for (var i = 1; i <= 5; i += 1) {
          (function (attempt) {
            chain = chain.then(function () {
              setOutput(out, "Checking server result (" + attempt + "/5)...");
              terminalLine(form, "checking server result (" + attempt + "/5) ...");
              return fetch("/data-theft/path-tunnel.php?status=1&id=" + encodeURIComponent(id), { cache: "no-store", headers: { Accept: "application/json" } })
                .then(function (r) { return r.json(); })
                .then(function (result) {
                  last = result;
                  if (result.success && result.reconstructed) return result;
                  if (result.partial) return result;
                  if (attempt < 5) return wait(1000);
                  return null;
                })
                .catch(function () { last = { success: false, reconstructed: false }; });
            }).then(function (result) {
              if (result && ((result.success && result.reconstructed) || result.partial)) {
                throw { done: true, result: result };
              }
            });
          })(i);
        }
        return chain.then(function () { return { result: last, delivery: delivery }; })
          .catch(function (marker) { if (marker.done) return { result: marker.result, delivery: delivery }; throw marker; });
      })
      .then(function (payload) {
        var result = payload && payload.result;
        var partialExfil = result && result.partial;
        var fullReconstruction = result && result.success && result.reconstructed;
        if (fullReconstruction) {
          terminalFail(form, "server reconstructed the file from URL path chunks.");
          revealServerFile(form, result.fileUrl);
          setPersistentOutput(out, "Test failed: the full file was reconstructed from URL path chunks.", "is-fail", pagePath);
        }
        else if (partialExfil) {
          terminalPass(form, "the file was not fully reconstructed from URL path chunks.");
          setPersistentOutput(out, "Test passed.", "is-pass", pagePath);
        }
        else {
          terminalPass(form, "the file was not reconstructed from URL path chunks.");
          setPersistentOutput(out, "Test passed.", "is-pass", pagePath);
        }
      })
      .catch(function () {
        terminalLine(form, "HTTP path tunnel test could not complete.");
        setOutput(out, "Test could not complete. Please retry.");
      })
      .finally(function () {
        submit.disabled = false;
        input.disabled = false;
        if (reset) reset.hidden = false;
      });
  }

  /* ---- delegated click handler ---------------------------------------- */
  document.addEventListener("auxclick", function (event) {
    handleDownloadNewTabActivation(event);
  }, true);

  document.addEventListener("click", function (event) {
    handleDownloadNewTabActivation(event);
  }, true);

  document.addEventListener("pointerup", function (event) {
    handleMobileSidebarActivation(event);
  }, true);

  document.addEventListener("touchend", function (event) {
    handleMobileSidebarActivation(event);
  }, true);

  document.addEventListener("click", function (event) {
    if (Date.now() - lastMobileSidebarTouch < 700) return;

    var mobileToggle = event.target.closest("[data-mobile-sb-toggle]");
    if (mobileToggle) {
      event.preventDefault();
      event.stopPropagation();
      toggleMobileSidebarFrom(mobileToggle);
      return;
    }

    if (event.target.hasAttribute("data-mobile-sb-close")) {
      event.preventDefault();
      event.stopPropagation();
      closeMobileSidebar();
      return;
    }

    // 0a) collapsible sidebar category; the adjacent category name remains a link.
    var sbToggle = event.target.closest("[data-sb-toggle]");
    if (sbToggle) {
      var groupId = sbToggle.getAttribute("data-sb-toggle");
      var sidebarGroup = document.getElementById(groupId);
      var categoryRow = sbToggle.closest(".swg-sb-cat");
      var willOpen = sidebarGroup && sidebarGroup.classList.contains("is-collapsed");
      if (sidebarGroup) sidebarGroup.classList.toggle("is-collapsed", !willOpen);
      if (categoryRow) {
        categoryRow.classList.toggle("is-open", willOpen);
        categoryRow.classList.toggle("is-collapsed", !willOpen);
      }
      sbToggle.setAttribute("aria-expanded", willOpen ? "true" : "false");
      sbToggle.setAttribute(
        "aria-label",
        (willOpen ? "Collapse " : "Expand ") + sbToggle.getAttribute("aria-label").replace(/^(Collapse|Expand) /, "")
      );
      return;
    }

    // 0b) custom dropdown open/close
    var ddToggle = event.target.closest("[data-dd-toggle]");
    if (ddToggle) {
      var dd = ddToggle.closest("[data-dd]");
      var wasOpen = dd.classList.contains("is-open");
      closeAllDropdowns();
      if (!wasOpen) {
        dd.classList.add("is-open");
        var menu = dd.querySelector("[data-dd-menu]");
        if (menu) menu.hidden = false;
      }
      return;
    }

    // 0c) dropdown option chosen
    var ddOpt = event.target.closest("[data-dd-opt]");
    if (ddOpt) {
      var ddo = ddOpt.closest("[data-dd]");
      ddo.querySelectorAll("[data-dd-opt]").forEach(function (o) {
        o.classList.toggle("is-active", o === ddOpt);
      });
      var label = ddo.querySelector("[data-dd-label]");
      if (label) label.textContent = ddOpt.textContent;
      var ddDesc = ddo.parentElement && ddo.parentElement.querySelector("[data-dd-desc]");
      if (ddDesc && ddOpt.getAttribute("data-desc")) ddDesc.textContent = ddOpt.getAttribute("data-desc");
      if (ddo.getAttribute("data-dd-dl")) {
        var pickDesc = ddo.parentElement && ddo.parentElement.querySelector("[data-pick-desc]");
        if (pickDesc && ddOpt.getAttribute("data-desc")) pickDesc.textContent = ddOpt.getAttribute("data-desc");
      }
      if (ddo.getAttribute("data-dd-dl")) {
        var pickDesc = ddo.parentElement && ddo.parentElement.querySelector("[data-pick-desc]");
        if (pickDesc && ddOpt.getAttribute("data-desc")) pickDesc.textContent = ddOpt.getAttribute("data-desc");
      }
      var frameId = ddo.getAttribute("data-dd-frame");
      if (frameId) {
        var frame = document.getElementById(frameId);
        var src = ddOpt.getAttribute("data-video");
        if (frame && src) {
          frame.src = src;
        }
      }
      closeAllDropdowns();
      return;
    }

    // 0d) click anywhere else closes any open dropdown
    if (!event.target.closest("[data-dd]")) closeAllDropdowns();

    // 1) chip selection
    var chip = event.target.closest("[data-chip]");
    if (chip) {
      var group = chip.closest("[data-pick]");
      if (group) {
        group.querySelectorAll("[data-chip]").forEach(function (c) {
          c.classList.toggle("is-active", c === chip);
        });
        // reflect choice in a sibling description, if present
        var desc =
          (group.closest(".swg-run") && group.closest(".swg-run").querySelector("[data-pick-desc]")) ||
          (group.parentElement && group.parentElement.querySelector("[data-pick-desc]"));
        if (desc && chip.getAttribute("data-desc")) desc.textContent = chip.getAttribute("data-desc");
      }
      if (smugglingConsoleFor(chip)) resetSmugglingConsole(chip);
      return;
    }

    // 2) plain static download link — verify fetch before opening
    var plain = event.target.closest("[data-reveal]");
    if (plain) {
      event.preventDefault();
      var revealUrl = plain.getAttribute("href");
      var revealName = (revealUrl || "").split("/").pop();
      startConsole(plain, "swg-audit fetch");
      openProtectedUrl(
        revealUrl,
        plain,
        "download request was allowed.",
        "download request was blocked or could not complete."
      );
      return;
    }

    var single = event.target.closest("[data-single-download]");
    if (single) {
      event.preventDefault();
      clickDownloadLink(
        single.getAttribute("data-url"),
        single.getAttribute("data-name"),
        single,
        "swg-audit fetch --file=" + (single.getAttribute("data-name") || "sample")
      );
      return;
    }

    var serverFile = event.target.closest("[data-open-server-file]");
    if (serverFile) {
      event.preventDefault();
      var serverUrl = serverFile.getAttribute("data-file-url");
      if (safeUploadUrl(serverUrl)) {
        terminalLine(serverFile, "opening " + serverUrl);
        openNewTab(serverUrl);
      }
      return;
    }

    var open = event.target.closest("[data-open]");
    if (open) {
      event.preventDefault();
      var openChip = activePick(open.getAttribute("data-open"));
      if (openChip) {
        startConsole(open, "swg-audit open-url");
        var openedTab = openNewTab(openChip.getAttribute("data-url"));
        if (openedTab) {
          terminalFail(open, "selected URL opened in a new tab.");
          revealBanner(open);
        } else {
          terminalPass(open, "selected URL was blocked before it could open.");
          hideBanner(open);
        }
      }
      return;
    }

    var cache = event.target.closest("[data-cache-launch]");
    if (cache) {
      event.preventDefault();
      startConsole(cache, "swg-audit cache-mutation");
      openNewTab("/phishing/cache-test.php?test=" + testId());
      terminalFail(cache, "content-change test page opened in a new tab.");
      return;
    }

    var stored = event.target.closest("[data-stored-launch]");
    if (stored) {
      event.preventDefault();
      var storedChip = activeChip(stored.getAttribute("data-stored-launch"));
      var format = storedChip ? storedChip.getAttribute("data-format") : "raw-html";
      startConsole(stored, "swg-audit stored-page --format=" + format);
      terminalLine(stored, format === "mhtml" ? "assembling MHTML payload in the browser ..." : "assembling raw HTML in the browser ...");
      try {
        // The phishing page is built entirely client-side (no server fetch),
        // then assembled into a blob and opened, mirroring an opened local file.
        var localHtml = makeDummyMicrosoftLoginHtml();
        var renderedHtml = format === "mhtml"
          ? extractHtmlFromMhtml(buildClientMhtml(localHtml))
          : localHtml;
        terminalLine(stored, "building blob from locally assembled " + (format === "mhtml" ? "MHTML" : "HTML") + " ...");
        var opened = openClientHtml(renderedHtml);
        if (opened) {
          terminalFail(stored, "locally assembled phishing page opened in a new tab.");
          revealBanner(stored);
        }
        else {
          terminalPass(stored, "locally assembled phishing page was blocked by the browser.");
          hideBanner(stored);
        }
      } catch (err) {
        reportIncompleteSubmission(stored, null, "stored phishing page could not be built.");
      }
      return;
    }

    var canvas = event.target.closest("[data-canvas-launch]");
    if (canvas) {
      event.preventDefault();
      startConsole(canvas, "swg-audit canvas-page");
      var openedCanvas = openClientHtml(buildCanvasHtml());
      if (openedCanvas) {
        terminalFail(canvas, "canvas-rendered phishing page opened in a new tab.");
        revealBanner(canvas);
      }
      else {
        terminalPass(canvas, "canvas-rendered phishing page was blocked by the browser.");
        hideBanner(canvas);
      }
      return;
    }

    // 3) JS download button driven by a chip group
    var dl = event.target.closest("[data-dl]");
    if (!dl) return;
    event.preventDefault();

    var groupId = dl.getAttribute("data-dl");
    var sel = activePick(groupId);
    if (!sel) return;

    var kind = sel.getAttribute("data-kind") || "direct";
    var url = sel.getAttribute("data-url");
    var name = sel.getAttribute("data-name");
    var mime = sel.getAttribute("data-mime");

    startConsole(dl, "swg-audit run --test=" + groupId);
    if (kind === "smuggle") {
      terminalLine(dl, "embedding payload in " + (sel.getAttribute("data-carrier") || "html") + " carrier ...");
      terminalLine(dl, "browser will attempt last-mile reassembly ...");
    }

    // cross-origin channels can't be fetched (CORS) — navigate a real anchor so
    // the request still traverses the SWG, matching the live delivery test.
    if (kind === "link") {
      runLinkDownload(url, name, dl, "swg-audit fetch --channel=external");
      return;
    }

    if (kind === "direct") {
      runDownloadTest(url, name, mime, dl, "swg-audit fetch --file=" + (name || "sample"));
      return;
    }

    dl.setAttribute("aria-busy", "true");
    var work;
    if (kind === "assemble") {
      terminalLine(dl, "fetching encoded or encrypted payload ...");
      work = buildAssembled(url);
    }
    else if (kind === "wasm") {
      terminalLine(dl, "fetching and instantiating WebAssembly module ...");
      terminalLine(dl, "assembling EICAR test string from WebAssembly memory ...");
      work = buildWasm(url, name, mime);
    }
    else if (kind === "chunk") {
      terminalLine(dl, "fetching file chunks ...");
      work = buildChunk(url);
    }
    else if (kind === "smuggle") work = buildSmuggled(sel.getAttribute("data-carrier") || "html", name);
    else work = buildDirect(url, name, mime);

    work
      .then(function (out) {
        terminalLine(dl, "file was successfully assembled in the browser.");
        try {
          downloadBytes(out.bytes, name || out.filename, mime || out.mime);
          terminalFail(dl, "file was successfully assembled in the browser and downloaded.");
          revealBanner(dl);
        } catch (error) {
          terminalFail(dl, "file was successfully assembled in the browser but not downloaded.");
          revealBanner(dl);
        }
      })
      .catch(function (err) {
        if (isBlockedFetchError(err)) {
          terminalPass(dl, "the file was not assembled in the browser.");
          hideBanner(dl);
          return;
        }
        terminalLine(dl, "assembly result could not be verified automatically.");
        hideBanner(dl);
      })
      .finally(function () {
        dl.removeAttribute("aria-busy");
      });
  });

  document.addEventListener("change", function (event) {
    var fileInput = event.target.closest('.swg-file-field input[type="file"]');
    if (!fileInput) return;
    var file = fileInput.files && fileInput.files[0];
    var key = fileInputKey(fileInput);
    if (file) selectedFileState[key] = file;
    else delete selectedFileState[key];
    updateFileLabel(fileInput, file || null);
  });

  document.addEventListener("submit", function (event) {
    var credential = event.target.closest("[data-credential-form]");
    if (credential) {
      event.preventDefault();
      bindRunPage(credential);
      var credPagePath = location.pathname;
      var credOut = cardOutput(credential);
      startConsole(credential, "swg-audit credential-submit");
      terminalLine(credential, "submitting credentials ...");
      setOutput(credOut, "Submitting credentials...");
      fetch(credential.action || "/phishing/credential-submit.php", {
        method: "post",
        body: new FormData(credential),
        headers: { Accept: "application/json, text/plain, */*" },
      })
        .then(function (response) {
          if (!response.ok) throw new Error("Submission returned HTTP " + response.status);
          return readJson(response);
      })
        .then(function (result) {
          terminalFail(credential, "credentials reached the submission endpoint.");
          setPersistentOutput(credOut, "Test failed.", "is-fail", credPagePath);
        })
        .catch(function (err) {
          if (isBlockedHttpError(err)) {
            reportBlockedSubmission(
              credential,
              credOut,
              credPagePath,
              "credential submission was blocked or interrupted."
            );
            return;
          }
          reportIncompleteSubmission(credential, credOut, "credential submission could not complete.");
        });
      return;
    }

    var normalFile = event.target.closest("[data-file-submission-form]");
    if (normalFile) {
      event.preventDefault();
      bindRunPage(normalFile);
      var uploadPagePath = location.pathname;
      var fileOut = cardOutput(normalFile);
      var fileInput = normalFile.querySelector('input[type="file"]');
      var normalSelectedFile = selectedFile(fileInput);
      if (!fileInput || !normalSelectedFile) {
        setOutput(fileOut, "Choose a file before running the test.");
        return;
      }
      clearRunResult(normalFile, fileOut);
      startConsole(normalFile, "swg-audit file-upload --file=" + normalSelectedFile.name);
      terminalLine(normalFile, "uploading selected file to server ...");
      setOutput(fileOut, "Uploading selected file...");
      var normalFormData = new FormData(normalFile);
      if (!fileInput.files || !fileInput.files[0]) {
        normalFormData.set(fileInput.name || "personal_data_file", normalSelectedFile, normalSelectedFile.name);
      }
      fetch(normalFile.action || "/data-theft/upload.php", {
        method: "post",
        body: normalFormData,
        headers: { Accept: "application/json, text/plain, */*" },
      })
        .then(function (response) {
          if (!response.ok) throw new Error("Upload returned HTTP " + response.status);
          return readJson(response);
      })
        .then(function (result) {
          terminalFail(normalFile, "server received and stored the uploaded file.");
          revealServerFile(normalFile, result.fileUrl);
          setPersistentOutput(fileOut, "Test failed.", "is-fail", uploadPagePath);
        })
        .catch(function (err) {
          if (isBlockedHttpError(err)) {
            reportBlockedSubmission(
              normalFile,
              fileOut,
              uploadPagePath,
              "file upload was blocked or interrupted."
            );
            return;
          }
          reportIncompleteSubmission(normalFile, fileOut, "file upload could not complete.");
        });
      return;
    }

    var encoding = event.target.closest("[data-data-theft-encoding-form]");
    if (encoding) {
      event.preventDefault();
      runDataTheftForm(encoding, buildEncodingForm, "Encoding selected file...");
      return;
    }

    var encryption = event.target.closest("[data-data-theft-encryption-form]");
    if (encryption) {
      event.preventDefault();
      runDataTheftForm(encryption, buildEncryptionForm, "Encrypting selected file...");
      return;
    }

    var chunking = event.target.closest("[data-data-theft-chunking-form]");
    if (chunking) {
      event.preventDefault();
      runDataTheftForm(chunking, buildChunkingForm, "Chunking selected file...");
      return;
    }

    var dns = event.target.closest("[data-dns-tunnel-form]");
    if (dns) {
      event.preventDefault();
      runDnsTunnel(dns);
      return;
    }

    var pathForm = event.target.closest("[data-path-tunnel-form]");
    if (pathForm) {
      event.preventDefault();
      runPathTunnel(pathForm);
    }
  }, true);

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") closeMobileSidebar();
  });

  document.addEventListener("click", function (event) {
    var dnsReset = event.target.closest("[data-dns-tunnel-reset]");
    if (dnsReset) {
      var dnsForm = dnsReset.closest("[data-dns-tunnel-form]");
      var dnsOut = dnsForm && cardOutput(dnsForm, "[data-dns-tunnel-status]");
      if (dnsForm) dnsForm.reset();
      clearSelectedFile(dnsForm && dnsForm.querySelector('input[type="file"]'));
      if (dnsOut) {
        clearPersistentOutput(dnsOut);
        dnsOut.hidden = true;
        dnsOut.textContent = "";
        dnsOut.classList.remove("is-pass", "is-fail");
      }
      clearServerFileButton(serverFileButtonFor(dnsForm));
      dnsReset.hidden = true;
      return;
    }

    var pathReset = event.target.closest("[data-path-tunnel-reset]");
    if (pathReset) {
      var pathForm = pathReset.closest("[data-path-tunnel-form]");
      var pathOut = pathForm && cardOutput(pathForm, "[data-path-tunnel-status]");
      if (pathForm) pathForm.reset();
      clearSelectedFile(pathForm && pathForm.querySelector('input[type="file"]'));
      if (pathOut) {
        clearPersistentOutput(pathOut);
        pathOut.hidden = true;
        pathOut.textContent = "";
        pathOut.classList.remove("is-pass", "is-fail");
      }
      clearServerFileButton(serverFileButtonFor(pathForm));
      pathReset.hidden = true;
    }
  });

  function initConsoles() {
    initMobileSidebar();
    initSmugglingConsoles();
    initTestConsoles();
    initFileControls();
    restorePersistentResults();
  }

  initConsoles();
  setTimeout(initConsoles, 100);
  setTimeout(initConsoles, 600);
  if (window.MutationObserver) {
    var initQueued = false;
    new MutationObserver(function () {
      if (initQueued) return;
      initQueued = true;
      setTimeout(function () {
        initQueued = false;
        initConsoles();
      }, 50);
    }).observe(document.documentElement, { childList: true, subtree: true });
  }
})();
