// Cookie Defense — bookmarklet edition.
//
// For browsers with no extension support at all (this was built for
// DuckDuckGo's iOS app, which — unlike desktop Chrome — has no public
// extension API and is not confirmed to support Safari Web Extensions
// either). A bookmarklet is plain JavaScript that runs in the current
// page when you tap it, so it's the only thing that works everywhere
// without compiling and installing a native app.
//
// This is NOT a port of the full extension — document.cookie (the only
// cookie API available to page JavaScript) is fundamentally more limited
// than chrome.cookies:
//   - HttpOnly cookies are invisible to it entirely. In practice this is
//     harmless here: HttpOnly is disproportionately used by real auth/
//     session cookies, so the ones this can't touch are mostly the ones
//     that should never be touched anyway.
//   - No per-cookie domain/path/session/secure flags are exposed, so the
//     heuristic below can only use the cookie's name and value — the two
//     weaker signals from extension/lib/heuristic.js (HttpOnly+session
//     flags) don't exist here; only the name-pattern and JWT-claim checks
//     do (roughly equivalent to the extension's level 3).
//   - Overwriting a cookie that the *site* originally set with an explicit
//     Domain attribute (e.g. Domain=.example.com) creates a new host-only
//     cookie instead of truly replacing it — both may end up being sent
//     to the server. There is no workaround from page JS; the browser
//     does not expose a cookie's Domain attribute to document.cookie.
//   - It only ever sees/affects the current page's own origin, once, when
//     tapped. No background auto-protect, no cross-site backup/restore,
//     no popup UI — this is a manual, single-shot tool.
//
// Usage: see ../README.md in this folder for how to install this as an
// actual bookmark on iOS (DuckDuckGo or Safari).

(function () {
  "use strict";

  var FUNCTIONAL_NAME_PATTERN =
    /(session|logged.?in|\bsid\b|csrf|xsrf|\bauth\b|login|jwt|refresh.?token|access.?token|id.?token|\btoken\b)/i;
  var SESSION_CLAIM_KEYS = ["sub", "exp", "iat", "aud", "iss", "jti", "nbf", "scope", "token_type"];

  function b64urlDecode(s) {
    try {
      var b64 = s.replace(/-/g, "+").replace(/_/g, "/");
      while (b64.length % 4) b64 += "=";
      return atob(b64);
    } catch (e) {
      return null;
    }
  }

  function looksLikeSessionJwt(value) {
    var parts = (value || "").split(".");
    if (parts.length !== 3) return false;
    var payloadRaw = b64urlDecode(parts[1]);
    if (!payloadRaw) return false;
    var payload;
    try {
      payload = JSON.parse(payloadRaw);
    } catch (e) {
      return false;
    }
    if (!payload || typeof payload !== "object") return false;
    return Object.keys(payload).some(function (k) {
      return SESSION_CLAIM_KEYS.indexOf(k.toLowerCase()) !== -1;
    });
  }

  function looksFunctional(name, value) {
    if (FUNCTIONAL_NAME_PATTERN.test(name)) return true;
    if (looksLikeSessionJwt(value)) return true;
    return false;
  }

  // --- Simplified, non-seeded version of extension/lib/lorem.js. No
  // persistence exists here, so there is no reason to keep values stable
  // across calls the way the extension does. ---
  var HEX_CHARS = "0123456789abcdef";
  var WORD_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789";

  function randomChars(alphabet, len) {
    var out = "";
    for (var i = 0; i < len; i++) out += alphabet[Math.floor(Math.random() * alphabet.length)];
    return out;
  }

  function randomDigits(len) {
    var out = randomChars("0123456789", len);
    return out.replace(/^0+(?=\d)/, "1");
  }

  function fakeUuid() {
    var h = function () {
      return randomChars(HEX_CHARS, 4);
    };
    var variant = "89ab"[Math.floor(Math.random() * 4)];
    return h() + h() + "-" + h() + "-4" + h().slice(1) + "-" + variant + h().slice(1) + "-" + h() + h() + h();
  }

  function detectEncoding(value) {
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return "uuid";
    if (/^[0-9a-f]+$/i.test(value) && value.length >= 8) return "hex";
    if (/^\d+$/.test(value)) return "numeric";
    return "default";
  }

  function fakeValue(originalValue) {
    var len = Math.min(128, Math.max(12, (originalValue || "").length || 12));
    switch (detectEncoding(originalValue || "")) {
      case "uuid":
        return fakeUuid();
      case "hex":
        return randomChars(HEX_CHARS, len);
      case "numeric":
        return randomDigits(len);
      default:
        return randomChars(WORD_CHARS, len);
    }
  }

  function setCookie(name, value) {
    document.cookie = name + "=" + encodeURIComponent(value) + "; path=/; max-age=31536000; SameSite=Lax";
  }

  function showBanner(obfuscated, total) {
    var el = document.createElement("div");
    el.textContent =
      "Cookie Defense: " + obfuscated + "/" + total + " cookie(s) on this page replaced with fake data.";
    el.style.cssText =
      "position:fixed;bottom:16px;left:16px;right:16px;z-index:2147483647;" +
      "background:#1a1a1a;color:#fff;font:14px/1.4 -apple-system,sans-serif;" +
      "padding:12px 16px;border-radius:10px;box-shadow:0 6px 20px rgba(0,0,0,.35);" +
      "text-align:center;";
    document.body.appendChild(el);
    setTimeout(function () {
      el.remove();
    }, 4000);
  }

  var raw = document.cookie ? document.cookie.split("; ") : [];
  var obfuscated = 0;
  for (var i = 0; i < raw.length; i++) {
    var eq = raw[i].indexOf("=");
    if (eq === -1) continue;
    var name = raw[i].slice(0, eq);
    var value = decodeURIComponent(raw[i].slice(eq + 1));
    if (looksFunctional(name, value)) continue;
    setCookie(name, fakeValue(value));
    obfuscated++;
  }
  showBanner(obfuscated, raw.length);
})();
