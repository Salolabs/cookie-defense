// Best-effort structural decoding of a cookie's raw value — "what shape of
// data is actually in here" — using only public, well-known encodings
// (JWT/base64/hex/JSON/UUID/URL-encoding). This decodes data already sitting
// in the user's own browser cookie jar; it makes no network calls and
// invents nothing it can't derive from the bytes themselves.
//
// Values are treated as potentially sensitive: decoded claim/field *names*
// are reported, but string values are redacted to a short preview unless
// the caller explicitly asks for full values (see `revealValues`).

import { t } from "./i18n.js";

const JWT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX_RE = /^[0-9a-fA-F]{8,}$/;
const NUMERIC_RE = /^\d+$/;
const GA_CLIENT_ID_RE = /^GA\d\.\d\.\d+\.\d+$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]{8,}$/;
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

function redact(value) {
  const s = String(value);
  if (s.length <= 6) return "*".repeat(s.length);
  return `${s.slice(0, 3)}${t("redactSuffix", [String(s.length)])}`;
}

function redactDeep(value, revealValues) {
  if (revealValues) return value;
  if (value === null || typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "string") return redact(value);
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, revealValues));
  if (typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactDeep(v, revealValues);
    return out;
  }
  return value;
}

function b64urlToStr(segment) {
  let s = segment.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return atob(s);
}

function tryJwt(value) {
  if (!JWT_RE.test(value)) return null;
  const parts = value.split(".");
  if (parts.length !== 3 || !parts[0] || !parts[1]) return null;
  try {
    const header = JSON.parse(b64urlToStr(parts[0]));
    const payload = JSON.parse(b64urlToStr(parts[1]));
    if (!header || typeof header !== "object" || !("alg" in header)) return null;
    return { header, payload };
  } catch {
    return null;
  }
}

function tryBase64Json(value) {
  const candidates = [];
  if (BASE64URL_RE.test(value)) candidates.push(value);
  if (BASE64_RE.test(value) && value.length % 4 === 0) candidates.push(value);
  for (const c of candidates) {
    try {
      const decoded = b64urlToStr(c.replace(/-/g, "+").replace(/_/g, "/"));
      try {
        return { decoded, json: JSON.parse(decoded) };
      } catch {
        // Decoded fine but isn't JSON; only report it if it's printable
        // text, otherwise it's almost certainly compressed/binary noise.
        if (/^[\x20-\x7e]*$/.test(decoded)) return { decoded, json: null };
      }
    } catch {
      // not valid base64 — fall through
    }
  }
  return null;
}

export function inspectValue(rawValue, { revealValues = false } = {}) {
  const value = rawValue || "";

  if (GA_CLIENT_ID_RE.test(value)) {
    return {
      encoding: "ga-client-id",
      summary: t("encGaClientId"),
      details: {},
    };
  }

  const jwt = tryJwt(value);
  if (jwt) {
    return {
      encoding: "jwt",
      summary: t("encJwt"),
      details: {
        header: jwt.header,
        payloadKeys: Object.keys(jwt.payload || {}),
        payload: redactDeep(jwt.payload, revealValues),
      },
    };
  }

  if (UUID_RE.test(value)) {
    return { encoding: "uuid", summary: t("encUuid"), details: {} };
  }

  if (NUMERIC_RE.test(value) && value.length <= 32) {
    return { encoding: "numeric", summary: t("encNumeric"), details: {} };
  }

  const b64 = tryBase64Json(value);
  if (b64 && b64.json !== null) {
    return {
      encoding: "base64-json",
      summary: t("encBase64Json"),
      details: { keys: Object.keys(b64.json), value: redactDeep(b64.json, revealValues) },
    };
  }
  if (b64) {
    return {
      encoding: "base64-text",
      summary: t("encBase64Text"),
      details: { preview: revealValues ? b64.decoded : redact(b64.decoded) },
    };
  }

  if (HEX_RE.test(value)) {
    return { encoding: "hex", summary: t("encHex"), details: {} };
  }

  if (/%[0-9a-fA-F]{2}/.test(value)) {
    try {
      const decoded = decodeURIComponent(value);
      try {
        const json = JSON.parse(decoded);
        return {
          encoding: "url-encoded-json",
          summary: t("encUrlEncodedJson"),
          details: { keys: Object.keys(json), value: redactDeep(json, revealValues) },
        };
      } catch {
        return {
          encoding: "url-encoded",
          summary: t("encUrlEncoded"),
          details: { preview: revealValues ? decoded : redact(decoded) },
        };
      }
    } catch {
      // malformed %-escape — fall through to opaque
    }
  }

  try {
    const json = JSON.parse(value);
    return {
      encoding: "json",
      summary: t("encJson"),
      details: { keys: Object.keys(json), value: redactDeep(json, revealValues) },
    };
  } catch {
    // not JSON
  }

  return {
    encoding: "opaque",
    summary: t("encOpaque"),
    details: {},
  };
}
