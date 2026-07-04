// Cookie-safe fake-value generator.
//
// RFC 6265 cookie-octet forbids whitespace, quotes, comma, semicolon and
// backslash, so word-based output is joined with "-" instead of spaces.
//
// Format-preserving by design: most tracking scripts run roughly
// `if (cookie exists AND parses as <expected shape>) use it; else regenerate`.
// A generic "lorem-ipsum-dolor" string fails that parse check for anything
// that isn't a bare opaque token, so the tracker notices and silently
// re-issues a real ID on the very next page load — the obfuscation "heals"
// away almost immediately. Matching the *shape* lib/reverse.js detected
// (UUID/GA-client-id/hex/numeric/JSON/JWT) makes the fake value survive
// that check and last much longer before anything regenerates it.

// Mostly classic lorem ipsum filler, with a couple of harmless easter-egg
// tokens mixed in (not song lyrics — just a video ID/meme reference). If a
// human ever manually inspects a bundle of "random-looking" fake tracking
// values and happens to search one of these, they get a small surprise
// instead of anything sensitive. Purely cosmetic — doesn't affect format
// validity, since this pool only feeds the generic opaque/text fallback.
const LOREM_WORDS = (
  "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod " +
  "tempor incididunt ut labore et dolore magna aliqua enim ad minim veniam " +
  "quis nostrud exercitation ullamco laboris nisi aliquip ex ea commodo " +
  "consequat duis aute irure in reprehenderit voluptate velit esse cillum " +
  "eu fugiat nulla pariatur excepteur sint occaecat cupidatat non proident " +
  "sunt culpa qui officia deserunt mollit anim id est laborum " +
  "dQw4w9WgXcQ rickroll"
).split(" ");

function pick(rand) {
  return LOREM_WORDS[Math.floor(rand() * LOREM_WORDS.length)];
}

// Deterministic-ish PRNG seeded from the cookie name+domain so repeated
// obfuscation passes on an untouched cookie produce a stable value instead
// of needless churn; Math.random() reseeds on every call site instead.
function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function hashSeed(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

const MIN_LEN = 12;
const MAX_LEN = 128;
const HEX_CHARS = "0123456789abcdef";
const BASE64URL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function randomChars(rand, alphabet, len) {
  let out = "";
  for (let i = 0; i < len; i++) out += alphabet[Math.floor(rand() * alphabet.length)];
  return out;
}

function randomDigits(rand, len) {
  let out = "";
  for (let i = 0; i < len; i++) out += Math.floor(rand() * 10);
  return out.replace(/^0+(?=\d)/, "1"); // avoid a leading zero looking suspicious
}

function loremWords(rand, targetLen) {
  let out = "";
  while (out.length < targetLen) out += (out ? "-" : "") + pick(rand);
  return out.slice(0, Math.max(targetLen, 1));
}

// Web API base64url encoding (btoa, not Buffer — this module runs in a
// service worker / extension popup, not Node). Callers only ever pass
// ASCII-safe input (JSON of ASCII fields, or lorem words), so no UTF-8
// pre-encoding step is needed before btoa.
function b64urlEncode(str) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fakeUuid(rand) {
  const h = () => randomChars(rand, HEX_CHARS, 4);
  const variant = "89ab"[Math.floor(rand() * 4)];
  return `${h()}${h()}-${h()}-4${h().slice(1)}-${variant}${h().slice(1)}-${h()}${h()}${h()}`;
}

function fakeGaClientId(rand) {
  const random = randomDigits(rand, 10);
  // Plausible recent-past timestamp (up to ~2 years back) rather than an
  // obviously-wrong one (epoch 0, or the future) that fraud/bot heuristics
  // on sophisticated sites might flag as anomalous.
  const twoYearsSeconds = 2 * 365 * 24 * 3600;
  const nowSeconds = Math.floor(Date.now() / 1000);
  const timestamp = nowSeconds - Math.floor(rand() * twoYearsSeconds);
  return `GA1.2.${random}.${timestamp}`;
}

function fakeJsonPayload(rand) {
  // Generic small object with plausible-looking, non-identifying keys —
  // enough to survive a "does this parse as JSON" check. Cannot replicate
  // any single vendor's exact schema without a per-vendor parser.
  return { v: Math.floor(rand() * 1e9), t: Math.floor(Date.now() / 1000), r: randomChars(rand, BASE64URL_CHARS, 8) };
}

function fakeJwt(rand) {
  const header = b64urlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64urlEncode(JSON.stringify(fakeJsonPayload(rand)));
  const signature = randomChars(rand, BASE64URL_CHARS, 32);
  return `${header}.${payload}.${signature}`;
}

/**
 * @param {string} originalValue - the real cookie value being replaced.
 * @param {string} seedKey - stable per-cookie seed (domain|name|path).
 * @param {string} [encoding] - lib/reverse.js `inspectValue(...).encoding`,
 *   e.g. "uuid" | "ga-client-id" | "hex" | "numeric" | "json" | "base64-json"
 *   | "jwt" | "base64-text" | "url-encoded" | "url-encoded-json" | "opaque".
 *   Omit (or pass an unrecognized value) to fall back to plain word output.
 */
export function generateLoremValue(originalValue, seedKey, encoding) {
  const targetLen = Math.min(MAX_LEN, Math.max(MIN_LEN, (originalValue || "").length || MIN_LEN));
  const rand = mulberry32(hashSeed(seedKey || String(Math.random())));

  switch (encoding) {
    case "uuid":
      return fakeUuid(rand);
    case "ga-client-id":
      return fakeGaClientId(rand);
    case "hex":
      return randomChars(rand, HEX_CHARS, targetLen);
    case "numeric":
      return randomDigits(rand, targetLen);
    case "jwt":
      // Truncating a JWT/JSON/base64 value to match the original length
      // would break its structure — these intentionally ignore targetLen
      // and return whatever length a valid instance of that shape needs.
      return fakeJwt(rand);
    case "json":
      return JSON.stringify(fakeJsonPayload(rand));
    case "base64-json":
      return b64urlEncode(JSON.stringify(fakeJsonPayload(rand)));
    case "base64-text":
      return b64urlEncode(loremWords(rand, targetLen));
    case "url-encoded":
    case "url-encoded-json":
      return encodeURIComponent(loremWords(rand, targetLen));
    default:
      return loremWords(rand, targetLen);
  }
}
