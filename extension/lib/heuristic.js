// Secondary classifier applied only to cookies the bundled database doesn't
// recognize (classification.match === "none"). Product decision: unrecognized
// cookies default to obfuscatable ("if it isn't whitelisted, it's junk")
// UNLESS they show a concrete functional/session signal — how many signals
// count depends on the user's chosen aggressiveness level (1-5).
//
// Signals are evidence-based, not guessed: a real full-browser scan of 1260
// unrecognized cookies showed that "not HttpOnly" alone appears on BOTH
// confirmed marketing trackers (100% of a sample of 13) AND confirmed
// auth/refresh-token cookies (~40% of a sample of 7 — tokens that must stay
// JS-readable for silent renewal). HttpOnly alone is therefore not a safe
// discriminator; it's only used combined with `session`.
//
// The three signals are ordered weakest-to-strongest evidence and each level
// drops the weakest remaining one, so higher levels trade false negatives
// (trackers that slip through) for a rising risk of false positives (a real
// functional cookie getting junked):
//   Level 1 - heuristic disabled entirely; "Unknown" is never touched.
//   Level 2 - all three signals protect (default).
//   Level 3 - drops "HttpOnly + session" (flags-only, no name/content check).
//   Level 4 - drops the name-pattern match too; only a JWT session-claim
//             match (content-based, the strongest signal) still protects.
//   Level 5 - drops JWT-claim protection too; only the user's own explicit
//             whitelist (see lib/settings.js) protects anything.
// The bundled-database result (match !== "none") is NEVER overridden by any
// level — this layer only fills the gap the database left as "Unknown".

import { DEFAULT_LEVEL, isWhitelisted } from "./settings.js";

// No \b around sid/auth/token: JS regex treats "_" as a word character, so
// \b never fires at the very common snake_case boundary ("auth_token",
// "guest_token", "_sid") or plain concatenation ("ebaysid", "ESTSAUTH",
// "OhpAuth") — a real full-browser scan found dozens of live examples,
// including Microsoft's own Azure AD session cookies (ESTSAUTH*) and
// Booking.com's SSO cookie (bkng_sso_auth), that \b silently excluded from
// this signal. Dropping \b trades a few likely-harmless false positives
// (e.g. "sidebar_open" now also reads as "protect this") for closing that
// gap — matches this module's own stated risk preference (see module doc:
// a spared tracker is the safe failure, a junked login is not).
const FUNCTIONAL_NAME_PATTERN =
  /(session|logged.?in|sid|csrf|xsrf|auth|login|jwt|refresh.?token|access.?token|id.?token|token)/i;

// JWT claim names that indicate an auth/session token rather than a tracking
// identifier repurposing the JWT format (trackers almost never use these).
const SESSION_CLAIM_KEYS = new Set(["sub", "exp", "iat", "aud", "iss", "jti", "nbf", "scope", "token_type"]);

function looksLikeSessionJwt(decoded) {
  if (!decoded || decoded.encoding !== "jwt") return false;
  const claims = Object.keys((decoded.details && decoded.details.payload) || {});
  return claims.some((c) => SESSION_CLAIM_KEYS.has(c.toLowerCase()));
}

function looksFunctional(cookie, decoded, level) {
  if (level <= 1) return true; // heuristic disabled: never treat as obfuscatable
  if (level <= 4 && looksLikeSessionJwt(decoded)) return true; // strongest signal, protects through level 4
  if (level <= 3 && FUNCTIONAL_NAME_PATTERN.test(cookie.name)) return true;
  if (level <= 2 && cookie.httpOnly && cookie.session) return true;
  return false;
}

/**
 * @param {object} cookie - chrome.cookies.Cookie-shaped object (name, httpOnly, session, ...).
 * @param {object} classification - lib/classify.js result for this cookie.
 * @param {object} decoded - lib/reverse.js inspectValue() result for cookie.value.
 * @param {number} [level] - aggressiveness level 1-5, see module doc. Defaults
 *   to DEFAULT_LEVEL (2) if omitted, invalid, or out of range.
 * @param {string[]} [whitelist] - user's own explicit safe-list of cookie
 *   names (lib/settings.js). Always wins, at every level.
 */
export function applyHeuristic(cookie, classification, decoded, level = DEFAULT_LEVEL, whitelist = []) {
  if (classification.match !== "none") return classification;
  if (isWhitelisted(cookie.name, whitelist)) return classification;
  const effectiveLevel = Number.isInteger(level) && level >= 1 && level <= 5 ? level : DEFAULT_LEVEL;
  if (looksFunctional(cookie, decoded, effectiveLevel)) return classification;
  return { ...classification, obfuscatable: true, match: "heuristic" };
}
