// Heuristic attack-surface scoring for a single cookie. This is a judgement
// aid, not a certified audit: weights are approximate and documented inline
// so they can be argued with. "First/third-party" here means "host-only vs.
// shared across the site's own subdomain family" — chrome.cookies.getAll({url})
// only ever returns cookies whose Domain attribute already matches the tab's
// URL, so genuinely unrelated third-party tracker domains never appear here;
// see the full-browser scan for that.

import { t, categoryLabel } from "./i18n.js";

const PII_LOOKING_CLAIMS = new Set([
  "email",
  "e_mail",
  "phone",
  "phone_number",
  "name",
  "given_name",
  "family_name",
  "address",
  "user_id",
  "userid",
  "uid",
  "sub",
]);

const LONG_LIVED_DAYS = 180;

export function assessCookie({ cookie, classification, decoded }) {
  const factors = [];
  let score = 0;

  const tracking = ["Analytics", "Marketing", "Personalization"].includes(classification.category);
  if (tracking) {
    const platformSuffix = classification.platform ? ` (${classification.platform})` : "";
    factors.push(t("factorTracking", [categoryLabel(classification.category), platformSuffix]));
    score += 2;
  } else if (classification.match === "heuristic") {
    factors.push(t("factorHeuristicUnknown"));
    score += 1;
  }

  if (!cookie.httpOnly) {
    factors.push(t("factorNotHttpOnly"));
    score += 1;
  }

  if (!cookie.secure) {
    factors.push(t("factorNotSecure"));
    score += 1;
  }

  if (cookie.sameSite === "no_restriction") {
    factors.push(t("factorSameSiteNone"));
    score += 1;
  }

  if (!cookie.hostOnly) {
    factors.push(t("factorDomainShared"));
    score += 0.5;
  }

  if (!cookie.session && typeof cookie.expirationDate === "number") {
    const days = (cookie.expirationDate * 1000 - Date.now()) / 86400000;
    if (days > LONG_LIVED_DAYS) {
      factors.push(t("factorLongLived", [String(Math.round(days))]));
      score += 1;
    }
  }

  if (decoded.encoding === "jwt") {
    const claims = Object.keys((decoded.details && decoded.details.payload) || {});
    const piiHits = claims.filter((c) => PII_LOOKING_CLAIMS.has(c.toLowerCase()));
    if (piiHits.length) {
      factors.push(t("factorJwtPii", [piiHits.join(", ")]));
      score += 2;
    } else if (claims.length) {
      factors.push(t("factorJwtFields", [claims.join(", ")]));
      score += 0.5;
    }
  }

  let level = "low";
  if (score >= 4) level = "high";
  else if (score >= 2) level = "medium";

  return { score, level, factors };
}
