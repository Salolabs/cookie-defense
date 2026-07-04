// Thin wrapper around chrome.i18n so callers don't need to know whether
// they're passing zero, one, or many substitution values, plus small
// lookup tables for the internal (English, locale-independent) category
// and risk-level tokens used throughout classify.js/risk.js/background.js.

export function t(key, substitutions) {
  return chrome.i18n.getMessage(key, substitutions);
}

const CATEGORY_KEYS = {
  Analytics: "categoryAnalytics",
  Marketing: "categoryMarketing",
  Personalization: "categoryPersonalization",
  Functional: "categoryFunctional",
  Necessary: "categoryNecessary",
  Security: "categorySecurity",
  Unknown: "categoryUnknown",
};

// Cookie categories come from the bundled database (see classify.js) as
// stable English tokens; this only translates them for display.
export function categoryLabel(category) {
  const key = CATEGORY_KEYS[category];
  return key ? t(key) : category;
}

const RISK_KEYS = { low: "riskLow", medium: "riskMedium", high: "riskHigh" };

// Risk levels are stable English tokens (see risk.js) so they can be used
// as CSS classes and compared in code; this only translates them for display.
export function riskLevelLabel(level) {
  const key = RISK_KEYS[level];
  return key ? t(key) : level;
}
