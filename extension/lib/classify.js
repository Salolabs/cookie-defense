// Classifies a cookie name against the bundled Open Cookie Database
// (see third_party/open-cookie-database.csv, Apache-2.0, regenerated via
// scripts/build_cookie_db.py). Unknown cookies default to "not obfuscatable"
// — a cookie we can't identify might be a login/session/CSRF token, and
// breaking those is worse than leaving an unrecognized tracker untouched.

let dbPromise = null;

async function loadDb() {
  if (!dbPromise) {
    dbPromise = fetch(chrome.runtime.getURL("data/cookie-database.json")).then((r) =>
      r.json()
    );
  }
  return dbPromise;
}

export async function classifyCookie(name) {
  const db = await loadDb();
  const exact = db.exact[name];
  if (exact) {
    return { ...exact, match: "exact", matchedRule: name };
  }
  for (const rule of db.prefixes) {
    if (name.startsWith(rule.prefix)) {
      return {
        category: rule.category,
        platform: rule.platform,
        obfuscatable: rule.obfuscatable,
        match: "prefix",
        matchedRule: rule.prefix,
      };
    }
  }
  return {
    category: "Unknown",
    platform: "",
    obfuscatable: false,
    match: "none",
    matchedRule: null,
  };
}

export async function classifyCookies(cookies) {
  const results = [];
  for (const cookie of cookies) {
    const classification = await classifyCookie(cookie.name);
    results.push({ cookie, classification });
  }
  return results;
}
