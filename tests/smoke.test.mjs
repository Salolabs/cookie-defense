// Minimal Node-based smoke test for the classification + lorem-value logic,
// run outside a real browser by stubbing the tiny bit of `chrome.*` surface
// that the lib/*.js modules touch (runtime.getURL, fetch, and i18n.getMessage
// — the last one backed by the real _locales/<locale>/messages.json files,
// so this also doubles as a regression check that the fi/en catalogs stay in
// sync and that chrome.i18n placeholder substitution actually works).
// Not a substitute for loading the unpacked extension in Chrome and clicking
// through it, just a fast regression check.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const extensionDir = path.join(__dirname, "..", "extension");

function loadMessages(locale) {
  return JSON.parse(readFileSync(path.join(extensionDir, "_locales", locale, "messages.json"), "utf8"));
}

function getMessage(messages, key, substitutions) {
  const entry = messages[key];
  if (!entry) return "";
  let msg = entry.message;
  const subs = substitutions == null ? [] : Array.isArray(substitutions) ? substitutions : [substitutions];
  for (const [name, def] of Object.entries(entry.placeholders || {})) {
    const index = Number(String(def.content).replace("$", "")) - 1;
    msg = msg.split(`$${name}$`).join(subs[index] !== undefined ? String(subs[index]) : "");
  }
  return msg;
}

let activeMessages = loadMessages("fi");
let activeLocale = "fi";

// In-memory stand-in for chrome.storage.local, just enough of the real API
// shape (get(key) -> {[key]: value}, set(obj) -> merge) for lib/settings.js.
const storageData = {};
globalThis.chrome = {
  runtime: {
    getURL: (p) => pathToFileURL(path.join(extensionDir, p)).href,
  },
  i18n: {
    getMessage: (key, substitutions) => getMessage(activeMessages, key, substitutions),
    getUILanguage: () => activeLocale,
  },
  storage: {
    local: {
      get: async (key) => (typeof key === "string" ? { [key]: storageData[key] } : { ...storageData }),
      set: async (obj) => Object.assign(storageData, obj),
    },
  },
};
const originalFetch = globalThis.fetch;
globalThis.fetch = async (url) => {
  const filePath = fileURLToPath(url);
  return { json: async () => JSON.parse(readFileSync(filePath, "utf8")) };
};

const { classifyCookie } = await import(pathToFileURL(path.join(extensionDir, "lib/classify.js")).href);
const { generateLoremValue } = await import(pathToFileURL(path.join(extensionDir, "lib/lorem.js")).href);
const { inspectValue } = await import(pathToFileURL(path.join(extensionDir, "lib/reverse.js")).href);
const { assessCookie } = await import(pathToFileURL(path.join(extensionDir, "lib/risk.js")).href);
const { formatSiteReport } = await import(pathToFileURL(path.join(extensionDir, "lib/report.js")).href);
const { categoryLabel } = await import(pathToFileURL(path.join(extensionDir, "lib/i18n.js")).href);
const { applyHeuristic } = await import(pathToFileURL(path.join(extensionDir, "lib/heuristic.js")).href);
const settings = await import(pathToFileURL(path.join(extensionDir, "lib/settings.js")).href);
const backupLib = await import(pathToFileURL(path.join(extensionDir, "lib/backup.js")).href);

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

// fi/en catalogs must define exactly the same set of keys, or a caller could
// silently get an empty string in one locale.
function assertMessageCatalogsMatch() {
  const fi = Object.keys(loadMessages("fi")).sort();
  const en = Object.keys(loadMessages("en")).sort();
  assert.deepEqual(fi, en, "fi/en messages.json must define the same keys");
}

async function run(locale, expected) {
  activeLocale = locale;
  activeMessages = loadMessages(locale);

  // Known Google Analytics cookie -> exact match, obfuscatable.
  const ga = await classifyCookie("_ga");
  assert.equal(ga.match, "exact");
  assert.equal(ga.obfuscatable, true);

  // GA4 per-property cookie uses the "_ga_" prefix rule.
  const ga4 = await classifyCookie("_ga_ABCDE12345");
  assert.equal(ga4.match, "prefix");
  assert.equal(ga4.obfuscatable, true);

  // A known session cookie (PHPSESSID) is classified "Functional" upstream
  // -> must never be obfuscatable, since that would break logins. Category
  // tokens from the database are stable English strings, independent of UI
  // locale.
  const phpSession = await classifyCookie("PHPSESSID");
  assert.equal(phpSession.obfuscatable, false);
  assert.equal(phpSession.category, "Functional");

  // A name absent from the database entirely -> unknown at the classify.js
  // layer (fail-safe baseline for anyone using classify.js in isolation).
  // background.js applies applyHeuristic() on top of this — see below.
  const unknown = await classifyCookie("this_cookie_name_is_not_in_any_database_xyz123");
  assert.equal(unknown.obfuscatable, false);
  assert.equal(unknown.category, "Unknown");

  // OSINT-identified trackers added to third_party/local-overrides.csv must
  // resolve like any other database entry (real full-browser-scan finding:
  // these were previously invisible inside the "Unknown" bucket).
  const criteo = await classifyCookie("cto_bundle");
  assert.equal(criteo.match, "exact");
  assert.equal(criteo.category, "Marketing");
  assert.equal(criteo.obfuscatable, true);

  // Fraud-detection/device-fingerprinting cookies must stay explicitly
  // protected even under the new deny-by-default policy — corrupting them
  // risks account lockouts on real payment/banking-adjacent sites without
  // reducing tracking (fingerprinting doesn't depend on the cookie value).
  const threatMetrix = await classifyCookie("thx_guid");
  assert.equal(threatMetrix.category, "Security");
  assert.equal(threatMetrix.obfuscatable, false);

  // --- heuristic secondary classifier (applies only where the database
  // came back empty — "if it isn't whitelisted, it's junk", but evidence-
  // based: a real scan showed some genuine auth/refresh tokens are also
  // "not HttpOnly", so HttpOnly alone can't be the discriminator) ---

  // An unrecognized, opaque, ordinary-looking cookie -> junked by default.
  const junkableUnknown = applyHeuristic(
    { name: "xyzUnknownTrackerId9000", httpOnly: false, session: false },
    { category: "Unknown", platform: "", obfuscatable: false, match: "none" },
    { encoding: "opaque", details: {} }
  );
  assert.equal(junkableUnknown.obfuscatable, true);
  assert.equal(junkableUnknown.match, "heuristic");

  // An unrecognized cookie whose value is a JWT with session-like claims ->
  // protected regardless of name or HttpOnly, so real logins never break.
  const protectedAuthJwt = applyHeuristic(
    { name: "some_vendors_weird_cookie_name", httpOnly: false, session: true },
    { category: "Unknown", platform: "", obfuscatable: false, match: "none" },
    { encoding: "jwt", details: { payload: { sub: "user-123", exp: 123456 } } }
  );
  assert.equal(protectedAuthJwt.obfuscatable, false);

  // An unrecognized cookie whose *name* clearly says session/auth/token ->
  // also protected, even with an opaque (non-JWT) value.
  const protectedByName = applyHeuristic(
    { name: "app_session_token", httpOnly: false, session: false },
    { category: "Unknown", platform: "", obfuscatable: false, match: "none" },
    { encoding: "opaque", details: {} }
  );
  assert.equal(protectedByName.obfuscatable, false);

  // A database hit is trusted as-is — the heuristic must never override it
  // (e.g. must not "protect" a confirmed tracker just because its name
  // happens to contain "id").
  const dbHitUnchanged = applyHeuristic(
    { name: "cto_bundle", httpOnly: false, session: false },
    criteo,
    { encoding: "opaque", details: {} }
  );
  assert.equal(dbHitUnchanged.obfuscatable, true);
  assert.equal(dbHitUnchanged.match, "exact");

  // --- aggressiveness levels 1-5: each level drops exactly one protective
  // signal, weakest evidence first (see lib/heuristic.js module doc) ---

  const dbNone = { category: "Unknown", platform: "", obfuscatable: false, match: "none" };
  const httpOnlySessionCookie = { name: "weirdname123", httpOnly: true, session: true };
  const namePatternCookie = { name: "app_session_id", httpOnly: false, session: false };
  const jwtSessionDecoded = { encoding: "jwt", details: { payload: { sub: "u1" } } };
  const genericOpaqueDecoded = { encoding: "opaque", details: {} };
  const plainUnknownCookie = { name: "xzy123random", httpOnly: false, session: false };

  // Level 1: heuristic fully disabled, "Unknown" is never touched by it.
  assert.equal(applyHeuristic(plainUnknownCookie, dbNone, genericOpaqueDecoded, 1).obfuscatable, false);
  assert.equal(applyHeuristic(plainUnknownCookie, dbNone, jwtSessionDecoded, 1).obfuscatable, false);

  // Level 2 (default): all three signals protect; only a cookie with none
  // of them gets junked.
  assert.equal(applyHeuristic(httpOnlySessionCookie, dbNone, genericOpaqueDecoded, 2).obfuscatable, false);
  assert.equal(applyHeuristic(namePatternCookie, dbNone, genericOpaqueDecoded, 2).obfuscatable, false);
  assert.equal(applyHeuristic(plainUnknownCookie, dbNone, jwtSessionDecoded, 2).obfuscatable, false);
  assert.equal(applyHeuristic(plainUnknownCookie, dbNone, genericOpaqueDecoded, 2).obfuscatable, true);

  // Level 3: HttpOnly+session alone no longer protects; name pattern and JWT still do.
  assert.equal(applyHeuristic(httpOnlySessionCookie, dbNone, genericOpaqueDecoded, 3).obfuscatable, true);
  assert.equal(applyHeuristic(namePatternCookie, dbNone, genericOpaqueDecoded, 3).obfuscatable, false);
  assert.equal(applyHeuristic(plainUnknownCookie, dbNone, jwtSessionDecoded, 3).obfuscatable, false);

  // Level 4: name pattern also stops protecting; only JWT session claims do.
  assert.equal(applyHeuristic(namePatternCookie, dbNone, genericOpaqueDecoded, 4).obfuscatable, true);
  assert.equal(applyHeuristic(plainUnknownCookie, dbNone, jwtSessionDecoded, 4).obfuscatable, false);

  // Level 5: nothing protects except the user's own explicit whitelist.
  assert.equal(applyHeuristic(plainUnknownCookie, dbNone, jwtSessionDecoded, 5).obfuscatable, true);
  assert.equal(
    applyHeuristic(plainUnknownCookie, dbNone, genericOpaqueDecoded, 5, ["xzy123random"]).obfuscatable,
    false,
    "user whitelist must override even at the most aggressive level"
  );
  // A database hit is never touched by the heuristic at ANY level, including 5.
  assert.equal(applyHeuristic({ name: "cto_bundle" }, criteo, genericOpaqueDecoded, 5).match, "exact");

  // An invalid/out-of-range level falls back to the default (2) rather than
  // silently disabling protection or crashing.
  assert.equal(
    applyHeuristic(httpOnlySessionCookie, dbNone, genericOpaqueDecoded, 999).obfuscatable,
    false,
    "out-of-range level must fall back to the default level's behavior"
  );

  // --- lib/settings.js: persisted level + user whitelist ---

  assert.equal(await settings.getLevel(), settings.DEFAULT_LEVEL, "level defaults to 2 before anything is set");
  await settings.setLevel(4);
  assert.equal(await settings.getLevel(), 4, "setLevel/getLevel round-trip through chrome.storage.local");
  await assert.rejects(() => settings.setLevel(6), /invalid level/);
  await assert.rejects(() => settings.setLevel(0), /invalid level/);
  await settings.setLevel(settings.DEFAULT_LEVEL); // reset for isolation from other assertions

  assert.deepEqual(await settings.getWhitelist(), []);
  await settings.addToWhitelist("my_functional_cookie");
  assert.deepEqual(await settings.getWhitelist(), ["my_functional_cookie"]);
  await settings.addToWhitelist("my_functional_cookie"); // idempotent, no duplicate
  assert.deepEqual(await settings.getWhitelist(), ["my_functional_cookie"]);
  assert.equal(settings.isWhitelisted("my_functional_cookie", ["my_functional_cookie"]), true);
  assert.equal(settings.isWhitelisted("someone_else", ["my_functional_cookie"]), false);
  await settings.removeFromWhitelist("my_functional_cookie");
  assert.deepEqual(await settings.getWhitelist(), []);

  // Global "protect every site" switch defaults to off, round-trips through
  // chrome.storage.local like the other settings.
  assert.equal(await settings.getGlobalAutoProtect(), false);
  await settings.setGlobalAutoProtect(true);
  assert.equal(await settings.getGlobalAutoProtect(), true);
  await settings.setGlobalAutoProtect(false); // reset for isolation from other assertions

  // --- lib/backup.js: pure backup-list management (no chrome.* calls) ---

  const ref = { domain: ".example.com", name: "_ga", path: "/" };
  let backups = backupLib.addBackup([], { ...ref, originalValue: "GA1.2.111.222" }, 1_000);
  assert.equal(backupLib.findBackup(backups, ref).originalValue, "GA1.2.111.222");

  // Re-obfuscating the same cookie replaces the stored backup rather than
  // stacking a second entry for the same (domain, name, path).
  backups = backupLib.addBackup(backups, { ...ref, originalValue: "GA1.2.333.444" }, 2_000);
  assert.equal(backups.length, 1);
  assert.equal(backupLib.findBackup(backups, ref).originalValue, "GA1.2.333.444");

  // Domain lookup ignores the leading-dot host-only/domain-shared distinction.
  assert.equal(backupLib.backupsForDomain(backups, "example.com").length, 1);

  // Restoring removes the backup — it shouldn't be offered again afterward.
  backups = backupLib.removeBackup(backups, ref);
  assert.equal(backupLib.findBackup(backups, ref), null);

  // Retention: entries older than RETENTION_MS are dropped.
  const old = backupLib.addBackup([], { ...ref, originalValue: "stale" }, 0);
  const pruned = backupLib.pruneBackups(old, backupLib.RETENTION_MS + 1);
  assert.equal(pruned.length, 0);

  // Cap: only the most recent MAX_BACKUPS entries survive pruning.
  let manyBackups = [];
  for (let i = 0; i < backupLib.MAX_BACKUPS + 10; i++) {
    manyBackups = backupLib.addBackup(
      manyBackups,
      { domain: "example.com", name: `cookie_${i}`, path: "/", originalValue: String(i) },
      i
    );
  }
  assert.equal(manyBackups.length, backupLib.MAX_BACKUPS);
  assert.equal(backupLib.findBackup(manyBackups, { domain: "example.com", name: "cookie_0", path: "/" }), null);
  assert.ok(backupLib.findBackup(manyBackups, { domain: "example.com", name: `cookie_${backupLib.MAX_BACKUPS + 9}`, path: "/" }));

  // Lorem value must be RFC 6265 cookie-octet safe and roughly length-matched.
  const original = "a".repeat(40);
  const fake = generateLoremValue(original, "example.com|_ga|/ ");
  assert.equal(fake.length, 40);
  assert.doesNotMatch(fake, /[\s",;\\]/);

  // Same seed key -> stable output (avoids needless churn on repeat passes).
  const fake2 = generateLoremValue(original, "example.com|_ga|/ ");
  assert.equal(fake, fake2);

  // Format-preserving fake values: a tracker's own client-side code usually
  // does "if cookie exists AND parses as <shape> use it, else regenerate" —
  // a fake value that doesn't parse gets silently healed away on the very
  // next page load. Each shape lib/reverse.js can detect must round-trip
  // back through inspectValue() as that SAME shape, or the poisoning is
  // ineffective against any tracker that validates format client-side.
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const formatCases = [
    ["uuid", "550e8400-e29b-41d4-a716-446655440000"],
    ["ga-client-id", "GA1.2.1234567890.1600000000"],
    ["hex", "a3f5c9d1e8b7a2f4"],
    ["numeric", "123456789"],
    ["json", '{"a":1}'],
    ["base64-json", "eyJhIjoxfQ=="],
    ["jwt", "aaa.bbb.ccc"],
  ];
  for (const [encoding, sample] of formatCases) {
    const poisoned = generateLoremValue(sample, `seed|${encoding}`, encoding);
    assert.equal(inspectValue(poisoned).encoding, encoding, `${encoding} fake value must re-detect as ${encoding}`);
  }
  assert.match(generateLoremValue("x", "seed|uuid", "uuid"), UUID_RE);

  // --- reverse-engineering: structural decoding of cookie values ---

  const jwtValue = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({
    sub: "1234567890",
    email: "user@example.com",
    iat: 1516239022,
  })}.signature-not-checked`;
  const jwtDecoded = inspectValue(jwtValue);
  assert.equal(jwtDecoded.encoding, "jwt");
  assert.deepEqual(jwtDecoded.details.payloadKeys.sort(), ["email", "iat", "sub"]);
  // Values redacted by default — the raw email must not leak into the report.
  assert.ok(!JSON.stringify(jwtDecoded.details.payload).includes("user@example.com"));
  // The decoded summary is localized text — sanity-check it against this
  // locale's expected wording rather than a hardcoded (formerly Finnish) string.
  assert.equal(jwtDecoded.summary, expected.encJwt);

  const jwtRevealed = inspectValue(jwtValue, { revealValues: true });
  assert.equal(jwtRevealed.details.payload.email, "user@example.com");

  const uuidDecoded = inspectValue("550e8400-e29b-41d4-a716-446655440000");
  assert.equal(uuidDecoded.encoding, "uuid");

  const hexDecoded = inspectValue("a3f5c9d1e8b7a2f4");
  assert.equal(hexDecoded.encoding, "hex");

  const opaqueDecoded = inspectValue("xJ8kL2mQ9pR");
  assert.notEqual(opaqueDecoded.encoding, "jwt");

  // --- risk scoring ---

  const trackerNoFlags = assessCookie({
    cookie: { httpOnly: false, secure: false, sameSite: "no_restriction", hostOnly: true, session: true },
    classification: { category: "Marketing", platform: "AdTech" },
    decoded: { encoding: "opaque", details: {} },
  });
  const functionalSecure = assessCookie({
    cookie: { httpOnly: true, secure: true, sameSite: "lax", hostOnly: true, session: true },
    classification: { category: "Functional", platform: "" },
    decoded: { encoding: "opaque", details: {} },
  });
  assert.ok(trackerNoFlags.score > functionalSecure.score);
  // Risk levels are stable English tokens ("low"/"medium"/"high") regardless
  // of UI locale — they're used as CSS classes and compared in background.js.
  assert.equal(functionalSecure.level, "low");
  // The factor text must show the *translated* category name, not the raw
  // internal token — this regressed once already (risk.js passed
  // classification.category straight through instead of categoryLabel()).
  assert.ok(trackerNoFlags.factors[0].includes(expected.trackingFactorNeedle));

  // Every category the bundled database actually uses (not just the ones
  // documented in the README) must have a translation — a real-world report
  // once leaked an untranslated "Necessary" into an otherwise-Finnish report.
  for (const [category, label] of Object.entries(expected.categoryLabels)) {
    assert.equal(categoryLabel(category), label, `categoryLabel(${category}) in ${locale}`);
  }

  // --- report formatting (this is where locale actually shows up) ---

  const md = formatSiteReport({
    hostname: "example.com",
    entries: [
      {
        name: "_ga",
        domain: ".example.com",
        session: false,
        httpOnly: false,
        secure: true,
        sameSite: "lax",
        hostOnly: false,
        category: "Analytics",
        platform: "Google Analytics",
        obfuscatable: true,
        decoded: { summary: "Google Analytics client ID format", details: {} },
        risk: { level: "medium", score: 2.5, factors: ["Tracking category: Analytics"] },
      },
    ],
    generatedAt: "2026-07-04T00:00:00.000Z",
  });
  assert.match(md, /_ga/);
  assert.match(md, new RegExp(expected.riskMediumLabel));
  assert.match(md, /Open Cookie Database/);

  console.log(`smoke tests passed (${locale})`);
}

assertMessageCatalogsMatch();

run("fi", {
  encJwt: "JWT (JSON Web Token) — base64url-koodattu, ei salattu; kuka tahansa sen näkevä voi lukea sisällön",
  trackingFactorNeedle: "Seurantaluokka: Markkinointi",
  riskMediumLabel: "Keskitaso",
  categoryLabels: {
    Analytics: "Analytiikka",
    Marketing: "Markkinointi",
    Personalization: "Personointi",
    Functional: "Toiminnallinen",
    Necessary: "Välttämätön",
    Security: "Turvallisuus",
    Unknown: "Tuntematon",
  },
})
  .then(() =>
    run("en", {
      encJwt: "JWT (JSON Web Token) — base64url-encoded, not encrypted; anyone who sees it can read the contents",
      trackingFactorNeedle: "Tracking category: Marketing",
      riskMediumLabel: "Medium",
      categoryLabels: {
        Analytics: "Analytics",
        Marketing: "Marketing",
        Personalization: "Personalization",
        Functional: "Functional",
        Necessary: "Necessary",
        Security: "Security",
        Unknown: "Unknown",
      },
    })
  )
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(() => {
    globalThis.fetch = originalFetch;
  });
