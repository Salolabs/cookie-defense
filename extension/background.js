import { classifyCookies, classifyCookie } from "./lib/classify.js";
import { generateLoremValue } from "./lib/lorem.js";
import { inspectValue } from "./lib/reverse.js";
import { assessCookie } from "./lib/risk.js";
import { t } from "./lib/i18n.js";
import { applyHeuristic } from "./lib/heuristic.js";
import {
  getLevel,
  setLevel,
  getWhitelist,
  addToWhitelist,
  getGlobalAutoProtect,
  setGlobalAutoProtect,
} from "./lib/settings.js";
import { addBackup, findBackup, removeBackup, backupsForDomain } from "./lib/backup.js";

// domain -> value we just wrote, so the onChanged echo of our own
// chrome.cookies.set() call isn't mistaken for the site re-setting the
// cookie and re-obfuscated in an infinite loop.
const lastWritten = new Map();

function cookieKey(cookie) {
  return `${cookie.domain}|${cookie.name}|${cookie.path}`;
}

function hostnameOf(domain) {
  return domain.replace(/^\./, "");
}

async function urlForCookie(cookie) {
  const domain = hostnameOf(cookie.domain);
  const protocol = cookie.secure ? "https" : "http";
  return `${protocol}://${domain}${cookie.path}`;
}

async function getBackups() {
  const { cookieBackups } = await chrome.storage.local.get("cookieBackups");
  return Array.isArray(cookieBackups) ? cookieBackups : [];
}

async function saveBackups(backups) {
  await chrome.storage.local.set({ cookieBackups: backups });
}

// Backs up the real value about to be lost UNLESS what we're about to
// overwrite is already our own fake value (re-obfuscating an untouched fake
// is a no-op re: the real backup, and must not clobber it with fake data).
async function backupBeforeOverwrite(cookie) {
  const isOwnPreviousFake = lastWritten.get(cookieKey(cookie)) === cookie.value;
  if (isOwnPreviousFake) return;
  const backups = await getBackups();
  await saveBackups(
    addBackup(backups, {
      domain: cookie.domain,
      name: cookie.name,
      path: cookie.path,
      originalValue: cookie.value,
    })
  );
}

async function overwriteCookie(cookie, encoding) {
  await backupBeforeOverwrite(cookie);
  const fakeValue = generateLoremValue(cookie.value, cookieKey(cookie), encoding);
  const url = await urlForCookie(cookie);
  const details = {
    url,
    name: cookie.name,
    value: fakeValue,
    path: cookie.path,
    secure: cookie.secure,
    httpOnly: cookie.httpOnly,
    sameSite: cookie.sameSite,
    storeId: cookie.storeId,
  };
  if (!cookie.hostOnly) details.domain = cookie.domain;
  if (!cookie.session) details.expirationDate = cookie.expirationDate;

  lastWritten.set(cookieKey(cookie), fakeValue);
  await chrome.cookies.set(details);
  return fakeValue;
}

// Writes `value` back into the (currently obfuscated) cookie identified by
// domain/name/path, reusing whatever flags the live cookie currently has —
// overwriteCookie always preserves the original flags when faking a value,
// so the current (fake) cookie's flags already match the backed-up original.
async function restoreCookieValue({ domain, name, path }, value) {
  const hostname = hostnameOf(domain);
  const existing = await chrome.cookies.getAll({ domain: hostname, name, path });
  const current = existing[0] || null;
  const protocol = current ? (current.secure ? "https" : "http") : "https";
  const details = {
    url: `${protocol}://${hostname}${path}`,
    name,
    value,
    path,
    secure: current ? current.secure : true,
    httpOnly: current ? current.httpOnly : false,
    sameSite: current ? current.sameSite : "lax",
    storeId: current ? current.storeId : undefined,
  };
  if (!current || !current.hostOnly) details.domain = domain;
  if (current && !current.session) details.expirationDate = current.expirationDate;

  // The value we're about to write is the real one again, not a fake — make
  // sure a subsequent onChanged event doesn't get ignored as "our own echo".
  lastWritten.delete(cookieKey({ domain, name, path }));
  await chrome.cookies.set(details);
}

async function restoreBackup({ domain, name, path }) {
  const backups = await getBackups();
  const backup = findBackup(backups, { domain, name, path });
  if (!backup) throw new Error(t("errorNoBackup"));
  await restoreCookieValue(backup, backup.originalValue);
  await saveBackups(removeBackup(backups, backup));
  return backup;
}

async function getAutoDomains() {
  const { autoDomains } = await chrome.storage.local.get("autoDomains");
  return autoDomains || {};
}

async function setAutoDomain(hostname, enabled) {
  const autoDomains = await getAutoDomains();
  if (enabled) autoDomains[hostname] = true;
  else delete autoDomains[hostname];
  await chrome.storage.local.set({ autoDomains });
}

function buildReportEntry(cookie, classification, revealValues, level, whitelist) {
  const decoded = inspectValue(cookie.value, { revealValues });
  classification = applyHeuristic(cookie, classification, decoded, level, whitelist);
  const risk = assessCookie({ cookie, classification, decoded });
  return {
    name: cookie.name,
    domain: cookie.domain,
    path: cookie.path,
    session: cookie.session,
    hostOnly: cookie.hostOnly,
    httpOnly: cookie.httpOnly,
    secure: cookie.secure,
    sameSite: cookie.sameSite,
    expirationDate: cookie.expirationDate || null,
    valueLength: cookie.value.length,
    category: classification.category,
    platform: classification.platform,
    obfuscatable: classification.obfuscatable,
    match: classification.match,
    decoded,
    risk,
  };
}

async function analyzeUrl(url, revealValues) {
  const [cookies, level, whitelist] = await Promise.all([chrome.cookies.getAll({ url }), getLevel(), getWhitelist()]);
  const classified = await classifyCookies(cookies);
  return classified.map(({ cookie, classification }) =>
    buildReportEntry(cookie, classification, revealValues, level, whitelist)
  );
}

async function obfuscateUrl(url) {
  const [cookies, level, whitelist] = await Promise.all([chrome.cookies.getAll({ url }), getLevel(), getWhitelist()]);
  const classified = await classifyCookies(cookies);
  const changed = [];
  for (const { cookie, classification } of classified) {
    const decoded = inspectValue(cookie.value);
    const resolved = applyHeuristic(cookie, classification, decoded, level, whitelist);
    if (resolved.obfuscatable) {
      await overwriteCookie(cookie, decoded.encoding);
      changed.push(cookie.name);
    }
  }
  return changed;
}

// Whole-browser snapshot: every cookie currently stored, across every
// domain — this is the actual "current cookie situation", not just the
// active tab's own domain family. Read-only; does not touch any values.
async function fullScan(revealValues) {
  const [cookies, level, whitelist] = await Promise.all([chrome.cookies.getAll({}), getLevel(), getWhitelist()]);
  const classified = await classifyCookies(cookies);
  const entries = classified.map(({ cookie, classification }) =>
    buildReportEntry(cookie, classification, revealValues, level, whitelist)
  );

  const byDomain = new Map();
  for (const e of entries) {
    if (!byDomain.has(e.domain)) byDomain.set(e.domain, []);
    byDomain.get(e.domain).push(e);
  }

  const summary = {
    totalCookies: entries.length,
    totalDomains: byDomain.size,
    obfuscatableCount: entries.filter((e) => e.obfuscatable).length,
    highRiskCount: entries.filter((e) => e.risk.level === "high").length,
    mediumRiskCount: entries.filter((e) => e.risk.level === "medium").length,
    notHttpOnlyCount: entries.filter((e) => !e.httpOnly).length,
    notSecureCount: entries.filter((e) => !e.secure).length,
    jwtCount: entries.filter((e) => e.decoded.encoding === "jwt").length,
    byCategory: {},
  };
  for (const e of entries) {
    summary.byCategory[e.category] = (summary.byCategory[e.category] || 0) + 1;
  }

  return { entries, domains: Array.from(byDomain.keys()).sort(), summary };
}

async function obfuscateAllBrowser() {
  const [cookies, level, whitelist] = await Promise.all([chrome.cookies.getAll({}), getLevel(), getWhitelist()]);
  const classified = await classifyCookies(cookies);
  const changed = [];
  for (const { cookie, classification } of classified) {
    const decoded = inspectValue(cookie.value);
    const resolved = applyHeuristic(cookie, classification, decoded, level, whitelist);
    if (resolved.obfuscatable) {
      await overwriteCookie(cookie, decoded.encoding);
      changed.push({ domain: cookie.domain, name: cookie.name });
    }
  }
  return changed;
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    try {
      if (message.type === "ANALYZE") {
        sendResponse({ ok: true, cookies: await analyzeUrl(message.url, message.revealValues) });
      } else if (message.type === "OBFUSCATE_NOW") {
        sendResponse({ ok: true, changed: await obfuscateUrl(message.url) });
      } else if (message.type === "GET_AUTO_DOMAINS") {
        sendResponse({ ok: true, autoDomains: await getAutoDomains() });
      } else if (message.type === "SET_AUTO_DOMAIN") {
        await setAutoDomain(message.hostname, message.enabled);
        if (message.enabled) await obfuscateUrl(message.url);
        sendResponse({ ok: true });
      } else if (message.type === "FULL_SCAN") {
        sendResponse({ ok: true, report: await fullScan(message.revealValues) });
      } else if (message.type === "OBFUSCATE_ALL_BROWSER") {
        sendResponse({ ok: true, changed: await obfuscateAllBrowser() });
      } else if (message.type === "GET_SETTINGS") {
        const [level, whitelist, globalAutoProtect] = await Promise.all([
          getLevel(),
          getWhitelist(),
          getGlobalAutoProtect(),
        ]);
        sendResponse({ ok: true, level, whitelist, globalAutoProtect });
      } else if (message.type === "SET_LEVEL") {
        await setLevel(message.level);
        sendResponse({ ok: true });
      } else if (message.type === "SET_GLOBAL_AUTO_PROTECT") {
        await setGlobalAutoProtect(message.enabled);
        sendResponse({ ok: true });
      } else if (message.type === "GET_BACKUPS_FOR_DOMAIN") {
        const backups = await getBackups();
        sendResponse({ ok: true, backups: backupsForDomain(backups, message.domain) });
      } else if (message.type === "RESTORE_COOKIE") {
        const backup = await restoreBackup(message.cookieRef);
        sendResponse({ ok: true, backup });
      } else if (message.type === "WHITELIST_COOKIE") {
        const backup = await restoreBackup(message.cookieRef);
        await addToWhitelist(message.cookieRef.name);
        sendResponse({ ok: true, backup });
      } else {
        sendResponse({ ok: false, error: t("errorUnknown") });
      }
    } catch (err) {
      sendResponse({ ok: false, error: String(err && err.message ? err.message : err) });
    }
  })();
  return true; // keep the message channel open for the async response
});

// Continuous protection: if a site (re-)sets a cookie on a domain the user
// enabled auto-obfuscation for — or on ANY domain, if the global "protect
// every site" switch is on — immediately overwrite it again.
chrome.cookies.onChanged.addListener((changeInfo) => {
  if (changeInfo.removed) return;
  const cookie = changeInfo.cookie;
  const key = cookieKey(cookie);
  if (lastWritten.get(key) === cookie.value) {
    // This is the echo of our own write; ignore it.
    lastWritten.delete(key);
    return;
  }
  (async () => {
    const hostname = hostnameOf(cookie.domain);
    const [autoDomains, globalAutoProtect] = await Promise.all([getAutoDomains(), getGlobalAutoProtect()]);
    if (!globalAutoProtect && !autoDomains[hostname]) return;
    const [classification, level, whitelist] = await Promise.all([
      classifyCookie(cookie.name),
      getLevel(),
      getWhitelist(),
    ]);
    const decoded = inspectValue(cookie.value);
    const resolved = applyHeuristic(cookie, classification, decoded, level, whitelist);
    if (resolved.obfuscatable) {
      await overwriteCookie(cookie, decoded.encoding);
    }
  })();
});
