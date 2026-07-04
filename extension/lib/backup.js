// Pure list-management for cookie value backups — no chrome.* calls, so it's
// easy to unit test. background.js owns reading/writing the actual list to
// chrome.storage.local; this module only decides what the list should look
// like after an add/prune, given the list and a clock it can inject.
//
// Backups exist because the deny-by-default heuristic (lib/heuristic.js) can
// misclassify a real functional cookie as junk. Every value this extension
// overwrites is backed up first so it can be restored. Because a backup is a
// copy of a real cookie value (session tokens, IDs — potentially sensitive),
// it is deliberately short-lived and capped rather than kept forever.

export const MAX_BACKUPS = 500;
export const RETENTION_MS = 14 * 24 * 3600 * 1000; // 14 days

function sameCookie(a, b) {
  return a.domain === b.domain && a.name === b.name && a.path === b.path;
}

// Drops entries older than RETENTION_MS, then keeps only the most recent
// MAX_BACKUPS if still over the cap.
export function pruneBackups(backups, now = Date.now()) {
  const fresh = backups.filter((b) => now - b.timestamp < RETENTION_MS);
  return fresh.length > MAX_BACKUPS ? fresh.slice(fresh.length - MAX_BACKUPS) : fresh;
}

// Replaces any existing backup for the same (domain, name, path) — only the
// most recent original value before the current obfuscation streak matters,
// re-obfuscating an already-backed-up cookie shouldn't stack copies.
export function addBackup(backups, entry, now = Date.now()) {
  const withoutExisting = backups.filter((b) => !sameCookie(b, entry));
  withoutExisting.push({ ...entry, timestamp: now });
  return pruneBackups(withoutExisting, now);
}

export function findBackup(backups, cookieRef) {
  return backups.find((b) => sameCookie(b, cookieRef)) || null;
}

export function removeBackup(backups, cookieRef) {
  return backups.filter((b) => !sameCookie(b, cookieRef));
}

// Cookie.domain can be host-only ("example.com") or domain-shared
// (".example.com") — compare with the leading dot stripped on both sides so
// callers can query with either form.
function bareDomain(domain) {
  return domain.replace(/^\./, "");
}

export function backupsForDomain(backups, domain) {
  const target = bareDomain(domain);
  return backups.filter((b) => bareDomain(b.domain) === target);
}
