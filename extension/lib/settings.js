// Persisted user settings: the aggressiveness level (1-5, see lib/heuristic.js
// for what each level actually gates) and the user's own explicit whitelist
// of cookie names that should never be touched regardless of level. Both
// live in chrome.storage.local — never synced, never leaves the device.

export const DEFAULT_LEVEL = 2;
export const MIN_LEVEL = 1;
export const MAX_LEVEL = 5;

const KEY_LEVEL = "aggressivenessLevel";
const KEY_WHITELIST = "userWhitelist";
const KEY_GLOBAL_AUTO_PROTECT = "globalAutoProtect";

export async function getLevel() {
  const { [KEY_LEVEL]: level } = await chrome.storage.local.get(KEY_LEVEL);
  return isValidLevel(level) ? level : DEFAULT_LEVEL;
}

export async function setLevel(level) {
  if (!isValidLevel(level)) throw new Error(`invalid level: ${level}`);
  await chrome.storage.local.set({ [KEY_LEVEL]: level });
}

export function isValidLevel(level) {
  return Number.isInteger(level) && level >= MIN_LEVEL && level <= MAX_LEVEL;
}

export async function getWhitelist() {
  const { [KEY_WHITELIST]: list } = await chrome.storage.local.get(KEY_WHITELIST);
  return Array.isArray(list) ? list : [];
}

export async function addToWhitelist(name) {
  const list = await getWhitelist();
  if (!isWhitelisted(name, list)) list.push(name);
  await chrome.storage.local.set({ [KEY_WHITELIST]: list });
  return list;
}

export async function removeFromWhitelist(name) {
  const list = (await getWhitelist()).filter((n) => n !== name);
  await chrome.storage.local.set({ [KEY_WHITELIST]: list });
  return list;
}

// Pure check, kept separate from the chrome.storage plumbing above so it's
// trivially unit-testable: exact cookie-name match against the whitelist.
export function isWhitelisted(name, whitelist) {
  return Array.isArray(whitelist) && whitelist.includes(name);
}

// Global "protect every site continuously" switch. Off by default — the
// per-site autoDomains list (background.js) is the opt-in path; this
// overrides it to apply everywhere without visiting each site's toggle.
export async function getGlobalAutoProtect() {
  const { [KEY_GLOBAL_AUTO_PROTECT]: enabled } = await chrome.storage.local.get(KEY_GLOBAL_AUTO_PROTECT);
  return Boolean(enabled);
}

export async function setGlobalAutoProtect(enabled) {
  await chrome.storage.local.set({ [KEY_GLOBAL_AUTO_PROTECT]: Boolean(enabled) });
}
