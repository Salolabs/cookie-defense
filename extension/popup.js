import { formatSiteReport, formatFullScanReport } from "./lib/report.js";
import { t, categoryLabel, riskLevelLabel } from "./lib/i18n.js";

const hostnameEl = document.getElementById("hostname");
const statusEl = document.getElementById("status");
const analyzeBtn = document.getElementById("analyzeBtn");
const obfuscateBtn = document.getElementById("obfuscateBtn");
const autoToggle = document.getElementById("autoToggle");
const revealToggle = document.getElementById("revealToggle");
const summaryEl = document.getElementById("summary");
const countObfuscatableEl = document.getElementById("countObfuscatable");
const countSafeEl = document.getElementById("countSafe");
const listEl = document.getElementById("cookieList");
const downloadSiteReportBtn = document.getElementById("downloadSiteReportBtn");

const tabSite = document.getElementById("tabSite");
const tabBrowser = document.getElementById("tabBrowser");
const siteView = document.getElementById("siteView");
const browserView = document.getElementById("browserView");
const fullScanBtn = document.getElementById("fullScanBtn");
const obfuscateAllBtn = document.getElementById("obfuscateAllBtn");
const browserStatusEl = document.getElementById("browserStatus");
const browserSummaryEl = document.getElementById("browserSummary");
const downloadBrowserReportBtn = document.getElementById("downloadBrowserReportBtn");

const globalAutoToggle = document.getElementById("globalAutoToggle");
const levelPickerEl = document.getElementById("levelPicker");
const levelWarningEl = document.getElementById("levelWarning");
const backupsSection = document.getElementById("backupsSection");
const backupsListEl = document.getElementById("backupsList");

const LEVELS = [
  { value: 1, nameKey: "level1Name", descKey: "level1Desc" },
  { value: 2, nameKey: "level2Name", descKey: "level2Desc" },
  { value: 3, nameKey: "level3Name", descKey: "level3Desc" },
  { value: 4, nameKey: "level4Name", descKey: "level4Desc" },
  { value: 5, nameKey: "level5Name", descKey: "level5Desc" },
];

let currentTab = null;
let lastSiteEntries = [];
let lastFullScanReport = null;
let currentLevel = 2;

function applyStaticI18n() {
  document.documentElement.lang = chrome.i18n.getUILanguage().split("-")[0];
  for (const el of document.querySelectorAll("[data-i18n]")) {
    el.textContent = t(el.dataset.i18n);
  }
}

function send(message) {
  return chrome.runtime.sendMessage(message).then((res) => {
    if (!res || !res.ok) throw new Error((res && res.error) || t("errorUnknown"));
    return res;
  });
}

function setStatus(text) {
  statusEl.textContent = text;
}

function downloadText(filename, text) {
  const blob = new Blob([text], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

function renderCookieItem(c) {
  const li = document.createElement("li");
  li.className = "cookie-item";
  const badgeClass = c.obfuscatable
    ? "badge-obfuscatable"
    : c.category === "Unknown"
    ? "badge-unknown"
    : "badge-safe";
  const badgeText = c.obfuscatable ? t("labelObfuscatable") : c.category === "Unknown" ? t("labelUnknown") : t("labelSafe");

  const factorsHtml = c.risk.factors.length
    ? `<ul class="factor-list">${c.risk.factors.map((f) => `<li>${f}</li>`).join("")}</ul>`
    : "";

  const sessionSuffix = c.session ? " · " + t("cookieMetaSession") : "";
  li.innerHTML = `
    <div class="cookie-name">${c.name}<span class="badge ${badgeClass}">${badgeText}</span></div>
    <div class="cookie-meta">
      ${categoryLabel(c.category)}${c.platform ? " · " + c.platform : ""} · ${t("cookieMetaChars", [String(c.valueLength)])}${sessionSuffix}
      · ${t("cookieMetaRiskPrefix")}: <span class="risk-${c.risk.level}">${riskLevelLabel(c.risk.level)}</span>
    </div>
    <details class="cookie-details">
      <summary>${c.decoded.summary}</summary>
      ${factorsHtml}
    </details>
  `;
  return li;
}

function renderCookies(cookies) {
  lastSiteEntries = cookies;
  listEl.innerHTML = "";
  const obfuscatable = cookies.filter((c) => c.obfuscatable);
  countObfuscatableEl.textContent = String(obfuscatable.length);
  countSafeEl.textContent = String(cookies.length - obfuscatable.length);
  summaryEl.hidden = cookies.length === 0;
  for (const c of cookies) listEl.appendChild(renderCookieItem(c));
  obfuscateBtn.disabled = obfuscatable.length === 0;
  downloadSiteReportBtn.disabled = cookies.length === 0;
}

async function analyze() {
  setStatus(t("statusAnalyzing"));
  try {
    const res = await send({ type: "ANALYZE", url: currentTab.url, revealValues: revealToggle.checked });
    renderCookies(res.cookies);
    setStatus(t("statusFoundCookies", [String(res.cookies.length)]));
    await loadBackupsForCurrentSite();
  } catch (err) {
    setStatus(t("statusErrorPrefix", [err.message]));
  }
}

async function obfuscateNow() {
  setStatus(t("statusObfuscating"));
  try {
    const res = await send({ type: "OBFUSCATE_NOW", url: currentTab.url });
    setStatus(t("statusObfuscated", [String(res.changed.length)]));
    await analyze();
  } catch (err) {
    setStatus(t("statusErrorPrefix", [err.message]));
  }
}

async function loadAutoToggleState() {
  const url = new URL(currentTab.url);
  const res = await send({ type: "GET_AUTO_DOMAINS" });
  autoToggle.checked = Boolean(res.autoDomains[url.hostname]);
  autoToggle.disabled = false;
}

async function onAutoToggle() {
  const url = new URL(currentTab.url);
  setStatus(autoToggle.checked ? t("statusEnabling") : t("statusDisabling"));
  try {
    await send({
      type: "SET_AUTO_DOMAIN",
      hostname: url.hostname,
      enabled: autoToggle.checked,
      url: currentTab.url,
    });
    setStatus(autoToggle.checked ? t("statusAutoEnabled") : t("statusAutoDisabled"));
    await analyze();
  } catch (err) {
    setStatus(t("statusErrorPrefix", [err.message]));
  }
}

function renderLevelPicker() {
  levelPickerEl.innerHTML = "";
  for (const level of LEVELS) {
    const label = document.createElement("label");
    label.className = "level-option";
    label.innerHTML = `
      <input type="radio" name="level" value="${level.value}" ${level.value === currentLevel ? "checked" : ""} />
      <span>
        <span class="level-name">${t(level.nameKey)}</span>
        <span class="level-desc">${t(level.descKey)}</span>
      </span>
    `;
    levelPickerEl.appendChild(label);
  }
  for (const input of levelPickerEl.querySelectorAll('input[name="level"]')) {
    input.addEventListener("change", onLevelChange);
  }
}

async function onLevelChange(event) {
  const input = event.target;
  const newLevel = Number(input.value);
  const previousLevel = currentLevel;

  if (newLevel === 5) {
    if (!window.confirm(t("level5ConfirmText"))) {
      input.checked = false;
      const previousInput = levelPickerEl.querySelector(`input[value="${previousLevel}"]`);
      if (previousInput) previousInput.checked = true;
      return;
    }
  }

  levelWarningEl.hidden = newLevel < 4;
  if (newLevel === 4) levelWarningEl.textContent = t("level4Warning");
  if (newLevel === 5) levelWarningEl.textContent = t("level5Warning");

  try {
    await send({ type: "SET_LEVEL", level: newLevel });
    currentLevel = newLevel;
    await analyze();
  } catch (err) {
    setStatus(t("statusErrorPrefix", [err.message]));
  }
}

function renderBackups(backups) {
  backupsListEl.innerHTML = "";
  backupsSection.hidden = backups.length === 0;
  for (const backup of backups) {
    const li = document.createElement("li");
    li.className = "backup-item";
    const nameSpan = document.createElement("span");
    nameSpan.className = "backup-name";
    nameSpan.textContent = backup.name;

    const actions = document.createElement("div");
    actions.className = "backup-actions";

    const restoreBtn = document.createElement("button");
    restoreBtn.type = "button";
    restoreBtn.textContent = t("restoreBtn");
    restoreBtn.addEventListener("click", () => handleRestore(backup, false));

    const whitelistBtn = document.createElement("button");
    whitelistBtn.type = "button";
    whitelistBtn.textContent = t("whitelistBtn");
    whitelistBtn.addEventListener("click", () => handleRestore(backup, true));

    actions.append(restoreBtn, whitelistBtn);
    li.append(nameSpan, actions);
    backupsListEl.appendChild(li);
  }
}

async function loadBackupsForCurrentSite() {
  if (!currentTab || !currentTab.url) return;
  const hostname = new URL(currentTab.url).hostname;
  try {
    const res = await send({ type: "GET_BACKUPS_FOR_DOMAIN", domain: hostname });
    renderBackups(res.backups);
  } catch {
    // Non-critical: leave the backups section as-is on failure.
  }
}

async function handleRestore(backup, whitelist) {
  const cookieRef = { domain: backup.domain, name: backup.name, path: backup.path };
  try {
    await send({ type: whitelist ? "WHITELIST_COOKIE" : "RESTORE_COOKIE", cookieRef });
    setStatus(whitelist ? t("statusWhitelisted", [backup.name]) : t("statusRestored", [backup.name]));
    await analyze();
    await loadBackupsForCurrentSite();
  } catch (err) {
    setStatus(t("statusErrorPrefix", [err.message]));
  }
}

function downloadSiteReport() {
  const md = formatSiteReport({
    hostname: hostnameEl.textContent,
    entries: lastSiteEntries,
    generatedAt: new Date().toISOString(),
  });
  downloadText(`cookie-defense-${hostnameEl.textContent}.md`, md);
}

function switchTab(which) {
  const site = which === "site";
  tabSite.classList.toggle("active", site);
  tabBrowser.classList.toggle("active", !site);
  siteView.hidden = !site;
  browserView.hidden = site;
}

function renderFullScanSummary(report) {
  const s = report.summary;
  browserSummaryEl.innerHTML = "";
  const categoryList = Object.entries(s.byCategory)
    .map(([k, v]) => `${categoryLabel(k)}=${v}`)
    .join(", ");
  const lines = [
    t("browserSummaryTotal", [String(s.totalCookies), String(s.totalDomains)]),
    t("browserSummaryObfuscatable", [String(s.obfuscatableCount)]),
    t("browserSummaryRisk", [String(s.highRiskCount), String(s.mediumRiskCount)]),
    t("browserSummaryFlags", [String(s.notHttpOnlyCount), String(s.notSecureCount), String(s.jwtCount)]),
    t("browserSummaryCategories", [categoryList]),
  ];
  for (const line of lines) {
    const li = document.createElement("li");
    li.textContent = line;
    browserSummaryEl.appendChild(li);
  }
  obfuscateAllBtn.disabled = s.obfuscatableCount === 0;
  downloadBrowserReportBtn.disabled = s.totalCookies === 0;
}

async function fullScan() {
  browserStatusEl.textContent = t("browserStatusScanning");
  try {
    const res = await send({ type: "FULL_SCAN", revealValues: false });
    lastFullScanReport = res.report;
    renderFullScanSummary(res.report);
    browserStatusEl.textContent = t("browserStatusDone");
  } catch (err) {
    browserStatusEl.textContent = t("statusErrorPrefix", [err.message]);
  }
}

async function obfuscateAllBrowser() {
  const count = lastFullScanReport ? lastFullScanReport.summary.obfuscatableCount : 0;
  const confirmed = window.confirm(t("confirmObfuscateAll", [String(count)]));
  if (!confirmed) return;
  browserStatusEl.textContent = t("browserStatusObfuscating");
  try {
    const res = await send({ type: "OBFUSCATE_ALL_BROWSER" });
    browserStatusEl.textContent = t("browserStatusObfuscated", [String(res.changed.length)]);
    await fullScan();
  } catch (err) {
    browserStatusEl.textContent = t("statusErrorPrefix", [err.message]);
  }
}

function downloadBrowserReport() {
  if (!lastFullScanReport) return;
  const md = formatFullScanReport({ report: lastFullScanReport, generatedAt: new Date().toISOString() });
  downloadText("cookie-defense-koko-selain.md", md);
}

async function loadSettings() {
  try {
    const res = await send({ type: "GET_SETTINGS" });
    currentLevel = res.level;
    globalAutoToggle.checked = Boolean(res.globalAutoProtect);
  } catch {
    currentLevel = 2;
  }
  renderLevelPicker();
}

async function onGlobalAutoToggle() {
  try {
    await send({ type: "SET_GLOBAL_AUTO_PROTECT", enabled: globalAutoToggle.checked });
  } catch (err) {
    setStatus(t("statusErrorPrefix", [err.message]));
  }
}

async function init() {
  applyStaticI18n();
  await loadSettings();
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTab = tab;
  if (!tab || !tab.url || !/^https?:/.test(tab.url)) {
    hostnameEl.textContent = t("statusNotSupported");
    analyzeBtn.disabled = true;
  } else {
    hostnameEl.textContent = new URL(tab.url).hostname;
    await loadAutoToggleState();
    await analyze();
  }
}

analyzeBtn.addEventListener("click", analyze);
obfuscateBtn.addEventListener("click", obfuscateNow);
autoToggle.addEventListener("change", onAutoToggle);
globalAutoToggle.addEventListener("change", onGlobalAutoToggle);
revealToggle.addEventListener("change", analyze);
downloadSiteReportBtn.addEventListener("click", downloadSiteReport);

tabSite.addEventListener("click", () => switchTab("site"));
tabBrowser.addEventListener("click", () => switchTab("browser"));
fullScanBtn.addEventListener("click", fullScan);
obfuscateAllBtn.addEventListener("click", obfuscateAllBrowser);
downloadBrowserReportBtn.addEventListener("click", downloadBrowserReport);

init();
