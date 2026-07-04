// Formats analysis results into a Markdown attack-surface report the user
// can save/share. Runs in the popup context, so chrome.i18n is available —
// pure string formatting otherwise, no other chrome.* calls, so it's easy
// to unit test.

import { t, categoryLabel, riskLevelLabel } from "./i18n.js";

function fmtEntry(e) {
  const flags = [
    e.session ? t("flagSession") : t("flagPersistent"),
    e.httpOnly ? t("flagHttpOnly") : t("flagNotHttpOnly"),
    e.secure ? t("flagSecure") : t("flagNotSecure"),
    `SameSite=${e.sameSite}`,
    e.hostOnly ? t("flagHostOnly") : t("flagDomainShared"),
  ].join(", ");
  const platformSuffix = e.platform ? ` (${e.platform})` : "";
  const lines = [
    `### \`${e.name}\` — ${e.domain}`,
    "",
    `- ${t("reportEntryCategory", [categoryLabel(e.category), platformSuffix, e.obfuscatable ? t("labelObfuscatable") : t("labelSafe")])}`,
    `- ${t("reportEntryRisk", [riskLevelLabel(e.risk.level), String(e.risk.score)])}`,
    `- ${t("reportEntryFlags", [flags])}`,
    `- ${t("reportEntryStructure", [e.decoded.summary])}`,
  ];
  if (e.risk.factors.length) {
    lines.push(`- ${t("reportRiskFactorsHeader")}`);
    for (const f of e.risk.factors) lines.push(`  - ${f}`);
  }
  if (e.decoded.details && e.decoded.details.keys) {
    lines.push(`- ${t("reportDetectedFields", [e.decoded.details.keys.join(", ")])}`);
  }
  if (e.decoded.details && e.decoded.details.payloadKeys) {
    lines.push(`- ${t("reportJwtFields", [e.decoded.details.payloadKeys.join(", ")])}`);
  }
  return lines.join("\n");
}

export function formatSiteReport({ hostname, entries, generatedAt }) {
  const obfuscatable = entries.filter((e) => e.obfuscatable);
  const header = [
    `# ${t("reportSiteTitle")}`,
    "",
    t("reportHostname", [hostname]),
    t("reportGeneratedAt", [generatedAt]),
    t("reportTotalCookies", [String(entries.length), String(obfuscatable.length)]),
    "",
    t("reportIntro"),
    "",
    "---",
    "",
  ].join("\n");
  return header + entries.map(fmtEntry).join("\n\n");
}

export function formatFullScanReport({ report, generatedAt }) {
  const { summary, entries } = report;
  const categoryList = Object.entries(summary.byCategory)
    .map(([k, v]) => `${categoryLabel(k)}=${v}`)
    .join(", ");
  const header = [
    `# ${t("reportFullScanTitle")}`,
    "",
    t("reportGeneratedAt", [generatedAt]),
    t("reportFullScanTotal", [String(summary.totalCookies), String(summary.totalDomains)]),
    t("reportFullScanObfuscatable", [String(summary.obfuscatableCount)]),
    t("reportFullScanRiskCounts", [String(summary.highRiskCount), String(summary.mediumRiskCount)]),
    t("reportFullScanFlagCounts", [String(summary.notHttpOnlyCount), String(summary.notSecureCount), String(summary.jwtCount)]),
    "",
    t("reportCategoriesLabel", [categoryList]),
    "",
    t("reportFullScanNote"),
    "",
    "---",
    "",
  ].join("\n");

  const highRiskFirst = [...entries].sort((a, b) => b.risk.score - a.risk.score);
  return header + highRiskFirst.map(fmtEntry).join("\n\n");
}

export function downloadFilenameFor(prefix) {
  return `${prefix}.md`;
}
