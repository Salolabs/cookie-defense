// Builds the installable "javascript:" URI from bookmarklet/cookie-defense.js.
// Strips full-line comments and blank lines (the source has no inline
// trailing comments, so this simple approach is safe) — not a real
// minifier, just enough to keep the bookmark URL a reasonable length.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const srcPath = path.join(here, "..", "bookmarklet", "cookie-defense.js");
const outPath = path.join(here, "..", "bookmarklet", "cookie-defense.bookmarklet.txt");

const src = fs.readFileSync(srcPath, "utf8");
const compact = src
  .split("\n")
  .filter((line) => !/^\s*\/\//.test(line))
  .join("\n")
  .replace(/\n\s*\n+/g, "\n")
  .trim();

// Sanity check: must still be valid JS after stripping comments.
new Function(compact);

const uri = "javascript:" + compact.replace(/\s+/g, " ").trim() + "void 0;";
fs.writeFileSync(outPath, uri);
console.log(`Wrote ${outPath} (${uri.length} chars)`);
