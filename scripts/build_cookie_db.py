#!/usr/bin/env python3
"""Convert the upstream Open Cookie Database CSV, plus our own
third_party/local-overrides.csv (same schema — cookies identified through
manual OSINT on real scans, not yet in upstream), into a compact JSON lookup
table used by the extension at runtime.

Source: https://github.com/jkwakman/Open-Cookie-Database (Apache-2.0).
Run this again after refreshing third_party/open-cookie-database.csv to
pick up upstream updates, or after editing local-overrides.csv:

    python3 scripts/build_cookie_db.py
"""
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC_CSV = ROOT / "third_party" / "open-cookie-database.csv"
# Cookies identified by our own OSINT analysis (name-pattern research on a
# real full-browser scan) that aren't in the upstream Open Cookie Database.
# Kept in a separate file, same CSV schema, so `curl`-refreshing SRC_CSV from
# upstream never silently wipes these out. Entries here win on name clashes.
LOCAL_OVERRIDES_CSV = ROOT / "third_party" / "local-overrides.csv"
OUT_JSON = ROOT / "extension" / "data" / "cookie-database.json"

# Categories that are safe to rewrite with placeholder data without breaking
# a site's core functionality (login, cart, CSRF tokens, language prefs, ...).
OBFUSCATABLE_CATEGORIES = {"Analytics", "Marketing", "Personalization"}


def load_csv_rows(path):
    if not path.exists():
        return
    with path.open(newline="", encoding="utf-8") as f:
        yield from csv.DictReader(f)


def main():
    exact = {}
    prefixes = []

    # Local overrides are loaded FIRST and use setdefault-with-overwrite
    # semantics further down (upstream uses plain setdefault, so anything
    # already present here from local overrides is never replaced by upstream).
    for row in load_csv_rows(LOCAL_OVERRIDES_CSV):
        name = (row.get("Cookie / Data Key name") or "").strip()
        category = (row.get("Category") or "").strip()
        if not name or not category:
            continue
        is_wildcard = (row.get("Wildcard match") or "0").strip() == "1"
        entry = {
            "category": category,
            "platform": (row.get("Platform") or "").strip(),
            "obfuscatable": category in OBFUSCATABLE_CATEGORIES,
        }
        if is_wildcard:
            prefixes.append({"prefix": name, **entry})
        else:
            exact[name] = entry

    for row in load_csv_rows(SRC_CSV):
        name = (row.get("Cookie / Data Key name") or "").strip()
        category = (row.get("Category") or "").strip()
        if not name or not category:
            continue
        is_wildcard = (row.get("Wildcard match") or "0").strip() == "1"
        entry = {
            "category": category,
            "platform": (row.get("Platform") or "").strip(),
            "obfuscatable": category in OBFUSCATABLE_CATEGORIES,
        }
        if is_wildcard:
            prefixes.append({"prefix": name, **entry})
        else:
            # First match wins if the CSV has duplicate exact names, and a
            # local override (already in `exact`) always wins over upstream.
            exact.setdefault(name, entry)

    # Longest prefix first so more specific rules match before generic ones.
    prefixes.sort(key=lambda e: len(e["prefix"]), reverse=True)

    out = {
        "source": "https://github.com/jkwakman/Open-Cookie-Database",
        "license": "Apache-2.0",
        "exact": exact,
        "prefixes": prefixes,
    }
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(out, ensure_ascii=False, separators=(",", ":")))
    print(f"exact={len(exact)} prefixes={len(prefixes)} -> {OUT_JSON}")


if __name__ == "__main__":
    main()
