# Cookie Defense — bookmarklet edition

A lightweight, manual companion to the [Chrome extension](../extension) for
browsers that don't support extensions at all — built for **DuckDuckGo's
iOS app**, which has no public extension API (unlike desktop Chrome) and
isn't confirmed to support Safari Web Extensions either, since it's its
own WebKit-based app rather than Safari itself.

A bookmarklet is just JavaScript saved as a bookmark's URL; tapping the
bookmark runs it on the page you're currently viewing. No app to build, no
Mac/Xcode/App Store needed.

## What it does differently from the extension

`document.cookie` (the only cookie access page JavaScript has) is far more
limited than the extension's `chrome.cookies` API:

| | Extension | Bookmarklet |
|---|---|---|
| Runs | Automatically, in the background | Manually, once per tap |
| HttpOnly cookies | Visible (used as a safety signal) | Invisible — can't touch them at all |
| Scope | Any/all sites, whole browser | Only the current page's own cookies |
| Backup/restore | Yes | No |
| Domain-scoped cookies (e.g. `Domain=.example.com`) | Overwritten correctly | May create a duplicate host-only cookie instead — no page-JS workaround exists |

The upside: since HttpOnly is disproportionately used by real login/session
cookies, the bookmarklet's blind spot mostly overlaps with cookies that
shouldn't be touched anyway. The remaining safety net is name-pattern
matching (`session`, `auth`, `token`, `csrf`, ...) and JWT session-claim
detection — the same logic as [`extension/lib/heuristic.js`](../extension/lib/heuristic.js),
ported without the HttpOnly/session-flag signals that page JS can't see.

## Install on iOS (DuckDuckGo or Safari)

Most mobile browsers block typing `javascript:` directly into the address
bar, but editing an existing bookmark's URL usually still works:

1. Open **`bookmarklet/cookie-defense.bookmarklet.txt`** in this repo and copy its entire contents (starts with `javascript:`).
2. In the browser, bookmark any page (e.g. its homepage) — this just creates a placeholder to edit.
3. Open the bookmark editor for that bookmark, rename it to **"Cookie Defense"**, and replace its URL with the copied text.
4. Save. To use it: browse to any site, open your bookmarks, tap **"Cookie Defense"**.

This has only been verified in headless desktop Chromium in this project's
test suite (see below) — it has **not** been tested in DuckDuckGo's actual
iOS app, since that requires a physical/simulated iPhone which isn't
available in this environment. The underlying API (`document.cookie`) is
standard and old enough that it should work in any WebKit-based browser,
but confirm it works as expected on your device before relying on it.

## Rebuilding after editing `cookie-defense.js`

```
node scripts/build_bookmarklet.mjs
```

Regenerates `cookie-defense.bookmarklet.txt` from the readable source.
