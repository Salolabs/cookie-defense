# Security Policy

Cookie Defense runs entirely locally in the browser and does not transmit
any data to a server (see the [privacy policy](https://salolabs.github.io/cookie-defense/)).
Even so, it requests broad permissions (`cookies`, `<all_urls>`) to do its
job, so we take reports about it seriously.

## Reporting a vulnerability

Please use GitHub's [private vulnerability reporting](https://github.com/Salolabs/cookie-defense/security/advisories/new)
for anything that could affect a user's security or privacy (e.g. a way to
exfiltrate cookie values, bypass the whitelist, or corrupt a functional
cookie unexpectedly). This keeps the report out of the public issue tracker
until a fix is available.

For anything else (bugs, missing tracker entries, feature requests), a
regular [GitHub issue](https://github.com/Salolabs/cookie-defense/issues) is fine.

## Supported versions

This is a small, actively developed extension with a single version line —
only the latest release on the `main` branch is supported.
