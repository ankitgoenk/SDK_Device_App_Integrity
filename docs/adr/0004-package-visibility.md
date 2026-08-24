# 0004. Curated `<queries>` instead of `QUERY_ALL_PACKAGES`

Date: 2026-08-24
Status: Accepted

## Context

Detecting hostile co-installed apps (patchers, memory editors, MITM proxies, cloners) requires
seeing which packages are installed. Since Android 11, `PackageManager` results are filtered
unless the app declares `<queries>` or holds `QUERY_ALL_PACKAGES`.

`QUERY_ALL_PACKAGES` gives complete coverage. It is also a Google Play restricted permission
with a narrow approved-use list; integrity scanning is not a dependable justification, it
requires a declaration form, and it exposes the host to removal. It is also, straightforwardly,
a large amount of personal data we do not need.

## Decision

The SDK never declares `QUERY_ALL_PACKAGES`. `integrity-detector-environment` ships a manifest
fragment with a curated `<queries>` list, one entry per package documented in the detection
catalog. Where visibility is filtered, affected signals return `INCONCLUSIVE` and the report
carries `META_VISIBILITY_RESTRICTED` — "not found" is never reported as "clean".

## Consequences

- **Easier:** Play review; privacy posture; the probe list is auditable and reviewable.
- **Harder:** coverage is limited to packages we anticipated; a renamed hostile app is
  invisible; the list needs maintenance every release.
- **Mitigation:** pair with signals that do not depend on package visibility (filesystem
  artefacts, maps scanning, virtual-container fingerprints) and with Play Integrity's
  `appAccessRiskVerdict`, which Google computes without exposing the inventory to us.
- **Accepted:** hosts that already hold the permission for an approved reason automatically
  get broader coverage; nobody adds it for our sake.
